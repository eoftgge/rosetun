//! The helper's cgroup leaves under its systemd unit (Linux, `--service`).
//!
//! With `Delegate=yes` the unit's cgroup subtree belongs to the helper. It
//! makes `helper` and `engines` below it, moves itself into `helper` and
//! hands the engine launcher the `engines` leaf, which the kill switch
//! permits. If any step fails, engines are refused (never started in the
//! helper's cgroup) and protection is off, both with the reason.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rosetun_engine::process::{self, Placement};
use rosetun_routing::cgroup::{self, CgroupPath, Leaves};

/// The extended attributes systemd sets on a delegated cgroup: `trusted.`
/// since v251, `user.` since v252.
const DELEGATE_ATTRIBUTES: [&str; 2] = ["trusted.delegate", "user.delegate"];

/// Prepares the leaves and the engine placement; returns the leaves for the
/// routing backend, or why there are none.
pub(crate) fn prepare() -> Result<Leaves, String> {
    match prepare_at(Path::new(cgroup::MOUNT)) {
        Ok((leaves, engines)) => {
            tracing::info!(engines = %leaves.engines, "engines start in their own cgroup");
            process::place_engines(Placement::Leaf(engines));
            Ok(leaves)
        }
        Err(reason) => {
            tracing::error!(
                %reason,
                "engines have no cgroup of their own; they will not start"
            );
            process::place_engines(Placement::Refused(reason.clone()));
            Err(reason)
        }
    }
}

fn prepare_at(mount: &Path) -> Result<(Leaves, File), String> {
    if !mount.join("cgroup.controllers").is_file() {
        return Err(format!("cgroup v2 is not mounted at {}", mount.display()));
    }
    let own = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| format!("cannot read /proc/self/cgroup: {error}"))?;
    let own = cgroup::own_cgroup(&own).map_err(|error| error.to_string())?;
    let leaves = Leaves::of(&own).map_err(|error| error.to_string())?;
    if !delegated(&leaves.service.under(mount)) {
        return Err(format!(
            "the cgroup of {} is not delegated to it (Delegate=yes)",
            cgroup::UNIT
        ));
    }
    let helper = make_leaf(mount, &leaves.helper)?;
    let engines = make_leaf(mount, &leaves.engines)?;
    // The whole process moves: in cgroup v2 a write to cgroup.procs moves
    // every thread.
    OpenOptions::new()
        .write(true)
        .open(helper.join("cgroup.procs"))
        .and_then(|mut procs| procs.write_all(b"0"))
        .map_err(|error| format!("cannot move the helper into its leaf: {error}"))?;
    let engines = OpenOptions::new()
        .write(true)
        .open(engines.join("cgroup.procs"))
        .map_err(|error| format!("cannot open the engines' leaf: {error}"))?;
    Ok((leaves, engines))
}

fn make_leaf(mount: &Path, leaf: &CgroupPath) -> Result<std::path::PathBuf, String> {
    let path = leaf.under(mount);
    match std::fs::create_dir(&path) {
        Ok(()) => Ok(path),
        // A restart after a crash may find it: systemd keeps the unit's
        // cgroup while it restarts.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => {
            Ok(path)
        }
        Err(error) => Err(format!("cannot create the cgroup {leaf}: {error}")),
    }
}

fn delegated(path: &Path) -> bool {
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    DELEGATE_ATTRIBUTES.iter().any(|name| {
        let Ok(name) = CString::new(*name) else {
            return false;
        };
        let mut value = [0_u8; 8];
        // SAFETY: Both strings are NUL-terminated and live across the call;
        // the kernel writes at most `value.len()` bytes into `value`.
        let length = unsafe {
            libc::getxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        usize::try_from(length).is_ok_and(|length| is_delegated(&value[..length.min(value.len())]))
    })
}

fn is_delegated(value: &[u8]) -> bool {
    value == b"1"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_systemds_mark_counts_as_delegation() {
        assert!(is_delegated(b"1"));
        assert!(!is_delegated(b"0"));
        assert!(!is_delegated(b""));
    }

    #[test]
    fn a_mount_without_cgroup_v2_is_refused() {
        let empty = std::env::temp_dir().join(format!("rosetun-no-cgroup-{}", std::process::id()));
        std::fs::create_dir_all(&empty).unwrap();
        let error = prepare_at(&empty).unwrap_err();
        let _ = std::fs::remove_dir_all(&empty);
        assert!(error.contains("cgroup v2"), "{error}");
    }

    #[test]
    fn outside_the_unit_the_tests_own_cgroup_is_never_taken() {
        // The test runs in a session or a build's cgroup, never in the unit.
        let mount = Path::new(cgroup::MOUNT);
        if !mount.join("cgroup.controllers").is_file() {
            return;
        }
        let error = prepare_at(mount).unwrap_err();
        assert!(
            error.contains(cgroup::UNIT) || error.contains("cgroup v2"),
            "{error}"
        );
    }
}
