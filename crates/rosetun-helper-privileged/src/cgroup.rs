//! The helper's cgroup leaves under its systemd unit (Linux, `--service`).
//!
//! With `Delegate=yes` the unit's cgroup subtree belongs to the helper. It
//! makes `helper` and `engines` below it, moves itself into `helper` and
//! hands the engine launcher the `engines` leaf, which the kill switch
//! permits. If any step fails, engines start in the helper's cgroup and the
//! routing backend gets the reason instead of leaves: no kill switch and no
//! DNS lock, and no rule that could let the helper's cgroup through.

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
    let (placement, leaves) = placement(prepare_at(Path::new(cgroup::MOUNT)));
    match &leaves {
        Ok(leaves) => {
            tracing::info!(engines = %leaves.engines, "engines start in their own cgroup");
        }
        Err(reason) => tracing::error!(
            %reason,
            "engines have no cgroup of their own; they start without the kill switch and the DNS lock"
        ),
    }
    process::place_engines(placement);
    leaves
}

/// Where engines start after the preparation, and what the routing backend
/// gets: the leaves, or why there are none.
fn placement(prepared: Result<(Leaves, File), String>) -> (Placement, Result<Leaves, String>) {
    match prepared {
        Ok((leaves, engines)) => (Placement::Leaf(engines), Ok(leaves)),
        Err(reason) => (Placement::Inherit, Err(reason)),
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

    fn leaves() -> Leaves {
        Leaves::of(&CgroupPath::parse("/system.slice/rosetun-helper.service").unwrap()).unwrap()
    }

    #[test]
    fn with_the_leaves_engines_start_in_theirs() {
        let procs = std::env::temp_dir().join(format!("rosetun-placement-{}", std::process::id()));
        let file = File::create(&procs).unwrap();
        let (placement, routed) = placement(Ok((leaves(), file)));
        let _ = std::fs::remove_file(&procs);
        assert!(matches!(placement, Placement::Leaf(_)));
        assert_eq!(routed.unwrap(), leaves());
    }

    #[test]
    fn every_failed_preparation_starts_engines_in_the_helpers_cgroup_without_protection() {
        let empty = std::env::temp_dir().join(format!("rosetun-no-v2-{}", std::process::id()));
        std::fs::create_dir_all(&empty).unwrap();
        let no_v2 = prepare_at(&empty);
        let _ = std::fs::remove_dir_all(&empty);
        for prepared in [
            no_v2,
            Err(format!("the cgroup of {} is not delegated to it (Delegate=yes)", cgroup::UNIT)),
            Err("cannot create the cgroup /system.slice/rosetun-helper.service/engines: Permission denied".to_owned()),
            Err("cannot move the helper into its leaf: Device or resource busy".to_owned()),
            Err("cannot open the engines' leaf: Permission denied".to_owned()),
        ] {
            let expected = prepared.as_ref().err().cloned();
            assert!(expected.is_some());
            let (placement, routed) = placement(prepared);
            assert!(matches!(placement, Placement::Inherit));
            assert_eq!(routed.err(), expected);
        }
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
