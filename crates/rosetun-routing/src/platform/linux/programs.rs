//! The GUI and the CLI under Lockdown (Linux). nftables cannot match a
//! process by its program file, and a match on the user would let out every
//! program of that user. So under Lockdown the GUI and the CLI start in a
//! user scope of a fixed name in the user's `app.slice` (as `systemd-run
//! --user --scope --unit=rosetun-gui` makes it), and Lockdown permits those
//! scopes, for accounts in group `rosetun` only.
//!
//! A process of the same user can name its own scope the same way; that is
//! no worse than starting `rosetun-gui.exe` on Windows: Lockdown stops
//! accidental leaks, not a program running as the user on purpose.
//!
//! nftables turns a cgroup path into the cgroup's ID when the rule is
//! loaded: a rule for a scope that does not exist cannot be loaded, and a
//! rule for a scope that was made again still names the old one. So the
//! scan keeps each scope's ID (the inode number of its folder, which is
//! the cgroup ID on cgroup v2) and the table is written again whenever the
//! scopes or their IDs change.

use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::cgroup::CgroupPath;

pub(crate) const GUI_SCOPE: &str = "rosetun-gui.scope";
pub(crate) const CLI_SCOPE: &str = "rosetun-cli.scope";
const GROUP: &CStr = c"rosetun";
const MAX_BUFFER: usize = 1024 * 1024;

/// A scope that exists now, with its cgroup ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Program {
    pub(crate) path: CgroupPath,
    id: u64,
}

/// Who may have a permitted scope.
pub(crate) type Membership = dyn Fn(u32) -> bool + Send + Sync;

/// The scopes in `scopes` of every logged-in account that `member` accepts,
/// in a fixed order.
pub(crate) fn scan(mount: &Path, scopes: &[&str], member: &Membership) -> Vec<Program> {
    let Ok(entries) = std::fs::read_dir(mount.join("user.slice")) else {
        return Vec::new();
    };
    let mut uids: Vec<u32> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let digits = name.to_str()?.strip_prefix("user-")?.strip_suffix(".slice")?;
            // Only the canonical spelling: no sign, no leading zero.
            let uid: u32 = digits.parse().ok()?;
            (uid.to_string() == digits).then_some(uid)
        })
        .collect();
    uids.sort_unstable();
    let mut found = Vec::new();
    for uid in uids {
        if !member(uid) {
            continue;
        }
        for scope in scopes {
            let Ok(path) = CgroupPath::parse(&format!(
                "/user.slice/user-{uid}.slice/user@{uid}.service/app.slice/{scope}"
            )) else {
                continue;
            };
            if let Ok(metadata) = std::fs::symlink_metadata(path.under(mount))
                && metadata.is_dir()
            {
                found.push(Program {
                    path,
                    id: metadata.ino(),
                });
            }
        }
    }
    found
}

/// Whether the account is in group `rosetun`, as its primary group or a
/// supplementary one (the same group the service's socket admits).
pub(crate) fn in_rosetun_group(uid: u32) -> bool {
    let Some(gid) = rosetun_gid() else {
        return false;
    };
    let Some((name, primary)) = account(uid) else {
        return false;
    };
    primary == gid || supplementary_groups(&name, primary).contains(&gid)
}

fn rosetun_gid() -> Option<libc::gid_t> {
    let mut buffer = vec![0u8; 4096];
    loop {
        let mut group = MaybeUninit::<libc::group>::uninit();
        let mut found = std::ptr::null_mut();
        // SAFETY: Every pointer is valid for the call: the name is a static
        // C string, `group` and `found` are local out-parameters and the
        // buffer is writable for its stated length; getgrnam_r stores
        // strings only inside that buffer, which is not read afterwards.
        let result = unsafe {
            libc::getgrnam_r(
                GROUP.as_ptr(),
                group.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &raw mut found,
            )
        };
        if result == libc::ERANGE && buffer.len() < MAX_BUFFER {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if result != 0 || found.is_null() {
            return None;
        }
        // SAFETY: A successful call with a non-null result initialized it.
        return Some(unsafe { group.assume_init() }.gr_gid);
    }
}

fn account(uid: u32) -> Option<(CString, libc::gid_t)> {
    let mut buffer = vec![0u8; 4096];
    loop {
        let mut entry = MaybeUninit::<libc::passwd>::uninit();
        let mut found = std::ptr::null_mut();
        // SAFETY: As in `rosetun_gid`: local out-parameters and a buffer
        // writable for its stated length, kept alive while the name in it
        // is copied below.
        let result = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &raw mut found,
            )
        };
        if result == libc::ERANGE && buffer.len() < MAX_BUFFER {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if result != 0 || found.is_null() {
            return None;
        }
        // SAFETY: Initialized by the successful call; `pw_name` points into
        // `buffer`, which is still alive, and is copied before it goes.
        let entry = unsafe { entry.assume_init() };
        if entry.pw_name.is_null() {
            return None;
        }
        // SAFETY: A non-null `pw_name` from getpwuid_r is a C string in the buffer.
        let name = unsafe { CStr::from_ptr(entry.pw_name) }.to_owned();
        return Some((name, entry.pw_gid));
    }
}

fn supplementary_groups(name: &CStr, primary: libc::gid_t) -> Vec<libc::gid_t> {
    let mut groups: Vec<libc::gid_t> = vec![0; 64];
    loop {
        let mut count = libc::c_int::try_from(groups.len()).unwrap_or(libc::c_int::MAX);
        // SAFETY: `name` is a C string, `groups` is writable for `count`
        // entries and `count` is a local in-out parameter.
        let result = unsafe {
            libc::getgrouplist(name.as_ptr(), primary, groups.as_mut_ptr(), &raw mut count)
        };
        let count = usize::try_from(count).unwrap_or(0);
        if result >= 0 {
            groups.truncate(count.min(groups.len()));
            return groups;
        }
        // Too small: `count` holds the number needed.
        if count <= groups.len() || count > 65_536 {
            return Vec::new();
        }
        groups.resize(count, 0);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Mount(PathBuf);

    impl Mount {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "rosetun-programs-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(path.join("user.slice")).unwrap();
            Self(path)
        }

        fn scope(&self, uid: &str, scope: &str) -> PathBuf {
            let path = self.0.join(format!(
                "user.slice/user-{uid}.slice/user@{uid}.service/app.slice/{scope}"
            ));
            std::fs::create_dir_all(&path).unwrap();
            path
        }
    }

    impl Drop for Mount {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn paths(found: &[Program]) -> Vec<String> {
        found.iter().map(|program| program.path.to_string()).collect()
    }

    #[test]
    fn only_members_scopes_of_the_fixed_names_are_found() {
        let mount = Mount::new();
        mount.scope("1000", GUI_SCOPE);
        mount.scope("1000", CLI_SCOPE);
        mount.scope("1000", "app-firefox.scope");
        mount.scope("1001", GUI_SCOPE);
        mount.scope("01002", GUI_SCOPE);
        let found = scan(&mount.0, &[GUI_SCOPE, CLI_SCOPE], &|uid| uid != 1001);
        assert_eq!(
            paths(&found),
            [
                "/user.slice/user-1000.slice/user@1000.service/app.slice/rosetun-gui.scope",
                "/user.slice/user-1000.slice/user@1000.service/app.slice/rosetun-cli.scope",
            ]
        );
        assert_eq!(found[0].path.level(), 5);
        let gui_only = scan(&mount.0, &[GUI_SCOPE], &|_| true);
        assert_eq!(gui_only.len(), 2);
        assert!(scan(&mount.0, &[], &|_| true).is_empty());
    }

    #[test]
    fn a_scope_made_again_is_a_different_program() {
        let mount = Mount::new();
        let path = mount.scope("1000", GUI_SCOPE);
        let first = scan(&mount.0, &[GUI_SCOPE], &|_| true);
        // Hold the old inode so the new folder cannot reuse its number.
        let keep = mount.0.join("old");
        std::fs::rename(&path, &keep).unwrap();
        std::fs::create_dir(&path).unwrap();
        let second = scan(&mount.0, &[GUI_SCOPE], &|_| true);
        assert_eq!(paths(&first), paths(&second));
        assert_ne!(first, second);
    }

    #[test]
    fn no_user_slice_means_no_programs() {
        let mount = Mount::new();
        std::fs::remove_dir(mount.0.join("user.slice")).unwrap();
        assert!(scan(&mount.0, &[GUI_SCOPE], &|_| true).is_empty());
    }

    #[test]
    fn an_account_that_does_not_exist_is_not_a_member() {
        assert!(!in_rosetun_group(u32::MAX - 1));
    }
}
