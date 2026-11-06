//! Adding the account to group `rosetun`, whose members may reach the
//! service's socket. Polkit asks for an administrator; the change counts from
//! the next start of the user's systemd manager, which can outlive a logout and
//! passes its groups on to programs, and until then the socket keeps refusing.

use std::ffi::CStr;
use std::io;
use std::mem::MaybeUninit;
use std::path::Path;
use std::process::{Command, Stdio};

const PKEXEC: &str = "/usr/bin/pkexec";
const USERMOD: &str = "/usr/sbin/usermod";
const GROUP: &str = "rosetun";
const GROUP_FILE: &str = "/etc/group";
/// `pkexec`: the prompt was dismissed.
const DISMISSED: i32 = 126;

/// How an attempt that ran to its end came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceGroupJoin {
    /// The account is in the group; a restart picks that up.
    Joined,
    /// The user dismissed the prompt.
    Declined,
}

/// Asks polkit only when the account is not listed yet: after an earlier
/// click all that is missing is the restart.
pub fn join_service_group() -> io::Result<ServiceGroupJoin> {
    let user = current_user()?;
    if user.starts_with('-') {
        return Err(io::Error::other("the account's name reads as an option"));
    }
    let listed = std::fs::read_to_string(GROUP_FILE)?;
    if lists_member(&listed, GROUP, &user) {
        return Ok(ServiceGroupJoin::Joined);
    }
    if !Path::new(PKEXEC).is_file() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "pkexec is missing"));
    }
    let status = Command::new(PKEXEC)
        .args([USERMOD, "-aG", GROUP, &user])
        .stdin(Stdio::null())
        .status()?;
    match status.code() {
        Some(0) => Ok(ServiceGroupJoin::Joined),
        Some(DISMISSED) => Ok(ServiceGroupJoin::Declined),
        code => Err(io::Error::other(format!(
            "usermod through pkexec ended with {code:?}"
        ))),
    }
}

fn current_user() -> io::Result<String> {
    let mut buffer = vec![0_u8; 16 * 1024];
    let mut entry = MaybeUninit::<libc::passwd>::uninit();
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: Every pointer is valid for the call, the length is the buffer's
    // own, and getpwuid_r writes the entry and its strings into them. geteuid
    // cannot fail.
    let result = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            entry.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &raw mut found,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    if found.is_null() {
        return Err(io::Error::other("this account has no name"));
    }
    // SAFETY: A non-null result points at `entry`, now initialized, whose name
    // is a NUL-terminated string inside `buffer`, alive here.
    let name = unsafe { CStr::from_ptr(entry.assume_init_ref().pw_name) };
    name.to_str()
        .map(str::to_owned)
        .map_err(|_| io::Error::other("the account's name is not UTF-8"))
}

/// Whether a file in the format of `/etc/group` lists the user in the group.
fn lists_member(file: &str, group: &str, user: &str) -> bool {
    file.lines().any(|line| {
        let mut fields = line.split(':');
        fields.next() == Some(group)
            && fields
                .nth(2)
                .is_some_and(|members| members.split(',').any(|member| member == user))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "root:x:0:\nrosetun:x:990:alice,bob\nrosetun2:x:991:carol\nbroken\n";

    #[test]
    fn a_listed_account_is_a_member_of_that_group_only() {
        assert!(lists_member(FILE, "rosetun", "alice"));
        assert!(lists_member(FILE, "rosetun", "bob"));
        assert!(!lists_member(FILE, "rosetun", "carol"));
        assert!(!lists_member(FILE, "rosetun", "ali"));
    }

    #[test]
    fn a_group_without_members_or_a_missing_group_lists_nobody() {
        assert!(!lists_member(FILE, "root", "root"));
        assert!(!lists_member(FILE, "absent", "alice"));
        assert!(!lists_member(FILE, "broken", "alice"));
    }

    #[test]
    fn the_running_account_has_a_name() {
        assert!(!current_user().unwrap().is_empty());
    }
}
