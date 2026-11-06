//! A package upgrade replaces the installed program under the running GUI.
//! The old process keeps working from the deleted file, may not speak the new
//! service's protocol and could not load anything new. So once the upgraded
//! service answers, it hands over to the new program: same process, same
//! session scope, and the new program decides what the service's state calls
//! for.

use std::ffi::OsStr;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use crate::HIDDEN_ARG;

/// A build run from anywhere else is not the package's to replace.
const INSTALLED_GUI: &str = "/usr/lib/rosetun/rosetun-gui";
/// How the kernel shows a running program whose file was replaced.
const REPLACED_LINK: &str = "/usr/lib/rosetun/rosetun-gui (deleted)";
pub(crate) const RELAUNCHED_ARG: &str = "--relaunched";

fn is_replaced(running: &Path) -> bool {
    running.as_os_str() == OsStr::new(REPLACED_LINK)
}

pub(crate) fn binary_replaced() -> bool {
    std::fs::read_link("/proc/self/exe").is_ok_and(|running| is_replaced(&running))
}

/// Only returns on failure. The instance lock and every other descriptor are
/// close-on-exec, so the new program finds them free.
pub(crate) fn exec(hidden: bool) -> std::io::Error {
    let mut command = Command::new(INSTALLED_GUI);
    command.arg(RELAUNCHED_ARG);
    if hidden {
        command.arg(HIDDEN_ARG);
    }
    command.exec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_installed_program_counts_as_replaced() {
        assert!(is_replaced(Path::new(REPLACED_LINK)));
        assert!(!is_replaced(Path::new(INSTALLED_GUI)));
        assert!(!is_replaced(Path::new(
            "/home/user/rosetun/target/release/rosetun-gui (deleted)"
        )));
    }
}
