//! Engine processes on macOS: each starts in a process group of its own so
//! stopping the engine delivers SIGTERM to the group without ever reaching the
//! helper itself.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};

use crate::EngineRights;

/// Starts `command` in a process group of its own. The standard library clears
/// the signal mask in the child, so the engine does not inherit the helper's
/// blocked signals.
pub fn spawn(mut command: Command) -> io::Result<Child> {
    command.process_group(0);
    command.spawn()
}

/// [`spawn`] accepting [`EngineRights`] for signature parity with Linux.
pub fn spawn_with_rights(command: Command, _rights: EngineRights) -> io::Result<Child> {
    spawn(command)
}

/// Sends SIGTERM to the process group led by `child`. Only a child that leads
/// its own group (as [`spawn`] starts it) is interrupted; any other returns
/// `ErrorKind::Unsupported`, because its group may hold the helper itself.
pub fn interrupt_group(child: &mut Child) -> io::Result<()> {
    let pid = libc::pid_t::try_from(child.id())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pid out of range"))?;
    // SAFETY: Plain value. The `&mut Child` is not reaped, so its pid cannot
    // have been reused by another process.
    let group = unsafe { libc::getpgid(pid) };
    if group < 0 {
        return Err(io::Error::last_os_error());
    }
    if group != pid {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the process does not lead a group of its own",
        ));
    }
    // SAFETY: Plain values. The group is the one the unreaped child leads, so
    // the signal reaches only processes the helper started.
    if unsafe { libc::kill(-pid, libc::SIGTERM) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    use super::*;

    fn sleep_command() -> Command {
        let mut command = Command::new("/bin/sleep");
        command
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    #[test]
    fn spawn_places_child_in_its_own_process_group_and_interrupt_stops_it() {
        let mut child = spawn(sleep_command()).expect("spawn sleep");
        let pid = libc::pid_t::try_from(child.id()).expect("pid fits pid_t");
        // SAFETY: Plain value; the child has not been reaped.
        let group = unsafe { libc::getpgid(pid) };
        assert_eq!(group, pid);

        interrupt_group(&mut child).expect("interrupt child group");

        let deadline = Instant::now() + Duration::from_secs(3);
        let exited = loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                break Some(status);
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(exited.is_some(), "child did not exit after SIGTERM");
    }

    #[test]
    fn interrupt_refuses_child_sharing_the_callers_group() {
        let mut child = sleep_command().spawn().expect("spawn plain sleep");
        let error = interrupt_group(&mut child).expect_err("must refuse shared group");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        let _ = child.kill();
        let _ = child.wait();
    }
}
