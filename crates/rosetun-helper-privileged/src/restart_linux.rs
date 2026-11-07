//! An administrator-requested restart after replacing installed files.

use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use rosetun_ipc::HelperClient;

pub(crate) const UPGRADE_MARKER: &str = "/run/rosetun/upgrading";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Mark,
    Restart,
    Wait,
}

fn sequence(mut run: impl FnMut(Step) -> io::Result<()>) -> io::Result<()> {
    for step in [Step::Mark, Step::Restart, Step::Wait] {
        run(step)?;
    }
    Ok(())
}

pub(crate) fn restart() -> ExitCode {
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("restarting for an upgrade needs root");
        return ExitCode::from(3);
    }
    match restart_inner() {
        Ok(held) => {
            if held {
                println!("service restarted; the network is held closed");
            } else {
                println!("service restarted; the network was not held closed");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("cannot restart for upgrade: {error}; protection has not been reset");
            ExitCode::FAILURE
        }
    }
}

fn restart_inner() -> io::Result<bool> {
    // Outside RuntimeDirectory: systemd removes that directory during restart.
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open("/run/rosetun-upgrade.lock")?;
    use std::os::fd::AsRawFd;
    // SAFETY: lock owns a live descriptor for the duration of the operation.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut held = false;
    sequence(|step| match step {
        Step::Mark => {
            let directory = std::fs::symlink_metadata("/run/rosetun")?;
            if !directory.is_dir() || directory.uid() != 0 || directory.mode() & 0o022 != 0 {
                return Err(io::Error::other("untrusted service runtime directory"));
            }
            OpenOptions::new()
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(UPGRADE_MARKER)?;
            Ok(())
        }
        Step::Restart => {
            // An absolute path and empty environment avoid root's PATH and
            // systemctl overrides. Type=notify waits for the new main process.
            let status = Command::new("/usr/bin/systemctl")
                .args(["restart", "rosetun-helper.service"])
                .env_clear()
                .stdin(Stdio::null())
                .status()?;
            if !status.success() {
                return Err(io::Error::other("systemctl restart failed"));
            }
            Ok(())
        }
        Step::Wait => {
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if let Ok(mut client) = HelperClient::connect(
                    &rosetun_ipc::default_endpoint(),
                    "restart-for-upgrade",
                ) && client.helper_version() == env!("CARGO_PKG_VERSION")
                    && let Ok(status) = client.status()
                {
                    held = status.upgrade_hold || status.lockdown;
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::other("new service did not answer"));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    })?;
    Ok(held)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_restart_marks_before_stopping_and_waits_for_the_new_service() {
        for _ in 0..2 {
            let mut steps = Vec::new();
            sequence(|step| {
                steps.push(step);
                Ok(())
            })
            .unwrap();
            assert_eq!(steps, [Step::Mark, Step::Restart, Step::Wait]);
        }
    }

    #[test]
    fn a_failed_step_prevents_every_later_step() {
        for failed in [Step::Mark, Step::Restart, Step::Wait] {
            let mut steps = Vec::new();
            assert!(sequence(|step| {
                steps.push(step);
                if step == failed { Err(io::Error::other("failed")) } else { Ok(()) }
            }).is_err());
            assert_eq!(steps.last(), Some(&failed));
        }
    }
}
