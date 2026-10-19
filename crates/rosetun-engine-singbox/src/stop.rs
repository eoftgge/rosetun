//! Graceful stop with a kill fallback. A killed sing-box leaves its Wintun
//! adapter for Windows to remove in the background, and the next start can
//! then fail with "already exists"; on an interrupt sing-tun closes the
//! adapter and its WFP session itself.

use std::io;
use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

/// sing-box aborts a hanging close after its `FatalStopTimeout` of 10 s.
pub(crate) const STOP_GRACE: Duration = Duration::from_secs(12);
/// A failed start may not have created the adapter yet: do not wait long.
pub(crate) const FAILED_SPAWN_GRACE: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(50);

pub(crate) trait Stoppable {
    fn has_exited(&mut self) -> io::Result<bool>;
    /// `ErrorKind::Unsupported` means there is no graceful path on this
    /// platform: kill without a warning.
    fn interrupt(&mut self) -> io::Result<()>;
    fn kill(&mut self) -> io::Result<()>;
    fn wait(&mut self) -> io::Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StopOutcome {
    AlreadyExited,
    Graceful(Duration),
    KilledAfterTimeout(Duration),
    Killed,
}

impl StopOutcome {
    pub(crate) fn log(self, probe: bool) {
        // Probe engines stop after every server check; keep them out of the default log.
        macro_rules! line {
            ($($arg:tt)*) => {
                if probe { tracing::debug!($($arg)*) } else { tracing::info!($($arg)*) }
            };
        }
        match self {
            Self::AlreadyExited => {}
            Self::Graceful(elapsed) => {
                line!(
                    elapsed_ms = elapsed.as_millis() as u64,
                    "sing-box stopped gracefully"
                );
            }
            Self::KilledAfterTimeout(waited) => {
                line!(
                    waited_ms = waited.as_millis() as u64,
                    "sing-box did not stop in time and was killed"
                );
            }
            Self::Killed => line!("sing-box killed"),
        }
    }
}

pub(crate) fn stop(process: &mut impl Stoppable, grace: Duration) -> io::Result<StopOutcome> {
    if process.has_exited()? {
        return Ok(StopOutcome::AlreadyExited);
    }
    let started = Instant::now();
    match process.interrupt() {
        Ok(()) => match wait_for_exit(process, started + grace) {
            Ok(true) => return Ok(StopOutcome::Graceful(started.elapsed())),
            Ok(false) => {
                return kill(process).map(|outcome| match outcome {
                    StopOutcome::Killed => StopOutcome::KilledAfterTimeout(started.elapsed()),
                    other => other,
                });
            }
            Err(error) => {
                tracing::warn!(%error, "waiting for sing-box to stop failed; killing it");
            }
        },
        Err(error) if error.kind() == io::ErrorKind::Unsupported => {}
        Err(error) => {
            // The process may have exited on its own just before the interrupt.
            if process.has_exited()? {
                return Ok(StopOutcome::AlreadyExited);
            }
            tracing::warn!(%error, "could not interrupt sing-box; killing it");
        }
    }
    kill(process)
}

fn wait_for_exit(process: &mut impl Stoppable, deadline: Instant) -> io::Result<bool> {
    loop {
        if process.has_exited()? {
            return Ok(true);
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        thread::sleep(POLL.min(deadline - now));
    }
}

fn kill(process: &mut impl Stoppable) -> io::Result<StopOutcome> {
    match process.kill() {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
        Err(error) => {
            // The process can exit between the last check and the kill.
            if process.has_exited()? {
                return Ok(StopOutcome::AlreadyExited);
            }
            return Err(error);
        }
    }
    process.wait()?;
    Ok(StopOutcome::Killed)
}

/// A spawned sing-box. On Windows it runs in its own process group, which is
/// the group the interrupt goes to.
pub(crate) struct ChildStop<'a>(pub(crate) &'a mut Child);

impl Stoppable for ChildStop<'_> {
    fn has_exited(&mut self) -> io::Result<bool> {
        Ok(self.0.try_wait()?.is_some())
    }

    fn interrupt(&mut self) -> io::Result<()> {
        #[cfg(windows)]
        {
            crate::console::interrupt_group(self.0.id())
        }
        // TODO: on Unix, send SIGTERM so the engine can remove its routes.
        #[cfg(not(windows))]
        {
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    fn kill(&mut self) -> io::Result<()> {
        self.0.kill()
    }

    fn wait(&mut self) -> io::Result<()> {
        self.0.wait().map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exits after `exits_after` exit checks following the interrupt, or never.
    #[derive(Default)]
    struct Fake {
        exited: bool,
        exits_after: Option<u32>,
        interrupt_error: Option<io::ErrorKind>,
        exit_on_interrupt_error: bool,
        interrupted: bool,
        checks_since_interrupt: u32,
        killed: bool,
        waited: bool,
    }

    impl Stoppable for Fake {
        fn has_exited(&mut self) -> io::Result<bool> {
            if self.interrupted {
                self.checks_since_interrupt += 1;
                if self
                    .exits_after
                    .is_some_and(|n| self.checks_since_interrupt >= n)
                {
                    self.exited = true;
                }
            }
            Ok(self.exited)
        }

        fn interrupt(&mut self) -> io::Result<()> {
            if let Some(kind) = self.interrupt_error {
                self.exited |= self.exit_on_interrupt_error;
                return Err(kind.into());
            }
            self.interrupted = true;
            Ok(())
        }

        fn kill(&mut self) -> io::Result<()> {
            self.killed = true;
            self.exited = true;
            Ok(())
        }

        fn wait(&mut self) -> io::Result<()> {
            self.waited = true;
            Ok(())
        }
    }

    #[test]
    fn exited_process_is_left_alone() {
        let mut fake = Fake {
            exited: true,
            ..Fake::default()
        };
        assert_eq!(
            stop(&mut fake, STOP_GRACE).unwrap(),
            StopOutcome::AlreadyExited
        );
        assert!(!fake.interrupted && !fake.killed);
    }

    #[test]
    fn interrupted_process_that_exits_is_not_killed() {
        let mut fake = Fake {
            exits_after: Some(3),
            ..Fake::default()
        };
        let outcome = stop(&mut fake, STOP_GRACE).unwrap();
        assert!(matches!(outcome, StopOutcome::Graceful(_)), "{outcome:?}");
        assert!(fake.interrupted && !fake.killed);
    }

    #[test]
    fn process_is_killed_once_the_grace_period_runs_out() {
        let grace = Duration::from_millis(200);
        let mut fake = Fake::default();
        let started = Instant::now();
        let outcome = stop(&mut fake, grace).unwrap();
        let StopOutcome::KilledAfterTimeout(waited) = outcome else {
            panic!("{outcome:?}");
        };
        assert!(waited >= grace && started.elapsed() >= grace);
        assert!(fake.interrupted && fake.killed && fake.waited);
    }

    #[test]
    fn failed_interrupt_kills_without_waiting() {
        let mut fake = Fake {
            interrupt_error: Some(io::ErrorKind::PermissionDenied),
            ..Fake::default()
        };
        let started = Instant::now();
        assert_eq!(stop(&mut fake, STOP_GRACE).unwrap(), StopOutcome::Killed);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(fake.killed && fake.waited);
    }

    #[test]
    fn unsupported_interrupt_kills() {
        let mut fake = Fake {
            interrupt_error: Some(io::ErrorKind::Unsupported),
            ..Fake::default()
        };
        assert_eq!(stop(&mut fake, STOP_GRACE).unwrap(), StopOutcome::Killed);
        assert!(fake.killed);
    }

    #[test]
    fn process_that_exits_during_a_failed_interrupt_is_not_killed() {
        let mut fake = Fake {
            interrupt_error: Some(io::ErrorKind::NotFound),
            exit_on_interrupt_error: true,
            ..Fake::default()
        };
        assert_eq!(
            stop(&mut fake, STOP_GRACE).unwrap(),
            StopOutcome::AlreadyExited
        );
        assert!(!fake.killed);
    }
}
