use std::collections::HashMap;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Condvar, LazyLock, Mutex, MutexGuard, PoisonError, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use rosetun_engine::errors::EngineError;

pub const SUPPORTED_SING_BOX_VERSION: &str = "1.14.1";

/// The first run after a boot can wait that long for Defender to scan the file.
const CHECK_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_OUTPUT: u64 = 16 * 1024;

fn parse_version(output: &str) -> Option<&str> {
    let mut versions = output.lines().filter_map(|line| {
        let mut words = line.split_whitespace();
        if words.next()? != "sing-box" || words.next()? != "version" {
            return None;
        }
        let version = words.next()?;
        words.next().is_none().then_some(version)
    });

    let version = versions.next()?;
    versions.next().is_none().then_some(version)
}

/// `sing-box version` creates no adapter, so there is nothing to stop
/// gracefully, and it runs outside a process group of its own: an interrupt
/// would reach the whole console, the helper included.
fn kill(child: &mut Child) {
    if let Err(error) = child.kill()
        && error.kind() != io::ErrorKind::InvalidInput
    {
        tracing::warn!(%error, "could not kill sing-box version");
    }
    let _ = child.wait();
}

#[derive(Debug, Clone)]
struct CheckFailure {
    message: String,
    /// Not remembered: the next attempt may find the scan finished.
    timed_out: bool,
}

impl CheckFailure {
    fn error(message: String) -> EngineError {
        io::Error::other(message).into()
    }
}

fn failure(binary: &Path, message: impl std::fmt::Display) -> CheckFailure {
    CheckFailure {
        message: format!(
            "sing-box version check failed for {}: {message}",
            binary.display()
        ),
        timed_out: false,
    }
}

/// The file a result belongs to: a replaced binary is checked again.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
}

impl FileStamp {
    fn read(binary: &Path) -> io::Result<Self> {
        let metadata = std::fs::metadata(binary)?;
        Ok(Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

#[derive(Debug)]
enum Slot {
    Running(FileStamp),
    Done(FileStamp, Result<(), String>),
}

/// One `sing-box version` per binary for the life of the service: the warmup
/// at start and a connect used to run two at once, each waiting for Defender.
#[derive(Debug, Default)]
struct Cache {
    slots: Mutex<HashMap<PathBuf, Slot>>,
    changed: Condvar,
}

static CACHE: LazyLock<Cache> = LazyLock::new(Cache::default);

pub(super) fn check(binary: &Path) -> Result<(), EngineError> {
    CACHE.check(binary, run)
}

impl Cache {
    fn lock(&self) -> MutexGuard<'_, HashMap<PathBuf, Slot>> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn check(
        &self,
        binary: &Path,
        run: impl FnOnce(&Path) -> Result<(), CheckFailure>,
    ) -> Result<(), EngineError> {
        let stamp = FileStamp::read(binary)
            .map_err(|error| CheckFailure::error(failure(binary, error).message))?;
        let mut slots = self.lock();
        loop {
            match slots.get(binary) {
                Some(Slot::Done(done, result)) if *done == stamp => {
                    return result.clone().map_err(CheckFailure::error);
                }
                Some(Slot::Running(running)) if *running == stamp => {
                    slots = self
                        .changed
                        .wait(slots)
                        .unwrap_or_else(PoisonError::into_inner);
                }
                _ => break,
            }
        }
        slots.insert(binary.to_owned(), Slot::Running(stamp.clone()));
        drop(slots);

        let mut running = Running {
            cache: self,
            binary,
            done: false,
        };
        tracing::debug!(binary = %binary.display(), "running sing-box version");
        let result = run(binary);
        let mut slots = self.lock();
        match &result {
            Err(failure) if failure.timed_out => {
                slots.remove(binary);
            }
            _ => {
                let remembered = result.clone().map_err(|failure| failure.message);
                slots.insert(binary.to_owned(), Slot::Done(stamp, remembered));
            }
        }
        running.done = true;
        drop(slots);
        drop(running);
        result.map_err(|failure| CheckFailure::error(failure.message))
    }
}

/// Wakes the waiters when the check ends, and frees the slot if it ended in
/// a panic, so nobody waits for it forever.
struct Running<'a> {
    cache: &'a Cache,
    binary: &'a Path,
    done: bool,
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.cache.lock().remove(self.binary);
        }
        self.cache.changed.notify_all();
    }
}

fn run(binary: &Path) -> Result<(), CheckFailure> {
    let deadline = Instant::now() + CHECK_TIMEOUT;
    let mut child = Command::new(binary)
        .arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| failure(binary, error))?;

    let Some(mut stdout) = child.stdout.take() else {
        kill(&mut child);
        return Err(failure(binary, "stdout pipe is unavailable"));
    };

    let (sender, receiver) = mpsc::channel();
    if let Err(error) = thread::Builder::new()
        .name("sing-box-version".into())
        .spawn(move || {
            let result = (|| -> io::Result<String> {
                let mut bytes = Vec::new();
                (&mut stdout).take(MAX_OUTPUT + 1).read_to_end(&mut bytes)?;

                // Drain the remainder without storing unbounded output.
                io::copy(&mut stdout, &mut io::sink())?;
                if bytes.len() > MAX_OUTPUT as usize {
                    return Err(io::Error::other("version output exceeds 16 KiB"));
                }
                String::from_utf8(bytes)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
            })();
            let _ = sender.send(result);
        })
    {
        kill(&mut child);
        return Err(failure(binary, error));
    }

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                kill(&mut child);
                return Err(failure(binary, error));
            }
        }

        if Instant::now() >= deadline {
            kill(&mut child);
            return Err(CheckFailure {
                timed_out: true,
                ..failure(
                    binary,
                    format!(
                        "sing-box version timed out after {} seconds",
                        CHECK_TIMEOUT.as_secs()
                    ),
                )
            });
        }
        thread::sleep(Duration::from_millis(10));
    };

    if !status.success() {
        return Err(failure(
            binary,
            format!("sing-box version exited with {status}"),
        ));
    }

    let output = receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|error| failure(binary, format!("cannot collect version output: {error}")))?
        .map_err(|error| failure(binary, error))?;

    let actual = parse_version(&output)
        .ok_or_else(|| failure(binary, format!("unrecognized version output: {output:?}")))?;

    if actual != SUPPORTED_SING_BOX_VERSION {
        return Err(failure(
            binary,
            format!(
                "expected {SUPPORTED_SING_BOX_VERSION}, found {actual}; install the supported version"
            ),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn binary(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("rosetun-version-{name}-{}.exe", std::process::id()));
        std::fs::write(&path, b"sing-box").unwrap();
        path
    }

    #[test]
    fn concurrent_checks_of_one_binary_run_it_once() {
        let cache = Arc::new(Cache::default());
        let path = binary("concurrent");
        let runs = Arc::new(AtomicUsize::new(0));
        let checks = (0..2)
            .map(|_| {
                let (cache, path, runs) = (Arc::clone(&cache), path.clone(), Arc::clone(&runs));
                thread::spawn(move || {
                    cache.check(&path, |_| {
                        runs.fetch_add(1, Ordering::AcqRel);
                        thread::sleep(Duration::from_millis(300));
                        Ok(())
                    })
                })
            })
            .collect::<Vec<_>>();
        for check in checks {
            check.join().unwrap().unwrap();
        }
        assert_eq!(runs.load(Ordering::Acquire), 1);
        cache.check(&path, |_| panic!("remembered")).unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_changed_binary_is_checked_again_and_failures_are_remembered() {
        let cache = Cache::default();
        let path = binary("changed");
        let wrong = |binary: &Path| Err(failure(binary, "expected 1.14.1, found 1.13.0"));
        assert!(cache.check(&path, wrong).is_err());
        assert!(cache.check(&path, |_| panic!("remembered")).is_err());
        std::fs::write(&path, b"sing-box 1.14.1").unwrap();
        let runs = AtomicUsize::new(0);
        cache
            .check(&path, |_| {
                runs.fetch_add(1, Ordering::AcqRel);
                Ok(())
            })
            .unwrap();
        assert_eq!(runs.load(Ordering::Acquire), 1);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_timeout_is_not_remembered() {
        let cache = Cache::default();
        let path = binary("timeout");
        let timed_out = |binary: &Path| {
            Err(CheckFailure {
                timed_out: true,
                ..failure(binary, "timed out")
            })
        };
        assert!(cache.check(&path, timed_out).is_err());
        let runs = AtomicUsize::new(0);
        cache
            .check(&path, |_| {
                runs.fetch_add(1, Ordering::AcqRel);
                Ok(())
            })
            .unwrap();
        assert_eq!(runs.load(Ordering::Acquire), 1);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn parses_observed_windows_1_14_1_version_output() {
        let output = include_str!("../tests/fixtures/version-1.14.1-windows.txt");

        assert_eq!(
            parse_version(output),
            Some(SUPPORTED_SING_BOX_VERSION),
            "the installed Windows build must match the pinned version"
        );
    }

    #[test]
    fn parses_multiline_output() {
        assert_eq!(
            parse_version("sing-box version 1.14.1\n\nEnvironment: go1.x windows/amd64\n"),
            Some(SUPPORTED_SING_BOX_VERSION)
        );
    }

    #[test]
    fn preserves_prerelease_suffix() {
        assert_eq!(
            parse_version("sing-box version 1.14.1-beta.1"),
            Some("1.14.1-beta.1")
        );
    }

    #[test]
    fn rejects_missing_ambiguous_or_extended_version_lines() {
        for output in [
            "",
            "sing-box version",
            "sing-box version 1.14.1 extra",
            "sing-box version 1.14.1\nsing-box version 1.14.1",
        ] {
            assert_eq!(parse_version(output), None, "{output:?}");
        }
    }
}
