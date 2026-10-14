use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use rosetun_engine::errors::EngineError;

pub const SUPPORTED_XRAY_VERSION: &str = "26.10.10";

const CHECK_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_OUTPUT: u64 = 16 * 1024;

fn parse_version(output: &str) -> Option<&str> {
    output
        .lines()
        .next()?
        .strip_prefix("Xray ")?
        .split_once(" (")
        .and_then(|(version, remainder)| (!remainder.is_empty()).then_some(version))
}

fn failure(binary: &Path, message: impl std::fmt::Display) -> EngineError {
    io::Error::other(format!(
        "Xray version check failed for {}: {message}",
        binary.display()
    ))
    .into()
}

pub(crate) fn check(binary: &Path) -> Result<(), EngineError> {
    let deadline = Instant::now() + CHECK_TIMEOUT;
    let mut child = Command::new(binary)
        .arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| failure(binary, error))?;

    let Some(mut stdout) = child.stdout.take() else {
        crate::stop_failed_spawn(&mut child);
        return Err(failure(binary, "stdout pipe is unavailable"));
    };
    let (sender, receiver) = mpsc::channel();
    if let Err(error) = thread::Builder::new()
        .name("xray-version".into())
        .spawn(move || {
            let result = (|| -> io::Result<String> {
                let mut bytes = Vec::new();
                (&mut stdout).take(MAX_OUTPUT + 1).read_to_end(&mut bytes)?;
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
        crate::stop_failed_spawn(&mut child);
        return Err(failure(binary, error));
    }

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                crate::stop_failed_spawn(&mut child);
                return Err(failure(binary, error));
            }
        }
        if Instant::now() >= deadline {
            crate::stop_failed_spawn(&mut child);
            return Err(failure(binary, "Xray version timed out after 30 seconds"));
        }
        thread::sleep(Duration::from_millis(10));
    };
    if !status.success() {
        return Err(failure(binary, format!("Xray version exited with {status}")));
    }
    let output = receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|error| failure(binary, format!("cannot collect version output: {error}")))?
        .map_err(|error| failure(binary, error))?;
    let actual = parse_version(&output)
        .ok_or_else(|| failure(binary, "unrecognized Xray version output"))?;
    if actual != SUPPORTED_XRAY_VERSION {
        return Err(failure(
            binary,
            format!("expected {SUPPORTED_XRAY_VERSION}, found {actual}; install the supported version"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_pinned_version_header_matches() {
        assert_eq!(parse_version("Xray 26.10.10 (Xray, Penetrates Everything.) Custom (go1.26 windows/amd64)\n"), Some(SUPPORTED_XRAY_VERSION));
        assert_eq!(parse_version("Xray 26.9.8 (Xray)\n"), Some("26.9.8"));
        assert_eq!(parse_version("Xray 26.10.10\n"), None);
        assert_eq!(parse_version("prefix Xray 26.10.10 (Xray)\n"), None);
    }
}
