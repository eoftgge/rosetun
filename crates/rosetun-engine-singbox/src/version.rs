use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use rosetun_engine::errors::EngineError;

pub const SUPPORTED_SING_BOX_VERSION: &str = "1.14.1";

const CHECK_TIMEOUT: Duration = Duration::from_secs(3);
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

fn failure(binary: &Path, message: impl std::fmt::Display) -> EngineError {
    io::Error::other(format!(
        "sing-box version check failed for {}: {message}",
        binary.display()
    ))
    .into()
}

pub(super) fn check(binary: &Path) -> Result<(), EngineError> {
    let deadline = Instant::now() + CHECK_TIMEOUT;
    let mut child = Command::new(binary)
        .arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| failure(binary, error))?;

    let Some(mut stdout) = child.stdout.take() else {
        super::stop_failed_spawn(&mut child);
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
        super::stop_failed_spawn(&mut child);
        return Err(failure(binary, error));
    }

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                super::stop_failed_spawn(&mut child);
                return Err(failure(binary, error));
            }
        }

        if Instant::now() >= deadline {
            super::stop_failed_spawn(&mut child);
            return Err(failure(
                binary,
                "sing-box version timed out after 3 seconds",
            ));
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
