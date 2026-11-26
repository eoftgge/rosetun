use std::io;
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};

#[derive(Debug)]
pub(super) struct Readiness {
    receiver: Receiver<()>,
    ready: bool,
}

impl Readiness {
    pub(super) fn new() -> (Sender<()>, Self) {
        let (sender, receiver) = channel();
        (
            sender,
            Self {
                receiver,
                ready: false,
            },
        )
    }

    pub(super) fn poll(&mut self) -> io::Result<bool> {
        if self.ready {
            return Ok(true);
        }

        match self.receiver.try_recv() {
            Ok(()) => {
                self.ready = true;
                Ok(true)
            }
            Err(TryRecvError::Empty) => Ok(false),
            Err(TryRecvError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "sing-box stderr closed before startup readiness",
            )),
        }
    }
}

/// Recognizes the startup message observed in the tested sing-box build.
/// This is a log-format contract, not a stable sing-box API.
pub(super) fn is_startup_message(line: &str) -> bool {
    let plain = strip_ansi_csi(line);
    let mut words = plain.split_whitespace();

    let info_found = words.by_ref().any(|word| {
        word == "INFO"
            || word
                .strip_prefix("INFO[")
                .and_then(|value| value.strip_suffix(']'))
                .is_some_and(|value| {
                    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
                })
    });

    if !info_found {
        return false;
    }

    if words.next() != Some("sing-box") || words.next() != Some("started") {
        return false;
    }

    let Some(duration) = words
        .next()
        .and_then(|word| word.strip_prefix('('))
        .and_then(|word| word.strip_suffix("s)"))
    else {
        return false;
    };

    !duration.is_empty()
        && duration
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        && duration
            .parse::<f64>()
            .is_ok_and(|value| value.is_finite() && value >= 0.0)
        && words.next().is_none()
}

pub(super) fn strip_ansi_csi(line: &str) -> String {
    let mut result = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();

    while let Some(character) = chars.next() {
        if character == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for control in chars.by_ref() {
                if ('\u{40}'..='\u{7e}').contains(&control) {
                    break;
                }
            }
        } else {
            result.push(character);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_final_readiness_line_from_windows_1_14_1_fixture() {
        let output = include_str!("../tests/fixtures/startup-1.14.1-windows.txt");
        let lines: Vec<&str> = output.lines().collect();

        assert_eq!(
            lines.len(),
            4,
            "fixture contains the observed startup sequence"
        );

        for (index, line) in lines.iter().enumerate() {
            assert_eq!(
                is_startup_message(line),
                index == 3,
                "only the final startup message signals readiness; line {index}: {line}"
            );
        }
    }

    #[test]
    fn accepts_ansi_and_elapsed_time_prefix() {
        assert!(is_startup_message(
            "\x1b[36mINFO\x1b[0m[0000] sing-box started (0.43s)"
        ));
    }

    #[test]
    fn accepts_observed_startup_message() {
        assert!(is_startup_message(
            "+0900 2026-10-02 22:10:26 INFO sing-box started (0.43s)"
        ));
    }

    #[test]
    fn rejects_other_messages() {
        for line in [
            "INFO inbound/tun[tun-in]: started at rosetun0",
            "FATAL start service: configure tun interface failed",
            "INFO outbound: sing-box started (0.43s)",
            "INFO sing-box started (invalid)",
            "INFO sing-box started (0.43s) trailing text",
        ] {
            assert!(!is_startup_message(line), "{line}");
        }
    }

    #[test]
    fn readiness_waits_and_then_latches() {
        let (sender, mut readiness) = Readiness::new();
        assert!(!readiness.poll().expect("pending"));

        sender.send(()).expect("receiver exists");
        assert!(readiness.poll().expect("ready"));

        drop(sender);
        assert!(readiness.poll().expect("readiness remains latched"));
    }

    #[test]
    fn eof_before_readiness_is_an_error() {
        let (sender, mut readiness) = Readiness::new();
        drop(sender);

        assert_eq!(
            readiness
                .poll()
                .expect_err("startup signal is missing")
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
