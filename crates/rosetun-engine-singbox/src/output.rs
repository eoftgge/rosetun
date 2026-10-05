use crate::readiness::strip_ansi_csi;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LineLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Reads the level word sing-box puts before each message, as in
/// `+0900 2026-10-03 02:24:27 DEBUG dns: ...` or `WARN[0000] ...`.
/// Continuation lines, such as a Go panic trace, have none.
pub(super) fn line_level(line: &str) -> Option<LineLevel> {
    strip_ansi_csi(line)
        .split_whitespace()
        .take(4)
        .find_map(|word| {
            let level = word.split_once('[').map_or(word, |(prefix, _)| prefix);
            match level {
                "TRACE" => Some(LineLevel::Trace),
                "DEBUG" => Some(LineLevel::Debug),
                "INFO" => Some(LineLevel::Info),
                "WARN" => Some(LineLevel::Warn),
                "ERROR" | "FATAL" | "PANIC" => Some(LineLevel::Error),
                _ => None,
            }
        })
}

#[cfg(test)]
mod tests {
    use super::{LineLevel, line_level};

    #[test]
    fn recognizes_every_startup_fixture_line() {
        for line in include_str!("../tests/fixtures/startup-1.14.1-windows.txt").lines() {
            assert_eq!(line_level(line), Some(LineLevel::Info), "{line}");
        }
    }

    #[test]
    fn recognizes_engine_levels_and_ignores_message_words() {
        for (line, expected) in [
            (
                "+0900 2026-10-03 02:24:27 DEBUG dns: exchange example.com. IN A",
                Some(LineLevel::Debug),
            ),
            (
                "+0900 2026-10-03 02:24:27 TRACE router: match",
                Some(LineLevel::Trace),
            ),
            (
                "WARN[0000] inbound/tun[tun-in]: slow",
                Some(LineLevel::Warn),
            ),
            (
                "+0900 2026-10-03 02:24:27 FATAL[0000] start service: failed",
                Some(LineLevel::Error),
            ),
            (
                "\x1b[31mERROR\x1b[0m[0000] dns: failed",
                Some(LineLevel::Error),
            ),
            (
                "+0900 2026-10-03 02:24:27 INFO router: ERROR in name",
                Some(LineLevel::Info),
            ),
            ("panic: runtime error", None),
            ("goroutine 1 [running]:", None),
            ("", None),
        ] {
            assert_eq!(line_level(line), expected, "{line}");
        }
    }
}
