use crate::readiness::strip_ansi_csi;
use rosetun_engine::{OutboundFailure, OutboundFailures};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub(super) struct FailureCounters {
    unreachable: AtomicU64,
    rejected: AtomicU64,
    closed: AtomicU64,
}

impl FailureCounters {
    pub(super) fn observe(&self, line: &str) {
        let counter = match classify_failure(line) {
            Some(OutboundFailure::Unreachable) => &self.unreachable,
            Some(OutboundFailure::Rejected) => &self.rejected,
            Some(OutboundFailure::Closed) => &self.closed,
            None => return,
        };
        let _ = counter.fetch_update(Ordering::Release, Ordering::Relaxed, |value| {
            Some(value.saturating_add(1))
        });
    }

    pub(super) fn snapshot(&self) -> OutboundFailures {
        OutboundFailures {
            unreachable: self.unreachable.load(Ordering::Acquire),
            rejected: self.rejected.load(Ordering::Acquire),
            closed: self.closed.load(Ordering::Acquire),
        }
    }
}

pub(super) fn classify_failure(line: &str) -> Option<OutboundFailure> {
    if line_level(line) != Some(LineLevel::Error) && line_level(line) != Some(LineLevel::Warn) {
        return None;
    }
    let plain = strip_ansi_csi(line).to_ascii_lowercase();
    let proxy = plain.split_whitespace().any(|word| {
        word.starts_with("outbound/")
            && !word.starts_with("outbound/direct[")
            && word.ends_with("[proxy]:")
    });
    if !proxy {
        return None;
    }
    if [
        "tls: handshake failure",
        "tls: bad certificate",
        "tls: protocol version",
        "reality verification failed",
        "certificate",
        "authentication failed",
        "invalid password",
        "handshake failed",
    ]
    .iter()
    .any(|marker| plain.contains(marker))
    {
        return Some(OutboundFailure::Rejected);
    }
    if [
        "i/o timeout",
        "connection refused",
        "connectex:",
        "network is unreachable",
        "no route to host",
        "context deadline exceeded",
    ]
    .iter()
    .any(|marker| plain.contains(marker))
    {
        return Some(OutboundFailure::Unreachable);
    }
    if [" eof", "connection reset", "forcibly closed", "broken pipe"]
        .iter()
        .any(|marker| plain.contains(marker))
    {
        return Some(OutboundFailure::Closed);
    }
    None
}

/// Keep the server dial target and the cause, but not destinations visited through the tunnel.
pub(super) fn hide_destinations(line: &str) -> String {
    let mut hidden = line.to_owned();
    replace_between(&mut hidden, "open connection to ", " using");
    for marker in [
        "connection to ",
        "connection from ",
        "exchange failed for ",
        "lookup ",
    ] {
        replace_token(&mut hidden, marker);
    }
    hidden
}

fn replace_between(line: &mut String, marker: &str, delimiter: &str) {
    let mut cursor = 0;
    while let Some(relative) = line[cursor..].find(marker) {
        let start = cursor + relative + marker.len();
        let end = line[start..]
            .find(delimiter)
            .map_or_else(|| token_end(line, start), |offset| start + offset);
        if end == start || line[start..end] == *"[hidden]" {
            cursor = start;
            continue;
        }
        line.replace_range(start..end, "[hidden]");
        cursor = start + "[hidden]".len();
    }
}

fn replace_token(line: &mut String, marker: &str) {
    let mut cursor = 0;
    while let Some(relative) = line[cursor..].find(marker) {
        let start = cursor + relative + marker.len();
        let end = token_end(line, start);
        if end == start || line[start..end] == *"[hidden]" {
            cursor = start;
            continue;
        }
        let (token_end, suffix) = if line.as_bytes()[end - 1] == b':' {
            (end - 1, ":")
        } else {
            (end, "")
        };
        if token_end == start {
            cursor = end;
            continue;
        }
        line.replace_range(start..token_end, "[hidden]");
        cursor = start + "[hidden]".len() + suffix.len();
    }
}

fn token_end(line: &str, start: usize) -> usize {
    line[start..]
        .find(char::is_whitespace)
        .map_or(line.len(), |offset| start + offset)
}

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
    fn hides_destinations_but_not_the_server_or_failure_cause() {
        let line = "ERROR [123 5.0s] connection: open connection to 198.51.100.20:443 using outbound/vless[proxy]: dial tcp 203.0.113.10:443: i/o timeout";
        let hidden = super::hide_destinations(line);
        assert_eq!(
            hidden,
            "ERROR [123 5.0s] connection: open connection to [hidden] using outbound/vless[proxy]: dial tcp 203.0.113.10:443: i/o timeout"
        );
        assert_eq!(super::hide_destinations(&hidden), hidden);
    }

    #[test]
    fn hides_other_connection_and_dns_destinations() {
        for (line, expected) in [
            (
                "ERROR connection to example.com:443: reset",
                "ERROR connection to [hidden]: reset",
            ),
            (
                "ERROR connection from 198.51.100.20:5544 using outbound/direct: EOF",
                "ERROR connection from [hidden] using outbound/direct: EOF",
            ),
            (
                "ERROR dns: exchange failed for example.com. IN A: timeout",
                "ERROR dns: exchange failed for [hidden] IN A: timeout",
            ),
            (
                "ERROR dns: lookup example.com: no such host",
                "ERROR dns: lookup [hidden]: no such host",
            ),
            (
                "+0900 2026-10-10 01:15:47 ERROR connection: open connection to [2001:db8::20]:443 using outbound/vless[proxy]: dial tcp 203.0.113.10:443: EOF",
                "+0900 2026-10-10 01:15:47 ERROR connection: open connection to [hidden] using outbound/vless[proxy]: dial tcp 203.0.113.10:443: EOF",
            ),
        ] {
            assert_eq!(super::hide_destinations(line), expected, "{line}");
        }
    }

    #[test]
    fn classifies_only_proxy_outbound_failures() {
        use rosetun_engine::OutboundFailure::*;
        for (cause, expected) in [
            ("dial tcp 192.0.2.1:443: i/o timeout", Unreachable),
            ("connection refused", Unreachable),
            ("tls: handshake failure", Rejected),
            ("REALITY verification failed", Rejected),
            ("EOF", Closed),
            ("connection reset by peer", Closed),
        ] {
            for prefix in [
                "ERROR ",
                "\x1b[31mERROR\x1b[0m[0001] ",
                "+0900 2026-10-10 12:00:00 WARN ",
            ] {
                assert_eq!(
                    super::classify_failure(&format!("{prefix}outbound/vless[proxy]: {cause}")),
                    Some(expected)
                );
            }
        }
        for line in [
            "ERROR outbound/direct[direct]: connection refused",
            "ERROR dns: EOF",
            "INFO outbound/vless[proxy]: EOF",
            "ERROR outbound/vless[proxy]: unknown error",
            "ERROR inbound/tun[tun-in]: EOF",
        ] {
            assert_eq!(super::classify_failure(line), None, "{line}");
        }
    }

    #[test]
    fn failure_counters_are_monotonic_and_saturating() {
        let counters = super::FailureCounters::default();
        counters.observe("ERROR outbound/vless[proxy]: EOF");
        let first = counters.snapshot();
        assert_eq!(first.closed, 1);
        assert_eq!(counters.snapshot().delta(first).closed, 0);
        counters
            .closed
            .store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
        counters.observe("ERROR outbound/vless[proxy]: EOF");
        assert_eq!(counters.snapshot().closed, u64::MAX);
    }

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
