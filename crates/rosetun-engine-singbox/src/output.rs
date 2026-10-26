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
    // Only the proxy outbound can speak REALITY, but sing-box reports its
    // failure under whoever dialled: with DNS as the only traffic the line is
    // `router: process DNS packet: reality verification failed`, with no tag.
    if plain.contains("reality verification failed") {
        return Some(OutboundFailure::Rejected);
    }
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

/// Hides the sites and the node a line names, keeping the failure cause and
/// the local and tunnel addresses it needs to be read.
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
    rosetun_config::hide_public_addresses(&hidden)
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
        .find_map(word_level)
}

fn word_level(word: &str) -> Option<LineLevel> {
    let level = word.split_once('[').map_or(word, |(prefix, _)| prefix);
    match level {
        "TRACE" => Some(LineLevel::Trace),
        "DEBUG" => Some(LineLevel::Debug),
        "INFO" => Some(LineLevel::Info),
        "WARN" => Some(LineLevel::Warn),
        "ERROR" | "FATAL" | "PANIC" => Some(LineLevel::Error),
        _ => None,
    }
}

/// Whether the line is about one connection: sing-box puts the
/// connection's id and age after the level, as in
/// `ERROR [1184364709 2.62s] connection: connection download closed: ...`.
/// Engine lines (start, config, the DNS module, a crash) carry none.
pub(super) fn is_connection_line(line: &str) -> bool {
    let plain = strip_ansi_csi(line);
    let mut words = plain
        .split_whitespace()
        .take(6)
        .skip_while(|word| word_level(word).is_none())
        .skip(1);
    let (Some(id), Some(age)) = (words.next(), words.next()) else {
        return false;
    };
    let id = id.strip_prefix('[').unwrap_or_default();
    let age = age.strip_suffix(']').unwrap_or_default();
    !id.is_empty()
        && id.bytes().all(|byte| byte.is_ascii_digit())
        && age.starts_with(|first: char| first.is_ascii_digit())
}

/// The FATAL sing-box prints when Wintun still holds the adapter of a killed
/// predecessor: creating it collides with the old device that Windows has
/// not removed yet, and opening it fails because the interface is gone.
pub(super) fn is_adapter_busy_message(line: &str) -> bool {
    let plain = strip_ansi_csi(line);
    let fatal = plain
        .split_whitespace()
        .take(4)
        .any(|word| word.split_once('[').map_or(word, |(prefix, _)| prefix) == "FATAL");
    let Some((_, configure)) = plain.split_once("configure tun interface:") else {
        return false;
    };
    let Some((_, create)) = configure.split_once("create adapter:") else {
        return false;
    };
    let create = create.split([')', '|']).next().unwrap_or_default();
    fatal && create.contains("already exists")
}

#[cfg(test)]
mod tests {
    use super::{LineLevel, is_adapter_busy_message, line_level};

    #[test]
    fn hides_destinations_and_the_server_but_not_the_failure_cause() {
        let line = "ERROR [123 5.0s] connection: open connection to 198.51.100.20:443 using outbound/vless[proxy]: dial tcp 203.0.113.10:443: i/o timeout";
        let hidden = super::hide_destinations(line);
        assert_eq!(
            hidden,
            "ERROR [123 5.0s] connection: open connection to [hidden] using outbound/vless[proxy]: dial tcp [hidden]:443: i/o timeout"
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
                "+0900 2026-10-10 01:15:47 ERROR connection: open connection to [hidden] using outbound/vless[proxy]: dial tcp [hidden]:443: EOF",
            ),
        ] {
            assert_eq!(super::hide_destinations(line), expected, "{line}");
        }
    }

    #[test]
    fn hides_public_addresses_wherever_a_socket_error_puts_them() {
        for (line, expected) in [
            (
                "ERROR engine_output: +0300 2026-10-21 22:08:32 ERROR [1184364709 1.84s] connection: connection download closed: close tcp 172.19.0.1:54626->198.51.100.7:443: endpoint not connected stream=\"stderr\"",
                "ERROR engine_output: +0300 2026-10-21 22:08:32 ERROR [1184364709 1.84s] connection: connection download closed: close tcp 172.19.0.1:54626->[hidden]:443: endpoint not connected stream=\"stderr\"",
            ),
            (
                "ERROR [77 3.1s] connection: connection upload closed: read tcp 172.19.0.1:50112->192.0.2.44:443: wsarecv: An existing connection was forcibly closed by the remote host.",
                "ERROR [77 3.1s] connection: connection upload closed: read tcp 172.19.0.1:50112->[hidden]:443: wsarecv: An existing connection was forcibly closed by the remote host.",
            ),
            (
                "ERROR [78 9.0s] connection: packet connection closed: read udp 172.19.0.1:61000->198.51.100.53:53: i/o timeout",
                "ERROR [78 9.0s] connection: packet connection closed: read udp 172.19.0.1:61000->[hidden]:53: i/o timeout",
            ),
            (
                "ERROR [79 0.4s] connection: connection download closed: write tcp [fdfe:dcba:9876::1]:50113->[2001:db8::7]:443: broken pipe",
                "ERROR [79 0.4s] connection: connection download closed: write tcp [fdfe:dcba:9876::1]:50113->[hidden]:443: broken pipe",
            ),
            (
                "ERROR outbound/vless[proxy]: dial tcp 203.0.113.10:443: i/o timeout",
                "ERROR outbound/vless[proxy]: dial tcp [hidden]:443: i/o timeout",
            ),
            (
                "ERROR dns: raw-read udp [::ffff:192.0.2.9]:53 from 2001:db8::1: refused",
                "ERROR dns: raw-read udp [hidden]:53 from [hidden]: refused",
            ),
            (
                "INFO inbound/tun[tun-in]: 127.0.0.1:9090 10.0.0.2 192.168.1.1:53 169.254.10.1 [::1]:9090 fe80::1%7 0.0.0.0",
                "INFO inbound/tun[tun-in]: 127.0.0.1:9090 10.0.0.2 192.168.1.1:53 169.254.10.1 [::1]:9090 fe80::1%7 0.0.0.0",
            ),
        ] {
            let hidden = super::hide_destinations(line);
            assert_eq!(hidden, expected, "{line}");
            assert_eq!(super::hide_destinations(&hidden), hidden);
        }
    }

    #[test]
    fn lines_without_addresses_are_unchanged() {
        for line in [
            "+0300 2026-10-21 22:08:32 INFO [1184364709 1.84s] sing-box started (1.84s)",
            "WARN[0000] inbound/tun[tun-in]: open interface take too much time to finish!",
            "FATAL[0015] start service: create adapter: Cannot create a file when that file already exists.",
            "",
        ] {
            assert_eq!(super::hide_destinations(line), line);
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
        assert_eq!(
            super::classify_failure(
                "+0300 2026-10-14 16:46:24 ERROR [2202218134 261ms] router: process DNS packet: reality verification failed"
            ),
            Some(Rejected)
        );
        assert_eq!(
            super::classify_failure("INFO router: process DNS packet: reality verification failed"),
            None
        );
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

    #[test]
    fn recognizes_lines_about_one_connection() {
        for line in [
            "+0300 2026-10-21 20:05:11 ERROR [3021546114 2.62s] connection: connection download closed: close tcp 172.19.0.1:50112->[hidden]:443: endpoint not connected",
            "+0300 2026-10-21 20:05:12 ERROR [2202218134 5.01s] connection: open connection to [hidden] using outbound/direct[direct]: dial tcp [hidden]:443: i/o timeout",
            "+0300 2026-10-21 20:05:13 INFO [2202218135 0ms] inbound/tun[tun-in]: inbound connection to [hidden]",
            "\x1b[31mERROR\x1b[0m [77 1m3s] outbound/vless[proxy]: EOF",
        ] {
            assert!(super::is_connection_line(line), "{line}");
        }
        for line in [
            "+0900 2026-10-03 02:24:28 INFO sing-box started (0.62s)",
            "+0900 2026-10-03 02:24:27 INFO inbound/tun[tun-in]: started at rosetun0",
            "WARN[0000] inbound/tun[tun-in]: open interface take too much time to finish!",
            "FATAL[0015] start service: create adapter: Cannot create a file when that file already exists.",
            "+0300 2026-10-21 20:05:14 ERROR dns: exchange failed for [hidden] IN A: timeout",
            "ERROR [hidden] connection: reset",
            "goroutine 1 [running]:",
            "",
        ] {
            assert!(!super::is_connection_line(line), "{line}");
        }
    }

    #[test]
    fn recognizes_an_adapter_still_being_removed() {
        const FATAL: &str = "FATAL[0015] start service: start inbound/tun[tun-in]: configure tun interface: (create adapter: Cannot create a file when that file already exists. | open existing adapter: Element not found.)";
        assert!(is_adapter_busy_message(FATAL));
        assert!(is_adapter_busy_message(&format!(
            "+0900 2026-10-19 12:00:00 \x1b[31m{}",
            FATAL.replacen("FATAL", "FATAL\x1b[0m", 1)
        )));
        for line in [
            "FATAL[0015] start service: start inbound/tun[tun-in]: configure tun interface: (create adapter: Access is denied. | open existing adapter: Element not found.)",
            "FATAL[0015] start service: start inbound/tun[tun-in]: configure tun interface: (create adapter: Access is denied. | open existing adapter: already exists)",
            "ERROR[0015] start service: start inbound/tun[tun-in]: configure tun interface: (create adapter: Cannot create a file when that file already exists.)",
            "FATAL[0015] start service: create adapter: Cannot create a file when that file already exists.",
            "WARN inbound/tun[tun-in]: open interface take too much time to finish!",
        ] {
            assert!(!is_adapter_busy_message(line), "{line}");
        }
    }
}
