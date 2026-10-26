use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use rosetun_engine::{OutboundFailure, OutboundFailures};

#[derive(Debug, Default)]
pub(crate) struct FailureCounters {
    unreachable: AtomicU64,
    rejected: AtomicU64,
    closed: AtomicU64,
}

impl FailureCounters {
    pub(crate) fn observe(&self, line: &str) {
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

    pub(crate) fn snapshot(&self) -> OutboundFailures {
        OutboundFailures {
            unreachable: self.unreachable.load(Ordering::Acquire),
            rejected: self.rejected.load(Ordering::Acquire),
            closed: self.closed.load(Ordering::Acquire),
        }
    }
}

pub(crate) fn line_level(line: &str) -> LineLevel {
    if line.contains("[Error]") || line.contains("[Fatal]") {
        LineLevel::Error
    } else if line.contains("[Warning]") {
        LineLevel::Warn
    } else if line.contains("[Debug]") {
        LineLevel::Debug
    } else {
        LineLevel::Info
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LineLevel {
    Debug,
    Info,
    Warn,
    Error,
}

fn classify_failure(line: &str) -> Option<OutboundFailure> {
    if !matches!(line_level(line), LineLevel::Error | LineLevel::Warn) {
        return None;
    }
    let message = line.to_ascii_lowercase();
    if !(message.contains("outbound") || message.contains("reality")) {
        return None;
    }
    if [
        "reality verification failed",
        "handshake failed",
        "tls: bad certificate",
        "certificate verify failed",
        "authentication failed",
        "invalid password",
    ]
    .iter()
    .any(|marker| message.contains(marker))
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
    .any(|marker| message.contains(marker))
    {
        return Some(OutboundFailure::Unreachable);
    }
    if [" eof", "connection reset", "forcibly closed", "broken pipe"]
        .iter()
        .any(|marker| message.contains(marker))
    {
        return Some(OutboundFailure::Closed);
    }
    None
}

/// The line as the service journal records it: unchanged while the verbose
/// log is on, without destinations otherwise.
pub(crate) fn journal_line(line: &str, verbose: bool) -> String {
    if verbose {
        line.to_owned()
    } else {
        hide_destinations(line)
    }
}

/// Hides the sites and the node a line names, keeping the failure cause and
/// the local and tunnel addresses it needs to be read.
pub(crate) fn hide_destinations(line: &str) -> String {
    let mut hidden = line.to_owned();
    for marker in ["tcp:", "udp:"] {
        hide_xray_destinations(&mut hidden, marker);
    }
    rosetun_config::hide_public_addresses(&hidden)
}

/// Xray writes a destination as `tcp:host:port` or `udp:host:port`, as in
/// `accepted tcp:example.com:443` or `[tcp:[2001:db8::1]:443]`: the host is
/// hidden there whatever it is, unless it is a local or tunnel address.
fn hide_xray_destinations(line: &mut String, marker: &str) {
    let mut cursor = 0;
    while let Some(relative) = line[cursor..].find(marker) {
        let position = cursor + relative;
        let start = position + marker.len();
        let preceded_by_word = line[..position]
            .chars()
            .next_back()
            .is_some_and(char::is_alphanumeric);
        let end = destination_end(line, start);
        if preceded_by_word
            || end == start
            || line[start..end] == *"[hidden]"
            || is_local_destination(&line[start..end])
        {
            cursor = end.max(start);
            continue;
        }
        line.replace_range(start..end, "[hidden]");
        cursor = start + "[hidden]".len();
    }
}

fn destination_end(line: &str, start: usize) -> usize {
    let rest = &line[start..];
    let host_end = if rest.starts_with('[') {
        match rest.find(']') {
            Some(close) => close + 1,
            None => return start,
        }
    } else {
        rest.find(|ch: char| ch.is_whitespace() || matches!(ch, ']' | ',' | ')' | '>'))
            .unwrap_or(rest.len())
    };
    let mut end = host_end;
    if rest.as_bytes().get(end) == Some(&b':') {
        let digits = rest[end + 1..]
            .find(|ch: char| !ch.is_ascii_digit())
            .unwrap_or(rest.len() - end - 1);
        if digits > 0 {
            end += 1 + digits;
        }
    }
    start + rest[..end].trim_end_matches([':', '.']).len()
}

fn is_local_destination(destination: &str) -> bool {
    let host = match destination.strip_prefix('[') {
        Some(bracketed) => bracketed
            .split_once(']')
            .map_or(bracketed, |(host, _)| host),
        None => destination
            .rsplit_once(':')
            .filter(|(_, port)| port.bytes().all(|byte| byte.is_ascii_digit()))
            .map_or(destination, |(host, _)| host),
    };
    destination
        .parse::<IpAddr>()
        .or_else(|_| host.parse::<IpAddr>())
        .is_ok_and(|ip| !rosetun_config::is_public_ip(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_documentation_only_xray_errors() {
        let lines = include_str!("../tests/fixtures/output-errors.txt");
        let kinds = lines.lines().map(classify_failure).collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![
                Some(OutboundFailure::Unreachable),
                Some(OutboundFailure::Unreachable),
                Some(OutboundFailure::Rejected),
                Some(OutboundFailure::Closed),
            ]
        );
    }

    #[test]
    fn hides_visited_destination_from_access_like_error() {
        let line =
            "2026/10/14 12:00:00 [Warning] accepted tcp:example.com:443 to tcp:198.51.100.1:443";
        let hidden = hide_destinations(line);
        assert_eq!(
            hidden,
            "2026/10/14 12:00:00 [Warning] accepted tcp:[hidden] to tcp:[hidden]"
        );
    }

    #[test]
    fn hides_the_node_in_every_fixture_line() {
        let lines = include_str!("../tests/fixtures/output-errors.txt");
        let hidden = lines.lines().map(hide_destinations).collect::<Vec<_>>();
        assert_eq!(
            hidden,
            vec![
                "2026/10/14 12:00:00 [Warning] proxy/vless/outbound: failed to process outbound traffic > dial tcp [hidden]:443: i/o timeout",
                "2026/10/14 12:00:01 [Error] proxy/trojan/outbound: failed to dial [hidden]:443: connectex: connection refused",
                "2026/10/14 12:00:02 [Warning] proxy/vless/outbound: reality verification failed for [hidden]:443",
                "2026/10/14 12:00:03 [Warning] proxy/vmess/outbound: failed to process outbound traffic > connection reset by peer",
            ]
        );
    }

    #[test]
    fn hides_every_public_address_and_name_in_a_line() {
        for (line, expected) in [
            (
                "[Info] [42] proxy/freedom: dialing to tcp:203.0.113.4:443 > dial tcp 192.0.2.5:443->198.51.100.6:443: i/o timeout",
                "[Info] [42] proxy/freedom: dialing to tcp:[hidden] > dial tcp [hidden]:443->[hidden]:443: i/o timeout",
            ),
            (
                "from 127.0.0.1:50110 accepted tcp:example.com:443 [socks -> proxy] and accepted udp:www.example.com:443",
                "from 127.0.0.1:50110 accepted tcp:[hidden] [socks -> proxy] and accepted udp:[hidden]",
            ),
            (
                "[Info] app/dispatcher: taking detour [proxy] for [tcp:example.com:443] and [udp:[2001:db8::8]:53]",
                "[Info] app/dispatcher: taking detour [proxy] for [tcp:[hidden]] and [udp:[hidden]]",
            ),
            (
                "[Warning] failed to open connection to tcp:198.51.100.9:443: read udp [2001:db8::1]:5300->203.0.113.7:53: refused",
                "[Warning] failed to open connection to tcp:[hidden]: read udp [hidden]:5300->[hidden]:53: refused",
            ),
        ] {
            let hidden = hide_destinations(line);
            assert_eq!(hidden, expected, "{line}");
            assert_eq!(hide_destinations(&hidden), hidden);
        }
    }

    #[test]
    fn the_verbose_log_keeps_the_line_unchanged() {
        let line = "from 127.0.0.1:50110 accepted tcp:example.com:443 > dial tcp 192.0.2.5:443: i/o timeout";
        assert_eq!(journal_line(line, true), line);
        assert_eq!(journal_line(line, false), hide_destinations(line));
    }

    #[test]
    fn keeps_local_and_tunnel_addresses() {
        for line in [
            "from 127.0.0.1:50110 accepted tcp:10.0.0.2:53 [socks -> direct]",
            "[Warning] dial tcp 172.19.0.1:54626->192.168.1.1:53: i/o timeout",
            "[Info] accepted udp:[fdfe:dcba:9876::1]:53 from [::1]:5000",
            "[Info] Xray 25.10.15 started",
            "",
        ] {
            assert_eq!(hide_destinations(line), line);
        }
    }
}
