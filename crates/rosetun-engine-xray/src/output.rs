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

pub(crate) fn hide_destinations(line: &str) -> String {
    let mut line = line.to_owned();
    for marker in ["accepted tcp:", "accepted udp:", "to tcp:", "to udp:"] {
        if let Some(position) = line.find(marker) {
            let start = position + marker.len();
            let end = line[start..]
                .find(char::is_whitespace)
                .map_or(line.len(), |offset| start + offset);
            if end > start {
                line.replace_range(start..end, "[hidden]");
            }
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_documentation_only_xray_errors() {
        let lines = include_str!("../tests/fixtures/output-errors.txt");
        let kinds = lines.lines().map(classify_failure).collect::<Vec<_>>();
        assert_eq!(kinds, vec![
            Some(OutboundFailure::Unreachable),
            Some(OutboundFailure::Unreachable),
            Some(OutboundFailure::Rejected),
            Some(OutboundFailure::Closed),
        ]);
    }

    #[test]
    fn hides_visited_destination_from_access_like_error() {
        let line = "2026/10/14 12:00:00 [Warning] accepted tcp:example.com:443 to tcp:198.51.100.1:443";
        let hidden = hide_destinations(line);
        assert!(!hidden.contains("example.com"));
        assert!(!hidden.contains("198.51.100.1"));
    }
}
