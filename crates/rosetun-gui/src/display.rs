use std::time::{Duration, UNIX_EPOCH};

use eframe::egui;
use rosetun_core::{provider_text, terminal_text};

use crate::strings;

pub(crate) fn safe_text(value: &str) -> String {
    let sanitized = terminal_text(value);
    regional_flags(&sanitized)
}

pub(crate) fn safe_multiline(value: &str) -> String {
    value
        .split('\n')
        .map(|line| safe_text(line.strip_suffix('\r').unwrap_or(line)))
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn provider_multiline(value: &str, subscription_url: &str) -> String {
    value
        .split('\n')
        .map(|line| {
            let line = line.strip_suffix('\r').unwrap_or(line);
            safe_text(&provider_text(line, subscription_url))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn regional_flags(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(character) = chars.next() {
        if is_regional_indicator(character) {
            if let Some(&next) = chars.peek()
                && is_regional_indicator(next)
            {
                chars.next();
                let first = (character as u32 - REGIONAL_START + b'A' as u32) as u8 as char;
                let second = (next as u32 - REGIONAL_START + b'A' as u32) as u8 as char;
                output.push('[');
                output.push(first);
                output.push(second);
                output.push(']');
            }
            continue;
        }
        output.push(character);
    }
    output
}

const REGIONAL_START: u32 = 0x1f1e6;
const REGIONAL_END: u32 = 0x1f1ff;

fn is_regional_indicator(character: char) -> bool {
    (REGIONAL_START..=REGIONAL_END).contains(&(character as u32))
}

pub(crate) fn session_duration(since_unix: Option<u64>, now_unix: u64) -> Option<Duration> {
    since_unix.map(|since| Duration::from_secs(now_unix.saturating_sub(since)))
}

pub(crate) fn session_text(since_unix: Option<u64>, now_unix: u64) -> String {
    let duration = session_duration(since_unix, now_unix).unwrap_or_default();
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3_600;
    let minutes = (total_seconds % 3_600) / 60;
    let seconds = total_seconds % 60;
    strings::session_time(hours, minutes, seconds)
}

pub(crate) fn now_unix() -> u64 {
    UNIX_EPOCH
        .elapsed()
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

pub(crate) fn safe_web_url(value: &str) -> Option<String> {
    let parsed = url::Url::parse(value).ok()?;
    if matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some() {
        Some(parsed.to_string())
    } else {
        None
    }
}

pub(crate) fn open_web_link(ctx: &egui::Context, value: &str) -> bool {
    let Some(url) = safe_web_url(value) else {
        return false;
    };
    ctx.open_url(egui::OpenUrl::new_tab(url));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_pairs_are_rendered_as_country_codes() {
        assert_eq!(safe_text("DE 🇩🇪 FR 🇫🇷"), "DE [DE] FR [FR]");
    }

    #[test]
    fn adjacent_flags_are_rendered_independently() {
        assert_eq!(safe_text("🇩🇪🇫🇷"), "[DE][FR]");
    }

    #[test]
    fn isolated_regional_indicators_are_removed() {
        assert_eq!(safe_text("🇩🇪🇫"), "[DE]");
        assert_eq!(safe_text("a\u{1f1e6}b"), "ab");
        assert_eq!(safe_text("\u{1f1eb}"), "");
    }

    #[test]
    fn controls_are_sanitized_before_flags_are_rendered() {
        assert_eq!(safe_text("Provider — 100%"), "Provider — 100%");
        assert_eq!(safe_text("🇩🇪\u{202e}\t🇫🇷"), "[DE]  [FR]");
    }

    #[test]
    fn multiline_diagnostics_keep_line_boundaries() {
        assert_eq!(
            safe_multiline("first\nsecond\r\n\nthird\n"),
            "first\nsecond\n\nthird\n"
        );
    }

    #[test]
    fn provider_diagnostics_keep_line_boundaries_and_redact_url() {
        let output = provider_multiline(
            "first https://sub.example/private-token?key=query-secret\r\nsecond",
            "https://sub.example/private-token?key=query-secret",
        );
        assert_eq!(output, "first https://sub.example/…\nsecond");
        assert!(!output.contains("private-token"));
        assert!(!output.contains("query-secret"));
    }

    #[test]
    fn session_duration_handles_missing_future_and_long_sessions() {
        assert_eq!(session_duration(None, 100), None);
        assert_eq!(session_duration(Some(100), 99), Some(Duration::ZERO));
        assert_eq!(
            session_duration(Some(0), 90_061),
            Some(Duration::from_secs(90_061))
        );
        assert_eq!(session_text(None, 100), "00:00:00");
        assert_eq!(session_text(Some(100), 99), "00:00:00");
        assert_eq!(session_text(Some(0), 90_061), "25:01:01");
    }

    #[test]
    fn only_http_and_https_links_are_openable() {
        assert_eq!(
            safe_web_url("http://example.com"),
            Some("http://example.com/".to_owned())
        );
        assert_eq!(
            safe_web_url("https://example.com/path"),
            Some("https://example.com/path".to_owned())
        );
        assert_eq!(safe_web_url("file:///secret"), None);
        assert_eq!(safe_web_url("javascript:alert(1)"), None);
        assert_eq!(safe_web_url("mailto:help@example.com"), None);
        assert_eq!(safe_web_url("https://"), None);
    }
}
