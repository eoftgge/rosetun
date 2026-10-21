use std::net::IpAddr;
use std::ops::Range;

const SECRET_KEYS: &[&str] = &[
    "password",
    "uuid",
    "public_key",
    "short_id",
    "private_key",
    "secret",
    "token",
    "auth",
    "psk",
    "x-hwid",
];
const PUBLIC_HOSTS: &[&str] = &["api.github.com", "github.com", "cp.cloudflare.com"];
const FILE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "log", "json", "txt", "toml", "yaml", "yml", "ps1", "msi", "zip", "dat",
    "db",
];

pub fn redact_report_text(text: &str) -> String {
    let text = redact_profiles(text);
    let text = redact_secrets(&text);
    let text = redact_urls(&text);
    let text = redact_emails(&text);
    redact_addresses(&text)
}

fn redact_profiles(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut at = 0;
    while at < text.len() {
        let rest = &text[at..];
        if rest.get(..9).is_some_and(|prefix| {
            prefix.eq_ignore_ascii_case("C:\\Users\\") || prefix.eq_ignore_ascii_case("C:/Users/")
        }) {
            let start = at + 9;
            let end = text[start..]
                .find(['\\', '/', '\n', '\r', '"', '\'', ',', ';'])
                .map_or(text.len(), |offset| start + offset);
            result.push_str(&text[at..start]);
            result.push_str("<user>");
            at = end;
        } else {
            let ch = rest.chars().next().expect("non-empty remainder");
            result.push(ch);
            at += ch.len_utf8();
        }
    }
    result
}

fn redact_secrets(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut at = 0;
    while at < text.len() {
        let rest = &text[at..];
        let found = SECRET_KEYS.iter().find_map(|key| {
            let matched = rest.get(..key.len())?.eq_ignore_ascii_case(key);
            let previous = text[..at].chars().next_back();
            if !matched || previous.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
                return None;
            }
            let mut pos = at + key.len();
            if text[pos..].starts_with(['"', '\'']) {
                pos += 1;
            }
            while text
                .as_bytes()
                .get(pos)
                .is_some_and(u8::is_ascii_whitespace)
            {
                pos += 1;
            }
            if !matches!(text.as_bytes().get(pos), Some(b':' | b'=')) {
                return None;
            }
            pos += 1;
            while text
                .as_bytes()
                .get(pos)
                .is_some_and(u8::is_ascii_whitespace)
            {
                pos += 1;
            }
            let quote = match text.as_bytes().get(pos) {
                Some(b'"' | b'\'') => {
                    let quote = text.as_bytes()[pos];
                    pos += 1;
                    Some(quote)
                }
                _ => None,
            };
            let end = if let Some(quote) = quote {
                text[pos..]
                    .find(quote as char)
                    .map_or(text.len(), |offset| pos + offset)
            } else {
                text[pos..]
                    .find(|ch: char| {
                        ch.is_whitespace() || matches!(ch, ',' | ';' | '&' | '}' | ']' | '"' | '\'')
                    })
                    .map_or(text.len(), |offset| pos + offset)
            };
            (end > pos).then_some((pos, end))
        });
        if let Some((start, end)) = found {
            result.push_str(&text[at..start]);
            result.push_str("<redacted>");
            at = end;
        } else {
            let ch = rest.chars().next().expect("non-empty remainder");
            result.push(ch);
            at += ch.len_utf8();
        }
    }
    result
}

fn redact_urls(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut at = 0;
    while at < text.len() {
        let rest = &text[at..];
        let scheme_len = rest
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
            .count();
        if rest.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && rest
                .get(scheme_len..)
                .is_some_and(|suffix| suffix.starts_with("://"))
            && !text[..at]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_ascii_alphanumeric())
        {
            let start = at + scheme_len + 3;
            let mut end = start
                + text[start..]
                    .find(|ch: char| ch.is_whitespace() || matches!(ch, '<' | '>' | '"' | '\''))
                    .unwrap_or(text.len() - start);
            while end > start && matches!(text.as_bytes()[end - 1], b',' | b';' | b')' | b']') {
                end -= 1;
            }
            if end > start {
                result.push_str("<url>");
                at = end;
                continue;
            }
        }
        let ch = rest.chars().next().expect("non-empty remainder");
        result.push(ch);
        at += ch.len_utf8();
    }
    result
}

fn redact_emails(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut at = 0;
    while at < text.len() {
        let rest = &text[at..];
        let local_len: usize = rest
            .chars()
            .take_while(|ch| ch.is_alphanumeric() || matches!(ch, '.' | '-' | '_' | '+'))
            .map(char::len_utf8)
            .sum();
        if local_len > 0 && rest[local_len..].starts_with('@') {
            let domain = &rest[local_len + 1..];
            let domain_len: usize = domain
                .chars()
                .take_while(|ch| ch.is_alphanumeric() || matches!(ch, '.' | '-'))
                .map(char::len_utf8)
                .sum();
            if domain[..domain_len].contains('.') {
                result.push_str("<redacted>");
                at += local_len + 1 + domain_len;
                continue;
            }
        }
        let ch = rest.chars().next().expect("non-empty remainder");
        result.push(ch);
        at += ch.len_utf8();
    }
    result
}

fn redact_addresses(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut copied = 0;
    for (start, word) in address_words(text) {
        result.push_str(&text[copied..start]);
        copied = start + word.len();
        let core = word.trim_end_matches(['.', ':']);
        let ip = leading_ip(word);
        let safe_ip = ip.is_some_and(|(ip, _)| {
            matches!(ip.to_string().as_str(), "127.0.0.1" | "::1" | "0.0.0.0")
        });
        let host = core
            .rsplit_once(':')
            .filter(|(_, port)| port.bytes().all(|byte| byte.is_ascii_digit()))
            .map_or(core, |(host, _)| host);
        let hostname = host.contains('.')
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label
                        .chars()
                        .all(|ch| ch.is_alphanumeric() || matches!(ch, '-' | '_'))
            })
            && host.rsplit('.').next().is_some_and(|tld| {
                tld.chars().count() >= 2
                    && tld.chars().all(char::is_alphabetic)
                    && !FILE_EXTENSIONS
                        .iter()
                        .any(|extension| tld.eq_ignore_ascii_case(extension))
            });
        if let Some((_, end)) = ip.filter(|_| !safe_ip) {
            result.push_str("<ip>");
            result.push_str(&word[end..]);
        } else if ip.is_none()
            && hostname
            && !PUBLIC_HOSTS
                .iter()
                .any(|public| host.eq_ignore_ascii_case(public))
        {
            result.push_str("<host>");
            result.push_str(&word[host.len()..]);
        } else {
            result.push_str(word);
        }
    }
    result.push_str(&text[copied..]);
    result
}

/// Every IP literal in `text` with its byte range, found in one pass. Brackets,
/// ports and the colon Go puts after a port stay outside the range; an IPv6
/// zone stays inside.
pub fn ip_literals(text: &str) -> impl Iterator<Item = (IpAddr, Range<usize>)> + '_ {
    address_words(text).filter_map(|(start, word)| {
        leading_ip(word).map(|(ip, end)| (ip, start..start + end))
    })
}

fn address_words(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let is_address_char =
        |ch: char| ch.is_alphanumeric() || matches!(ch, '.' | ':' | '-' | '_' | '%');
    let mut at = 0;
    std::iter::from_fn(move || {
        let start = at + text[at..].find(is_address_char)?;
        at = text[start..]
            .find(|ch: char| !is_address_char(ch))
            .map_or(text.len(), |offset| start + offset);
        Some((start, &text[start..at]))
    })
}

fn leading_ip(word: &str) -> Option<(IpAddr, usize)> {
    let core = word.trim_end_matches(['.', ':']);
    let address = word.split_once('%').map_or(word, |(ip, _)| ip);
    address
        .parse::<IpAddr>()
        .ok()
        .map(|ip| (ip, word.len()))
        .or_else(|| {
            address
                .trim_end_matches(['.', ':'])
                .parse::<IpAddr>()
                .ok()
                .map(|ip| (ip, core.len()))
        })
        .or_else(|| {
            // Go errors put a colon after the port: `dial tcp <ip>:443: i/o timeout`,
            // and an arrow between the ends of a socket: `<ip>:54626-><ip>:443`.
            address
                .trim_end_matches(['.', ':'])
                .rsplit_once(':')
                .and_then(|(head, _)| {
                    head.parse::<std::net::Ipv4Addr>()
                        .ok()
                        .map(|ip| (IpAddr::V4(ip), head.len()))
                })
        })
}

#[cfg(test)]
mod tests {
    use super::redact_report_text;

    #[test]
    fn redacts_addresses_without_changing_local_sentinels() {
        let input = "192.0.2.3:443 [2001:db8::42]:8443 2001:db8::5 2001:db8:: 192.0.2.3:https 127.0.0.1 ::1 0.0.0.0";
        assert_eq!(
            redact_report_text(input),
            "<ip>:443 [<ip>]:8443 <ip> <ip> <ip>:https 127.0.0.1 ::1 0.0.0.0"
        );
        assert_eq!(
            redact_report_text("dial tcp 203.0.113.5:443: i/o timeout"),
            "dial tcp <ip>:443: i/o timeout"
        );
    }

    #[test]
    fn redacts_urls_and_hosts_but_not_project_hosts() {
        let input = "https://token@example.com/path?a=b node.example.com:443 api.github.com github.com cp.cloudflare.com 198.51.100.5";
        assert_eq!(
            redact_report_text(input),
            "<url> <host>:443 api.github.com github.com cp.cloudflare.com <ip>"
        );
    }

    #[test]
    fn keeps_file_names_without_exempting_real_hosts() {
        assert_eq!(
            redact_report_text("xray.exe wintun.dll helper.log config.v3.json node.example.com"),
            "xray.exe wintun.dll helper.log config.v3.json <host>"
        );
        for extension in super::FILE_EXTENSIONS {
            for suffix in [extension.to_string(), extension.to_ascii_uppercase()] {
                let filename = format!("support.{suffix}");
                assert_eq!(redact_report_text(&filename), filename);
            }
        }
        assert_eq!(redact_report_text("NODE.EXAMPLE.COM:443"), "<host>:443");
    }

    #[test]
    fn redacts_all_credential_keys() {
        for key in super::SECRET_KEYS {
            for text in [
                format!("{key}=value"),
                format!("\"{key}\": \"value\""),
                format!("?{key}=value&next=ok"),
            ] {
                let output = redact_report_text(&text);
                assert!(!output.contains("value"), "{key}: {output}");
                assert!(output.contains("<redacted>"), "{key}: {output}");
            }
        }
    }

    #[test]
    fn redacts_windows_profile_and_verbose_sites() {
        let input = "C:\\Users\\Example User\\AppData 2026-10-15T15:02:03Z WARN target=example.com login.example.com:443 uuid=123e4567-e89b-12d3-a456-426614174000";
        let output = redact_report_text(input);
        assert!(output.contains("C:\\Users\\<user>\\AppData"));
        assert!(output.contains("2026-10-15T15:02:03Z WARN"));
        assert!(output.contains("target=<host> <host>:443 uuid=<redacted>"));
        assert!(!output.contains("Example User"));
    }

    #[test]
    fn email_addresses_do_not_leave_the_local_part_visible() {
        assert_eq!(
            redact_report_text("contact=user@example.com"),
            "contact=<redacted>"
        );
    }

    #[test]
    fn unicode_domains_and_ipv6_zones_are_hidden() {
        let input = "узел.example.com магазин.рф [2001:db8::a%7]:443";
        assert_eq!(redact_report_text(input), "<host> <host> [<ip>]:443");
    }

    #[test]
    fn ordinary_logs_keep_levels_times_and_error_codes() {
        let input = "2026-10-15T15:02:03Z INFO helper::state: ErrorCode::NoNetwork (code 10061)\n";
        assert_eq!(redact_report_text(input), input);
    }
}
