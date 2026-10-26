use std::net::IpAddr;
use std::ops::Range;

const SECRET_KEYS: &[&str] = &[
    "password",
    "uuid",
    "public_key",
    "publickey",
    "short_id",
    "shortid",
    "pre_shared_key",
    "presharedkey",
    "private_key",
    "secret",
    "token",
    "auth",
    "psk",
    "x-hwid",
    // Xray names the VLESS and VMess user ID only `id`; a bare `id` would hide
    // ordinary fields such as `thread_id`.
    "\"id\"",
];
const PUBLIC_HOSTS: &[&str] = &["api.github.com", "github.com", "cp.cloudflare.com"];
const FILE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "log", "json", "txt", "toml", "yaml", "yml", "ps1", "msi", "zip", "dat",
    "db",
];

pub fn redact_report_text(text: &str) -> String {
    let text = redact_profiles(text);
    let text = redact_secrets(&text);
    let text = redact_uuids(&text);
    let text = redact_urls(&text);
    let text = redact_emails(&text);
    redact_addresses(&text)
}

fn redact_profiles(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut at = 0;
    while at < text.len() {
        let rest = &text[at..];
        let drive = rest.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && !text[..at]
                .chars()
                .next_back()
                .is_some_and(char::is_alphanumeric);
        if drive
            && rest.get(1..9).is_some_and(|prefix| {
                prefix.eq_ignore_ascii_case(":\\Users\\") || prefix.eq_ignore_ascii_case(":/Users/")
            })
        {
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
            // `_` is no boundary: `peer_public_key` hides like `public_key`.
            let previous = text[..at].chars().next_back();
            if !matched || previous.is_some_and(|ch| ch.is_ascii_alphanumeric()) {
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

/// Hides a UUID wherever it stands: VLESS and VMess user IDs also reach a log
/// without a key in front of them.
fn redact_uuids(text: &str) -> String {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    const UUID_LEN: usize = 36;
    let is_uuid_char = |ch: char| ch.is_alphanumeric() || ch == '-';
    let mut result = String::with_capacity(text.len());
    let mut at = 0;
    while at < text.len() {
        let rest = &text[at..];
        let is_uuid = rest.get(..UUID_LEN).is_some_and(|candidate| {
            let mut groups = candidate.split('-');
            GROUPS.iter().all(|&len| {
                groups.next().is_some_and(|group| {
                    group.len() == len && group.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            }) && groups.next().is_none()
                && !text[..at].chars().next_back().is_some_and(is_uuid_char)
                && !rest[UUID_LEN..].chars().next().is_some_and(is_uuid_char)
        });
        if is_uuid {
            result.push_str("<redacted>");
            at += UUID_LEN;
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
                // Engines write international names in punycode: `.xn--p1ai` is `.рф`.
                let punycode = tld.len() > 4
                    && tld
                        .get(..4)
                        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("xn--"))
                    && tld[4..]
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
                punycode
                    || tld.chars().count() >= 2
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
    address_words(text)
        .filter_map(|(start, word)| leading_ip(word).map(|(ip, end)| (ip, start..start + end)))
}

/// Replaces every public IP literal in an engine line with `[hidden]`, keeping
/// private, loopback, link-local and tunnel addresses. Go socket errors name
/// both ends wherever they occur, as in
/// `close tcp 172.19.0.1:54626->198.51.100.7:443: endpoint not connected`,
/// so addresses are found by what they are, not by the words before them.
pub fn hide_public_addresses(line: &str) -> String {
    let mut hidden = String::with_capacity(line.len());
    let mut copied = 0;
    for (ip, mut range) in ip_literals(line) {
        if !is_public_ip(ip) {
            continue;
        }
        if line[..range.start].ends_with('[') && line[range.end..].starts_with(']') {
            range = range.start - 1..range.end + 1;
        }
        hidden.push_str(&line[copied..range.start]);
        hidden.push_str("[hidden]");
        copied = range.end;
    }
    hidden.push_str(&line[copied..]);
    hidden
}

/// Whether `ip` can name a node or a site rather than this machine, its
/// local network or the tunnel.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            !(ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified())
        }
        IpAddr::V6(ip) => {
            !(ip.is_unique_local()
                || ip.is_loopback()
                || ip.is_unicast_link_local()
                || ip.is_unspecified())
        }
    }
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
        let word = &text[start..at];
        // Engines tag an address with its network, as in `tcp:203.0.113.5:443`:
        // the tag ends the word, so the address after it is a word of its own.
        if leading_ip(word).is_none()
            && let Some(tag_len) = network_tag_len(word)
        {
            at = start + tag_len + 1;
            return Some((start, &word[..tag_len]));
        }
        Some((start, word))
    })
}

/// Length of a leading `tag:` in front of more text. It is asked only of a word
/// that does not start with an IP literal, so an IPv6 address is never split.
fn network_tag_len(word: &str) -> Option<usize> {
    let tag_len = word
        .bytes()
        .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        .count();
    (word.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && word.as_bytes().get(tag_len) == Some(&b':')
        && word
            .as_bytes()
            .get(tag_len + 1)
            .is_some_and(|&byte| byte != b':'))
    .then_some(tag_len)
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

    #[test]
    fn punycode_names_are_hidden() {
        let input = "node.xn--e1afmkfd xn--e1afmkfd.test:443 XN--E1AFMKFD.XN--E1AFMKFD";
        assert_eq!(redact_report_text(input), "<host> <host>:443 <host>");
    }

    #[test]
    fn addresses_after_a_network_tag_are_hidden() {
        let input = "from tcp:192.0.2.7:51234 accepted udp:[2001:db8::7]:53 tcp:node.example.test:443 dns:2001:db8::53";
        assert_eq!(
            redact_report_text(input),
            "from tcp:<ip>:51234 accepted udp:[<ip>]:53 tcp:<host>:443 dns:<ip>"
        );
        assert_eq!(
            super::hide_public_addresses("tcp:203.0.113.5:443"),
            "tcp:[hidden]:443"
        );
    }

    #[test]
    fn engine_key_spellings_and_bare_uuids_are_hidden() {
        for text in [
            "\"publicKey\": \"value\"",
            "\"shortId\": \"value\"",
            "\"id\": \"value\"",
            "peer_public_key=value",
            "pre_shared_key: value",
            "PresharedKey = value",
        ] {
            let output = redact_report_text(text);
            assert!(!output.contains("value"), "{output}");
            assert!(output.contains("<redacted>"), "{output}");
        }
        assert_eq!(
            redact_report_text("user 00000000-0000-0000-0000-000000000000 rejected"),
            "user <redacted> rejected"
        );
    }

    #[test]
    fn profile_paths_on_every_drive_are_hidden() {
        for (input, expected) in [
            (r"D:\Users\Example\Rosetun", r"D:\Users\<user>\Rosetun"),
            ("e:/users/Example/rosetun", "e:/users/<user>/rosetun"),
            (r"\\?\C:\Users\Example\x", r"\\?\C:\Users\<user>\x"),
        ] {
            assert_eq!(redact_report_text(input), expected);
        }
    }

    #[test]
    fn ordinary_report_lines_stay_as_they_are() {
        let input = "Rosetun: 0.3.1\nsing-box: 1.12.10\nXray: 25.10.15\nDNS: 1\n\
            Rules: 12\nWindows 10.0.26300\nFirewall: Found\n\
            2026-10-26T10:00:00.123Z  INFO rosetun_helper::state: connected elapsed_ms=532 thread_id=4 stage=CheckingEngine\n";
        assert_eq!(redact_report_text(input), input);
    }
}
