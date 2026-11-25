//! Host-name validation shared by every protocol.

use std::net::IpAddr;

const MAX_HOST_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Lower-cases and validates a host name taken from the wire.
///
/// Returns `None` for an empty name, an IP literal, a label that is empty or
/// too long, or any byte outside letters, digits, `-`, `_` and `.`. One
/// trailing dot is dropped.
pub(super) fn normalize_host(raw: &[u8]) -> Option<String> {
    let raw = raw.strip_suffix(b".").unwrap_or(raw);
    if raw.is_empty() || raw.len() > MAX_HOST_LEN {
        return None;
    }
    let valid_bytes = raw
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid_bytes {
        return None;
    }
    if raw
        .split(|byte| *byte == b'.')
        .any(|label| label.is_empty() || label.len() > MAX_LABEL_LEN)
    {
        return None;
    }
    let host = std::str::from_utf8(raw).ok()?.to_ascii_lowercase();
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_cases_and_drops_the_trailing_dot() {
        assert_eq!(
            normalize_host(b"WWW.Example.COM.").as_deref(),
            Some("www.example.com")
        );
    }

    #[test]
    fn rejects_ip_literals_and_malformed_names() {
        let cases: [&[u8]; 12] = [
            b"",
            b".",
            b"192.0.2.1",
            b"2001:db8::1",
            b"[2001:db8::1]",
            b"a..example.com",
            b".example.com",
            b"exa mple.com",
            b"example.com:443",
            b"exa\xffmple.com",
            b"ex\0ample.com",
            b"caf\xc3\xa9.example.com",
        ];
        for case in cases {
            assert_eq!(normalize_host(case), None, "{case:?}");
        }
    }

    #[test]
    fn rejects_names_over_the_length_limits() {
        let label = "a".repeat(64);
        assert_eq!(
            normalize_host(format!("{label}.example.com").as_bytes()),
            None
        );
        let long = vec!["abcdefghi"; 30].join(".");
        assert_eq!(normalize_host(long.as_bytes()), None);
        let ok_label = "a".repeat(63);
        assert!(normalize_host(format!("{ok_label}.example.com").as_bytes()).is_some());
    }

    #[test]
    fn accepts_underscores_and_punycode_labels() {
        assert_eq!(
            normalize_host(b"_dmarc.xn--e1afmkfd.example.com").as_deref(),
            Some("_dmarc.xn--e1afmkfd.example.com")
        );
    }
}
