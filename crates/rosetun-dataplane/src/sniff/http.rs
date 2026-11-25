//! HTTP/1.x request-line and `Host` header sniffer.

use super::hostname::normalize_host;
use super::{Probe, Protocol, Sniffed};

const KNOWN_METHODS: [&[u8]; 8] = [
    b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"OPTIONS", b"TRACE", b"PATCH",
];

const MAX_METHOD_LEN: usize = 7;
const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Probes the leading bytes of a TCP stream for an HTTP/1.x request.
///
/// Recognises standard methods except `CONNECT` (handled directly by the
/// proxy), extracts the `Host` header (case-insensitive) or falls back to an
/// absolute-form request target when no `Host` header is sent. IP literals
/// yield `domain: None`.
pub fn probe_http(buf: &[u8]) -> Probe {
    if buf.is_empty() {
        return Probe::NeedMore;
    }

    let Some(first_nl) = find_byte(buf, b'\n') else {
        return probe_incomplete_request_line(buf);
    };

    let request_line = strip_trailing_cr(&buf[..first_nl]);
    let Some(target_host) = parse_request_line(request_line) else {
        return Probe::NotThis;
    };

    let mut pos = first_nl + 1;
    let mut header_host: Option<Option<String>> = None;

    while pos < buf.len() {
        let rest = &buf[pos..];
        let Some(nl) = find_byte(rest, b'\n') else {
            if rest.len() > MAX_HEADER_BYTES || buf.len() > MAX_HEADER_BYTES {
                if let Some(domain) = header_host.flatten().or(target_host) {
                    return Probe::Found(Sniffed {
                        protocol: Protocol::Http,
                        domain: Some(domain),
                    });
                }
                return Probe::NotThis;
            }
            // Reject control characters that cannot appear in a header line
            // while still allowing a trailing CR waiting for LF.
            let check = rest.strip_suffix(b"\r").unwrap_or(rest);
            if check
                .iter()
                .any(|b| (*b < 0x20 && *b != b'\t') || *b == 0x7f)
            {
                return Probe::NotThis;
            }
            return Probe::NeedMore;
        };

        let line = strip_trailing_cr(&rest[..nl]);
        pos += nl + 1;

        if line.is_empty() {
            let domain = header_host.flatten().or(target_host);
            return Probe::Found(Sniffed {
                protocol: Protocol::Http,
                domain,
            });
        }

        let Some(colon) = find_byte(line, b':') else {
            return Probe::NotThis;
        };
        let name = &line[..colon];
        if !is_valid_header_name(name) {
            return Probe::NotThis;
        }
        let value = trim_ows(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"host") && header_host.is_none() {
            header_host = Some(parse_host_authority(value));
        }
    }

    if buf.len() >= MAX_HEADER_BYTES {
        if let Some(domain) = header_host {
            return Probe::Found(Sniffed {
                protocol: Protocol::Http,
                domain: domain.or(target_host),
            });
        }
        if let Some(domain) = target_host {
            return Probe::Found(Sniffed {
                protocol: Protocol::Http,
                domain: Some(domain),
            });
        }
        return Probe::NotThis;
    }

    Probe::NeedMore
}

fn probe_incomplete_request_line(buf: &[u8]) -> Probe {
    if buf.len() > MAX_REQUEST_LINE_BYTES {
        return Probe::NotThis;
    }
    let trimmed = buf.strip_suffix(b"\r").unwrap_or(buf);
    if trimmed.iter().any(|b| *b < 0x20 || *b == 0x7f) {
        return Probe::NotThis;
    }

    let Some(first_sp) = find_byte(trimmed, b' ') else {
        if trimmed.len() > MAX_METHOD_LEN {
            return Probe::NotThis;
        }
        if KNOWN_METHODS.iter().any(|m| m.starts_with(trimmed)) {
            return Probe::NeedMore;
        }
        return Probe::NotThis;
    };

    let method = &trimmed[..first_sp];
    if !KNOWN_METHODS.contains(&method) {
        return Probe::NotThis;
    }

    let after_method = &trimmed[first_sp + 1..];
    if let Some(second_sp) = find_byte(after_method, b' ') {
        if second_sp == 0 {
            return Probe::NotThis;
        }
        let version_prefix = &after_method[second_sp + 1..];
        if !is_http_version_prefix(version_prefix) {
            return Probe::NotThis;
        }
    }

    Probe::NeedMore
}

fn parse_request_line(line: &[u8]) -> Option<Option<String>> {
    if line.len() > MAX_REQUEST_LINE_BYTES {
        return None;
    }
    let first_sp = find_byte(line, b' ')?;
    let method = &line[..first_sp];
    if !KNOWN_METHODS.contains(&method) {
        return None;
    }

    let rest = &line[first_sp + 1..];
    let second_sp = find_byte(rest, b' ')?;
    let target = &rest[..second_sp];
    let version = &rest[second_sp + 1..];

    if target.is_empty() || !target.iter().all(|b| (0x21..=0x7e).contains(b)) {
        return None;
    }
    if !is_http1_version(version) {
        return None;
    }

    Some(extract_absolute_uri_host(target))
}

fn is_http1_version(version: &[u8]) -> bool {
    version.len() == 8 && version.starts_with(b"HTTP/1.") && version[7].is_ascii_digit()
}

fn is_http_version_prefix(prefix: &[u8]) -> bool {
    if prefix.len() > 8 {
        return false;
    }
    let expected = b"HTTP/1.";
    let common = prefix.len().min(expected.len());
    if prefix[..common] != expected[..common] {
        return false;
    }
    if prefix.len() == 8 && !prefix[7].is_ascii_digit() {
        return false;
    }
    true
}

fn extract_absolute_uri_host(target: &[u8]) -> Option<String> {
    let rest = if target.len() >= 7 && target[..7].eq_ignore_ascii_case(b"http://") {
        &target[7..]
    } else if target.len() >= 8 && target[..8].eq_ignore_ascii_case(b"https://") {
        &target[8..]
    } else {
        return None;
    };

    let authority_end = rest
        .iter()
        .position(|b| matches!(*b, b'/' | b'?' | b'#'))
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let hostport = match authority.iter().rposition(|b| *b == b'@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    parse_host_authority(hostport)
}

fn parse_host_authority(value: &[u8]) -> Option<String> {
    if value.is_empty() || value.starts_with(b"[") {
        return None;
    }

    let host = match find_byte(value, b':') {
        Some(colon) => {
            let port = &value[colon + 1..];
            // A second colon means an unbracketed IPv6 literal.
            if find_byte(port, b':').is_some() {
                return None;
            }
            if !port.is_empty() && !is_valid_port(port) {
                return None;
            }
            &value[..colon]
        }
        None => value,
    };

    normalize_host(host)
}

fn is_valid_port(port: &[u8]) -> bool {
    if port.is_empty() || port.len() > 5 || !port.iter().all(u8::is_ascii_digit) {
        return false;
    }
    std::str::from_utf8(port)
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .is_some()
}

fn is_valid_header_name(name: &[u8]) -> bool {
    !name.is_empty() && name.iter().all(|b| is_tchar(*b))
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn trim_ows(mut bytes: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = bytes.split_first() {
        if first == b' ' || first == b'\t' {
            bytes = rest;
        } else {
            break;
        }
    }
    while let Some((&last, rest)) = bytes.split_last() {
        if last == b' ' || last == b'\t' {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

fn strip_trailing_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn find_byte(haystack: &[u8], needle: u8) -> Option<usize> {
    haystack.iter().position(|b| *b == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_mixed_case_host_header_and_strips_port() {
        let req = b"GET /index.html HTTP/1.1\r\nUser-Agent: test\r\nhOsT: Example.COM:8080\r\n\r\n";
        assert_eq!(
            probe_http(req),
            Probe::Found(Sniffed {
                protocol: Protocol::Http,
                domain: Some("example.com".to_owned()),
            })
        );
    }

    #[test]
    fn suppresses_ipv4_and_ipv6_literals_in_host_header() {
        let ipv6 = b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n";
        assert_eq!(
            probe_http(ipv6),
            Probe::Found(Sniffed {
                protocol: Protocol::Http,
                domain: None,
            })
        );

        let ipv4 = b"GET / HTTP/1.1\r\nHost: 192.0.2.10:80\r\n\r\n";
        assert_eq!(
            probe_http(ipv4),
            Probe::Found(Sniffed {
                protocol: Protocol::Http,
                domain: None,
            })
        );
    }

    #[test]
    fn extracts_host_from_absolute_uri_when_host_header_is_absent() {
        let req = b"GET http://Sub.Example.COM:8080/path?x=1 HTTP/1.1\r\nAccept: */*\r\n\r\n";
        assert_eq!(
            probe_http(req),
            Probe::Found(Sniffed {
                protocol: Protocol::Http,
                domain: Some("sub.example.com".to_owned()),
            })
        );
    }

    #[test]
    fn waits_for_complete_headers_when_split_across_reads() {
        let full = b"POST /submit HTTP/1.1\r\nContent-Length: 0\r\nHost: api.example.com\r\n\r\n";
        for split in 0..full.len() {
            assert_eq!(probe_http(&full[..split]), Probe::NeedMore, "split={split}");
        }
        assert_eq!(
            probe_http(full),
            Probe::Found(Sniffed {
                protocol: Protocol::Http,
                domain: Some("api.example.com".to_owned()),
            })
        );
    }

    #[test]
    fn recognises_http_request_without_host_header() {
        let req = b"GET / HTTP/1.0\r\nUser-Agent: probe\r\n\r\n";
        assert_eq!(
            probe_http(req),
            Probe::Found(Sniffed {
                protocol: Protocol::Http,
                domain: None,
            })
        );
    }

    #[test]
    fn rejects_connect_requests_and_binary_garbage() {
        let cases: [&[u8]; 7] = [
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
            b"CONNECT ",
            &[0x16, 0x03, 0x01, 0x00, 0x40],
            &[0x00, 0xff, 0xfe, 0xfd],
            b"FOOBAR / HTTP/1.1\r\n\r\n",
            b"GET / HTTP/2.0\r\nHost: example.com\r\n\r\n",
            b"GET / HTTP/1.1\r\nnot a valid header\r\n\r\n",
        ];
        for case in cases {
            assert_eq!(probe_http(case), Probe::NotThis, "{case:?}");
        }
    }
}
