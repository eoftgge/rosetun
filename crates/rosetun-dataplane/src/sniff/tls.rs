//! TLS record and ClientHello SNI parser.

use super::hostname::normalize_host;
use super::wire::Reader;
use super::{Probe, Protocol, Sniffed};

const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const RECORD_HEADER_LEN: usize = 5;
const HANDSHAKE_HEADER_LEN: usize = 4;
const MAX_TLS_RECORD_LEN: usize = 16 * 1024;
const MAX_CLIENT_HELLO_BYTES: usize = 16 * 1024;
const MAX_SESSION_ID_LEN: usize = 32;
const EXT_SERVER_NAME: u16 = 0x0000;
const NAME_TYPE_HOST_NAME: u8 = 0x00;

/// Probes the leading bytes of a TCP stream for a TLS ClientHello.
///
/// Reassembles a ClientHello split across multiple TLS Handshake records and
/// extracts the `server_name` extension when present. IP literals in SNI
/// yield `domain: None`.
pub fn probe_tls(buf: &[u8]) -> Probe {
    if buf.is_empty() {
        return Probe::NeedMore;
    }

    let mut offset = 0usize;
    let mut assembled: Vec<u8> = Vec::new();
    let mut expected_total: Option<usize> = None;

    loop {
        let rest = &buf[offset..];
        if rest.is_empty() {
            return Probe::NeedMore;
        }
        if rest[0] != CONTENT_TYPE_HANDSHAKE {
            return Probe::NotThis;
        }
        if rest.len() >= 2 && rest[1] != 0x03 {
            return Probe::NotThis;
        }
        if rest.len() >= 3 && rest[2] > 0x04 {
            return Probe::NotThis;
        }
        if rest.len() < RECORD_HEADER_LEN {
            return Probe::NeedMore;
        }

        let record_len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        if record_len == 0 || record_len > MAX_TLS_RECORD_LEN {
            return Probe::NotThis;
        }

        let avail = rest.len() - RECORD_HEADER_LEN;
        if avail < record_len {
            // Validate the handshake header early when the first record is
            // still arriving so non-ClientHello handshake traffic fails fast.
            if assembled.is_empty() && avail > 0 {
                let partial = &rest[RECORD_HEADER_LEN..];
                if partial[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
                    return Probe::NotThis;
                }
                if partial.len() >= HANDSHAKE_HEADER_LEN {
                    let body_len = read_u24(&partial[1..4]);
                    if body_len > MAX_CLIENT_HELLO_BYTES {
                        return Probe::NotThis;
                    }
                }
            }
            return Probe::NeedMore;
        }

        let payload = &rest[RECORD_HEADER_LEN..RECORD_HEADER_LEN + record_len];
        offset += RECORD_HEADER_LEN + record_len;

        // Fast path: the entire ClientHello fits in the first TLS record.
        if assembled.is_empty() {
            if payload[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
                return Probe::NotThis;
            }
            if payload.len() >= HANDSHAKE_HEADER_LEN {
                let body_len = read_u24(&payload[1..4]);
                if body_len > MAX_CLIENT_HELLO_BYTES {
                    return Probe::NotThis;
                }
                let total = HANDSHAKE_HEADER_LEN + body_len;
                if payload.len() >= total {
                    return parse_client_hello_message(&payload[..total], Protocol::Tls);
                }
                expected_total = Some(total);
            }
            assembled.extend_from_slice(payload);
            continue;
        }

        let cap = expected_total.unwrap_or(HANDSHAKE_HEADER_LEN + MAX_CLIENT_HELLO_BYTES);
        let take = payload.len().min(cap.saturating_sub(assembled.len()));
        assembled.extend_from_slice(&payload[..take]);

        if expected_total.is_none() && assembled.len() >= HANDSHAKE_HEADER_LEN {
            let body_len = read_u24(&assembled[1..4]);
            if body_len > MAX_CLIENT_HELLO_BYTES {
                return Probe::NotThis;
            }
            expected_total = Some(HANDSHAKE_HEADER_LEN + body_len);
        }

        if let Some(total) = expected_total
            && assembled.len() >= total
        {
            return parse_client_hello_message(&assembled[..total], Protocol::Tls);
        }
    }
}

/// Parses a bare TLS Handshake `ClientHello` message (type `0x01`, 3-byte
/// length, body). Shared by the TCP TLS sniffer and the QUIC CRYPTO reassembler.
pub(super) fn parse_client_hello_message(msg: &[u8], protocol: Protocol) -> Probe {
    let mut reader = Reader::new(msg);
    let Some(msg_type) = reader.u8() else {
        return Probe::NeedMore;
    };
    if msg_type != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Probe::NotThis;
    }
    let Some(body_len) = reader.u24() else {
        return Probe::NeedMore;
    };
    if body_len > MAX_CLIENT_HELLO_BYTES {
        return Probe::NotThis;
    }
    let Some(body) = reader.take(body_len) else {
        return Probe::NeedMore;
    };

    match parse_client_hello_body(body) {
        Some(domain) => Probe::Found(Sniffed { protocol, domain }),
        None => Probe::NotThis,
    }
}

fn parse_client_hello_body(body: &[u8]) -> Option<Option<String>> {
    let mut reader = Reader::new(body);

    let legacy_version = reader.u16()?;
    if (legacy_version >> 8) != 0x03 || (legacy_version & 0xff) > 0x04 {
        return None;
    }
    let _random = reader.take(32)?;
    let session_id = reader.vec8()?;
    if session_id.len() > MAX_SESSION_ID_LEN {
        return None;
    }
    let cipher_suites = reader.vec16()?;
    if cipher_suites.is_empty() || !cipher_suites.len().is_multiple_of(2) {
        return None;
    }
    let compression_methods = reader.vec8()?;
    if compression_methods.is_empty() {
        return None;
    }

    if reader.is_empty() {
        return Some(None);
    }

    let extensions_bytes = reader.vec16()?;
    if !reader.is_empty() {
        return None;
    }

    let mut exts = Reader::new(extensions_bytes);
    let mut domain: Option<String> = None;

    while !exts.is_empty() {
        let ext_type = exts.u16()?;
        let ext_data = exts.vec16()?;
        if ext_type == EXT_SERVER_NAME && domain.is_none() {
            domain = parse_sni_extension(ext_data)?;
        }
    }

    Some(domain)
}

fn parse_sni_extension(ext_data: &[u8]) -> Option<Option<String>> {
    let mut reader = Reader::new(ext_data);
    let list_bytes = reader.vec16()?;
    if !reader.is_empty() {
        return None;
    }
    let mut list = Reader::new(list_bytes);
    let mut host: Option<String> = None;
    while !list.is_empty() {
        let name_type = list.u8()?;
        let name_bytes = list.vec16()?;
        if name_type == NAME_TYPE_HOST_NAME && host.is_none() {
            host = normalize_host(name_bytes);
        }
    }
    Some(host)
}

fn read_u24(bytes: &[u8]) -> usize {
    (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2])
}

#[cfg(test)]
mod tests {
    use super::super::testing::{
        build_client_hello_message, build_realistic_client_hello_message, wrap_tls_record,
        wrap_tls_records_split,
    };
    use super::*;

    #[test]
    fn extracts_sni_from_hand_built_client_hello() {
        let msg = build_client_hello_message(Some(b"Example.COM."));
        let record = wrap_tls_record(&msg);
        assert_eq!(
            probe_tls(&record),
            Probe::Found(Sniffed {
                protocol: Protocol::Tls,
                domain: Some("example.com".to_owned()),
            })
        );
    }

    #[test]
    fn extracts_sni_from_realistic_client_hello_with_grease_and_alpn() {
        let msg = build_realistic_client_hello_message(Some(b"api.example.com"));
        let record = wrap_tls_record(&msg);
        assert_eq!(
            probe_tls(&record),
            Probe::Found(Sniffed {
                protocol: Protocol::Tls,
                domain: Some("api.example.com".to_owned()),
            })
        );
    }

    #[test]
    fn recognises_client_hello_without_sni() {
        let msg = build_client_hello_message(None);
        let record = wrap_tls_record(&msg);
        assert_eq!(
            probe_tls(&record),
            Probe::Found(Sniffed {
                protocol: Protocol::Tls,
                domain: None,
            })
        );
    }

    #[test]
    fn suppresses_ip_literal_sni() {
        for literal in [b"192.0.2.1".as_slice(), b"2001:db8::1".as_slice()] {
            let msg = build_client_hello_message(Some(literal));
            let record = wrap_tls_record(&msg);
            assert_eq!(
                probe_tls(&record),
                Probe::Found(Sniffed {
                    protocol: Protocol::Tls,
                    domain: None,
                })
            );
        }
    }

    #[test]
    fn reassembles_client_hello_split_across_two_tls_records() {
        let msg = build_realistic_client_hello_message(Some(b"split.example.com"));
        let split_at = 25;
        let records = wrap_tls_records_split(&msg, split_at);

        let first_record_len = 5 + split_at;
        assert_eq!(probe_tls(&records[..first_record_len]), Probe::NeedMore);
        assert_eq!(
            probe_tls(&records),
            Probe::Found(Sniffed {
                protocol: Protocol::Tls,
                domain: Some("split.example.com".to_owned()),
            })
        );
    }

    #[test]
    fn reassembles_client_hello_split_inside_the_handshake_header() {
        let msg = build_client_hello_message(Some(b"tiny.example.com"));
        let records = wrap_tls_records_split(&msg, 2);
        assert_eq!(probe_tls(&records[..7]), Probe::NeedMore);
        assert_eq!(
            probe_tls(&records),
            Probe::Found(Sniffed {
                protocol: Protocol::Tls,
                domain: Some("tiny.example.com".to_owned()),
            })
        );
    }

    #[test]
    fn requests_more_bytes_for_every_prefix_of_a_valid_client_hello() {
        let msg = build_client_hello_message(Some(b"example.com"));
        let record = wrap_tls_record(&msg);
        for len in 0..record.len() {
            assert_eq!(probe_tls(&record[..len]), Probe::NeedMore, "len={len}");
        }
        assert!(matches!(probe_tls(&record), Probe::Found(_)));
    }

    #[test]
    fn rejects_non_tls_and_malformed_records_without_panicking() {
        let cases: [&[u8]; 9] = [
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"SSH-2.0-OpenSSH_9.0\r\n",
            &[0x17, 0x03, 0x03, 0x00, 0x10, 0x00],
            &[0x16, 0x02, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00],
            &[0x16, 0x03, 0x09, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00],
            &[0x16, 0x03, 0x01, 0x00, 0x00],
            &[0x16, 0x03, 0x01, 0x50, 0x00, 0x01, 0x00, 0x00, 0x01],
            &[0x16, 0x03, 0x01, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00],
            &[
                0x16, 0x03, 0x01, 0x00, 0x08, 0x01, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00,
            ],
        ];
        for case in cases {
            assert_eq!(probe_tls(case), Probe::NotThis, "{case:?}");
        }
    }
}
