//! The DNS message format (RFC 1035): queries and the parts of a reply a
//! stub resolver needs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

pub const RCODE_NXDOMAIN: u8 = 3;

/// A recursive query for one name. `labels` must already be valid: 1 to 63
/// bytes each, see `labels`.
pub fn query(id: u16, labels: &[&[u8]], kind: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(50);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in labels {
        packet.push(u8::try_from(label.len()).expect("DNS labels fit in a byte"));
        packet.extend_from_slice(label);
    }
    packet.push(0);
    packet.extend_from_slice(&kind.to_be_bytes());
    packet.extend_from_slice(&CLASS_IN.to_be_bytes());
    packet
}

/// The labels of a host name, or `None` if it cannot be sent as one: ASCII
/// letters, digits, `-` and `_`, 1 to 63 bytes per label, 253 in all.
pub fn labels(name: &str) -> Option<Vec<&[u8]>> {
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    name.split('.')
        .map(|label| {
            let bytes = label.as_bytes();
            (!bytes.is_empty()
                && bytes.len() <= 63
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
            .then_some(bytes)
        })
        .collect()
}

pub fn word(packet: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *packet.get(offset)?,
        *packet.get(offset + 1)?,
    ]))
}

/// Reads a possibly compressed name at `offset`, lowercased, and moves
/// `offset` past it. Pointers may only go backwards, so a loop cannot form.
fn read_name(packet: &[u8], offset: &mut usize) -> Option<String> {
    let mut cursor = *offset;
    let mut end = None;
    let mut expanded_length = 0usize;
    let mut name = Vec::new();

    for _ in 0..packet.len() {
        let length = *packet.get(cursor)?;
        match length & 0xc0 {
            0x00 => {
                cursor += 1;
                expanded_length += usize::from(length) + 1;
                if expanded_length > 255 {
                    return None;
                }
                if length == 0 {
                    *offset = end.unwrap_or(cursor);
                    return Some(String::from_utf8_lossy(&name).into_owned());
                }
                let label = packet.get(cursor..cursor.checked_add(usize::from(length))?)?;
                if !name.is_empty() {
                    name.push(b'.');
                }
                name.extend(label.iter().map(u8::to_ascii_lowercase));
                cursor += usize::from(length);
            }
            0xc0 => {
                let target = usize::from(word(packet, cursor)? & 0x3fff);
                if target < 12 || target >= cursor {
                    return None;
                }
                end.get_or_insert(cursor + 2);
                cursor = target;
            }
            _ => return None,
        }
    }

    None
}

pub fn skip_name(packet: &[u8], offset: &mut usize) -> Option<()> {
    read_name(packet, offset).map(|_| ())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData {
    Address(IpAddr),
    Alias(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub owner: String,
    pub data: RecordData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub rcode: u8,
    /// The reply did not fit into UDP; its records are not read.
    pub truncated: bool,
    /// A, AAAA and CNAME records of the answer section.
    pub records: Vec<Record>,
}

/// Parses the reply to `question`, or `None` if it is not one: another ID,
/// another question, not a response, or malformed.
pub fn parse_answer(packet: &[u8], question: &[u8]) -> Option<Answer> {
    if packet.len() < 12 || word(packet, 0)? != word(question, 0)? || word(packet, 4)? != 1 {
        return None;
    }
    let flags = word(packet, 2)?;
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 {
        return None;
    }

    let mut offset = 12;
    skip_name(packet, &mut offset)?;
    offset = offset.checked_add(4)?;
    if !packet
        .get(12..offset)?
        .eq_ignore_ascii_case(question.get(12..)?)
    {
        return None;
    }
    let rcode = (flags & 0x000f) as u8;
    if flags & 0x0200 != 0 {
        return Some(Answer {
            rcode,
            truncated: true,
            records: Vec::new(),
        });
    }

    let mut records = Vec::new();
    for _ in 0..word(packet, 6)? {
        let owner = read_name(packet, &mut offset)?;
        let kind = word(packet, offset)?;
        let class = word(packet, offset + 2)?;
        let data_length = usize::from(word(packet, offset + 8)?);
        offset = offset.checked_add(10)?;
        let data_end = offset.checked_add(data_length)?;
        let data = packet.get(offset..data_end)?;
        let record = match (kind, class, data) {
            (TYPE_A, CLASS_IN, &[a, b, c, d]) => {
                Some(RecordData::Address(Ipv4Addr::new(a, b, c, d).into()))
            }
            (TYPE_AAAA, CLASS_IN, data) => <[u8; 16]>::try_from(data)
                .ok()
                .map(|octets| RecordData::Address(Ipv6Addr::from(octets).into())),
            (TYPE_CNAME, CLASS_IN, _) => {
                let mut target = offset;
                let alias = read_name(packet, &mut target)?;
                (target == data_end).then_some(RecordData::Alias(alias))
            }
            _ => None,
        };
        if let Some(data) = record {
            records.push(Record { owner, data });
        }
        offset = data_end;
    }

    Some(Answer {
        rcode,
        truncated: false,
        records,
    })
}

/// What the answer says about `name`: its addresses after following the
/// CNAME chain, and the name the chain ends at.
pub fn follow(records: &[Record], name: &str) -> (Vec<IpAddr>, String) {
    let mut current = name.to_owned();
    // A chain longer than the answer has a loop.
    for _ in 0..=records.len() {
        let next = records.iter().find_map(|record| match &record.data {
            RecordData::Alias(target) if record.owner == current => Some(target),
            _ => None,
        });
        match next {
            Some(target) if *target != current => current.clone_from(target),
            _ => break,
        }
    }
    let addresses = records
        .iter()
        .filter_map(|record| match record.data {
            RecordData::Address(address) if record.owner == current => Some(address),
            _ => None,
        })
        .collect();
    (addresses, current)
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::{CLASS_IN, TYPE_A, TYPE_AAAA, TYPE_CNAME};

    /// Builds a reply to `question` with the given flags and answer records
    /// `(owner, type, data)`; owners and CNAME targets are written in full.
    pub(crate) fn reply(question: &[u8], flags: u16, records: &[(&str, u16, Vec<u8>)]) -> Vec<u8> {
        let mut packet = question[..2].to_vec();
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&u16::try_from(records.len()).unwrap().to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(&question[12..]);
        for (owner, kind, data) in records {
            packet.extend(encode(owner));
            packet.extend_from_slice(&kind.to_be_bytes());
            packet.extend_from_slice(&CLASS_IN.to_be_bytes());
            packet.extend_from_slice(&60u32.to_be_bytes());
            packet.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            packet.extend_from_slice(data);
        }
        packet
    }

    pub(crate) fn encode(name: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for label in name.split('.') {
            bytes.push(u8::try_from(label.len()).unwrap());
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes
    }

    pub(crate) fn a(owner: &str, octets: [u8; 4]) -> (&str, u16, Vec<u8>) {
        (owner, TYPE_A, octets.to_vec())
    }

    pub(crate) fn aaaa(owner: &str, octets: [u8; 16]) -> (&str, u16, Vec<u8>) {
        (owner, TYPE_AAAA, octets.to_vec())
    }

    pub(crate) fn cname<'a>(owner: &'a str, target: &str) -> (&'a str, u16, Vec<u8>) {
        (owner, TYPE_CNAME, encode(target))
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::test_support::{a, aaaa, cname, reply};
    use super::*;

    fn ask(name: &str, kind: u16) -> Vec<u8> {
        query(0x1234, &labels(name).unwrap(), kind)
    }

    #[test]
    fn names_that_cannot_be_sent_have_no_labels() {
        assert_eq!(
            labels("node.example.com"),
            Some(vec![&b"node"[..], b"example", b"com"])
        );
        assert!(labels("_srv.example.com").is_some());
        for name in ["", "a..b", ".a", "a.", "пример.рф", "a b.com", &"a".repeat(64)] {
            assert_eq!(labels(name), None, "{name:?}");
        }
        let long = vec!["a".repeat(63); 4].join(".");
        assert_eq!(labels(&long), None);
    }

    #[test]
    fn a_and_aaaa_records_of_the_name_are_read() {
        let question = ask("node.example.com", TYPE_A);
        let packet = reply(
            &question,
            0x8180,
            &[
                a("node.example.com", [192, 0, 2, 7]),
                a("node.example.com", [192, 0, 2, 8]),
            ],
        );
        let answer = parse_answer(&packet, &question).unwrap();
        assert_eq!(answer.rcode, 0);
        assert!(!answer.truncated);
        assert_eq!(
            follow(&answer.records, "node.example.com").0,
            [
                IpAddr::from([192, 0, 2, 7]),
                IpAddr::from([192, 0, 2, 8])
            ]
        );

        let question = ask("node.example.com", TYPE_AAAA);
        let mut v6 = [0u8; 16];
        v6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        v6[15] = 1;
        let packet = reply(&question, 0x8180, &[aaaa("NODE.example.com", v6)]);
        let answer = parse_answer(&packet, &question).unwrap();
        assert_eq!(
            follow(&answer.records, "node.example.com").0,
            [IpAddr::from(v6)]
        );
    }

    #[test]
    fn a_cname_chain_leads_to_the_addresses_of_its_end() {
        let question = ask("sub.example.com", TYPE_A);
        let packet = reply(
            &question,
            0x8180,
            &[
                cname("sub.example.com", "cdn.example.net"),
                cname("cdn.example.net", "edge.example.org"),
                a("edge.example.org", [198, 51, 100, 4]),
                a("other.example.org", [203, 0, 113, 9]),
            ],
        );
        let answer = parse_answer(&packet, &question).unwrap();
        let (addresses, end) = follow(&answer.records, "sub.example.com");
        assert_eq!(addresses, [IpAddr::from([198, 51, 100, 4])]);
        assert_eq!(end, "edge.example.org");

        // A chain the server did not finish ends at a name to ask next.
        let packet = reply(
            &question,
            0x8180,
            &[cname("sub.example.com", "cdn.example.net")],
        );
        let answer = parse_answer(&packet, &question).unwrap();
        assert_eq!(
            follow(&answer.records, "sub.example.com"),
            (Vec::new(), "cdn.example.net".to_owned())
        );

        let looped = reply(
            &question,
            0x8180,
            &[
                cname("sub.example.com", "cdn.example.net"),
                cname("cdn.example.net", "sub.example.com"),
            ],
        );
        let answer = parse_answer(&looped, &question).unwrap();
        assert!(follow(&answer.records, "sub.example.com").0.is_empty());
    }

    #[test]
    fn nxdomain_and_truncation_are_reported() {
        let question = ask("missing.example.com", TYPE_A);
        let answer = parse_answer(&reply(&question, 0x8183, &[]), &question).unwrap();
        assert_eq!(answer.rcode, RCODE_NXDOMAIN);
        assert!(answer.records.is_empty());

        let answer = parse_answer(
            &reply(
                &question,
                0x8380,
                &[a("missing.example.com", [192, 0, 2, 1])],
            ),
            &question,
        )
        .unwrap();
        assert!(answer.truncated);
        assert!(answer.records.is_empty());
    }

    #[test]
    fn replies_to_something_else_are_ignored() {
        let question = ask("node.example.com", TYPE_A);
        let good = reply(&question, 0x8180, &[a("node.example.com", [192, 0, 2, 7])]);

        let mut other_id = good.clone();
        other_id[1] ^= 1;
        assert_eq!(parse_answer(&other_id, &question), None);

        let other_question = ask("evil.example.com", TYPE_A);
        let spoofed = reply(
            &other_question,
            0x8180,
            &[a("node.example.com", [192, 0, 2, 66])],
        );
        assert_eq!(parse_answer(&spoofed, &question), None);

        let mut not_a_response = good.clone();
        not_a_response[2] &= 0x7f;
        assert_eq!(parse_answer(&not_a_response, &question), None);

        for length in 0..good.len() {
            let _ = parse_answer(&good[..length], &question);
        }
        assert_eq!(parse_answer(&good[..good.len() - 1], &question), None);
    }

    #[test]
    fn compressed_names_are_followed_only_backwards() {
        let question = ask("node.example.com", TYPE_A);
        // Answer owner as a pointer to the question name at offset 12.
        let mut packet = question[..2].to_vec();
        packet.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        packet.extend_from_slice(&question[12..]);
        packet.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
        let answer = parse_answer(&packet, &question).unwrap();
        assert_eq!(
            follow(&answer.records, "node.example.com").0,
            [IpAddr::from([192, 0, 2, 7])]
        );

        let mut forward = packet.clone();
        let pointer = forward.len() - 16;
        forward[pointer + 1] = u8::try_from(forward.len() - 1).unwrap();
        assert_eq!(parse_answer(&forward, &question), None);
    }
}
