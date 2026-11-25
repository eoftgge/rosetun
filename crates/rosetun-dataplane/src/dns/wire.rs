//! A minimal DNS message reader and writer (RFC 1035, RFC 6891).
//!
//! Only what the service needs: the header, one question, a walk over the
//! resource records with bounded compression pointers, address and CNAME
//! extraction, TTL rewriting and the few messages the service builds itself.
//! Nothing here panics on hostile input, and no type prints a name.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Range;

pub(crate) const TYPE_A: u16 = 1;
pub(crate) const TYPE_CNAME: u16 = 5;
pub(crate) const TYPE_SOA: u16 = 6;
pub(crate) const TYPE_AAAA: u16 = 28;
pub(crate) const TYPE_OPT: u16 = 41;
pub(crate) const TYPE_IXFR: u16 = 251;
pub(crate) const TYPE_AXFR: u16 = 252;
pub(crate) const CLASS_IN: u16 = 1;

pub(crate) const RCODE_NOERROR: u8 = 0;
pub(crate) const RCODE_FORMERR: u8 = 1;
pub(crate) const RCODE_SERVFAIL: u8 = 2;
pub(crate) const RCODE_NXDOMAIN: u8 = 3;
pub(crate) const RCODE_NOTIMP: u8 = 4;
pub(crate) const RCODE_REFUSED: u8 = 5;

pub(crate) const HEADER_LEN: usize = 12;

const FLAG_RESPONSE: u8 = 0x80;
const FLAG_AUTHORITATIVE: u8 = 0x04;
const FLAG_TRUNCATED: u8 = 0x02;
const FLAG_RECURSION_DESIRED: u8 = 0x01;
const FLAG_RECURSION_AVAILABLE: u8 = 0x80;
const OPCODE_MASK: u8 = 0x78;
const RCODE_MASK: u8 = 0x0f;
const DNSSEC_OK: u32 = 0x8000;

/// Pointer hops one name may take; legitimate messages need a couple.
const MAX_POINTER_JUMPS: usize = 16;
const MAX_NAME_WIRE_LEN: usize = 255;
const MAX_LABEL_LEN: usize = 63;
/// CNAME links followed when deciding which address records answer the question.
const MAX_CNAME_CHAIN: usize = 8;
/// The smallest resource record: root name, type, class, TTL, empty data.
const MIN_RECORD_LEN: usize = 11;
/// Payload size announced in the OPT record of locally built answers.
const LOCAL_EDNS_PAYLOAD: u16 = 1232;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireError {
    Truncated,
    BadName,
    BadPointer,
    NotAQuery,
    UnsupportedOpcode,
    QuestionCount,
    NotAResponse,
    InvalidName,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Question {
    /// Lower case, no trailing dot, `.` escaped inside labels.
    pub(crate) name: String,
    pub(crate) qtype: u16,
    pub(crate) qclass: u16,
}

impl fmt::Debug for Question {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Question").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Edns {
    pub(crate) payload: u16,
    pub(crate) dnssec_ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Query {
    pub(crate) id: u16,
    pub(crate) recursion_desired: bool,
    pub(crate) question: Question,
    pub(crate) edns: Option<Edns>,
    /// End of the question section: bytes `HEADER_LEN..question_end` of the
    /// query are the question exactly as received.
    pub(crate) question_end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Section {
    Answer,
    Authority,
    Additional,
}

#[derive(Debug, Clone)]
pub(crate) struct Record {
    pub(crate) section: Section,
    pub(crate) rtype: u16,
    pub(crate) class: u16,
    pub(crate) ttl: u32,
    pub(crate) name_offset: usize,
    pub(crate) ttl_offset: usize,
    pub(crate) rdata: Range<usize>,
}

/// What the service needs to know about an upstream response.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Answer {
    pub(crate) rcode: u8,
    pub(crate) truncated: bool,
    pub(crate) answer_count: usize,
    /// Address records that belong to the question's CNAME chain, each paired
    /// with its own record TTL in seconds.
    pub(crate) addresses: Vec<(IpAddr, u32)>,
    /// Smallest TTL among the answer records.
    pub(crate) answer_ttl: Option<u32>,
    /// What the SOA in the authority section allows for a negative answer.
    pub(crate) negative_ttl: Option<u32>,
}

impl fmt::Debug for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Answer")
            .field("rcode", &self.rcode)
            .field("truncated", &self.truncated)
            .finish_non_exhaustive()
    }
}

fn u16_at(msg: &[u8], pos: usize) -> Result<u16, WireError> {
    let bytes = msg.get(pos..pos + 2).ok_or(WireError::Truncated)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn u32_at(msg: &[u8], pos: usize) -> Result<u32, WireError> {
    let bytes = msg.get(pos..pos + 4).ok_or(WireError::Truncated)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(crate) fn message_id(msg: &[u8]) -> Option<u16> {
    u16_at(msg, 0).ok()
}

pub(crate) fn set_id(msg: &mut [u8], id: u16) {
    if let Some(slot) = msg.get_mut(0..2) {
        slot.copy_from_slice(&id.to_be_bytes());
    }
}

#[cfg(test)]
pub(crate) fn rcode_of(msg: &[u8]) -> Option<u8> {
    msg.get(3).map(|flags| flags & RCODE_MASK)
}

/// Copies the recursion-desired bit of the query into a response.
pub(crate) fn set_recursion_desired(msg: &mut [u8], desired: bool) {
    if let Some(flags) = msg.get_mut(2) {
        if desired {
            *flags |= FLAG_RECURSION_DESIRED;
        } else {
            *flags &= !FLAG_RECURSION_DESIRED;
        }
    }
}

fn push_label_byte(out: &mut String, byte: u8) {
    match byte {
        b'.' | b'\\' => {
            out.push('\\');
            out.push(char::from(byte));
        }
        0x21..=0x7e => out.push(char::from(byte.to_ascii_lowercase())),
        _ => {
            out.push('\\');
            out.push_str(&format!("{byte:03}"));
        }
    }
}

/// Reads the name at `start`. Returns it with the offset just past its
/// encoding at `start` (after the first pointer, when there is one).
/// Pointers must go strictly backwards and are limited in number, so a loop
/// is an error rather than a hang.
fn read_name(msg: &[u8], start: usize, allow_pointers: bool) -> Result<(String, usize), WireError> {
    let mut pos = start;
    let mut end = None;
    let mut jumps = 0;
    let mut wire_len = 1;
    let mut out = String::new();
    loop {
        let length = *msg.get(pos).ok_or(WireError::Truncated)?;
        match length & 0xc0 {
            0x00 => {
                if length == 0 {
                    pos += 1;
                    break;
                }
                let size = usize::from(length);
                let label = msg
                    .get(pos + 1..pos + 1 + size)
                    .ok_or(WireError::Truncated)?;
                wire_len += 1 + size;
                if wire_len > MAX_NAME_WIRE_LEN {
                    return Err(WireError::BadName);
                }
                if !out.is_empty() {
                    out.push('.');
                }
                for byte in label {
                    push_label_byte(&mut out, *byte);
                }
                pos += 1 + size;
            }
            0xc0 => {
                if !allow_pointers {
                    return Err(WireError::BadPointer);
                }
                let low = *msg.get(pos + 1).ok_or(WireError::Truncated)?;
                let target = (usize::from(length & 0x3f) << 8) | usize::from(low);
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS || target >= pos {
                    return Err(WireError::BadPointer);
                }
                end.get_or_insert(pos + 2);
                pos = target;
            }
            _ => return Err(WireError::BadName),
        }
    }
    Ok((out, end.unwrap_or(pos)))
}

/// The offset after the name at `start`, without decoding it.
fn skip_name(msg: &[u8], start: usize) -> Result<usize, WireError> {
    let mut pos = start;
    loop {
        let length = *msg.get(pos).ok_or(WireError::Truncated)?;
        match length & 0xc0 {
            0x00 => {
                if length == 0 {
                    return Ok(pos + 1);
                }
                pos += 1 + usize::from(length);
                if pos > msg.len() {
                    return Err(WireError::Truncated);
                }
            }
            0xc0 => {
                if pos + 2 > msg.len() {
                    return Err(WireError::Truncated);
                }
                return Ok(pos + 2);
            }
            _ => return Err(WireError::BadName),
        }
    }
}

struct Layout {
    flags: [u8; 2],
    question_count: usize,
    question_end: usize,
    records: Vec<Record>,
}

/// Header, the offset after the question section and every resource record.
fn layout(msg: &[u8]) -> Result<Layout, WireError> {
    if msg.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    let question_count = usize::from(u16_at(msg, 4)?);
    let counts = [
        (Section::Answer, usize::from(u16_at(msg, 6)?)),
        (Section::Authority, usize::from(u16_at(msg, 8)?)),
        (Section::Additional, usize::from(u16_at(msg, 10)?)),
    ];
    let total: usize = counts.iter().map(|(_, count)| count).sum();
    // Every item takes bytes, so counts beyond the length are a lie.
    if question_count * 5 + total * MIN_RECORD_LEN > msg.len() {
        return Err(WireError::Truncated);
    }
    let mut pos = HEADER_LEN;
    for _ in 0..question_count {
        pos = skip_name(msg, pos)? + 4;
        if pos > msg.len() {
            return Err(WireError::Truncated);
        }
    }
    let question_end = pos;
    let mut records = Vec::with_capacity(total);
    for (section, count) in counts {
        for _ in 0..count {
            let name_offset = pos;
            pos = skip_name(msg, pos)?;
            let rtype = u16_at(msg, pos)?;
            let class = u16_at(msg, pos + 2)?;
            let ttl = u32_at(msg, pos + 4)?;
            let rdlength = usize::from(u16_at(msg, pos + 8)?);
            let rdata = pos + 10..pos + 10 + rdlength;
            if rdata.end > msg.len() {
                return Err(WireError::Truncated);
            }
            records.push(Record {
                section,
                rtype,
                class,
                ttl,
                name_offset,
                ttl_offset: pos + 4,
                rdata: rdata.clone(),
            });
            pos = rdata.end;
        }
    }
    Ok(Layout {
        flags: [msg[2], msg[3]],
        question_count,
        question_end,
        records,
    })
}

/// Reads a query the service is willing to answer: one plain question.
pub(crate) fn parse_query(msg: &[u8]) -> Result<Query, WireError> {
    let layout = layout(msg)?;
    if layout.flags[0] & FLAG_RESPONSE != 0 {
        return Err(WireError::NotAQuery);
    }
    if layout.question_count != 1 {
        return Err(WireError::QuestionCount);
    }
    let (name, name_end) = read_name(msg, HEADER_LEN, false)?;
    let qtype = u16_at(msg, name_end)?;
    let qclass = u16_at(msg, name_end + 2)?;
    if layout.flags[0] & OPCODE_MASK != 0 {
        return Err(WireError::UnsupportedOpcode);
    }
    let edns = layout
        .records
        .iter()
        .find(|record| record.section == Section::Additional && record.rtype == TYPE_OPT)
        .map(|record| Edns {
            payload: record.class,
            dnssec_ok: record.ttl & DNSSEC_OK != 0,
        });
    Ok(Query {
        id: u16_at(msg, 0)?,
        recursion_desired: layout.flags[0] & FLAG_RECURSION_DESIRED != 0,
        question: Question {
            name,
            qtype,
            qclass,
        },
        edns,
        question_end: layout.question_end,
    })
}

/// Reads an upstream response to a question named `qname`.
pub(crate) fn parse_response(msg: &[u8], qname: &str) -> Result<Answer, WireError> {
    let layout = layout(msg)?;
    if layout.flags[0] & FLAG_RESPONSE == 0 {
        return Err(WireError::NotAResponse);
    }
    let mut chain = vec![qname.to_owned()];
    let mut addresses = Vec::new();
    let mut answer_ttl: Option<u32> = None;
    let mut negative_ttl: Option<u32> = None;
    let mut answer_count = 0;
    // The chain grows while records are read in order; a record that
    // precedes its owner's CNAME is missed, which only costs a mapping.
    for record in &layout.records {
        match record.section {
            Section::Answer => {
                answer_count += 1;
                answer_ttl = Some(answer_ttl.map_or(record.ttl, |ttl| ttl.min(record.ttl)));
                if record.class != CLASS_IN {
                    continue;
                }
                let Ok((owner, _)) = read_name(msg, record.name_offset, true) else {
                    continue;
                };
                if !chain.contains(&owner) {
                    continue;
                }
                match record.rtype {
                    TYPE_CNAME if chain.len() < MAX_CNAME_CHAIN => {
                        if let Ok((target, _)) = read_name(msg, record.rdata.start, true) {
                            chain.push(target);
                        }
                    }
                    TYPE_A => {
                        if let Some(octets) = msg
                            .get(record.rdata.clone())
                            .and_then(|d| <[u8; 4]>::try_from(d).ok())
                        {
                            addresses.push((IpAddr::V4(Ipv4Addr::from(octets)), record.ttl));
                        }
                    }
                    TYPE_AAAA => {
                        if let Some(octets) = msg
                            .get(record.rdata.clone())
                            .and_then(|d| <[u8; 16]>::try_from(d).ok())
                        {
                            addresses.push((IpAddr::V6(Ipv6Addr::from(octets)), record.ttl));
                        }
                    }
                    _ => {}
                }
            }
            Section::Authority if record.rtype == TYPE_SOA => {
                if let Some(minimum) = soa_minimum(msg, record) {
                    let allowed = record.ttl.min(minimum);
                    negative_ttl = Some(negative_ttl.map_or(allowed, |ttl| ttl.min(allowed)));
                }
            }
            _ => {}
        }
    }
    Ok(Answer {
        rcode: layout.flags[1] & RCODE_MASK,
        truncated: layout.flags[0] & FLAG_TRUNCATED != 0,
        answer_count,
        addresses,
        answer_ttl,
        negative_ttl,
    })
}

/// The MINIMUM field, the last four bytes of the SOA data, after both names.
fn soa_minimum(msg: &[u8], record: &Record) -> Option<u32> {
    let after_mname = skip_name(msg, record.rdata.start).ok()?;
    let after_rname = skip_name(msg, after_mname).ok()?;
    if after_rname + 20 != record.rdata.end {
        return None;
    }
    u32_at(msg, after_rname + 16).ok()
}

/// Replaces the TTL of every record except the OPT pseudo record.
pub(crate) fn rewrite_ttls(msg: &mut [u8], rewrite: impl Fn(u32) -> u32) -> Result<(), WireError> {
    let records = layout(msg)?.records;
    for record in records {
        if record.rtype == TYPE_OPT {
            continue;
        }
        if let Some(slot) = msg.get_mut(record.ttl_offset..record.ttl_offset + 4) {
            slot.copy_from_slice(&rewrite(record.ttl).to_be_bytes());
        }
    }
    Ok(())
}

/// A recursive query for `name` with the recursion-desired bit set.
pub(crate) fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, WireError> {
    let mut msg = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&[FLAG_RECURSION_DESIRED, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            let size = u8::try_from(label.len()).map_err(|_| WireError::InvalidName)?;
            if label.is_empty() || usize::from(size) > MAX_LABEL_LEN || !label.is_ascii() {
                return Err(WireError::InvalidName);
            }
            msg.push(size);
            msg.extend_from_slice(label.as_bytes());
        }
    }
    msg.push(0);
    if msg.len() - HEADER_LEN > MAX_NAME_WIRE_LEN {
        return Err(WireError::InvalidName);
    }
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(msg)
}

/// The end of a question section made of one pointer-free name, when `msg`
/// starts with one.
fn plain_question_end(msg: &[u8]) -> Option<usize> {
    if msg.len() < HEADER_LEN || u16_at(msg, 4).ok()? != 1 {
        return None;
    }
    let (_, end) = read_name(msg, HEADER_LEN, false).ok()?;
    (end + 4 <= msg.len()).then_some(end + 4)
}

/// A header-only error response that echoes the id, the opcode, the
/// recursion-desired bit and a plain question when there is one.
pub(crate) fn error_response(query: &[u8], rcode: u8) -> Vec<u8> {
    let id = message_id(query).unwrap_or(0);
    let request_flags = query.get(2).copied().unwrap_or(0);
    let question_end = plain_question_end(query);
    let mut msg = Vec::with_capacity(question_end.unwrap_or(HEADER_LEN));
    msg.extend_from_slice(&id.to_be_bytes());
    msg.push(FLAG_RESPONSE | (request_flags & (OPCODE_MASK | FLAG_RECURSION_DESIRED)));
    msg.push(FLAG_RECURSION_AVAILABLE | (rcode & RCODE_MASK));
    msg.extend_from_slice(&[0, u8::from(question_end.is_some()), 0, 0, 0, 0, 0, 0]);
    if let (Some(end), Some(question)) = (question_end, query.get(HEADER_LEN..)) {
        msg.extend_from_slice(&question[..end - HEADER_LEN]);
    }
    msg
}

/// An authoritative answer built from `query` and its parsed form: one
/// address record when `address` is given, an empty NOERROR otherwise.
pub(crate) fn local_answer(
    query: &[u8],
    parsed: &Query,
    address: Option<IpAddr>,
    ttl: u32,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(parsed.question_end + 40);
    msg.extend_from_slice(&parsed.id.to_be_bytes());
    let recursion = if parsed.recursion_desired {
        FLAG_RECURSION_DESIRED
    } else {
        0
    };
    msg.push(FLAG_RESPONSE | FLAG_AUTHORITATIVE | recursion);
    msg.push(FLAG_RECURSION_AVAILABLE | RCODE_NOERROR);
    msg.extend_from_slice(&[0, 1]);
    msg.extend_from_slice(&[0, u8::from(address.is_some())]);
    msg.extend_from_slice(&[0, 0]);
    msg.extend_from_slice(&[0, u8::from(parsed.edns.is_some())]);
    msg.extend_from_slice(&query[HEADER_LEN..parsed.question_end]);
    if let Some(ip) = address {
        msg.extend_from_slice(&[0xc0, HEADER_LEN as u8]);
        let (rtype, octets) = match ip {
            IpAddr::V4(v4) => (TYPE_A, v4.octets().to_vec()),
            IpAddr::V6(v6) => (TYPE_AAAA, v6.octets().to_vec()),
        };
        msg.extend_from_slice(&rtype.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
        msg.extend_from_slice(&ttl.to_be_bytes());
        msg.extend_from_slice(&u16::try_from(octets.len()).unwrap_or(0).to_be_bytes());
        msg.extend_from_slice(&octets);
    }
    if let Some(edns) = parsed.edns {
        msg.push(0);
        msg.extend_from_slice(&TYPE_OPT.to_be_bytes());
        msg.extend_from_slice(&LOCAL_EDNS_PAYLOAD.to_be_bytes());
        let flags = if edns.dnssec_ok { DNSSEC_OK } else { 0 };
        msg.extend_from_slice(&flags.to_be_bytes());
        msg.extend_from_slice(&[0, 0]);
    }
    msg
}

/// The largest UDP response the client accepts: 512 bytes, or its EDNS
/// payload size up to what survives most paths without fragmenting.
pub(crate) fn udp_limit(query: &[u8]) -> usize {
    match parse_query(query).ok().and_then(|parsed| parsed.edns) {
        Some(edns) => usize::from(edns.payload).clamp(512, usize::from(LOCAL_EDNS_PAYLOAD)),
        None => 512,
    }
}

/// A response cut down to its header and question with the TC bit set, which
/// tells the client to ask again over TCP.
pub(crate) fn truncated_response(response: &[u8]) -> Vec<u8> {
    let question_end = plain_question_end(response);
    let end = question_end.unwrap_or(HEADER_LEN.min(response.len()));
    let mut msg = response[..end].to_vec();
    if msg.len() >= HEADER_LEN {
        msg[2] |= FLAG_TRUNCATED;
        msg[4..12].fill(0);
        msg[5] = u8::from(question_end.is_some());
    }
    msg
}

#[cfg(test)]
mod tests;
