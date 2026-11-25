//! sing-box binary rule-set (`.srs`, versions 1..=5) parser.

use std::collections::HashSet;
use std::io::Read;

use flate2::read::ZlibDecoder;

use super::RulesError;
use super::cidr::ip_from_bytes;
use super::domain::SuccinctDomainSet;
use super::list::{
    CompiledList, CompiledListRule, DefaultListRule, LogicalListRule, LogicalMode, MAX_LIST_BYTES,
    MAX_LOGICAL_DEPTH, compile_regex, count_entries,
};

const SRS_MAGIC: [u8; 3] = *b"SRS";
const MIN_SRS_VERSION: u8 = 1;
const MAX_SRS_VERSION: u8 = 5;

const RULE_TYPE_DEFAULT: u8 = 0;
const RULE_TYPE_LOGICAL: u8 = 1;

const LOGICAL_AND: u8 = 0;
const LOGICAL_OR: u8 = 1;

const ITEM_QUERY_TYPE: u8 = 0;
const ITEM_NETWORK: u8 = 1;
const ITEM_DOMAIN: u8 = 2;
const ITEM_DOMAIN_KEYWORD: u8 = 3;
const ITEM_DOMAIN_REGEX: u8 = 4;
const ITEM_SOURCE_IP_CIDR: u8 = 5;
const ITEM_IP_CIDR: u8 = 6;
const ITEM_SOURCE_PORT: u8 = 7;
const ITEM_SOURCE_PORT_RANGE: u8 = 8;
const ITEM_PORT: u8 = 9;
const ITEM_PORT_RANGE: u8 = 10;
const ITEM_PROCESS_NAME: u8 = 11;
const ITEM_PROCESS_PATH: u8 = 12;
const ITEM_PACKAGE_NAME: u8 = 13;
const ITEM_WIFI_SSID: u8 = 14;
const ITEM_WIFI_BSSID: u8 = 15;
const ITEM_ADGUARD_DOMAIN: u8 = 16;
const ITEM_PROCESS_PATH_REGEX: u8 = 17;
const ITEM_NETWORK_TYPE: u8 = 18;
const ITEM_NETWORK_IS_EXPENSIVE: u8 = 19;
const ITEM_NETWORK_IS_CONSTRAINED: u8 = 20;
const ITEM_NETWORK_INTERFACE_ADDRESS: u8 = 21;
const ITEM_DEFAULT_INTERFACE_ADDRESS: u8 = 22;
const ITEM_PACKAGE_NAME_REGEX: u8 = 23;
const ITEM_FINAL: u8 = 0xff;

pub(crate) fn parse_srs(bytes: &[u8]) -> Result<CompiledList, RulesError> {
    if bytes.len() > MAX_LIST_BYTES {
        return Err(RulesError::ListTooLarge);
    }
    if bytes.len() < 4 || bytes[..3] != SRS_MAGIC {
        return Err(RulesError::InvalidSrs);
    }
    let version = bytes[3];
    if !(MIN_SRS_VERSION..=MAX_SRS_VERSION).contains(&version) {
        return Err(RulesError::UnsupportedSrsVersion(version));
    }

    let mut decompressed = Vec::new();
    let decoder = ZlibDecoder::new(&bytes[4..]);
    decoder
        .take(MAX_LIST_BYTES as u64 + 1)
        .read_to_end(&mut decompressed)
        .map_err(|_| RulesError::InvalidSrs)?;
    if decompressed.len() > MAX_LIST_BYTES {
        return Err(RulesError::ListTooLarge);
    }

    let mut cursor = Cursor::new(&decompressed);
    let rule_count = cursor.read_len(1)?;
    let mut entries = 0_usize;
    let mut regex_count = 0_usize;
    count_entries(&mut entries, rule_count)?;

    let mut rules = Vec::with_capacity(rule_count);
    for _ in 0..rule_count {
        rules.push(read_rule(&mut cursor, 0, &mut entries, &mut regex_count)?);
    }
    Ok(CompiledList { rules })
}

fn read_rule(
    cursor: &mut Cursor<'_>,
    depth: usize,
    entries: &mut usize,
    regex_count: &mut usize,
) -> Result<CompiledListRule, RulesError> {
    if depth > MAX_LOGICAL_DEPTH {
        return Err(RulesError::InvalidSrs);
    }
    match cursor.read_u8()? {
        RULE_TYPE_DEFAULT => read_default_rule(cursor, entries, regex_count)
            .map(|rule| CompiledListRule::Default(Box::new(rule))),
        RULE_TYPE_LOGICAL => {
            read_logical_rule(cursor, depth, entries, regex_count).map(CompiledListRule::Logical)
        }
        _ => Err(RulesError::InvalidSrs),
    }
}

fn read_logical_rule(
    cursor: &mut Cursor<'_>,
    depth: usize,
    entries: &mut usize,
    regex_count: &mut usize,
) -> Result<LogicalListRule, RulesError> {
    let mode = match cursor.read_u8()? {
        LOGICAL_AND => LogicalMode::And,
        LOGICAL_OR => LogicalMode::Or,
        _ => return Err(RulesError::InvalidSrs),
    };
    let count = cursor.read_len(1)?;
    count_entries(entries, count)?;
    let mut rules = Vec::with_capacity(count);
    for _ in 0..count {
        rules.push(read_rule(cursor, depth + 1, entries, regex_count)?);
    }
    let invert = cursor.read_bool()?;
    Ok(LogicalListRule {
        mode,
        rules,
        invert,
    })
}

fn read_default_rule(
    cursor: &mut Cursor<'_>,
    entries: &mut usize,
    regex_count: &mut usize,
) -> Result<DefaultListRule, RulesError> {
    let mut rule = DefaultListRule::default();
    loop {
        match cursor.read_u8()? {
            ITEM_QUERY_TYPE | ITEM_SOURCE_PORT | ITEM_PORT => {
                let count = cursor.read_len(2)?;
                count_entries(entries, count)?;
                cursor.take(count * 2)?;
                rule.has_unmatchable = true;
            }
            ITEM_NETWORK
            | ITEM_SOURCE_PORT_RANGE
            | ITEM_PORT_RANGE
            | ITEM_PACKAGE_NAME
            | ITEM_PACKAGE_NAME_REGEX
            | ITEM_WIFI_SSID
            | ITEM_WIFI_BSSID => {
                let values = read_string_slice(cursor, entries)?;
                let _ = values;
                rule.has_unmatchable = true;
            }
            ITEM_DOMAIN => {
                let matcher = read_succinct_matcher(cursor, entries, false)?;
                rule.succinct_domains.push(matcher);
            }
            ITEM_ADGUARD_DOMAIN => {
                let matcher = read_succinct_matcher(cursor, entries, true)?;
                rule.succinct_domains.push(matcher);
            }
            ITEM_DOMAIN_KEYWORD => {
                let values = read_string_slice(cursor, entries)?;
                rule.keywords
                    .extend(values.into_iter().map(|s| s.to_lowercase()));
            }
            ITEM_DOMAIN_REGEX => {
                for pattern in read_string_slice(cursor, entries)? {
                    rule.domain_regexes
                        .push(compile_regex(&pattern, regex_count)?);
                }
            }
            ITEM_SOURCE_IP_CIDR => {
                skip_ip_set(cursor, entries)?;
                rule.has_unmatchable = true;
            }
            ITEM_IP_CIDR => {
                read_ip_set_into(cursor, entries, &mut rule.cidrs)?;
            }
            ITEM_PROCESS_NAME => {
                let set = rule.process_names.get_or_insert_with(HashSet::new);
                set.extend(read_string_slice(cursor, entries)?);
            }
            ITEM_PROCESS_PATH => {
                let set = rule.process_paths.get_or_insert_with(HashSet::new);
                set.extend(read_string_slice(cursor, entries)?);
            }
            ITEM_PROCESS_PATH_REGEX => {
                let regexes = rule.process_path_regexes.get_or_insert_with(Vec::new);
                for pattern in read_string_slice(cursor, entries)? {
                    regexes.push(compile_regex(&pattern, regex_count)?);
                }
            }
            ITEM_NETWORK_TYPE => {
                let count = cursor.read_len(1)?;
                count_entries(entries, count)?;
                cursor.take(count)?;
                rule.has_unmatchable = true;
            }
            ITEM_NETWORK_IS_EXPENSIVE | ITEM_NETWORK_IS_CONSTRAINED => {
                count_entries(entries, 1)?;
                rule.has_unmatchable = true;
            }
            ITEM_NETWORK_INTERFACE_ADDRESS => {
                let map_len = cursor.read_len(2)?;
                count_entries(entries, map_len)?;
                for _ in 0..map_len {
                    let _key = cursor.read_u8()?;
                    let prefix_count = cursor.read_len(6)?;
                    count_entries(entries, prefix_count)?;
                    for _ in 0..prefix_count {
                        skip_prefix(cursor)?;
                    }
                }
                rule.has_unmatchable = true;
            }
            ITEM_DEFAULT_INTERFACE_ADDRESS => {
                let prefix_count = cursor.read_len(6)?;
                count_entries(entries, prefix_count)?;
                for _ in 0..prefix_count {
                    skip_prefix(cursor)?;
                }
                rule.has_unmatchable = true;
            }
            ITEM_FINAL => {
                rule.invert = cursor.read_bool()?;
                return Ok(rule);
            }
            _ => return Err(RulesError::InvalidSrs),
        }
    }
}

fn read_succinct_matcher(
    cursor: &mut Cursor<'_>,
    entries: &mut usize,
    allow_wildcard: bool,
) -> Result<SuccinctDomainSet, RulesError> {
    let version = cursor.read_u8()?;
    if version != 0 {
        return Err(RulesError::InvalidSrs);
    }
    let leaves = read_u64_slice(cursor)?;
    let label_bitmap = read_u64_slice(cursor)?;
    let labels_len = cursor.read_len(1)?;
    let labels = cursor.take(labels_len)?.to_vec();
    count_entries(entries, 1)?;
    SuccinctDomainSet::from_raw(leaves, label_bitmap, labels, allow_wildcard)
}

fn read_u64_slice(cursor: &mut Cursor<'_>) -> Result<Vec<u64>, RulesError> {
    let count = cursor.read_len(8)?;
    let raw = cursor.take(count * 8)?;
    let (chunks, _) = raw.as_chunks::<8>();
    Ok(chunks
        .iter()
        .map(|chunk| u64::from_be_bytes(*chunk))
        .collect())
}

fn read_string_slice(
    cursor: &mut Cursor<'_>,
    entries: &mut usize,
) -> Result<Vec<String>, RulesError> {
    let count = cursor.read_len(1)?;
    count_entries(entries, count)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let len = cursor.read_len(1)?;
        let raw = cursor.take(len)?;
        let text = std::str::from_utf8(raw).map_err(|_| RulesError::InvalidSrs)?;
        values.push(text.to_owned());
    }
    Ok(values)
}

fn read_ip_set_header(cursor: &mut Cursor<'_>, entries: &mut usize) -> Result<usize, RulesError> {
    let version = cursor.read_u8()?;
    if version != 1 {
        return Err(RulesError::InvalidSrs);
    }
    let raw_count = cursor.read_u64_be()?;
    let count = usize::try_from(raw_count).map_err(|_| RulesError::InvalidSrs)?;
    // Each range encodes at least two 4-byte addresses with 1-byte length prefixes (10 bytes).
    if count.checked_mul(10).is_none_or(|min| min > cursor.len()) {
        return Err(RulesError::InvalidSrs);
    }
    count_entries(entries, count)?;
    Ok(count)
}

fn read_ip_set_addr(cursor: &mut Cursor<'_>) -> Result<std::net::IpAddr, RulesError> {
    let addr_len = cursor.read_uvarint()?;
    if addr_len != 4 && addr_len != 16 {
        return Err(RulesError::InvalidSrs);
    }
    let raw = cursor.take(addr_len as usize)?;
    ip_from_bytes(raw).ok_or(RulesError::InvalidSrs)
}

fn read_ip_set_into(
    cursor: &mut Cursor<'_>,
    entries: &mut usize,
    tree: &mut super::cidr::CidrTree,
) -> Result<(), RulesError> {
    let count = read_ip_set_header(cursor, entries)?;
    for _ in 0..count {
        let from = read_ip_set_addr(cursor)?;
        let to = read_ip_set_addr(cursor)?;
        if from.is_ipv4() != to.is_ipv4() || from > to {
            return Err(RulesError::InvalidSrs);
        }
        tree.insert_range(from, to);
    }
    Ok(())
}

fn skip_ip_set(cursor: &mut Cursor<'_>, entries: &mut usize) -> Result<(), RulesError> {
    let count = read_ip_set_header(cursor, entries)?;
    for _ in 0..count {
        let from = read_ip_set_addr(cursor)?;
        let to = read_ip_set_addr(cursor)?;
        if from.is_ipv4() != to.is_ipv4() || from > to {
            return Err(RulesError::InvalidSrs);
        }
    }
    Ok(())
}

fn skip_prefix(cursor: &mut Cursor<'_>) -> Result<(), RulesError> {
    let addr_len = cursor.read_uvarint()?;
    if addr_len != 4 && addr_len != 16 {
        return Err(RulesError::InvalidSrs);
    }
    let _ = cursor.take(addr_len as usize)?;
    let prefix_bits = cursor.read_u8()?;
    let max_bits = if addr_len == 4 { 32 } else { 128 };
    if prefix_bits > max_bits {
        return Err(RulesError::InvalidSrs);
    }
    Ok(())
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn len(&self) -> usize {
        self.remaining.len()
    }

    fn read_u8(&mut self) -> Result<u8, RulesError> {
        let (&byte, rest) = self.remaining.split_first().ok_or(RulesError::InvalidSrs)?;
        self.remaining = rest;
        Ok(byte)
    }

    fn read_bool(&mut self) -> Result<bool, RulesError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(RulesError::InvalidSrs),
        }
    }

    fn read_u64_be(&mut self) -> Result<u64, RulesError> {
        let raw = self.take(8)?;
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(raw);
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_uvarint(&mut self) -> Result<u64, RulesError> {
        let mut value = 0_u64;
        for shift in (0..=63).step_by(7) {
            let byte = self.read_u8()?;
            if shift == 63 && byte > 1 {
                return Err(RulesError::InvalidSrs);
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(RulesError::InvalidSrs)
    }

    /// Reads a uvarint length and checks that at least `count * min_bytes`
    /// remain in the input before any allocation occurs.
    fn read_len(&mut self, min_bytes: usize) -> Result<usize, RulesError> {
        let raw = self.read_uvarint()?;
        let count = usize::try_from(raw).map_err(|_| RulesError::InvalidSrs)?;
        if count
            .checked_mul(min_bytes)
            .is_none_or(|needed| needed > self.remaining.len())
        {
            return Err(RulesError::InvalidSrs);
        }
        Ok(count)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], RulesError> {
        if count > self.remaining.len() {
            return Err(RulesError::InvalidSrs);
        }
        let (head, rest) = self.remaining.split_at(count);
        self.remaining = rest;
        Ok(head)
    }
}

#[cfg(test)]
pub(crate) mod test_encoder {
    use std::io::Write;
    use std::net::IpAddr;

    use flate2::Compression;
    use flate2::write::ZlibEncoder;

    use super::*;
    use crate::rules::domain::encode_succinct_domains;

    #[derive(Default)]
    pub(crate) struct SrsDefaultRule<'a> {
        pub(crate) domain: &'a [&'a str],
        pub(crate) domain_suffix: &'a [&'a str],
        pub(crate) domain_keyword: &'a [&'a str],
        pub(crate) domain_regex: &'a [&'a str],
        pub(crate) ip_ranges: &'a [(IpAddr, IpAddr)],
        pub(crate) process_name: &'a [&'a str],
        pub(crate) process_path: &'a [&'a str],
        pub(crate) process_path_regex: &'a [&'a str],
        pub(crate) ports: &'a [u16],
        pub(crate) invert: bool,
    }

    pub(crate) enum SrsRule<'a> {
        Default(SrsDefaultRule<'a>),
        Logical {
            mode: LogicalMode,
            rules: &'a [SrsRule<'a>],
            invert: bool,
        },
    }

    pub(crate) fn encode_srs(version: u8, rules: &[SrsRule<'_>]) -> Vec<u8> {
        let mut body = Vec::new();
        write_uvarint(&mut body, rules.len() as u64);
        for rule in rules {
            write_rule(&mut body, rule, version == 1);
        }
        wrap_srs(version, &body)
    }

    pub(crate) fn wrap_srs(version: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&SRS_MAGIC);
        out.push(version);
        let mut encoder = ZlibEncoder::new(out, Compression::default());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    pub(crate) fn write_uvarint(out: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            out.push((value as u8) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }

    fn write_rule(out: &mut Vec<u8>, rule: &SrsRule<'_>, legacy_v1: bool) {
        match rule {
            SrsRule::Default(rule) => {
                out.push(RULE_TYPE_DEFAULT);
                if !rule.domain.is_empty() || !rule.domain_suffix.is_empty() {
                    out.push(ITEM_DOMAIN);
                    let (leaves, bm, labels) =
                        encode_succinct_domains(rule.domain, rule.domain_suffix, legacy_v1);
                    out.push(0);
                    write_u64_slice(out, &leaves);
                    write_u64_slice(out, &bm);
                    write_uvarint(out, labels.len() as u64);
                    out.extend_from_slice(&labels);
                }
                if !rule.domain_keyword.is_empty() {
                    write_string_item(out, ITEM_DOMAIN_KEYWORD, rule.domain_keyword);
                }
                if !rule.domain_regex.is_empty() {
                    write_string_item(out, ITEM_DOMAIN_REGEX, rule.domain_regex);
                }
                if !rule.ip_ranges.is_empty() {
                    out.push(ITEM_IP_CIDR);
                    out.push(1);
                    out.extend_from_slice(&(rule.ip_ranges.len() as u64).to_be_bytes());
                    for &(from, to) in rule.ip_ranges {
                        write_ip_addr(out, from);
                        write_ip_addr(out, to);
                    }
                }
                if !rule.ports.is_empty() {
                    out.push(ITEM_PORT);
                    write_uvarint(out, rule.ports.len() as u64);
                    for &port in rule.ports {
                        out.extend_from_slice(&port.to_be_bytes());
                    }
                }
                if !rule.process_name.is_empty() {
                    write_string_item(out, ITEM_PROCESS_NAME, rule.process_name);
                }
                if !rule.process_path.is_empty() {
                    write_string_item(out, ITEM_PROCESS_PATH, rule.process_path);
                }
                if !rule.process_path_regex.is_empty() {
                    write_string_item(out, ITEM_PROCESS_PATH_REGEX, rule.process_path_regex);
                }
                out.push(ITEM_FINAL);
                out.push(u8::from(rule.invert));
            }
            SrsRule::Logical {
                mode,
                rules,
                invert,
            } => {
                out.push(RULE_TYPE_LOGICAL);
                out.push(match mode {
                    LogicalMode::And => LOGICAL_AND,
                    LogicalMode::Or => LOGICAL_OR,
                });
                write_uvarint(out, rules.len() as u64);
                for sub in *rules {
                    write_rule(out, sub, legacy_v1);
                }
                out.push(u8::from(*invert));
            }
        }
    }

    fn write_u64_slice(out: &mut Vec<u8>, values: &[u64]) {
        write_uvarint(out, values.len() as u64);
        for &value in values {
            out.extend_from_slice(&value.to_be_bytes());
        }
    }

    fn write_string_item(out: &mut Vec<u8>, item: u8, values: &[&str]) {
        out.push(item);
        write_uvarint(out, values.len() as u64);
        for value in values {
            write_uvarint(out, value.len() as u64);
            out.extend_from_slice(value.as_bytes());
        }
    }

    fn write_ip_addr(out: &mut Vec<u8>, addr: IpAddr) {
        match addr {
            IpAddr::V4(v4) => {
                write_uvarint(out, 4);
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                write_uvarint(out, 16);
                out.extend_from_slice(&v6.octets());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::IpAddr;

    use super::test_encoder::{SrsDefaultRule, SrsRule, encode_srs, wrap_srs, write_uvarint};
    use super::*;
    use crate::net::Resolve;
    use crate::rules::EvalCtx;

    struct NoResolve;

    impl Resolve for NoResolve {
        fn resolve(&self, _name: &str) -> io::Result<Vec<IpAddr>> {
            Err(io::Error::new(io::ErrorKind::NotFound, "unused"))
        }
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn matches(
        list: &CompiledList,
        domain: Option<&str>,
        addr: Option<IpAddr>,
        process: Option<&str>,
    ) -> bool {
        let lowered = domain.map(str::to_lowercase);
        let mut ctx = EvalCtx::new(lowered.as_deref(), addr, process, &NoResolve);
        list.matches(&mut ctx)
    }

    #[test]
    fn srs_round_trips_domains_ips_regexes_processes_and_logical_rules() {
        for version in [1_u8, 2, 3, 4] {
            let bytes = encode_srs(
                version,
                &[
                    SrsRule::Default(SrsDefaultRule {
                        domain: &["exact.example.com"],
                        domain_suffix: &["example.org", ".sub.example.net"],
                        domain_keyword: &["secret-kw"],
                        domain_regex: &[r"^re[0-9]+\.example\.invalid$"],
                        ip_ranges: &[
                            (ip("192.0.2.10"), ip("192.0.2.20")),
                            (ip("2001:db8::1"), ip("2001:db8::4")),
                        ],
                        ..Default::default()
                    }),
                    SrsRule::Logical {
                        mode: LogicalMode::And,
                        rules: &[
                            SrsRule::Default(SrsDefaultRule {
                                domain_suffix: &["gated.invalid"],
                                ..Default::default()
                            }),
                            SrsRule::Default(SrsDefaultRule {
                                domain: &["skip.gated.invalid"],
                                invert: true,
                                ..Default::default()
                            }),
                        ],
                        invert: false,
                    },
                    SrsRule::Default(SrsDefaultRule {
                        process_name: &["app.exe"],
                        process_path_regex: &[r"[/\\]bin[/\\]app\.exe$"],
                        ..Default::default()
                    }),
                ],
            );

            let list = parse_srs(&bytes).unwrap();
            assert!(matches(&list, Some("exact.example.com"), None, None));
            assert!(!matches(&list, Some("a.exact.example.com"), None, None));
            assert!(matches(&list, Some("example.org"), None, None));
            assert!(matches(&list, Some("www.example.org"), None, None));
            assert!(!matches(&list, Some("badexample.org"), None, None));
            assert!(!matches(&list, Some("sub.example.net"), None, None));
            assert!(matches(&list, Some("a.sub.example.net"), None, None));
            assert!(matches(&list, Some("my-secret-kw.invalid"), None, None));
            assert!(matches(&list, Some("re99.example.invalid"), None, None));
            assert!(!matches(&list, Some("re.example.invalid"), None, None));

            assert!(matches(&list, None, Some(ip("192.0.2.15")), None));
            assert!(!matches(&list, None, Some(ip("192.0.2.21")), None));
            assert!(matches(&list, None, Some(ip("2001:db8::3")), None));
            assert!(!matches(&list, None, Some(ip("2001:db8::5")), None));

            assert!(matches(&list, Some("ok.gated.invalid"), None, None));
            assert!(!matches(&list, Some("skip.gated.invalid"), None, None));

            assert!(matches(&list, None, None, Some("/usr/bin/app.exe")));
            assert!(!matches(&list, None, None, Some("/opt/other/app.exe")));
        }
    }

    #[test]
    fn unmatchable_proxy_items_never_match_even_when_inverted() {
        let bytes = encode_srs(
            3,
            &[
                SrsRule::Default(SrsDefaultRule {
                    ports: &[443],
                    invert: false,
                    ..Default::default()
                }),
                SrsRule::Default(SrsDefaultRule {
                    ports: &[443],
                    invert: true,
                    ..Default::default()
                }),
            ],
        );
        let list = parse_srs(&bytes).unwrap();
        assert!(!matches(
            &list,
            Some("example.com"),
            Some(ip("192.0.2.1")),
            None
        ));
    }

    #[test]
    fn malformed_and_truncated_srs_inputs_fail_closed_without_panicking() {
        let mut huge_rules = Vec::new();
        write_uvarint(&mut huge_rules, 1_u64 << 40);

        let mut huge_ip_count = vec![1, RULE_TYPE_DEFAULT, ITEM_IP_CIDR, 1];
        huge_ip_count.extend_from_slice(&(1_u64 << 40).to_be_bytes());

        let mut empty_domain = vec![1, RULE_TYPE_DEFAULT, ITEM_DOMAIN, 0, 0, 0, 0];
        empty_domain.extend_from_slice(&[ITEM_FINAL, 0]);

        let mut deep_logical = vec![1];
        for _ in 0..150 {
            deep_logical.extend_from_slice(&[RULE_TYPE_LOGICAL, LOGICAL_AND, 1]);
        }

        let cases: Vec<Vec<u8>> = vec![
            vec![],
            b"SRS".to_vec(),
            b"NOPE\x01".to_vec(),
            b"SRS\x00".to_vec(),
            b"SRS\x06".to_vec(),
            b"SRS\x03not-zlib".to_vec(),
            wrap_srs(3, &huge_rules),
            wrap_srs(3, &huge_ip_count),
            wrap_srs(3, &empty_domain),
            wrap_srs(3, &deep_logical),
            wrap_srs(3, &[1, 99]),
            wrap_srs(3, &[1, RULE_TYPE_DEFAULT, 200]),
        ];

        for case in cases {
            assert!(parse_srs(&case).is_err());
        }

        let valid = encode_srs(
            3,
            &[SrsRule::Default(SrsDefaultRule {
                domain: &["example.com"],
                ip_ranges: &[(ip("192.0.2.0"), ip("192.0.2.255"))],
                ..Default::default()
            })],
        );
        for cut in 0..valid.len() {
            assert!(parse_srs(&valid[..cut]).is_err(), "cut={cut}");
        }
    }
}
