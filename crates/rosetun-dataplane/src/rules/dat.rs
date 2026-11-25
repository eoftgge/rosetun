//! Xray `geosite.dat` and `geoip.dat` protobuf parser.

use rosetun_config::IpPrefix;

use super::RulesError;
use super::cidr::ip_from_bytes;
use super::list::{
    CompiledList, CompiledListRule, DefaultListRule, MAX_LIST_BYTES, compile_regex, count_entries,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum DatKind {
    Site,
    Ip,
}

struct Selection<'a> {
    base: String,
    filter: Option<(&'a str, bool)>,
}

impl<'a> Selection<'a> {
    fn parse(category: &'a str, kind: DatKind) -> Result<Self, RulesError> {
        let (base, filter) = match category.split_once('@') {
            Some((base, raw_filter)) => {
                let (filter, negative) = match raw_filter.strip_prefix('!') {
                    Some(rest) => (rest, true),
                    None => (raw_filter, false),
                };
                if kind != DatKind::Site
                    || filter.is_empty()
                    || !filter.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'_' | b'-')
                    })
                {
                    return Err(RulesError::InvalidDat);
                }
                (base, Some((filter, negative)))
            }
            None => (category, None),
        };
        if base.is_empty() {
            return Err(RulesError::InvalidDat);
        }
        Ok(Self {
            base: base.to_lowercase(),
            filter,
        })
    }
}

pub(crate) fn parse_dat(bytes: &[u8], category: &str) -> Result<CompiledList, RulesError> {
    if bytes.len() > MAX_LIST_BYTES {
        return Err(RulesError::ListTooLarge);
    }
    let kind = detect_dat(bytes)?;
    let selection = Selection::parse(category, kind)?;

    let mut reader = ProtoReader::new(bytes);
    let mut rule = DefaultListRule::default();
    let mut found_category = false;
    let mut entries = 0_usize;
    let mut regex_count = 0_usize;

    while let Some(field) = reader.next()? {
        if field.number != 1 {
            continue;
        }
        let entry = field.bytes()?;
        match kind {
            DatKind::Site => {
                if read_site_entry(entry, &selection, &mut rule, &mut entries, &mut regex_count)? {
                    found_category = true;
                }
            }
            DatKind::Ip => {
                if read_ip_entry(entry, &selection, &mut rule, &mut entries)? {
                    found_category = true;
                }
            }
        }
    }

    if !found_category {
        return Err(RulesError::UnknownCategory);
    }
    let rules = if rule.has_any_condition() {
        vec![CompiledListRule::Default(Box::new(rule))]
    } else {
        Vec::new()
    };
    Ok(CompiledList { rules })
}

fn detect_dat(bytes: &[u8]) -> Result<DatKind, RulesError> {
    let mut reader = ProtoReader::new(bytes);
    while let Some(field) = reader.next()? {
        if field.number == 1
            && let Some(kind) = detect_entry_kind(field.bytes()?)?
        {
            return Ok(kind);
        }
    }
    Err(RulesError::InvalidDat)
}

fn detect_entry_kind(bytes: &[u8]) -> Result<Option<DatKind>, RulesError> {
    let mut reader = ProtoReader::new(bytes);
    while let Some(field) = reader.next()? {
        if field.number == 2 {
            let mut element = ProtoReader::new(field.bytes()?);
            while let Some(child) = element.next()? {
                let kind = match (child.number, child.value) {
                    (1, FieldValue::Varint(_)) | (2, FieldValue::Bytes(_)) => Some(DatKind::Site),
                    (1, FieldValue::Bytes(ip)) if matches!(ip.len(), 4 | 16) => Some(DatKind::Ip),
                    (2, FieldValue::Varint(_)) => Some(DatKind::Ip),
                    (1 | 2, _) => return Err(RulesError::InvalidDat),
                    _ => None,
                };
                if kind.is_some() {
                    return Ok(kind);
                }
            }
            return Err(RulesError::InvalidDat);
        }
    }
    Ok(None)
}

fn read_site_entry(
    bytes: &[u8],
    selection: &Selection<'_>,
    rule: &mut DefaultListRule,
    entries: &mut usize,
    regex_count: &mut usize,
) -> Result<bool, RulesError> {
    // Protobuf fields may appear in any order: read the category code first.
    let mut reader = ProtoReader::new(bytes);
    let mut category = None;
    while let Some(field) = reader.next()? {
        if field.number == 1 {
            category = Some(read_category(field.bytes()?)?);
        }
    }
    let category = category.ok_or(RulesError::InvalidDat)?;
    let selected = category == selection.base;

    let mut reader = ProtoReader::new(bytes);
    while let Some(field) = reader.next()? {
        if field.number == 2 {
            read_domain(
                field.bytes()?,
                selected.then_some(selection),
                rule,
                entries,
                regex_count,
            )?;
        }
    }
    Ok(selected)
}

fn read_ip_entry(
    bytes: &[u8],
    selection: &Selection<'_>,
    rule: &mut DefaultListRule,
    entries: &mut usize,
) -> Result<bool, RulesError> {
    let mut reader = ProtoReader::new(bytes);
    let mut category = None;
    let mut reverse_match = false;
    while let Some(field) = reader.next()? {
        match field.number {
            1 => category = Some(read_category(field.bytes()?)?),
            3 => reverse_match = field.varint()? != 0,
            _ => {}
        }
    }
    let category = category.ok_or(RulesError::InvalidDat)?;
    let selected = category == selection.base;
    if selected && reverse_match {
        return Err(RulesError::Unsupported);
    }

    let mut reader = ProtoReader::new(bytes);
    while let Some(field) = reader.next()? {
        if field.number == 2 {
            read_cidr(field.bytes()?, selected, rule, entries)?;
        }
    }
    Ok(selected)
}

fn read_category(bytes: &[u8]) -> Result<String, RulesError> {
    let category = std::str::from_utf8(bytes).map_err(|_| RulesError::InvalidDat)?;
    if category.is_empty() {
        return Err(RulesError::InvalidDat);
    }
    Ok(category.to_lowercase())
}

fn read_domain(
    bytes: &[u8],
    selection: Option<&Selection<'_>>,
    rule: &mut DefaultListRule,
    entries: &mut usize,
    regex_count: &mut usize,
) -> Result<(), RulesError> {
    let mut reader = ProtoReader::new(bytes);
    let mut kind = 0_u64;
    let mut value = None;
    let mut has_attribute = false;

    while let Some(field) = reader.next()? {
        match field.number {
            1 => kind = field.varint()?,
            2 => {
                value =
                    Some(std::str::from_utf8(field.bytes()?).map_err(|_| RulesError::InvalidDat)?);
            }
            3 => {
                has_attribute |= read_attribute(field.bytes()?, selection.and_then(|s| s.filter))?;
            }
            _ => {}
        }
    }

    let value = value
        .filter(|text| !text.is_empty())
        .ok_or(RulesError::InvalidDat)?;
    if kind > 3 {
        return Err(RulesError::InvalidDat);
    }
    let Some(selection) = selection else {
        return Ok(());
    };
    let include = selection
        .filter
        .is_none_or(|(_, negative)| has_attribute != negative);
    if !include {
        return Ok(());
    }

    count_entries(entries, 1)?;
    match kind {
        0 => rule.keywords.push(value.to_lowercase()),
        1 => rule.domain_regexes.push(compile_regex(value, regex_count)?),
        2 => rule.suffixes.insert(value),
        3 => {
            rule.domains.insert(value.to_lowercase());
        }
        _ => return Err(RulesError::InvalidDat),
    }
    Ok(())
}

fn read_attribute(bytes: &[u8], filter: Option<(&str, bool)>) -> Result<bool, RulesError> {
    let mut reader = ProtoReader::new(bytes);
    let mut key = None;
    while let Some(field) = reader.next()? {
        match field.number {
            1 => {
                key =
                    Some(std::str::from_utf8(field.bytes()?).map_err(|_| RulesError::InvalidDat)?);
            }
            2 | 3 => {
                let _ = field.varint()?;
            }
            _ => {}
        }
    }
    let key = key
        .filter(|text| !text.is_empty())
        .ok_or(RulesError::InvalidDat)?;
    Ok(filter.is_some_and(|(requested, _)| key.eq_ignore_ascii_case(requested)))
}

fn read_cidr(
    bytes: &[u8],
    selected: bool,
    rule: &mut DefaultListRule,
    entries: &mut usize,
) -> Result<(), RulesError> {
    let mut reader = ProtoReader::new(bytes);
    let mut ip = None;
    let mut prefix = None;

    while let Some(field) = reader.next()? {
        match field.number {
            1 => {
                ip = Some(ip_from_bytes(field.bytes()?).ok_or(RulesError::InvalidDat)?);
            }
            2 => prefix = Some(field.varint()?),
            _ => {}
        }
    }

    let ip = ip.ok_or(RulesError::InvalidDat)?;
    let prefix = prefix.ok_or(RulesError::InvalidDat)?;
    let prefix = u8::try_from(prefix).map_err(|_| RulesError::InvalidDat)?;
    let prefix = IpPrefix::new(ip, prefix).ok_or(RulesError::InvalidDat)?;
    if selected {
        count_entries(entries, 1)?;
        rule.cidrs.insert(prefix);
    }
    Ok(())
}

struct ProtoReader<'a> {
    remaining: &'a [u8],
}

struct Field<'a> {
    number: u64,
    value: FieldValue<'a>,
}

enum FieldValue<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Fixed,
}

impl<'a> Field<'a> {
    fn bytes(&self) -> Result<&'a [u8], RulesError> {
        match self.value {
            FieldValue::Bytes(bytes) => Ok(bytes),
            _ => Err(RulesError::InvalidDat),
        }
    }

    fn varint(&self) -> Result<u64, RulesError> {
        match self.value {
            FieldValue::Varint(value) => Ok(value),
            _ => Err(RulesError::InvalidDat),
        }
    }
}

impl<'a> ProtoReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn varint(&mut self) -> Result<u64, RulesError> {
        let mut value = 0_u64;
        for shift in (0..=63).step_by(7) {
            let (&byte, rest) = self.remaining.split_first().ok_or(RulesError::InvalidDat)?;
            self.remaining = rest;
            if shift == 63 && byte > 1 {
                return Err(RulesError::InvalidDat);
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(RulesError::InvalidDat)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], RulesError> {
        if count > self.remaining.len() {
            return Err(RulesError::InvalidDat);
        }
        let (head, rest) = self.remaining.split_at(count);
        self.remaining = rest;
        Ok(head)
    }

    fn next(&mut self) -> Result<Option<Field<'a>>, RulesError> {
        while !self.remaining.is_empty() {
            let tag = self.varint()?;
            let number = tag >> 3;
            if number == 0 || number > u64::from(u32::MAX) {
                return Err(RulesError::InvalidDat);
            }
            let value = match tag & 7 {
                0 => FieldValue::Varint(self.varint()?),
                1 => {
                    self.take(8)?;
                    FieldValue::Fixed
                }
                2 => {
                    let count =
                        usize::try_from(self.varint()?).map_err(|_| RulesError::InvalidDat)?;
                    FieldValue::Bytes(self.take(count)?)
                }
                3 => {
                    self.skip_group(number, 1)?;
                    continue;
                }
                5 => {
                    self.take(4)?;
                    FieldValue::Fixed
                }
                _ => return Err(RulesError::InvalidDat),
            };
            return Ok(Some(Field { number, value }));
        }
        Ok(None)
    }

    fn skip_group(&mut self, number: u64, depth: usize) -> Result<(), RulesError> {
        if depth > 16 {
            return Err(RulesError::InvalidDat);
        }
        loop {
            let tag = self.varint()?;
            let field = tag >> 3;
            if field == 0 || field > u64::from(u32::MAX) {
                return Err(RulesError::InvalidDat);
            }
            match tag & 7 {
                0 => {
                    let _ = self.varint()?;
                }
                1 => {
                    self.take(8)?;
                }
                2 => {
                    let count =
                        usize::try_from(self.varint()?).map_err(|_| RulesError::InvalidDat)?;
                    self.take(count)?;
                }
                3 => self.skip_group(field, depth + 1)?,
                4 if field == number => return Ok(()),
                5 => {
                    self.take(4)?;
                }
                _ => return Err(RulesError::InvalidDat),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::IpAddr;

    use super::*;
    use crate::net::Resolve;
    use crate::rules::EvalCtx;

    struct NoResolve;

    impl Resolve for NoResolve {
        fn resolve(&self, _name: &str) -> io::Result<Vec<IpAddr>> {
            Err(io::Error::new(io::ErrorKind::NotFound, "unused"))
        }
    }

    fn varint(out: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            out.push((value as u8) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }

    fn bytes_field(number: u8, bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![(number << 3) | 2];
        varint(&mut out, bytes.len() as u64);
        out.extend_from_slice(bytes);
        out
    }

    fn varint_field(number: u8, value: u64) -> Vec<u8> {
        let mut out = vec![number << 3];
        varint(&mut out, value);
        out
    }

    fn site_domain(kind: u64, value: &str, attrs: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(varint_field(1, kind));
        out.extend(bytes_field(2, value.as_bytes()));
        for attr in attrs {
            let mut body = bytes_field(1, attr.as_bytes());
            body.extend(varint_field(2, 1));
            out.extend(bytes_field(3, &body));
        }
        bytes_field(2, &out)
    }

    fn site_entry(category: &str, domains: &[Vec<u8>]) -> Vec<u8> {
        let mut out = bytes_field(1, category.as_bytes());
        for domain in domains {
            out.extend_from_slice(domain);
        }
        bytes_field(1, &out)
    }

    fn cidr_entry(ip: &[u8], prefix: u64) -> Vec<u8> {
        let mut out = bytes_field(1, ip);
        out.extend(varint_field(2, prefix));
        bytes_field(2, &out)
    }

    fn ip_entry(category: &str, cidrs: &[Vec<u8>], reverse: bool) -> Vec<u8> {
        let mut out = bytes_field(1, category.as_bytes());
        for cidr in cidrs {
            out.extend_from_slice(cidr);
        }
        if reverse {
            out.extend(varint_field(3, 1));
        }
        bytes_field(1, &out)
    }

    fn matches(list: &CompiledList, domain: Option<&str>, ip: Option<&str>) -> bool {
        let lowered = domain.map(str::to_lowercase);
        let addr = ip.map(|s| s.parse::<IpAddr>().unwrap());
        let mut ctx = EvalCtx::new(lowered.as_deref(), addr, None, &NoResolve);
        list.matches(&mut ctx)
    }

    #[test]
    fn geosite_dat_matches_all_domain_types_and_attribute_filters() {
        let mut dat = Vec::new();
        dat.extend(site_entry(
            "EXAMPLE",
            &[
                site_domain(0, "kw-hit", &["mobile"]),
                site_domain(1, r"^re[0-9]+\.example\.org$", &[]),
                site_domain(2, "example.com", &["ads"]),
                site_domain(3, "exact.example.net", &[]),
            ],
        ));

        let all = parse_dat(&dat, "example").unwrap();
        assert!(matches(&all, Some("a-kw-hit.invalid"), None));
        assert!(matches(&all, Some("re5.example.org"), None));
        assert!(matches(&all, Some("www.example.com"), None));
        assert!(matches(&all, Some("exact.example.net"), None));
        assert!(!matches(&all, Some("sub.exact.example.net"), None));

        let only_ads = parse_dat(&dat, "example@ads").unwrap();
        assert!(matches(&only_ads, Some("sub.example.com"), None));
        assert!(!matches(&only_ads, Some("exact.example.net"), None));

        let without_ads = parse_dat(&dat, "example@!ads").unwrap();
        assert!(!matches(&without_ads, Some("sub.example.com"), None));
        assert!(matches(&without_ads, Some("exact.example.net"), None));
        assert!(matches(&without_ads, Some("re9.example.org"), None));
    }

    #[test]
    fn geoip_dat_matches_cidrs_and_rejects_reverse_match_as_unsupported() {
        let mut dat = Vec::new();
        dat.extend(ip_entry(
            "DOC",
            &[
                cidr_entry(&[192, 0, 2, 0], 24),
                cidr_entry(
                    &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    32,
                ),
            ],
            false,
        ));
        dat.extend(ip_entry("REV", &[cidr_entry(&[198, 51, 100, 0], 24)], true));

        let doc = parse_dat(&dat, "doc").unwrap();
        assert!(matches(&doc, None, Some("192.0.2.42")));
        assert!(!matches(&doc, None, Some("198.51.100.1")));
        assert!(matches(&doc, None, Some("2001:db8::99")));

        assert_eq!(parse_dat(&dat, "rev").unwrap_err(), RulesError::Unsupported);
        assert_eq!(
            parse_dat(&dat, "missing").unwrap_err(),
            RulesError::UnknownCategory
        );
        assert!(parse_dat(&dat, "doc@attr").is_err());
    }

    #[test]
    fn malformed_and_truncated_dat_inputs_fail_without_panicking() {
        let valid = ip_entry("DOC", &[cidr_entry(&[192, 0, 2, 0], 24)], false);
        for cut in 0..valid.len() {
            assert!(parse_dat(&valid[..cut], "doc").is_err(), "cut={cut}");
        }
        assert!(parse_dat(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff], "doc").is_err());
    }
}
