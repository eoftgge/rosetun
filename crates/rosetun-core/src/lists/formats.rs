use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rosetun_config::{DomainMatch, ListCategoryError, ListFormat};
use serde_json::{Value, json};

use crate::rules::parse_domain_input;

const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 1_000_000;
const ALLOWED_KEYS: [&str; 7] = [
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "ip_cidr",
    "process_name",
    "process_path",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFormat {
    Binary,
    Source,
}

pub struct ListPayload {
    pub format: PayloadFormat,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for ListPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListPayload")
            .field("format", &self.format)
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

pub(crate) struct InspectedList {
    pub format: ListFormat,
    pub categories: Vec<String>,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for InspectedList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InspectedList")
            .field("format", &self.format)
            .field("category_count", &self.categories.len())
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextErrorKind {
    InvalidUtf8,
    InvalidDomain,
    InvalidIpCidr,
    EmptyValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextLineError {
    pub line: usize,
    pub kind: TextErrorKind,
}

#[derive(thiserror::Error)]
pub enum ListParseError {
    #[error("list exceeds the 32 MiB input limit")]
    InputTooLarge,
    #[error("list payload exceeds the 16 MiB limit")]
    PayloadTooLarge,
    #[error("list payload exceeds the 1,000,000 entry limit")]
    TooManyEntries,
    #[error("invalid sing-box binary header")]
    InvalidSrs,
    #[error("unsupported sing-box binary version {0}")]
    UnsupportedSrsVersion(u8),
    #[error("invalid sing-box source JSON")]
    InvalidJson,
    #[error("invalid sing-box source: {0}")]
    InvalidSource(&'static str),
    #[error("unsupported sing-box rule key: {}", safe_rule_key(.0))]
    UnsupportedRuleKey(String),
    #[error("invalid Xray dat protobuf")]
    InvalidProtobuf,
    #[error("could not identify Xray dat entry type")]
    UnknownDatType,
    #[error("invalid text list: {}", text_error_summary(errors, *remaining))]
    TextLines {
        errors: Vec<TextLineError>,
        remaining: usize,
    },
    #[error(transparent)]
    Category(#[from] ListCategoryError),
    #[error("reverse_match categories are not supported")]
    ReverseMatch,
    #[error("the selected list contains no entries")]
    EmptyResult,
}

// Neither Debug nor the ordinary errors print downloaded list contents or payload bytes.
impl fmt::Debug for ListParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedRuleKey(_) => f.write_str("UnsupportedRuleKey(<redacted>)"),
            other => write!(f, "{other}"),
        }
    }
}

fn safe_rule_key(key: &str) -> &str {
    if !key.is_empty()
        && key.len() <= 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        key
    } else {
        "<redacted>"
    }
}

fn text_error_summary(errors: &[TextLineError], remaining: usize) -> String {
    let mut summary = errors
        .iter()
        .map(|error| {
            let reason = match error.kind {
                TextErrorKind::InvalidUtf8 => "invalid UTF-8",
                TextErrorKind::InvalidDomain => "invalid domain",
                TextErrorKind::InvalidIpCidr => "invalid IP/CIDR",
                TextErrorKind::EmptyValue => "empty value",
            };
            format!("line {}: {reason}", error.line)
        })
        .collect::<Vec<_>>()
        .join("; ");
    if remaining > 0 {
        summary.push_str(&format!("; and {remaining} more"));
    }
    summary
}

pub(crate) fn inspect(bytes: &[u8], hint: Option<&str>) -> Result<InspectedList, ListParseError> {
    check_input(bytes)?;
    let hint = hint
        .and_then(|name| name.split(['?', '#']).next())
        .and_then(|name| name.rsplit('.').next())
        .unwrap_or_default();
    let hint = hint.to_ascii_lowercase();
    let first = bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace());

    // Field 1 (0x0a) is also a newline in text, so only a valid protobuf
    // overrides a text hint. Non-UTF-8 input may have unknown fields first.
    let probable_dat = bytes.first() == Some(&0x0a) || std::str::from_utf8(bytes).is_err();
    let dat = probable_dat.then(|| detect_dat(bytes).ok()).flatten();
    let format = if bytes.starts_with(b"SRS") {
        ListFormat::SingBoxBinary
    } else if first == Some(b'{') {
        ListFormat::SingBoxSource
    } else if let Some(format) = dat {
        format
    } else if hint == "srs" {
        ListFormat::SingBoxBinary
    } else if hint == "json" {
        ListFormat::SingBoxSource
    } else if hint == "dat" {
        detect_dat(bytes)?
    } else {
        ListFormat::Text
    };

    let (categories, bytes) = match format {
        ListFormat::SingBoxBinary => {
            check_srs(bytes)?;
            check_payload_size(bytes.len())?;
            (Vec::new(), bytes.to_vec())
        }
        ListFormat::SingBoxSource => (Vec::new(), normalize_json(bytes)?),
        ListFormat::GeoSite | ListFormat::GeoIp => {
            let parsed = read_dat(bytes, None)?;
            if parsed.format != format {
                return Err(ListParseError::UnknownDatType);
            }
            (parsed.categories, bytes.to_vec())
        }
        ListFormat::Text => {
            let records = read_text(bytes)?;
            let _ = source_payload(records)?;
            (Vec::new(), bytes.to_vec())
        }
    };
    Ok(InspectedList {
        format,
        categories,
        bytes,
    })
}

pub(crate) fn payload(
    bytes: &[u8],
    format: ListFormat,
    category: Option<&str>,
) -> Result<ListPayload, ListParseError> {
    check_input(bytes)?;
    let (format, bytes) = match format {
        ListFormat::SingBoxBinary => {
            no_category(category)?;
            check_srs(bytes)?;
            check_payload_size(bytes.len())?;
            (PayloadFormat::Binary, bytes.to_vec())
        }
        ListFormat::SingBoxSource => {
            no_category(category)?;
            (PayloadFormat::Source, normalize_json(bytes)?)
        }
        ListFormat::Text => {
            no_category(category)?;
            (PayloadFormat::Source, source_payload(read_text(bytes)?)?)
        }
        ListFormat::GeoSite | ListFormat::GeoIp => {
            let category = category.ok_or(ListCategoryError::Required)?;
            let selection = Selection::parse(category, format)?;
            let parsed = read_dat(bytes, Some(&selection))?;
            if parsed.format != format {
                return Err(ListParseError::UnknownDatType);
            }
            if !parsed.categories.contains(&selection.base.to_owned()) {
                return Err(ListCategoryError::Unknown.into());
            }
            if parsed.reverse_match {
                return Err(ListParseError::ReverseMatch);
            }
            (PayloadFormat::Source, source_payload(parsed.records)?)
        }
    };
    Ok(ListPayload { format, bytes })
}

fn check_input(bytes: &[u8]) -> Result<(), ListParseError> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(ListParseError::InputTooLarge);
    }
    Ok(())
}

fn check_payload_size(bytes: usize) -> Result<(), ListParseError> {
    if bytes > MAX_PAYLOAD_BYTES {
        return Err(ListParseError::PayloadTooLarge);
    }
    Ok(())
}

fn no_category(category: Option<&str>) -> Result<(), ListParseError> {
    if category.is_some() {
        return Err(ListCategoryError::Unexpected.into());
    }
    Ok(())
}

fn check_srs(bytes: &[u8]) -> Result<(), ListParseError> {
    if bytes.len() < 4 || &bytes[..3] != b"SRS" {
        return Err(ListParseError::InvalidSrs);
    }
    if bytes[3] > 5 {
        return Err(ListParseError::UnsupportedSrsVersion(bytes[3]));
    }
    Ok(())
}

fn normalize_json(bytes: &[u8]) -> Result<Vec<u8>, ListParseError> {
    let source: Value = serde_json::from_slice(bytes).map_err(|_| ListParseError::InvalidJson)?;
    let root = source
        .as_object()
        .ok_or(ListParseError::InvalidSource("expected an object"))?;
    if root.len() != 2 || !root.contains_key("version") || !root.contains_key("rules") {
        return Err(ListParseError::InvalidSource(
            "expected only version and rules at the root",
        ));
    }
    if root["version"].as_u64().is_none() {
        return Err(ListParseError::InvalidSource(
            "version must be a nonnegative integer",
        ));
    }
    let rules = root["rules"]
        .as_array()
        .ok_or(ListParseError::InvalidSource("rules must be an array"))?;
    let mut count = 0_usize;
    for rule in rules {
        let rule = rule
            .as_object()
            .ok_or(ListParseError::InvalidSource("each rule must be an object"))?;
        let before = count;
        for (key, values) in rule {
            if !ALLOWED_KEYS.contains(&key.as_str()) {
                return Err(ListParseError::UnsupportedRuleKey(key.clone()));
            }
            let values = values.as_array().ok_or(ListParseError::InvalidSource(
                "rule conditions must be arrays of strings",
            ))?;
            for value in values {
                if value.as_str().is_none_or(|value| value.trim().is_empty()) {
                    return Err(ListParseError::InvalidSource(
                        "rule conditions must contain nonempty strings",
                    ));
                }
                count += 1;
                if count > MAX_ENTRIES {
                    return Err(ListParseError::TooManyEntries);
                }
            }
        }
        if count == before {
            return Err(ListParseError::InvalidSource("a rule has no conditions"));
        }
    }
    if count == 0 {
        return Err(ListParseError::EmptyResult);
    }
    let output = serde_json::to_vec(&source).map_err(|_| ListParseError::InvalidJson)?;
    check_payload_size(output.len())?;
    Ok(output)
}

struct Record {
    key: &'static str,
    value: String,
}

fn source_payload(records: Vec<Record>) -> Result<Vec<u8>, ListParseError> {
    if records.is_empty() {
        return Err(ListParseError::EmptyResult);
    }
    if records.len() > MAX_ENTRIES {
        return Err(ListParseError::TooManyEntries);
    }
    let mut conditions: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for record in records {
        conditions.entry(record.key).or_default().push(record.value);
    }
    let bytes = serde_json::to_vec(&json!({"version": 3, "rules": [conditions]}))
        .map_err(|_| ListParseError::InvalidJson)?;
    check_payload_size(bytes.len())?;
    Ok(bytes)
}

fn read_text(bytes: &[u8]) -> Result<Vec<Record>, ListParseError> {
    let text = std::str::from_utf8(bytes).map_err(|error| ListParseError::TextLines {
        errors: vec![TextLineError {
            line: bytes[..error.valid_up_to()]
                .iter()
                .filter(|&&byte| byte == b'\n')
                .count()
                + 1,
            kind: TextErrorKind::InvalidUtf8,
        }],
        remaining: 0,
    })?;
    let mut records = Vec::new();
    let mut errors = Vec::new();
    let mut remaining = 0;
    for (index, line) in text.lines().enumerate() {
        let line = line.split_once('#').map_or(line, |(entry, _)| entry).trim();
        if line.is_empty() {
            continue;
        }
        match parse_text_line(line) {
            Ok(record) => {
                records.push(record);
                if records.len() > MAX_ENTRIES {
                    return Err(ListParseError::TooManyEntries);
                }
            }
            Err(kind) => {
                if errors.len() < 5 {
                    errors.push(TextLineError {
                        line: index + 1,
                        kind,
                    });
                } else {
                    remaining += 1;
                }
            }
        }
    }
    if !errors.is_empty() {
        return Err(ListParseError::TextLines { errors, remaining });
    }
    Ok(records)
}

fn parse_text_line(line: &str) -> Result<Record, TextErrorKind> {
    let (kind, value) = ["full:", "domain:", "keyword:", "regexp:"]
        .into_iter()
        .find_map(|prefix| {
            line.strip_prefix(prefix)
                .map(|value| (prefix, value.trim()))
        })
        .unwrap_or(("", line));
    if value.is_empty() {
        return Err(TextErrorKind::EmptyValue);
    }
    match kind {
        "keyword:" | "regexp:" => Ok(Record {
            key: if kind == "keyword:" {
                "domain_keyword"
            } else {
                "domain_regex"
            },
            value: value.to_owned(),
        }),
        _ => {
            if kind.is_empty() && (value.parse::<IpAddr>().is_ok() || value.contains('/')) {
                return parse_ip_cidr(value);
            }
            if value.contains(['/', '?', '#']) || value.contains("://") {
                return Err(TextErrorKind::InvalidDomain);
            }
            let domain = parse_domain_input(value).map_err(|_| TextErrorKind::InvalidDomain)?;
            let (key, value) = match domain {
                DomainMatch::Exact(value) => (
                    if kind == "full:" {
                        "domain"
                    } else {
                        "domain_suffix"
                    },
                    value,
                ),
                DomainMatch::Suffix(value) if kind != "full:" => ("domain_suffix", value),
                DomainMatch::Suffix(_) | DomainMatch::Keyword(_) => {
                    return Err(TextErrorKind::InvalidDomain);
                }
            };
            Ok(Record { key, value })
        }
    }
}

fn parse_ip_cidr(value: &str) -> Result<Record, TextErrorKind> {
    let (ip, prefix) = match value.split_once('/') {
        Some((ip, prefix)) => {
            let ip = ip
                .parse::<IpAddr>()
                .map_err(|_| TextErrorKind::InvalidIpCidr)?;
            let prefix = prefix
                .parse::<u8>()
                .map_err(|_| TextErrorKind::InvalidIpCidr)?;
            (ip, prefix)
        }
        None => {
            let ip = value
                .parse::<IpAddr>()
                .map_err(|_| TextErrorKind::InvalidIpCidr)?;
            let prefix = if ip.is_ipv4() { 32 } else { 128 };
            (ip, prefix)
        }
    };
    if prefix > if ip.is_ipv4() { 32 } else { 128 } {
        return Err(TextErrorKind::InvalidIpCidr);
    }
    Ok(Record {
        key: "ip_cidr",
        value: format!("{ip}/{prefix}"),
    })
}

struct Selection<'a> {
    base: &'a str,
    filter: Option<(&'a str, bool)>,
}

impl<'a> Selection<'a> {
    fn parse(category: &'a str, format: ListFormat) -> Result<Self, ListParseError> {
        let (base, filter) = match category.split_once('@') {
            Some((base, filter)) => {
                let (filter, negative) = match filter.strip_prefix('!') {
                    Some(filter) => (filter, true),
                    None => (filter, false),
                };
                if format != ListFormat::GeoSite
                    || filter.is_empty()
                    || !filter.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'_' | b'-')
                    })
                {
                    return Err(ListCategoryError::InvalidFilter.into());
                }
                (base, Some((filter, negative)))
            }
            None => (category, None),
        };
        if base.is_empty() {
            return Err(ListCategoryError::Unknown.into());
        }
        Ok(Self { base, filter })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DatKind {
    Site,
    Ip,
}

impl DatKind {
    fn format(self) -> ListFormat {
        match self {
            Self::Site => ListFormat::GeoSite,
            Self::Ip => ListFormat::GeoIp,
        }
    }
}

struct ParsedDat {
    format: ListFormat,
    categories: Vec<String>,
    records: Vec<Record>,
    reverse_match: bool,
}

fn detect_dat(bytes: &[u8]) -> Result<ListFormat, ListParseError> {
    let mut reader = Reader::new(bytes);
    while let Some(field) = reader.next()? {
        if field.number == 1 {
            return detect_entry_kind(field.bytes()?).map(DatKind::format);
        }
    }
    Err(ListParseError::UnknownDatType)
}

fn detect_entry_kind(bytes: &[u8]) -> Result<DatKind, ListParseError> {
    let mut reader = Reader::new(bytes);
    while let Some(field) = reader.next()? {
        if field.number == 2 {
            let mut element = Reader::new(field.bytes()?);
            while let Some(child) = element.next()? {
                let kind = match (child.number, child.value) {
                    (1, FieldValue::Varint(_)) | (2, FieldValue::Bytes(_)) => Some(DatKind::Site),
                    (1, FieldValue::Bytes(ip)) if matches!(ip.len(), 4 | 16) => Some(DatKind::Ip),
                    (2, FieldValue::Varint(_)) => Some(DatKind::Ip),
                    (1 | 2, _) => return Err(ListParseError::UnknownDatType),
                    _ => None,
                };
                if let Some(kind) = kind {
                    return Ok(kind);
                }
            }
            return Err(ListParseError::UnknownDatType);
        }
    }
    Err(ListParseError::UnknownDatType)
}

fn read_dat(bytes: &[u8], selection: Option<&Selection<'_>>) -> Result<ParsedDat, ListParseError> {
    let kind = match detect_dat(bytes)? {
        ListFormat::GeoSite => DatKind::Site,
        ListFormat::GeoIp => DatKind::Ip,
        _ => unreachable!("dat detection returns only GeoSite or GeoIp"),
    };
    let mut reader = Reader::new(bytes);
    let mut categories = BTreeSet::new();
    let mut records = Vec::new();
    let mut reverse_match = false;
    while let Some(field) = reader.next()? {
        if field.number != 1 {
            continue;
        }
        let entry = field.bytes()?;
        if kind == DatKind::Site {
            let category = read_site_entry(entry, selection, &mut records)?;
            categories.insert(category);
        } else {
            let (category, reverse) = read_ip_entry(entry, selection, &mut records)?;
            if selection.is_some_and(|selected| selected.base == category) {
                reverse_match |= reverse;
            }
            categories.insert(category);
        }
        if categories.len() > MAX_ENTRIES {
            return Err(ListParseError::TooManyEntries);
        }
    }
    Ok(ParsedDat {
        format: kind.format(),
        categories: categories.into_iter().collect(),
        records,
        reverse_match,
    })
}

fn push_record(records: &mut Vec<Record>, record: Record) -> Result<(), ListParseError> {
    if records.len() >= MAX_ENTRIES {
        return Err(ListParseError::TooManyEntries);
    }
    records.push(record);
    Ok(())
}

fn read_site_entry(
    bytes: &[u8],
    selection: Option<&Selection<'_>>,
    records: &mut Vec<Record>,
) -> Result<String, ListParseError> {
    // Protobuf does not guarantee field order: discover the category before
    // deciding whether any of its domains need to be materialized.
    let mut reader = Reader::new(bytes);
    let mut category = None;
    while let Some(field) = reader.next()? {
        if field.number == 1 {
            category = Some(read_category(field.bytes()?)?);
        }
    }
    let category = category.ok_or(ListParseError::InvalidProtobuf)?;
    let selected = selection.filter(|selection| selection.base == category);
    let mut reader = Reader::new(bytes);
    while let Some(field) = reader.next()? {
        if field.number == 2
            && let Some(record) = read_domain(field.bytes()?, selected)?
        {
            push_record(records, record)?;
        }
    }
    Ok(category)
}

fn read_ip_entry(
    bytes: &[u8],
    selection: Option<&Selection<'_>>,
    records: &mut Vec<Record>,
) -> Result<(String, bool), ListParseError> {
    let mut reader = Reader::new(bytes);
    let mut category = None;
    let mut reverse = false;
    while let Some(field) = reader.next()? {
        match field.number {
            1 => category = Some(read_category(field.bytes()?)?),
            3 => reverse = field.varint()? != 0,
            _ => {}
        }
    }
    let category = category.ok_or(ListParseError::InvalidProtobuf)?;
    let selected = selection.is_some_and(|selection| selection.base == category);
    let mut reader = Reader::new(bytes);
    while let Some(field) = reader.next()? {
        if field.number == 2
            && let Some(record) = read_cidr(field.bytes()?, selected)?
        {
            push_record(records, record)?;
        }
    }
    Ok((category, reverse))
}

fn read_category(bytes: &[u8]) -> Result<String, ListParseError> {
    let category = std::str::from_utf8(bytes).map_err(|_| ListParseError::InvalidProtobuf)?;
    if category.is_empty() {
        return Err(ListParseError::InvalidProtobuf);
    }
    Ok(category.to_lowercase())
}

fn read_domain(
    bytes: &[u8],
    selection: Option<&Selection<'_>>,
) -> Result<Option<Record>, ListParseError> {
    let mut reader = Reader::new(bytes);
    let mut kind = 0;
    let mut value = None;
    let mut has_attribute = false;
    while let Some(field) = reader.next()? {
        match field.number {
            1 => kind = field.varint()?,
            2 => {
                value = Some(
                    std::str::from_utf8(field.bytes()?)
                        .map_err(|_| ListParseError::InvalidProtobuf)?,
                );
            }
            3 => {
                has_attribute |= read_attribute(field.bytes()?, selection.and_then(|s| s.filter))?;
            }
            _ => {}
        }
    }
    let key = match kind {
        0 => "domain_keyword",
        1 => "domain_regex",
        2 => "domain_suffix",
        3 => "domain",
        _ => return Err(ListParseError::InvalidProtobuf),
    };
    let value = value
        .filter(|value| !value.is_empty())
        .ok_or(ListParseError::InvalidProtobuf)?;
    let selected = selection.is_some_and(|selection| {
        selection
            .filter
            .is_none_or(|(_, negative)| has_attribute != negative)
    });
    Ok(selected.then(|| Record {
        key,
        value: value.to_owned(),
    }))
}

fn read_attribute(bytes: &[u8], filter: Option<(&str, bool)>) -> Result<bool, ListParseError> {
    let mut reader = Reader::new(bytes);
    let mut key = None;
    while let Some(field) = reader.next()? {
        match field.number {
            1 => {
                key = Some(
                    std::str::from_utf8(field.bytes()?)
                        .map_err(|_| ListParseError::InvalidProtobuf)?,
                );
            }
            2 | 3 => {
                field.varint()?;
            }
            _ => {}
        }
    }
    let key = key
        .filter(|key| !key.is_empty())
        .ok_or(ListParseError::InvalidProtobuf)?;
    Ok(filter.is_some_and(|(requested, _)| key.eq_ignore_ascii_case(requested)))
}

fn read_cidr(bytes: &[u8], selected: bool) -> Result<Option<Record>, ListParseError> {
    let mut reader = Reader::new(bytes);
    let mut ip = None;
    let mut prefix = None;
    while let Some(field) = reader.next()? {
        match field.number {
            1 => {
                let bytes = field.bytes()?;
                ip = Some(match bytes {
                    [a, b, c, d] => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
                    bytes if bytes.len() == 16 => {
                        let mut octets = [0; 16];
                        octets.copy_from_slice(bytes);
                        IpAddr::V6(Ipv6Addr::from(octets))
                    }
                    _ => return Err(ListParseError::InvalidProtobuf),
                });
            }
            2 => prefix = Some(field.varint()?),
            _ => {}
        }
    }
    let ip = ip.ok_or(ListParseError::InvalidProtobuf)?;
    // Reject an omitted prefix rather than interpreting malformed data as /0.
    let prefix = prefix.ok_or(ListParseError::InvalidProtobuf)?;
    if prefix > if ip.is_ipv4() { 32 } else { 128 } {
        return Err(ListParseError::InvalidProtobuf);
    }
    Ok(selected.then(|| Record {
        key: "ip_cidr",
        value: format!("{ip}/{prefix}"),
    }))
}

struct Reader<'a> {
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
    fn bytes(&self) -> Result<&'a [u8], ListParseError> {
        match self.value {
            FieldValue::Bytes(bytes) => Ok(bytes),
            _ => Err(ListParseError::InvalidProtobuf),
        }
    }

    fn varint(&self) -> Result<u64, ListParseError> {
        match self.value {
            FieldValue::Varint(value) => Ok(value),
            _ => Err(ListParseError::InvalidProtobuf),
        }
    }
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn varint(&mut self) -> Result<u64, ListParseError> {
        let mut value = 0;
        for shift in (0..=63).step_by(7) {
            let Some((&byte, rest)) = self.remaining.split_first() else {
                return Err(ListParseError::InvalidProtobuf);
            };
            self.remaining = rest;
            if shift == 63 && byte > 1 {
                return Err(ListParseError::InvalidProtobuf);
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(ListParseError::InvalidProtobuf)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], ListParseError> {
        if count > self.remaining.len() {
            return Err(ListParseError::InvalidProtobuf);
        }
        let (bytes, rest) = self.remaining.split_at(count);
        self.remaining = rest;
        Ok(bytes)
    }

    fn next(&mut self) -> Result<Option<Field<'a>>, ListParseError> {
        while !self.remaining.is_empty() {
            let tag = self.varint()?;
            let number = tag >> 3;
            if number == 0 || number > u64::from(u32::MAX) {
                return Err(ListParseError::InvalidProtobuf);
            }
            let value = match tag & 7 {
                0 => FieldValue::Varint(self.varint()?),
                1 => {
                    self.take(8)?;
                    FieldValue::Fixed
                }
                2 => {
                    let count = usize::try_from(self.varint()?)
                        .map_err(|_| ListParseError::InvalidProtobuf)?;
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
                _ => return Err(ListParseError::InvalidProtobuf),
            };
            return Ok(Some(Field { number, value }));
        }
        Ok(None)
    }

    fn skip_group(&mut self, number: u64, depth: usize) -> Result<(), ListParseError> {
        if depth > 16 {
            return Err(ListParseError::InvalidProtobuf);
        }
        loop {
            let tag = self.varint()?;
            let field = tag >> 3;
            if field == 0 || field > u64::from(u32::MAX) {
                return Err(ListParseError::InvalidProtobuf);
            }
            match tag & 7 {
                0 => {
                    self.varint()?;
                }
                1 => {
                    self.take(8)?;
                }
                2 => {
                    let count = usize::try_from(self.varint()?)
                        .map_err(|_| ListParseError::InvalidProtobuf)?;
                    self.take(count)?;
                }
                3 => self.skip_group(field, depth + 1)?,
                4 if field == number => return Ok(()),
                5 => {
                    self.take(4)?;
                }
                _ => return Err(ListParseError::InvalidProtobuf),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(number: u8, bytes: &[u8]) -> Vec<u8> {
        let mut output = vec![(number << 3) | 2];
        varint(&mut output, bytes.len() as u64);
        output.extend_from_slice(bytes);
        output
    }

    fn varint(output: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            output.push(value as u8 | 0x80);
            value >>= 7;
        }
        output.push(value as u8);
    }

    fn number(field: u8, value: u64) -> Vec<u8> {
        let mut output = vec![field << 3];
        varint(&mut output, value);
        output
    }

    fn site_domain(kind: u64, value: &str, attrs: &[&str]) -> Vec<u8> {
        let mut domain = number(1, kind);
        domain.extend(field(2, value.as_bytes()));
        for attr in attrs {
            let mut attribute = field(1, attr.as_bytes());
            attribute.extend(number(2, 1));
            domain.extend(field(3, &attribute));
        }
        domain
    }

    fn site() -> Vec<u8> {
        let mut entry = field(1, b"EXAMPLE");
        entry.extend(field(2, &site_domain(0, "example", &[])));
        entry.extend(field(2, &site_domain(1, "example\\.com", &[])));
        entry.extend(field(2, &site_domain(2, "example.com", &["cn"])));
        entry.extend(field(2, &site_domain(3, "www.example.com", &["other"])));
        let mut bytes = field(1, &entry);
        let mut other = field(1, b"EMPTY");
        other.extend(field(2, &site_domain(2, "a.invalid", &[])));
        bytes.extend(field(1, &other));
        bytes
    }

    fn ip_list(reverse: bool) -> Vec<u8> {
        let mut cidr = field(1, &[192, 0, 2, 0]);
        cidr.extend(number(2, 24));
        let mut entry = field(1, b"EXAMPLE");
        entry.extend(field(2, &cidr));
        let mut cidr6 = field(1, &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0).octets());
        cidr6.extend(number(2, 32));
        entry.extend(field(2, &cidr6));
        if reverse {
            entry.extend(number(3, 1));
        }
        field(1, &entry)
    }

    fn source(bytes: &[u8], format: ListFormat, category: Option<&str>) -> Value {
        let payload = payload(bytes, format, category).unwrap();
        assert_eq!(payload.format, PayloadFormat::Source);
        serde_json::from_slice(&payload.bytes).unwrap()
    }

    #[test]
    fn srs_header_is_bounded_and_binary_bytes_are_preserved() {
        let bytes = b"SRS\x05\0\xff";
        let inspected = inspect(bytes, Some("wrong.json")).unwrap();
        assert_eq!(inspected.format, ListFormat::SingBoxBinary);
        assert_eq!(inspected.bytes, bytes);
        let result = payload(bytes, inspected.format, None).unwrap();
        assert_eq!(result.format, PayloadFormat::Binary);
        assert_eq!(result.bytes, bytes);
        assert!(matches!(
            inspect(b"BAD\x01", Some("file.srs")),
            Err(ListParseError::InvalidSrs)
        ));
        assert!(matches!(
            inspect(b"SRS\x06", None),
            Err(ListParseError::UnsupportedSrsVersion(6))
        ));
        assert!(matches!(
            inspect(b"SRS", None),
            Err(ListParseError::InvalidSrs)
        ));
    }

    #[test]
    fn json_is_normalized_and_rules_are_strict() {
        let bytes = br#" { "rules": [{"domain_suffix":["example.com"]},{"ip_cidr":["198.51.100.0/24"]}], "version":3 } "#;
        let inspected = inspect(bytes, Some("wrong.txt")).unwrap();
        assert_eq!(inspected.format, ListFormat::SingBoxSource);
        assert_eq!(
            inspect(bytes, Some("wrong.srs")).unwrap().format,
            inspected.format
        );
        assert_ne!(inspected.bytes, bytes);
        assert_eq!(
            inspected.bytes,
            payload(bytes, inspected.format, None).unwrap().bytes
        );
        let json: Value = serde_json::from_slice(&inspected.bytes).unwrap();
        assert_eq!(json["rules"].as_array().unwrap().len(), 2);
        for bad in [
            br#"{"version":"3","rules":[]}"#.as_slice(),
            br#"{"version":3.5,"rules":[{"domain":["example.com"]}]}"#,
            br#"{"version":-1,"rules":[{"domain":["example.com"]}]}"#,
            br#"{"version":3,"rules":[{}]}"#,
            br#"{"version":3,"rules":[{"domain":[]}]}"#,
            br#"{"version":3,"rules":[{"domain":[12]}]}"#,
            br#"{"version":3,"rules":[{"domain":[" "]}]}"#,
            br#"{"version":3,"rules":{},"extra":true}"#,
        ] {
            assert!(inspect(bad, None).is_err());
        }
        let err = inspect(br#"{"version":3,"rules":[{"url":"private-token"}]}"#, None).unwrap_err();
        assert!(matches!(err, ListParseError::UnsupportedRuleKey(ref key) if key == "url"));
        assert!(err.to_string().contains("url"));
        assert!(!format!("{err:?}").contains("url"));
        let secret_key = r#"{"version":3,"rules":[{"https://example.invalid/path?token=secret":["example.com"]}]}"#;
        let err = inspect(secret_key.as_bytes(), None).unwrap_err();
        assert!(err.to_string().contains("<redacted>"));
        assert!(!err.to_string().contains("secret"));
        assert!(!format!("{err:?}").contains("secret"));
        let long_key = "a".repeat(65);
        assert_eq!(safe_rule_key(&long_key), "<redacted>");
        assert!(matches!(
            inspect(b"{not json", None),
            Err(ListParseError::InvalidJson)
        ));
    }

    #[test]
    fn site_detects_and_filters_categories_and_attributes() {
        let bytes = site();
        let inspected = inspect(&bytes, Some("wrong.txt")).unwrap();
        assert_eq!(inspected.format, ListFormat::GeoSite);
        assert_eq!(
            inspect(&bytes, Some("wrong.json")).unwrap().format,
            inspected.format
        );
        assert_eq!(inspected.categories, ["empty", "example"]);
        assert_eq!(inspected.bytes, bytes);
        let all = source(&bytes, ListFormat::GeoSite, Some("example"));
        assert_eq!(all["version"], 3);
        assert_eq!(all["rules"][0]["domain_keyword"], json!(["example"]));
        assert_eq!(all["rules"][0]["domain_regex"], json!(["example\\.com"]));
        assert_eq!(all["rules"][0]["domain_suffix"], json!(["example.com"]));
        assert_eq!(all["rules"][0]["domain"], json!(["www.example.com"]));
        let filtered = source(&bytes, ListFormat::GeoSite, Some("example@cn"));
        assert_eq!(
            filtered["rules"][0],
            json!({"domain_suffix": ["example.com"]})
        );
        let negative = source(&bytes, ListFormat::GeoSite, Some("example@!cn"));
        assert!(negative["rules"][0].get("domain_suffix").is_none());
        assert!(matches!(
            payload(&bytes, ListFormat::GeoSite, Some("example@absent")),
            Err(ListParseError::EmptyResult)
        ));
        assert!(matches!(
            payload(&bytes, ListFormat::GeoSite, Some("unknown")),
            Err(ListParseError::Category(ListCategoryError::Unknown))
        ));
        assert!(matches!(
            payload(&bytes, ListFormat::GeoSite, Some("example@!")),
            Err(ListParseError::Category(ListCategoryError::InvalidFilter))
        ));
    }

    #[test]
    fn geoip_cidr_and_reverse_match_are_checked_on_selection() {
        let bytes = ip_list(true);
        let inspected = inspect(&bytes, None).unwrap();
        assert_eq!(inspected.format, ListFormat::GeoIp);
        assert_eq!(inspected.categories, ["example"]);
        assert!(matches!(
            payload(&bytes, ListFormat::GeoIp, Some("example")),
            Err(ListParseError::ReverseMatch)
        ));
        assert!(matches!(
            payload(&bytes, ListFormat::GeoIp, Some("example@cn")),
            Err(ListParseError::Category(ListCategoryError::InvalidFilter))
        ));
        let bytes = ip_list(false);
        assert_eq!(
            source(&bytes, ListFormat::GeoIp, Some("example"))["rules"][0]["ip_cidr"],
            json!(["192.0.2.0/24", "2001:db8::/32"])
        );
    }

    #[test]
    fn protobuf_skips_unknown_fields_and_rejects_truncation() {
        let mut bytes = site();
        bytes.extend(number(9, 111));
        bytes.extend([0x51, 0, 0, 0, 0, 0, 0, 0, 0]);
        bytes.extend([0x5d, 0, 0, 0, 0]);
        bytes.extend([0x63, 0x08, 0x01, 0x64]);
        assert_eq!(
            source(&bytes, ListFormat::GeoSite, Some("example"))["version"],
            3
        );
        let mut truncated = site();
        truncated.extend([0x0a, 0x80]);
        assert!(matches!(
            inspect(&truncated, Some("geo.dat")),
            Err(ListParseError::InvalidProtobuf)
        ));
        let mut bad_cidr = field(1, &[192, 0, 2, 0]);
        bad_cidr.extend(number(2, 33));
        let mut entry = field(1, b"EXAMPLE");
        entry.extend(field(2, &bad_cidr));
        assert!(matches!(
            inspect(&field(1, &entry), None),
            Err(ListParseError::InvalidProtobuf)
        ));
        let mut entry = field(1, b"EXAMPLE");
        entry.extend(field(2, &field(1, &[192, 0, 2, 0])));
        assert!(matches!(
            inspect(&field(1, &entry), Some("geoip.dat")),
            Err(ListParseError::InvalidProtobuf)
        ));
    }

    #[test]
    fn omitted_plain_type_is_detected_from_value_field() {
        let mut entry = field(2, &field(2, b"example.com"));
        entry.extend(field(1, b"EXAMPLE"));
        let bytes = field(1, &entry);
        assert_eq!(inspect(&bytes, None).unwrap().format, ListFormat::GeoSite);
        assert_eq!(
            source(&bytes, ListFormat::GeoSite, Some("example"))["rules"][0]["domain_keyword"],
            json!(["example.com"])
        );
    }

    #[test]
    fn leading_blank_line_is_text_without_dat_hint() {
        let bytes = b"\nexample.com\n";
        let inspected = inspect(bytes, None).unwrap();
        assert_eq!(inspected.format, ListFormat::Text);
        assert_eq!(
            source(bytes, inspected.format, None)["rules"][0]["domain_suffix"],
            json!(["example.com"])
        );
    }

    #[test]
    fn text_prefixes_ip_and_idn_make_a_single_source_rule() {
        let bytes = "# comment\nexample.com\nfull:example.com\ndomain:.invalid\nkeyword:example\nregexp:example\\.com\n192.0.2.0/24\n198.51.100.1\n2001:db8::/32\nпример.invalid\n".as_bytes();
        let inspected = inspect(bytes, None).unwrap();
        assert_eq!(inspected.format, ListFormat::Text);
        assert_eq!(inspected.bytes, bytes);
        let json = source(bytes, ListFormat::Text, None);
        assert_eq!(json["rules"].as_array().unwrap().len(), 1);
        let rule = &json["rules"][0];
        assert_eq!(
            rule["domain_suffix"],
            json!(["example.com", "invalid", "xn--e1afmkfd.invalid"])
        );
        assert_eq!(rule["domain"], json!(["example.com"]));
        assert_eq!(rule["domain_keyword"], json!(["example"]));
        assert_eq!(rule["domain_regex"], json!(["example\\.com"]));
        assert_eq!(
            rule["ip_cidr"],
            json!(["192.0.2.0/24", "198.51.100.1/32", "2001:db8::/32"])
        );
    }

    #[test]
    fn text_reports_up_to_five_errors_with_line_numbers_and_remaining_count() {
        let bad = b"# header\nfull:\n192.0.2.0/33\ninvalid host\nfull:.invalid\n198.51.100.0/nope\nexample.com/path\nregExp:\n";
        let err = inspect(bad, Some("file.txt")).unwrap_err();
        let ListParseError::TextLines { errors, remaining } = err else {
            panic!("expected text line errors");
        };
        assert_eq!(
            errors.iter().map(|error| error.line).collect::<Vec<_>>(),
            [2, 3, 4, 5, 6]
        );
        assert_eq!(remaining, 2);
        assert!(matches!(
            inspect(b"example.com\n\xff", None),
            Err(ListParseError::TextLines { .. })
        ));
    }

    #[test]
    fn input_payload_and_entry_limits_are_enforced() {
        assert!(matches!(
            inspect(&vec![b'a'; MAX_INPUT_BYTES + 1], None),
            Err(ListParseError::InputTooLarge)
        ));
        let mut huge_srs = b"SRS\x03".to_vec();
        huge_srs.resize(MAX_PAYLOAD_BYTES + 1, 0);
        assert!(matches!(
            inspect(&huge_srs, None),
            Err(ListParseError::PayloadTooLarge)
        ));
        let json = format!(
            "{{\"version\":3,\"rules\":[{{\"domain\":[\"{}\"]}}]}}",
            "a".repeat(MAX_PAYLOAD_BYTES)
        );
        assert!(matches!(
            inspect(json.as_bytes(), None),
            Err(ListParseError::PayloadTooLarge)
        ));
        let text = "example.com\n".repeat(MAX_ENTRIES + 1);
        assert!(matches!(
            inspect(text.as_bytes(), None),
            Err(ListParseError::TooManyEntries)
        ));
    }

    #[test]
    fn category_is_required_only_for_dat() {
        assert!(matches!(
            payload(b"SRS\x03", ListFormat::SingBoxBinary, Some("example")),
            Err(ListParseError::Category(ListCategoryError::Unexpected))
        ));
        assert!(matches!(
            payload(&site(), ListFormat::GeoSite, None),
            Err(ListParseError::Category(ListCategoryError::Required))
        ));
        assert!(matches!(
            inspect(b"# nothing\n", None),
            Err(ListParseError::EmptyResult)
        ));
    }

    #[test]
    fn unknown_fields_before_entries_and_reverse_match_on_other_category() {
        let mut bytes = number(9, 42);
        bytes.extend(ip_list(true));
        let mut other_cidr = field(1, &[198, 51, 100, 0]);
        other_cidr.extend(number(2, 24));
        let mut other = field(1, b"OTHER");
        other.extend(field(2, &other_cidr));
        bytes.extend(field(1, &other));
        assert_eq!(
            inspect(&bytes, Some("list.dat")).unwrap().categories,
            ["example", "other"]
        );
        assert_eq!(
            source(&bytes, ListFormat::GeoIp, Some("other"))["rules"][0]["ip_cidr"],
            json!(["198.51.100.0/24"])
        );
    }

    #[test]
    fn text_diagnostics_never_include_entries() {
        let error = inspect(b"full:secret invalid\n", None).unwrap_err();
        assert!(error.to_string().contains("line 1: invalid domain"));
        assert!(!format!("{error:?}").contains("secret"));
        let error = inspect(
            b"invalid host\ninvalid host\ninvalid host\ninvalid host\ninvalid host\ninvalid host\n",
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("and 1 more"));
    }

    #[test]
    fn unselected_dat_records_are_still_validated() {
        let mut site_bytes = site();
        let mut broken_site = field(1, b"OTHER");
        broken_site.extend(field(2, &number(1, 2)));
        site_bytes.extend(field(1, &broken_site));
        assert!(matches!(
            payload(&site_bytes, ListFormat::GeoSite, Some("example")),
            Err(ListParseError::InvalidProtobuf)
        ));

        let mut ip_bytes = ip_list(false);
        let mut broken_cidr = field(1, &[198, 51, 100, 0]);
        broken_cidr.extend(number(2, 33));
        let mut broken_ip = field(1, b"OTHER");
        broken_ip.extend(field(2, &broken_cidr));
        ip_bytes.extend(field(1, &broken_ip));
        assert!(matches!(
            payload(&ip_bytes, ListFormat::GeoIp, Some("example")),
            Err(ListParseError::InvalidProtobuf)
        ));
    }

    #[test]
    fn unselected_dat_category_streams_past_one_million_records() {
        let domain = field(2, &site_domain(0, "example.com", &[]));
        let mut bulk = domain.repeat(MAX_ENTRIES + 1);
        bulk.extend(field(1, b"BULK"));
        let mut bytes = field(1, &bulk);
        let mut small = field(2, &site_domain(2, "a.invalid", &[]));
        small.extend(field(1, b"OTHER"));
        bytes.extend(field(1, &small));
        assert_eq!(inspect(&bytes, None).unwrap().categories, ["bulk", "other"]);
        assert_eq!(
            source(&bytes, ListFormat::GeoSite, Some("other"))["rules"][0]["domain_suffix"],
            json!(["a.invalid"])
        );
        assert!(matches!(
            payload(&bytes, ListFormat::GeoSite, Some("bulk")),
            Err(ListParseError::TooManyEntries)
        ));
    }

    #[test]
    fn json_total_entry_limit_covers_multiple_rule_objects() {
        let mut source = String::from("{\"version\":3,\"rules\":[{\"domain\":[");
        for index in 0..=MAX_ENTRIES {
            if index == MAX_ENTRIES / 2 {
                source.push_str("\"example.com\"]},{\"domain_suffix\":[");
            } else {
                source.push_str("\"example.com\",");
            }
        }
        source.push_str("\"example.com\"]}]}");
        assert!(matches!(
            inspect(source.as_bytes(), None),
            Err(ListParseError::TooManyEntries)
        ));
    }
}
