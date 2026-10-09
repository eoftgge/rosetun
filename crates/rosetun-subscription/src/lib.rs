#![forbid(unsafe_code)]

mod common;
mod json;
mod links;
mod meta;

use std::collections::BTreeMap;
use std::fmt;

use rosetun_config::{Node, SubscriptionInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Links { base64: bool },
    XrayJson,
    SingBoxJson,
}

pub struct Parsed {
    pub format: Format,
    pub nodes: Vec<Node>,
    pub skipped: Vec<Skipped>,
    pub meta: SubscriptionMeta,
}

impl fmt::Debug for Parsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Parsed")
            .field("format", &self.format)
            .field("node_count", &self.nodes.len())
            .field("skipped", &self.skipped)
            .field("meta", &self.meta)
            .finish()
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct SubscriptionMeta {
    pub title: Option<String>,
    pub info: Option<SubscriptionInfo>,
    pub update_interval_hours: Option<u64>,
    pub support_url: Option<String>,
    pub web_page_url: Option<String>,
    pub announce: Option<String>,
    pub notices: Vec<String>,
}

impl fmt::Debug for SubscriptionMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscriptionMeta")
            .field("has_title", &self.title.is_some())
            .field("info", &self.info)
            .field("update_interval_hours", &self.update_interval_hours)
            .field("has_support_url", &self.support_url.is_some())
            .field("has_web_page_url", &self.web_page_url.is_some())
            .field("has_announce", &self.announce.is_some())
            .field("notice_count", &self.notices.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub index: usize,
    pub scheme: Option<String>,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnsupportedTransport {
    Xhttp,
    SplitHttp,
    Kcp,
    Quic,
    H2,
    Http,
    Other,
}

impl fmt::Display for UnsupportedTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Xhttp => "xhttp",
            Self::SplitHttp => "splithttp",
            Self::Kcp => "kcp",
            Self::Quic => "quic",
            Self::H2 => "h2",
            Self::Http => "http",
            Self::Other => "unknown",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SkipReason {
    InvalidRecord,
    InvalidPort,
    MissingField,
    InvalidJson { line: usize, column: usize },
    UnsupportedProtocol,
    ClientSettings,
    UnsupportedVmessFormat,
    UnsupportedTransport(UnsupportedTransport),
    UnsupportedTcpHeader,
    UnsupportedGrpcMultiMode,
    UnsupportedEncryption,
    UnsupportedFlow,
    UnsupportedSecurity,
    MissingRealityPublicKey,
    ShadowsocksPlugin,
    UnsupportedShadowsocksMethod,
    UnsupportedObfs,
    UnsupportedPin,
    ServiceRecord,
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRecord => f.write_str("record is invalid"),
            Self::InvalidPort => f.write_str("port must be between 1 and 65535"),
            Self::MissingField => f.write_str("a required field is missing"),
            Self::InvalidJson { line, column } => {
                write!(f, "invalid JSON at line {line}, column {column}")
            }
            Self::UnsupportedProtocol => f.write_str("protocol is not supported yet"),
            Self::ClientSettings => f.write_str("client settings are not node records"),
            Self::UnsupportedVmessFormat => {
                f.write_str("only the v2rayN JSON vmess link format is supported")
            }
            Self::UnsupportedTransport(transport) => {
                write!(f, "{transport} transport is not supported")
            }
            Self::UnsupportedTcpHeader => {
                f.write_str("TCP HTTP header camouflage is not supported")
            }
            Self::UnsupportedGrpcMultiMode => f.write_str("gRPC multi mode is not supported"),
            Self::UnsupportedEncryption => f.write_str("VLESS encryption is not supported"),
            Self::UnsupportedFlow => f.write_str("flow is not supported"),
            Self::UnsupportedSecurity => f.write_str("security mode is not supported"),
            Self::MissingRealityPublicKey => f.write_str("Reality public key is missing"),
            Self::ShadowsocksPlugin => f.write_str("Shadowsocks plugins are not supported"),
            Self::UnsupportedShadowsocksMethod => {
                f.write_str("Shadowsocks method is not supported")
            }
            Self::UnsupportedObfs => f.write_str("Hysteria2 obfuscation type is not supported"),
            Self::UnsupportedPin => f.write_str("Hysteria2 certificate pin is not supported"),
            Self::ServiceRecord => f.write_str("record contains a provider notice"),
        }
    }
}

pub enum ParseError {
    Empty,
    WebPage,
    UnsupportedFormat,
    EncryptedHappLink,
    UnrecognizedFormat,
    InvalidUtf8,
    InvalidJson {
        line: usize,
        column: usize,
    },
    DeviceLimit {
        max_devices_reached: bool,
        not_supported: bool,
        announce: Option<String>,
    },
    NoUsableNodes {
        skipped: Vec<Skipped>,
        notices: Vec<String>,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("subscription body is empty"),
            Self::WebPage => f.write_str("server returned a web page instead of a subscription"),
            Self::UnsupportedFormat => f.write_str("subscription format is not supported"),
            Self::EncryptedHappLink => f.write_str(
                "Happ link is encrypted; ask your provider for a regular subscription link",
            ),
            Self::UnrecognizedFormat => f.write_str("subscription format is not recognized"),
            Self::InvalidUtf8 => f.write_str("subscription body is not valid UTF-8"),
            Self::InvalidJson { line, column } => {
                write!(
                    f,
                    "invalid subscription JSON at line {line}, column {column}"
                )
            }
            Self::DeviceLimit { .. } => {
                f.write_str("subscription access was refused by the device policy")
            }
            Self::NoUsableNodes { .. } => f.write_str("subscription contains no usable nodes"),
        }
    }
}

impl fmt::Debug for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceLimit {
                max_devices_reached,
                not_supported,
                announce,
            } => f
                .debug_struct("DeviceLimit")
                .field("max_devices_reached", max_devices_reached)
                .field("not_supported", not_supported)
                .field("has_announce", &announce.is_some())
                .finish(),
            Self::NoUsableNodes { skipped, notices } => f
                .debug_struct("NoUsableNodes")
                .field("skipped", skipped)
                .field("notice_count", &notices.len())
                .finish(),
            Self::InvalidJson { line, column } => f
                .debug_struct("InvalidJson")
                .field("line", line)
                .field("column", column)
                .finish(),
            Self::Empty => f.write_str("Empty"),
            Self::WebPage => f.write_str("WebPage"),
            Self::UnsupportedFormat => f.write_str("UnsupportedFormat"),
            Self::EncryptedHappLink => f.write_str("EncryptedHappLink"),
            Self::UnrecognizedFormat => f.write_str("UnrecognizedFormat"),
            Self::InvalidUtf8 => f.write_str("InvalidUtf8"),
        }
    }
}

impl std::error::Error for ParseError {}

pub fn parse(body: &[u8], header: &dyn Fn(&str) -> Option<String>) -> Result<Parsed, ParseError> {
    let max_devices_reached = header_true(header, "x-hwid-max-devices-reached");
    let not_supported = header_true(header, "x-hwid-not-supported");
    let limited = header_true(header, "x-hwid-limit");

    if max_devices_reached || not_supported || limited {
        let announce = header("announce").and_then(|value| meta::display_text(&value, 1000));
        return Err(ParseError::DeviceLimit {
            max_devices_reached,
            not_supported,
            announce,
        });
    }

    let body = body.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(body);
    let text = std::str::from_utf8(body)
        .map_err(|_| ParseError::InvalidUtf8)?
        .trim();
    if text.is_empty() {
        return Err(ParseError::Empty);
    }

    let mut metadata = meta::from_headers(header);
    match classify(text)? {
        Some(format) => parse_text(text, format, &mut metadata),
        None => {
            let decoded = common::decode_base64(text).ok_or(ParseError::UnrecognizedFormat)?;
            let text = std::str::from_utf8(&decoded)
                .map_err(|_| ParseError::UnrecognizedFormat)?
                .trim_start_matches('\u{feff}')
                .trim();
            let format = classify(text)?.ok_or(ParseError::UnrecognizedFormat)?;
            let format = match format {
                Format::Links { .. } => Format::Links { base64: true },
                other => other,
            };
            parse_text(text, format, &mut metadata)
        }
    }
}

fn header_true(header: &dyn Fn(&str) -> Option<String>, key: &str) -> bool {
    header(key).is_some_and(|value| value.trim().eq_ignore_ascii_case("true"))
}

fn classify(text: &str) -> Result<Option<Format>, ParseError> {
    if starts_ascii_case(text, "<!doctype") || starts_ascii_case(text, "<html") {
        return Err(ParseError::WebPage);
    }
    if text.starts_with('{') || text.starts_with('[') {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|error| ParseError::InvalidJson {
                line: error.line(),
                column: error.column(),
            })?;
        return json::format(&value).map(Some);
    }
    if text
        .lines()
        .any(|line| line.trim_start().starts_with("proxies:"))
    {
        return Err(ParseError::UnsupportedFormat);
    }
    if text.starts_with("happ://crypt") {
        return Err(ParseError::EncryptedHappLink);
    }
    if text
        .lines()
        .any(|line| !line.trim_start().starts_with('#') && line.contains("://"))
    {
        return Ok(Some(Format::Links { base64: false }));
    }
    Ok(None)
}

fn starts_ascii_case(text: &str, prefix: &str) -> bool {
    text.get(..prefix.len())
        .is_some_and(|part| part.eq_ignore_ascii_case(prefix))
}

fn parse_text(
    text: &str,
    format: Format,
    metadata: &mut SubscriptionMeta,
) -> Result<Parsed, ParseError> {
    let mut nodes = Vec::new();
    let mut skipped = Vec::new();
    let mut ids = BTreeMap::<String, usize>::new();

    let records = match format {
        Format::Links { .. } => {
            let mut records = Vec::new();
            for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
                if line.starts_with('#') {
                    meta::apply_comment(metadata, line);
                } else {
                    records.push(links::parse(line));
                }
            }
            records
        }
        Format::XrayJson | Format::SingBoxJson => {
            let value: serde_json::Value =
                serde_json::from_str(text).map_err(|error| ParseError::InvalidJson {
                    line: error.line(),
                    column: error.column(),
                })?;
            json::records(&value, format)
        }
    };

    for (offset, (scheme, entry)) in records.into_iter().enumerate() {
        let entry = match entry {
            Entry::Node(node) if common::is_service(&node) => Entry::Notice(node.name),
            entry => entry,
        };
        match entry {
            Entry::Node(mut node) => {
                let base = common::stable_id(&node);
                let count = ids.entry(base.clone()).or_default();
                *count += 1;
                node.id = if *count == 1 {
                    base.into()
                } else {
                    format!("{base}-{count}").into()
                };
                nodes.push(*node);
            }
            Entry::Notice(text) => {
                if !text.is_empty() {
                    metadata.notices.push(text);
                }
                skipped.push(Skipped {
                    index: offset + 1,
                    scheme,
                    reason: SkipReason::ServiceRecord,
                });
            }
            Entry::Skip(reason) => skipped.push(Skipped {
                index: offset + 1,
                scheme,
                reason,
            }),
        }
    }

    if nodes.is_empty() {
        return Err(ParseError::NoUsableNodes {
            skipped,
            notices: std::mem::take(&mut metadata.notices),
        });
    }

    Ok(Parsed {
        format,
        nodes,
        skipped,
        meta: std::mem::take(metadata),
    })
}

pub(crate) enum Entry {
    Node(Box<Node>),
    Notice(String),
    Skip(SkipReason),
}

impl From<Result<Node, SkipReason>> for Entry {
    fn from(result: Result<Node, SkipReason>) -> Self {
        match result {
            Ok(node) => Self::Node(Box::new(node)),
            Err(reason) => Self::Skip(reason),
        }
    }
}

type Record = (Option<String>, Entry);
