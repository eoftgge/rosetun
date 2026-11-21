use std::net::{IpAddr, Ipv6Addr};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rosetun_config::{
    Node, NodeId, Outbound, StreamSettings, WIREGUARD_MTU_MAX, WIREGUARD_MTU_MIN, WireGuardParams,
    is_valid_wireguard_address, is_valid_wireguard_key,
};
use serde_json::Value;
use url::Host;

use crate::common::{clean, decode_base64, endpoint, is_service_address, percent_decode};
use crate::{Entry, Record, SkipReason, SubscriptionMeta, meta};

const MAX_ADDRESSES: usize = 8;

pub(crate) struct WireGuardInput {
    pub(crate) name: String,
    pub(crate) server: String,
    pub(crate) port: u16,
    pub(crate) private_key: String,
    pub(crate) public_key: String,
    pub(crate) pre_shared_key: Option<String>,
    pub(crate) address: Vec<String>,
    pub(crate) reserved: Option<[u8; 3]>,
    pub(crate) mtu: Option<u16>,
    pub(crate) persistent_keepalive: Option<u16>,
}

pub(crate) fn build_node(input: WireGuardInput) -> Result<Node, SkipReason> {
    let mut name = clean(&input.name, 128);
    if name.is_empty() {
        name = clean(&endpoint(&input.server, input.port), 128);
    }
    let node = Node {
        id: NodeId::new(""),
        name,
        server: input.server,
        port: input.port,
        outbound: Outbound::WireGuard(WireGuardParams {
            private_key: input.private_key,
            public_key: input.public_key,
            pre_shared_key: input.pre_shared_key,
            address: input.address,
            reserved: input.reserved,
            mtu: input.mtu,
            persistent_keepalive: input.persistent_keepalive,
        }),
        stream: StreamSettings::default(),
        raw: None,
    };
    node.validate_proxy()
        .map_err(|_| SkipReason::InvalidRecord)?;
    Ok(node)
}

/// Decodes a 32-byte WireGuard Base64 key (standard or URL-safe, padded or unpadded)
/// into its canonical 44-character standard Base64 form.
pub(crate) fn canonical_key(value: &str) -> Result<String, SkipReason> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SkipReason::MissingField);
    }
    let bytes = decode_base64(trimmed).ok_or(SkipReason::InvalidRecord)?;
    if bytes.len() != 32 {
        return Err(SkipReason::InvalidRecord);
    }
    let encoded = STANDARD.encode(bytes);
    if !is_valid_wireguard_key(&encoded) {
        return Err(SkipReason::InvalidRecord);
    }
    Ok(encoded)
}

pub(crate) fn optional_key(value: Option<&str>) -> Result<Option<String>, SkipReason> {
    match value.map(str::trim) {
        None | Some("") => Ok(None),
        Some(raw) => canonical_key(raw).map(Some),
    }
}

/// Parses one or more comma-separated WireGuard interface addresses (CIDR or bare IP).
pub(crate) fn parse_addresses<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<String>, SkipReason> {
    let mut result = Vec::new();
    for raw in values {
        for part in raw.split(',') {
            let item = part.trim();
            if item.is_empty() {
                continue;
            }
            let normalized = normalize_address(item)?;
            if !result.contains(&normalized) {
                result.push(normalized);
            }
        }
    }
    if result.is_empty() {
        return Err(SkipReason::MissingField);
    }
    if result.len() > MAX_ADDRESSES {
        return Err(SkipReason::InvalidRecord);
    }
    Ok(result)
}

fn normalize_address(value: &str) -> Result<String, SkipReason> {
    if let Some((ip, prefix)) = value.split_once('/') {
        if !is_valid_wireguard_address(value) {
            return Err(SkipReason::InvalidRecord);
        }
        let parsed_ip: IpAddr = ip.parse().map_err(|_| SkipReason::InvalidRecord)?;
        return Ok(format!("{parsed_ip}/{prefix}"));
    }
    match value.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => Ok(format!("{ip}/32")),
        Ok(IpAddr::V6(ip)) => Ok(format!("{ip}/128")),
        Err(_) => Err(SkipReason::InvalidRecord),
    }
}

/// Parses 3 WireGuard `reserved` bytes from `1,2,3`, `[1,2,3]`, or 3-byte Base64.
pub(crate) fn parse_reserved_str(value: &str) -> Result<[u8; 3], SkipReason> {
    let trimmed = value.trim();
    let inner = trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(trimmed);
    if inner.contains(',') {
        let parts: Vec<_> = inner.split(',').map(str::trim).collect();
        if parts.len() != 3 {
            return Err(SkipReason::InvalidRecord);
        }
        let a = parts[0]
            .parse::<u8>()
            .map_err(|_| SkipReason::InvalidRecord)?;
        let b = parts[1]
            .parse::<u8>()
            .map_err(|_| SkipReason::InvalidRecord)?;
        let c = parts[2]
            .parse::<u8>()
            .map_err(|_| SkipReason::InvalidRecord)?;
        return Ok([a, b, c]);
    }
    let bytes = decode_base64(trimmed).ok_or(SkipReason::InvalidRecord)?;
    let array: [u8; 3] = bytes.try_into().map_err(|_| SkipReason::InvalidRecord)?;
    Ok(array)
}

pub(crate) fn parse_reserved_json(value: &Value) -> Result<Option<[u8; 3]>, SkipReason> {
    match value {
        Value::Null => Ok(None),
        Value::String(text) => {
            if text.trim().is_empty() {
                Ok(None)
            } else {
                parse_reserved_str(text).map(Some)
            }
        }
        Value::Array(items) => {
            if items.is_empty() {
                return Ok(None);
            }
            if items.len() != 3 {
                return Err(SkipReason::InvalidRecord);
            }
            let mut out = [0u8; 3];
            for (slot, item) in out.iter_mut().zip(items) {
                let number = item.as_u64().ok_or(SkipReason::InvalidRecord)?;
                *slot = u8::try_from(number).map_err(|_| SkipReason::InvalidRecord)?;
            }
            Ok(Some(out))
        }
        _ => Err(SkipReason::InvalidRecord),
    }
}

pub(crate) fn parse_mtu_str(value: &str) -> Result<u16, SkipReason> {
    let mtu: u16 = value
        .trim()
        .parse()
        .map_err(|_| SkipReason::InvalidRecord)?;
    if !(WIREGUARD_MTU_MIN..=WIREGUARD_MTU_MAX).contains(&mtu) {
        return Err(SkipReason::InvalidRecord);
    }
    Ok(mtu)
}

pub(crate) fn parse_mtu_json(value: &Value) -> Result<Option<u16>, SkipReason> {
    match value {
        Value::Null => Ok(None),
        Value::Number(number) => {
            let raw = number.as_u64().ok_or(SkipReason::InvalidRecord)?;
            let mtu = u16::try_from(raw).map_err(|_| SkipReason::InvalidRecord)?;
            if !(WIREGUARD_MTU_MIN..=WIREGUARD_MTU_MAX).contains(&mtu) {
                return Err(SkipReason::InvalidRecord);
            }
            Ok(Some(mtu))
        }
        Value::String(text) if text.trim().is_empty() => Ok(None),
        Value::String(text) => parse_mtu_str(text).map(Some),
        _ => Err(SkipReason::InvalidRecord),
    }
}

pub(crate) fn parse_keepalive_str(value: &str) -> Result<Option<u16>, SkipReason> {
    let seconds: u16 = value
        .trim()
        .parse()
        .map_err(|_| SkipReason::InvalidRecord)?;
    Ok((seconds != 0).then_some(seconds))
}

pub(crate) fn parse_keepalive_json(value: &Value) -> Result<Option<u16>, SkipReason> {
    match value {
        Value::Null => Ok(None),
        Value::Number(number) => {
            let raw = number.as_u64().ok_or(SkipReason::InvalidRecord)?;
            let seconds = u16::try_from(raw).map_err(|_| SkipReason::InvalidRecord)?;
            Ok((seconds != 0).then_some(seconds))
        }
        Value::String(text) if text.trim().is_empty() => Ok(None),
        Value::String(text) => parse_keepalive_str(text),
        _ => Err(SkipReason::InvalidRecord),
    }
}

pub(crate) fn normalize_host(raw: &str) -> Result<String, SkipReason> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(SkipReason::MissingField);
    }
    let decoded = percent_decode(trimmed);
    let inner = decoded
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(&decoded);
    if let Ok(ip) = inner.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    match Host::parse(&decoded).map_err(|_| SkipReason::InvalidRecord)? {
        Host::Domain(domain) => Ok(domain),
        Host::Ipv4(ip) => Ok(ip.to_string()),
        Host::Ipv6(ip) => Ok(ip.to_string()),
    }
}

pub(crate) fn parse_endpoint(value: &str) -> Result<(String, u16), SkipReason> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SkipReason::MissingField);
    }
    let (host, port_str) = if let Some(rest) = trimmed.strip_prefix('[') {
        let closing = rest.find(']').ok_or(SkipReason::InvalidRecord)?;
        let ip_str = &rest[..closing];
        let ip: Ipv6Addr = ip_str.parse().map_err(|_| SkipReason::InvalidRecord)?;
        let port_str = rest[closing + 1..]
            .strip_prefix(':')
            .ok_or(SkipReason::InvalidPort)?;
        (ip.to_string(), port_str)
    } else {
        let (raw_host, port_str) = trimmed.rsplit_once(':').ok_or(SkipReason::InvalidPort)?;
        if raw_host.contains(':') {
            // Unbracketed IPv6 address.
            return Err(SkipReason::InvalidRecord);
        }
        (normalize_host(raw_host)?, port_str)
    };
    let port: u16 = port_str
        .parse()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(SkipReason::InvalidPort)?;
    Ok((host, port))
}

pub(crate) fn is_amnezia_key(key: &str) -> bool {
    let normalized = key.trim().to_ascii_lowercase().replace(['-', '_'], "");
    matches!(
        normalized.as_str(),
        "jc" | "jmin"
            | "jmax"
            | "s1"
            | "s2"
            | "s3"
            | "s4"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "i1"
            | "i2"
            | "i3"
            | "i4"
            | "i5"
            | "amnezia"
            | "headerprotectionkey"
            | "contentpaddingaddition"
            | "randomtrailers"
            | "disablecookies"
            | "rekeyaftertime"
            | "rekeytimeout"
            | "rejectaftertime"
            | "keepalivetimeout"
            | "maxhandshakeattempts"
    )
}

pub(crate) fn parse_link(rest: &str) -> Record {
    let (before_fragment, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let (before_query, query) = before_fragment
        .split_once('?')
        .unwrap_or((before_fragment, ""));
    let Some((raw_private_key, endpoint_and_path)) = before_query.rsplit_once('@') else {
        return (
            Some("wireguard".to_owned()),
            Entry::Skip(SkipReason::MissingField),
        );
    };
    let endpoint_str = endpoint_and_path
        .split_once('/')
        .map_or(endpoint_and_path, |(value, _)| value);
    let (server, port) = match parse_endpoint(endpoint_str) {
        Ok(value) => value,
        Err(reason) => return (Some("wireguard".to_owned()), Entry::Skip(reason)),
    };
    let name = percent_decode(fragment);
    if is_service_address(&server) {
        return (
            Some("wireguard".to_owned()),
            Entry::Notice(clean(&name, 128)),
        );
    }

    let result = parse_link_params(raw_private_key, server, port, name, query);
    match result {
        Ok(node) => (Some("wireguard".to_owned()), Entry::Node(Box::new(node))),
        Err((scheme, reason)) => (Some(scheme.to_owned()), Entry::Skip(reason)),
    }
}

fn parse_link_params(
    raw_private_key: &str,
    server: String,
    port: u16,
    name: String,
    query: &str,
) -> Result<Node, (&'static str, SkipReason)> {
    let private_key =
        canonical_key(&percent_decode(raw_private_key)).map_err(|reason| ("wireguard", reason))?;

    let mut public_key: Option<String> = None;
    let mut pre_shared_key: Option<String> = None;
    let mut raw_addresses: Vec<String> = Vec::new();
    let mut reserved: Option<[u8; 3]> = None;
    let mut mtu: Option<u16> = None;
    let mut persistent_keepalive: Option<u16> = None;

    for pair in query.split('&').filter(|part| !part.is_empty()) {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(raw_key).trim().to_ascii_lowercase();
        let value = percent_decode(raw_value);
        if value.trim().is_empty() {
            continue;
        }
        if is_amnezia_key(&key) {
            return Err(("amneziawg", SkipReason::UnsupportedProtocol));
        }
        let normalized_key = key.replace('-', "_");
        match normalized_key.as_str() {
            "publickey" | "public_key" | "peer_public_key" | "pbk" => {
                public_key = Some(canonical_key(&value).map_err(|reason| ("wireguard", reason))?);
            }
            "presharedkey" | "pre_shared_key" | "psk" => {
                pre_shared_key =
                    Some(canonical_key(&value).map_err(|reason| ("wireguard", reason))?);
            }
            "address" | "ip" | "local_address" => {
                raw_addresses.push(value);
            }
            "reserved" => {
                reserved =
                    Some(parse_reserved_str(&value).map_err(|reason| ("wireguard", reason))?);
            }
            "mtu" => {
                mtu = Some(parse_mtu_str(&value).map_err(|reason| ("wireguard", reason))?);
            }
            "keepalive" | "persistent_keepalive" | "persistent_keepalive_interval" => {
                persistent_keepalive =
                    parse_keepalive_str(&value).map_err(|reason| ("wireguard", reason))?;
            }
            "dns" => {}
            _ => return Err(("wireguard", SkipReason::UnsupportedOption)),
        }
    }

    let public_key = public_key.ok_or(("wireguard", SkipReason::MissingField))?;
    let address = parse_addresses(raw_addresses.iter().map(String::as_str))
        .map_err(|reason| ("wireguard", reason))?;
    build_node(WireGuardInput {
        name,
        server,
        port,
        private_key,
        public_key,
        pre_shared_key,
        address,
        reserved,
        mtu,
        persistent_keepalive,
    })
    .map_err(|reason| ("wireguard", reason))
}

pub(crate) fn is_conf(text: &str) -> bool {
    let mut has_interface = false;
    let mut has_peer = false;
    for line in text.lines().map(str::trim) {
        if line.eq_ignore_ascii_case("[interface]") {
            has_interface = true;
        } else if line.eq_ignore_ascii_case("[peer]") {
            has_peer = true;
        }
        if has_interface && has_peer {
            return true;
        }
    }
    false
}

pub(crate) fn parse_conf(text: &str, metadata: &mut SubscriptionMeta) -> Vec<Record> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Section {
        None,
        Interface,
        Peer,
    }

    let mut section = Section::None;
    let mut interface_count = 0usize;
    let mut peer_count = 0usize;

    let mut private_key: Option<String> = None;
    let mut public_key: Option<String> = None;
    let mut pre_shared_key: Option<String> = None;
    let mut raw_addresses: Vec<String> = Vec::new();
    let mut endpoint_value: Option<(String, u16)> = None;
    let mut reserved: Option<[u8; 3]> = None;
    let mut mtu: Option<u16> = None;
    let mut persistent_keepalive: Option<u16> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if line.starts_with('#') {
            meta::apply_comment(metadata, line);
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let header = line[1..line.len() - 1].trim();
            if header.eq_ignore_ascii_case("interface") {
                interface_count += 1;
                if interface_count > 1 {
                    return vec![(
                        Some("wireguard".to_owned()),
                        Entry::Skip(SkipReason::InvalidRecord),
                    )];
                }
                section = Section::Interface;
            } else if header.eq_ignore_ascii_case("peer") {
                peer_count += 1;
                if peer_count > 1 {
                    return vec![(
                        Some("wireguard".to_owned()),
                        Entry::Skip(SkipReason::UnsupportedOption),
                    )];
                }
                section = Section::Peer;
            } else {
                return vec![(
                    Some("wireguard".to_owned()),
                    Entry::Skip(SkipReason::InvalidRecord),
                )];
            }
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return vec![(
                Some("wireguard".to_owned()),
                Entry::Skip(SkipReason::InvalidRecord),
            )];
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() {
            return vec![(
                Some("wireguard".to_owned()),
                Entry::Skip(SkipReason::InvalidRecord),
            )];
        }
        if is_amnezia_key(key) && !value.is_empty() {
            return vec![(
                Some("amneziawg".to_owned()),
                Entry::Skip(SkipReason::UnsupportedProtocol),
            )];
        }

        let lowered = key.to_ascii_lowercase();
        match section {
            Section::None => {
                return vec![(
                    Some("wireguard".to_owned()),
                    Entry::Skip(SkipReason::InvalidRecord),
                )];
            }
            Section::Interface => match lowered.as_str() {
                "privatekey" => match canonical_key(value) {
                    Ok(key) => private_key = Some(key),
                    Err(reason) => {
                        return vec![(Some("wireguard".to_owned()), Entry::Skip(reason))];
                    }
                },
                "address" => {
                    if !value.is_empty() {
                        raw_addresses.push(value.to_owned());
                    }
                }
                "mtu" => {
                    if !value.is_empty() {
                        match parse_mtu_str(value) {
                            Ok(parsed) => mtu = Some(parsed),
                            Err(reason) => {
                                return vec![(Some("wireguard".to_owned()), Entry::Skip(reason))];
                            }
                        }
                    }
                }
                "reserved" => {
                    if !value.is_empty() {
                        match parse_reserved_str(value) {
                            Ok(parsed) => reserved = Some(parsed),
                            Err(reason) => {
                                return vec![(Some("wireguard".to_owned()), Entry::Skip(reason))];
                            }
                        }
                    }
                }
                "dns" | "listenport" | "table" | "fwmark" | "saveconfig" | "preup" | "postup"
                | "predown" | "postdown" => {}
                _ if value.is_empty() => {}
                _ => {
                    return vec![(
                        Some("wireguard".to_owned()),
                        Entry::Skip(SkipReason::UnsupportedOption),
                    )];
                }
            },
            Section::Peer => match lowered.as_str() {
                "publickey" => match canonical_key(value) {
                    Ok(key) => public_key = Some(key),
                    Err(reason) => {
                        return vec![(Some("wireguard".to_owned()), Entry::Skip(reason))];
                    }
                },
                "presharedkey" => match optional_key(Some(value)) {
                    Ok(key) => pre_shared_key = key,
                    Err(reason) => {
                        return vec![(Some("wireguard".to_owned()), Entry::Skip(reason))];
                    }
                },
                "endpoint" => match parse_endpoint(value) {
                    Ok(parsed) => endpoint_value = Some(parsed),
                    Err(reason) => {
                        return vec![(Some("wireguard".to_owned()), Entry::Skip(reason))];
                    }
                },
                "persistentkeepalive" => {
                    if !value.is_empty() {
                        match parse_keepalive_str(value) {
                            Ok(parsed) => persistent_keepalive = parsed,
                            Err(reason) => {
                                return vec![(Some("wireguard".to_owned()), Entry::Skip(reason))];
                            }
                        }
                    }
                }
                "reserved" => {
                    if !value.is_empty() {
                        match parse_reserved_str(value) {
                            Ok(parsed) => reserved = Some(parsed),
                            Err(reason) => {
                                return vec![(Some("wireguard".to_owned()), Entry::Skip(reason))];
                            }
                        }
                    }
                }
                "allowedips" => {}
                _ if value.is_empty() => {}
                _ => {
                    return vec![(
                        Some("wireguard".to_owned()),
                        Entry::Skip(SkipReason::UnsupportedOption),
                    )];
                }
            },
        }
    }

    if interface_count != 1 || peer_count != 1 {
        return vec![(
            Some("wireguard".to_owned()),
            Entry::Skip(SkipReason::InvalidRecord),
        )];
    }

    let (Some(private_key), Some(public_key), Some((server, port))) =
        (private_key, public_key, endpoint_value)
    else {
        return vec![(
            Some("wireguard".to_owned()),
            Entry::Skip(SkipReason::MissingField),
        )];
    };

    let address = match parse_addresses(raw_addresses.iter().map(String::as_str)) {
        Ok(value) => value,
        Err(reason) => return vec![(Some("wireguard".to_owned()), Entry::Skip(reason))],
    };

    let name = metadata
        .title
        .as_deref()
        .map_or("", |title| title.strip_suffix(".conf").unwrap_or(title))
        .to_owned();

    let result = build_node(WireGuardInput {
        name,
        server,
        port,
        private_key,
        public_key,
        pre_shared_key,
        address,
        reserved,
        mtu,
        persistent_keepalive,
    });
    vec![(Some("wireguard".to_owned()), result.into())]
}
