use rosetun_config::{Node, NodeId, Outbound, ProxyCredentials, StreamSettings, TlsMode, TlsParams};
use url::{Host, Url};

use crate::SkipReason;

/// Parses a proxy URI only in a context explicitly expecting a server, never a subscription URL.
pub fn parse_proxy_uri(input: &str) -> Result<Node, SkipReason> {
    let invalid = || SkipReason::InvalidRecord;
    if input.chars().any(|ch| ch.is_control() || ch.is_whitespace()) || input.contains('\\') {
        return Err(invalid());
    }
    let (scheme, rest) = input.split_once("://").ok_or_else(invalid)?;
    if !matches!(scheme, "http" | "https" | "socks5") {
        return Err(SkipReason::UnsupportedProtocol);
    }
    let authority = rest.split(['/', '?', '#']).next().ok_or_else(invalid)?;
    if authority.matches('@').count() > 1 { return Err(invalid()); }
    let endpoint = authority.rsplit('@').next().ok_or_else(invalid)?;
    let (_, port) = endpoint.rsplit_once(':').ok_or(SkipReason::InvalidPort)?;
    if !port.bytes().all(|byte| byte.is_ascii_digit()) { return Err(SkipReason::InvalidPort); }
    let port = port.parse::<u16>().ok().filter(|port| *port != 0).ok_or(SkipReason::InvalidPort)?;
    let url = Url::parse(input).map_err(|_| invalid())?;
    if !matches!(url.path(), "" | "/") || url.query().is_some() {
        return Err(invalid());
    }
    let server = match url.host().ok_or_else(invalid)? {
        Host::Domain(host) => host.to_owned(),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => ip.to_string(),
    };
    let credentials = ProxyCredentials {
        username: decode(url.username())?,
        password: decode(url.password().unwrap_or_default())?,
    };
    let mut node = Node {
        id: NodeId::new("pending"),
        name: decode(url.fragment().unwrap_or(scheme))?,
        server,
        port,
        outbound: if scheme == "socks5" { Outbound::Socks5(credentials) } else { Outbound::Http(credentials) },
        stream: StreamSettings {
            tls: if scheme == "https" { TlsMode::Tls(TlsParams::default()) } else { TlsMode::Plain },
            ..StreamSettings::default()
        },
        raw: None,
    };
    node.validate_proxy().map_err(|_| invalid())?;
    node.id = NodeId::new(crate::common::stable_id(&node));
    Ok(node)
}

fn decode(value: &str) -> Result<String, SkipReason> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        decoded.push(if byte == b'%' {
            let high = bytes.next().and_then(|byte| char::from(byte).to_digit(16));
            let low = bytes.next().and_then(|byte| char::from(byte).to_digit(16));
            match (high, low) {
                (Some(high), Some(low)) => (high * 16 + low) as u8,
                _ => return Err(SkipReason::InvalidRecord),
            }
        } else { byte });
    }
    String::from_utf8(decoded).map_err(|_| SkipReason::InvalidRecord)
}
