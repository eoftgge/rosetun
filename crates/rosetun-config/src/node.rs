use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{CountryCode, NodeId, Settings, XrayUse};

// sing-box#4520: REALITY servers on Xray 26.9.8+ reject sing-box's handshake.
const XRAY_FOR_REALITY: bool = true;

/// Whether Xray carries this node. Every caller asks here, so a connect, an apply and a server
/// check always agree.
pub fn uses_xray(node: &Node, settings: &Settings) -> bool {
    match settings.xray {
        XrayUse::Off => false,
        // Splitting the packets to the server is Xray's feature, so a node it can run goes there.
        _ if settings.tls_fragment.applies_to(node) => true,
        // sing-box has no XHTTP transport, so such a node has no other route.
        XrayUse::Auto if matches!(node.stream.transport, Transport::Xhttp { .. }) => {
            xray_supports(&node.outbound)
        }
        XrayUse::Auto => {
            XRAY_FOR_REALITY
                && matches!(&node.outbound, Outbound::Vless(_))
                && matches!(&node.stream.tls, TlsMode::Reality(_))
        }
        XrayUse::Always => xray_supports(&node.outbound),
    }
}

/// Whether the connection to the node's server is split in this session. Xray must be allowed,
/// or the node never reaches it.
pub fn fragments_tls(node: &Node, settings: &Settings) -> bool {
    settings.xray != XrayUse::Off && settings.tls_fragment.applies_to(node)
}

pub(crate) fn xray_supports(outbound: &Outbound) -> bool {
    match outbound {
        Outbound::Vmess(params) => params.alter_id == 0,
        Outbound::Vless(_) | Outbound::Trojan(_) | Outbound::Shadowsocks(_) => true,
        Outbound::Http(_)
        | Outbound::Socks5(_)
        | Outbound::Hysteria2(_)
        | Outbound::Tuic(_)
        | Outbound::AnyTls(_)
        | Outbound::WireGuard(_)
        | Outbound::Unknown { .. } => false,
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub outbound: Outbound,
    #[serde(default)]
    pub stream: StreamSettings,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

pub fn node_country(name: &str) -> Option<CountryCode> {
    let indicator = |character: char| {
        let value = character as u32;
        (0x1f1e6..=0x1f1ff)
            .contains(&value)
            .then(|| (value - 0x1f1e6) as u8 + b'A')
    };
    let characters: Vec<_> = name.chars().collect();
    for pair in characters.windows(2) {
        if let (Some(first), Some(second)) = (indicator(pair[0]), indicator(pair[1])) {
            let code =
                String::from_utf8(vec![first, second]).expect("regional indicators are ASCII");
            if let Some(country) = CountryCode::parse(&code) {
                return Some(country);
            }
        }
    }

    let mut country = None;
    for word in name.split(|character: char| !character.is_alphanumeric() && character != '_') {
        let code = if word == "UK" { "GB" } else { word };
        if let Some(found) = CountryCode::parse(code) {
            if country.as_ref().is_some_and(|previous| previous != &found) {
                return None;
            }
            country = Some(found);
        }
    }
    country
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("id", &self.id)
            .field("name", &"[redacted]")
            .field("server", &"[redacted]")
            .field("port", &self.port)
            .field("outbound", &self.outbound)
            .field("stream", &self.stream)
            .field("raw", &self.raw.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outbound {
    Http(ProxyCredentials),
    Socks5(ProxyCredentials),
    Vless(VlessParams),
    Vmess(VmessParams),
    Trojan(TrojanParams),
    Shadowsocks(ShadowsocksParams),
    Hysteria2(Hysteria2Params),
    Tuic(TuicParams),
    #[serde(rename = "anytls")]
    AnyTls(AnyTlsParams),
    #[serde(rename = "wireguard")]
    WireGuard(WireGuardParams),
    Unknown {
        scheme: String,
        params: BTreeMap<String, String>,
    },
}

impl fmt::Debug for Outbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(params) => f.debug_tuple("Http").field(params).finish(),
            Self::Socks5(params) => f.debug_tuple("Socks5").field(params).finish(),
            Self::Vless(params) => f.debug_tuple("Vless").field(params).finish(),
            Self::Vmess(params) => f.debug_tuple("Vmess").field(params).finish(),
            Self::Trojan(params) => f.debug_tuple("Trojan").field(params).finish(),
            Self::Shadowsocks(params) => f.debug_tuple("Shadowsocks").field(params).finish(),
            Self::Hysteria2(params) => f.debug_tuple("Hysteria2").field(params).finish(),
            Self::Tuic(params) => f.debug_tuple("Tuic").field(params).finish(),
            Self::AnyTls(params) => f.debug_tuple("AnyTls").field(params).finish(),
            Self::WireGuard(params) => f.debug_tuple("WireGuard").field(params).finish(),
            Self::Unknown { scheme, params } => f
                .debug_struct("Unknown")
                .field("scheme", scheme)
                .field("params_count", &params.len())
                .finish(),
        }
    }
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyCredentials {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for ProxyCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProxyCredentials([redacted])")
    }
}

/// Checks a standard 36-character hyphenated or 32-character hex UUID.
pub fn is_valid_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    match bytes.len() {
        32 => bytes.iter().all(u8::is_ascii_hexdigit),
        36 => bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        }),
        _ => false,
    }
}

/// Checks a positive Go-style duration string (for example `10s`, `500ms`, `1m30s`).
pub fn is_valid_duration(value: &str) -> bool {
    if value.is_empty() || value.len() > 32 {
        return false;
    }
    let mut rest = value;
    let mut non_zero = false;
    while !rest.is_empty() {
        let digits_end = rest
            .find(|ch: char| !ch.is_ascii_digit())
            .unwrap_or(rest.len());
        if digits_end == 0 {
            return false;
        }
        if rest[..digits_end].bytes().any(|byte| byte != b'0') {
            non_zero = true;
        }
        rest = &rest[digits_end..];
        if let Some(after_dot) = rest.strip_prefix('.') {
            let frac_end = after_dot
                .find(|ch: char| !ch.is_ascii_digit())
                .unwrap_or(after_dot.len());
            if frac_end == 0 {
                return false;
            }
            if after_dot[..frac_end].bytes().any(|byte| byte != b'0') {
                non_zero = true;
            }
            rest = &after_dot[frac_end..];
        }
        let unit_len = if rest.starts_with("ns") || rest.starts_with("us") || rest.starts_with("ms")
        {
            2
        } else if rest.starts_with(['s', 'm', 'h']) {
            1
        } else {
            return false;
        };
        rest = &rest[unit_len..];
    }
    non_zero
}

/// Minimum and maximum interface MTU accepted for WireGuard endpoints.
pub const WIREGUARD_MTU_MIN: u16 = 576;
pub const WIREGUARD_MTU_MAX: u16 = 9000;

/// Checks a canonical 44-character standard Base64 32-byte WireGuard key.
pub fn is_valid_wireguard_key(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 44 || bytes[43] != b'=' {
        return false;
    }
    let decode = |byte: u8| match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    if !bytes[..43].iter().all(|&byte| decode(byte).is_some()) {
        return false;
    }
    // 32 bytes = 256 bits = 42 * 6 + 4 bits; the 2 unused low bits of char 42 must be zero.
    decode(bytes[42]).is_some_and(|bits| bits & 0x03 == 0)
}

/// Checks a WireGuard interface CIDR (`<ip>/<prefix>`), preserving host bits.
pub fn is_valid_wireguard_address(value: &str) -> bool {
    let Some((ip, prefix)) = value.split_once('/') else {
        return false;
    };
    if prefix.is_empty()
        || !prefix.bytes().all(|byte| byte.is_ascii_digit())
        || (prefix.len() > 1 && prefix.starts_with('0'))
    {
        return false;
    }
    let Ok(bits) = prefix.parse::<u8>() else {
        return false;
    };
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => bits <= 32,
        Ok(std::net::IpAddr::V6(_)) => bits <= 128,
        Err(_) => false,
    }
}

fn is_valid_host(server: &str) -> bool {
    let host = server.strip_suffix('.').unwrap_or(server);
    server.parse::<std::net::IpAddr>().is_ok()
        || (!host.is_empty()
            && host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            }))
}

impl Node {
    /// Validates external proxies and strict native protocols at both storage and engine boundaries.
    pub fn validate_proxy(&self) -> Result<(), &'static str> {
        match &self.outbound {
            Outbound::Http(credentials) | Outbound::Socks5(credentials) => {
                if !is_valid_host(&self.server) || self.port == 0 {
                    return Err(
                        "proxy requires a valid DNS name or IP address and a port between 1 and 65535",
                    );
                }
                if self.stream.transport != Transport::Tcp {
                    return Err("proxy requires TCP transport");
                }
                match (&self.outbound, &self.stream.tls) {
                    (Outbound::Http(_), TlsMode::Tls(tls)) => {
                        if tls.allow_insecure
                            || tls.sni.as_ref().is_some_and(|name| !is_valid_host(name))
                        {
                            return Err(
                                "HTTPS proxy requires certificate verification and a valid TLS server name",
                            );
                        }
                    }
                    (_, TlsMode::Plain) => {}
                    _ => return Err("proxy TLS mode is not supported"),
                }
                if credentials
                    .username
                    .chars()
                    .chain(credentials.password.chars())
                    .any(char::is_control)
                    || (credentials.username.is_empty() && !credentials.password.is_empty())
                    || (matches!(self.outbound, Outbound::Http(_))
                        && credentials.username.contains(':'))
                    || (matches!(self.outbound, Outbound::Socks5(_))
                        && (credentials.username.len() > 255
                            || credentials.password.len() > 255
                            || (!credentials.username.is_empty()
                                && credentials.password.is_empty())))
                {
                    return Err("proxy credentials are invalid for the selected protocol");
                }
                Ok(())
            }
            Outbound::Tuic(params) => {
                if !is_valid_host(&self.server) || self.port == 0 {
                    return Err(
                        "TUIC requires a valid DNS name or IP address and a port between 1 and 65535",
                    );
                }
                if self.stream.transport != Transport::Tcp {
                    return Err("TUIC uses its built-in QUIC transport");
                }
                if !matches!(self.stream.tls, TlsMode::Tls(_)) {
                    return Err("TUIC requires TLS");
                }
                if !is_valid_uuid(&params.uuid) || params.password.chars().any(char::is_control) {
                    return Err("TUIC requires a valid UUID and valid password");
                }
                if params
                    .heartbeat
                    .as_deref()
                    .is_some_and(|value| !is_valid_duration(value))
                {
                    return Err("TUIC heartbeat must be a positive duration");
                }
                Ok(())
            }
            Outbound::AnyTls(params) => {
                if !is_valid_host(&self.server) || self.port == 0 {
                    return Err(
                        "AnyTLS requires a valid DNS name or IP address and a port between 1 and 65535",
                    );
                }
                if self.stream.transport != Transport::Tcp {
                    return Err("AnyTLS requires TCP transport");
                }
                match &self.stream.tls {
                    TlsMode::Tls(_) => {}
                    TlsMode::Reality(reality) if !reality.public_key.is_empty() => {}
                    _ => return Err("AnyTLS requires TLS or REALITY"),
                }
                if params.password.is_empty() || params.password.chars().any(char::is_control) {
                    return Err("AnyTLS requires a non-empty password");
                }
                if params
                    .idle_session_check_interval
                    .as_deref()
                    .is_some_and(|value| !is_valid_duration(value))
                    || params
                        .idle_session_timeout
                        .as_deref()
                        .is_some_and(|value| !is_valid_duration(value))
                    || params
                        .min_idle_session
                        .is_some_and(|value| i32::try_from(value).is_err())
                {
                    return Err("AnyTLS idle session settings are invalid");
                }
                Ok(())
            }
            Outbound::WireGuard(params) => {
                if !is_valid_host(&self.server) || self.port == 0 {
                    return Err(
                        "WireGuard requires a valid DNS name or IP address and a port between 1 and 65535",
                    );
                }
                if self.stream.transport != Transport::Tcp
                    || !matches!(self.stream.tls, TlsMode::Plain)
                {
                    return Err("WireGuard uses its built-in encrypted UDP transport");
                }
                if !is_valid_wireguard_key(&params.private_key)
                    || !is_valid_wireguard_key(&params.public_key)
                    || params
                        .pre_shared_key
                        .as_deref()
                        .is_some_and(|key| !is_valid_wireguard_key(key))
                {
                    return Err("WireGuard keys must be valid 32-byte Base64 values");
                }
                if params.address.is_empty()
                    || params.address.len() > 8
                    || !params
                        .address
                        .iter()
                        .all(|address| is_valid_wireguard_address(address))
                {
                    return Err("WireGuard requires valid interface CIDR addresses");
                }
                if params
                    .mtu
                    .is_some_and(|mtu| !(WIREGUARD_MTU_MIN..=WIREGUARD_MTU_MAX).contains(&mtu))
                {
                    return Err("WireGuard MTU is out of range");
                }
                if params.persistent_keepalive == Some(0) {
                    return Err("WireGuard persistent keepalive must be greater than zero");
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlessParams {
    pub uuid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
}

impl fmt::Debug for VlessParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VlessParams")
            .field("uuid", &"[redacted]")
            .field("flow", &self.flow)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmessParams {
    pub uuid: String,
    #[serde(default)]
    pub alter_id: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
}

impl fmt::Debug for VmessParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmessParams")
            .field("uuid", &"[redacted]")
            .field("alter_id", &self.alter_id)
            .field("security", &self.security)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrojanParams {
    pub password: String,
}

impl fmt::Debug for TrojanParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrojanParams")
            .field("password", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowsocksParams {
    pub method: String,
    pub password: String,
}

impl fmt::Debug for ShadowsocksParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowsocksParams")
            .field("method", &self.method)
            .field("password", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hysteria2Params {
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs_password: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_ranges: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<u32>,
}

impl fmt::Debug for Hysteria2Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hysteria2Params")
            .field("password", &"[redacted]")
            .field(
                "obfs_password",
                &self.obfs_password.as_ref().map(|_| "[redacted]"),
            )
            .field("port_ranges", &self.port_ranges)
            .field("up_mbps", &self.up_mbps)
            .field("down_mbps", &self.down_mbps)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TuicCongestionControl {
    #[default]
    Cubic,
    NewReno,
    Bbr,
}

impl TuicCongestionControl {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "cubic" => Some(Self::Cubic),
            "new_reno" => Some(Self::NewReno),
            "bbr" => Some(Self::Bbr),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cubic => "cubic",
            Self::NewReno => "new_reno",
            Self::Bbr => "bbr",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TuicUdpRelayMode {
    #[default]
    Native,
    Quic,
}

impl TuicUdpRelayMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "native" => Some(Self::Native),
            "quic" => Some(Self::Quic),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Quic => "quic",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TuicParams {
    pub uuid: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub congestion_control: Option<TuicCongestionControl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_relay_mode: Option<TuicUdpRelayMode>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub zero_rtt_handshake: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_sni: bool,
}

impl fmt::Debug for TuicParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TuicParams")
            .field("uuid", &"[redacted]")
            .field(
                "password",
                &(!self.password.is_empty()).then_some("[redacted]"),
            )
            .field("congestion_control", &self.congestion_control)
            .field("udp_relay_mode", &self.udp_relay_mode)
            .field("zero_rtt_handshake", &self.zero_rtt_handshake)
            .field("heartbeat", &self.heartbeat)
            .field("disable_sni", &self.disable_sni)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnyTlsParams {
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_session_check_interval: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_session_timeout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_idle_session: Option<u32>,
}

impl fmt::Debug for AnyTlsParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnyTlsParams")
            .field("password", &"[redacted]")
            .field(
                "idle_session_check_interval",
                &self.idle_session_check_interval,
            )
            .field("idle_session_timeout", &self.idle_session_timeout)
            .field("min_idle_session", &self.min_idle_session)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireGuardParams {
    pub private_key: String,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_shared_key: Option<String>,
    pub address: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved: Option<[u8; 3]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u16>,
}

impl fmt::Debug for WireGuardParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireGuardParams")
            .field("private_key", &"[redacted]")
            .field("public_key", &"[redacted]")
            .field("has_pre_shared_key", &self.pre_shared_key.is_some())
            .field("address_count", &self.address.len())
            .field("has_reserved", &self.reserved.is_some())
            .field("mtu", &self.mtu)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StreamSettings {
    #[serde(default)]
    pub transport: Transport,
    #[serde(default)]
    pub tls: TlsMode,
}

#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    #[default]
    Tcp,
    Ws {
        path: String,
        host: Option<String>,
    },
    Grpc {
        service_name: String,
    },
    HttpUpgrade {
        path: String,
        host: Option<String>,
    },
    Xhttp {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
        #[serde(default)]
        mode: XhttpMode,
        #[serde(default, skip_serializing_if = "XhttpExtra::is_empty")]
        extra: XhttpExtra,
    },
}

impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => f.write_str("Tcp"),
            Self::Ws { path: _, host } => f
                .debug_struct("Ws")
                .field("path", &"[redacted]")
                .field("host", &host.as_ref().map(|_| "[redacted]"))
                .finish(),
            Self::Grpc { service_name: _ } => f
                .debug_struct("Grpc")
                .field("service_name", &"[redacted]")
                .finish(),
            Self::HttpUpgrade { path: _, host } => f
                .debug_struct("HttpUpgrade")
                .field("path", &"[redacted]")
                .field("host", &host.as_ref().map(|_| "[redacted]"))
                .finish(),
            Self::Xhttp {
                path: _,
                host,
                mode,
                extra,
            } => f
                .debug_struct("Xhttp")
                .field("path", &"[redacted]")
                .field("host", &host.as_ref().map(|_| "[redacted]"))
                .field("mode", mode)
                .field("extra", extra)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum XhttpMode {
    #[default]
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
}

impl XhttpMode {
    /// Xray reads an empty mode as `auto`.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "" | "auto" => Some(Self::Auto),
            "packet-up" => Some(Self::PacketUp),
            "stream-up" => Some(Self::StreamUp),
            "stream-one" => Some(Self::StreamOne),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::PacketUp => "packet-up",
            Self::StreamUp => "stream-up",
            Self::StreamOne => "stream-one",
        }
    }
}

/// The client options of Xray's `xhttpSettings.extra` that Rosetun passes on.
/// Subscriptions are parsed into this model and checked against its limits;
/// nothing from a subscription reaches Xray as raw JSON.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct XhttpExtra {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x_padding_bytes: Option<XhttpRange>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_grpc_header: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_sse_header: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sc_max_each_post_bytes: Option<XhttpRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sc_min_posts_interval_ms: Option<XhttpRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sc_max_buffered_posts: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmux: Option<XhttpXmux>,
}

impl XhttpExtra {
    pub const MAX_HEADERS: usize = 16;
    pub const MAX_HEADER_LENGTH: usize = 256;

    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

impl fmt::Debug for XhttpExtra {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XhttpExtra")
            .field("headers_count", &self.headers.len())
            .field("x_padding_bytes", &self.x_padding_bytes)
            .field("no_grpc_header", &self.no_grpc_header)
            .field("no_sse_header", &self.no_sse_header)
            .field("sc_max_each_post_bytes", &self.sc_max_each_post_bytes)
            .field("sc_min_posts_interval_ms", &self.sc_min_posts_interval_ms)
            .field("sc_max_buffered_posts", &self.sc_max_buffered_posts)
            .field("xmux", &self.xmux)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct XhttpXmux {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<XhttpRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<XhttpRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub c_max_reuse_times: Option<XhttpRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h_max_request_times: Option<XhttpRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h_max_reusable_secs: Option<XhttpRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h_keep_alive_period: Option<i64>,
}

/// Xray's `Int32Range`, a number or a `"from-to"` string, kept with `from <= to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct XhttpRange {
    pub from: u32,
    pub to: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    #[default]
    Plain,
    Tls(TlsParams),
    Reality(RealityParams),
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TlsParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealityParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_from_flag_or_standalone_code() {
        for (name, expected) in [
            ("Germany 🇩🇪 server", Some("DE")),
            ("US server 🇬🇧", Some("GB")),
            ("Node UK #2", Some("GB")),
            ("Node DE #2", Some("DE")),
            ("PREMIUM IN NL", None),
            ("🇳🇱 IN NL", Some("NL")),
            ("NL #1 NL", Some("NL")),
            ("VPN server", None),
            ("someUSnode", None),
            ("VPN_DE", None),
            ("🇩 test 🇪", None),
            ("ZZ server", None),
        ] {
            assert_eq!(
                node_country(name).as_ref().map(CountryCode::as_str),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn hysteria2_debug_redacts_credentials_and_serde_omits_defaults() {
        let node = Node {
            id: NodeId::new("test"),
            name: "Test".into(),
            server: "example.com".into(),
            port: 443,
            outbound: Outbound::Hysteria2(Hysteria2Params {
                password: "test-secret".into(),
                obfs_password: Some("test-secret-obfs".into()),
                port_ranges: Vec::new(),
                up_mbps: None,
                down_mbps: None,
            }),
            stream: StreamSettings::default(),
            raw: Some("hy2://test-secret@example.com:443?obfs-password=test-secret-obfs".into()),
        };
        let debug = format!("{node:?}");
        assert!(!debug.contains("test-secret"));
        let json = serde_json::to_value(&node).unwrap();
        assert_eq!(json["outbound"]["hysteria2"]["password"], "test-secret");
        assert!(json["outbound"]["hysteria2"].get("port_ranges").is_none());
        assert!(json["outbound"]["hysteria2"].get("up_mbps").is_none());
    }

    #[test]
    fn existing_password_outbounds_redact_debug() {
        for outbound in [
            Outbound::Trojan(TrojanParams {
                password: "test-secret".into(),
            }),
            Outbound::Shadowsocks(ShadowsocksParams {
                method: "aes-128-gcm".into(),
                password: "test-secret".into(),
            }),
            Outbound::Vless(VlessParams {
                uuid: "test-secret".into(),
                flow: None,
            }),
            Outbound::Vmess(VmessParams {
                uuid: "test-secret".into(),
                alter_id: 0,
                security: None,
            }),
        ] {
            assert!(!format!("{outbound:?}").contains("test-secret"));
        }
    }

    #[test]
    fn unknown_outbound_debug_hides_parameter_keys_and_values() {
        let outbound = Outbound::Unknown {
            scheme: "example".into(),
            params: [("secret-key".into(), "secret-value".into())].into(),
        };
        let debug = format!("{outbound:?}");
        assert!(debug.contains("example"));
        assert!(debug.contains("params_count: 1"));
        assert!(!debug.contains("secret-key"));
        assert!(!debug.contains("secret-value"));
    }

    #[test]
    fn xray_selection_covers_modes_and_protocols() {
        let mut node = Node {
            id: NodeId::new("test"),
            name: "Test".into(),
            server: "192.0.2.1".into(),
            port: 443,
            outbound: Outbound::Vless(VlessParams {
                uuid: "00000000-0000-4000-8000-000000000001".into(),
                flow: None,
            }),
            stream: StreamSettings::default(),
            raw: None,
        };
        let reality = TlsMode::Reality(RealityParams {
            sni: Some("example.com".into()),
            public_key: "test-public-key".into(),
            short_id: None,
            fingerprint: None,
        });
        let outbounds = [
            (node.outbound.clone(), true),
            (
                Outbound::Vmess(VmessParams {
                    uuid: "test".into(),
                    alter_id: 0,
                    security: None,
                }),
                true,
            ),
            (
                Outbound::Vmess(VmessParams {
                    uuid: "test".into(),
                    alter_id: 1,
                    security: None,
                }),
                false,
            ),
            (
                Outbound::Trojan(TrojanParams {
                    password: "test".into(),
                }),
                true,
            ),
            (
                Outbound::Shadowsocks(ShadowsocksParams {
                    method: "aes-128-gcm".into(),
                    password: "test".into(),
                }),
                true,
            ),
            (
                Outbound::Hysteria2(Hysteria2Params {
                    password: "test".into(),
                    obfs_password: None,
                    port_ranges: Vec::new(),
                    up_mbps: None,
                    down_mbps: None,
                }),
                false,
            ),
            (
                Outbound::Tuic(TuicParams {
                    uuid: "00000000-0000-4000-8000-000000000001".into(),
                    password: "test".into(),
                    congestion_control: None,
                    udp_relay_mode: None,
                    zero_rtt_handshake: false,
                    heartbeat: None,
                    disable_sni: false,
                }),
                false,
            ),
            (
                Outbound::AnyTls(AnyTlsParams {
                    password: "test".into(),
                    idle_session_check_interval: None,
                    idle_session_timeout: None,
                    min_idle_session: None,
                }),
                false,
            ),
            (
                Outbound::Unknown {
                    scheme: "example".into(),
                    params: BTreeMap::new(),
                },
                false,
            ),
        ];
        for (outbound, supported) in outbounds {
            node.outbound = outbound;
            for tls in [TlsMode::Plain, reality.clone()] {
                node.stream.tls = tls;
                let auto = supported
                    && matches!(node.outbound, Outbound::Vless(_))
                    && matches!(node.stream.tls, TlsMode::Reality(_));
                assert_eq!(uses_xray(&node, &with_xray(XrayUse::Auto)), auto);
                assert!(!uses_xray(&node, &with_xray(XrayUse::Off)));
                assert_eq!(uses_xray(&node, &with_xray(XrayUse::Always)), supported);
            }
        }
    }

    fn with_xray(xray: XrayUse) -> Settings {
        Settings {
            xray,
            ..Settings::default()
        }
    }

    fn with_fragment(xray: XrayUse, packets: &str) -> Settings {
        let mut settings = with_xray(xray);
        settings.tls_fragment.enabled = true;
        settings.tls_fragment.packets = packets.parse().unwrap();
        settings
    }

    fn example_node(outbound: Outbound, tls: TlsMode) -> Node {
        Node {
            id: NodeId::new("test"),
            name: "Test".into(),
            server: "192.0.2.1".into(),
            port: 443,
            outbound,
            stream: StreamSettings {
                transport: Transport::Tcp,
                tls,
            },
            raw: None,
        }
    }

    fn every_outbound() -> Vec<(Outbound, bool)> {
        vec![
            (
                Outbound::Vless(VlessParams {
                    uuid: "00000000-0000-4000-8000-000000000001".into(),
                    flow: None,
                }),
                true,
            ),
            (
                Outbound::Vmess(VmessParams {
                    uuid: "00000000-0000-4000-8000-000000000001".into(),
                    alter_id: 0,
                    security: None,
                }),
                true,
            ),
            (
                Outbound::Vmess(VmessParams {
                    uuid: "00000000-0000-4000-8000-000000000001".into(),
                    alter_id: 2,
                    security: None,
                }),
                false,
            ),
            (
                Outbound::Trojan(TrojanParams {
                    password: "test".into(),
                }),
                true,
            ),
            (
                Outbound::Shadowsocks(ShadowsocksParams {
                    method: "aes-128-gcm".into(),
                    password: "test".into(),
                }),
                true,
            ),
            (
                Outbound::Hysteria2(Hysteria2Params {
                    password: "test".into(),
                    obfs_password: None,
                    port_ranges: Vec::new(),
                    up_mbps: None,
                    down_mbps: None,
                }),
                false,
            ),
            (
                Outbound::Tuic(TuicParams {
                    uuid: "00000000-0000-4000-8000-000000000001".into(),
                    password: "test".into(),
                    congestion_control: None,
                    udp_relay_mode: None,
                    zero_rtt_handshake: false,
                    heartbeat: None,
                    disable_sni: false,
                }),
                false,
            ),
            (
                Outbound::AnyTls(AnyTlsParams {
                    password: "test".into(),
                    idle_session_check_interval: None,
                    idle_session_timeout: None,
                    min_idle_session: None,
                }),
                false,
            ),
            (Outbound::Http(ProxyCredentials::default()), false),
            (Outbound::Socks5(ProxyCredentials::default()), false),
        ]
    }

    #[test]
    fn fragmentation_sends_every_node_xray_can_run_through_xray() {
        let tls = TlsMode::Tls(TlsParams::default());
        for (outbound, supported) in every_outbound() {
            let node = example_node(outbound, tls.clone());
            for packets in ["tlshello", "1-3"] {
                for xray in [XrayUse::Auto, XrayUse::Always] {
                    let settings = with_fragment(xray, packets);
                    assert_eq!(uses_xray(&node, &settings), supported);
                    assert_eq!(fragments_tls(&node, &settings), supported);
                }
                let off = with_fragment(XrayUse::Off, packets);
                assert!(!uses_xray(&node, &off));
                assert!(!fragments_tls(&node, &off));
            }
        }
    }

    #[test]
    fn fragmentation_off_changes_nothing_for_any_node() {
        let tls = TlsMode::Tls(TlsParams::default());
        for (outbound, _) in every_outbound() {
            let node = example_node(outbound, tls.clone());
            for xray in [XrayUse::Auto, XrayUse::Off, XrayUse::Always] {
                let settings = with_xray(xray);
                assert!(!settings.tls_fragment.enabled);
                assert!(!fragments_tls(&node, &settings));
            }
        }
    }

    #[test]
    fn the_hello_mode_leaves_a_node_without_tls_on_sing_box() {
        let vless = every_outbound().remove(0).0;
        let node = example_node(vless, TlsMode::Plain);
        let hello = with_fragment(XrayUse::Auto, "tlshello");
        assert!(!uses_xray(&node, &hello));
        assert!(!fragments_tls(&node, &hello));
        let range = with_fragment(XrayUse::Auto, "1-3");
        assert!(uses_xray(&node, &range));
        assert!(fragments_tls(&node, &range));
    }

    fn xhttp() -> Transport {
        Transport::Xhttp {
            path: "/secret-path".into(),
            host: Some("secret-host.example.com".into()),
            mode: XhttpMode::PacketUp,
            extra: XhttpExtra {
                headers: [("X-Secret-Name".into(), "secret-value".into())].into(),
                x_padding_bytes: Some(XhttpRange {
                    from: 100,
                    to: 1000,
                }),
                ..XhttpExtra::default()
            },
        }
    }

    #[test]
    fn xhttp_debug_hides_path_host_and_headers() {
        let debug = format!("{:?}", xhttp());
        assert!(debug.contains("PacketUp"));
        assert!(debug.contains("headers_count: 1"));
        for secret in [
            "secret-path",
            "secret-host",
            "X-Secret-Name",
            "secret-value",
        ] {
            assert!(!debug.contains(secret), "{secret} leaked: {debug}");
        }
    }

    #[test]
    fn transport_debug_hides_paths_hosts_and_service_names() {
        for transport in [
            Transport::Tcp,
            Transport::Ws {
                path: "/secret-path".into(),
                host: Some("secret-host.example.com".into()),
            },
            Transport::Grpc {
                service_name: "secret-service".into(),
            },
            Transport::HttpUpgrade {
                path: "/secret-path".into(),
                host: Some("secret-host.example.com".into()),
            },
            xhttp(),
        ] {
            let debug = format!("{transport:?}");
            for secret in ["secret-path", "secret-host", "secret-service"] {
                assert!(!debug.contains(secret), "{secret} leaked: {debug}");
            }
        }
    }

    #[test]
    fn xhttp_serializes_every_field_and_reads_back() {
        let transport = xhttp();
        let json = serde_json::to_value(&transport).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "xhttp": {
                "path": "/secret-path",
                "host": "secret-host.example.com",
                "mode": "packet-up",
                "extra": {
                    "headers": { "X-Secret-Name": "secret-value" },
                    "x_padding_bytes": { "from": 100, "to": 1000 }
                }
            }})
        );
        assert_eq!(
            serde_json::from_value::<Transport>(json).unwrap(),
            transport
        );
    }

    #[test]
    fn xhttp_goes_through_xray_unless_xray_is_off() {
        let mut node = Node {
            id: NodeId::new("test"),
            name: "Test".into(),
            server: "192.0.2.1".into(),
            port: 443,
            outbound: Outbound::Trojan(TrojanParams {
                password: "test".into(),
            }),
            stream: StreamSettings {
                transport: xhttp(),
                tls: TlsMode::Plain,
            },
            raw: None,
        };
        assert!(uses_xray(&node, &with_xray(XrayUse::Auto)));
        assert!(uses_xray(&node, &with_xray(XrayUse::Always)));
        assert!(!uses_xray(&node, &with_xray(XrayUse::Off)));

        node.outbound = Outbound::Hysteria2(Hysteria2Params {
            password: "test".into(),
            obfs_password: None,
            port_ranges: Vec::new(),
            up_mbps: None,
            down_mbps: None,
        });
        assert!(!uses_xray(&node, &with_xray(XrayUse::Auto)));
        assert!(!uses_xray(&node, &with_xray(XrayUse::Always)));
    }

    #[test]
    fn tuic_and_anytls_debug_redact_credentials_and_serde_omits_defaults() {
        let tuic = Node {
            id: NodeId::new("tuic"),
            name: "TUIC".into(),
            server: "example.com".into(),
            port: 443,
            outbound: Outbound::Tuic(TuicParams {
                uuid: "00000000-0000-4000-8000-000000000042".into(),
                password: "test-secret-tuic".into(),
                congestion_control: None,
                udp_relay_mode: None,
                zero_rtt_handshake: false,
                heartbeat: None,
                disable_sni: false,
            }),
            stream: StreamSettings {
                transport: Transport::Tcp,
                tls: TlsMode::Tls(TlsParams::default()),
            },
            raw: Some(
                "tuic://00000000-0000-4000-8000-000000000042:test-secret-tuic@example.com:443"
                    .into(),
            ),
        };
        let debug = format!("{tuic:?}");
        assert!(!debug.contains("00000000-0000-4000-8000-000000000042"));
        assert!(!debug.contains("test-secret-tuic"));
        let json = serde_json::to_value(&tuic).unwrap();
        assert_eq!(
            json["outbound"]["tuic"]["uuid"],
            "00000000-0000-4000-8000-000000000042"
        );
        assert_eq!(json["outbound"]["tuic"]["password"], "test-secret-tuic");
        assert!(json["outbound"]["tuic"].get("congestion_control").is_none());
        assert!(json["outbound"]["tuic"].get("udp_relay_mode").is_none());
        assert!(json["outbound"]["tuic"].get("zero_rtt_handshake").is_none());
        assert!(json["outbound"]["tuic"].get("heartbeat").is_none());
        assert!(json["outbound"]["tuic"].get("disable_sni").is_none());

        let anytls = Node {
            id: NodeId::new("anytls"),
            name: "AnyTLS".into(),
            server: "example.com".into(),
            port: 443,
            outbound: Outbound::AnyTls(AnyTlsParams {
                password: "test-secret-anytls".into(),
                idle_session_check_interval: None,
                idle_session_timeout: None,
                min_idle_session: None,
            }),
            stream: StreamSettings {
                transport: Transport::Tcp,
                tls: TlsMode::Tls(TlsParams::default()),
            },
            raw: Some("anytls://test-secret-anytls@example.com:443".into()),
        };
        let debug = format!("{anytls:?}");
        assert!(!debug.contains("test-secret-anytls"));
        let json = serde_json::to_value(&anytls).unwrap();
        assert_eq!(json["outbound"]["anytls"]["password"], "test-secret-anytls");
        assert!(
            json["outbound"]["anytls"]
                .get("idle_session_check_interval")
                .is_none()
        );
        assert!(
            json["outbound"]["anytls"]
                .get("idle_session_timeout")
                .is_none()
        );
        assert!(json["outbound"]["anytls"].get("min_idle_session").is_none());
    }

    #[test]
    fn tuic_and_anytls_validate_required_fields_and_durations() {
        let mut tuic = example_node(
            Outbound::Tuic(TuicParams {
                uuid: "00000000-0000-4000-8000-000000000001".into(),
                password: String::new(),
                congestion_control: Some(TuicCongestionControl::Bbr),
                udp_relay_mode: Some(TuicUdpRelayMode::Native),
                zero_rtt_handshake: true,
                heartbeat: Some("10s".into()),
                disable_sni: false,
            }),
            TlsMode::Tls(TlsParams::default()),
        );
        assert!(tuic.validate_proxy().is_ok());

        let mut bad = tuic.clone();
        bad.stream.tls = TlsMode::Plain;
        assert!(bad.validate_proxy().is_err());

        let mut bad = tuic.clone();
        bad.stream.tls = TlsMode::Reality(RealityParams {
            sni: Some("example.com".into()),
            public_key: "test-public-key".into(),
            short_id: None,
            fingerprint: None,
        });
        assert!(bad.validate_proxy().is_err());

        let mut bad = tuic.clone();
        bad.outbound = Outbound::Tuic(TuicParams {
            uuid: "not-a-uuid".into(),
            password: "test".into(),
            congestion_control: None,
            udp_relay_mode: None,
            zero_rtt_handshake: false,
            heartbeat: None,
            disable_sni: false,
        });
        assert!(bad.validate_proxy().is_err());

        tuic.outbound = Outbound::Tuic(TuicParams {
            uuid: "00000000-0000-4000-8000-000000000001".into(),
            password: "test".into(),
            congestion_control: None,
            udp_relay_mode: None,
            zero_rtt_handshake: false,
            heartbeat: Some("0s".into()),
            disable_sni: false,
        });
        assert!(tuic.validate_proxy().is_err());

        let anytls = example_node(
            Outbound::AnyTls(AnyTlsParams {
                password: "test-password".into(),
                idle_session_check_interval: Some("30s".into()),
                idle_session_timeout: Some("1m30s".into()),
                min_idle_session: Some(2),
            }),
            TlsMode::Reality(RealityParams {
                sni: Some("example.com".into()),
                public_key: "test-public-key".into(),
                short_id: Some("0123".into()),
                fingerprint: Some("chrome".into()),
            }),
        );
        assert!(anytls.validate_proxy().is_ok());

        let mut bad = anytls.clone();
        bad.stream.tls = TlsMode::Plain;
        assert!(bad.validate_proxy().is_err());

        let mut bad = anytls.clone();
        bad.outbound = Outbound::AnyTls(AnyTlsParams {
            password: String::new(),
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
        });
        assert!(bad.validate_proxy().is_err());

        let mut bad = anytls;
        bad.outbound = Outbound::AnyTls(AnyTlsParams {
            password: "test-password".into(),
            idle_session_check_interval: Some("-5s".into()),
            idle_session_timeout: None,
            min_idle_session: None,
        });
        assert!(bad.validate_proxy().is_err());

        assert!(is_valid_uuid("00000000-0000-4000-8000-000000000001"));
        assert!(is_valid_uuid("00000000000040008000000000000001"));
        assert!(!is_valid_uuid("00000000-0000-4000-8000-00000000000g"));
        assert!(is_valid_duration("10s"));
        assert!(is_valid_duration("500ms"));
        assert!(is_valid_duration("1m30s"));
        assert!(is_valid_duration("0.5s"));
        assert!(!is_valid_duration("0s"));
        assert!(!is_valid_duration("-10s"));
        assert!(!is_valid_duration("10"));

        let wg_key_a = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let wg_key_b = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let wg_psk = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
        assert!(is_valid_wireguard_key(wg_key_a));
        assert!(is_valid_wireguard_key(wg_key_b));
        assert!(!is_valid_wireguard_key("too-short"));
        // Trailing unused bits in char 42 ('B' = 1) must be rejected.
        assert!(!is_valid_wireguard_key(
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        ));
        assert!(!is_valid_wireguard_key(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));

        assert!(is_valid_wireguard_address("10.0.0.2/32"));
        assert!(is_valid_wireguard_address("172.16.0.2/24"));
        assert!(is_valid_wireguard_address("fd00::2/128"));
        assert!(!is_valid_wireguard_address("10.0.0.2"));
        assert!(!is_valid_wireguard_address("10.0.0.2/33"));
        assert!(!is_valid_wireguard_address("fd00::2/129"));
        assert!(!is_valid_wireguard_address("10.0.0.2/08"));

        let wg = example_node(
            Outbound::WireGuard(WireGuardParams {
                private_key: wg_key_a.into(),
                public_key: wg_key_b.into(),
                pre_shared_key: Some(wg_psk.into()),
                address: vec!["10.0.0.2/32".into(), "fd00::2/128".into()],
                reserved: Some([1, 2, 3]),
                mtu: Some(1280),
                persistent_keepalive: Some(25),
            }),
            TlsMode::Plain,
        );
        assert!(wg.validate_proxy().is_ok());
        let debug = format!("{wg:?}");
        for secret in [wg_key_a, wg_key_b, wg_psk] {
            assert!(!debug.contains(secret), "debug leaked {secret}: {debug}");
        }
        let encoded = serde_json::to_value(&wg).unwrap();
        assert_eq!(encoded["outbound"]["wireguard"]["mtu"], 1280);
        assert_eq!(
            encoded["outbound"]["wireguard"]["reserved"],
            serde_json::json!([1, 2, 3])
        );

        let mut bad = wg.clone();
        bad.stream.tls = TlsMode::Tls(TlsParams::default());
        assert!(bad.validate_proxy().is_err());

        let mut bad = wg.clone();
        bad.outbound = Outbound::WireGuard(WireGuardParams {
            private_key: wg_key_a.into(),
            public_key: wg_key_b.into(),
            pre_shared_key: None,
            address: Vec::new(),
            reserved: None,
            mtu: None,
            persistent_keepalive: None,
        });
        assert!(bad.validate_proxy().is_err());

        let mut bad = wg.clone();
        bad.outbound = Outbound::WireGuard(WireGuardParams {
            private_key: wg_key_a.into(),
            public_key: wg_key_b.into(),
            pre_shared_key: None,
            address: vec!["10.0.0.2/32".into()],
            reserved: None,
            mtu: Some(500),
            persistent_keepalive: None,
        });
        assert!(bad.validate_proxy().is_err());

        let mut bad = wg;
        bad.outbound = Outbound::WireGuard(WireGuardParams {
            private_key: wg_key_a.into(),
            public_key: wg_key_b.into(),
            pre_shared_key: None,
            address: vec!["10.0.0.2/32".into()],
            reserved: None,
            mtu: None,
            persistent_keepalive: Some(0),
        });
        assert!(bad.validate_proxy().is_err());
    }
}
