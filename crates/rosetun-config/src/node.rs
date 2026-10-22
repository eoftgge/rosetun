use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{CountryCode, NodeId, XrayUse};

// sing-box#4520: REALITY servers on Xray 26.9.8+ reject sing-box's handshake.
const XRAY_FOR_REALITY: bool = true;

pub fn uses_xray(node: &Node, setting: XrayUse) -> bool {
    match setting {
        XrayUse::Off => false,
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

fn xray_supports(outbound: &Outbound) -> bool {
    match outbound {
        Outbound::Vmess(params) => params.alter_id == 0,
        Outbound::Vless(_) | Outbound::Trojan(_) | Outbound::Shadowsocks(_) => true,
        Outbound::Hysteria2(_) | Outbound::Unknown { .. } => false,
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
            .field("name", &self.name)
            .field("server", &self.server)
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
    Vless(VlessParams),
    Vmess(VmessParams),
    Trojan(TrojanParams),
    Shadowsocks(ShadowsocksParams),
    Hysteria2(Hysteria2Params),
    Unknown {
        scheme: String,
        params: BTreeMap<String, String>,
    },
}

impl fmt::Debug for Outbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vless(params) => f.debug_tuple("Vless").field(params).finish(),
            Self::Vmess(params) => f.debug_tuple("Vmess").field(params).finish(),
            Self::Trojan(params) => f.debug_tuple("Trojan").field(params).finish(),
            Self::Shadowsocks(params) => f.debug_tuple("Shadowsocks").field(params).finish(),
            Self::Hysteria2(params) => f.debug_tuple("Hysteria2").field(params).finish(),
            Self::Unknown { scheme, params } => f
                .debug_struct("Unknown")
                .field("scheme", scheme)
                .field("params_count", &params.len())
                .finish(),
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
                assert_eq!(uses_xray(&node, XrayUse::Auto), auto);
                assert!(!uses_xray(&node, XrayUse::Off));
                assert_eq!(uses_xray(&node, XrayUse::Always), supported);
            }
        }
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
        assert!(uses_xray(&node, XrayUse::Auto));
        assert!(uses_xray(&node, XrayUse::Always));
        assert!(!uses_xray(&node, XrayUse::Off));

        node.outbound = Outbound::Hysteria2(Hysteria2Params {
            password: "test".into(),
            obfs_password: None,
            port_ranges: Vec::new(),
            up_mbps: None,
            down_mbps: None,
        });
        assert!(!uses_xray(&node, XrayUse::Auto));
        assert!(!uses_xray(&node, XrayUse::Always));
    }
}
