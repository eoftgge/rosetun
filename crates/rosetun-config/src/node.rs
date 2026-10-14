use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{NodeId, XrayUse};

// sing-box#4520: REALITY servers on Xray 26.9.8+ reject sing-box's handshake.
const XRAY_FOR_REALITY: bool = true;

pub fn uses_xray(node: &Node, setting: XrayUse) -> bool {
    match setting {
        XrayUse::Off => false,
        XrayUse::Auto => {
            XRAY_FOR_REALITY
                && matches!(&node.outbound, Outbound::Vless(_))
                && matches!(&node.stream.tls, TlsMode::Reality(_))
        }
        XrayUse::Always => matches!(
            &node.outbound,
            Outbound::Vless(_)
                | Outbound::Vmess(_)
                | Outbound::Trojan(_)
                | Outbound::Shadowsocks(_)
        ),
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

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
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
            (Outbound::Vmess(VmessParams { uuid: "test".into(), alter_id: 0, security: None }), true),
            (Outbound::Trojan(TrojanParams { password: "test".into() }), true),
            (Outbound::Shadowsocks(ShadowsocksParams { method: "aes-128-gcm".into(), password: "test".into() }), true),
            (Outbound::Hysteria2(Hysteria2Params { password: "test".into(), obfs_password: None, port_ranges: Vec::new(), up_mbps: None, down_mbps: None }), false),
            (Outbound::Unknown { scheme: "example".into(), params: BTreeMap::new() }, false),
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
}
