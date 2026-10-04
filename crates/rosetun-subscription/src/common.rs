use std::collections::BTreeMap;
use std::net::IpAddr;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use rosetun_config::{
    Node, NodeId, Outbound, RealityParams, ShadowsocksParams, StreamSettings, TlsMode, TlsParams,
    Transport, TrojanParams, VlessParams, VmessParams,
};

use crate::{SkipReason, UnsupportedTransport};

pub(crate) type Fields = BTreeMap<String, String>;

pub(crate) fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let compact: String = value.chars().filter(|ch| !ch.is_whitespace()).collect();
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(&compact).ok())
}

pub(crate) fn percent_decode(value: &str) -> String {
    // Form decoding treats '+' as a space, unlike URI userinfo and fragments.
    let encoded = format!("value={}", value.replace('+', "%2B"));
    url::form_urlencoded::parse(encoded.as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default()
}

pub(crate) fn clean(value: &str, limit: usize) -> String {
    value
        .chars()
        .filter(|ch| {
            !ch.is_control() && !matches!(*ch, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .collect::<String>()
        .trim()
        .chars()
        .take(limit)
        .collect::<String>()
        .trim_end()
        .to_owned()
}

pub(crate) fn field<'a>(fields: &'a Fields, key: &str) -> &'a str {
    fields.get(key).map(String::as_str).unwrap_or("")
}

pub(crate) fn optional(fields: &Fields, key: &str) -> Option<String> {
    let value = field(fields, key);
    (!value.is_empty()).then(|| value.to_owned())
}

pub(crate) fn truth(value: &str) -> bool {
    value == "1" || value.eq_ignore_ascii_case("true")
}

pub(crate) fn build(protocol: &str, fields: &Fields) -> Result<Node, SkipReason> {
    let server = field(fields, "server");
    if server.is_empty()
        || server
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(SkipReason::MissingField);
    }

    let port: u16 = field(fields, "port")
        .parse()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(SkipReason::InvalidPort)?;

    let outbound = match protocol {
        "vless" => {
            let encryption = field(fields, "encryption");
            if !matches!(encryption, "" | "none") {
                return Err(SkipReason::UnsupportedEncryption);
            }
            let flow = field(fields, "flow");
            if !matches!(flow, "" | "xtls-rprx-vision") {
                return Err(SkipReason::UnsupportedFlow);
            }
            Outbound::Vless(VlessParams {
                uuid: required(fields, "uuid")?,
                flow: optional(fields, "flow"),
            })
        }
        "vmess" => {
            let alter_id = match field(fields, "aid") {
                "" => 0,
                value => value.parse().map_err(|_| SkipReason::InvalidRecord)?,
            };
            Outbound::Vmess(VmessParams {
                uuid: required(fields, "uuid")?,
                alter_id,
                security: optional(fields, "cipher"),
            })
        }
        "trojan" => Outbound::Trojan(TrojanParams {
            password: required(fields, "password")?,
        }),
        "ss" => {
            if fields.contains_key("plugin") {
                return Err(SkipReason::ShadowsocksPlugin);
            }
            let method = field(fields, "method");
            if !matches!(
                method,
                "aes-128-gcm"
                    | "aes-192-gcm"
                    | "aes-256-gcm"
                    | "chacha20-ietf-poly1305"
                    | "xchacha20-ietf-poly1305"
                    | "2022-blake3-aes-128-gcm"
                    | "2022-blake3-aes-256-gcm"
                    | "2022-blake3-chacha20-poly1305"
            ) {
                return Err(SkipReason::UnsupportedShadowsocksMethod);
            }
            Outbound::Shadowsocks(ShadowsocksParams {
                method: method.to_owned(),
                password: required(fields, "password")?,
            })
        }
        _ => return Err(SkipReason::UnsupportedProtocol),
    };

    let transport = transport(fields)?;
    let tls = tls(protocol, fields)?;
    let mut name = clean(field(fields, "name"), 128);
    if name.is_empty() {
        name = clean(&endpoint(server, port), 128);
    }

    Ok(Node {
        id: NodeId::new(""),
        name,
        server: server.to_owned(),
        port,
        outbound,
        stream: StreamSettings { transport, tls },
        raw: None,
    })
}

fn required(fields: &Fields, key: &str) -> Result<String, SkipReason> {
    optional(fields, key).ok_or(SkipReason::MissingField)
}

fn transport(fields: &Fields) -> Result<Transport, SkipReason> {
    match field(fields, "transport") {
        "" | "tcp" | "raw" => {
            if field(fields, "header") == "http" {
                return Err(SkipReason::UnsupportedTcpHeader);
            }
            Ok(Transport::Tcp)
        }
        "ws" => Ok(Transport::Ws {
            path: field(fields, "path").to_owned(),
            host: optional(fields, "host"),
        }),
        "grpc" => {
            if field(fields, "mode") == "multi" || truth(field(fields, "multi")) {
                return Err(SkipReason::UnsupportedGrpcMultiMode);
            }
            Ok(Transport::Grpc {
                service_name: field(fields, "service").to_owned(),
            })
        }
        "httpupgrade" => Ok(Transport::HttpUpgrade {
            path: field(fields, "path").to_owned(),
            host: optional(fields, "host"),
        }),
        value => Err(SkipReason::UnsupportedTransport(match value {
            "xhttp" => UnsupportedTransport::Xhttp,
            "splithttp" => UnsupportedTransport::SplitHttp,
            "kcp" => UnsupportedTransport::Kcp,
            "quic" => UnsupportedTransport::Quic,
            "h2" => UnsupportedTransport::H2,
            "http" => UnsupportedTransport::Http,
            _ => UnsupportedTransport::Other,
        })),
    }
}

fn tls(protocol: &str, fields: &Fields) -> Result<TlsMode, SkipReason> {
    let security = fields
        .get("security")
        .map(String::as_str)
        .unwrap_or(if protocol == "trojan" { "tls" } else { "" });

    match security {
        "" | "none" => Ok(TlsMode::Plain),
        "tls" => Ok(TlsMode::Tls(TlsParams {
            sni: optional(fields, "sni"),
            alpn: field(fields, "alpn")
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect(),
            allow_insecure: truth(field(fields, "insecure")),
            fingerprint: optional(fields, "fingerprint"),
        })),
        "reality" => Ok(TlsMode::Reality(RealityParams {
            sni: optional(fields, "sni"),
            public_key: optional(fields, "public_key")
                .ok_or(SkipReason::MissingRealityPublicKey)?,
            short_id: optional(fields, "short_id"),
            fingerprint: optional(fields, "fingerprint"),
        })),
        _ => Err(SkipReason::UnsupportedSecurity),
    }
}

fn endpoint(server: &str, port: u16) -> String {
    if server.contains(':') && !server.starts_with('[') {
        format!("[{server}]:{port}")
    } else {
        format!("{server}:{port}")
    }
}

pub(crate) fn is_service(node: &Node) -> bool {
    let server = node.server.trim_matches(['[', ']']);
    let unspecified = server
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_unspecified());
    let uuid = match &node.outbound {
        Outbound::Vless(params) => Some(params.uuid.as_str()),
        Outbound::Vmess(params) => Some(params.uuid.as_str()),
        _ => None,
    };
    let zero_uuid = uuid.is_some_and(|uuid| {
        uuid == "00000000-0000-0000-0000-000000000000" || uuid == "00000000000000000000000000000000"
    });
    unspecified || zero_uuid
}

pub(crate) fn stable_id(node: &Node) -> String {
    let protocol = match &node.outbound {
        Outbound::Vless(_) => "vless",
        Outbound::Vmess(_) => "vmess",
        Outbound::Trojan(_) => "trojan",
        Outbound::Shadowsocks(_) => "ss",
        Outbound::Unknown { .. } => "unknown",
    };
    let (transport, path, host, service) = match &node.stream.transport {
        Transport::Tcp => ("tcp", "", "", ""),
        Transport::Ws { path, host } => ("ws", path.as_str(), host.as_deref().unwrap_or(""), ""),
        Transport::Grpc { service_name } => ("grpc", "", "", service_name.as_str()),
        Transport::HttpUpgrade { path, host } => (
            "httpupgrade",
            path.as_str(),
            host.as_deref().unwrap_or(""),
            "",
        ),
    };
    let (security, sni) = match &node.stream.tls {
        TlsMode::Plain => ("none", ""),
        TlsMode::Tls(params) => ("tls", params.sni.as_deref().unwrap_or("")),
        TlsMode::Reality(params) => ("reality", params.sni.as_deref().unwrap_or("")),
    };
    let canonical = format!(
        "{protocol}|{}|{}|{transport}|{path}|{host}|{service}|{security}|{sni}",
        node.server.to_lowercase(),
        node.port,
    );

    // DefaultHasher does not guarantee a stable algorithm across Rust versions.
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in canonical.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}
