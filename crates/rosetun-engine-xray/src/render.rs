use rosetun_config::{LogLevel, Node, Outbound, TlsMode, Transport};
use rosetun_engine::{RenderedConfig, errors::EngineError};
use serde_json::{Value, json};

use crate::SocksEndpoint;

pub fn render(
    node: &Node,
    socks: &SocksEndpoint,
    interface: &str,
    verbose: bool,
    log_level: LogLevel,
) -> Result<RenderedConfig, EngineError> {
    let config = json!({
        "log": log_section(verbose, log_level),
        "inbounds": [socks_inbound(socks, "proxy-in")],
        "outbounds": [proxy_outbound(node, "proxy", interface)?],
    });
    rendered("config.json", config)
}

pub fn render_probe(
    nodes: &[(String, Node, SocksEndpoint)],
    interface: &str,
) -> Result<RenderedConfig, EngineError> {
    let mut inbounds = Vec::with_capacity(nodes.len());
    let mut outbounds = Vec::with_capacity(nodes.len());
    let mut rules = Vec::with_capacity(nodes.len());
    let mut unsupported_probes = Vec::new();
    for (tag, node, socks) in nodes {
        let outbound = match proxy_outbound(node, tag, interface) {
            Ok(outbound) => outbound,
            Err(EngineError::Unsupported(_)) => {
                unsupported_probes.push(tag.clone());
                continue;
            }
            Err(error) => return Err(error),
        };
        let inbound_tag = format!("{tag}-in");
        inbounds.push(socks_inbound(socks, &inbound_tag));
        outbounds.push(outbound);
        rules.push(json!({
            "type": "field",
            "inboundTag": [inbound_tag],
            "outboundTag": tag,
        }));
    }
    let config = json!({
        "log": log_section(false, LogLevel::Info),
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": { "rules": rules },
    });
    let mut rendered = rendered("probe.json", config)?;
    rendered.unsupported_probes = unsupported_probes;
    Ok(rendered)
}

fn rendered(file_name: &str, config: Value) -> Result<RenderedConfig, EngineError> {
    Ok(RenderedConfig {
        file_name: file_name.to_owned(),
        body: serde_json::to_vec_pretty(&config)
            .map_err(|error| EngineError::Render(error.to_string()))?,
        unsupported: Vec::new(),
        unsupported_probes: Vec::new(),
    })
}

fn log_section(verbose: bool, _log_level: LogLevel) -> Value {
    // Xray prints its startup handshake at Warning; Info would disclose destinations.
    json!({ "access": "none", "loglevel": if verbose { "debug" } else { "warning" } })
}

fn socks_inbound(socks: &SocksEndpoint, tag: &str) -> Value {
    json!({
        "tag": tag,
        "listen": "127.0.0.1",
        "port": socks.address().port(),
        "protocol": "socks",
        "settings": {
            "auth": "password",
            "accounts": [{ "user": socks.username(), "pass": socks.password() }],
            "udp": true,
            "ip": "127.0.0.1",
        },
    })
}

fn proxy_outbound(node: &Node, tag: &str, interface: &str) -> Result<Value, EngineError> {
    if node.server.parse::<std::net::IpAddr>().is_err() {
        return Err(EngineError::Render(
            "Xray server address must be an IP literal".into(),
        ));
    }
    if interface.is_empty() {
        return Err(EngineError::Render(
            "physical interface is required for Xray".into(),
        ));
    }
    let (protocol, settings) = match &node.outbound {
        Outbound::Vless(params) => {
            let mut settings = json!({
                "address": node.server,
                "port": node.port,
                "id": params.uuid,
                "encryption": "none",
            });
            if let Some(flow) = &params.flow {
                settings["flow"] = flow.clone().into();
            }
            ("vless", settings)
        }
        Outbound::Vmess(params) if params.alter_id == 0 => (
            "vmess",
            json!({
                "address": node.server,
                "port": node.port,
                "id": params.uuid,
                "security": params.security.as_deref().unwrap_or("auto"),
            }),
        ),
        Outbound::Trojan(params) => (
            "trojan",
            json!({
                "address": node.server,
                "port": node.port,
                "password": params.password,
            }),
        ),
        Outbound::Shadowsocks(params) => (
            "shadowsocks",
            json!({
                "address": node.server,
                "port": node.port,
                "method": params.method,
                "password": params.password,
            }),
        ),
        _ => {
            return Err(EngineError::Unsupported(
                "Xray does not support this node".into(),
            ));
        }
    };

    let mut stream = json!({ "network": "tcp", "sockopt": { "interface": interface } });
    match &node.stream.transport {
        Transport::Tcp => {}
        Transport::Ws { path, host } => {
            stream["network"] = "ws".into();
            let mut options = json!({ "path": path });
            if let Some(host) = host {
                options["host"] = host.clone().into();
            }
            stream["wsSettings"] = options;
        }
        Transport::Grpc { service_name } => {
            stream["network"] = "grpc".into();
            stream["grpcSettings"] = json!({ "serviceName": service_name });
        }
        Transport::HttpUpgrade { path, host } => {
            stream["network"] = "httpupgrade".into();
            let mut options = json!({ "path": path });
            if let Some(host) = host {
                options["host"] = host.clone().into();
            }
            stream["httpupgradeSettings"] = options;
        }
    }
    match &node.stream.tls {
        TlsMode::Plain => {}
        TlsMode::Tls(params) => {
            stream["security"] = "tls".into();
            let mut tls = json!({
                "allowInsecure": params.allow_insecure,
                "fingerprint": params.fingerprint.as_deref().unwrap_or("chrome"),
            });
            if let Some(sni) = &params.sni {
                tls["serverName"] = sni.clone().into();
            }
            if !params.alpn.is_empty() {
                tls["alpn"] = params.alpn.clone().into();
            }
            stream["tlsSettings"] = tls;
        }
        TlsMode::Reality(params) => {
            if !matches!(
                node.stream.transport,
                Transport::Tcp | Transport::Grpc { .. }
            ) {
                return Err(EngineError::Unsupported(
                    "Xray REALITY requires TCP or gRPC transport".into(),
                ));
            }
            stream["security"] = "reality".into();
            let mut reality = json!({
                "publicKey": params.public_key,
                "shortId": params.short_id.as_deref().unwrap_or(""),
                "fingerprint": params.fingerprint.as_deref().unwrap_or("chrome"),
            });
            if let Some(sni) = &params.sni {
                reality["serverName"] = sni.clone().into();
            }
            stream["realitySettings"] = reality;
        }
    }

    Ok(json!({
        "tag": tag,
        "protocol": protocol,
        "settings": settings,
        "streamSettings": stream,
    }))
}

#[cfg(test)]
mod tests {
    use rosetun_config::{NodeId, RealityParams, StreamSettings, VlessParams};

    use super::*;

    fn reality_node() -> Node {
        Node {
            id: NodeId::new("reality"),
            name: "Example".into(),
            server: "192.0.2.10".into(),
            port: 443,
            outbound: Outbound::Vless(VlessParams {
                uuid: "00000000-0000-4000-8000-000000000001".into(),
                flow: Some("xtls-rprx-vision".into()),
            }),
            stream: StreamSettings {
                transport: Transport::Tcp,
                tls: TlsMode::Reality(RealityParams {
                    sni: Some("example.com".into()),
                    public_key: "test-public-key".into(),
                    short_id: Some("01234567".into()),
                    fingerprint: Some("firefox".into()),
                }),
            },
            raw: None,
        }
    }

    #[test]
    fn reality_config_uses_authenticated_loopback_and_bound_server() {
        let socks = SocksEndpoint::local().unwrap();
        let rendered = render(&reality_node(), &socks, "Ethernet", false, LogLevel::Info).unwrap();
        let debug = format!("{rendered:?}");
        assert!(!debug.contains(socks.password()));
        let value: Value = serde_json::from_slice(&rendered.body).unwrap();
        assert_eq!(value["inbounds"][0]["settings"]["auth"], "password");
        assert_eq!(value["inbounds"][0]["settings"]["udp"], true);
        assert_eq!(value["inbounds"][0]["settings"]["ip"], "127.0.0.1");
        assert_eq!(value["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(
            value["inbounds"][0]["settings"]["accounts"][0]["pass"],
            socks.password()
        );
        assert_eq!(value["outbounds"][0]["settings"]["address"], "192.0.2.10");
        assert_eq!(
            value["outbounds"][0]["settings"]["flow"],
            "xtls-rprx-vision"
        );
        assert_eq!(
            value["outbounds"][0]["streamSettings"]["sockopt"]["interface"],
            "Ethernet"
        );
        assert_eq!(
            value["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"],
            "example.com"
        );
        assert_eq!(
            value["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"],
            "firefox"
        );
        assert!(value.get("routing").is_none());
        assert!(value.get("dns").is_none());
    }

    #[test]
    fn probes_route_each_authenticated_inbound_to_its_server() {
        let nodes = (0..2)
            .map(|index| {
                (
                    format!("probe-{index}"),
                    reality_node(),
                    SocksEndpoint::local().unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let value: Value =
            serde_json::from_slice(&render_probe(&nodes, "Ethernet").unwrap().body).unwrap();
        assert_eq!(value["inbounds"].as_array().unwrap().len(), 2);
        assert_eq!(
            value["routing"]["rules"][1]["inboundTag"],
            json!(["probe-1-in"])
        );
        assert_eq!(value["routing"]["rules"][1]["outboundTag"], "probe-1");
    }
}
