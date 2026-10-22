use rosetun_config::{LogLevel, Node, Outbound, TlsMode, Transport, XhttpExtra, XhttpRange};
use rosetun_engine::{RenderedConfig, errors::EngineError};
use serde_json::{Value, json};

use crate::SocksEndpoint;

/// One outbound per `(tag, node, socks)`, reached through its own SOCKS inbound
/// `<tag>-in`.
pub fn render(
    nodes: &[(&str, &Node, &SocksEndpoint)],
    interface: &str,
    verbose: bool,
    log_level: LogLevel,
) -> Result<RenderedConfig, EngineError> {
    let mut inbounds = Vec::with_capacity(nodes.len());
    let mut outbounds = Vec::with_capacity(nodes.len());
    let mut rules = Vec::with_capacity(nodes.len());
    for (tag, node, socks) in nodes {
        let inbound_tag = format!("{tag}-in");
        inbounds.push(socks_inbound(socks, &inbound_tag));
        outbounds.push(proxy_outbound(node, tag, interface)?);
        rules.push(json!({
            "type": "field",
            "inboundTag": [inbound_tag],
            "outboundTag": tag,
        }));
    }
    let mut config = json!({
        "log": log_section(verbose, log_level),
        "inbounds": inbounds,
        "outbounds": outbounds,
    });
    // Xray sends everything to its first outbound, so one node needs no routing.
    if nodes.len() > 1 {
        config["routing"] = json!({ "rules": rules });
    }
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
            // Xray accepts Vision on XHTTP but then fails every TCP connection with
            // "XTLS only supports TLS and REALITY directly", and the server refuses
            // Vision on XHTTP the same way, so the flow is left out.
            if let Some(flow) = &params.flow
                && !matches!(node.stream.transport, Transport::Xhttp { .. })
            {
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
        Transport::Xhttp {
            path,
            host,
            mode,
            extra,
        } => {
            stream["network"] = "xhttp".into();
            let mut options = json!({ "path": path, "mode": mode.as_str() });
            if let Some(host) = host {
                options["host"] = host.clone().into();
            }
            if !extra.is_empty() {
                options["extra"] = xhttp_extra(extra);
            }
            stream["xhttpSettings"] = options;
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
                Transport::Tcp | Transport::Grpc { .. } | Transport::Xhttp { .. }
            ) {
                return Err(EngineError::Unsupported(
                    "Xray REALITY requires TCP, gRPC or XHTTP transport".into(),
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

fn xhttp_extra(extra: &XhttpExtra) -> Value {
    fn range(value: XhttpRange) -> Value {
        if value.from == value.to {
            value.from.into()
        } else {
            format!("{}-{}", value.from, value.to).into()
        }
    }
    fn put_range(object: &mut Value, key: &str, value: Option<XhttpRange>) {
        if let Some(value) = value {
            object[key] = range(value);
        }
    }

    let mut options = json!({});
    if !extra.headers.is_empty() {
        options["headers"] = json!(extra.headers);
    }
    put_range(&mut options, "xPaddingBytes", extra.x_padding_bytes);
    if extra.no_grpc_header {
        options["noGRPCHeader"] = true.into();
    }
    if extra.no_sse_header {
        options["noSSEHeader"] = true.into();
    }
    put_range(&mut options, "scMaxEachPostBytes", extra.sc_max_each_post_bytes);
    put_range(&mut options, "scMinPostsIntervalMs", extra.sc_min_posts_interval_ms);
    if let Some(posts) = extra.sc_max_buffered_posts {
        options["scMaxBufferedPosts"] = posts.into();
    }
    if let Some(xmux) = &extra.xmux {
        let mut value = json!({});
        put_range(&mut value, "maxConcurrency", xmux.max_concurrency);
        put_range(&mut value, "maxConnections", xmux.max_connections);
        put_range(&mut value, "cMaxReuseTimes", xmux.c_max_reuse_times);
        put_range(&mut value, "hMaxRequestTimes", xmux.h_max_request_times);
        put_range(&mut value, "hMaxReusableSecs", xmux.h_max_reusable_secs);
        if let Some(period) = xmux.h_keep_alive_period {
            value["hKeepAlivePeriod"] = period.into();
        }
        options["xmux"] = value;
    }
    options
}

#[cfg(test)]
mod tests {
    use rosetun_config::{
        NodeId, RealityParams, StreamSettings, TlsParams, VlessParams, XhttpMode, XhttpXmux,
    };

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
        let rendered = render(
            &[("proxy", &reality_node(), &socks)],
            "Ethernet",
            false,
            LogLevel::Info,
        )
        .unwrap();
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
    fn extra_nodes_share_the_process_with_their_own_inbounds() {
        let main = SocksEndpoint::local().unwrap();
        let extra = SocksEndpoint::local().unwrap();
        let mut extra_node = reality_node();
        extra_node.server = "198.51.100.20".into();
        let rendered = render(
            &[
                ("proxy", &reality_node(), &main),
                ("exit-1", &extra_node, &extra),
            ],
            "Ethernet",
            false,
            LogLevel::Info,
        )
        .unwrap();
        let value: Value = serde_json::from_slice(&rendered.body).unwrap();
        assert_eq!(value["inbounds"][0]["tag"], "proxy-in");
        assert_eq!(value["inbounds"][1]["tag"], "exit-1-in");
        assert_eq!(value["inbounds"][1]["port"], extra.address().port());
        assert_eq!(value["outbounds"][1]["tag"], "exit-1");
        assert_eq!(
            value["outbounds"][1]["settings"]["address"],
            "198.51.100.20"
        );
        assert_eq!(
            value["routing"]["rules"][1],
            json!({ "type": "field", "inboundTag": ["exit-1-in"], "outboundTag": "exit-1" })
        );
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

    fn xhttp_node(tls: TlsMode, extra: XhttpExtra) -> Node {
        let mut node = reality_node();
        node.stream = StreamSettings {
            transport: Transport::Xhttp {
                path: "/example".into(),
                host: Some("xhttp.example.com".into()),
                mode: XhttpMode::StreamOne,
                extra,
            },
            tls,
        };
        node
    }

    fn stream_of(node: &Node) -> Value {
        let socks = SocksEndpoint::local().unwrap();
        let rendered = render(&[("proxy", node, &socks)], "Ethernet", false, LogLevel::Info)
            .unwrap();
        let mut value: Value = serde_json::from_slice(&rendered.body).unwrap();
        value["outbounds"][0].take()
    }

    #[test]
    fn xhttp_with_reality_renders_without_vision() {
        let node = xhttp_node(reality_node().stream.tls, XhttpExtra::default());
        let outbound = stream_of(&node);
        assert!(outbound["settings"].get("flow").is_none());
        let stream = &outbound["streamSettings"];
        assert_eq!(stream["network"], "xhttp");
        assert_eq!(stream["security"], "reality");
        assert_eq!(
            stream["xhttpSettings"],
            json!({ "path": "/example", "host": "xhttp.example.com", "mode": "stream-one" })
        );
        assert_eq!(stream["realitySettings"]["serverName"], "example.com");
    }

    #[test]
    fn xhttp_with_tls_and_without_tls() {
        let tls = TlsMode::Tls(TlsParams {
            sni: Some("example.com".into()),
            alpn: vec!["h2".into()],
            allow_insecure: false,
            fingerprint: None,
        });
        let stream = stream_of(&xhttp_node(tls, XhttpExtra::default()))["streamSettings"].take();
        assert_eq!(stream["network"], "xhttp");
        assert_eq!(stream["security"], "tls");
        assert_eq!(stream["tlsSettings"]["serverName"], "example.com");

        let stream =
            stream_of(&xhttp_node(TlsMode::Plain, XhttpExtra::default()))["streamSettings"].take();
        assert_eq!(stream["network"], "xhttp");
        assert!(stream.get("security").is_none());
        assert_eq!(stream["xhttpSettings"]["path"], "/example");
    }

    #[test]
    fn xhttp_extra_is_rendered_completely_and_nothing_else() {
        let range = |from, to| Some(XhttpRange { from, to });
        let extra = XhttpExtra {
            headers: [("X-Example".to_owned(), "example-value".to_owned())].into(),
            x_padding_bytes: range(100, 1000),
            no_grpc_header: true,
            no_sse_header: true,
            sc_max_each_post_bytes: range(1_000_000, 1_000_000),
            sc_min_posts_interval_ms: range(10, 50),
            sc_max_buffered_posts: Some(30),
            xmux: Some(XhttpXmux {
                max_concurrency: range(16, 32),
                max_connections: None,
                c_max_reuse_times: range(0, 8),
                h_max_request_times: range(600, 900),
                h_max_reusable_secs: range(1800, 3000),
                h_keep_alive_period: Some(15),
            }),
        };
        let stream = stream_of(&xhttp_node(TlsMode::Plain, extra))["streamSettings"].take();
        assert_eq!(
            stream["xhttpSettings"],
            json!({
                "path": "/example",
                "host": "xhttp.example.com",
                "mode": "stream-one",
                "extra": {
                    "headers": { "X-Example": "example-value" },
                    "xPaddingBytes": "100-1000",
                    "noGRPCHeader": true,
                    "noSSEHeader": true,
                    "scMaxEachPostBytes": 1_000_000,
                    "scMinPostsIntervalMs": "10-50",
                    "scMaxBufferedPosts": 30,
                    "xmux": {
                        "maxConcurrency": "16-32",
                        "cMaxReuseTimes": "0-8",
                        "hMaxRequestTimes": "600-900",
                        "hMaxReusableSecs": "1800-3000",
                        "hKeepAlivePeriod": 15,
                    },
                },
            })
        );
    }

    #[test]
    fn xhttp_probe_uses_the_same_outbound() {
        let node = xhttp_node(reality_node().stream.tls, XhttpExtra::default());
        let nodes = [("probe-0".to_owned(), node, SocksEndpoint::local().unwrap())];
        let rendered = render_probe(&nodes, "Ethernet").unwrap();
        assert!(rendered.unsupported.is_empty());
        let value: Value = serde_json::from_slice(&rendered.body).unwrap();
        assert_eq!(value["outbounds"][0]["streamSettings"]["network"], "xhttp");
    }
}
