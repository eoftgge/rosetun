use rosetun_config::{
    BalancerStrategy, BurstObservatory, FinalMask, FragmentPackets, HeaderCustomItem,
    HeaderCustomPacket, HeaderCustomPacketType, HeaderCustomTcp, LogLevel, Node, Outbound,
    StandardObservatory, StreamSettings, TcpFinalMask, TlsFragment, TlsMode, Transport, XhttpExtra,
    XhttpRange, XrayBalancer, XrayObservatory,
};
use rosetun_engine::{RenderedConfig, errors::EngineError};
use serde_json::{Value, json};

use crate::SocksEndpoint;

/// One outbound (or balancer group) per `(tag, node, socks)`, reached through its own SOCKS
/// inbound `<tag>-in`. A node that `fragment` applies to dials its server through a `freedom`
/// outbound `<tag>-fragment`, which is placed after every proxy outbound because Xray sends
/// unrouted traffic to the first one.
pub fn render(
    nodes: &[(&str, &Node, &SocksEndpoint)],
    interface: &str,
    fragment: &TlsFragment,
    verbose: bool,
    log_level: LogLevel,
) -> Result<RenderedConfig, EngineError> {
    if interface.is_empty() {
        return Err(EngineError::Render(
            "physical interface is required for Xray".into(),
        ));
    }
    render_session(nodes, Some(interface), fragment, verbose, log_level)
}

pub fn render_outbound_worker(
    nodes: &[(&str, &Node, &SocksEndpoint)],
    fragment: &TlsFragment,
    verbose: bool,
    log_level: LogLevel,
) -> Result<RenderedConfig, EngineError> {
    render_session(nodes, None, fragment, verbose, log_level)
}

fn render_session(
    nodes: &[(&str, &Node, &SocksEndpoint)],
    interface: Option<&str>,
    fragment: &TlsFragment,
    verbose: bool,
    log_level: LogLevel,
) -> Result<RenderedConfig, EngineError> {
    let mut inbounds = Vec::with_capacity(nodes.len());
    let mut outbounds = Vec::with_capacity(nodes.len());
    let mut fragments = Vec::new();
    let mut rules = Vec::with_capacity(nodes.len());
    let mut balancers = Vec::new();
    let mut burst_obs: Option<BurstObservatory> = None;
    let mut standard_obs: Option<StandardObservatory> = None;

    for (tag, node, socks) in nodes {
        let inbound_tag = format!("{tag}-in");
        inbounds.push(socks_inbound(socks, &inbound_tag));
        match &node.outbound {
            Outbound::XrayBalancer(balancer) => {
                render_balancer_entry(
                    tag,
                    &inbound_tag,
                    balancer,
                    interface,
                    fragment,
                    &mut outbounds,
                    &mut fragments,
                    &mut balancers,
                    &mut rules,
                    &mut burst_obs,
                    &mut standard_obs,
                )?;
            }
            _ => {
                outbounds.push(proxy_outbound_parts(
                    &node.server,
                    node.port,
                    &node.outbound,
                    &node.stream,
                    tag,
                    interface,
                    fragment,
                )?);
                fragments.extend(fragment_outbound_parts(
                    &node.outbound,
                    &node.stream,
                    tag,
                    interface,
                    fragment,
                ));
                rules.push(json!({
                    "type": "field",
                    "inboundTag": [inbound_tag],
                    "outboundTag": tag,
                }));
            }
        }
    }
    outbounds.extend(fragments);
    let mut config = json!({
        "log": log_section(verbose, log_level),
        "inbounds": inbounds,
        "outbounds": outbounds,
    });
    // Xray sends everything to its first outbound, so one standalone node needs no routing.
    if nodes.len() > 1 || !balancers.is_empty() {
        let mut routing = json!({ "rules": rules });
        if !balancers.is_empty() {
            routing["balancers"] = Value::Array(balancers);
        }
        config["routing"] = routing;
    }
    if let Some(obs) = burst_obs {
        config["burstObservatory"] = render_burst_observatory(&obs);
    }
    if let Some(obs) = standard_obs {
        config["observatory"] = render_standard_observatory(&obs);
    }
    rendered("config.json", config)
}

#[expect(
    clippy::too_many_arguments,
    reason = "collects Xray config sections for one balanced exit"
)]
fn render_balancer_entry(
    tag: &str,
    inbound_tag: &str,
    balancer: &XrayBalancer,
    interface: Option<&str>,
    fragment: &TlsFragment,
    outbounds: &mut Vec<Value>,
    fragments: &mut Vec<Value>,
    balancers: &mut Vec<Value>,
    rules: &mut Vec<Value>,
    burst_obs: &mut Option<BurstObservatory>,
    standard_obs: &mut Option<StandardObservatory>,
) -> Result<(), EngineError> {
    balancer
        .validate()
        .map_err(|message| EngineError::Render(message.into()))?;
    for member in &balancer.members {
        let member_tag = balancer_member_tag(tag, &member.tag);
        outbounds.push(proxy_outbound_parts(
            &member.server,
            member.port,
            &member.outbound,
            &member.stream,
            &member_tag,
            interface,
            fragment,
        )?);
        fragments.extend(fragment_outbound_parts(
            &member.outbound,
            &member.stream,
            &member_tag,
            interface,
            fragment,
        ));
    }
    let bal_tag = format!("{tag}-bal");
    let selector: Vec<String> = balancer
        .selector
        .iter()
        .map(|prefix| balancer_member_tag(tag, prefix))
        .collect();
    let mut entry = json!({
        "tag": bal_tag,
        "selector": selector,
        "strategy": render_balancer_strategy(&balancer.strategy),
    });
    if let Some(fallback) = &balancer.fallback_tag {
        entry["fallbackTag"] = balancer_member_tag(tag, fallback).into();
    }
    balancers.push(entry);
    rules.push(json!({
        "type": "field",
        "inboundTag": [inbound_tag],
        "balancerTag": bal_tag,
    }));

    match &balancer.observatory {
        Some(XrayObservatory::Burst(obs)) => {
            let prefixed: Vec<String> = obs
                .subject_selector
                .iter()
                .map(|prefix| balancer_member_tag(tag, prefix))
                .collect();
            match burst_obs {
                Some(existing) => existing.subject_selector.extend(prefixed),
                None => {
                    let mut merged = obs.clone();
                    merged.subject_selector = prefixed;
                    *burst_obs = Some(merged);
                }
            }
        }
        Some(XrayObservatory::Standard(obs)) => {
            let prefixed: Vec<String> = obs
                .subject_selector
                .iter()
                .map(|prefix| balancer_member_tag(tag, prefix))
                .collect();
            match standard_obs {
                Some(existing) => existing.subject_selector.extend(prefixed),
                None => {
                    let mut merged = obs.clone();
                    merged.subject_selector = prefixed;
                    *standard_obs = Some(merged);
                }
            }
        }
        None => {}
    }
    Ok(())
}

fn balancer_member_tag(node_tag: &str, member_tag: &str) -> String {
    format!("{node_tag}--{member_tag}")
}

fn render_balancer_strategy(strategy: &BalancerStrategy) -> Value {
    match strategy {
        BalancerStrategy::Random => json!({ "type": "random" }),
        BalancerStrategy::RoundRobin => json!({ "type": "roundRobin" }),
        BalancerStrategy::LeastPing => json!({ "type": "leastPing" }),
        BalancerStrategy::LeastLoad(settings) => {
            let mut inner = serde_json::Map::new();
            if let Some(expected) = settings.expected {
                inner.insert("expected".into(), expected.into());
            }
            if let Some(max_rtt) = &settings.max_rtt {
                inner.insert("maxRTT".into(), max_rtt.clone().into());
            }
            if let Some(tolerance_bp) = settings.tolerance_bp {
                inner.insert(
                    "tolerance".into(),
                    (f64::from(tolerance_bp) / 10_000.0).into(),
                );
            }
            if !settings.baselines.is_empty() {
                inner.insert("baselines".into(), settings.baselines.clone().into());
            }
            if inner.is_empty() {
                json!({ "type": "leastLoad" })
            } else {
                json!({ "type": "leastLoad", "settings": Value::Object(inner) })
            }
        }
    }
}

fn render_burst_observatory(obs: &BurstObservatory) -> Value {
    let mut ping = serde_json::Map::new();
    if let Some(destination) = &obs.destination {
        ping.insert("destination".into(), destination.clone().into());
    }
    if let Some(interval) = &obs.interval {
        ping.insert("interval".into(), interval.clone().into());
    }
    if let Some(timeout) = &obs.timeout {
        ping.insert("timeout".into(), timeout.clone().into());
    }
    if let Some(sampling) = obs.sampling {
        ping.insert("sampling".into(), sampling.into());
    }
    if let Some(http_method) = &obs.http_method {
        ping.insert("httpMethod".into(), http_method.clone().into());
    }
    let mut value = json!({ "subjectSelector": obs.subject_selector });
    if !ping.is_empty() {
        value["pingConfig"] = Value::Object(ping);
    }
    value
}

fn render_standard_observatory(obs: &StandardObservatory) -> Value {
    let mut value = json!({ "subjectSelector": obs.subject_selector });
    if let Some(url) = &obs.probe_url {
        value["probeUrl"] = url.clone().into();
    }
    if let Some(interval) = &obs.probe_interval {
        value["probeInterval"] = interval.clone().into();
    }
    if obs.enable_concurrency {
        value["enableConcurrency"] = true.into();
    }
    value
}

/// Server checks take the same path as the connection, so a node that is fragmented when
/// connected is fragmented when checked.
pub fn render_probe(
    nodes: &[(String, Node, SocksEndpoint)],
    interface: &str,
    fragment: &TlsFragment,
) -> Result<RenderedConfig, EngineError> {
    if interface.is_empty() {
        return Err(EngineError::Render(
            "physical interface is required for Xray".into(),
        ));
    }
    let mut inbounds = Vec::with_capacity(nodes.len());
    let mut outbounds = Vec::with_capacity(nodes.len());
    let mut fragments = Vec::new();
    let mut rules = Vec::with_capacity(nodes.len());
    let mut unsupported_probes = Vec::new();
    for (tag, node, socks) in nodes {
        let (server, port, outbound_kind, stream) = match &node.outbound {
            Outbound::XrayBalancer(balancer) => match balancer.primary_member() {
                Some(member) => (
                    member.server.as_str(),
                    member.port,
                    &member.outbound,
                    &member.stream,
                ),
                None => {
                    unsupported_probes.push(tag.clone());
                    continue;
                }
            },
            _ => (
                node.server.as_str(),
                node.port,
                &node.outbound,
                &node.stream,
            ),
        };
        let outbound = match proxy_outbound_parts(
            server,
            port,
            outbound_kind,
            stream,
            tag,
            Some(interface),
            fragment,
        ) {
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
        fragments.extend(fragment_outbound_parts(
            outbound_kind,
            stream,
            tag,
            Some(interface),
            fragment,
        ));
        rules.push(json!({
            "type": "field",
            "inboundTag": [inbound_tag],
            "outboundTag": tag,
        }));
    }
    outbounds.extend(fragments);
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

fn fragment_tag(tag: &str) -> String {
    format!("{tag}-fragment")
}

/// The `freedom` outbound that splits what the proxy outbound writes to its server. It carries
/// the physical interface itself: Xray dials through it, so the proxy outbound's own
/// `sockopt` is not used and a missing one here sends the connection into the tunnel.
fn fragment_outbound_parts(
    outbound: &Outbound,
    stream: &StreamSettings,
    tag: &str,
    interface: Option<&str>,
    fragment: &TlsFragment,
) -> Option<Value> {
    fragment.applies_to_parts(outbound, stream).then(|| {
        let mut outbound = json!({
            "tag": fragment_tag(tag),
            "protocol": "freedom",
            "settings": {
                "fragment": {
                    "packets": packets(stream, fragment),
                    "length": fragment.length.to_string(),
                    "interval": fragment.interval.to_string(),
                },
            },

        });
        if let Some(interface) = interface {
            outbound["streamSettings"] = json!({ "sockopt": { "interface": interface } });
        }
        outbound
    })
}

/// The TLS hello mode cuts the hello into several TLS records. v2rayN treats that as
/// incompatible with REALITY and cuts the first three packets there instead; so does this.
fn packets(stream: &StreamSettings, fragment: &TlsFragment) -> String {
    match fragment.packets {
        FragmentPackets::TlsHello if matches!(stream.tls, TlsMode::Reality(_)) => "1-3".to_owned(),
        packets => packets.to_string(),
    }
}

fn proxy_outbound_parts(
    server: &str,
    port: u16,
    outbound: &Outbound,
    stream_settings: &StreamSettings,
    tag: &str,
    interface: Option<&str>,
    fragment: &TlsFragment,
) -> Result<Value, EngineError> {
    if server.parse::<std::net::IpAddr>().is_err() {
        return Err(EngineError::Render(
            "Xray server address must be an IP literal".into(),
        ));
    }
    let (protocol, settings) = match outbound {
        Outbound::Vless(params) => {
            let mut settings = json!({
                "address": server,
                "port": port,
                "id": params.uuid,
                "encryption": "none",
            });
            // Xray accepts Vision on XHTTP but then fails every TCP connection with
            // "XTLS only supports TLS and REALITY directly", and the server refuses
            // Vision on XHTTP the same way, so the flow is left out.
            if let Some(flow) = &params.flow
                && !matches!(stream_settings.transport, Transport::Xhttp { .. })
            {
                settings["flow"] = flow.clone().into();
            }
            ("vless", settings)
        }
        Outbound::Vmess(params) if params.alter_id == 0 => (
            "vmess",
            json!({
                "address": server,
                "port": port,
                "id": params.uuid,
                "security": params.security.as_deref().unwrap_or("auto"),
            }),
        ),
        Outbound::Trojan(params) => (
            "trojan",
            json!({
                "address": server,
                "port": port,
                "password": params.password,
            }),
        ),
        Outbound::Shadowsocks(params) => (
            "shadowsocks",
            json!({
                "address": server,
                "port": port,
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

    let mut stream = json!({ "network": "tcp" });
    if let Some(interface) = interface {
        stream["sockopt"] = json!({ "interface": interface });
    }
    if fragment.applies_to_parts(outbound, stream_settings) {
        stream["sockopt"]["dialerProxy"] = fragment_tag(tag).into();
    }
    match &stream_settings.transport {
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
    match &stream_settings.tls {
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
            if let Some(resumption) = params.enable_session_resumption {
                tls["enableSessionResumption"] = resumption.into();
            }
            stream["tlsSettings"] = tls;
        }
        TlsMode::Reality(params) => {
            if !matches!(
                stream_settings.transport,
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
    if let Some(finalmask) = &stream_settings.finalmask {
        finalmask
            .validate()
            .map_err(|message| EngineError::Render(message.into()))?;
        stream["finalmask"] = render_finalmask(finalmask);
    }

    Ok(json!({
        "tag": tag,
        "protocol": protocol,
        "settings": settings,
        "streamSettings": stream,
    }))
}

fn render_finalmask(finalmask: &FinalMask) -> Value {
    let tcp: Vec<Value> = finalmask
        .tcp
        .iter()
        .map(|mask| match mask {
            TcpFinalMask::HeaderCustom(custom) => json!({
                "type": "header-custom",
                "settings": render_header_custom_tcp(custom),
            }),
        })
        .collect();
    json!({ "tcp": tcp })
}

fn render_header_custom_tcp(custom: &HeaderCustomTcp) -> Value {
    let mut settings = serde_json::Map::new();
    if !custom.clients.is_empty() {
        settings.insert(
            "clients".into(),
            render_header_custom_steps(&custom.clients),
        );
    }
    if !custom.servers.is_empty() {
        settings.insert(
            "servers".into(),
            render_header_custom_steps(&custom.servers),
        );
    }
    if !custom.errors.is_empty() {
        settings.insert("errors".into(), render_header_custom_steps(&custom.errors));
    }
    Value::Object(settings)
}

fn render_header_custom_steps(steps: &[Vec<HeaderCustomItem>]) -> Value {
    Value::Array(
        steps
            .iter()
            .map(|step| {
                Value::Array(
                    step.iter()
                        .map(|item| {
                            let mut obj = serde_json::Map::new();
                            if let Some(delay) = item.delay {
                                obj.insert("delay".into(), delay.into());
                            }
                            if let Some(rand) = item.rand {
                                obj.insert("rand".into(), rand.into());
                            }
                            if let Some(range) = &item.rand_range {
                                obj.insert("randRange".into(), range.clone().into());
                            }
                            if let Some(packet_type) = item.packet_type {
                                obj.insert(
                                    "type".into(),
                                    match packet_type {
                                        HeaderCustomPacketType::Array => "array",
                                        HeaderCustomPacketType::Str => "str",
                                        HeaderCustomPacketType::Hex => "hex",
                                        HeaderCustomPacketType::Base64 => "base64",
                                    }
                                    .into(),
                                );
                            }
                            if let Some(packet) = &item.packet {
                                obj.insert(
                                    "packet".into(),
                                    match packet {
                                        HeaderCustomPacket::Bytes(bytes) => json!(bytes),
                                        HeaderCustomPacket::Text(text) => text.clone().into(),
                                    },
                                );
                            }
                            Value::Object(obj)
                        })
                        .collect(),
                )
            })
            .collect(),
    )
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
    put_range(
        &mut options,
        "scMaxEachPostBytes",
        extra.sc_max_each_post_bytes,
    );
    put_range(
        &mut options,
        "scMinPostsIntervalMs",
        extra.sc_min_posts_interval_ms,
    );
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
                finalmask: None,
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
            &TlsFragment::default(),
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
            &TlsFragment::default(),
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
        let value: Value = serde_json::from_slice(
            &render_probe(&nodes, "Ethernet", &TlsFragment::default())
                .unwrap()
                .body,
        )
        .unwrap();
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
            finalmask: None,
        };
        node
    }

    fn stream_of(node: &Node) -> Value {
        let socks = SocksEndpoint::local().unwrap();
        let rendered = render(
            &[("proxy", node, &socks)],
            "Ethernet",
            &TlsFragment::default(),
            false,
            LogLevel::Info,
        )
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
            enable_session_resumption: None,
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
        let rendered = render_probe(&nodes, "Ethernet", &TlsFragment::default()).unwrap();
        assert!(rendered.unsupported.is_empty());
        let value: Value = serde_json::from_slice(&rendered.body).unwrap();
        assert_eq!(value["outbounds"][0]["streamSettings"]["network"], "xhttp");
    }

    fn fragmented(node: &Node, fragment: &TlsFragment) -> Value {
        let socks = SocksEndpoint::local().unwrap();
        let rendered = render(
            &[("proxy", node, &socks)],
            "Ethernet",
            fragment,
            false,
            LogLevel::Info,
        )
        .unwrap();
        serde_json::from_slice(&rendered.body).unwrap()
    }

    fn on() -> TlsFragment {
        TlsFragment {
            enabled: true,
            ..TlsFragment::default()
        }
    }

    #[test]
    fn the_physical_interface_is_on_the_freedom_outbound_and_the_proxy_dials_through_it() {
        let value = fragmented(&reality_node(), &on());
        let outbounds = value["outbounds"].as_array().unwrap();
        assert_eq!(outbounds.len(), 2);
        assert_eq!(outbounds[0]["tag"], "proxy");
        assert_eq!(
            outbounds[0]["streamSettings"]["sockopt"]["dialerProxy"],
            "proxy-fragment"
        );
        assert_eq!(outbounds[1]["tag"], "proxy-fragment");
        assert_eq!(outbounds[1]["protocol"], "freedom");
        assert_eq!(
            outbounds[1]["streamSettings"]["sockopt"]["interface"],
            "Ethernet"
        );
        assert!(value.get("routing").is_none());
    }

    #[test]
    fn reality_cuts_packets_one_to_three_where_tls_cuts_the_hello() {
        let reality = fragmented(&reality_node(), &on());
        assert_eq!(
            reality["outbounds"][1]["settings"]["fragment"],
            json!({ "packets": "1-3", "length": "50-100", "interval": "10-20" })
        );
        let mut node = reality_node();
        node.stream.tls = TlsMode::Tls(TlsParams::default());
        let tls = fragmented(&node, &on());
        assert_eq!(
            tls["outbounds"][1]["settings"]["fragment"]["packets"],
            "tlshello"
        );
        let range = TlsFragment {
            packets: "5-8".parse().unwrap(),
            ..on()
        };
        let reality = fragmented(&reality_node(), &range);
        assert_eq!(
            reality["outbounds"][1]["settings"]["fragment"]["packets"],
            "5-8"
        );
    }

    #[test]
    fn nothing_is_added_when_fragmentation_is_off_or_does_not_apply() {
        let off = fragmented(&reality_node(), &TlsFragment::default());
        assert_eq!(off["outbounds"].as_array().unwrap().len(), 1);
        assert!(
            off["outbounds"][0]["streamSettings"]["sockopt"]
                .get("dialerProxy")
                .is_none()
        );
        let mut node = reality_node();
        node.stream.tls = TlsMode::Plain;
        let plain = fragmented(&node, &on());
        assert_eq!(plain["outbounds"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn extra_nodes_and_probes_get_their_own_freedom_outbound() {
        let main = SocksEndpoint::local().unwrap();
        let extra = SocksEndpoint::local().unwrap();
        let rendered = render(
            &[
                ("proxy", &reality_node(), &main),
                ("exit-1", &reality_node(), &extra),
            ],
            "Ethernet",
            &on(),
            false,
            LogLevel::Info,
        )
        .unwrap();
        let value: Value = serde_json::from_slice(&rendered.body).unwrap();
        let tags = value["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|outbound| outbound["tag"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            tags,
            ["proxy", "exit-1", "proxy-fragment", "exit-1-fragment"]
        );

        let nodes = [(
            "probe-0".to_owned(),
            reality_node(),
            SocksEndpoint::local().unwrap(),
        )];
        let probe: Value =
            serde_json::from_slice(&render_probe(&nodes, "Ethernet", &on()).unwrap().body).unwrap();
        assert_eq!(probe["outbounds"][1]["tag"], "probe-0-fragment");
        assert_eq!(
            probe["outbounds"][1]["streamSettings"]["sockopt"]["interface"],
            "Ethernet"
        );
    }

    #[test]
    fn tuic_and_anytls_are_refused_as_unsupported_by_xray() {
        let mut tuic = reality_node();
        tuic.outbound = Outbound::Tuic(rosetun_config::TuicParams {
            uuid: "00000000-0000-4000-8000-000000000001".into(),
            password: "test-secret".into(),
            congestion_control: None,
            udp_relay_mode: None,
            zero_rtt_handshake: false,
            heartbeat: None,
            disable_sni: false,
        });
        let mut anytls = reality_node();
        anytls.outbound = Outbound::AnyTls(rosetun_config::AnyTlsParams {
            password: "test-secret".into(),
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
        });
        let mut wireguard = reality_node();
        wireguard.outbound = Outbound::WireGuard(rosetun_config::WireGuardParams {
            private_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
            public_key: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".into(),
            pre_shared_key: None,
            address: vec!["10.0.0.2/32".into()],
            reserved: None,
            mtu: None,
            persistent_keepalive: None,
        });
        wireguard.stream = StreamSettings::default();
        for node in [&tuic, &anytls, &wireguard] {
            assert!(matches!(
                proxy_outbound_parts(
                    &node.server,
                    node.port,
                    &node.outbound,
                    &node.stream,
                    "proxy",
                    Some("Ethernet"),
                    &TlsFragment::default(),
                ),
                Err(EngineError::Unsupported(_))
            ));
        }
    }

    #[test]
    fn bsd_interface_names_bind_proxy_and_fragment_outbounds_for_session_and_probe() {
        let socks = SocksEndpoint::local().unwrap();

        let plain: Value = serde_json::from_slice(
            &render(
                &[("proxy", &reality_node(), &socks)],
                "en0",
                &TlsFragment::default(),
                false,
                LogLevel::Info,
            )
            .unwrap()
            .body,
        )
        .unwrap();
        assert_eq!(
            plain["outbounds"][0]["streamSettings"]["sockopt"]["interface"],
            "en0"
        );

        let fragmented: Value = serde_json::from_slice(
            &render(
                &[("proxy", &reality_node(), &socks)],
                "en5",
                &on(),
                false,
                LogLevel::Info,
            )
            .unwrap()
            .body,
        )
        .unwrap();
        assert_eq!(
            fragmented["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"],
            "proxy-fragment"
        );
        assert_eq!(
            fragmented["outbounds"][0]["streamSettings"]["sockopt"]["interface"],
            "en5"
        );
        assert_eq!(fragmented["outbounds"][1]["tag"], "proxy-fragment");
        assert_eq!(
            fragmented["outbounds"][1]["streamSettings"]["sockopt"]["interface"],
            "en5"
        );

        let probe_nodes = [(
            "probe-0".to_owned(),
            reality_node(),
            SocksEndpoint::local().unwrap(),
        )];
        let probe_plain: Value = serde_json::from_slice(
            &render_probe(&probe_nodes, "en0", &TlsFragment::default())
                .unwrap()
                .body,
        )
        .unwrap();
        assert_eq!(
            probe_plain["outbounds"][0]["streamSettings"]["sockopt"]["interface"],
            "en0"
        );

        let probe_fragmented: Value =
            serde_json::from_slice(&render_probe(&probe_nodes, "en5", &on()).unwrap().body)
                .unwrap();
        assert_eq!(probe_fragmented["outbounds"][1]["tag"], "probe-0-fragment");
        assert_eq!(
            probe_fragmented["outbounds"][1]["streamSettings"]["sockopt"]["interface"],
            "en5"
        );
    }

    fn balanced_node_with_mask(observatory: Option<rosetun_config::XrayObservatory>) -> Node {
        use rosetun_config::{
            BalancerMember, BalancerStrategy, FinalMask, HeaderCustomItem, HeaderCustomPacket,
            HeaderCustomPacketType, HeaderCustomTcp, LeastLoadSettings, TcpFinalMask, XrayBalancer,
        };
        let primary = BalancerMember {
            tag: "proxy".into(),
            server: "192.0.2.10".into(),
            port: 443,
            outbound: reality_node().outbound,
            stream: reality_node().stream,
        };
        let mask = BalancerMember {
            tag: "mask".into(),
            server: "192.0.2.11".into(),
            port: 443,
            outbound: reality_node().outbound,
            stream: StreamSettings {
                transport: Transport::Tcp,
                tls: TlsMode::Tls(TlsParams {
                    sni: Some("mask.example.com".into()),
                    alpn: vec!["http/1.1".into()],
                    allow_insecure: false,
                    fingerprint: Some("firefox".into()),
                    enable_session_resumption: Some(false),
                }),
                finalmask: Some(FinalMask {
                    tcp: vec![TcpFinalMask::HeaderCustom(HeaderCustomTcp {
                        clients: Vec::new(),
                        servers: vec![vec![HeaderCustomItem {
                            packet_type: Some(HeaderCustomPacketType::Str),
                            packet: Some(HeaderCustomPacket::Text(
                                "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20\r\n".into(),
                            )),
                            ..HeaderCustomItem::default()
                        }]],
                        errors: Vec::new(),
                    })],
                }),
            },
        };
        Node {
            id: NodeId::new("balanced"),
            name: "Balanced".into(),
            server: "192.0.2.10".into(),
            port: 443,
            outbound: Outbound::XrayBalancer(Box::new(XrayBalancer {
                members: vec![primary, mask],
                selector: vec!["proxy".into()],
                strategy: BalancerStrategy::LeastLoad(LeastLoadSettings {
                    max_rtt: Some("3000ms".into()),
                    tolerance_bp: Some(5000),
                    expected: None,
                    baselines: Vec::new(),
                }),
                fallback_tag: Some("mask".into()),
                observatory,
            })),
            stream: StreamSettings::default(),
            raw: None,
        }
    }

    #[test]
    fn balanced_node_renders_prefixed_members_balancer_burst_observatory_and_finalmask() {
        use rosetun_config::{BurstObservatory, XrayObservatory};
        let node = balanced_node_with_mask(Some(XrayObservatory::Burst(BurstObservatory {
            subject_selector: vec!["proxy".into()],
            destination: Some("https://connectivitycheck.gstatic.com/generate_204".into()),
            interval: Some("15s".into()),
            timeout: Some("5s".into()),
            sampling: Some(2),
            http_method: Some("GET".into()),
        })));
        let socks = SocksEndpoint::local().unwrap();
        let value: Value = serde_json::from_slice(
            &render(
                &[("proxy", &node, &socks)],
                "Ethernet",
                &on(),
                false,
                LogLevel::Info,
            )
            .unwrap()
            .body,
        )
        .unwrap();

        let outbounds = value["outbounds"].as_array().unwrap();
        let tags: Vec<_> = outbounds
            .iter()
            .map(|o| o["tag"].as_str().unwrap())
            .collect();
        // Fragmentation applies only to the non-finalmask primary member.
        assert_eq!(
            tags,
            ["proxy--proxy", "proxy--mask", "proxy--proxy-fragment"]
        );

        assert_eq!(
            outbounds[0]["streamSettings"]["sockopt"]["dialerProxy"],
            "proxy--proxy-fragment"
        );
        assert!(
            outbounds[1]["streamSettings"]["sockopt"]
                .get("dialerProxy")
                .is_none()
        );
        assert_eq!(
            outbounds[1]["streamSettings"]["tlsSettings"]["enableSessionResumption"],
            false
        );
        assert_eq!(
            outbounds[1]["streamSettings"]["finalmask"]["tcp"][0]["type"],
            "header-custom"
        );
        assert_eq!(
            outbounds[1]["streamSettings"]["finalmask"]["tcp"][0]["settings"]["servers"][0][0]["packet"],
            "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20\r\n"
        );

        assert_eq!(
            value["routing"]["rules"][0],
            json!({
                "type": "field",
                "inboundTag": ["proxy-in"],
                "balancerTag": "proxy-bal",
            })
        );
        assert_eq!(
            value["routing"]["balancers"][0],
            json!({
                "tag": "proxy-bal",
                "selector": ["proxy--proxy"],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "maxRTT": "3000ms",
                        "tolerance": 0.5,
                    },
                },
                "fallbackTag": "proxy--mask",
            })
        );
        assert_eq!(
            value["burstObservatory"]["subjectSelector"],
            json!(["proxy--proxy"])
        );
        assert!(
            value["burstObservatory"]["pingConfig"]
                .get("connectivity")
                .is_none()
        );
    }

    #[test]
    fn multiple_balanced_exits_merge_observatory_subjects_and_tags() {
        use rosetun_config::{BurstObservatory, XrayObservatory};
        let main = balanced_node_with_mask(Some(XrayObservatory::Burst(BurstObservatory {
            subject_selector: vec!["proxy".into()],
            destination: Some("https://connectivitycheck.gstatic.com/generate_204".into()),
            interval: Some("15s".into()),
            timeout: Some("5s".into()),
            sampling: Some(2),
            http_method: Some("GET".into()),
        })));
        let extra = balanced_node_with_mask(Some(XrayObservatory::Burst(BurstObservatory {
            subject_selector: vec!["proxy".into()],
            destination: Some("https://connectivitycheck.gstatic.com/generate_204".into()),
            interval: Some("30s".into()),
            timeout: Some("5s".into()),
            sampling: Some(2),
            http_method: Some("GET".into()),
        })));
        let main_socks = SocksEndpoint::local().unwrap();
        let extra_socks = SocksEndpoint::local().unwrap();
        let value: Value = serde_json::from_slice(
            &render(
                &[
                    ("proxy", &main, &main_socks),
                    ("exit-1", &extra, &extra_socks),
                ],
                "Ethernet",
                &TlsFragment::default(),
                false,
                LogLevel::Info,
            )
            .unwrap()
            .body,
        )
        .unwrap();

        assert_eq!(
            value["burstObservatory"]["subjectSelector"],
            json!(["proxy--proxy", "exit-1--proxy"])
        );
        assert_eq!(value["routing"]["balancers"].as_array().unwrap().len(), 2);
        assert_eq!(value["routing"]["balancers"][0]["tag"], "proxy-bal");
        assert_eq!(value["routing"]["balancers"][1]["tag"], "exit-1-bal");
    }
}
