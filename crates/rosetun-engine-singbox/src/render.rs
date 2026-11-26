use rosetun_config::{
    DnsSettings, DomainMatch, EXIT_TRACE_IP, EXIT_TRACE_PORT, ExitId, IpPrefix, LINK_LOCAL_V4,
    LINK_LOCAL_V6, ListRef, LogLevel, Node, Outbound, ProcessMatch, Rule, RuleId, RuleMatcher,
    RuleSet, RuleTarget, TlsMode, Transport, UploadedListFormat, list_tag,
};
use rosetun_engine::errors::EngineError;
use rosetun_engine::{
    DelayInbound, EngineRights, EngineRoute, ExtraOutbound, LocalProxyListen, PROXY_TAG,
    ProbeRenderRequest, RenderRequest, RenderedConfig, RuleCapabilities, SocksProxy, exit_tag,
};
use serde_json::{Map, Value, json};

pub(crate) const TAG_PROXY: &str = PROXY_TAG;
const TAG_DIRECT: &str = "direct";
const TAG_DNS_PROXY: &str = "dns-proxy";
const TAG_LOCAL_DNS: &str = "dns-in";
/// The inbound that times a repeated request; see [`delay_entry`].
pub(crate) const TAG_DELAY_INBOUND: &str = "delay-in";
const DEFAULT_FINGERPRINT: &str = "chrome";
/// The GUI's exit-country lookup is pinned to the main node by this program name.
#[cfg(windows)]
pub(crate) const GUI_PROCESS: &str = "rosetun-gui.exe";
#[cfg(not(windows))]
pub(crate) const GUI_PROCESS: &str = "rosetun-gui";

/// The route of a connection whose outbound chain ends with `tag`.
pub(crate) fn route_of(tag: &str) -> EngineRoute {
    match tag {
        TAG_PROXY => EngineRoute::Proxy,
        TAG_DIRECT => EngineRoute::Direct,
        _ => match tag.strip_prefix("exit-").map(str::parse::<usize>) {
            Some(Ok(index)) if exit_tag(index) == tag => EngineRoute::Exit(tag.to_owned()),
            _ => EngineRoute::Other,
        },
    }
}

/// The GUI's exit-country lookup, matched exactly as its route rule matches it.
pub(crate) fn is_exit_trace(process: Option<&str>, ip: &str, port: u16) -> bool {
    port == EXIT_TRACE_PORT
        && ip == EXIT_TRACE_IP
        && process
            .and_then(|path| path.rsplit(['\\', '/']).next())
            .is_some_and(|name| {
                if cfg!(windows) {
                    name.eq_ignore_ascii_case(GUI_PROCESS)
                } else {
                    name == GUI_PROCESS
                }
            })
}

/// Rules by program too: the helper refuses them where it cannot give the engine
/// the rights to read programs (`rosetun_engine::process::rights_unavailable`).
pub(crate) const RULE_CAPABILITIES: RuleCapabilities = RuleCapabilities {
    domain_exact: true,
    domain_suffix: true,
    domain_keyword: true,
    process_name: true,
    process_path: true,
    ip_cidr: true,
    lists: true,
    exits: true,
};

fn validate_exit_chains(request: &RenderRequest<'_>) -> Result<(), EngineError> {
    let mut indices = std::collections::HashSet::new();
    for extra in request.extra {
        if !indices.insert(extra.index) {
            return Err(EngineError::Unsupported("duplicate outbound index".into()));
        }
        if let Some(via) = extra.via {
            let parent = request
                .extra
                .iter()
                .find(|entry| entry.exit == via)
                .ok_or_else(|| EngineError::Unsupported("missing first hop".into()))?;
            if request.settings.engine != rosetun_config::EngineKind::SingBox
                || parent.exit == extra.exit
                || parent.via.is_some()
                || extra.socks.is_some()
                || request.settings.tls_fragment.enabled
                || rosetun_config::uses_xray(extra.node, request.settings)
                || extra.node.server.parse::<std::net::IpAddr>().is_err()
                || !matches!(extra.node.outbound, Outbound::Http(_) | Outbound::Socks5(_))
                || matches!(parent.node.outbound, Outbound::Unknown { .. })
            {
                return Err(EngineError::Unsupported("unsupported exit chain".into()));
            }
        }
    }
    Ok(())
}

pub fn render(request: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError> {
    validate_exit_chains(request)?;
    let lan = request.settings.allow_lan.then_some(request.lan_segment);
    let (mut route, unsupported) = route_section_with_lists(
        request.rules,
        RULE_CAPABILITIES,
        lan,
        PrivateNetworks {
            on: request.settings.private_networks,
            servers: request.lan_servers,
        },
        request.lists,
        request.extra,
        request.local_proxy.is_some(),
    );
    let mut outbounds = Vec::with_capacity(request.extra.len() + 2);
    let mut endpoints = Vec::new();
    match request.socks {
        Some(socks) => outbounds.push(socks_outbound(socks, TAG_PROXY)),
        None if matches!(request.node.outbound, Outbound::WireGuard(_)) => {
            endpoints.push(wireguard_endpoint(request.node, TAG_PROXY)?);
        }
        None => outbounds.push(proxy_outbound(request.node, TAG_PROXY)?),
    }
    for extra in request.extra {
        let tag = exit_tag(extra.index);
        if extra.socks.is_none() && matches!(extra.node.outbound, Outbound::WireGuard(_)) {
            // WireGuard endpoints are not cloned into a second `hop-{tag}` endpoint:
            // a WireGuard server peer only permits one active session per client
            // public key, so two endpoints sharing the same private_key would
            // continuously steal each other's session. Second hops detour directly
            // to `tag`.
            endpoints.push(wireguard_endpoint(extra.node, &tag)?);
            continue;
        }
        let mut outbound = match extra.socks {
            Some(socks) => socks_outbound(socks, &tag),
            None => proxy_outbound(extra.node, &tag)?,
        };
        if let Some(via) = extra.via {
            let parent = request
                .extra
                .iter()
                .find(|entry| entry.exit == via)
                .ok_or_else(|| EngineError::Unsupported("missing first hop".into()))?;
            let first = exit_tag(parent.index);
            let detour = if parent.socks.is_none()
                && matches!(parent.node.outbound, Outbound::WireGuard(_))
            {
                first
            } else {
                format!("hop-{first}")
            };
            outbound["detour"] = detour.into();
            if matches!(extra.node.outbound, Outbound::Socks5(_)) {
                outbound["network"] = "tcp".into();
            }
        }
        if request
            .extra
            .iter()
            .any(|entry| entry.via == Some(extra.exit))
        {
            let mut hop = outbound.clone();
            hop["tag"] = format!("hop-{tag}").into();
            outbounds.push(hop);
        }
        outbounds.push(outbound);
    }
    outbounds.push(json!({ "type": "direct", "tag": TAG_DIRECT }));
    let mut inbounds = request
        .local_proxy
        .map(local_proxy_inbounds)
        .unwrap_or_default();
    if let Some((inbound, rules)) = request
        .control
        .and_then(|control| control.delay.as_ref())
        .and_then(|delay| delay_entry(delay, request.extra))
    {
        inbounds.push(inbound);
        // First of all: nothing else may route what comes in here, and the
        // user's rules and the sniffer never see it.
        if let Some(route_rules) = route["rules"].as_array_mut() {
            route_rules.splice(0..0, rules);
        }
    }
    let mut config = json!({
        "log": log_section(request),
        "dns": dns_section(&request.settings.dns)?,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route,
    });
    if !endpoints.is_empty() {
        config["endpoints"] = Value::Array(endpoints);
    }
    if let Some(control) = request.control {
        config["experimental"] = json!({
            "clash_api": {
                "external_controller": control.address.to_string(),
                "secret": control.secret,
            },
        });
    }

    let body = serde_json::to_vec_pretty(&config)
        .map_err(|error| EngineError::Render(error.to_string()))?;
    Ok(RenderedConfig {
        file_name: "config.json".to_owned(),
        body,
        unsupported,
        unsupported_probes: Vec::new(),
    })
}

/// The loopback SOCKS entry that times a repeated request, and its route
/// rules. Each account reaches its own outbound over TCP; anything else that
/// comes in (UDP, an account of no outbound) is refused. An account whose
/// outbound this config does not define is left out.
fn delay_entry(delay: &DelayInbound, extra: &[ExtraOutbound<'_>]) -> Option<(Value, Vec<Value>)> {
    let defined = |tag: &str| {
        tag == TAG_PROXY
            || tag == rosetun_engine::SUBSCRIPTION_PROXY_USER
            || extra.iter().any(|node| exit_tag(node.index) == tag)
    };
    let accounts: Vec<_> = delay
        .accounts
        .iter()
        .filter(|account| defined(&account.tag))
        .collect();
    if accounts.is_empty() {
        return None;
    }
    let inbound = json!({
        "type": "socks",
        "tag": TAG_DELAY_INBOUND,
        "listen": delay.address.ip().to_string(),
        "listen_port": delay.address.port(),
        "users": accounts
            .iter()
            .map(|account| json!({ "username": account.tag, "password": account.password }))
            .collect::<Vec<_>>(),
    });
    let mut rules: Vec<Value> = accounts
        .iter()
        .map(|account| {
            json!({
                "inbound": [TAG_DELAY_INBOUND],
                "auth_user": [account.tag],
                "network": "tcp",
                "action": "route",
                "outbound": if account.tag == rosetun_engine::SUBSCRIPTION_PROXY_USER {
                    TAG_PROXY
                } else {
                    &account.tag
                },
            })
        })
        .collect();
    rules.push(json!({
        "inbound": [TAG_DELAY_INBOUND],
        "action": "reject",
    }));
    Some((inbound, rules))
}

pub fn render_outbound_worker(
    main: Option<&Node>,
    extra: &[ExtraOutbound<'_>],
    listeners: &[(&str, SocksProxy<'_>)],
    verbose: bool,
    log_level: LogLevel,
) -> Result<RenderedConfig, EngineError> {
    let mut inbounds = Vec::new();
    let mut outbounds = Vec::new();
    let mut endpoints = Vec::new();
    let mut rules = Vec::new();
    for (tag, socks) in listeners {
        let inbound = format!("{tag}-in");
        inbounds.push(json!({
            "type": "socks",
            "tag": inbound,
            "listen": socks.address.ip().to_string(),
            "listen_port": socks.address.port(),
            "users": [{ "username": socks.username, "password": socks.password }],
        }));
        rules.push(json!({
            "inbound": [inbound],
            "auth_user": [socks.username],
            "action": "route",
            "outbound": tag,
        }));
    }
    if let Some(node) = main {
        if matches!(node.outbound, Outbound::WireGuard(_)) {
            endpoints.push(wireguard_endpoint(node, TAG_PROXY)?);
        } else {
            outbounds.push(proxy_outbound(node, TAG_PROXY)?);
        }
    }
    for entry in extra {
        let tag = exit_tag(entry.index);
        if entry.socks.is_none() && matches!(entry.node.outbound, Outbound::WireGuard(_)) {
            endpoints.push(wireguard_endpoint(entry.node, &tag)?);
            continue;
        }
        let mut outbound = match entry.socks {
            Some(socks) => socks_outbound(socks, &tag),
            None => proxy_outbound(entry.node, &tag)?,
        };
        if let Some(via) = entry.via {
            let parent = extra
                .iter()
                .find(|entry| entry.exit == via)
                .ok_or_else(|| EngineError::Unsupported("missing first hop".into()))?;
            let tag = exit_tag(parent.index);
            let detour = if parent.socks.is_none()
                && matches!(parent.node.outbound, Outbound::WireGuard(_))
            {
                tag
            } else {
                format!("hop-{tag}")
            };
            outbound["detour"] = detour.into();
            if matches!(entry.node.outbound, Outbound::Socks5(_)) {
                outbound["network"] = "tcp".into();
            }
        }
        if extra.iter().any(|child| child.via == Some(entry.exit)) {
            let mut hop = outbound.clone();
            hop["tag"] = format!("hop-{tag}").into();
            outbounds.push(hop);
        }
        outbounds.push(outbound);
    }
    rules.push(json!({ "action": "reject" }));
    let config = json!({
        "log": engine_log(verbose, log_level),
        "inbounds": inbounds,
        "outbounds": outbounds,
        "endpoints": endpoints,
        "route": { "rules": rules },
    });
    Ok(RenderedConfig {
        file_name: "worker.json".to_owned(),
        body: serde_json::to_vec_pretty(&config)
            .map_err(|error| EngineError::Render(error.to_string()))?,
        unsupported: Vec::new(),
        unsupported_probes: Vec::new(),
    })
}

pub(crate) fn render_probe(
    request: &ProbeRenderRequest<'_>,
) -> Result<RenderedConfig, EngineError> {
    let mut outbounds = Vec::with_capacity(request.nodes.len() + 1);
    let mut endpoints = Vec::new();
    let mut unsupported_probes = Vec::new();
    for (tag, node) in request.nodes {
        let socks = request.socks.iter().find(|(name, _)| name == tag);
        match socks {
            Some((_, endpoint)) => outbounds.push(socks_outbound(*endpoint, tag)),
            None if matches!(node.outbound, Outbound::WireGuard(_)) => {
                match wireguard_endpoint(node, tag) {
                    Ok(endpoint) => endpoints.push(endpoint),
                    Err(EngineError::Unsupported(_)) => unsupported_probes.push(tag.clone()),
                    Err(error) => return Err(error),
                }
            }
            None => match proxy_outbound(node, tag) {
                Ok(outbound) => outbounds.push(outbound),
                Err(EngineError::Unsupported(_)) => unsupported_probes.push(tag.clone()),
                Err(error) => return Err(error),
            },
        }
    }
    outbounds.push(json!({ "type": "direct", "tag": TAG_DIRECT }));

    let route = match request.interface {
        Some(interface) => json!({ "final": TAG_DIRECT, "default_interface": interface }),
        None => json!({ "final": TAG_DIRECT, "auto_detect_interface": true }),
    };
    let mut config = json!({
        "log": { "level": "info", "timestamp": true },
        "outbounds": outbounds,
        "route": route,
        "experimental": { "clash_api": {
            "external_controller": request.control.address.to_string(),
            "secret": request.control.secret,
        } },
    });
    if !endpoints.is_empty() {
        config["endpoints"] = Value::Array(endpoints);
    }
    let body = serde_json::to_vec_pretty(&config)
        .map_err(|error| EngineError::Render(error.to_string()))?;
    Ok(RenderedConfig {
        file_name: "probe.json".to_owned(),
        body,
        unsupported: Vec::new(),
        unsupported_probes,
    })
}

fn dns_section(settings: &DnsSettings) -> Result<Value, EngineError> {
    if settings.server_name.is_empty() || settings.server_name.chars().any(char::is_whitespace) {
        return Err(EngineError::Render(
            "DNS server_name must be non-empty and contain no whitespace".to_owned(),
        ));
    }
    if let Some(path) = &settings.path
        && !path.starts_with('/')
    {
        return Err(EngineError::Render(
            "DNS path must start with '/'".to_owned(),
        ));
    }
    if settings.port == Some(0) {
        return Err(EngineError::Render(
            "DNS port must be greater than zero".to_owned(),
        ));
    }

    let mut server = json!({
        "type": "https",
        "tag": TAG_DNS_PROXY,
        "server": settings.server.to_string(),
        "tls": { "server_name": settings.server_name },
        "detour": TAG_PROXY,
    });
    if let Some(port) = settings.port {
        server["server_port"] = port.into();
    }
    if let Some(path) = &settings.path {
        server["path"] = path.clone().into();
    }

    Ok(json!({ "servers": [server] }))
}

fn log_section(request: &RenderRequest<'_>) -> Value {
    engine_log(request.verbose_log, request.settings.log_level)
}

fn engine_log(verbose: bool, log_level: LogLevel) -> Value {
    // Startup readiness needs the INFO message, so the engine must not go below INFO.
    let level = match (verbose, log_level) {
        (false, _) => "info",
        (true, LogLevel::Trace) => "trace",
        (true, _) => "debug",
    };
    json!({ "level": level, "timestamp": true })
}

fn local_proxy_inbounds(listen: &LocalProxyListen) -> Vec<Value> {
    let mut inbounds: Vec<Value> = listen
        .addresses
        .iter()
        .enumerate()
        .map(|(index, address)| {
            let tag = match index {
                0 => "mixed-in".to_owned(),
                _ => format!("mixed-in-{index}"),
            };
            json!({
                "type": "mixed",
                "tag": tag,
                "listen": address.ip().to_string(),
                "listen_port": address.port(),
            })
        })
        .collect();
    inbounds.push(json!({
        "type": "direct",
        "tag": TAG_LOCAL_DNS,
        "network": "udp",
        "listen": listen.dns.ip().to_string(),
        "listen_port": listen.dns.port(),
    }));
    inbounds
}

fn socks_outbound(socks: SocksProxy<'_>, tag: &str) -> Value {
    json!({
        "type": "socks",
        "tag": tag,
        "version": "5",
        "server": "127.0.0.1",
        "server_port": socks.address.port(),
        "username": socks.username,
        "password": socks.password,
        // In 1.14.3 this disables auto_detect_interface for this outbound:
        // the local connection must not bind to the physical adapter.
        "inet4_bind_address": "127.0.0.1",
    })
}

fn proxy_outbound(node: &Node, tag: &str) -> Result<Value, EngineError> {
    node.validate_proxy()
        .map_err(|message| EngineError::Unsupported(message.into()))?;
    if node.stream.finalmask.is_some() {
        return Err(EngineError::Unsupported(
            "finalmask is only supported by the Xray backend".into(),
        ));
    }
    let mut outbound = Map::new();
    outbound.insert("tag".into(), tag.into());
    outbound.insert("server".into(), node.server.clone().into());
    outbound.insert("server_port".into(), node.port.into());

    match &node.outbound {
        Outbound::Http(credentials) | Outbound::Socks5(credentials) => {
            let socks = matches!(node.outbound, Outbound::Socks5(_));
            outbound.insert("type".into(), if socks { "socks" } else { "http" }.into());
            if socks {
                outbound.insert("version".into(), "5".into());
            }
            if !credentials.username.is_empty() {
                outbound.insert("username".into(), credentials.username.clone().into());
                outbound.insert("password".into(), credentials.password.clone().into());
            }
        }
        Outbound::Vless(params) => {
            outbound.insert("type".into(), "vless".into());
            outbound.insert("uuid".into(), params.uuid.clone().into());
            if let Some(flow) = &params.flow {
                outbound.insert("flow".into(), flow.clone().into());
            }
        }
        Outbound::Vmess(params) => {
            outbound.insert("type".into(), "vmess".into());
            outbound.insert("uuid".into(), params.uuid.clone().into());
            outbound.insert("alter_id".into(), params.alter_id.into());
            if let Some(security) = &params.security {
                outbound.insert("security".into(), security.clone().into());
            }
        }
        Outbound::Trojan(params) => {
            outbound.insert("type".into(), "trojan".into());
            outbound.insert("password".into(), params.password.clone().into());
        }
        Outbound::Shadowsocks(params) => {
            outbound.insert("type".into(), "shadowsocks".into());
            outbound.insert("method".into(), params.method.clone().into());
            outbound.insert("password".into(), params.password.clone().into());
        }
        Outbound::Hysteria2(params) => {
            if !matches!(node.stream.tls, TlsMode::Tls(_))
                || node.stream.transport != Transport::Tcp
            {
                return Err(EngineError::Unsupported(
                    "Hysteria2 requires TLS and its built-in QUIC transport".into(),
                ));
            }
            outbound.insert("type".into(), "hysteria2".into());
            outbound.insert("password".into(), params.password.clone().into());
            if let Some(password) = &params.obfs_password {
                outbound.insert(
                    "obfs".into(),
                    json!({ "type": "salamander", "password": password }),
                );
            }
            if !params.port_ranges.is_empty() {
                let first_port = params.port_ranges[0]
                    .split_once(['-', ':'])
                    .map_or(params.port_ranges[0].as_str(), |(start, _)| start);
                let mut ports = Vec::new();
                // server_port is ignored when server_ports is set, and every entry must be a range.
                if first_port.parse::<u16>().ok() != Some(node.port) {
                    ports.push(format!("{}:{}", node.port, node.port));
                }
                ports.extend(params.port_ranges.iter().map(|range| {
                    range.split_once(['-', ':']).map_or_else(
                        || format!("{range}:{range}"),
                        |(start, end)| format!("{start}:{end}"),
                    )
                }));
                outbound.insert("server_ports".into(), ports.into());
            }
            if let Some(up) = params.up_mbps {
                outbound.insert("up_mbps".into(), up.into());
            }
            if let Some(down) = params.down_mbps {
                outbound.insert("down_mbps".into(), down.into());
            }
        }
        Outbound::Tuic(params) => {
            if !matches!(node.stream.tls, TlsMode::Tls(_))
                || node.stream.transport != Transport::Tcp
            {
                return Err(EngineError::Unsupported(
                    "TUIC requires TLS and its built-in QUIC transport".into(),
                ));
            }
            outbound.insert("type".into(), "tuic".into());
            outbound.insert("uuid".into(), params.uuid.clone().into());
            if !params.password.is_empty() {
                outbound.insert("password".into(), params.password.clone().into());
            }
            if let Some(congestion_control) = params.congestion_control {
                outbound.insert(
                    "congestion_control".into(),
                    congestion_control.as_str().into(),
                );
            }
            if let Some(udp_relay_mode) = params.udp_relay_mode {
                outbound.insert("udp_relay_mode".into(), udp_relay_mode.as_str().into());
            }
            if params.zero_rtt_handshake {
                outbound.insert("zero_rtt_handshake".into(), true.into());
            }
            if let Some(heartbeat) = &params.heartbeat {
                outbound.insert("heartbeat".into(), heartbeat.clone().into());
            }
        }
        Outbound::AnyTls(params) => {
            if matches!(node.stream.tls, TlsMode::Plain) || node.stream.transport != Transport::Tcp
            {
                return Err(EngineError::Unsupported(
                    "AnyTLS requires TLS or REALITY over TCP".into(),
                ));
            }
            outbound.insert("type".into(), "anytls".into());
            outbound.insert("password".into(), params.password.clone().into());
            if let Some(interval) = &params.idle_session_check_interval {
                outbound.insert(
                    "idle_session_check_interval".into(),
                    interval.clone().into(),
                );
            }
            if let Some(timeout) = &params.idle_session_timeout {
                outbound.insert("idle_session_timeout".into(), timeout.clone().into());
            }
            if let Some(min_idle) = params.min_idle_session {
                outbound.insert("min_idle_session".into(), min_idle.into());
            }
        }
        Outbound::WireGuard(_) => {
            return Err(EngineError::Unsupported(
                "WireGuard must be rendered as a sing-box endpoint".into(),
            ));
        }
        Outbound::XrayBalancer(_) => {
            return Err(EngineError::Unsupported(
                "Xray balancer nodes require the Xray backend".into(),
            ));
        }
        Outbound::Unknown { scheme, .. } => {
            return Err(EngineError::Unsupported(format!(
                "protocol {scheme} not supported by the sing box backend"
            )));
        }
    }

    if let Some(mut tls) = tls_section(
        &node.stream.tls,
        !matches!(
            &node.outbound,
            Outbound::Hysteria2(_) | Outbound::Tuic(_) | Outbound::Http(_)
        ),
    ) {
        if matches!(&node.outbound, Outbound::Tuic(params) if params.disable_sni)
            && let Some(object) = tls.as_object_mut()
        {
            object.insert("disable_sni".into(), true.into());
        }
        outbound.insert("tls".into(), tls);
    }
    if let Some(transport) = transport_section(&node.stream.transport)? {
        outbound.insert("transport".into(), transport);
    }

    Ok(Value::Object(outbound))
}

fn wireguard_endpoint(node: &Node, tag: &str) -> Result<Value, EngineError> {
    node.validate_proxy()
        .map_err(|message| EngineError::Unsupported(message.into()))?;
    let Outbound::WireGuard(params) = &node.outbound else {
        return Err(EngineError::Unsupported(
            "expected a WireGuard node for endpoint rendering".into(),
        ));
    };
    let mut peer = Map::new();
    peer.insert("address".into(), node.server.clone().into());
    peer.insert("port".into(), node.port.into());
    peer.insert("public_key".into(), params.public_key.clone().into());
    if let Some(psk) = &params.pre_shared_key {
        peer.insert("pre_shared_key".into(), psk.clone().into());
    }
    peer.insert("allowed_ips".into(), json!(["0.0.0.0/0", "::/0"]));
    if let Some(keepalive) = params.persistent_keepalive {
        peer.insert("persistent_keepalive_interval".into(), keepalive.into());
    }
    if let Some(reserved) = params.reserved {
        peer.insert("reserved".into(), json!(reserved));
    }

    let mut endpoint = Map::new();
    endpoint.insert("type".into(), "wireguard".into());
    endpoint.insert("tag".into(), tag.into());
    endpoint.insert("address".into(), json!(params.address));
    endpoint.insert("private_key".into(), params.private_key.clone().into());
    if let Some(mtu) = params.mtu {
        endpoint.insert("mtu".into(), mtu.into());
    }
    endpoint.insert("peers".into(), json!([Value::Object(peer)]));
    Ok(Value::Object(endpoint))
}

fn tls_section(mode: &TlsMode, use_utls: bool) -> Option<Value> {
    match mode {
        TlsMode::Plain => None,
        TlsMode::Tls(params) => {
            let mut tls = Map::new();
            tls.insert("enabled".into(), true.into());
            if let Some(sni) = &params.sni {
                tls.insert("server_name".into(), sni.clone().into());
            }
            if !params.alpn.is_empty() {
                tls.insert("alpn".into(), params.alpn.clone().into());
            }
            if params.allow_insecure {
                tls.insert("insecure".into(), true.into());
            }
            if use_utls {
                let fingerprint = params.fingerprint.as_deref().unwrap_or(DEFAULT_FINGERPRINT);
                tls.insert(
                    "utls".into(),
                    json!({ "enabled": true, "fingerprint": fingerprint }),
                );
            }
            Some(Value::Object(tls))
        }
        TlsMode::Reality(params) => {
            let mut reality = Map::new();
            reality.insert("enabled".into(), true.into());
            reality.insert("public_key".into(), params.public_key.clone().into());
            if let Some(short_id) = &params.short_id {
                reality.insert("short_id".into(), short_id.clone().into());
            }

            let mut tls = Map::new();
            tls.insert("enabled".into(), true.into());
            if let Some(sni) = &params.sni {
                tls.insert("server_name".into(), sni.clone().into());
            }
            tls.insert("reality".into(), Value::Object(reality));
            let fingerprint = params.fingerprint.as_deref().unwrap_or(DEFAULT_FINGERPRINT);
            tls.insert(
                "utls".into(),
                json!({ "enabled": true, "fingerprint": fingerprint }),
            );
            Some(Value::Object(tls))
        }
    }
}

fn transport_section(transport: &Transport) -> Result<Option<Value>, EngineError> {
    Ok(match transport {
        Transport::Tcp => None,
        Transport::Ws { path, host } => {
            let mut value = json!({ "type": "ws", "path": path });
            if let Some(host) = host {
                value["headers"] = json!({ "Host": host });
            }
            Some(value)
        }
        Transport::Grpc { service_name } => {
            Some(json!({ "type": "grpc", "service_name": service_name }))
        }
        Transport::HttpUpgrade { path, host } => {
            let mut value = json!({ "type": "httpupgrade", "path": path });
            if let Some(host) = host {
                value["host"] = host.clone().into();
            }
            Some(value)
        }
        Transport::Xhttp { .. } => {
            return Err(EngineError::Unsupported(
                "XHTTP is not supported by the sing box backend".into(),
            ));
        }
    })
}

#[cfg(test)]
pub(crate) fn route_section(
    rules: &RuleSet,
    capabilities: RuleCapabilities,
    allow_lan: bool,
) -> (Value, Vec<RuleId>) {
    route_section_with_lists(
        rules,
        capabilities,
        allow_lan.then_some(&[]),
        PrivateNetworks {
            on: allow_lan,
            servers: &[],
        },
        &[],
        &[],
        false,
    )
}

/// "Private networks behind the router", and the VPN servers it leaves out.
#[derive(Clone, Copy)]
struct PrivateNetworks<'a> {
    on: bool,
    servers: &'a [std::net::IpAddr],
}

/// `lan` is the connected networks when "Local network" is on;
/// `private` adds every private range after the user's rules.
fn route_section_with_lists(
    rules: &RuleSet,
    capabilities: RuleCapabilities,
    lan: Option<&[IpPrefix]>,
    private: PrivateNetworks<'_>,
    lists: &[ListRef],
    extra: &[ExtraOutbound<'_>],
    local_proxy: bool,
) -> (Value, Vec<RuleId>) {
    let mut route_rules = vec![
        json!({
            "action": "sniff",
            "sniffer": ["http", "tls", "quic", "dns"],
        }),
        json!({
            "protocol": "dns",
            "action": "hijack-dns",
        }),
    ];
    route_rules.extend(exit_trace_rule(rules));
    if local_proxy {
        route_rules.insert(
            2,
            json!({
                "inbound": [TAG_LOCAL_DNS],
                "action": "hijack-dns",
            }),
        );
    }
    // Before the user's rules: a rule that sends a site or a program through
    // the VPN must not take the devices next to this computer with it.
    if let Some(segment) = lan {
        let mut networks: Vec<String> = segment.iter().map(ToString::to_string).collect();
        networks.extend(
            LINK_LOCAL_V4
                .iter()
                .chain(&LINK_LOCAL_V6)
                .map(ToString::to_string),
        );
        route_rules.push(json!({
            "ip_cidr": networks,
            "action": "route",
            "outbound": TAG_DIRECT,
        }));
    }
    let mut unsupported = Vec::new();
    let mut used_lists = Vec::<&ListRef>::new();
    // Through a proxy a program often names a site instead of its address, and
    // an address rule matches a name only once it is resolved. Only from the
    // first rule that needs it: otherwise the server resolves names itself.
    let mut unresolved = local_proxy;

    for rule in rules.enabled() {
        if !capabilities.supports(&rule.matcher) || !capabilities.supports_target(rule.target) {
            unsupported.push(rule.id.clone());
            continue;
        }
        if unresolved
            && matches!(
                rule.matcher,
                RuleMatcher::IpCidr(_) | RuleMatcher::List { .. }
            )
        {
            route_rules.push(json!({ "action": "resolve" }));
            unresolved = false;
        }
        let Some(action) = route_action(rule, extra) else {
            unsupported.push(rule.id.clone());
            continue;
        };
        let value = match &rule.matcher {
            RuleMatcher::List { list, category } => {
                let tag = list_tag(list, category.as_deref());
                let mut matching = lists.iter().filter(|reference| reference.tag == tag);
                match (matching.next(), matching.next()) {
                    (Some(reference), None) => {
                        if !used_lists.iter().any(|used| used.tag == tag) {
                            used_lists.push(reference);
                        }
                        let mut value = Map::new();
                        value.insert("rule_set".into(), json!([tag]));
                        Some(value)
                    }
                    _ => None,
                }
            }
            _ => route_rule(rule),
        };
        if let Some(mut value) = value {
            if rule.target == RuleTarget::Exit
                && extra
                    .iter()
                    .any(|node| Some(node.exit) == rule.exit.as_ref() && node.via.is_some())
            {
                let mut blocked = value.clone();
                blocked.insert("network".into(), "udp".into());
                blocked.insert("action".into(), "reject".into());
                route_rules.push(Value::Object(blocked));
            }
            value.extend(action);
            route_rules.push(Value::Object(value));
        } else {
            unsupported.push(rule.id.clone());
        }
    }

    // After the user's rules: a rule that sends one of these networks
    // through the VPN (an office network on the server's side) still wins.
    if lan.is_some() && private.on {
        route_rules.push(if private.servers.is_empty() {
            json!({
                "ip_is_private": true,
                "action": "route",
                "outbound": TAG_DIRECT,
            })
        } else {
            // In one plain rule sing-box joins these two with OR. Past this
            // rule a server's address goes on to the default route, as any
            // address outside does.
            let servers: Vec<String> = private
                .servers
                .iter()
                .map(|server| match server {
                    std::net::IpAddr::V4(_) => format!("{server}/32"),
                    std::net::IpAddr::V6(_) => format!("{server}/128"),
                })
                .collect();
            json!({
                "type": "logical",
                "mode": "and",
                "rules": [
                    { "ip_is_private": true },
                    { "ip_cidr": servers, "invert": true },
                ],
                "action": "route",
                "outbound": TAG_DIRECT,
            })
        });
    }

    let final_outbound = match rules.default_target {
        RuleTarget::Proxy => TAG_PROXY,
        RuleTarget::Direct => TAG_DIRECT,
        RuleTarget::Block | RuleTarget::Exit => {
            route_rules.push(json!({ "action": "reject" }));
            TAG_DIRECT
        }
    };

    let mut route = json!({
        "rules": route_rules,
        "final": final_outbound,
        "auto_detect_interface": true,
    });
    if !used_lists.is_empty() {
        route["rule_set"] = Value::Array(
            used_lists
                .into_iter()
                .map(|reference| {
                    json!({
                        "type": "local",
                        "tag": reference.tag,
                        "format": match reference.format {
                            UploadedListFormat::Binary => "binary",
                            UploadedListFormat::Source => "source",
                        },
                        "path": format!("{}.{}", reference.tag, reference.format.extension()),
                    })
                })
                .collect(),
        );
    }
    (route, unsupported)
}

/// The rule's condition; the caller appends its [`route_action`].
fn route_rule(rule: &Rule) -> Option<Map<String, Value>> {
    let mut value = Map::new();
    match &rule.matcher {
        RuleMatcher::Domain(DomainMatch::Exact(domain)) => {
            value.insert("domain".into(), json!([domain]));
        }
        RuleMatcher::Domain(DomainMatch::Suffix(domain)) => {
            value.insert("domain_suffix".into(), json!([domain]));
        }
        RuleMatcher::Domain(DomainMatch::Keyword(keyword)) => {
            value.insert("domain_keyword".into(), json!([keyword]));
        }
        RuleMatcher::Process(ProcessMatch::Name(name)) => {
            value.insert(
                "process_path_regex".into(),
                json!([process_name_regex(name)]),
            );
        }
        RuleMatcher::Process(ProcessMatch::Path(path)) => {
            value.insert("process_path".into(), json!([path.to_string_lossy()]));
        }
        RuleMatcher::IpCidr(cidr) => {
            value.insert("ip_cidr".into(), json!([cidr]));
        }
        RuleMatcher::List { .. } | RuleMatcher::Group { .. } => return None,
    }

    Some(value)
}

/// A name matched against the whole path: Windows ignores letter case, Linux and macOS do not.
/// The GUI's look at its exit goes through the tunnel whatever the rules say. It
/// has to name the GUI: by address alone it would override the user's rules for
/// anyone's traffic to that address, a Block included. Linux reads other accounts'
/// programs only for a session with rules by program, so without them there is no
/// such rule, and the lookup goes as the rules send it.
fn exit_trace_rule(rules: &RuleSet) -> Option<Value> {
    (cfg!(any(windows, target_os = "macos"))
        || EngineRights::for_rules(rules) == EngineRights::NetworkAndProcesses)
        .then(|| {
            json!({
                "ip_cidr": [format!("{EXIT_TRACE_IP}/32")],
                "port": [EXIT_TRACE_PORT],
                "process_path_regex": [process_name_regex(GUI_PROCESS)],
                "action": "route",
                "outbound": TAG_PROXY,
            })
        })
}

pub(crate) fn process_name_regex(name: &str) -> String {
    let flags = if cfg!(windows) { "(?i)" } else { "" };
    format!(r"{flags}(?:^|[\\/]){}$", quote_process_name(name))
}

fn quote_process_name(name: &str) -> String {
    let mut quoted = String::with_capacity(name.len());
    for character in name.chars() {
        if "\\.+*?()|[]{}^$".contains(character) {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted
}

/// `None` for an `Exit` rule whose exit has no extra node in the request.
fn route_action(rule: &Rule, extra: &[ExtraOutbound<'_>]) -> Option<Map<String, Value>> {
    let outbound = match rule.target {
        RuleTarget::Proxy => TAG_PROXY.to_owned(),
        RuleTarget::Direct => TAG_DIRECT.to_owned(),
        RuleTarget::Block => {
            let mut action = Map::new();
            action.insert("action".into(), "reject".into());
            return Some(action);
        }
        RuleTarget::Exit => exit_outbound(rule.exit.as_ref()?, extra)?,
    };
    let mut action = Map::new();
    action.insert("action".into(), "route".into());
    action.insert("outbound".into(), outbound.into());
    Some(action)
}

fn exit_outbound(exit: &ExitId, extra: &[ExtraOutbound<'_>]) -> Option<String> {
    extra
        .iter()
        .find(|node| node.exit == exit)
        .map(|node| exit_tag(node.index))
}

#[cfg(test)]
mod tests {
    use rosetun_config::Settings;
    use rosetun_config::{
        AnyTlsParams, ExitId, Hysteria2Params, ListId, NodeId, RealityParams, Rule, RuleSetId,
        RuleTemplate, StreamSettings, TlsParams, TuicCongestionControl, TuicParams,
        TuicUdpRelayMode,
    };

    #[test]
    fn native_http_and_https_chain_keep_tls_identity_and_verify_certificates() {
        let main = shadowsocks_node("main", "203.0.113.1");
        let a = ExitId::new("a");
        let b = ExitId::new("b");
        for secure in [false, true] {
            let mut last = shadowsocks_node("b", "2001:db8::2");
            last.outbound = Outbound::Http(Default::default());
            if secure {
                last.stream.tls = TlsMode::Tls(TlsParams {
                    sni: Some("b.example.com".into()),
                    ..Default::default()
                });
            }
            let extra = [
                ExtraOutbound {
                    index: 0,
                    via: None,
                    exit: &a,
                    node: &main,
                    socks: None,
                },
                ExtraOutbound {
                    index: 1,
                    via: Some(&a),
                    exit: &b,
                    node: &last,
                    socks: None,
                },
            ];
            let settings = Settings::default();
            let rules = RuleSet::new(RuleSetId::new("test"), "Test", RuleTarget::Proxy);
            let request = RenderRequest {
                node: &main,
                socks: None,
                extra: &extra,
                rules: &rules,
                lists: &[],
                settings: &settings,
                lan_segment: &[],
                lan_servers: &[],
                control: None,
                verbose_log: false,
                local_proxy: None,
            };
            let value: Value = serde_json::from_slice(&render(&request).unwrap().body).unwrap();
            let last = value["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|node| node["tag"] == "exit-1")
                .unwrap();
            assert_eq!(last["detour"], "hop-exit-0");
            assert_eq!(last["server"], "2001:db8::2");
            if secure {
                assert_eq!(last["tls"]["server_name"], "b.example.com");
                assert_ne!(last["tls"]["insecure"], true);
            } else {
                assert!(last["tls"].is_null());
            }
        }
    }

    #[test]
    fn native_chain_routes_to_b_and_blocks_udp_without_fallback() {
        let main = shadowsocks_node("main", "203.0.113.1");
        let first = shadowsocks_node("first", "192.0.2.1");
        let mut last = shadowsocks_node("last", "198.51.100.2");
        last.outbound = Outbound::Socks5(Default::default());
        let a = ExitId::new("a");
        let b = ExitId::new("b");
        let extra = [
            ExtraOutbound {
                index: 2,
                via: Some(&a),
                exit: &b,
                node: &last,
                socks: None,
            },
            ExtraOutbound {
                index: 5,
                via: None,
                exit: &a,
                node: &first,
                socks: None,
            },
        ];
        let mut rules = RuleSet::new(RuleSetId::new("chain"), "Chain", RuleTarget::Direct);
        rules.rules.push(exit_rule(
            "b",
            RuleMatcher::Domain(DomainMatch::Suffix("example.com".into())),
            "b",
        ));
        let settings = Settings::default();
        let request = RenderRequest {
            node: &main,
            socks: None,
            extra: &extra,
            rules: &rules,
            lists: &[],
            settings: &settings,
            lan_segment: &[],
            lan_servers: &[],
            control: None,
            verbose_log: false,
            local_proxy: None,
        };
        let rendered = render(&request).unwrap();
        assert!(rendered.unsupported.is_empty());
        let value: Value = serde_json::from_slice(&rendered.body).unwrap();
        let actual = json!({"b": value["outbounds"][1], "rules": value["route"]["rules"].as_array().unwrap().iter().filter(|rule| !rule["domain_suffix"].is_null()).collect::<Vec<_>>()});
        let golden: Value =
            serde_json::from_str(include_str!("../tests/fixtures/native-chain.json")).unwrap();
        assert_eq!(actual, golden);
        let mut invalid = extra;
        invalid[1].via = Some(&b);
        assert!(
            render(&RenderRequest {
                extra: &invalid,
                ..request
            })
            .is_err()
        );
        assert!(
            render(&RenderRequest {
                extra: &extra[..1],
                ..request
            })
            .is_err()
        );
    }

    #[test]
    fn first_hop_through_xray_is_reached_by_a_hop_copy_of_its_socks_outbound() {
        let main = shadowsocks_node("main", "203.0.113.1");
        let first = shadowsocks_node("first", "192.0.2.1");
        let a = ExitId::new("a");
        let b = ExitId::new("b");
        let socks = SocksProxy {
            address: "127.0.0.1:10802".parse().unwrap(),
            username: "fixture-user",
            password: "fixture-password",
        };
        let settings = Settings::default();
        let rules = RuleSet::new(RuleSetId::new("test"), "Test", RuleTarget::Proxy);
        for (outbound, network) in [
            (Outbound::Http(Default::default()), Value::Null),
            (Outbound::Socks5(Default::default()), json!("tcp")),
        ] {
            let mut last = shadowsocks_node("last", "198.51.100.2");
            last.outbound = outbound;
            let extra = [
                ExtraOutbound {
                    index: 0,
                    via: None,
                    exit: &a,
                    node: &first,
                    socks: Some(socks),
                },
                ExtraOutbound {
                    index: 1,
                    via: Some(&a),
                    exit: &b,
                    node: &last,
                    socks: None,
                },
            ];
            let request = RenderRequest {
                node: &main,
                socks: None,
                extra: &extra,
                rules: &rules,
                lists: &[],
                settings: &settings,
                lan_segment: &[],
                lan_servers: &[],
                control: None,
                verbose_log: false,
                local_proxy: None,
            };
            let value: Value = serde_json::from_slice(&render(&request).unwrap().body).unwrap();
            let outbounds = value["outbounds"].as_array().unwrap();
            let tagged = |tag: &str| {
                outbounds
                    .iter()
                    .find(|outbound| outbound["tag"] == tag)
                    .unwrap()
                    .clone()
            };
            let (first, hop, last) = (tagged("exit-0"), tagged("hop-exit-0"), tagged("exit-1"));
            assert_eq!(first["type"], "socks");
            assert_eq!(first["server"], "127.0.0.1");
            let mut copy = hop.clone();
            copy["tag"] = "exit-0".into();
            assert_eq!(copy, first);
            assert_eq!(last["detour"], "hop-exit-0");
            assert_eq!(last["server"], "198.51.100.2");
            assert_eq!(last["network"], network);
        }
    }

    #[test]
    fn second_hop_through_xray_is_unsupported() {
        let main = shadowsocks_node("main", "203.0.113.1");
        let first = shadowsocks_node("first", "192.0.2.1");
        let mut last = shadowsocks_node("last", "198.51.100.2");
        last.outbound = Outbound::Http(Default::default());
        let a = ExitId::new("a");
        let b = ExitId::new("b");
        let extra = [
            ExtraOutbound {
                index: 0,
                via: None,
                exit: &a,
                node: &first,
                socks: None,
            },
            ExtraOutbound {
                index: 1,
                via: Some(&a),
                exit: &b,
                node: &last,
                socks: Some(SocksProxy {
                    address: "127.0.0.1:10803".parse().unwrap(),
                    username: "fixture-user",
                    password: "fixture-password",
                }),
            },
        ];
        let settings = Settings::default();
        let rules = RuleSet::new(RuleSetId::new("test"), "Test", RuleTarget::Proxy);
        assert!(
            render(&RenderRequest {
                node: &main,
                socks: None,
                extra: &extra,
                rules: &rules,
                lists: &[],
                settings: &settings,
                lan_segment: &[],
                lan_servers: &[],
                control: None,
                verbose_log: false,
                local_proxy: None,
            })
            .is_err()
        );
    }

    #[test]
    fn rules_by_program_are_offered_on_every_system() {
        const { assert!(RULE_CAPABILITIES.process_name && RULE_CAPABILITIES.process_path) };
    }

    #[test]
    fn the_exit_lookup_has_a_rule_only_where_it_can_name_the_gui() {
        let mut set = RuleSet::new(RuleSetId::new("set"), "Set", RuleTarget::Proxy);
        assert_eq!(
            exit_trace_rule(&set).is_some(),
            cfg!(any(windows, target_os = "macos"))
        );

        set.rules.push(Rule {
            id: RuleId::new("curl"),
            enabled: true,
            matcher: RuleMatcher::Process(ProcessMatch::Name("curl".into())),
            target: RuleTarget::Direct,
            exit: None,
        });
        let rule = exit_trace_rule(&set).expect("this session reads programs");
        assert!(rule.get("process_path_regex").is_some());
        assert_eq!(rule["outbound"], TAG_PROXY);
    }

    use super::*;

    /// Sniffing, DNS and, where it can name the GUI, the exit lookup.
    const OWN_RULES: usize = if cfg!(any(windows, target_os = "macos")) {
        3
    } else {
        2
    };

    const NO_PRIVATE: PrivateNetworks<'static> = PrivateNetworks {
        on: false,
        servers: &[],
    };

    // A rule by program renders differently per system, and so do the rule templates.
    #[cfg(windows)]
    const GOLDEN_FULL: &[u8] = include_bytes!("../tests/fixtures/full-config.json");
    #[cfg(not(windows))]
    const GOLDEN_FULL: &[u8] = include_bytes!("../tests/fixtures/full-config-unix.json");
    #[cfg(windows)]
    const GOLDEN_XRAY_CHAIN: &[u8] = include_bytes!("../tests/fixtures/xray-chain-config.json");
    #[cfg(not(windows))]
    const GOLDEN_XRAY_CHAIN: &[u8] =
        include_bytes!("../tests/fixtures/xray-chain-config-unix.json");
    #[cfg(windows)]
    const GOLDEN_EXTRA_EXITS: &[u8] = include_bytes!("../tests/fixtures/extra-exits-config.json");
    #[cfg(windows)]
    const GOLDEN_LOCAL_PROXY: &[u8] = include_bytes!("../tests/fixtures/local-proxy-config.json");
    #[cfg(not(windows))]
    const GOLDEN_LOCAL_PROXY: &[u8] =
        include_bytes!("../tests/fixtures/local-proxy-config-unix.json");
    #[cfg(windows)]
    const GOLDEN_LOCAL_PROXY_SHARED: &[u8] =
        include_bytes!("../tests/fixtures/local-proxy-shared-config.json");
    #[cfg(not(windows))]
    const GOLDEN_LOCAL_PROXY_SHARED: &[u8] =
        include_bytes!("../tests/fixtures/local-proxy-shared-config-unix.json");
    #[cfg(windows)]
    const GOLDEN_LOCAL_PROXY_XRAY: &[u8] =
        include_bytes!("../tests/fixtures/local-proxy-xray-config.json");
    #[cfg(not(windows))]
    const GOLDEN_LOCAL_PROXY_XRAY: &[u8] =
        include_bytes!("../tests/fixtures/local-proxy-xray-config-unix.json");
    #[cfg(not(windows))]
    const GOLDEN_EXTRA_EXITS: &[u8] =
        include_bytes!("../tests/fixtures/extra-exits-config-unix.json");

    #[cfg(windows)]
    #[test]
    fn process_names_match_complete_paths_without_case_sensitivity() {
        let mut rule = Rule {
            id: rosetun_config::RuleId::new("process"),
            enabled: true,
            matcher: RuleMatcher::Process(ProcessMatch::Name("Telegram.exe".into())),
            target: RuleTarget::Direct,
            exit: None,
        };
        assert_eq!(
            route_rule(&rule).unwrap()["process_path_regex"],
            json!([r"(?i)(?:^|[\\/])Telegram\.exe$"])
        );

        rule.matcher = RuleMatcher::Process(ProcessMatch::Name("C++(test).exe".into()));
        assert_eq!(
            route_rule(&rule).unwrap()["process_path_regex"],
            json!([r"(?i)(?:^|[\\/])C\+\+\(test\)\.exe$"])
        );
        assert_eq!(
            quote_process_name(r"a\.+*?()|[]{}^$"),
            r"a\\\.\+\*\?\(\)\|\[\]\{\}\^\$"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn process_names_match_complete_paths_in_their_own_case() {
        let mut rule = Rule {
            id: rosetun_config::RuleId::new("process"),
            enabled: true,
            matcher: RuleMatcher::Process(ProcessMatch::Name("Telegram".into())),
            target: RuleTarget::Direct,
            exit: None,
        };
        assert_eq!(
            route_rule(&rule).unwrap()["process_path_regex"],
            json!([r"(?:^|[\\/])Telegram$"])
        );
        rule.matcher = RuleMatcher::Process(ProcessMatch::Path("/opt/App/app".into()));
        assert_eq!(
            route_rule(&rule).unwrap()["process_path"],
            json!(["/opt/App/app"])
        );
    }

    #[test]
    fn the_exit_lookup_is_told_by_this_systems_program_name() {
        let path = format!("/opt/rosetun/{GUI_PROCESS}");
        assert!(is_exit_trace(Some(&path), EXIT_TRACE_IP, EXIT_TRACE_PORT));
        assert!(!is_exit_trace(
            Some("/opt/other"),
            EXIT_TRACE_IP,
            EXIT_TRACE_PORT
        ));
        assert!(!is_exit_trace(None, EXIT_TRACE_IP, EXIT_TRACE_PORT));
        assert_eq!(
            is_exit_trace(
                Some(&GUI_PROCESS.to_uppercase()),
                EXIT_TRACE_IP,
                EXIT_TRACE_PORT
            ),
            cfg!(windows)
        );
    }

    #[test]
    fn xhttp_is_refused_with_a_typed_error() {
        let node = Node {
            id: NodeId::new("example-xhttp"),
            name: "Example".into(),
            server: "203.0.113.10".into(),
            port: 443,
            outbound: Outbound::Trojan(rosetun_config::TrojanParams {
                password: "test-secret".into(),
            }),
            stream: StreamSettings {
                transport: Transport::Xhttp {
                    path: "/example".into(),
                    host: None,
                    mode: rosetun_config::XhttpMode::Auto,
                    extra: rosetun_config::XhttpExtra::default(),
                },
                tls: TlsMode::Plain,
                finalmask: None,
            },
            raw: None,
        };
        assert!(matches!(
            proxy_outbound(&node, "proxy"),
            Err(EngineError::Unsupported(message)) if message.contains("XHTTP")
        ));
    }

    #[test]
    fn full_rendered_config_matches_golden() {
        use rosetun_config::ShadowsocksParams;

        let node = Node {
            id: NodeId::new("example-node"),
            name: "Example node".into(),
            server: "203.0.113.10".into(),
            port: 443,
            outbound: Outbound::Shadowsocks(ShadowsocksParams {
                method: "aes-128-gcm".into(),
                password: "test-secret".into(),
            }),
            stream: StreamSettings::default(),
            raw: None,
        };
        let mut rules = RuleSet::new(
            RuleSetId::new("example-rules"),
            "Examples",
            RuleTarget::Block,
        );
        for (id, matcher, target) in [
            (
                "exact",
                RuleMatcher::Domain(DomainMatch::Exact("example.com".into())),
                RuleTarget::Direct,
            ),
            (
                "suffix",
                RuleMatcher::Domain(DomainMatch::Suffix("example.org".into())),
                RuleTarget::Proxy,
            ),
            (
                "keyword",
                RuleMatcher::Domain(DomainMatch::Keyword("example".into())),
                RuleTarget::Block,
            ),
            (
                "name",
                RuleMatcher::Process(ProcessMatch::Name("example.exe".into())),
                RuleTarget::Direct,
            ),
            (
                "path",
                RuleMatcher::Process(ProcessMatch::Path("C:\\example\\example.exe".into())),
                RuleTarget::Proxy,
            ),
            (
                "cidr",
                RuleMatcher::IpCidr("198.51.100.0/24".into()),
                RuleTarget::Block,
            ),
            (
                "group",
                RuleTemplate::Torrents.to_group("Torrents"),
                RuleTarget::Direct,
            ),
            (
                "list",
                RuleMatcher::List {
                    list: ListId::new("golden-list"),
                    category: None,
                },
                RuleTarget::Direct,
            ),
        ] {
            rules.rules.push(rosetun_config::Rule {
                id: RuleId::new(id),
                enabled: true,
                matcher,
                target,
                exit: None,
            });
        }
        let rules = rules.with_groups_expanded();
        let mut settings = Settings {
            kill_switch: true,
            allow_lan: true,
            private_networks: true,
            dns: DnsSettings {
                server: "192.0.2.53".parse().unwrap(),
                server_name: "dns.example.com".into(),
                port: Some(443),
                path: Some("/dns-query".into()),
            },
            ..Settings::default()
        };
        settings.tun.ipv4 = "198.51.100.1/30".into();
        let control = rosetun_engine::ControlEndpoint {
            address: "127.0.0.1:9090".parse().unwrap(),
            secret: "fixture-secret".into(),
            delay: None,
        };
        let lists = [ListRef {
            tag: list_tag(&ListId::new("golden-list"), None),
            sha256: "a".repeat(64),
            format: UploadedListFormat::Source,
        }];
        let request = RenderRequest {
            extra: &[],
            node: &node,
            socks: None,
            rules: &rules,
            lists: &lists,
            settings: &settings,
            lan_segment: &[IpPrefix::new("203.0.113.0".parse().unwrap(), 24).unwrap()],
            lan_servers: &[],
            control: Some(&control),
            verbose_log: false,
            local_proxy: None,
        };
        let rendered = render(&request).unwrap();
        assert!(rendered.unsupported.is_empty());
        assert_golden_session(&rendered.body, GOLDEN_FULL);

        let chained = render(&RenderRequest {
            extra: &[],
            socks: Some(SocksProxy {
                address: "127.0.0.1:10801".parse().unwrap(),
                username: "fixture-user",
                password: "fixture-password",
            }),
            ..request
        })
        .unwrap();
        assert!(chained.unsupported.is_empty());
        assert_golden_session(&chained.body, GOLDEN_XRAY_CHAIN);
    }

    fn assert_golden_session(actual: &[u8], expected: &[u8]) {
        #[cfg(not(target_os = "macos"))]
        assert_eq!(actual, expected);

        #[cfg(target_os = "macos")]
        {
            let mut expected: Value = serde_json::from_slice(expected).unwrap();
            let rules = expected["route"]["rules"].as_array_mut().unwrap();
            let has_exit_trace = rules
                .iter()
                .any(|rule| rule.get("ip_cidr") == Some(&json!([format!("{EXIT_TRACE_IP}/32")])));
            if !has_exit_trace {
                rules.insert(
                    2,
                    json!({
                        "action": "route",
                        "ip_cidr": [format!("{EXIT_TRACE_IP}/32")],
                        "outbound": TAG_PROXY,
                        "port": [EXIT_TRACE_PORT],
                        "process_path_regex": [process_name_regex(GUI_PROCESS)],
                    }),
                );
            }
            let actual: Value = serde_json::from_slice(actual).unwrap();
            assert_eq!(actual, expected);
        }
    }

    fn shadowsocks_node(id: &str, server: &str) -> Node {
        Node {
            id: NodeId::new(id),
            name: format!("Node {id}"),
            server: server.into(),
            port: 443,
            outbound: Outbound::Shadowsocks(rosetun_config::ShadowsocksParams {
                method: "aes-128-gcm".into(),
                password: "test-secret".into(),
            }),
            stream: StreamSettings::default(),
            raw: None,
        }
    }

    fn exit_rule(id: &str, matcher: RuleMatcher, exit: &str) -> Rule {
        Rule {
            id: RuleId::new(id),
            enabled: true,
            matcher,
            target: RuleTarget::Exit,
            exit: Some(ExitId::new(exit)),
        }
    }

    #[test]
    fn a_rule_by_program_to_an_exit_renders_through_its_node() {
        let node = shadowsocks_node("main", "203.0.113.10");
        let work = shadowsocks_node("work", "198.51.100.20");
        let work_exit = ExitId::new("work-exit");
        let mut rules = RuleSet::new(RuleSetId::new("exit-rules"), "Exits", RuleTarget::Proxy);
        rules.rules = vec![exit_rule(
            "program-exit",
            RuleMatcher::Process(ProcessMatch::Name("example-app".into())),
            "work-exit",
        )];
        let settings = Settings::default();
        let rendered = render(&RenderRequest {
            node: &node,
            socks: None,
            extra: &[ExtraOutbound {
                index: 0,
                via: None,
                exit: &work_exit,
                node: &work,
                socks: None,
            }],
            rules: &rules,
            lists: &[],
            settings: &settings,
            lan_segment: &[],
            lan_servers: &[],
            control: None,
            verbose_log: false,
            local_proxy: None,
        })
        .unwrap();
        assert!(rendered.unsupported.is_empty());
        let value: Value = serde_json::from_slice(&rendered.body).unwrap();
        let rule = value["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| rule["outbound"] == "exit-0")
            .expect("the rule by program");
        assert_eq!(
            rule["process_path_regex"],
            json!([process_name_regex("example-app")])
        );
    }

    #[test]
    fn exit_rules_render_through_extra_nodes_golden() {
        let node = shadowsocks_node("main", "203.0.113.10");
        let work = shadowsocks_node("work", "198.51.100.20");
        let media = shadowsocks_node("media", "198.51.100.30");
        let work_exit = ExitId::new("work-exit");
        let media_exit = ExitId::new("media-exit");
        let mut rules = RuleSet::new(RuleSetId::new("exit-rules"), "Exits", RuleTarget::Proxy);
        rules.rules = vec![
            exit_rule(
                "work-suffix",
                RuleMatcher::Domain(DomainMatch::Suffix("example.org".into())),
                "work-exit",
            ),
            exit_rule(
                "work-keyword",
                RuleMatcher::Domain(DomainMatch::Keyword("example".into())),
                "work-exit",
            ),
            exit_rule(
                "media-cidr",
                RuleMatcher::IpCidr("192.0.2.0/24".into()),
                "media-exit",
            ),
        ];
        let mut settings = Settings {
            dns: DnsSettings {
                server: "192.0.2.53".parse().unwrap(),
                server_name: "dns.example.com".into(),
                port: None,
                path: None,
            },
            ..Settings::default()
        };
        settings.tun.ipv4 = "198.51.100.1/30".into();
        let extra = [
            ExtraOutbound {
                index: 0,
                via: None,
                exit: &work_exit,
                node: &work,
                socks: None,
            },
            ExtraOutbound {
                index: 1,
                via: None,
                exit: &media_exit,
                node: &media,
                socks: Some(SocksProxy {
                    address: "127.0.0.1:10802".parse().unwrap(),
                    username: "fixture-user",
                    password: "fixture-password",
                }),
            },
        ];
        let rendered = render(&RenderRequest {
            node: &node,
            socks: None,
            extra: &extra,
            rules: &rules,
            lists: &[],
            settings: &settings,
            lan_segment: &[],
            lan_servers: &[],
            control: None,
            verbose_log: false,
            local_proxy: None,
        })
        .unwrap();
        assert!(rendered.unsupported.is_empty());
        assert_golden_session(&rendered.body, GOLDEN_EXTRA_EXITS);

        let value: Value = serde_json::from_slice(&rendered.body).unwrap();
        let tags = value["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|outbound| outbound["tag"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(tags, ["proxy", "exit-0", "exit-1", "direct"]);
        assert_eq!(value["outbounds"][2]["type"], "socks");
        let routed = value["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|rule| rule["outbound"].as_str())
            .filter(|outbound| outbound.starts_with("exit-"))
            .collect::<Vec<_>>();
        assert_eq!(routed, ["exit-0", "exit-0", "exit-1"]);
    }

    fn local_proxy_request_body(
        address: &str,
        socks: Option<SocksProxy<'_>>,
        rules: &RuleSet,
    ) -> Vec<u8> {
        let node = shadowsocks_node("main", "203.0.113.10");
        render(&RenderRequest {
            node: &node,
            socks,
            extra: &[],
            rules,
            lists: &[],
            settings: &Settings::default(),
            lan_segment: &[],
            lan_servers: &[],
            control: None,
            verbose_log: false,
            local_proxy: Some(&LocalProxyListen {
                addresses: vec![address.parse().unwrap()],
                dns: "127.0.0.1:53535".parse().unwrap(),
            }),
        })
        .unwrap()
        .body
    }

    fn local_proxy_rules() -> RuleSet {
        let mut rules = RuleSet::new(RuleSetId::new("local"), "Local", RuleTarget::Proxy);
        rules.rules = vec![
            Rule {
                id: RuleId::new("site"),
                enabled: true,
                matcher: RuleMatcher::Domain(DomainMatch::Suffix("example.com".into())),
                target: RuleTarget::Direct,
                exit: None,
            },
            Rule {
                id: RuleId::new("program"),
                enabled: true,
                matcher: RuleMatcher::Process(ProcessMatch::Name("example".into())),
                target: RuleTarget::Direct,
                exit: None,
            },
            Rule {
                id: RuleId::new("network"),
                enabled: true,
                matcher: RuleMatcher::IpCidr("198.51.100.0/24".into()),
                target: RuleTarget::Block,
                exit: None,
            },
        ];
        rules
    }

    fn assert_golden(body: &[u8], golden: &[u8]) {
        let actual: Value = serde_json::from_slice(body).unwrap();
        let expected: Value = serde_json::from_slice(golden).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn the_local_proxy_replaces_the_adapter_and_listens_on_loopback() {
        let rules = local_proxy_rules();
        let body = local_proxy_request_body("127.0.0.1:10808", None, &rules);
        assert_golden(&body, GOLDEN_LOCAL_PROXY);
        let value: Value = serde_json::from_slice(&body).unwrap();
        let inbounds = value["inbounds"].as_array().unwrap();
        assert!(inbounds.iter().all(|inbound| inbound["type"] != "tun"));
        assert_eq!(inbounds[0]["type"], "mixed");
        assert_eq!(inbounds[0]["listen"], "127.0.0.1");
        assert_eq!(inbounds[0]["listen_port"], 10808);
    }

    #[test]
    fn a_shared_local_proxy_listens_on_one_dual_stack_socket() {
        let rules = local_proxy_rules();
        let body = local_proxy_request_body("[::]:10808", None, &rules);
        assert_golden(&body, GOLDEN_LOCAL_PROXY_SHARED);
        let value: Value = serde_json::from_slice(&body).unwrap();
        let inbounds = value["inbounds"].as_array().unwrap();
        let mixed: Vec<_> = inbounds
            .iter()
            .filter(|inbound| inbound["type"] == "mixed")
            .collect();
        assert_eq!(mixed.len(), 1);
        assert_eq!(mixed[0]["listen"], "::");
        // Only the proxy is shared.
        assert_eq!(inbounds[1]["listen"], "127.0.0.1");
    }

    #[test]
    fn a_proxy_on_several_addresses_gets_an_inbound_for_each() {
        let node = shadowsocks_node("main", "203.0.113.10");
        let rules = local_proxy_rules();
        let body = render(&RenderRequest {
            node: &node,
            socks: None,
            extra: &[],
            rules: &rules,
            lists: &[],
            settings: &Settings::default(),
            lan_segment: &[],
            lan_servers: &[],
            control: None,
            verbose_log: false,
            local_proxy: Some(&LocalProxyListen {
                addresses: vec![
                    "127.0.0.1:10808".parse().unwrap(),
                    "192.168.1.5:10808".parse().unwrap(),
                    "[fd00:1::5]:10808".parse().unwrap(),
                ],
                dns: "127.0.0.1:53535".parse().unwrap(),
            }),
        })
        .unwrap()
        .body;
        let value: Value = serde_json::from_slice(&body).unwrap();
        let inbounds = value["inbounds"].as_array().unwrap();
        let mixed: Vec<_> = inbounds
            .iter()
            .filter(|inbound| inbound["type"] == "mixed")
            .collect();
        assert_eq!(mixed.len(), 3);
        assert_eq!(mixed[0]["tag"], "mixed-in");
        assert_eq!(mixed[1]["listen"], "192.168.1.5");
        assert_eq!(mixed[2]["tag"], "mixed-in-2");
        assert_eq!(mixed[2]["listen"], "fd00:1::5");
    }

    #[test]
    fn the_local_proxy_stands_in_front_of_xray_as_the_tunnel_does() {
        let rules = local_proxy_rules();
        for (address, golden) in [
            ("127.0.0.1:10808", GOLDEN_LOCAL_PROXY_XRAY),
            ("[::]:10808", GOLDEN_LOCAL_PROXY_XRAY),
        ] {
            let body = local_proxy_request_body(
                address,
                Some(SocksProxy {
                    address: "127.0.0.1:20000".parse().unwrap(),
                    username: "fixture-user",
                    password: "fixture-password",
                }),
                &rules,
            );
            let mut actual: Value = serde_json::from_slice(&body).unwrap();
            let listen = actual["inbounds"][0]["listen"].take();
            assert_eq!(
                listen,
                address.rsplit_once(':').unwrap().0.trim_matches(['[', ']'])
            );
            let mut expected: Value = serde_json::from_slice(golden).unwrap();
            expected["inbounds"][0]["listen"].take();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn address_rules_through_the_local_proxy_resolve_names_first() {
        let rules = local_proxy_rules();
        let body = local_proxy_request_body("127.0.0.1:10808", None, &rules);
        let value: Value = serde_json::from_slice(&body).unwrap();
        let route = value["route"]["rules"].as_array().unwrap();
        let resolve = route
            .iter()
            .position(|rule| rule["action"] == "resolve")
            .expect("a resolve step");
        let network = route
            .iter()
            .position(|rule| rule.get("ip_cidr").is_some() && rule["action"] == "reject")
            .expect("the address rule");
        let site = route
            .iter()
            .position(|rule| rule.get("domain_suffix").is_some())
            .expect("the site rule");
        assert!(site < resolve && resolve + 1 == network);

        let mut no_addresses = rules.clone();
        no_addresses.rules.pop();
        let body = local_proxy_request_body("127.0.0.1:10808", None, &no_addresses);
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            value["route"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .all(|rule| rule["action"] != "resolve")
        );
    }

    #[test]
    fn the_engines_own_dns_answers_on_its_loopback_port() {
        let rules = local_proxy_rules();
        let body = local_proxy_request_body("127.0.0.1:10808", None, &rules);
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["inbounds"][1]["type"], "direct");
        assert_eq!(value["inbounds"][1]["network"], "udp");
        assert_eq!(value["inbounds"][1]["listen_port"], 53535);
        assert!(
            value["route"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|rule| {
                    rule["inbound"] == serde_json::json!(["dns-in"])
                        && rule["action"] == "hijack-dns"
                })
        );
    }

    #[test]
    fn exit_rule_without_extra_node_is_unsupported() {
        let node = shadowsocks_node("main", "203.0.113.10");
        let mut rules = RuleSet::new(RuleSetId::new("exit-rules"), "Exits", RuleTarget::Proxy);
        rules.rules = vec![exit_rule(
            "orphan",
            RuleMatcher::Domain(DomainMatch::Exact("example.com".into())),
            "missing-exit",
        )];
        let rendered = render(&RenderRequest {
            node: &node,
            socks: None,
            extra: &[],
            rules: &rules,
            lists: &[],
            settings: &Settings::default(),
            lan_segment: &[],
            lan_servers: &[],
            control: None,
            verbose_log: false,
            local_proxy: None,
        })
        .unwrap();
        assert_eq!(rendered.unsupported, vec![RuleId::new("orphan")]);
        let value: Value = serde_json::from_slice(&rendered.body).unwrap();
        assert!(
            value["route"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .all(|rule| rule.get("domain").is_none())
        );
    }

    #[test]
    fn render_request_debug_hides_extra_node_addresses() {
        let node = shadowsocks_node("main", "203.0.113.10");
        let work = shadowsocks_node("work", "198.51.100.20");
        let work_exit = ExitId::new("work-exit");
        let rules = RuleSet::new(RuleSetId::new("rules"), "Rules", RuleTarget::Proxy);
        let extra = [ExtraOutbound {
            index: 0,
            via: None,
            exit: &work_exit,
            node: &work,
            socks: Some(SocksProxy {
                address: "127.0.0.1:10802".parse().unwrap(),
                username: "fixture-user",
                password: "fixture-password",
            }),
        }];
        let debug = format!(
            "{:?}",
            RenderRequest {
                node: &node,
                socks: None,
                extra: &extra,
                rules: &rules,
                lists: &[],
                settings: &Settings::default(),
                lan_segment: &[],
                lan_servers: &[],
                control: None,
                verbose_log: false,
                local_proxy: None,
            }
        );
        assert!(debug.contains("work-exit"));
        for secret in [
            "198.51.100.20",
            "203.0.113.10",
            "10802",
            "fixture-user",
            "fixture-password",
            "test-secret",
        ] {
            assert!(!debug.contains(secret), "{secret} leaked into {debug}");
        }
    }

    #[test]
    fn tls_without_fingerprint_uses_chrome_utls() {
        let tls = tls_section(&TlsMode::Tls(Default::default()), true).unwrap();
        assert_eq!(
            tls["utls"],
            json!({ "enabled": true, "fingerprint": "chrome" })
        );
    }

    #[test]
    fn tls_preserves_explicit_fingerprint() {
        let mut mode = TlsMode::Tls(Default::default());
        let TlsMode::Tls(params) = &mut mode else {
            unreachable!();
        };
        params.fingerprint = Some("firefox".into());
        let tls = tls_section(&mode, true).unwrap();
        assert_eq!(
            tls["utls"],
            json!({ "enabled": true, "fingerprint": "firefox" })
        );
    }

    #[test]
    fn hysteria2_renders_quic_ports_obfs_bandwidth_and_tls_without_utls() {
        let mut node = Node {
            id: NodeId::new("test"),
            name: "Test".into(),
            server: "192.0.2.1".into(),
            port: 443,
            outbound: Outbound::Hysteria2(Hysteria2Params {
                password: "test-secret".into(),
                obfs_password: Some("test-secret-obfs".into()),
                port_ranges: vec!["20000-30000".into()],
                up_mbps: Some(100),
                down_mbps: Some(200),
            }),
            stream: StreamSettings {
                tls: TlsMode::Tls(TlsParams {
                    sni: Some("example.com".into()),
                    fingerprint: Some("firefox".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            raw: None,
        };
        let outbound = proxy_outbound(&node, "proxy").unwrap();
        assert_eq!(outbound["type"], "hysteria2");
        assert_eq!(outbound["server_ports"], json!(["443:443", "20000:30000"]));
        assert_eq!(
            outbound["obfs"],
            json!({ "type": "salamander", "password": "test-secret-obfs" })
        );
        assert_eq!(outbound["password"], "test-secret");
        assert_eq!(outbound["up_mbps"], 100);
        assert_eq!(outbound["down_mbps"], 200);
        assert_eq!(outbound["tls"]["server_name"], "example.com");
        assert!(outbound["tls"].get("utls").is_none());
        assert!(outbound["tls"].get("alpn").is_none());
        let rendered = RenderedConfig {
            file_name: "config.json".into(),
            body: serde_json::to_vec(&outbound).unwrap(),
            unsupported: Vec::new(),
            unsupported_probes: Vec::new(),
        };
        assert!(!format!("{rendered:?}").contains("test-secret"));

        node.port = 20000;
        if let TlsMode::Tls(tls) = &mut node.stream.tls {
            tls.fingerprint = None;
        }
        let outbound = proxy_outbound(&node, "proxy").unwrap();
        assert_eq!(outbound["server_ports"], json!(["20000:30000"]));
        assert!(outbound["tls"].get("utls").is_none());

        let Outbound::Hysteria2(params) = &mut node.outbound else {
            unreachable!();
        };
        params.port_ranges = vec!["30001".into()];
        let outbound = proxy_outbound(&node, "proxy").unwrap();
        assert_eq!(
            outbound["server_ports"],
            json!(["20000:20000", "30001:30001"])
        );

        let Outbound::Hysteria2(params) = &mut node.outbound else {
            unreachable!();
        };
        params.port_ranges.clear();
        let outbound = proxy_outbound(&node, "proxy").unwrap();
        assert!(outbound.get("server_ports").is_none());
        assert_eq!(outbound["server_port"], 20000);

        node.stream.tls = TlsMode::Plain;
        assert!(matches!(
            proxy_outbound(&node, "proxy"),
            Err(EngineError::Unsupported(_))
        ));
    }

    #[test]
    fn tuic_outbound_matches_golden_and_handles_optional_fields() {
        let mut node = Node {
            id: NodeId::new("tuic-node"),
            name: "TUIC".into(),
            server: "192.0.2.1".into(),
            port: 8444,
            outbound: Outbound::Tuic(TuicParams {
                uuid: "00000000-0000-4000-8000-000000000001".into(),
                password: "test-secret".into(),
                congestion_control: Some(TuicCongestionControl::Bbr),
                udp_relay_mode: Some(TuicUdpRelayMode::Quic),
                zero_rtt_handshake: true,
                heartbeat: Some("10s".into()),
                disable_sni: true,
            }),
            stream: StreamSettings {
                tls: TlsMode::Tls(TlsParams {
                    sni: Some("tuic.example.com".into()),
                    alpn: vec!["h3".into()],
                    fingerprint: Some("firefox".into()),
                    allow_insecure: true,
                    enable_session_resumption: None,
                }),
                ..Default::default()
            },
            raw: None,
        };
        let outbound = proxy_outbound(&node, "proxy").unwrap();
        let golden: Value =
            serde_json::from_str(include_str!("../tests/fixtures/tuic-outbound.json")).unwrap();
        assert_eq!(outbound, golden);
        assert!(outbound["tls"].get("utls").is_none());

        let rendered = RenderedConfig {
            file_name: "config.json".into(),
            body: serde_json::to_vec(&outbound).unwrap(),
            unsupported: Vec::new(),
            unsupported_probes: Vec::new(),
        };
        let shown = format!("{rendered:?}");
        assert!(!shown.contains("test-secret"));
        assert!(!shown.contains("00000000-0000-4000-8000-000000000001"));

        node.outbound = Outbound::Tuic(TuicParams {
            uuid: "00000000-0000-4000-8000-000000000001".into(),
            password: String::new(),
            congestion_control: None,
            udp_relay_mode: None,
            zero_rtt_handshake: false,
            heartbeat: None,
            disable_sni: false,
        });
        node.stream.tls = TlsMode::Tls(TlsParams::default());
        let minimal = proxy_outbound(&node, "proxy").unwrap();
        assert_eq!(
            minimal,
            json!({
                "tag": "proxy",
                "type": "tuic",
                "server": "192.0.2.1",
                "server_port": 8444,
                "uuid": "00000000-0000-4000-8000-000000000001",
                "tls": { "enabled": true },
            })
        );

        node.stream.tls = TlsMode::Reality(RealityParams {
            sni: Some("tuic.example.com".into()),
            public_key: "test-key".into(),
            short_id: None,
            fingerprint: None,
        });
        assert!(matches!(
            proxy_outbound(&node, "proxy"),
            Err(EngineError::Unsupported(_))
        ));

        node.stream.tls = TlsMode::Plain;
        assert!(matches!(
            proxy_outbound(&node, "proxy"),
            Err(EngineError::Unsupported(_))
        ));
    }

    #[test]
    fn anytls_outbound_matches_golden_and_supports_reality() {
        let mut node = Node {
            id: NodeId::new("anytls-node"),
            name: "AnyTLS".into(),
            server: "192.0.2.2".into(),
            port: 8445,
            outbound: Outbound::AnyTls(AnyTlsParams {
                password: "test-secret".into(),
                idle_session_check_interval: Some("30s".into()),
                idle_session_timeout: Some("60s".into()),
                min_idle_session: Some(2),
            }),
            stream: StreamSettings {
                tls: TlsMode::Tls(TlsParams {
                    sni: Some("anytls.example.com".into()),
                    alpn: vec!["h2".into(), "http/1.1".into()],
                    fingerprint: Some("firefox".into()),
                    allow_insecure: false,
                    enable_session_resumption: None,
                }),
                ..Default::default()
            },
            raw: None,
        };
        let outbound = proxy_outbound(&node, "proxy").unwrap();
        let golden: Value =
            serde_json::from_str(include_str!("../tests/fixtures/anytls-outbound.json")).unwrap();
        assert_eq!(outbound, golden);

        node.outbound = Outbound::AnyTls(AnyTlsParams {
            password: "test-secret".into(),
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
        });
        node.stream.tls = TlsMode::Reality(RealityParams {
            sni: Some("anytls.example.com".into()),
            public_key: "test-pubkey".into(),
            short_id: Some("abcd".into()),
            fingerprint: Some("chrome".into()),
        });
        let reality = proxy_outbound(&node, "proxy").unwrap();
        assert_eq!(reality["type"], "anytls");
        assert_eq!(reality["tls"]["reality"]["enabled"], true);
        assert_eq!(reality["tls"]["reality"]["public_key"], "test-pubkey");
        assert_eq!(reality["tls"]["reality"]["short_id"], "abcd");
        assert_eq!(reality["tls"]["utls"]["fingerprint"], "chrome");
        assert!(reality.get("idle_session_check_interval").is_none());
        assert!(reality.get("idle_session_timeout").is_none());
        assert!(reality.get("min_idle_session").is_none());

        node.stream.tls = TlsMode::Plain;
        assert!(matches!(
            proxy_outbound(&node, "proxy"),
            Err(EngineError::Unsupported(_))
        ));
    }

    #[test]
    fn tuic_and_anytls_render_in_probes_and_as_first_hop_in_a_two_hop_chain() {
        let tuic = Node {
            id: NodeId::new("tuic-probe"),
            name: "TUIC".into(),
            server: "192.0.2.1".into(),
            port: 8444,
            outbound: Outbound::Tuic(TuicParams {
                uuid: "00000000-0000-4000-8000-000000000001".into(),
                password: "test-secret".into(),
                congestion_control: Some(TuicCongestionControl::Bbr),
                udp_relay_mode: None,
                zero_rtt_handshake: false,
                heartbeat: None,
                disable_sni: false,
            }),
            stream: StreamSettings {
                tls: TlsMode::Tls(TlsParams {
                    sni: Some("tuic.example.com".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            raw: None,
        };
        let anytls = Node {
            id: NodeId::new("anytls-probe"),
            name: "AnyTLS".into(),
            server: "192.0.2.2".into(),
            port: 8445,
            outbound: Outbound::AnyTls(AnyTlsParams {
                password: "test-secret".into(),
                idle_session_check_interval: None,
                idle_session_timeout: None,
                min_idle_session: None,
            }),
            stream: StreamSettings {
                tls: TlsMode::Tls(TlsParams {
                    sni: Some("anytls.example.com".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            raw: None,
        };
        let control = rosetun_engine::ControlEndpoint {
            address: "127.0.0.1:9090".parse().unwrap(),
            secret: "fixture-secret".into(),
            delay: None,
        };
        let nodes = vec![
            ("probe-tuic".to_owned(), tuic.clone()),
            ("probe-anytls".to_owned(), anytls.clone()),
        ];
        let probe = render_probe(&ProbeRenderRequest {
            nodes: &nodes,
            socks: &[],
            interface: None,
            control: &control,
        })
        .unwrap();
        assert!(probe.unsupported_probes.is_empty());
        let probe_json: Value = serde_json::from_slice(&probe.body).unwrap();
        assert_eq!(probe_json["outbounds"][0]["type"], "tuic");
        assert_eq!(probe_json["outbounds"][1]["type"], "anytls");

        let main = shadowsocks_node("main", "203.0.113.1");
        let mut exit_b = shadowsocks_node("exit-b", "198.51.100.2");
        exit_b.outbound = Outbound::Socks5(Default::default());
        let (a, b) = (ExitId::new("a"), ExitId::new("b"));
        let rules = RuleSet::new(RuleSetId::new("test"), "Test", RuleTarget::Proxy);
        let settings = Settings::default();
        for (parent, expected_type) in [(&tuic, "tuic"), (&anytls, "anytls")] {
            let extra = [
                ExtraOutbound {
                    index: 0,
                    via: None,
                    exit: &a,
                    node: parent,
                    socks: None,
                },
                ExtraOutbound {
                    index: 1,
                    via: Some(&a),
                    exit: &b,
                    node: &exit_b,
                    socks: None,
                },
            ];
            let rendered = render(&RenderRequest {
                node: &main,
                socks: None,
                extra: &extra,
                rules: &rules,
                lists: &[],
                settings: &settings,
                lan_segment: &[],
                lan_servers: &[],
                control: None,
                verbose_log: false,
                local_proxy: None,
            })
            .unwrap();
            let value: Value = serde_json::from_slice(&rendered.body).unwrap();
            let outbounds = value["outbounds"].as_array().unwrap();
            let hop = outbounds
                .iter()
                .find(|outbound| outbound["tag"] == "hop-exit-0")
                .unwrap();
            let second = outbounds
                .iter()
                .find(|outbound| outbound["tag"] == "exit-1")
                .unwrap();
            assert_eq!(hop["type"], expected_type);
            assert_eq!(second["detour"], "hop-exit-0");
        }
    }

    #[test]
    fn list_matcher_is_reported_without_a_match_all_route() {
        let mut set = RuleSet::new(RuleSetId::new("set"), "Test", RuleTarget::Proxy);
        let list = Rule {
            id: RuleId::new("list"),
            enabled: true,
            matcher: RuleMatcher::List {
                list: ListId::new("1"),
                category: None,
            },
            target: RuleTarget::Direct,
            exit: None,
        };
        assert_eq!(route_rule(&list), None);
        set.rules.push(list.clone());
        let (route, unsupported) = route_section(&set, RuleCapabilities::ALL, false);
        assert_eq!(unsupported, vec![list.id]);
        assert_eq!(route["rules"].as_array().unwrap().len(), OWN_RULES);
    }

    #[test]
    fn list_rules_share_one_local_rule_set_and_keep_their_actions() {
        let list = ListId::new("example-list");
        let tag = list_tag(&list, None);
        let reference = ListRef {
            tag: tag.clone(),
            sha256: "a".repeat(64),
            format: UploadedListFormat::Binary,
        };
        let mut set = RuleSet::new(RuleSetId::new("set"), "Test", RuleTarget::Proxy);
        for (id, target) in [("direct", RuleTarget::Direct), ("block", RuleTarget::Block)] {
            set.rules.push(rosetun_config::Rule {
                id: RuleId::new(id),
                enabled: true,
                matcher: RuleMatcher::List {
                    list: list.clone(),
                    category: None,
                },
                target,
                exit: None,
            });
        }
        let (route, unsupported) = route_section_with_lists(
            &set,
            RULE_CAPABILITIES,
            None,
            NO_PRIVATE,
            &[reference],
            &[],
            false,
        );
        assert!(unsupported.is_empty());
        assert_eq!(
            route["rule_set"],
            json!([{
                "type": "local", "tag": tag, "format": "binary", "path": format!("{tag}.srs")
            }])
        );
        assert_eq!(
            route["rules"][OWN_RULES],
            json!({
                "rule_set": [tag], "action": "route", "outbound": "direct"
            })
        );
        assert_eq!(
            route["rules"][OWN_RULES + 1],
            json!({"rule_set": [tag], "action": "reject"})
        );
        assert!(
            route_section_with_lists(
                &set,
                RuleCapabilities::NONE,
                None,
                NO_PRIVATE,
                &[],
                &[],
                false,
            )
            .1
            .len()
                == 2
        );
    }

    #[test]
    fn exit_target_is_unsupported_until_renderer_can_route_it() {
        let mut set = RuleSet::new(RuleSetId::new("set"), "Test", RuleTarget::Proxy);
        set.rules.push(Rule {
            id: RuleId::new("exit"),
            enabled: true,
            matcher: RuleMatcher::IpCidr("192.0.2.0/24".into()),
            target: RuleTarget::Exit,
            exit: Some(rosetun_config::ExitId::new("1")),
        });
        let (route, unsupported) = route_section(&set, RuleCapabilities::ALL, false);
        assert_eq!(unsupported, vec![RuleId::new("exit")]);
        assert!(
            !route["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|rule| { rule["ip_cidr"] == serde_json::json!(["192.0.2.0/24"]) })
        );
    }

    #[test]
    fn missing_list_reference_is_unsupported_without_affecting_other_list_rules() {
        let mut set = RuleSet::new(RuleSetId::new("set"), "Test", RuleTarget::Proxy);
        let vanished = RuleId::new("vanished");
        set.rules.push(rosetun_config::Rule {
            id: vanished.clone(),
            enabled: true,
            matcher: RuleMatcher::List {
                list: ListId::new("dat"),
                category: Some("missing@ads".into()),
            },
            target: RuleTarget::Block,
            exit: None,
        });
        let remaining = ListId::new("still-present");
        let tag = list_tag(&remaining, None);
        set.rules.push(rosetun_config::Rule {
            id: RuleId::new("remaining"),
            enabled: true,
            matcher: RuleMatcher::List {
                list: remaining,
                category: None,
            },
            target: RuleTarget::Direct,
            exit: None,
        });
        let reference = ListRef {
            tag: tag.clone(),
            sha256: "b".repeat(64),
            format: UploadedListFormat::Source,
        };
        let (route, unsupported) = route_section_with_lists(
            &set,
            RULE_CAPABILITIES,
            None,
            NO_PRIVATE,
            &[reference],
            &[],
            false,
        );
        assert_eq!(unsupported, [vanished]);
        assert_eq!(route["rules"].as_array().unwrap().len(), OWN_RULES + 1);
        assert_eq!(
            route["rules"][OWN_RULES],
            json!({
                "rule_set": [tag], "action": "route", "outbound": "direct"
            })
        );
        assert_eq!(route["rule_set"][0]["format"], "source");
        assert_eq!(route["rule_set"][0]["path"], format!("{tag}.json"));
    }

    #[test]
    fn unexpanded_group_is_reported_without_a_match_all_route() {
        let mut set = RuleSet::new(RuleSetId::new("set"), "Test", RuleTarget::Proxy);
        let group = Rule {
            id: RuleId::new("group"),
            enabled: true,
            matcher: RuleTemplate::RussianSites.to_group("Russian sites"),
            target: RuleTarget::Direct,
            exit: None,
        };
        assert_eq!(route_rule(&group), None);
        set.rules.push(group.clone());
        let (route, unsupported) = route_section(&set, RuleCapabilities::ALL, false);
        assert_eq!(unsupported, vec![group.id]);
        assert_eq!(route["rules"].as_array().unwrap().len(), OWN_RULES);
    }

    fn delay_control(tags: &[&str]) -> rosetun_engine::ControlEndpoint {
        let accounts = tags
            .iter()
            .enumerate()
            .map(|(index, tag)| rosetun_engine::DelayAccount {
                tag: (*tag).to_owned(),
                password: format!("fixture-password-{index}"),
            })
            .collect();
        rosetun_engine::ControlEndpoint {
            address: "127.0.0.1:9090".parse().unwrap(),
            secret: "fixture-secret".into(),
            delay: Some(rosetun_engine::DelayInbound {
                address: "127.0.0.1:9091".parse().unwrap(),
                accounts,
            }),
        }
    }

    fn delay_body(
        control: &rosetun_engine::ControlEndpoint,
        socks: Option<SocksProxy<'_>>,
        extra: &[ExtraOutbound<'_>],
        local_proxy: Option<&LocalProxyListen>,
    ) -> Value {
        let node = shadowsocks_node("main", "203.0.113.10");
        let rules = local_proxy_rules();
        let rendered = render(&RenderRequest {
            node: &node,
            socks,
            extra,
            rules: &rules,
            lists: &[],
            settings: &Settings::default(),
            lan_segment: &[],
            lan_servers: &[],
            control: Some(control),
            verbose_log: false,
            local_proxy,
        })
        .unwrap();
        serde_json::from_slice(&rendered.body).unwrap()
    }

    fn rules_of(value: &Value) -> &Vec<Value> {
        value["route"]["rules"].as_array().unwrap()
    }

    fn mentions_the_delay_inbound(rule: &Value) -> bool {
        rule["inbound"]
            .as_array()
            .is_some_and(|tags| tags.iter().any(|tag| tag == TAG_DELAY_INBOUND))
    }

    #[test]
    fn a_session_with_a_control_endpoint_gets_one_loopback_entry_for_timing() {
        let control = delay_control(&["proxy"]);
        let value = delay_body(&control, None, &[], None);
        let entries: Vec<_> = value["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|inbound| inbound["tag"] == TAG_DELAY_INBOUND)
            .collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["type"], "socks");
        assert_eq!(entries[0]["listen"], "127.0.0.1");
        assert_eq!(entries[0]["listen_port"], 9091);
        assert_eq!(
            entries[0]["users"],
            json!([{ "username": "proxy", "password": "fixture-password-0" }])
        );
    }

    #[test]
    fn subscription_requests_reach_the_main_outbound_before_user_rules() {
        let control = delay_control(&["proxy", rosetun_engine::SUBSCRIPTION_PROXY_USER]);
        let value = delay_body(&control, None, &[], None);
        let rules = rules_of(&value);
        assert_eq!(rules[1]["auth_user"], json!(["subscription"]));
        assert_eq!(rules[1]["outbound"], "proxy");
        assert_eq!(rules[1]["network"], "tcp");
        assert_eq!(rules[2]["action"], "reject");
        assert_eq!(rules[2]["inbound"], json!([TAG_DELAY_INBOUND]));
    }

    #[test]
    fn the_entry_is_absent_without_a_control_endpoint_or_an_account() {
        let node = shadowsocks_node("main", "203.0.113.10");
        let rules = local_proxy_rules();
        let settings = Settings::default();
        let mut control = delay_control(&["proxy"]);
        let has_entry = |control: Option<&rosetun_engine::ControlEndpoint>| {
            let body = render(&RenderRequest {
                node: &node,
                socks: None,
                extra: &[],
                rules: &rules,
                lists: &[],
                settings: &settings,
                lan_segment: &[],
                lan_servers: &[],
                control,
                verbose_log: false,
                local_proxy: None,
            })
            .unwrap()
            .body;
            String::from_utf8(body).unwrap().contains(TAG_DELAY_INBOUND)
        };
        assert!(has_entry(Some(&control)));
        assert!(!has_entry(None));
        control.delay.as_mut().unwrap().accounts.clear();
        assert!(!has_entry(Some(&control)));
        control.delay = None;
        assert!(!has_entry(Some(&control)));
    }

    #[test]
    fn every_outbound_gets_an_account_and_a_rule_before_the_users_rules() {
        let first = shadowsocks_node("first", "192.0.2.1");
        let second = shadowsocks_node("second", "198.51.100.2");
        let (a, b) = (ExitId::new("a"), ExitId::new("b"));
        let extra = [
            ExtraOutbound {
                index: 0,
                via: None,
                exit: &a,
                node: &first,
                socks: None,
            },
            ExtraOutbound {
                index: 2,
                via: None,
                exit: &b,
                node: &second,
                socks: None,
            },
        ];
        // `exit-1` has no node in this request, so its account has nothing to reach.
        let control = delay_control(&["proxy", "exit-0", "exit-1", "exit-2"]);
        let value = delay_body(&control, None, &extra, None);

        let users = value["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|inbound| inbound["tag"] == TAG_DELAY_INBOUND)
            .unwrap()["users"]
            .clone();
        let names: Vec<_> = users
            .as_array()
            .unwrap()
            .iter()
            .map(|user| user["username"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["proxy", "exit-0", "exit-2"]);

        let rules = rules_of(&value);
        for (position, tag) in ["proxy", "exit-0", "exit-2"].into_iter().enumerate() {
            assert_eq!(rules[position]["inbound"], json!([TAG_DELAY_INBOUND]));
            assert_eq!(rules[position]["auth_user"], json!([tag]));
            assert_eq!(rules[position]["action"], "route");
            assert_eq!(rules[position]["outbound"], tag);
        }
        assert_eq!(
            rules[3],
            json!({ "inbound": [TAG_DELAY_INBOUND], "action": "reject" })
        );
        // The sniffer and the user's rules come after, and none of them names the entry.
        assert_eq!(rules[4]["action"], "sniff");
        assert!(
            rules[4..]
                .iter()
                .all(|rule| !mentions_the_delay_inbound(rule))
        );
    }

    #[test]
    fn the_entry_carries_tcp_only_and_refuses_all_else() {
        let control = delay_control(&["proxy"]);
        let value = delay_body(&control, None, &[], None);
        let rules = rules_of(&value);
        assert_eq!(rules[0]["network"], "tcp");
        // No `network`, no `auth_user`: UDP and any other account fall here.
        assert_eq!(rules[1].as_object().unwrap().len(), 2);
        assert_eq!(rules[1]["action"], "reject");
    }

    #[test]
    fn a_node_behind_xray_is_timed_through_the_same_outbound() {
        let control = delay_control(&["proxy"]);
        let socks = SocksProxy {
            address: "127.0.0.1:10801".parse().unwrap(),
            username: "fixture-user",
            password: "fixture-password",
        };
        let value = delay_body(&control, Some(socks), &[], None);
        let proxy = value["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|outbound| outbound["tag"] == "proxy")
            .unwrap();
        assert_eq!(proxy["type"], "socks");
        assert_eq!(rules_of(&value)[0]["outbound"], "proxy");
    }

    #[test]
    fn a_two_hop_exit_is_timed_through_its_own_outbound() {
        let first = shadowsocks_node("first", "192.0.2.1");
        let mut last = shadowsocks_node("last", "198.51.100.2");
        last.outbound = Outbound::Http(Default::default());
        let (a, b) = (ExitId::new("a"), ExitId::new("b"));
        let extra = [
            ExtraOutbound {
                index: 0,
                via: None,
                exit: &a,
                node: &first,
                socks: None,
            },
            ExtraOutbound {
                index: 1,
                via: Some(&a),
                exit: &b,
                node: &last,
                socks: None,
            },
        ];
        let control = delay_control(&["proxy", "exit-0", "exit-1"]);
        let value = delay_body(&control, None, &extra, None);
        let rules = rules_of(&value);
        assert_eq!(rules[2]["auth_user"], json!(["exit-1"]));
        assert_eq!(rules[2]["outbound"], "exit-1");
        let outbounds = value["outbounds"].as_array().unwrap();
        let last = outbounds
            .iter()
            .find(|outbound| outbound["tag"] == "exit-1")
            .unwrap();
        assert_eq!(last["detour"], "hop-exit-0");
    }

    #[test]
    fn the_proxy_mode_keeps_its_own_inbound_apart_from_the_entry() {
        let control = delay_control(&["proxy"]);
        let listen = LocalProxyListen {
            addresses: vec!["127.0.0.1:10808".parse().unwrap()],
            dns: "127.0.0.1:53535".parse().unwrap(),
        };
        let value = delay_body(&control, None, &[], Some(&listen));
        let inbounds = value["inbounds"].as_array().unwrap();
        assert_eq!(inbounds[0]["type"], "mixed");
        assert_eq!(inbounds[0]["listen_port"], 10808);
        assert!(inbounds[0].get("users").is_none());
        assert_eq!(inbounds.last().unwrap()["tag"], TAG_DELAY_INBOUND);
        assert!(
            !inbounds
                .iter()
                .filter(|inbound| inbound["tag"] != TAG_DELAY_INBOUND)
                .any(|inbound| inbound["listen_port"] == 9091)
        );
    }

    #[test]
    fn the_entry_passwords_stay_out_of_debug_output() {
        let control = delay_control(&["proxy"]);
        let node = shadowsocks_node("main", "203.0.113.10");
        let rules = local_proxy_rules();
        let request = RenderRequest {
            node: &node,
            socks: None,
            extra: &[],
            rules: &rules,
            lists: &[],
            settings: &Settings::default(),
            lan_segment: &[],
            lan_servers: &[],
            control: Some(&control),
            verbose_log: false,
            local_proxy: None,
        };
        let shown = format!("{request:?} {control:?}");
        assert!(!shown.contains("fixture-password"));
        assert!(!shown.contains("fixture-secret"));
        let rendered = render(&request).unwrap();
        assert!(!format!("{rendered:?}").contains("fixture-password"));
    }

    #[test]
    fn macos_bundle_paths_and_helper_names_render_for_process_rules() {
        let node = shadowsocks_node("main", "203.0.113.10");
        let mut rules = RuleSet::new(RuleSetId::new("macos"), "macOS", RuleTarget::Proxy);
        let bundle_path = "/Applications/Visual Studio Code.app/Contents/MacOS/Electron";
        let helper_name = "Google Chrome Helper (Renderer)";
        rules.rules = vec![
            Rule {
                id: RuleId::new("bundle"),
                enabled: true,
                matcher: RuleMatcher::Process(ProcessMatch::Path(std::path::PathBuf::from(
                    bundle_path,
                ))),
                target: RuleTarget::Direct,
                exit: None,
            },
            Rule {
                id: RuleId::new("helper"),
                enabled: true,
                matcher: RuleMatcher::Process(ProcessMatch::Name(helper_name.into())),
                target: RuleTarget::Block,
                exit: None,
            },
        ];

        let rendered = render(&RenderRequest {
            node: &node,
            socks: None,
            extra: &[],
            rules: &rules,
            lists: &[],
            settings: &Settings::default(),
            lan_segment: &[],
            lan_servers: &[],
            control: None,
            verbose_log: false,
            local_proxy: None,
        })
        .unwrap();
        assert!(rendered.unsupported.is_empty());

        let value: Value = serde_json::from_slice(&rendered.body).unwrap();
        let route_rules = rules_of(&value);

        let bundle_rule = route_rules
            .iter()
            .find(|rule| rule["process_path"] == json!([bundle_path]))
            .expect("bundle process_path rule");
        assert_eq!(bundle_rule["action"], "route");
        assert_eq!(bundle_rule["outbound"], "direct");

        let expected_regex = if cfg!(windows) {
            r"(?i)(?:^|[\\/])Google Chrome Helper \(Renderer\)$"
        } else {
            r"(?:^|[\\/])Google Chrome Helper \(Renderer\)$"
        };
        let helper_rule = route_rules
            .iter()
            .find(|rule| rule["process_path_regex"] == json!([expected_regex]))
            .expect("escaped helper process_path_regex rule");
        assert_eq!(helper_rule["action"], "reject");
    }

    #[test]
    fn wireguard_endpoint_matches_fixture_and_omits_optional_fields() {
        let mut node = Node {
            id: NodeId::new("wg-full"),
            name: "WireGuard".into(),
            server: "192.0.2.42".into(),
            port: 51820,
            outbound: Outbound::WireGuard(rosetun_config::WireGuardParams {
                private_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
                public_key: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".into(),
                pre_shared_key: Some("AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=".into()),
                address: vec!["10.0.0.2/32".into(), "fd00::2/128".into()],
                reserved: Some([1, 2, 3]),
                mtu: Some(1280),
                persistent_keepalive: Some(25),
            }),
            stream: StreamSettings::default(),
            raw: None,
        };
        let endpoint = wireguard_endpoint(&node, "proxy").unwrap();
        let golden: Value =
            serde_json::from_str(include_str!("../tests/fixtures/wireguard-endpoint.json"))
                .unwrap();
        assert_eq!(endpoint, golden);

        node.outbound = Outbound::WireGuard(rosetun_config::WireGuardParams {
            private_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
            public_key: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".into(),
            pre_shared_key: None,
            address: vec!["10.0.0.2/32".into()],
            reserved: None,
            mtu: None,
            persistent_keepalive: None,
        });
        let minimal = wireguard_endpoint(&node, "proxy").unwrap();
        assert!(minimal.get("mtu").is_none());
        let peer = &minimal["peers"][0];
        assert!(peer.get("pre_shared_key").is_none());
        assert!(peer.get("persistent_keepalive_interval").is_none());
        assert!(peer.get("reserved").is_none());
        assert_eq!(peer["allowed_ips"], json!(["0.0.0.0/0", "::/0"]));

        node.stream.tls = TlsMode::Tls(TlsParams::default());
        assert!(matches!(
            wireguard_endpoint(&node, "proxy"),
            Err(EngineError::Unsupported(_))
        ));
    }

    #[test]
    fn wireguard_renders_in_endpoints_probes_and_two_hop_without_duplicating_endpoint() {
        let wg = Node {
            id: NodeId::new("wg-main"),
            name: "WireGuard".into(),
            server: "192.0.2.42".into(),
            port: 51820,
            outbound: Outbound::WireGuard(rosetun_config::WireGuardParams {
                private_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
                public_key: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".into(),
                pre_shared_key: None,
                address: vec!["10.0.0.2/32".into()],
                reserved: Some([1, 2, 3]),
                mtu: Some(1280),
                persistent_keepalive: None,
            }),
            stream: StreamSettings::default(),
            raw: None,
        };
        let mut socks = shadowsocks_node("socks", "198.51.100.2");
        socks.port = 1080;
        socks.outbound = Outbound::Socks5(Default::default());

        let (a, b) = (ExitId::new("a"), ExitId::new("b"));
        let extra = [
            ExtraOutbound {
                index: 0,
                via: None,
                exit: &a,
                node: &wg,
                socks: None,
            },
            ExtraOutbound {
                index: 1,
                via: Some(&a),
                exit: &b,
                node: &socks,
                socks: None,
            },
        ];
        let mut rules = local_proxy_rules();
        rules.rules.push(Rule {
            id: RuleId::new("wg-chain"),
            enabled: true,
            matcher: RuleMatcher::Domain(DomainMatch::Suffix("example.com".into())),
            target: RuleTarget::Exit,
            exit: Some(b.clone()),
        });
        let rendered = render(&RenderRequest {
            node: &wg,
            socks: None,
            extra: &extra,
            rules: &rules,
            lists: &[],
            settings: &Settings::default(),
            lan_segment: &[],
            lan_servers: &[],
            control: None,
            verbose_log: false,
            local_proxy: None,
        })
        .unwrap();
        let value: Value = serde_json::from_slice(&rendered.body).unwrap();
        let endpoints = value["endpoints"].as_array().unwrap();
        let endpoint_tags: Vec<_> = endpoints
            .iter()
            .map(|entry| entry["tag"].as_str().unwrap())
            .collect();
        // Primary `proxy` and single `exit-0` endpoint — no cloned `hop-exit-0`.
        assert_eq!(endpoint_tags, ["proxy", "exit-0"]);

        let outbounds = value["outbounds"].as_array().unwrap();
        let second = outbounds
            .iter()
            .find(|outbound| outbound["tag"] == "exit-1")
            .unwrap();
        assert_eq!(second["detour"], "exit-0");
        assert_eq!(second["network"], "tcp");
        assert!(
            !outbounds
                .iter()
                .any(|outbound| outbound["tag"] == "hop-exit-0")
        );

        // Probe places WireGuard in `endpoints` and keeps `direct` in `outbounds`.
        let control = rosetun_engine::ControlEndpoint::local().unwrap();
        let probe_nodes = [("probe-0".to_owned(), wg)];
        let probe = render_probe(&ProbeRenderRequest {
            nodes: &probe_nodes,
            socks: &[],
            interface: None,
            control: &control,
        })
        .unwrap();
        assert!(probe.unsupported_probes.is_empty());
        let probe_json: Value = serde_json::from_slice(&probe.body).unwrap();
        assert_eq!(probe_json["endpoints"][0]["tag"], "probe-0");
        assert_eq!(probe_json["endpoints"][0]["type"], "wireguard");
        assert_eq!(probe_json["outbounds"][0]["tag"], "direct");
    }
}
