use rosetun_config::{
    DnsSettings, DomainMatch, LogLevel, Node, Outbound, ProcessMatch, RuleId, RuleMatcher, RuleSet,
    RuleTarget, Settings, TlsMode, Transport,
};
use rosetun_engine::errors::EngineError;
use rosetun_engine::{RenderRequest, RenderedConfig, RuleCapabilities};
use serde_json::{Map, Value, json};

const TAG_PROXY: &str = "proxy";
const TAG_DIRECT: &str = "direct";
const TAG_DNS_PROXY: &str = "dns-proxy";

pub(crate) const RULE_CAPABILITIES: RuleCapabilities = RuleCapabilities {
    domain_exact: true,
    domain_suffix: true,
    domain_keyword: true,
    process_name: true,
    process_path: true,
    ip_cidr: true,
};

pub fn render(request: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError> {
    let (route, unsupported) =
        route_section(request.rules, RULE_CAPABILITIES, request.settings.allow_lan);
    let mut config = json!({
        "log": log_section(request),
        "dns": dns_section(&request.settings.dns)?,
        "inbounds": [tun_inbound(request.settings)],
        "outbounds": [
            proxy_outbound(request.node)?,
            json!({ "type": "direct", "tag": TAG_DIRECT }),
        ],
        "route": route,
    });
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
    // Startup readiness needs the INFO message, so the engine must not go below INFO.
    let level = match (request.verbose_log, request.settings.log_level) {
        (false, _) => "info",
        (true, LogLevel::Trace) => "trace",
        (true, _) => "debug",
    };
    json!({ "level": level, "timestamp": true })
}

fn tun_inbound(settings: &Settings) -> Value {
    let tun = &settings.tun;
    let mut address = vec![Value::String(tun.ipv4.clone())];
    if let Some(ipv6) = &tun.ipv6 {
        address.push(Value::String(ipv6.clone()));
    }
    json!({
        "type": "tun",
        "tag": "tun-in",
        "interface_name": tun.name,
        "address": address,
        "mtu": tun.mtu,
        // The system stack hands TUN connections back to sing-box through
        // Windows, so a firewall that blocks inbound traffic to sing-box.exe
        // silently drops all TCP. gVisor keeps TCP inside the process.
        "stack": "gvisor",
        "auto_route": tun.auto_route,
        "strict_route": tun.auto_route,
    })
}

fn proxy_outbound(node: &Node) -> Result<Value, EngineError> {
    let mut outbound = Map::new();
    outbound.insert("tag".into(), TAG_PROXY.into());
    outbound.insert("server".into(), node.server.clone().into());
    outbound.insert("server_port".into(), node.port.into());

    match &node.outbound {
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
        Outbound::Unknown { scheme, .. } => {
            return Err(EngineError::Unsupported(format!(
                "protocol {scheme} not supported by the sing box backend"
            )));
        }
    }

    if let Some(tls) = tls_section(&node.stream.tls) {
        outbound.insert("tls".into(), tls);
    }
    if let Some(transport) = transport_section(&node.stream.transport) {
        outbound.insert("transport".into(), transport);
    }

    Ok(Value::Object(outbound))
}

fn tls_section(mode: &TlsMode) -> Option<Value> {
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
            if let Some(fingerprint) = &params.fingerprint {
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
            let fingerprint = params
                .fingerprint
                .clone()
                .unwrap_or_else(|| "chrome".into());
            tls.insert(
                "utls".into(),
                json!({ "enabled": true, "fingerprint": fingerprint }),
            );
            Some(Value::Object(tls))
        }
    }
}

fn transport_section(transport: &Transport) -> Option<Value> {
    match transport {
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
    }
}

pub(crate) fn route_section(
    rules: &RuleSet,
    capabilities: RuleCapabilities,
    allow_lan: bool,
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
    let mut unsupported = Vec::new();

    for rule in rules.enabled() {
        if capabilities.supports(&rule.matcher) {
            route_rules.push(route_rule(rule));
        } else {
            unsupported.push(rule.id.clone());
        }
    }

    if allow_lan {
        route_rules.push(json!({
            "ip_is_private": true,
            "action": "route",
            "outbound": TAG_DIRECT,
        }));
    }

    let final_outbound = match rules.default_target {
        RuleTarget::Proxy => TAG_PROXY,
        RuleTarget::Direct => TAG_DIRECT,
        RuleTarget::Block => {
            route_rules.push(json!({ "action": "reject" }));
            TAG_DIRECT
        }
    };

    (
        json!({
            "rules": route_rules,
            "final": final_outbound,
            "auto_detect_interface": true,
        }),
        unsupported,
    )
}

fn route_rule(rule: &rosetun_config::Rule) -> Value {
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
            value.insert("process_name".into(), json!([name]));
        }
        RuleMatcher::Process(ProcessMatch::Path(path)) => {
            value.insert("process_path".into(), json!([path.to_string_lossy()]));
        }
        RuleMatcher::IpCidr(cidr) => {
            value.insert("ip_cidr".into(), json!([cidr]));
        }
    }

    match rule.target {
        RuleTarget::Proxy | RuleTarget::Direct => {
            value.insert("action".into(), "route".into());
            value.insert(
                "outbound".into(),
                match rule.target {
                    RuleTarget::Proxy => TAG_PROXY,
                    _ => TAG_DIRECT,
                }
                .into(),
            );
        }
        RuleTarget::Block => {
            value.insert("action".into(), "reject".into());
        }
    }

    Value::Object(value)
}
