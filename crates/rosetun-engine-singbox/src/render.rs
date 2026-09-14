use rosetun_config::{
    DomainMatch, LogLevel, Node, Outbound, ProcessMatch, RuleMatcher, RuleSet, RuleTarget,
    Settings, TlsMode, Transport,
};
use rosetun_core_engine::{EngineError, RenderRequest, RenderedConfig};
use serde_json::{Map, Value, json};

const TAG_PROXY: &str = "proxy";
const TAG_DIRECT: &str = "direct";
const TAG_BLOCK: &str = "block";

pub fn render(request: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError> {
    let config = json!({
        "log": log_section(request.settings),
        "inbounds": [tun_inbound(request.settings)],
        "outbounds": [
            proxy_outbound(request.node)?,
            json!({ "type": "direct", "tag": TAG_DIRECT }),
            json!({ "type": "block", "tag": TAG_BLOCK }),
        ],
        "route": route_section(request.rules),
    });

    let body = serde_json::to_vec_pretty(&config)
        .map_err(|error| EngineError::Render(error.to_string()))?;
    Ok(RenderedConfig {
        file_name: "config.json".to_owned(),
        body,
    })
}

fn log_section(settings: &Settings) -> Value {
    let level = match settings.log_level {
        LogLevel::Error => "error",
        LogLevel::Warn => "warn",
        LogLevel::Info => "info",
        LogLevel::Debug => "debug",
        LogLevel::Trace => "trace",
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
            let fingerprint = params.fingerprint.clone().unwrap_or_else(|| "chrome".into());
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

fn route_section(rules: &RuleSet) -> Value {
    let route_rules: Vec<Value> = rules.enabled().map(route_rule).collect();
    json!({
        "rules": route_rules,
        "final": tag_for(rules.default_target),
        "auto_detect_interface": true,
    })
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
    value.insert("outbound".into(), tag_for(rule.target).into());
    Value::Object(value)
}

fn tag_for(target: RuleTarget) -> &'static str {
    match target {
        RuleTarget::Proxy => TAG_PROXY,
        RuleTarget::Direct => TAG_DIRECT,
        RuleTarget::Block => TAG_BLOCK,
    }
}