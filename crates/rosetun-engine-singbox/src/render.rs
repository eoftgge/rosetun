use rosetun_config::{
    DnsSettings, DomainMatch, ListRef, LogLevel, Node, Outbound, ProcessMatch, RuleId, RuleMatcher,
    RuleSet, RuleTarget, Settings, TlsMode, Transport, UploadedListFormat, list_tag,
};
use rosetun_engine::errors::EngineError;
use rosetun_engine::{ProbeRenderRequest, RenderRequest, RenderedConfig, RuleCapabilities};
use serde_json::{Map, Value, json};

pub(crate) const TAG_PROXY: &str = "proxy";
const TAG_DIRECT: &str = "direct";
const TAG_DNS_PROXY: &str = "dns-proxy";
const DEFAULT_FINGERPRINT: &str = "chrome";

pub(crate) const RULE_CAPABILITIES: RuleCapabilities = RuleCapabilities {
    domain_exact: true,
    domain_suffix: true,
    domain_keyword: true,
    process_name: true,
    process_path: true,
    ip_cidr: true,
    lists: true,
};

pub fn render(request: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError> {
    let (route, unsupported) = route_section_with_lists(
        request.rules,
        RULE_CAPABILITIES,
        request.settings.allow_lan,
        request.lists,
    );
    let mut config = json!({
        "log": log_section(request),
        "dns": dns_section(&request.settings.dns)?,
        "inbounds": [tun_inbound(request.settings)],
        "outbounds": [
            proxy_outbound(request.node, TAG_PROXY)?,
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
        unsupported_probes: Vec::new(),
    })
}

pub(crate) fn render_probe(
    request: &ProbeRenderRequest<'_>,
) -> Result<RenderedConfig, EngineError> {
    let mut outbounds = Vec::with_capacity(request.nodes.len() + 1);
    let mut unsupported_probes = Vec::new();
    for (tag, node) in request.nodes {
        match proxy_outbound(node, tag) {
            Ok(outbound) => outbounds.push(outbound),
            Err(EngineError::Unsupported(_)) => unsupported_probes.push(tag.clone()),
            Err(error) => return Err(error),
        }
    }
    outbounds.push(json!({ "type": "direct", "tag": TAG_DIRECT }));

    let route = match request.interface {
        Some(interface) => json!({ "final": TAG_DIRECT, "default_interface": interface }),
        None => json!({ "final": TAG_DIRECT, "auto_detect_interface": true }),
    };
    let config = json!({
        "log": { "level": "info", "timestamp": true },
        "outbounds": outbounds,
        "route": route,
        "experimental": { "clash_api": {
            "external_controller": request.control.address.to_string(),
            "secret": request.control.secret,
        } },
    });
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

fn proxy_outbound(node: &Node, tag: &str) -> Result<Value, EngineError> {
    let mut outbound = Map::new();
    outbound.insert("tag".into(), tag.into());
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
        Outbound::Unknown { scheme, .. } => {
            return Err(EngineError::Unsupported(format!(
                "protocol {scheme} not supported by the sing box backend"
            )));
        }
    }

    if let Some(tls) = tls_section(
        &node.stream.tls,
        !matches!(&node.outbound, Outbound::Hysteria2(_)),
    ) {
        outbound.insert("tls".into(), tls);
    }
    if let Some(transport) = transport_section(&node.stream.transport) {
        outbound.insert("transport".into(), transport);
    }

    Ok(Value::Object(outbound))
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

#[cfg(test)]
pub(crate) fn route_section(
    rules: &RuleSet,
    capabilities: RuleCapabilities,
    allow_lan: bool,
) -> (Value, Vec<RuleId>) {
    route_section_with_lists(rules, capabilities, allow_lan, &[])
}

fn route_section_with_lists(
    rules: &RuleSet,
    capabilities: RuleCapabilities,
    allow_lan: bool,
    lists: &[ListRef],
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
    let mut used_lists = Vec::<&ListRef>::new();

    for rule in rules.enabled() {
        if !capabilities.supports(&rule.matcher) {
            unsupported.push(rule.id.clone());
            continue;
        }
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
                        route_action(&mut value, rule.target);
                        Some(Value::Object(value))
                    }
                    _ => None,
                }
            }
            _ => route_rule(rule),
        };
        if let Some(value) = value {
            route_rules.push(value);
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

fn route_rule(rule: &rosetun_config::Rule) -> Option<Value> {
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
        RuleMatcher::List { .. } | RuleMatcher::Template(_) => return None,
    }

    route_action(&mut value, rule.target);

    Some(Value::Object(value))
}

fn route_action(value: &mut Map<String, Value>, target: RuleTarget) {
    match target {
        RuleTarget::Proxy | RuleTarget::Direct => {
            value.insert("action".into(), "route".into());
            value.insert(
                "outbound".into(),
                match target {
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
}

#[cfg(test)]
mod tests {
    use rosetun_config::{
        Hysteria2Params, ListId, NodeId, Rule, RuleSetId, RuleTemplate, StreamSettings, TlsParams,
    };

    use super::*;

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
                "template",
                RuleMatcher::Template(RuleTemplate::Torrents),
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
            });
        }
        let rules = rules.with_templates_expanded();
        let mut settings = Settings {
            kill_switch: true,
            allow_lan: true,
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
        };
        let lists = [ListRef {
            tag: list_tag(&ListId::new("golden-list"), None),
            sha256: "a".repeat(64),
            format: UploadedListFormat::Source,
        }];
        let rendered = render(&RenderRequest {
            node: &node,
            rules: &rules,
            lists: &lists,
            settings: &settings,
            control: Some(&control),
            verbose_log: false,
        })
        .unwrap();
        assert!(rendered.unsupported.is_empty());
        assert_eq!(
            rendered.body,
            include_bytes!("../tests/fixtures/full-config.json")
        );
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
        };
        assert_eq!(route_rule(&list), None);
        set.rules.push(list.clone());
        let (route, unsupported) = route_section(&set, RuleCapabilities::ALL, false);
        assert_eq!(unsupported, vec![list.id]);
        assert_eq!(route["rules"].as_array().unwrap().len(), 2);
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
            });
        }
        let (route, unsupported) =
            route_section_with_lists(&set, RULE_CAPABILITIES, false, &[reference]);
        assert!(unsupported.is_empty());
        assert_eq!(
            route["rule_set"],
            json!([{
                "type": "local", "tag": tag, "format": "binary", "path": format!("{tag}.srs")
            }])
        );
        assert_eq!(
            route["rules"][2],
            json!({
                "rule_set": [tag], "action": "route", "outbound": "direct"
            })
        );
        assert_eq!(
            route["rules"][3],
            json!({"rule_set": [tag], "action": "reject"})
        );
        assert!(
            route_section_with_lists(&set, RuleCapabilities::NONE, false, &[])
                .1
                .len()
                == 2
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
        });
        let reference = ListRef {
            tag: tag.clone(),
            sha256: "b".repeat(64),
            format: UploadedListFormat::Source,
        };
        let (route, unsupported) =
            route_section_with_lists(&set, RULE_CAPABILITIES, false, &[reference]);
        assert_eq!(unsupported, [vanished]);
        assert_eq!(route["rules"].as_array().unwrap().len(), 3);
        assert_eq!(
            route["rules"][2],
            json!({
                "rule_set": [tag], "action": "route", "outbound": "direct"
            })
        );
        assert_eq!(route["rule_set"][0]["format"], "source");
        assert_eq!(route["rule_set"][0]["path"], format!("{tag}.json"));
    }

    #[test]
    fn unexpanded_template_is_reported_without_a_match_all_route() {
        let mut set = RuleSet::new(RuleSetId::new("set"), "Test", RuleTarget::Proxy);
        let template = Rule {
            id: RuleId::new("template"),
            enabled: true,
            matcher: RuleMatcher::Template(RuleTemplate::RussianSites),
            target: RuleTarget::Direct,
        };
        assert_eq!(route_rule(&template), None);
        set.rules.push(template.clone());
        let (route, unsupported) = route_section(&set, RuleCapabilities::ALL, false);
        assert_eq!(unsupported, vec![template.id]);
        assert_eq!(route["rules"].as_array().unwrap().len(), 2);
    }
}
