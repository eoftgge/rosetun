use rosetun_config::{ExitId, Node, NodeId, Outbound, ProxyCredentials, Rule, RuleId, RuleMatcher, RuleSet, RuleSetId, RuleTarget, Settings, StreamSettings, TlsMode, TlsParams};
use rosetun_engine::{ControlEndpoint, EngineBackend, ExtraOutbound, ProbeRenderRequest, RenderRequest};
use rosetun_engine_singbox::SingBoxBackend;
use serde_json::{Value, json};

fn proxy(socks: bool, tls: bool) -> Node {
    let credentials = ProxyCredentials { username: "fixture-user".into(), password: "пароль:@/\"%".into() };
    Node { id: NodeId::new("fixture"), name: "Example".into(), server: "2001:db8::1".into(), port: 443,
        outbound: if socks { Outbound::Socks5(credentials) } else { Outbound::Http(credentials) },
        stream: StreamSettings { tls: if tls { TlsMode::Tls(TlsParams { sni: Some("proxy.example.com".into()), ..Default::default() }) } else { TlsMode::Plain }, ..Default::default() }, raw: None }
}

#[test]
fn proxy_rendering_keeps_credentials_structured_and_dns_on_tcp() {
    let backend = SingBoxBackend::new(std::env::temp_dir());
    let rules = RuleSet::new(RuleSetId::new("fixture"), "Example", RuleTarget::Proxy);
    for (socks, tls) in [(false, false), (false, true), (true, false)] {
        let node = proxy(socks, tls);
        let rendered = backend.render(&RenderRequest { node: &node, socks: None, extra: &[], rules: &rules, lists: &[], settings: &Settings::default(), control: None, verbose_log: false }).unwrap();
        let body: Value = serde_json::from_slice(&rendered.body).unwrap();
        let outbound = &body["outbounds"][0];
        assert_eq!(outbound["type"], if socks { "socks" } else { "http" });
        assert_eq!(outbound["username"], "fixture-user");
        assert_eq!(outbound["password"], "пароль:@/\"%");
        assert_eq!(outbound["server"], "2001:db8::1");
        assert_eq!(outbound["tls"]["enabled"], if tls { json!(true) } else { Value::Null });
        assert!(outbound["tls"]["insecure"].is_null());
        assert!(outbound["tls"]["utls"].is_null());
        assert_eq!(body["dns"]["servers"][0]["type"], "https");
        assert_eq!(body["dns"]["servers"][0]["detour"], "proxy");
        assert_eq!(body["dns"]["servers"].as_array().unwrap().len(), 1);
        assert_eq!(body["route"]["final"], "proxy");
        assert!(rendered.unsupported.is_empty());
        assert!(!format!("{rendered:?}").contains("fixture-user"));
    }
}

#[test]
fn proxy_routes_preserve_direct_rules_and_never_skip_udp_to_a_fallback() {
    let backend = SingBoxBackend::new(std::env::temp_dir());
    let main = proxy(false, false);
    let extra_node = proxy(true, false);
    let exit = ExitId::new("fixture");
    let extra = [ExtraOutbound { exit: &exit, node: &extra_node, socks: None }];
    let mut rules = RuleSet::new(RuleSetId::new("fixture"), "Example", RuleTarget::Proxy);
    for (id, target, exit) in [("direct", RuleTarget::Direct, None), ("extra", RuleTarget::Exit, Some(exit.clone()))] {
        rules.rules.push(Rule { id: RuleId::new(id), enabled: true, matcher: RuleMatcher::IpCidr("198.51.100.0/24".into()), target, exit });
    }
    let rendered = backend.render(&RenderRequest { node: &main, socks: None, extra: &extra, rules: &rules, lists: &[], settings: &Settings::default(), control: None, verbose_log: false }).unwrap();
    let body: Value = serde_json::from_slice(&rendered.body).unwrap();
    let routes = body["route"]["rules"].as_array().unwrap();
    assert!(routes.iter().any(|rule| rule["outbound"] == "direct"));
    assert!(routes.iter().any(|rule| rule["outbound"] == "exit-0"));
    assert!(routes.iter().all(|rule| rule.get("network").is_none()));
    assert_eq!(body["route"]["final"], "proxy");
    assert_eq!(body["outbounds"][1]["type"], "socks");
    assert!(body["outbounds"][1].get("udp_over_tcp").is_none());
}

#[test]
fn probes_render_all_proxy_protocols_and_reject_unsupported_tls() {
    let backend = SingBoxBackend::new(std::env::temp_dir());
    let nodes = [("probe-0".into(), proxy(false, false)), ("probe-1".into(), proxy(false, true)), ("probe-2".into(), proxy(true, false))];
    let control = ControlEndpoint { address: "127.0.0.1:10800".parse().unwrap(), secret: "fixture-secret".into() };
    let rendered = backend.render_probe(&ProbeRenderRequest { nodes: &nodes, socks: &[], control: &control, interface: None }).unwrap();
    assert!(rendered.unsupported_probes.is_empty());
    let mut invalid = proxy(true, true);
    let rules = RuleSet::new(RuleSetId::new("fixture"), "Example", RuleTarget::Proxy);
    assert!(backend.render(&RenderRequest { node: &invalid, socks: None, extra: &[], rules: &rules, lists: &[], settings: &Settings::default(), control: None, verbose_log: false }).is_err());
    invalid = proxy(false, true);
    if let TlsMode::Tls(tls) = &mut invalid.stream.tls { tls.allow_insecure = true; }
    assert!(backend.render(&RenderRequest { node: &invalid, socks: None, extra: &[], rules: &rules, lists: &[], settings: &Settings::default(), control: None, verbose_log: false }).is_err());
}
