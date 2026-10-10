use rosetun_config::{
    AppConfig, DnsSettings, DomainMatch, EngineKind, InterfaceSettings, LanguageSetting, LogLevel,
    Node, NodeId, Outbound, ProcessMatch, RealityParams, Rule, RuleId, RuleMatcher, RuleSet,
    RuleSetId, RuleTarget, RuleTemplate, Selection, Settings, ShadowsocksParams, StreamSettings,
    Subscription, SubscriptionId, SubscriptionInfo, TlsMode, TlsParams, Transport, TrojanParams,
    TunSettings, VlessParams, VmessParams,
};

fn node(
    id: &str,
    name: &str,
    server: &str,
    port: u16,
    outbound: Outbound,
    stream: StreamSettings,
) -> Node {
    Node {
        id: NodeId::new(id),
        name: name.to_owned(),
        server: server.to_owned(),
        port,
        outbound,
        stream,
        raw: None,
    }
}

fn rule(id: &str, enabled: bool, matcher: RuleMatcher, target: RuleTarget) -> Rule {
    Rule {
        id: RuleId::new(id),
        enabled,
        matcher,
        target,
    }
}

pub(crate) fn legacy_config() -> AppConfig {
    let first_subscription = SubscriptionId::new("subscription-one");
    let second_subscription = SubscriptionId::new("subscription-two");
    let active_node = NodeId::new("vless-reality");
    let rule_set = RuleSetId::new("routing");

    let vless = node(
        "vless-reality",
        "VLESS Reality",
        "192.0.2.10",
        443,
        Outbound::Vless(VlessParams {
            uuid: "00000000-0000-4000-8000-000000000001".to_owned(),
            flow: Some("xtls-rprx-vision".to_owned()),
        }),
        StreamSettings {
            transport: Transport::Tcp,
            tls: TlsMode::Reality(RealityParams {
                sni: Some("reality.example.com".to_owned()),
                public_key: "test-reality-public-key".to_owned(),
                short_id: Some("01234567".to_owned()),
                fingerprint: Some("chrome".to_owned()),
            }),
        },
    );
    let vmess = node(
        "vmess-ws-tls",
        "VMess WebSocket TLS",
        "198.51.100.10",
        8443,
        Outbound::Vmess(VmessParams {
            uuid: "00000000-0000-4000-8000-000000000002".to_owned(),
            alter_id: 7,
            security: Some("auto".to_owned()),
        }),
        StreamSettings {
            transport: Transport::Ws {
                path: "/vmess".to_owned(),
                host: Some("ws.example.com".to_owned()),
            },
            tls: TlsMode::Tls(TlsParams {
                sni: Some("tls.example.com".to_owned()),
                alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
                allow_insecure: true,
                fingerprint: Some("firefox".to_owned()),
            }),
        },
    );
    let trojan = node(
        "trojan-grpc",
        "Trojan gRPC",
        "203.0.113.10",
        443,
        Outbound::Trojan(TrojanParams {
            password: "test-secret".to_owned(),
        }),
        StreamSettings {
            transport: Transport::Grpc {
                service_name: "trojan-grpc".to_owned(),
            },
            tls: TlsMode::Tls(TlsParams {
                sni: Some("trojan.example.com".to_owned()),
                alpn: vec!["h2".to_owned()],
                allow_insecure: false,
                fingerprint: None,
            }),
        },
    );
    let shadowsocks = node(
        "shadowsocks",
        "Shadowsocks",
        "2001:db8::10",
        8388,
        Outbound::Shadowsocks(ShadowsocksParams {
            method: "aes-256-gcm".to_owned(),
            password: "test-secret".to_owned(),
        }),
        StreamSettings::default(),
    );

    AppConfig {
        version: 1,
        settings: Settings {
            engine: EngineKind::Xray,
            kill_switch: true,
            auto_reconnect: false,
            allow_lan: true,
            autostart: true,
            tun: TunSettings {
                name: "rosetun-test".to_owned(),
                mtu: 1420,
                ipv4: "192.0.2.1/24".to_owned(),
                ipv6: Some("2001:db8::1/64".to_owned()),
                auto_route: false,
            },
            dns: DnsSettings {
                server: "192.0.2.53".parse().expect("documentation address"),
                server_name: "dns.example.com".to_owned(),
                port: Some(8443),
                path: Some("/dns-query".to_owned()),
            },
            log_level: LogLevel::Trace,
            verbose_log_until: Some(1_700_000_000),
        },
        interface: InterfaceSettings {
            scale_percent: 125,
            close_to_tray: false,
            connect_on_start: true,
            auto_update_subscriptions: false,
            language: LanguageSetting::Russian,
            reduce_motion: true,
            ..InterfaceSettings::default()
        },
        subscriptions: vec![
            Subscription {
                id: first_subscription.clone(),
                name: "Primary provider".to_owned(),
                url: "https://sub.example.com/primary".to_owned(),
                nodes: vec![vless, vmess],
                auto_update: true,
                updated_at_unix: Some(1_700_000_001),
                user_agent: Some("Rosetun fixture".to_owned()),
                send_hwid: false,
                info: Some(SubscriptionInfo {
                    upload: 100,
                    download: 200,
                    total: Some(1_000),
                    expire_unix: Some(1_800_000_000),
                }),
                update_interval_hours: Some(24),
                support_url: Some("https://sub.example.com/support".to_owned()),
                web_page_url: Some("https://sub.example.com/account".to_owned()),
                announce: Some("Provider announcement".to_owned()),
                notices: vec!["Provider notice".to_owned()],
            },
            Subscription {
                id: second_subscription,
                name: "Secondary provider".to_owned(),
                url: "https://sub.example.com/secondary".to_owned(),
                nodes: vec![trojan, shadowsocks],
                auto_update: false,
                updated_at_unix: Some(1_700_000_002),
                user_agent: Some("Rosetun fixture secondary".to_owned()),
                send_hwid: true,
                info: Some(SubscriptionInfo {
                    upload: 300,
                    download: 400,
                    total: Some(2_000),
                    expire_unix: Some(1_900_000_000),
                }),
                update_interval_hours: Some(12),
                support_url: Some("https://sub.example.com/secondary-support".to_owned()),
                web_page_url: Some("https://sub.example.com/secondary-account".to_owned()),
                announce: Some("Secondary announcement".to_owned()),
                notices: vec![
                    "Secondary notice".to_owned(),
                    "Maintenance notice".to_owned(),
                ],
            },
        ],
        lists: Vec::new(),
        rule_sets: vec![
            RuleSet {
                id: rule_set.clone(),
                name: "Full routing rules".to_owned(),
                default_target: RuleTarget::Proxy,
                rules: vec![
                    rule(
                        "domain-exact",
                        true,
                        RuleMatcher::Domain(DomainMatch::Exact("exact.example.com".to_owned())),
                        RuleTarget::Direct,
                    ),
                    rule(
                        "domain-suffix",
                        true,
                        RuleMatcher::Domain(DomainMatch::Suffix("suffix.example.com".to_owned())),
                        RuleTarget::Proxy,
                    ),
                    rule(
                        "domain-keyword",
                        false,
                        RuleMatcher::Domain(DomainMatch::Keyword("keyword".to_owned())),
                        RuleTarget::Block,
                    ),
                    rule(
                        "process-name",
                        true,
                        RuleMatcher::Process(ProcessMatch::Name("example.exe".to_owned())),
                        RuleTarget::Direct,
                    ),
                    rule(
                        "process-path",
                        true,
                        RuleMatcher::Process(ProcessMatch::Path(
                            "C:/Program Files/Example/example.exe".into(),
                        )),
                        RuleTarget::Block,
                    ),
                    rule(
                        "ip-v4",
                        true,
                        RuleMatcher::IpCidr("198.51.100.0/24".to_owned()),
                        RuleTarget::Proxy,
                    ),
                    rule(
                        "ip-v6",
                        true,
                        RuleMatcher::IpCidr("2001:db8::/32".to_owned()),
                        RuleTarget::Direct,
                    ),
                    rule(
                        "template-russian-sites",
                        true,
                        RuleMatcher::Template(RuleTemplate::RussianSites),
                        RuleTarget::Direct,
                    ),
                    rule(
                        "template-messengers",
                        true,
                        RuleMatcher::Template(RuleTemplate::Messengers),
                        RuleTarget::Proxy,
                    ),
                    rule(
                        "template-youtube",
                        false,
                        RuleMatcher::Template(RuleTemplate::Youtube),
                        RuleTarget::Block,
                    ),
                    rule(
                        "template-torrents",
                        true,
                        RuleMatcher::Template(RuleTemplate::Torrents),
                        RuleTarget::Direct,
                    ),
                ],
            },
            RuleSet {
                id: RuleSetId::new("fallback"),
                name: "Fallback rules".to_owned(),
                default_target: RuleTarget::Block,
                rules: vec![rule(
                    "fallback-domain",
                    true,
                    RuleMatcher::Domain(DomainMatch::Suffix("fallback.example.com".to_owned())),
                    RuleTarget::Direct,
                )],
            },
        ],
        active: Some(Selection {
            subscription: first_subscription,
            node: active_node,
        }),
        active_rule_set: Some(rule_set),
    }
}
