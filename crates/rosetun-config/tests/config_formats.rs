mod support;

use rosetun_config::{
    AppConfig, CONFIG_VERSION, ConfigError, CountryCode, EngineKind, Exit, ExitId, ExitTarget,
    FormatError, HwidScope, Hysteria2Params, List, ListFormat, ListId, ListSource, Node, NodeId,
    Outbound, RealityParams, Rule, RuleId, RuleMatcher, RuleTarget, Selection, StreamSettings,
    SubscriptionId, TlsMode, TlsParams, Transport, VlessParams, XhttpExtra, XhttpMode, XhttpRange,
    XhttpXmux, from_json,
};
use serde_json::{Value, json};

const ALPHA_1: &[u8] = include_bytes!("fixtures/v0.1.0-alpha.1.json");
const ALPHA_2: &[u8] = include_bytes!("fixtures/v0.1.0-alpha.2.json");
const ALPHA_3: &[u8] = include_bytes!("fixtures/v0.1.0-alpha.3.json");
const V2: &[u8] = include_bytes!("fixtures/v2.json");
const V3: &[u8] = include_bytes!("fixtures/v3.json");
const V4: &[u8] = include_bytes!("fixtures/v4.json");
const V5: &[u8] = include_bytes!("fixtures/v5.json");
const V6: &[u8] = include_bytes!("fixtures/v6.json");
const V7: &[u8] = include_bytes!("fixtures/v7.json");

fn current_config() -> AppConfig {
    let mut config = support::legacy_config();
    config.version = CONFIG_VERSION;
    config.settings.engine = EngineKind::SingBox;
    config.interface.check_updates = false;
    config.interface.skipped_version = Some("v9.9.9-test".to_owned());
    config.interface.last_update_check = Some(1_700_000_003);
    config.subscriptions[1].nodes.push(Node {
        id: NodeId::new("hysteria2"),
        name: "Hysteria2".to_owned(),
        server: "192.0.2.20".to_owned(),
        port: 8443,
        outbound: Outbound::Hysteria2(Hysteria2Params {
            password: "test-secret".to_owned(),
            obfs_password: Some("test-secret-obfs".to_owned()),
            port_ranges: vec!["8443-8445".to_owned(), "9443".to_owned()],
            up_mbps: Some(100),
            down_mbps: Some(200),
        }),
        stream: StreamSettings {
            transport: Transport::Tcp,
            tls: TlsMode::Tls(TlsParams {
                sni: Some("hysteria.example.com".to_owned()),
                alpn: vec!["h3".to_owned()],
                allow_insecure: false,
                fingerprint: Some("chrome".to_owned()),
            }),
        },
        raw: None,
    });
    config.lists = vec![
        List {
            id: ListId::new("1"),
            name: "Example domains".to_owned(),
            source: ListSource::Url("https://lists.example.com/example.txt".to_owned()),
            format: ListFormat::Text,
            updated_at: Some(1_700_000_004),
            size: Some(12),
            sha256: Some(
                "391196688aa55d3321deffa736f8d103b4813470952b748e9c2c9deb17fa60f5".to_owned(),
            ),
            categories: Vec::new(),
        },
        List {
            id: ListId::new("2"),
            name: "Example categories".to_owned(),
            source: ListSource::File {
                original_name: "geosite.dat".to_owned(),
            },
            format: ListFormat::GeoSite,
            updated_at: Some(1_700_000_005),
            size: Some(7),
            sha256: Some("a".repeat(64)),
            categories: vec!["example".to_owned()],
        },
    ];
    config.rule_sets[0].rules.push(Rule {
        id: RuleId::new("list-example"),
        enabled: true,
        matcher: RuleMatcher::List {
            list: ListId::new("2"),
            category: Some("example@cn".to_owned()),
        },
        target: RuleTarget::Direct,
        exit: None,
    });
    config
}

fn format_five_config() -> AppConfig {
    let mut config = current_config();
    let country = CountryCode::parse("CN").unwrap();
    config.exits = vec![
        Exit {
            id: ExitId::new("node-exit"),
            name: "Example node exit".to_owned(),
            target: ExitTarget::Node {
                selection: Selection {
                    subscription: SubscriptionId::new("subscription-one"),
                    node: NodeId::new("vless-reality"),
                },
                fallback: Some(country.clone()),
            },
        },
        Exit {
            id: ExitId::new("country-exit"),
            name: "Example country exit".to_owned(),
            target: ExitTarget::Country(country),
        },
    ];
    config.rule_sets[0].rules[0].target = RuleTarget::Exit;
    config.rule_sets[0].rules[0].exit = Some(ExitId::new("node-exit"));
    config
}

fn range(from: u32, to: u32) -> Option<XhttpRange> {
    Some(XhttpRange { from, to })
}

fn format_six_config() -> AppConfig {
    let mut config = format_five_config();
    config.subscriptions[1].nodes.push(Node {
        id: NodeId::new("vless-xhttp"),
        name: "VLESS XHTTP".to_owned(),
        server: "192.0.2.30".to_owned(),
        port: 443,
        outbound: Outbound::Vless(VlessParams {
            uuid: "00000000-0000-4000-8000-000000000030".to_owned(),
            flow: None,
        }),
        stream: StreamSettings {
            transport: Transport::Xhttp {
                path: "/example-xhttp".to_owned(),
                host: Some("xhttp.example.com".to_owned()),
                mode: XhttpMode::StreamOne,
                extra: XhttpExtra {
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
                        c_max_reuse_times: range(0, 0),
                        h_max_request_times: range(600, 900),
                        h_max_reusable_secs: range(1800, 3000),
                        h_keep_alive_period: Some(0),
                    }),
                },
            },
            tls: TlsMode::Reality(RealityParams {
                sni: Some("example.com".to_owned()),
                public_key: "test-public-key".to_owned(),
                short_id: Some("0123abcd".to_owned()),
                fingerprint: Some("chrome".to_owned()),
            }),
        },
        raw: None,
    });
    config
}

fn format_seven_config() -> AppConfig {
    let mut config = format_six_config();
    config.subscriptions[1].hwid_scope = HwidScope::Provider;
    config
}

fn expected_migrated_legacy_config() -> AppConfig {
    let mut config = support::legacy_config();
    config.version = CONFIG_VERSION;
    config.settings.engine = EngineKind::SingBox;
    config
}

fn value(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("fixture contains JSON")
}

#[test]
fn released_configurations_migrate_to_the_expected_configuration() {
    assert_eq!(
        CONFIG_VERSION, 7,
        "released fixtures require format version seven"
    );
    let expected = expected_migrated_legacy_config();

    for (name, bytes) in [
        ("v0.1.0-alpha.1", ALPHA_1),
        ("v0.1.0-alpha.2", ALPHA_2),
        ("v0.1.0-alpha.3", ALPHA_3),
    ] {
        let (config, migrated_from) = from_json(bytes).unwrap_or_else(|error| {
            panic!("{name} fixture should load: {error}");
        });
        assert_eq!(
            migrated_from,
            Some(1),
            "{name} must report its source version"
        );
        assert_eq!(config, expected, "{name} must preserve every saved setting");
    }
}

#[test]
fn current_configuration_fixture_guards_the_serialized_format() {
    let expected = format_seven_config();
    let (loaded, migrated_from) = from_json(V7).expect("current fixture should load");

    assert_eq!(migrated_from, None);
    assert_eq!(loaded, expected);
    assert_eq!(loaded.exits.len(), 2);
    assert!(matches!(
        &loaded.exits[0].target,
        ExitTarget::Node { selection, fallback }
            if selection.subscription == SubscriptionId::new("subscription-one")
                && selection.node == NodeId::new("vless-reality")
                && fallback.as_ref() == CountryCode::parse("CN").as_ref()
    ));
    assert_eq!(
        loaded.exits[1].target,
        ExitTarget::Country(CountryCode::parse("CN").unwrap())
    );
    assert_eq!(loaded.rule_sets[0].rules[0].target, RuleTarget::Exit);
    assert_eq!(
        loaded.rule_sets[0].rules[0].exit,
        Some(loaded.exits[0].id.clone())
    );
    let encoded = serde_json::to_vec(&loaded).expect("serialize current fixture");
    let (round_trip, migrated_from) = from_json(&encoded).expect("current fixture round trip");
    assert_eq!(migrated_from, None);
    assert_eq!(round_trip.exits, loaded.exits);
    assert_eq!(
        round_trip.rule_sets[0].rules[0],
        loaded.rule_sets[0].rules[0]
    );
    assert_eq!(
        serde_json::to_value(&expected).expect("serialize expected configuration"),
        value(V7),
        "the serialized configuration shape changed; bump CONFIG_VERSION, add a migration, and add a new fixture instead of changing v7.json"
    );
}

fn with_machine_scope(mut config: Value) -> Value {
    for subscription in config["subscriptions"].as_array_mut().unwrap() {
        subscription["hwid_scope"] = json!("machine");
    }
    config
}

#[test]
fn version_five_loads_and_saves_as_version_seven() {
    let (config, migrated_from) = from_json(V5).expect("version five should migrate");
    assert_eq!(migrated_from, Some(5));
    assert_eq!(config, format_five_config());

    let mut expected = with_machine_scope(value(V5));
    expected["version"] = json!(7);
    assert_eq!(
        serde_json::to_value(&config).expect("serialize migrated configuration"),
        expected
    );
}

#[test]
fn version_six_keeps_the_machine_id_of_every_subscription() {
    let (config, migrated_from) = from_json(V6).expect("version six should migrate");
    assert_eq!(migrated_from, Some(6));
    assert_eq!(config, format_six_config());
    assert!(
        config
            .subscriptions
            .iter()
            .all(|subscription| subscription.hwid_scope == HwidScope::Machine)
    );

    let mut expected = with_machine_scope(value(V6));
    expected["version"] = json!(7);
    assert_eq!(
        serde_json::to_value(&config).expect("serialize migrated configuration"),
        expected
    );
}

#[test]
fn version_six_overrides_a_stray_hwid_scope_with_machine() {
    let mut input = value(V6);
    input["subscriptions"][0]["hwid_scope"] = json!("provider");

    let (config, _) = from_json(&serde_json::to_vec(&input).unwrap()).expect("version six");
    assert_eq!(config.subscriptions[0].hwid_scope, HwidScope::Machine);
}

#[test]
fn a_format_seven_subscription_without_hwid_scope_keeps_the_machine_id() {
    let mut input = value(V7);
    input["subscriptions"][1]
        .as_object_mut()
        .unwrap()
        .remove("hwid_scope");

    let (config, migrated_from) =
        from_json(&serde_json::to_vec(&input).unwrap()).expect("hand-edited format seven");
    assert_eq!(migrated_from, None);
    assert_eq!(config.subscriptions[1].hwid_scope, HwidScope::Machine);
}

#[test]
fn xhttp_without_extra_omits_it_and_reads_defaults() {
    let mut input = value(V6);
    let nodes = &mut input["subscriptions"][1]["nodes"];
    let last = nodes.as_array().unwrap().len() - 1;
    nodes[last]["stream"]["transport"] = json!({ "xhttp": { "path": "/example-xhttp" } });

    let (config, _) = from_json(&serde_json::to_vec(&input).unwrap()).expect("minimal XHTTP");
    let node = config.subscriptions[1].nodes.last().unwrap();
    assert_eq!(
        node.stream.transport,
        Transport::Xhttp {
            path: "/example-xhttp".to_owned(),
            host: None,
            mode: XhttpMode::Auto,
            extra: XhttpExtra::default(),
        }
    );
    assert_eq!(
        serde_json::to_value(&node.stream.transport).unwrap(),
        json!({ "xhttp": { "path": "/example-xhttp", "mode": "auto" } })
    );
}

#[test]
fn version_four_adds_empty_exits() {
    let (config, migrated_from) = from_json(V4).expect("version four should migrate");
    assert_eq!(migrated_from, Some(4));
    assert_eq!(config, current_config());
    assert!(config.exits.is_empty());
}

#[test]
fn version_three_migrates_the_unavailable_xray_engine() {
    let (config, migrated_from) = from_json(V3).expect("version three should migrate");
    assert_eq!(migrated_from, Some(3));
    assert_eq!(config, current_config());
    assert_eq!(config.settings.engine, EngineKind::SingBox);
}

#[test]
fn version_two_configuration_adds_empty_lists() {
    let (config, migrated_from) = from_json(V2).expect("version two should migrate");
    let mut expected = current_config();
    expected.lists.clear();
    expected.rule_sets[0].rules.pop();
    assert_eq!(migrated_from, Some(2));
    assert_eq!(config, expected);
}

#[test]
fn absent_version_is_reported_as_a_version_one_migration() {
    let mut old = value(ALPHA_1);
    old.as_object_mut()
        .expect("fixture root is an object")
        .remove("version");

    let (config, migrated_from) =
        from_json(&serde_json::to_vec(&old).expect("serialize old configuration"))
            .expect("missing version should mean version one");

    assert_eq!(migrated_from, Some(1));
    assert_eq!(config, expected_migrated_legacy_config());
}

#[test]
fn unknown_fields_do_not_prevent_loading() {
    let (config, migrated_from) =
        from_json(br#"{"version":2,"unknown_root":"ignored","settings":{"unknown_setting":true}}"#)
            .expect("unknown fields remain accepted");
    assert_eq!(migrated_from, Some(2));
    assert_eq!(config, AppConfig::default());
}

#[test]
fn invalid_and_future_versions_are_rejected_without_echoing_sensitive_values() {
    assert!(matches!(
        from_json(b"[]"),
        Err(FormatError::UnexpectedValue)
    ));

    for input in [
        json!({ "version": 0 }),
        json!({ "version": -1 }),
        json!({ "version": "one" }),
        json!({ "version": 1.0 }),
        json!({ "version": 4_294_967_296_u64 }),
        json!({ "version": null }),
    ] {
        assert!(
            matches!(
                from_json(&serde_json::to_vec(&input).expect("serialize invalid version")),
                Err(FormatError::UnexpectedValue)
            ),
            "{input} must be rejected as an invalid version"
        );
    }

    let future_version = CONFIG_VERSION + 1;
    assert!(matches!(
        from_json(&serde_json::to_vec(&json!({ "version": future_version }))
            .expect("serialize future version")),
        Err(FormatError::Config(ConfigError::UnsupportedVersion { found, expected }))
            if found == future_version && expected == CONFIG_VERSION
    ));

    let secret = "https://sub.example.com/private?token=test-secret";
    let error =
        from_json(format!(r#"{{"version":1,"subscriptions":[{{"url":"{secret}"}}"#).as_bytes())
            .expect_err("invalid JSON must fail");
    assert!(
        !error.to_string().contains(secret),
        "configuration errors must not echo subscription URLs"
    );
    assert!(
        !error.to_string().contains("test-secret"),
        "configuration errors must not echo secrets"
    );

    let malformed_value = format!(r#"{{"version":1,"subscriptions":"{secret}"}}"#);
    let error = from_json(malformed_value.as_bytes()).expect_err("wrong field type must fail");
    assert!(matches!(error, FormatError::UnexpectedValue));
    assert!(!error.to_string().contains(secret));
    assert!(!error.to_string().contains("test-secret"));
}

#[test]
fn exit_references_and_country_codes_are_validated() {
    let mut config = current_config();
    let id = ExitId::new("1");
    config.exits.push(Exit {
        id: id.clone(),
        name: "Example exit".into(),
        target: ExitTarget::Country(CountryCode::parse("GB").unwrap()),
    });
    let rule = &mut config.rule_sets[0].rules[0];
    rule.target = RuleTarget::Exit;
    rule.exit = Some(id.clone());
    assert!(config.validate().is_ok());
    let encoded = serde_json::to_vec(&config).unwrap();
    assert_eq!(from_json(&encoded).unwrap().0, config);

    config.exits.clear();
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidRuleExit)
    ));
    config.exits.push(Exit {
        id: id.clone(),
        name: "Example exit".into(),
        target: ExitTarget::Country(CountryCode::parse("GB").unwrap()),
    });
    config.rule_sets[0].rules[0].exit = None;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidRuleExit)
    ));
    config.rule_sets[0].rules[0].target = RuleTarget::Direct;
    config.rule_sets[0].rules[0].exit = Some(id.clone());
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidRuleExit)
    ));
    config.exits.push(config.exits[0].clone());
    assert!(matches!(config.validate(), Err(ConfigError::InvalidExitId)));

    for code in ["uk", "UK", "ZZ", "U1"] {
        let mut input = value(V5);
        input["exits"] = json!([{"id":"1","name":"Example exit","target":{"country":code}}]);
        assert!(matches!(
            from_json(&serde_json::to_vec(&input).unwrap()),
            Err(FormatError::UnexpectedValue)
        ));
    }
}

#[test]
fn list_references_and_metadata_are_validated() {
    let mut config = current_config();
    assert!(config.validate().is_ok());

    config.lists.pop();
    assert!(matches!(config.validate(), Err(ConfigError::MissingList)));
    config.rule_sets[0].rules.last_mut().unwrap().enabled = false;
    assert!(matches!(config.validate(), Err(ConfigError::MissingList)));

    let mut config = current_config();
    config.lists[1].id = ListId::new("../example.invalid");
    assert!(matches!(config.validate(), Err(ConfigError::InvalidListId)));

    let mut config = current_config();
    config.lists[1].categories.push("example".to_owned());
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidListMetadata)
    ));

    let mut config = current_config();
    config.lists[1].categories = vec!["other".to_owned()];
    assert!(
        config.validate().is_ok(),
        "a vanished category must remain loadable"
    );
    assert!(from_json(&serde_json::to_vec(&config).unwrap()).is_ok());

    let mut config = current_config();
    config.lists[1].format = ListFormat::GeoIp;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidListCategory)
    ));
}
