mod support;

use rosetun_config::{
    AppConfig, CONFIG_VERSION, ConfigError, FormatError, Hysteria2Params, Node, NodeId, Outbound,
    StreamSettings, TlsMode, TlsParams, Transport, from_json,
};
use serde_json::{Value, json};

const ALPHA_1: &[u8] = include_bytes!("fixtures/v0.1.0-alpha.1.json");
const ALPHA_2: &[u8] = include_bytes!("fixtures/v0.1.0-alpha.2.json");
const ALPHA_3: &[u8] = include_bytes!("fixtures/v0.1.0-alpha.3.json");
const V2: &[u8] = include_bytes!("fixtures/v2.json");

fn current_config() -> AppConfig {
    let mut config = support::legacy_config();
    config.version = CONFIG_VERSION;
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
    config
}

fn expected_migrated_legacy_config() -> AppConfig {
    let mut config = support::legacy_config();
    config.version = CONFIG_VERSION;
    config
}

fn value(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("fixture contains JSON")
}

#[test]
fn released_configurations_migrate_to_the_expected_configuration() {
    assert_eq!(
        CONFIG_VERSION, 2,
        "released fixtures require format version two"
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
    let expected = current_config();
    let (loaded, migrated_from) = from_json(V2).expect("current fixture should load");

    assert_eq!(migrated_from, None);
    assert_eq!(loaded, expected);
    assert_eq!(
        serde_json::to_value(&expected).expect("serialize expected configuration"),
        value(V2),
        "the serialized configuration shape changed; bump CONFIG_VERSION, add a migration, and add a new fixture instead of changing v2.json"
    );
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
    assert_eq!(migrated_from, None);
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
