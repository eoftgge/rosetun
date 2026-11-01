use rosetun_config::{
    Node, NodeId, Outbound, ProxyCredentials, StreamSettings, TlsMode, TlsParams, Transport,
    XrayUse, uses_xray,
};

fn proxy(socks: bool) -> Node {
    let credentials = ProxyCredentials {
        username: "fixture-user".into(),
        password: "пароль:@/%".into(),
    };
    Node {
        id: NodeId::new("fixture"),
        name: "Example".into(),
        server: "2001:db8::1".into(),
        port: 1080,
        outbound: if socks {
            Outbound::Socks5(credentials)
        } else {
            Outbound::Http(credentials)
        },
        stream: StreamSettings::default(),
        raw: None,
    }
}

#[test]
fn proxy_nodes_round_trip_and_stay_on_sing_box() {
    for (socks, tls) in [(false, false), (false, true), (true, false)] {
        let mut node = proxy(socks);
        if tls {
            node.stream.tls = TlsMode::Tls(TlsParams::default());
        }
        assert!(node.validate_proxy().is_ok());
        let encoded = serde_json::to_vec(&node).unwrap();
        assert_eq!(serde_json::from_slice::<Node>(&encoded).unwrap(), node);
        for setting in [XrayUse::Auto, XrayUse::Off, XrayUse::Always] {
            assert!(!uses_xray(&node, setting));
        }
        let debug = format!("{node:?}");
        assert!(!debug.contains("fixture-user"));
        assert!(!debug.contains("пароль"));
    }
}

#[test]
fn invalid_proxy_endpoints_credentials_and_streams_fail_validation() {
    for server in [
        "",
        "https://example.com",
        "example.com/path",
        "[2001:db8::1]",
        "bad name",
        "-invalid.example",
    ] {
        let mut node = proxy(false);
        node.server = server.into();
        assert!(node.validate_proxy().is_err());
    }
    for server in ["proxy.example.com", "192.0.2.1", "2001:db8::1"] {
        let mut node = proxy(false);
        node.server = server.into();
        assert!(node.validate_proxy().is_ok());
    }
    let mut node = proxy(false);
    node.port = 0;
    assert!(node.validate_proxy().is_err());
    node = proxy(false);
    node.stream.transport = Transport::Grpc {
        service_name: "fixture".into(),
    };
    assert!(node.validate_proxy().is_err());
    node = proxy(false);
    node.stream.tls = TlsMode::Tls(TlsParams {
        allow_insecure: true,
        ..Default::default()
    });
    assert!(node.validate_proxy().is_err());
    node = proxy(true);
    node.stream.tls = TlsMode::Tls(Default::default());
    assert!(node.validate_proxy().is_err());
    node = proxy(true);
    if let Outbound::Socks5(credentials) = &mut node.outbound {
        credentials.password = "x".repeat(256);
    }
    assert!(node.validate_proxy().is_err());
}

#[test]
fn reports_remove_proxy_credentials_and_uris() {
    let report = rosetun_config::redact_report_text(
        "username=fixture-user password=fixture-password https://fixture-user:fixture-password@example.com:443",
    );
    assert!(!report.contains("fixture-user"));
    assert!(!report.contains("fixture-password"));
}

#[test]
fn protocol_credentials_and_tls_names_are_validated_before_rendering() {
    for (socks, username, password) in [
        (false, "", "password"),
        (false, "user:name", "password"),
        (false, "user", "line\nsecret"),
        (true, "user", ""),
        (true, "", "password"),
        (true, "user\0name", "password"),
    ] {
        let mut node = proxy(socks);
        let credentials = ProxyCredentials {
            username: username.into(),
            password: password.into(),
        };
        node.outbound = if socks {
            Outbound::Socks5(credentials)
        } else {
            Outbound::Http(credentials)
        };
        assert!(node.validate_proxy().is_err());
    }
    for name in ["", "bad name", "bad!name", "example.com/path"] {
        let mut node = proxy(false);
        node.stream.tls = TlsMode::Tls(TlsParams {
            sni: Some(name.into()),
            ..Default::default()
        });
        assert!(node.validate_proxy().is_err());
    }
    let mut node = proxy(true);
    if let Outbound::Socks5(credentials) = &mut node.outbound {
        credentials.username = "я".repeat(128);
    }
    assert!(node.validate_proxy().is_err());
}
