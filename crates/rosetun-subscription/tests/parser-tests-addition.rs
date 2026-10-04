// Add to crates/rosetun-subscription/tests/parser.rs.
// Each test is tagged with the review item it checks; until that fix lands it
// fails on purpose.

// Fixes 2 and 4: 3x-ui flat Xray outbounds and its socks info record.
#[test]
fn xray_3x_ui_flat_outbounds_and_info_record() {
    let result = parsed(include_str!("fixtures/xray-3x-ui.json"));
    assert_eq!(result.format, Format::XrayJson);
    assert_eq!(result.nodes.len(), 4);

    let reality = &result.nodes[0];
    assert_eq!(reality.name, "🇩🇪 Reality-test@example.com");
    assert_eq!(reality.server, "reality.example.com");
    assert_eq!(reality.port, 443);
    let Outbound::Vless(vless) = &reality.outbound else {
        panic!("expected VLESS");
    };
    assert_eq!(vless.uuid, UUID);
    assert_eq!(vless.flow.as_deref(), Some("xtls-rprx-vision"));
    let TlsMode::Reality(params) = &reality.stream.tls else {
        panic!("expected Reality");
    };
    assert_eq!(
        params.public_key,
        "dGVzdC1yZWFsaXR5LXB1YmxpYy1rZXktZm9yLXRlc3Q"
    );
    assert_eq!(params.short_id.as_deref(), Some("6ba85179e30d4fc2"));
    assert_eq!(params.sni.as_deref(), Some("www.example.com"));
    assert_eq!(params.fingerprint.as_deref(), Some("chrome"));

    let vmess = &result.nodes[1];
    let Outbound::Vmess(params) = &vmess.outbound else {
        panic!("expected VMess");
    };
    assert_eq!(params.uuid, "22222222-2222-2222-2222-222222222222");
    assert_eq!(params.security.as_deref(), Some("auto"));
    assert_eq!(
        vmess.stream.transport,
        Transport::Ws {
            path: "/ws?ed=2048".to_owned(),
            host: Some("cdn.example.com".to_owned()),
        }
    );
    let TlsMode::Tls(tls) = &vmess.stream.tls else {
        panic!("expected TLS");
    };
    assert_eq!(tls.sni.as_deref(), Some("cdn.example.com"));
    assert_eq!(tls.alpn, ["h2", "http/1.1"]);

    let trojan = &result.nodes[2];
    let Outbound::Trojan(params) = &trojan.outbound else {
        panic!("expected Trojan");
    };
    assert_eq!(params.password, "test-password");
    assert_eq!(
        trojan.stream.transport,
        Transport::Grpc {
            service_name: "grpc-service".to_owned(),
        }
    );

    let shadowsocks = &result.nodes[3];
    let Outbound::Shadowsocks(params) = &shadowsocks.outbound else {
        panic!("expected Shadowsocks");
    };
    assert_eq!(params.method, "2022-blake3-aes-128-gcm");
    // A multi-user 2022 inbound sends the server key and the user key together.
    assert_eq!(
        params.password,
        "dGVzdC1zZXJ2ZXIta2V5IQ==:dGVzdC11c2VyLWtleS0wMQ=="
    );
    assert_eq!(shadowsocks.stream.tls, TlsMode::Plain);

    let reasons: Vec<_> = result
        .skipped
        .iter()
        .map(|skipped| (skipped.index, skipped.reason.clone()))
        .collect();
    assert_eq!(
        reasons,
        [
            (1, SkipReason::ServiceRecord),
            (
                6,
                SkipReason::UnsupportedTransport(UnsupportedTransport::Xhttp)
            ),
            (7, SkipReason::UnsupportedEncryption),
        ]
    );
    assert_eq!(result.meta.notices, ["⏳ 12 days left · 34.5 GB remaining"]);
}

// Fix 4: 3x-ui writes its info record into link subscriptions as
// socks://127.0.0.1:1080#<message>.
#[test]
fn x_ui_link_info_record_becomes_a_notice() {
    let body = format!(
        "socks://127.0.0.1:1080#%E2%8F%B3%2012%20days%20left\n{}",
        vless("", "Test")
    );
    let result = parsed(&body);
    assert_eq!(result.nodes.len(), 1);
    assert_eq!(result.skipped[0].reason, SkipReason::ServiceRecord);
    assert_eq!(result.meta.notices, ["⏳ 12 days left"]);

    match parse(
        b"socks://127.0.0.1:1080#Subscription%20expired",
        &no_headers,
    ) {
        Err(ParseError::NoUsableNodes { notices, .. }) => {
            assert_eq!(notices, ["Subscription expired"]);
        }
        other => panic!("unexpected result: {other:?}"),
    }
}

// Fix 1: url leaves '&' unescaped in userinfo and fragments.
#[test]
fn ampersands_survive_percent_decoding() {
    let trojan = parsed("trojan://p&ss@example.com:443#Germany%20&%20Netherlands");
    let Outbound::Trojan(params) = &trojan.nodes[0].outbound else {
        panic!("expected Trojan");
    };
    assert_eq!(params.password, "p&ss");
    assert_eq!(trojan.nodes[0].name, "Germany & Netherlands");

    let shadowsocks = parsed("ss://aes-256-gcm:p&ss@example.com:8388#S&S");
    let Outbound::Shadowsocks(params) = &shadowsocks.nodes[0].outbound else {
        panic!("expected Shadowsocks");
    };
    assert_eq!(params.password, "p&ss");
    assert_eq!(shadowsocks.nodes[0].name, "S&S");
}

// Fix 5: Remnawave sets x-hwid-limit on every refusal, so it must not
// imply that the device limit was reached.
#[test]
fn hwid_limit_header_does_not_imply_max_devices() {
    let header = |key: &str| {
        matches!(key, "x-hwid-limit" | "x-hwid-not-supported").then(|| "true".to_owned())
    };
    match parse(b"", &header) {
        Err(ParseError::DeviceLimit {
            max_devices_reached,
            not_supported,
            ..
        }) => {
            assert!(!max_devices_reached);
            assert!(not_supported);
        }
        other => panic!("unexpected result: {other:?}"),
    }
}
