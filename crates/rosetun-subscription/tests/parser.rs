use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use rosetun_config::{Outbound, TlsMode, Transport};
use rosetun_subscription::{Format, ParseError, Parsed, SkipReason, UnsupportedTransport, parse};

const UUID: &str = "11111111-1111-1111-1111-111111111111";
const LINKS: &str = include_str!("fixtures/links.txt");

fn no_headers(_: &str) -> Option<String> {
    None
}

fn parsed(body: &str) -> Parsed {
    parse(body.as_bytes(), &no_headers).unwrap()
}

fn vless(query: &str, name: &str) -> String {
    format!("vless://{UUID}@example.com:443?{query}#{name}")
}

fn only_skip(body: &str) -> SkipReason {
    match parse(body.as_bytes(), &no_headers).unwrap_err() {
        ParseError::NoUsableNodes { skipped, .. } => {
            assert_eq!(skipped.len(), 1);
            assert_eq!(skipped[0].index, 1);
            skipped.into_iter().next().unwrap().reason
        }
        error => panic!("unexpected error: {error:?}"),
    }
}

#[test]
fn plain_links_and_supported_transports() {
    let result = parsed(LINKS);
    assert_eq!(result.format, Format::Links { base64: false });
    assert_eq!(result.nodes.len(), 7);
    assert!(result.skipped.is_empty());
    assert_eq!(result.meta.title.as_deref(), Some("Test subscription"));
    assert!(result.nodes.iter().all(|node| node.raw.is_none()));

    let TlsMode::Reality(reality) = &result.nodes[0].stream.tls else {
        panic!("expected Reality");
    };
    assert_eq!(reality.public_key, "test-public-key");
    assert_eq!(reality.short_id.as_deref(), Some("abcd"));
    assert_eq!(reality.sni.as_deref(), Some("example.com"));
    assert_eq!(reality.fingerprint.as_deref(), Some("chrome"));

    let Outbound::Vless(vless) = &result.nodes[0].outbound else {
        panic!("expected VLESS");
    };
    assert_eq!(vless.flow.as_deref(), Some("xtls-rprx-vision"));

    assert_eq!(
        result.nodes[1].stream.transport,
        Transport::Ws {
            path: "/test?key=value".to_owned(),
            host: Some("cdn.example.com".to_owned()),
        },
    );
    assert_eq!(result.nodes[1].name, "WebSocket 🌹");
    assert_eq!(
        result.nodes[2].stream.transport,
        Transport::Grpc {
            service_name: "test-service".to_owned()
        },
    );
    assert!(matches!(
        result.nodes[3].stream.transport,
        Transport::HttpUpgrade { .. },
    ));
    assert!(matches!(result.nodes[4].stream.tls, TlsMode::Tls(_)));

    let Outbound::Trojan(trojan) = &result.nodes[4].outbound else {
        panic!("expected Trojan");
    };
    assert_eq!(trojan.password, "test-password:with@symbols");
    assert_eq!(result.nodes[6].server, "2001:db8::1");
}

#[test]
fn base64_variants_and_wrapping() {
    let body = format!("\u{feff}\r\n{}\r\n\r\n", LINKS.replace('\n', "\r\n"));
    assert_eq!(parsed(&body).nodes.len(), 7);

    for engine in [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD] {
        let encoded = engine.encode(body.as_bytes());
        let wrapped = encoded
            .as_bytes()
            .chunks(19)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join(" \r\n");
        let result = parsed(&wrapped);
        assert_eq!(result.format, Format::Links { base64: true });
        assert_eq!(result.nodes.len(), 7);
    }
}

#[test]
fn vmess_accepts_string_and_numeric_ports() {
    for port in [serde_json::json!("443"), serde_json::json!(443)] {
        let value = serde_json::json!({
            "ps": "Test VMess",
            "add": "vmess.example.com",
            "port": port,
            "id": UUID,
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": "cdn.example.com",
            "path": "/test",
            "tls": "tls",
            "sni": "example.com",
            "alpn": "h2,http/1.1",
            "fp": "chrome"
        });
        for engine in [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD] {
            let link = format!("vmess://{}", engine.encode(value.to_string()));
            let result = parsed(&link);
            assert_eq!(result.nodes[0].port, 443);
            assert!(matches!(result.nodes[0].outbound, Outbound::Vmess(_)));
        }
    }
    assert_eq!(
        only_skip("vmess://not-a-json-format"),
        SkipReason::UnsupportedVmessFormat,
    );
}

#[test]
fn shadowsocks_formats() {
    let userinfo = URL_SAFE_NO_PAD.encode("aes-256-gcm:test-password");
    let sip002 = format!("ss://{userinfo}@ss.example.com:443/#Test");
    let legacy = format!(
        "ss://{}#Test",
        STANDARD.encode("aes-256-gcm:test-password@ss.example.com:443"),
    );
    let plain = "ss://2022-blake3-aes-128-gcm:test%2Dpassword@ss.example.com:443#Test";

    for link in [sip002.as_str(), legacy.as_str(), plain] {
        let result = parsed(link);
        let Outbound::Shadowsocks(params) = &result.nodes[0].outbound else {
            panic!("expected Shadowsocks");
        };
        assert_eq!(params.password, "test-password");
    }
}

#[test]
fn hysteria2_links_keep_credentials_ports_tls_and_obfuscation() {
    for scheme in ["hysteria2", "hy2"] {
        let link = format!(
            "{scheme}://test%2Duser%3Atest%2Dsecret@example.com:443,20000-30000/?sni=example.com&insecure=1&obfs=salamander&obfs-password=test%2Dsecret%2Dobfs&upmbps=100&downmbps=200#Test"
        );
        let result = parsed(&link);
        let node = &result.nodes[0];
        let Outbound::Hysteria2(params) = &node.outbound else {
            panic!("expected Hysteria2");
        };
        assert_eq!(params.password, "test-user:test-secret");
        assert_eq!(params.obfs_password.as_deref(), Some("test-secret-obfs"));
        assert_eq!(params.port_ranges, ["20000-30000"]);
        assert_eq!((params.up_mbps, params.down_mbps), (Some(100), Some(200)));
        assert_eq!(node.port, 443);
        assert_eq!(node.stream.transport, Transport::Tcp);
        let TlsMode::Tls(tls) = &node.stream.tls else {
            panic!("expected TLS");
        };
        assert_eq!(tls.sni.as_deref(), Some("example.com"));
        assert!(tls.allow_insecure);
        assert!(!format!("{node:?}").contains("test-secret"));
    }

    let single = parsed("hy2://test-secret@example.com:443#Test");
    assert_eq!(single.nodes[0].port, 443);
    let Outbound::Hysteria2(params) = &single.nodes[0].outbound else {
        panic!("expected Hysteria2");
    };
    assert!(params.port_ranges.is_empty());
    let userpass = parsed("hysteria2://test-user:test-secret@example.com:443#Test");
    let Outbound::Hysteria2(params) = &userpass.nodes[0].outbound else {
        panic!("expected Hysteria2");
    };
    assert_eq!(params.password, "test-user:test-secret");
    let range = parsed("hy2://test-secret@[2001:db8::1]:20000-30000#Test");
    assert_eq!(range.nodes[0].server, "2001:db8::1");
    assert_eq!(range.nodes[0].port, 20000);
    let Outbound::Hysteria2(params) = &range.nodes[0].outbound else {
        panic!("expected Hysteria2");
    };
    assert_eq!(params.port_ranges, ["20000-30000"]);

    let hopped = parsed("hy2://test-secret@example.com:443?mport=20000-30000,30001#Test");
    let Outbound::Hysteria2(params) = &hopped.nodes[0].outbound else {
        panic!("expected Hysteria2");
    };
    assert_eq!(params.port_ranges, ["20000-30000", "30001"]);
    let mport_only = parsed("hy2://test-secret@example.com?mport=20000-30000#Test");
    assert_eq!(mport_only.nodes[0].port, 20000);
}

#[test]
fn hysteria2_rejects_unsupported_or_incomplete_security_without_leaking_secrets() {
    for (link, reason) in [
        (
            "hy2://test-secret@example.com:443?obfs=gecko",
            SkipReason::UnsupportedObfs,
        ),
        (
            "hy2://test-secret@example.com:443?obfs=salamander",
            SkipReason::MissingField,
        ),
        (
            "hy2://test-secret@example.com:443?pinSHA256=test-secret-pin&insecure=1",
            SkipReason::UnsupportedPin,
        ),
        ("hy2://example.com:443", SkipReason::MissingField),
        ("hy2://test-secret@:443", SkipReason::MissingField),
        (
            "hy2://test-secret@example.com:65536",
            SkipReason::InvalidPort,
        ),
        (
            "hy2://test-secret@example.com:443,30000-20000",
            SkipReason::InvalidPort,
        ),
    ] {
        assert_eq!(only_skip(link), reason);
        let error = parse(link.as_bytes(), &no_headers).unwrap_err();
        assert!(!error.to_string().contains("test-secret"));
        assert!(!format!("{error:?}").contains("test-secret"));
    }
}

#[test]
fn unsupported_options_have_typed_reasons() {
    let cases = [
        (
            "type=xhttp",
            SkipReason::UnsupportedTransport(UnsupportedTransport::Xhttp),
        ),
        (
            "type=kcp",
            SkipReason::UnsupportedTransport(UnsupportedTransport::Kcp),
        ),
        ("type=tcp&headerType=http", SkipReason::UnsupportedTcpHeader),
        ("type=grpc&mode=multi", SkipReason::UnsupportedGrpcMultiMode),
        (
            "encryption=test-encryption",
            SkipReason::UnsupportedEncryption,
        ),
        ("flow=test-flow", SkipReason::UnsupportedFlow),
        ("security=reality", SkipReason::MissingRealityPublicKey),
        ("security=test-security", SkipReason::UnsupportedSecurity),
    ];
    for (query, expected) in cases {
        assert_eq!(only_skip(&vless(query, "Test")), expected);
    }
    assert_eq!(
        only_skip("ss://aes-256-gcm:test-password@example.com:443?plugin=test"),
        SkipReason::ShadowsocksPlugin,
    );
    assert_eq!(
        only_skip("ss://unsupported:test-password@example.com:443"),
        SkipReason::UnsupportedShadowsocksMethod,
    );
    assert_eq!(
        only_skip("tuic://test-password@example.com:443"),
        SkipReason::UnsupportedProtocol,
    );
    assert_eq!(only_skip("happ://routing/test"), SkipReason::ClientSettings,);
    assert_eq!(
        only_skip(&format!("vless://{UUID}@example.com:0")),
        SkipReason::InvalidPort,
    );
}

#[test]
fn malformed_lines_are_records_in_a_link_list() {
    let body = format!("{}\nnot a link\n", vless("", "Test"));
    let result = parsed(&body);
    assert_eq!(result.nodes.len(), 1);
    assert_eq!(result.skipped[0].index, 2);
    assert_eq!(result.skipped[0].reason, SkipReason::InvalidRecord);
}

#[test]
fn provider_notices_do_not_become_nodes() {
    let body = format!(
        "{}\nvless://{UUID}@0.0.0.0:443#Expired%1B\n\
         vless://00000000-0000-0000-0000-000000000000@example.com:443#Limit\n\
         vless://{UUID}@[::]:443#Notice\n",
        vless("", "Test"),
    );
    let result = parsed(&body);
    assert_eq!(result.nodes.len(), 1);
    assert_eq!(result.meta.notices, ["Expired", "Limit", "Notice"]);
    assert!(
        result
            .skipped
            .iter()
            .all(|record| record.reason == SkipReason::ServiceRecord)
    );
}

#[test]
fn names_are_cleaned_and_bounded() {
    let name = " %1B%07%C2%85%E2%80%AEHello%E2%81%A6%F0%9F%8C%B9 ";
    assert_eq!(parsed(&vless("", name)).nodes[0].name, "Hello🌹");
    assert_eq!(parsed(&vless("", "")).nodes[0].name, "example.com:443");
    assert_eq!(
        parsed(&vless("", &"🌹".repeat(200))).nodes[0]
            .name
            .chars()
            .count(),
        128,
    );
    let ipv6 = format!("vless://{UUID}@[2001:db8::1]:443");
    assert_eq!(parsed(&ipv6).nodes[0].name, "[2001:db8::1]:443");
}

#[test]
fn metadata_headers_and_body_overrides() {
    let headers = [
        (
            "Profile-Title",
            format!("base64:{}", STANDARD.encode("Header title")),
        ),
        (
            "Announce",
            format!("base64:{}", URL_SAFE_NO_PAD.encode("Header announcement")),
        ),
        (
            "Subscription-Userinfo",
            "upload=1; download=2; total=0; expire=0; junk; unknown=9".to_owned(),
        ),
        ("Profile-Update-Interval", "24".to_owned()),
        ("Support-Url", "https://example.com/support".to_owned()),
        ("Profile-Web-Page-Url", "javascript:test".to_owned()),
    ];
    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    };
    let body = format!(
        "#profile-title: Body title\n#announce: Body announcement\n{}",
        vless("", "Test"),
    );
    let result = parse(body.as_bytes(), &header).unwrap();
    assert_eq!(result.meta.title.as_deref(), Some("Body title"));
    assert_eq!(result.meta.announce.as_deref(), Some("Body announcement"));
    assert_eq!(result.meta.update_interval_hours, Some(24));
    assert!(result.meta.web_page_url.is_none());
    assert!(result.meta.support_url.is_some());
    let info = result.meta.info.unwrap();
    assert_eq!(info.upload, 1);
    assert_eq!(info.download, 2);
    assert_eq!(info.total, None);
    assert_eq!(info.expire_unix, None);

    let result = parse(vless("", "Test").as_bytes(), &header).unwrap();
    assert_eq!(result.meta.title.as_deref(), Some("Header title"));
    assert_eq!(result.meta.announce.as_deref(), Some("Header announcement"));
}

#[test]
fn content_disposition_fallbacks() {
    for (value, expected) in [
        (
            "attachment; filename=\"Test subscription\"",
            "Test subscription",
        ),
        (
            "attachment; filename=\"Test; subscription\"",
            "Test; subscription",
        ),
        (
            "attachment; filename*=UTF-8''Test%20%F0%9F%8C%B9",
            "Test 🌹",
        ),
    ] {
        let header = |key: &str| (key == "content-disposition").then(|| value.to_owned());
        let result = parse(vless("", "Test").as_bytes(), &header).unwrap();
        assert_eq!(result.meta.title.as_deref(), Some(expected));
    }
}

#[test]
fn device_policy_is_checked_before_body() {
    for key in [
        "x-hwid-max-devices-reached",
        "x-hwid-not-supported",
        "x-hwid-limit",
    ] {
        let header = |name: &str| (name == key).then(|| "true".to_owned());
        for body in [
            "",
            "vless://00000000-0000-0000-0000-000000000000@0.0.0.0:443#Limit",
        ] {
            assert!(matches!(
                parse(body.as_bytes(), &header),
                Err(ParseError::DeviceLimit { .. }),
            ));
        }
    }
}

#[test]
fn format_errors() {
    assert!(matches!(
        parse(b" \r\n", &no_headers),
        Err(ParseError::Empty)
    ));
    assert!(matches!(
        parse(b"<!DOCTYPE html><html></html>", &no_headers),
        Err(ParseError::WebPage),
    ));
    assert!(matches!(
        parse(b"<HTML>test</HTML>", &no_headers),
        Err(ParseError::WebPage),
    ));
    assert!(matches!(
        parse(b"proxies:\n  - name: Test", &no_headers),
        Err(ParseError::UnsupportedFormat),
    ));
    assert!(matches!(
        parse(b"happ://crypt/test", &no_headers),
        Err(ParseError::EncryptedHappLink),
    ));
    assert!(matches!(
        parse(b"not a subscription", &no_headers),
        Err(ParseError::UnrecognizedFormat),
    ));
    assert!(matches!(
        parse(b"{\"unknown\":true}", &no_headers),
        Err(ParseError::UnsupportedFormat),
    ));
}

#[test]
fn errors_and_debug_do_not_expose_credentials() {
    let secret = "test-password-secret";
    let body = format!("{{\"password\":\"{secret}\",\"outbounds\":");
    let error = parse(body.as_bytes(), &no_headers).unwrap_err();
    assert!(!error.to_string().contains(secret));
    assert!(!format!("{error:?}").contains(secret));

    let body = format!("ss://unsupported:{secret}@example.com:443");
    let error = parse(body.as_bytes(), &no_headers).unwrap_err();
    assert!(!error.to_string().contains(secret));
    assert!(!format!("{error:?}").contains(secret));

    let body = format!("trojan://{secret}@example.com:443#{secret}");
    let result = parsed(&body);
    assert!(!format!("{result:?}").contains(secret));

    let header = |key: &str| match key {
        "announce" => Some(secret.to_owned()),
        "x-hwid-limit" => Some("true".to_owned()),
        _ => None,
    };
    let error = parse(b"", &header).unwrap_err();
    assert!(!error.to_string().contains(secret));
    assert!(!format!("{error:?}").contains(secret));

    let body = format!("vless://{UUID}@0.0.0.0:443#{secret}");
    let error = parse(body.as_bytes(), &no_headers).unwrap_err();
    assert!(!error.to_string().contains(secret));
    assert!(!format!("{error:?}").contains(secret));
}

#[test]
fn stable_ids_ignore_names_credentials_and_order() {
    let first = vless("type=ws&path=%2Ftest", "First");
    let second = "trojan://test-password@trojan.example.com:443#Second".to_string();
    let before = parsed(&format!("{first}\n{second}"));

    let renamed = first.replace("#First", "#Renamed");
    let rotated = second.replace("test-password", "test-password-rotated");
    let after = parsed(&format!("{rotated}\n{renamed}"));

    assert_eq!(before.nodes[0].id, after.nodes[1].id);
    assert_eq!(before.nodes[1].id, after.nodes[0].id);
    assert_eq!(before.nodes[0].id.as_str().len(), 16);

    let duplicates = parsed(&format!("{first}\n{first}\n{first}"));
    assert_eq!(
        duplicates.nodes[1].id.as_str(),
        format!("{}-2", duplicates.nodes[0].id),
    );
    assert_eq!(
        duplicates.nodes[2].id.as_str(),
        format!("{}-3", duplicates.nodes[0].id),
    );
}

#[test]
fn xray_array_and_proxy_preference() {
    let result = parsed(include_str!("fixtures/xray.json"));
    assert_eq!(result.format, Format::XrayJson);
    assert_eq!(result.nodes.len(), 2);
    assert_eq!(result.nodes[0].server, "reality.example.com");
    assert!(matches!(result.nodes[0].stream.tls, TlsMode::Reality(_)));
    assert!(matches!(
        result.nodes[1].stream.transport,
        Transport::Ws { .. }
    ));
}

#[test]
fn sing_box_ignores_non_node_outbounds() {
    let result = parsed(include_str!("fixtures/sing-box.json"));
    assert_eq!(result.format, Format::SingBoxJson);
    assert_eq!(result.nodes.len(), 2);
    assert!(result.skipped.is_empty());
    assert_eq!(result.nodes[0].name, "Test VLESS");
    assert_eq!(result.nodes[1].name, "Test Shadowsocks");
}

#[test]
fn sing_box_hysteria2_matches_the_equivalent_link_and_xray_remains_unsupported() {
    let link = parsed(
        "hy2://test-secret@example.com:443,20000-30000/?sni=example.com&insecure=true&alpn=h3&obfs=salamander&obfs-password=test-secret-obfs&upmbps=100&downmbps=200#Test",
    );
    let json = parsed(
        &serde_json::json!({ "outbounds": [{
            "type": "hysteria2", "tag": "Test", "server": "example.com", "server_port": 9,
            "server_ports": ["443:443", "20000:30000"], "password": "test-secret",
            "obfs": { "type": "salamander", "password": "test-secret-obfs" },
            "tls": { "enabled": true, "server_name": "example.com", "insecure": true, "alpn": ["h3"] },
            "up_mbps": 100, "down_mbps": 200
        }]})
        .to_string(),
    );
    assert_eq!(json.format, Format::SingBoxJson);
    assert_eq!(json.nodes, link.nodes);
    let xray = serde_json::json!({ "outbounds": [{ "protocol": "hysteria2" }] });
    assert_eq!(
        only_skip(&xray.to_string()),
        SkipReason::UnsupportedProtocol
    );

    for (field, value, reason) in [
        (
            "obfs",
            serde_json::json!({ "type": "gecko", "password": "test-secret-obfs" }),
            SkipReason::UnsupportedObfs,
        ),
        (
            "tls",
            serde_json::json!({ "enabled": false }),
            SkipReason::UnsupportedSecurity,
        ),
        (
            "tls",
            serde_json::json!({ "enabled": true, "certificate_public_key_sha256": ["test-secret-pin"] }),
            SkipReason::UnsupportedPin,
        ),
    ] {
        let mut outbound = serde_json::json!({
            "type": "hysteria2", "server": "example.com", "server_port": 443,
            "password": "test-secret", "tls": { "enabled": true }
        });
        outbound[field] = value;
        let body = serde_json::json!({ "outbounds": [outbound] });
        assert_eq!(only_skip(&body.to_string()), reason);
    }
}

#[test]
fn only_unsupported_records_fail() {
    assert!(matches!(
        parse(b"tuic://test-password@example.com:443", &no_headers),
        Err(ParseError::NoUsableNodes { .. }),
    ));
}

#[test]
fn invalid_body_metadata_preserves_valid_headers() {
    let headers = [
        ("profile-title", "Header title"),
        ("announce", "Header announcement"),
        ("support-url", "https://example.com/support"),
        ("profile-web-page-url", "https://example.com/profile"),
        ("profile-update-interval", "24"),
        (
            "subscription-userinfo",
            "upload=10; download=20; total=100; expire=200",
        ),
    ];
    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| (*value).to_owned())
    };
    let body = format!(
        "#profile-title: base64:!\n\
         #announce: base64:!\n\
         #support-url: javascript:test\n\
         #profile-web-page-url: not a URL\n\
         #profile-update-interval: invalid\n\
         #subscription-userinfo: upload=invalid; unknown=42; junk\n\
         {}",
        vless("", "Test"),
    );

    let result = parse(body.as_bytes(), &header).unwrap();

    assert_eq!(result.meta.title.as_deref(), Some("Header title"));
    assert_eq!(result.meta.announce.as_deref(), Some("Header announcement"));
    assert_eq!(
        result.meta.support_url.as_deref(),
        Some("https://example.com/support"),
    );
    assert_eq!(
        result.meta.web_page_url.as_deref(),
        Some("https://example.com/profile"),
    );
    assert_eq!(result.meta.update_interval_hours, Some(24));

    let info = result.meta.info.unwrap();
    assert_eq!(info.upload, 10);
    assert_eq!(info.download, 20);
    assert_eq!(info.total, Some(100));
    assert_eq!(info.expire_unix, Some(200));
}

#[test]
fn userinfo_requires_a_valid_known_field() {
    for value in ["", "junk", "unknown=42", "upload=invalid; download=-1"] {
        let header = |name: &str| (name == "subscription-userinfo").then(|| value.to_owned());
        let result = parse(vless("", "Test").as_bytes(), &header).unwrap();
        assert!(result.meta.info.is_none());

        let body = format!("#subscription-userinfo: {value}\n{}", vless("", "Test"));
        assert!(parsed(&body).meta.info.is_none());
    }

    let body = format!(
        "#subscription-userinfo: upload=0; download=0; total=0; expire=0\n{}",
        vless("", "Test"),
    );
    let info = parsed(&body).meta.info.unwrap();
    assert_eq!(info.upload, 0);
    assert_eq!(info.download, 0);
    assert_eq!(info.total, None);
    assert_eq!(info.expire_unix, None);
}

#[test]
fn xray_trojan_defaults_to_plain_but_links_default_to_tls() {
    for stream in [
        None,
        Some(serde_json::json!({})),
        Some(serde_json::json!({"network": "tcp"})),
        Some(serde_json::json!({"security": "none"})),
        Some(serde_json::json!({"security": "tls"})),
    ] {
        let expects_tls = stream
            .as_ref()
            .and_then(|value| value.get("security"))
            .and_then(serde_json::Value::as_str)
            == Some("tls");
        let mut outbound = serde_json::json!({
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": "example.com",
                    "port": 443,
                    "password": "test-password"
                }]
            }
        });
        if let Some(stream) = stream {
            outbound["streamSettings"] = stream;
        }
        let config = serde_json::json!({"outbounds": [outbound]});
        let result = parsed(&config.to_string());

        if expects_tls {
            assert!(matches!(result.nodes[0].stream.tls, TlsMode::Tls(_)));
        } else {
            assert_eq!(result.nodes[0].stream.tls, TlsMode::Plain);
        }
    }

    let result = parsed("trojan://test-password@example.com:443");
    assert!(matches!(result.nodes[0].stream.tls, TlsMode::Tls(_)));
}

#[test]
fn unicode_link_hosts_are_normalized_to_punycode() {
    let userinfo = URL_SAFE_NO_PAD.encode("aes-256-gcm:test-password");
    let legacy = STANDARD.encode("aes-256-gcm:test-password@пример.example.com:443");

    for host in [
        "пример.example.com",
        "%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%80.example.com",
        "xn--e1afmkfd.example.com",
    ] {
        for link in [
            format!("vless://{UUID}@{host}:443"),
            format!("trojan://test-password@{host}:443"),
            format!("ss://{userinfo}@{host}:443"),
        ] {
            let result = parsed(&link);
            assert_eq!(result.nodes[0].server, "xn--e1afmkfd.example.com");
        }
    }

    let result = parsed(&format!("ss://{legacy}"));
    assert_eq!(result.nodes[0].server, "xn--e1afmkfd.example.com");

    let unicode = parsed(&format!("vless://{UUID}@пример.example.com:443"));
    let ascii = parsed(&format!("vless://{UUID}@xn--e1afmkfd.example.com:443"));
    assert_eq!(unicode.nodes[0].id, ascii.nodes[0].id);
}
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
