use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use rosetun_config::{Outbound, TlsMode, Transport, XhttpExtra, XhttpMode, XhttpRange};
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
            "type=xhttp&mode=test-mode",
            SkipReason::UnsupportedXhttpMode,
        ),
        (
            "type=xhttp&extra=%7Bnot-json",
            SkipReason::InvalidXhttpExtra,
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
        only_skip("amneziawg://test-password@example.com:51820"),
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
    assert_eq!(result.nodes.len(), 5);

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

    let xhttp = &result.nodes[4];
    assert_eq!(xhttp.server, "xhttp.example.com");
    assert_eq!(
        xhttp.stream.transport,
        Transport::Xhttp {
            path: "/xhttp".to_owned(),
            host: None,
            mode: XhttpMode::Auto,
            extra: XhttpExtra::default(),
        }
    );
    assert!(matches!(xhttp.stream.tls, TlsMode::Reality(_)));

    let reasons: Vec<_> = result
        .skipped
        .iter()
        .map(|skipped| (skipped.index, skipped.reason.clone()))
        .collect();
    assert_eq!(
        reasons,
        [
            (1, SkipReason::ServiceRecord),
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

const XHTTP_EXTRA: &str = r#"{"headers":{"X-Example":"example-value"},"xPaddingBytes":"100-1000","noSSEHeader":true,"xmux":{"maxConcurrency":"16-32","hMaxReusableSecs":1800},"unknownOption":1}"#;

fn encoded(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

#[test]
fn xhttp_links_keep_every_field() {
    let link = vless(
        &format!(
            "type=xhttp&security=reality&pbk=test-public-key&sni=example.com&path=%2Fexample&host=xhttp.example.com&mode=stream-up&extra={}",
            encoded(XHTTP_EXTRA)
        ),
        "XHTTP",
    );
    let result = parsed(&link);
    let Transport::Xhttp {
        path,
        host,
        mode,
        extra,
    } = &result.nodes[0].stream.transport
    else {
        panic!("expected XHTTP");
    };
    assert_eq!(path, "/example");
    assert_eq!(host.as_deref(), Some("xhttp.example.com"));
    assert_eq!(*mode, XhttpMode::StreamUp);
    assert_eq!(
        extra.headers.get("X-Example").map(String::as_str),
        Some("example-value")
    );
    assert_eq!(
        extra.x_padding_bytes,
        Some(XhttpRange {
            from: 100,
            to: 1000
        })
    );
    assert!(extra.no_sse_header);
    let xmux = extra.xmux.as_ref().unwrap();
    assert_eq!(xmux.max_concurrency, Some(XhttpRange { from: 16, to: 32 }));
    assert_eq!(
        xmux.h_max_reusable_secs,
        Some(XhttpRange {
            from: 1800,
            to: 1800
        })
    );

    let old_name = parsed(&vless("type=splithttp&path=%2Fexample", "SplitHTTP"));
    assert!(matches!(
        &old_name.nodes[0].stream.transport,
        Transport::Xhttp { path, mode: XhttpMode::Auto, extra, .. }
            if path == "/example" && extra.is_empty()
    ));
}

#[test]
fn xhttp_download_settings_and_broken_extra_skip_only_that_node() {
    let download = encoded(r#"{"downloadSettings":{"address":"192.0.2.5","port":443}}"#);
    let broken = encoded(r#"{"xmux":{"maxConcurrency":"many"}}"#);
    let body = [
        vless(&format!("type=xhttp&extra={download}"), "Download"),
        vless(&format!("type=xhttp&extra={broken}"), "Broken"),
        vless("type=xhttp&path=%2Fok", "Good"),
    ]
    .join("\n");
    let result = parsed(&body);
    assert_eq!(result.nodes.len(), 1);
    assert_eq!(result.nodes[0].name, "Good");
    let reasons: Vec<_> = result
        .skipped
        .iter()
        .map(|skipped| skipped.reason.clone())
        .collect();
    assert_eq!(
        reasons,
        [
            SkipReason::XhttpDownloadSettings,
            SkipReason::InvalidXhttpExtra
        ]
    );
}

#[test]
fn xray_json_xhttp_reads_extra_or_the_settings_themselves() {
    let config = |settings: &str| {
        format!(
            r#"{{"remarks":"XHTTP","outbounds":[{{"protocol":"vless","tag":"proxy","settings":{{"address":"192.0.2.40","port":443,"id":"00000000-0000-4000-8000-000000000040","encryption":"none"}},"streamSettings":{{"network":"xhttp","security":"tls","xhttpSettings":{settings}}}}}]}}"#
        )
    };
    let extra = |settings: &str| match &parsed(&config(settings)).nodes[0].stream.transport {
        Transport::Xhttp { extra, .. } => extra.clone(),
        other => panic!("expected XHTTP, got {other:?}"),
    };

    let direct = extra(r#"{"path":"/x","mode":"packet-up","noGRPCHeader":true}"#);
    assert!(direct.no_grpc_header);

    // With `extra` present Xray ignores the options next to it.
    let nested = extra(r#"{"path":"/x","noGRPCHeader":true,"extra":{"scMaxBufferedPosts":30}}"#);
    assert!(!nested.no_grpc_header);
    assert_eq!(nested.sc_max_buffered_posts, Some(30));

    let split = config(r#"{"path":"/x"}"#)
        .replace(r#""network":"xhttp""#, r#""network":"splithttp""#)
        .replace("xhttpSettings", "splithttpSettings");
    assert!(matches!(
        &parsed(&split).nodes[0].stream.transport,
        Transport::Xhttp { path, .. } if path == "/x"
    ));

    for (settings, reason) in [
        (
            r#"{"path":"/x","downloadSettings":{"address":"192.0.2.5"}}"#,
            SkipReason::XhttpDownloadSettings,
        ),
        (
            r#"{"path":"/x","extra":{"downloadSettings":{"address":"192.0.2.5"}}}"#,
            SkipReason::XhttpDownloadSettings,
        ),
        (
            r#"{"path":"/x","extra":"text"}"#,
            SkipReason::InvalidXhttpExtra,
        ),
        (
            r#"{"path":"/x","mode":"test-mode"}"#,
            SkipReason::UnsupportedXhttpMode,
        ),
    ] {
        match parse(config(settings).as_bytes(), &no_headers) {
            Err(ParseError::NoUsableNodes { skipped, .. }) => {
                assert_eq!(skipped[0].reason, reason, "{settings}");
            }
            _ => panic!("{settings} should be skipped"),
        }
    }
}

#[test]
fn xhttp_debug_and_errors_hide_path_host_and_headers() {
    let link = vless(
        &format!(
            "type=xhttp&path=%2Fsecret-path&host=secret-host.example.com&extra={}",
            encoded(r#"{"headers":{"X-Secret":"secret-value"}}"#)
        ),
        "XHTTP",
    );
    let debug = format!("{:?}", parsed(&link).nodes[0].stream);
    for secret in ["secret-path", "secret-host", "X-Secret", "secret-value"] {
        assert!(!debug.contains(secret), "{secret} leaked: {debug}");
    }
}

#[test]
fn skipped_unsupported_protocols_record_known_schemes_and_wrapper_links_are_client_settings() {
    let body = [
        "amneziawg://secret@192.0.2.1:51820#AWG",
        "hysteria://192.0.2.2:443?auth=secret#Hy1",
        "clash://install-config?url=https://example.com/sub",
        "customproto://secret@192.0.2.3:443#Unknown",
        "trojan://secret@192.0.2.4:443#Good",
    ]
    .join("\n");
    let result = parsed(&body);
    assert_eq!(result.nodes.len(), 1);
    let summary: Vec<_> = result
        .skipped
        .iter()
        .map(|entry| (entry.scheme.as_deref(), &entry.reason))
        .collect();
    assert_eq!(
        summary,
        vec![
            (Some("amneziawg"), &SkipReason::UnsupportedProtocol),
            (Some("hysteria"), &SkipReason::UnsupportedProtocol),
            (Some("clash"), &SkipReason::ClientSettings),
            (None, &SkipReason::UnsupportedProtocol),
        ]
    );

    let sing_box = r#"{
        "outbounds": [
            {"type": "mieru", "tag": "Mieru"},
            {"type": "unknownproto", "tag": "Unknown"},
            {"type": "trojan", "tag": "Good", "server": "192.0.2.5", "server_port": 443, "password": "pw"}
        ]
    }"#;
    let sb = parsed(sing_box);
    assert_eq!(sb.nodes.len(), 1);
    assert_eq!(sb.skipped[0].scheme.as_deref(), Some("mieru"));
    assert_eq!(sb.skipped[0].reason, SkipReason::UnsupportedProtocol);
    assert_eq!(sb.skipped[1].scheme, None);
    assert_eq!(sb.skipped[1].reason, SkipReason::UnsupportedProtocol);

    let xray = r#"[
        {"remarks": "Socks", "outbounds": [{"protocol": "socks", "tag": "proxy"}]},
        {"remarks": "Good", "outbounds": [{"protocol": "trojan", "tag": "proxy", "settings": {"servers": [{"address": "192.0.2.6", "port": 443, "password": "pw"}]}}]}
    ]"#;
    let xr = parsed(xray);
    assert_eq!(xr.nodes.len(), 1);
    assert_eq!(xr.skipped[0].scheme.as_deref(), Some("socks"));
    assert_eq!(xr.skipped[0].reason, SkipReason::UnsupportedProtocol);
}

#[test]
fn tuic_links_and_sing_box_json_parse_supported_fields_and_skip_unsupported_options() {
    use rosetun_config::{TuicCongestionControl, TuicUdpRelayMode};

    let link = format!(
        "tuic://{UUID}:p%3Ass@example.com:8444?congestion_control=bbr&udp_relay_mode=quic&reduce_rtt=1&heartbeat=15&sni=tuic.example.com&alpn=h3,h3-29&allow_insecure=1&disable_sni=1&fp=chrome#TUIC%20Node"
    );
    let result = parsed(&link);
    assert_eq!(result.nodes.len(), 1);
    let node = &result.nodes[0];
    assert_eq!(node.name, "TUIC Node");
    assert_eq!(node.server, "example.com");
    assert_eq!(node.port, 8444);
    assert_eq!(node.stream.transport, Transport::Tcp);
    let Outbound::Tuic(params) = &node.outbound else {
        panic!("expected TUIC");
    };
    assert_eq!(params.uuid, UUID);
    assert_eq!(params.password, "p:ss");
    assert_eq!(params.congestion_control, Some(TuicCongestionControl::Bbr));
    assert_eq!(params.udp_relay_mode, Some(TuicUdpRelayMode::Quic));
    assert!(params.zero_rtt_handshake);
    assert_eq!(params.heartbeat.as_deref(), Some("15s"));
    assert!(params.disable_sni);
    let TlsMode::Tls(tls) = &node.stream.tls else {
        panic!("expected TLS");
    };
    assert_eq!(tls.sni.as_deref(), Some("tuic.example.com"));
    assert_eq!(tls.alpn, ["h3", "h3-29"]);
    assert!(tls.allow_insecure);
    assert_eq!(tls.fingerprint.as_deref(), Some("chrome"));

    // Password is optional in TUIC v5.
    let minimal = parsed(&format!("tuic://{UUID}@192.0.2.40:443?version=5"));
    let Outbound::Tuic(params) = &minimal.nodes[0].outbound else {
        panic!("expected TUIC");
    };
    assert_eq!(params.password, "");
    assert!(!params.zero_rtt_handshake);

    // Zero UUID becomes a service notice.
    let notice_body =
        format!("tuic://00000000-0000-0000-0000-000000000000@example.com:443#Expired\n{link}");
    let notice = parsed(&notice_body);
    assert_eq!(notice.nodes.len(), 1);
    assert_eq!(notice.meta.notices, ["Expired"]);
    assert_eq!(notice.skipped[0].reason, SkipReason::ServiceRecord);

    for (bad, expected) in [
        (
            String::from("tuic://not-a-uuid:pw@example.com:443"),
            SkipReason::InvalidRecord,
        ),
        (
            format!("tuic://{UUID}:pw@example.com:443?version=4"),
            SkipReason::UnsupportedOption,
        ),
        (
            format!("tuic://{UUID}:pw@example.com:443?udp_over_stream=1"),
            SkipReason::UnsupportedOption,
        ),
        (
            format!("tuic://{UUID}:pw@example.com:443?congestion_control=reno"),
            SkipReason::UnsupportedOption,
        ),
        (
            format!("tuic://{UUID}:pw@example.com:443?udp_relay_mode=stream"),
            SkipReason::UnsupportedOption,
        ),
        (
            format!("tuic://{UUID}:pw@example.com:443?unknown_required=1"),
            SkipReason::UnsupportedOption,
        ),
        (
            format!("tuic://{UUID}:pw@example.com:443?pinSHA256=abc"),
            SkipReason::UnsupportedPin,
        ),
        (
            format!("tuic://{UUID}:pw@example.com:443?security=reality&pbk=key"),
            SkipReason::UnsupportedSecurity,
        ),
        (
            format!("tuic://{UUID}:pw@example.com:443?security=none"),
            SkipReason::UnsupportedSecurity,
        ),
        (
            format!("tuic://{UUID}:pw@example.com:443?heartbeat=0s"),
            SkipReason::InvalidRecord,
        ),
    ] {
        assert_eq!(only_skip(&bad), expected, "{bad}");
    }

    let json = format!(
        r#"{{
            "outbounds": [
                {{
                    "type": "tuic",
                    "tag": "TUIC JSON",
                    "server": "192.0.2.40",
                    "server_port": 8444,
                    "uuid": "{UUID}",
                    "password": "secret",
                    "congestion_control": "new_reno",
                    "udp_relay_mode": "native",
                    "zero_rtt_handshake": true,
                    "heartbeat": "10s",
                    "tls": {{
                        "enabled": true,
                        "server_name": "tuic.example.com",
                        "alpn": ["h3"],
                        "insecure": true,
                        "disable_sni": true
                    }}
                }},
                {{
                    "type": "tuic",
                    "tag": "TUIC UOS",
                    "server": "192.0.2.40",
                    "server_port": 8444,
                    "uuid": "{UUID}",
                    "udp_over_stream": true,
                    "tls": {{ "enabled": true }}
                }},
                {{
                    "type": "tuic",
                    "tag": "TUIC No TLS",
                    "server": "192.0.2.40",
                    "server_port": 8444,
                    "uuid": "{UUID}",
                    "tls": {{ "enabled": false }}
                }}
            ]
        }}"#
    );
    let parsed_json = parsed(&json);
    assert_eq!(parsed_json.nodes.len(), 1);
    let Outbound::Tuic(params) = &parsed_json.nodes[0].outbound else {
        panic!("expected TUIC");
    };
    assert_eq!(
        params.congestion_control,
        Some(TuicCongestionControl::NewReno)
    );
    assert_eq!(params.udp_relay_mode, Some(TuicUdpRelayMode::Native));
    assert!(params.zero_rtt_handshake);
    assert_eq!(params.heartbeat.as_deref(), Some("10s"));
    assert!(params.disable_sni);
    assert_eq!(parsed_json.skipped.len(), 2);
    assert_eq!(parsed_json.skipped[0].reason, SkipReason::UnsupportedOption);
    assert_eq!(
        parsed_json.skipped[1].reason,
        SkipReason::UnsupportedSecurity
    );
}

#[test]
fn anytls_links_and_sing_box_json_parse_supported_fields_and_skip_unsupported_options() {
    let tls_link = "anytls://user:p%40ss@example.com?sni=anytls.example.com&alpn=h2,http/1.1&insecure=1&fp=chrome&idle_session_check_interval=30s&idle_session_timeout=60&min_idle_session=2&udp=1#AnyTLS%20TLS";
    let result = parsed(tls_link);
    assert_eq!(result.nodes.len(), 1);
    let node = &result.nodes[0];
    assert_eq!(node.name, "AnyTLS TLS");
    assert_eq!(node.server, "example.com");
    assert_eq!(node.port, 443);
    let Outbound::AnyTls(params) = &node.outbound else {
        panic!("expected AnyTLS");
    };
    assert_eq!(params.password, "user:p@ss");
    assert_eq!(params.idle_session_check_interval.as_deref(), Some("30s"));
    assert_eq!(params.idle_session_timeout.as_deref(), Some("60s"));
    assert_eq!(params.min_idle_session, Some(2));
    let TlsMode::Tls(tls) = &node.stream.tls else {
        panic!("expected TLS");
    };
    assert_eq!(tls.sni.as_deref(), Some("anytls.example.com"));
    assert_eq!(tls.alpn, ["h2", "http/1.1"]);
    assert!(tls.allow_insecure);
    assert_eq!(tls.fingerprint.as_deref(), Some("chrome"));

    let reality_link = "anytls://secret@192.0.2.41:8445?security=reality&sni=example.com&pbk=test-public-key&sid=01ab&fp=firefox#AnyTLS%20Reality";
    let reality = parsed(reality_link);
    assert_eq!(reality.nodes[0].port, 8445);
    let TlsMode::Reality(r) = &reality.nodes[0].stream.tls else {
        panic!("expected REALITY");
    };
    assert_eq!(r.public_key, "test-public-key");
    assert_eq!(r.short_id.as_deref(), Some("01ab"));
    assert_eq!(r.fingerprint.as_deref(), Some("firefox"));

    for (bad, expected) in [
        ("anytls://@example.com:443", SkipReason::MissingField),
        ("anytls://secret@example.com:0", SkipReason::InvalidPort),
        (
            "anytls://secret@example.com:443?udp=0",
            SkipReason::UnsupportedOption,
        ),
        (
            "anytls://secret@example.com:443?tfo=1",
            SkipReason::UnsupportedOption,
        ),
        (
            "anytls://secret@example.com:443?hpkp=sha256",
            SkipReason::UnsupportedPin,
        ),
        (
            "anytls://secret@example.com:443?client_metadata=foo",
            SkipReason::UnsupportedOption,
        ),
        (
            "anytls://secret@example.com:443?unknown_param=1",
            SkipReason::UnsupportedOption,
        ),
        (
            "anytls://secret@example.com:443?security=none",
            SkipReason::UnsupportedSecurity,
        ),
        (
            "anytls://secret@example.com:443?pbk=test-key",
            SkipReason::UnsupportedSecurity,
        ),
        (
            "anytls://secret@example.com:443?idle_session_timeout=0s",
            SkipReason::InvalidRecord,
        ),
    ] {
        assert_eq!(only_skip(bad), expected, "{bad}");
    }

    let json = r#"{
        "outbounds": [
            {
                "type": "anytls",
                "tag": "AnyTLS JSON",
                "server": "192.0.2.41",
                "server_port": 8445,
                "password": "secret",
                "idle_session_check_interval": "30s",
                "idle_session_timeout": "1m",
                "min_idle_session": 3,
                "tls": {
                    "enabled": true,
                    "server_name": "anytls.example.com",
                    "utls": { "enabled": true, "fingerprint": "chrome" },
                    "reality": {
                        "enabled": true,
                        "public_key": "test-public-key",
                        "short_id": "abcd"
                    }
                }
            },
            {
                "type": "anytls",
                "tag": "AnyTLS Metadata",
                "server": "192.0.2.41",
                "server_port": 8445,
                "password": "secret",
                "client_metadata": "custom",
                "tls": { "enabled": true }
            },
            {
                "type": "anytls",
                "tag": "AnyTLS Pin",
                "server": "192.0.2.41",
                "server_port": 8445,
                "password": "secret",
                "tls": { "enabled": true, "certificate_public_key_sha256": ["abc"] }
            }
        ]
    }"#;
    let parsed_json = parsed(json);
    assert_eq!(parsed_json.nodes.len(), 1);
    let Outbound::AnyTls(params) = &parsed_json.nodes[0].outbound else {
        panic!("expected AnyTLS");
    };
    assert_eq!(params.password, "secret");
    assert_eq!(params.idle_session_check_interval.as_deref(), Some("30s"));
    assert_eq!(params.idle_session_timeout.as_deref(), Some("1m"));
    assert_eq!(params.min_idle_session, Some(3));
    assert!(matches!(
        parsed_json.nodes[0].stream.tls,
        TlsMode::Reality(_)
    ));
    assert_eq!(parsed_json.skipped.len(), 2);
    assert_eq!(parsed_json.skipped[0].reason, SkipReason::UnsupportedOption);
    assert_eq!(parsed_json.skipped[1].reason, SkipReason::UnsupportedPin);
}

#[test]
fn wireguard_links_parse_standard_and_warp_fields_and_reject_amneziawg() {
    let priv_bytes = [0xfb; 32]; // produces + and / in standard Base64
    let pub_bytes = [0xfe; 32];
    let psk_bytes = [0x03; 32];
    let priv_std = STANDARD.encode(priv_bytes);
    let pub_std = STANDARD.encode(pub_bytes);
    let psk_std = STANDARD.encode(psk_bytes);
    let priv_url = URL_SAFE_NO_PAD.encode(priv_bytes);
    let pub_url = URL_SAFE_NO_PAD.encode(pub_bytes);

    // Percent-encoded and raw Base64 keys (+, /, =) both work under wireguard:// and wg://.
    for link in [
        format!(
            "wireguard://{}@192.0.2.42:51820?publickey={}&presharedkey={}&address=10.0.0.2%2F24,fd00%3A%3A2&reserved=1,2,3&mtu=1280&keepalive=25&dns=1.1.1.1#WG%20Node",
            encoded(&priv_std),
            encoded(&pub_std),
            encoded(&psk_std),
        ),
        format!(
            "wg://{priv_std}@192.0.2.42:51820/?public_key={pub_std}&psk={psk_std}&ip=10.0.0.2/24,fd00::2/128&reserved=AQID&mtu=1280&persistent_keepalive=25#WG%20Node",
        ),
        format!(
            "wireguard://{priv_url}@192.0.2.42:51820?pbk={pub_url}&pre_shared_key={psk_std}&local_address=10.0.0.2/24,fd00::2&reserved=%5B1,2,3%5D&mtu=1280&persistent_keepalive_interval=25#WG%20Node",
        ),
    ] {
        let result = parsed(&link);
        assert_eq!(result.nodes.len(), 1);
        let node = &result.nodes[0];
        assert_eq!(node.name, "WG Node");
        assert_eq!(node.server, "192.0.2.42");
        assert_eq!(node.port, 51820);
        assert_eq!(node.stream.transport, Transport::Tcp);
        assert_eq!(node.stream.tls, TlsMode::Plain);
        let Outbound::WireGuard(params) = &node.outbound else {
            panic!("expected WireGuard");
        };
        assert_eq!(params.private_key, priv_std);
        assert_eq!(params.public_key, pub_std);
        assert_eq!(params.pre_shared_key.as_deref(), Some(psk_std.as_str()));
        assert_eq!(params.address, ["10.0.0.2/24", "fd00::2/128"]);
        assert_eq!(params.reserved, Some([1, 2, 3]));
        assert_eq!(params.mtu, Some(1280));
        assert_eq!(params.persistent_keepalive, Some(25));
        let debug = format!("{node:?}");
        assert!(!debug.contains(&priv_std));
        assert!(!debug.contains(&pub_std));
        assert!(!debug.contains(&psk_std));
    }

    // IPv6 endpoint and bare IPv4 address.
    let v6 = parsed(&format!(
        "wg://{priv_url}@[2001:db8::42]:51820?publickey={pub_url}&address=10.0.0.2&keepalive=0#WGv6"
    ));
    assert_eq!(v6.nodes[0].server, "2001:db8::42");
    let Outbound::WireGuard(params) = &v6.nodes[0].outbound else {
        panic!("expected WireGuard");
    };
    assert_eq!(params.address, ["10.0.0.2/32"]);
    assert_eq!(params.persistent_keepalive, None);

    // AmneziaWG query parameters are rejected as amneziawg UnsupportedProtocol.
    match parse(
        format!("wireguard://{priv_url}@192.0.2.42:51820?publickey={pub_url}&address=10.0.0.2/32&jc=4&s1=15").as_bytes(),
        &no_headers,
    ) {
        Err(ParseError::NoUsableNodes { skipped, .. }) => {
            assert_eq!(skipped[0].scheme.as_deref(), Some("amneziawg"));
            assert_eq!(skipped[0].reason, SkipReason::UnsupportedProtocol);
        }
        other => panic!("unexpected result: {other:?}"),
    }

    for (bad, expected) in [
        (
            format!("wireguard://{priv_url}@192.0.2.42:51820?address=10.0.0.2/32"),
            SkipReason::MissingField,
        ),
        (
            format!("wireguard://{priv_url}@192.0.2.42:51820?publickey={pub_url}"),
            SkipReason::MissingField,
        ),
        (
            format!(
                "wireguard://shortkey@192.0.2.42:51820?publickey={pub_url}&address=10.0.0.2/32"
            ),
            SkipReason::InvalidRecord,
        ),
        (
            format!(
                "wireguard://{priv_url}@192.0.2.42:51820?publickey={pub_url}&address=10.0.0.2/32&mtu=200"
            ),
            SkipReason::InvalidRecord,
        ),
        (
            format!(
                "wireguard://{priv_url}@192.0.2.42:51820?publickey={pub_url}&address=10.0.0.2/32&reserved=1,2"
            ),
            SkipReason::InvalidRecord,
        ),
        (
            format!(
                "wireguard://{priv_url}@192.0.2.42:51820?publickey={pub_url}&address=10.0.0.2/32&wnoise=m4"
            ),
            SkipReason::UnsupportedOption,
        ),
    ] {
        assert_eq!(only_skip(&bad), expected, "{bad}");
        let err = parse(bad.as_bytes(), &no_headers).unwrap_err();
        assert!(!format!("{err:?}").contains(&priv_url));
    }
}

#[test]
fn wireguard_sing_box_endpoints_legacy_outbounds_and_xray_json_match_links() {
    let priv_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    let pub_key = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    let psk = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";

    let link = parsed(&format!(
        "wireguard://{}@192.0.2.42:51820?publickey={}&presharedkey={}&address=10.0.0.2/32,fd00::2/128&reserved=1,2,3&mtu=1280&keepalive=25#WARP",
        encoded(priv_key),
        encoded(pub_key),
        encoded(psk),
    ));

    // sing-box 1.11+ endpoints-only JSON (without outbounds).
    let sb_endpoints = parsed(
        &serde_json::json!({
            "endpoints": [
                {
                    "type": "wireguard",
                    "tag": "WARP",
                    "address": ["10.0.0.2/32", "fd00::2/128"],
                    "private_key": priv_key,
                    "mtu": 1280,
                    "peers": [
                        {
                            "address": "192.0.2.42",
                            "port": 51820,
                            "public_key": pub_key,
                            "pre_shared_key": psk,
                            "allowed_ips": ["0.0.0.0/0", "::/0"],
                            "persistent_keepalive_interval": 25,
                            "reserved": [1, 2, 3]
                        }
                    ]
                },
                {
                    "type": "awg",
                    "tag": "Amnezia"
                },
                {
                    "type": "wireguard",
                    "tag": "AmneziaBlock",
                    "address": ["10.0.0.2/32"],
                    "private_key": priv_key,
                    "amnezia": { "jc": 4 },
                    "peers": [{ "address": "192.0.2.42", "port": 51820, "public_key": pub_key }]
                },
                {
                    "type": "wireguard",
                    "tag": "MultiPeer",
                    "address": ["10.0.0.2/32"],
                    "private_key": priv_key,
                    "peers": [
                        { "address": "192.0.2.42", "port": 51820, "public_key": pub_key },
                        { "address": "192.0.2.43", "port": 51820, "public_key": pub_key }
                    ]
                },
                {
                    "type": "wireguard",
                    "tag": "SystemInterface",
                    "system": true,
                    "address": ["10.0.0.2/32"],
                    "private_key": priv_key,
                    "peers": [{ "address": "192.0.2.42", "port": 51820, "public_key": pub_key }]
                }
            ]
        })
        .to_string(),
    );
    assert_eq!(sb_endpoints.format, Format::SingBoxJson);
    assert_eq!(sb_endpoints.nodes, link.nodes);
    assert_eq!(sb_endpoints.skipped.len(), 4);
    assert_eq!(sb_endpoints.skipped[0].scheme.as_deref(), Some("amneziawg"));
    assert_eq!(
        sb_endpoints.skipped[0].reason,
        SkipReason::UnsupportedProtocol
    );
    assert_eq!(sb_endpoints.skipped[1].scheme.as_deref(), Some("amneziawg"));
    assert_eq!(
        sb_endpoints.skipped[1].reason,
        SkipReason::UnsupportedProtocol
    );
    assert_eq!(
        sb_endpoints.skipped[2].reason,
        SkipReason::UnsupportedOption
    );
    assert_eq!(
        sb_endpoints.skipped[3].reason,
        SkipReason::UnsupportedOption
    );

    // Legacy sing-box outbound.
    let sb_legacy = parsed(
        &serde_json::json!({
            "outbounds": [
                {
                    "type": "wireguard",
                    "tag": "WARP",
                    "server": "192.0.2.42",
                    "server_port": 51820,
                    "local_address": ["10.0.0.2/32", "fd00::2/128"],
                    "private_key": priv_key,
                    "peer_public_key": pub_key,
                    "pre_shared_key": psk,
                    "reserved": "AQID",
                    "mtu": 1280,
                    "persistent_keepalive_interval": 25
                }
            ]
        })
        .to_string(),
    );
    assert_eq!(sb_legacy.format, Format::SingBoxJson);
    assert_eq!(sb_legacy.nodes, link.nodes);

    // Xray JSON WireGuard outbound.
    let xray = parsed(
        &serde_json::json!({
            "remarks": "WARP",
            "outbounds": [
                {
                    "protocol": "wireguard",
                    "tag": "proxy",
                    "settings": {
                        "secretKey": priv_key,
                        "address": ["10.0.0.2/32", "fd00::2/128"],
                        "mtu": 1280,
                        "reserved": [1, 2, 3],
                        "peers": [
                            {
                                "publicKey": pub_key,
                                "preSharedKey": psk,
                                "endpoint": "192.0.2.42:51820",
                                "keepAlive": 25
                            }
                        ]
                    }
                }
            ]
        })
        .to_string(),
    );
    assert_eq!(xray.format, Format::XrayJson);
    assert_eq!(xray.nodes, link.nodes);
}

#[test]
fn wireguard_conf_ini_parses_plain_and_base64_and_rejects_amneziawg() {
    let priv_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    let pub_key = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    let psk = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";

    let conf = format!(
        "#profile-title: Frankfurt WG\n\
         [Interface]\n\
         PrivateKey = {priv_key}\n\
         Address = 10.0.0.2/32\n\
         Address = fd00::2/128\n\
         DNS = 1.1.1.1, 2606:4700:4700::1111\n\
         MTU = 1280\n\
         ListenPort = 51820\n\
         \n\
         [Peer]\n\
         PublicKey = {pub_key}\n\
         PresharedKey = {psk}\n\
         AllowedIPs = 0.0.0.0/0, ::/0\n\
         Endpoint = [2001:db8::42]:51820\n\
         PersistentKeepalive = 25\n\
         Reserved = 1, 2, 3\n"
    );

    for body in [conf.clone(), STANDARD.encode(conf.as_bytes())] {
        let result = parsed(&body);
        assert_eq!(result.format, Format::WireGuardConf);
        assert_eq!(result.nodes.len(), 1);
        let node = &result.nodes[0];
        assert_eq!(node.name, "Frankfurt WG");
        assert_eq!(node.server, "2001:db8::42");
        assert_eq!(node.port, 51820);
        let Outbound::WireGuard(params) = &node.outbound else {
            panic!("expected WireGuard");
        };
        assert_eq!(params.private_key, priv_key);
        assert_eq!(params.public_key, pub_key);
        assert_eq!(params.pre_shared_key.as_deref(), Some(psk));
        assert_eq!(params.address, ["10.0.0.2/32", "fd00::2/128"]);
        assert_eq!(params.reserved, Some([1, 2, 3]));
        assert_eq!(params.mtu, Some(1280));
        assert_eq!(params.persistent_keepalive, Some(25));
    }

    // Content-Disposition filename strips .conf when naming the node.
    let minimal_conf = format!(
        "[Interface]\nPrivateKey = {priv_key}\nAddress = 10.0.0.2/32\n\n\
         [Peer]\nPublicKey = {pub_key}\nEndpoint = 192.0.2.42:51820\n"
    );
    let header = |name: &str| {
        name.eq_ignore_ascii_case("content-disposition")
            .then(|| r#"attachment; filename="nl-amsterdam.conf""#.to_owned())
    };
    let named = parse(minimal_conf.as_bytes(), &header).unwrap();
    assert_eq!(named.nodes[0].name, "nl-amsterdam");

    // AmneziaWG .conf is rejected as amneziawg UnsupportedProtocol.
    let awg_conf = format!(
        "[Interface]\nPrivateKey = {priv_key}\nAddress = 10.0.0.2/32\nJc = 4\nS1 = 15\n\n\
         [Peer]\nPublicKey = {pub_key}\nEndpoint = 192.0.2.42:51820\n"
    );
    match parse(awg_conf.as_bytes(), &no_headers) {
        Err(ParseError::NoUsableNodes { skipped, .. }) => {
            assert_eq!(skipped[0].scheme.as_deref(), Some("amneziawg"));
            assert_eq!(skipped[0].reason, SkipReason::UnsupportedProtocol);
        }
        other => panic!("unexpected result: {other:?}"),
    }

    // Multiple [Peer] sections are rejected as UnsupportedOption.
    let multi_peer = format!(
        "[Interface]\nPrivateKey = {priv_key}\nAddress = 10.0.0.2/32\n\n\
         [Peer]\nPublicKey = {pub_key}\nEndpoint = 192.0.2.42:51820\n\n\
         [Peer]\nPublicKey = {pub_key}\nEndpoint = 192.0.2.43:51820\n"
    );
    assert_eq!(only_skip(&multi_peer), SkipReason::UnsupportedOption);
}

#[test]
fn xray_json_balancer_array_parses_members_observatory_finalmask_and_distinct_ids() {
    use rosetun_config::{
        BalancerStrategy, HeaderCustomPacket, HeaderCustomPacketType, TcpFinalMask, XrayObservatory,
    };

    let body = format!(
        r#"[
            {{
                "remarks": "NL",
                "routing": {{
                    "rules": [
                        {{"ip": ["geoip:private"], "outboundTag": "direct"}},
                        {{"network": "tcp,udp", "balancerTag": "bal"}}
                    ],
                    "balancers": [{{
                        "tag": "bal",
                        "selector": ["proxy"],
                        "strategy": {{"type": "leastLoad", "settings": {{"maxRTT": "3000ms", "tolerance": 0.5}}}},
                        "fallbackTag": "mask"
                    }}]
                }},
                "outbounds": [
                    {{
                        "tag": "proxy",
                        "protocol": "vless",
                        "settings": {{"vnext": [{{"address": "nl.example.com", "port": 443, "users": [{{"id": "{UUID}", "encryption": "none", "flow": "xtls-rprx-vision"}}]}}]}},
                        "streamSettings": {{"network": "tcp", "security": "reality", "realitySettings": {{"serverName": "blog.example.com", "publicKey": "test-public-key", "fingerprint": "firefox"}}}}
                    }},
                    {{
                        "tag": "mask",
                        "protocol": "vless",
                        "settings": {{"vnext": [{{"address": "nl4.example.com", "port": 443, "users": [{{"id": "{UUID}", "encryption": "none", "flow": "xtls-rprx-vision"}}]}}]}},
                        "streamSettings": {{
                            "network": "tcp",
                            "security": "tls",
                            "tlsSettings": {{"serverName": "nl4.example.com", "enableSessionResumption": false, "fingerprint": "firefox", "alpn": ["http/1.1"]}},
                            "finalmask": {{"tcp": [{{"type": "header-custom", "settings": {{"servers": [[{{"type": "str", "packet": "SSH-2.0-OpenSSH_9.6p1\r\n"}}]]}}}}]}}
                        }}
                    }},
                    {{"tag": "direct", "protocol": "freedom"}}
                ],
                "burstObservatory": {{
                    "subjectSelector": ["proxy"],
                    "pingConfig": {{
                        "timeout": "5s",
                        "interval": "15s",
                        "sampling": 2,
                        "httpMethod": "GET",
                        "destination": "https://connectivitycheck.gstatic.com/generate_204",
                        "connectivity": "https://probe-should-be-omitted.example.com"
                    }}
                }}
            }},
            {{
                "remarks": "JP",
                "routing": {{"rules": [{{"ip": ["geoip:private"], "outboundTag": "direct"}}]}},
                "outbounds": [
                    {{
                        "tag": "proxy",
                        "protocol": "vless",
                        "settings": {{"vnext": [{{"address": "jp.example.com", "port": 443, "users": [{{"id": "{UUID}", "encryption": "none", "flow": "xtls-rprx-vision"}}]}}]}},
                        "streamSettings": {{"network": "tcp", "security": "reality", "realitySettings": {{"serverName": "jp.example.com", "publicKey": "test-public-key", "fingerprint": "firefox"}}}}
                    }},
                    {{"tag": "direct", "protocol": "freedom"}}
                ]
            }},
            {{
                "remarks": "RU Relay A",
                "routing": {{
                    "rules": [{{"network": "tcp,udp", "balancerTag": "bal-europe"}}],
                    "balancers": [{{
                        "tag": "bal-europe",
                        "selector": ["Europe"],
                        "strategy": {{"type": "leastPing"}},
                        "fallbackTag": "proxy"
                    }}]
                }},
                "outbounds": [
                    {{
                        "tag": "proxy",
                        "protocol": "vless",
                        "settings": {{"vnext": [{{"address": "ru2.example.com", "port": 443, "users": [{{"id": "{UUID}", "encryption": "none", "flow": "xtls-rprx-vision"}}]}}]}},
                        "streamSettings": {{"network": "tcp", "security": "reality", "realitySettings": {{"serverName": "ru2.example.com", "publicKey": "test-public-key"}}}}
                    }},
                    {{
                        "tag": "Europe",
                        "protocol": "vless",
                        "settings": {{"vnext": [{{"address": "nl.example.com", "port": 443, "users": [{{"id": "{UUID}", "encryption": "none", "flow": "xtls-rprx-vision"}}]}}]}},
                        "streamSettings": {{"network": "tcp", "security": "reality", "realitySettings": {{"serverName": "blog.example.com", "publicKey": "test-public-key"}}}}
                    }}
                ],
                "observatory": {{
                    "subjectSelector": ["Europe"],
                    "probeUrl": "https://connectivitycheck.gstatic.com/generate_204",
                    "probeInterval": "1m",
                    "enableConcurrency": true
                }}
            }},
            {{
                "remarks": "RU Relay B",
                "routing": {{
                    "rules": [{{"network": "tcp,udp", "balancerTag": "bal-europe"}}],
                    "balancers": [{{
                        "tag": "bal-europe",
                        "selector": ["Europe"],
                        "strategy": {{"type": "leastPing"}},
                        "fallbackTag": "proxy"
                    }}]
                }},
                "outbounds": [
                    {{
                        "tag": "proxy",
                        "protocol": "vless",
                        "settings": {{"vnext": [{{"address": "ru3.example.com", "port": 443, "users": [{{"id": "{UUID}", "encryption": "none", "flow": "xtls-rprx-vision"}}]}}]}},
                        "streamSettings": {{"network": "tcp", "security": "tls", "tlsSettings": {{"serverName": "ru3.example.com"}}}}
                    }},
                    {{
                        "tag": "Europe",
                        "protocol": "vless",
                        "settings": {{"vnext": [{{"address": "nl.example.com", "port": 443, "users": [{{"id": "{UUID}", "encryption": "none", "flow": "xtls-rprx-vision"}}]}}]}},
                        "streamSettings": {{"network": "tcp", "security": "reality", "realitySettings": {{"serverName": "blog.example.com", "publicKey": "test-public-key"}}}}
                    }}
                ],
                "observatory": {{
                    "subjectSelector": ["Europe"],
                    "probeUrl": "https://connectivitycheck.gstatic.com/generate_204",
                    "probeInterval": "1m"
                }}
            }}
        ]"#
    );

    let result = parsed(&body);
    assert_eq!(result.nodes.len(), 4);
    assert!(result.skipped.is_empty());

    // Entry 0: balanced NL with burstObservatory + finalmask + enableSessionResumption=false
    let nl = &result.nodes[0];
    assert_eq!(nl.name, "NL");
    assert_eq!(nl.server, "nl.example.com");
    assert!(nl.requires_xray());
    let Outbound::XrayBalancer(nl_bal) = &nl.outbound else {
        panic!("expected XrayBalancer for NL");
    };
    assert_eq!(nl_bal.members.len(), 2);
    assert_eq!(nl_bal.selector, ["proxy"]);
    assert_eq!(nl_bal.fallback_tag.as_deref(), Some("mask"));
    let BalancerStrategy::LeastLoad(ll) = &nl_bal.strategy else {
        panic!("expected LeastLoad");
    };
    assert_eq!(ll.max_rtt.as_deref(), Some("3000ms"));
    assert_eq!(ll.tolerance_bp, Some(5000));
    let Some(XrayObservatory::Burst(burst)) = &nl_bal.observatory else {
        panic!("expected BurstObservatory");
    };
    assert_eq!(burst.subject_selector, ["proxy"]);
    assert_eq!(burst.interval.as_deref(), Some("15s"));
    assert_eq!(burst.timeout.as_deref(), Some("5s"));
    assert_eq!(burst.sampling, Some(2));
    assert_eq!(burst.http_method.as_deref(), Some("GET"));

    let mask_member = &nl_bal.members[1];
    assert_eq!(mask_member.tag, "mask");
    let TlsMode::Tls(mask_tls) = &mask_member.stream.tls else {
        panic!("expected TLS on mask member");
    };
    assert_eq!(mask_tls.enable_session_resumption, Some(false));
    assert_eq!(mask_tls.alpn, ["http/1.1"]);
    let mask = mask_member.stream.finalmask.as_ref().unwrap();
    assert_eq!(mask.tcp.len(), 1);
    let TcpFinalMask::HeaderCustom(custom) = &mask.tcp[0];
    assert_eq!(custom.servers.len(), 1);
    assert_eq!(
        custom.servers[0][0].packet_type,
        Some(HeaderCustomPacketType::Str)
    );
    assert_eq!(
        custom.servers[0][0].packet,
        Some(HeaderCustomPacket::Text("SSH-2.0-OpenSSH_9.6p1\r\n".into()))
    );

    // Entry 1: plain JP VLESS node (no balancer)
    assert!(matches!(result.nodes[1].outbound, Outbound::Vless(_)));
    assert!(!result.nodes[1].requires_xray());

    // Entries 2 and 3: both have Europe (nl.example.com) as primary selector, different fallback relays -> distinct IDs
    let ru_a = &result.nodes[2];
    let ru_b = &result.nodes[3];
    assert_ne!(ru_a.id, ru_b.id);
    assert_ne!(nl.id, ru_a.id);
    let Outbound::XrayBalancer(ru_a_bal) = &ru_a.outbound else {
        panic!("expected XrayBalancer for RU Relay A");
    };
    assert_eq!(ru_a.server, "nl.example.com");
    assert_eq!(ru_a_bal.selector, ["Europe"]);
    assert_eq!(ru_a_bal.fallback_tag.as_deref(), Some("proxy"));
    assert!(matches!(
        ru_a_bal.observatory,
        Some(XrayObservatory::Standard(ref obs)) if obs.enable_concurrency
    ));

    // Unsupported finalmask (e.g. udp mask or unknown tcp type) skips only that node.
    let bad_mask = format!(
        r#"{{
            "remarks": "BadMask",
            "outbounds": [{{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {{"vnext": [{{"address": "192.0.2.50", "port": 443, "users": [{{"id": "{UUID}", "encryption": "none"}}]}}]}},
                "streamSettings": {{
                    "network": "tcp",
                    "security": "tls",
                    "finalmask": {{"udp": [{{"type": "salamander"}}]}}
                }}
            }}]
        }}"#
    );
    assert_eq!(only_skip(&bad_mask), SkipReason::UnsupportedOption);
}
