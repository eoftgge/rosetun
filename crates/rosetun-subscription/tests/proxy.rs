use rosetun_config::{Outbound, TlsMode};
use rosetun_subscription::{parse, parse_proxy_uri};

#[test]
fn proxy_uris_decode_credentials_without_losing_ipv6_or_tls() {
    for scheme in ["http", "https", "socks5"] {
        let node = parse_proxy_uri(&format!(
            "{scheme}://%D1%82%D0%B5%D1%81%D1%82:p%40%3A%2F%25%23@[2001:db8::1]:443#Example"
        ))
        .unwrap();
        assert_eq!(node.server, "2001:db8::1");
        assert_eq!(node.port, 443);
        assert_eq!(node.name, "Example");
        let (Outbound::Http(credentials) | Outbound::Socks5(credentials)) = &node.outbound else {
            panic!()
        };
        assert_eq!(credentials.username, "тест");
        assert_eq!(credentials.password, "p@:/%#");
        assert_eq!(
            matches!(node.stream.tls, TlsMode::Tls(_)),
            scheme == "https"
        );
        assert!(node.raw.is_none());
        let debug = format!("{node:?}");
        for secret in ["тест", "p@:/%#", "2001:db8::1"] {
            assert!(!debug.contains(secret));
        }
    }
}

#[test]
fn ambiguous_and_invalid_proxy_uris_are_rejected() {
    for input in [
        "https://example.com/sub",
        "https://example.com",
        "http://example.com:0",
        "http://example.com:65536",
        "http://example.com:+80",
        "http://example.com:80?token=private",
        "socks://example.com:1080",
        "socks5://2001:db8::1:1080",
        "http://u:%ff@example.com:80",
        "http://u:%0d%0a@example.com:80",
        "http://u:%xx@example.com:80",
        "http://a:b:c@example.com:80/path",
        "http://a@b@example.com:80",
        "socks5://:password@example.com:1080",
    ] {
        assert!(parse_proxy_uri(input).is_err(), "{input}");
    }
}

#[test]
fn subscription_bodies_accept_explicit_proxy_endpoints_only() {
    let parsed = parse(b"http://192.0.2.1:8080\nhttps://proxy.example.com:443\nsocks5://192.0.2.2:1080\nhttps://example.com/subscription", &|_| None).unwrap();
    assert_eq!(parsed.nodes.len(), 3);
    assert_eq!(parsed.skipped.len(), 1);
}
