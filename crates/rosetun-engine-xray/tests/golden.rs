use rosetun_config::{
    FragmentPackets, LogLevel, Node, NodeId, Outbound, RealityParams, StreamSettings, TlsFragment,
    TlsMode, TlsParams, TrojanParams, VlessParams,
};
use rosetun_engine_xray::{SocksEndpoint, render, render_probe};
use serde_json::{Value, json};

const PLAIN: &str = include_str!("fixtures/config.json");
const FRAGMENTED: &str = include_str!("fixtures/fragment-config.json");
const FRAGMENTED_RANGE: &str = include_str!("fixtures/fragment-range-probe.json");

fn reality_node() -> Node {
    Node {
        id: NodeId::new("reality"),
        name: "Example".into(),
        server: "192.0.2.10".into(),
        port: 443,
        outbound: Outbound::Vless(VlessParams {
            uuid: "00000000-0000-4000-8000-000000000001".into(),
            flow: Some("xtls-rprx-vision".into()),
        }),
        stream: StreamSettings {
            tls: TlsMode::Reality(RealityParams {
                sni: Some("example.com".into()),
                public_key: "test-public-key".into(),
                short_id: Some("01234567".into()),
                fingerprint: Some("firefox".into()),
            }),
            ..Default::default()
        },
        raw: None,
    }
}

fn trojan_node() -> Node {
    Node {
        id: NodeId::new("trojan"),
        name: "Example".into(),
        server: "198.51.100.20".into(),
        port: 443,
        outbound: Outbound::Trojan(TrojanParams {
            password: "test-password".into(),
        }),
        stream: StreamSettings {
            tls: TlsMode::Tls(TlsParams {
                sni: Some("example.com".into()),
                ..TlsParams::default()
            }),
            ..Default::default()
        },
        raw: None,
    }
}

fn plain_node() -> Node {
    Node {
        stream: StreamSettings::default(),
        ..reality_node()
    }
}

fn enabled() -> TlsFragment {
    TlsFragment {
        enabled: true,
        ..TlsFragment::default()
    }
}

/// The endpoints are random per run; the fixtures hold fixed ones.
fn pretty(body: &[u8]) -> String {
    let mut config: Value = serde_json::from_slice(body).unwrap();
    for (index, inbound) in config["inbounds"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .enumerate()
    {
        inbound["port"] = json!(10801 + index);
        inbound["settings"]["accounts"] =
            json!([{ "user": "fixture-user", "pass": "fixture-password" }]);
    }
    let mut text = serde_json::to_string_pretty(&config).unwrap();
    text.push('\n');
    text
}

fn check(name: &str, expected: &str, actual: String) {
    assert_eq!(actual, expected, "{name}");
}

fn main_and_exit() -> Vec<(&'static str, Node, SocksEndpoint)> {
    vec![
        ("proxy", reality_node(), SocksEndpoint::local().unwrap()),
        ("exit-1", trojan_node(), SocksEndpoint::local().unwrap()),
    ]
}

fn rendered(fragment: &TlsFragment) -> String {
    let nodes = main_and_exit();
    let borrowed = nodes
        .iter()
        .map(|(tag, node, socks)| (*tag, node, socks))
        .collect::<Vec<_>>();
    let config = render(&borrowed, "Ethernet", fragment, false, LogLevel::Info).unwrap();
    pretty(&config.body)
}

#[test]
fn rendering_without_fragmentation_is_the_same_bytes_as_before() {
    check("config.json", PLAIN, rendered(&TlsFragment::default()));
}

#[test]
fn fragmentation_adds_a_freedom_outbound_after_the_proxies() {
    check("fragment-config.json", FRAGMENTED, rendered(&enabled()));
}

#[test]
fn a_range_of_packets_and_the_probe_take_the_same_path() {
    let fragment = TlsFragment {
        packets: FragmentPackets::Range("1-3".parse().unwrap()),
        length: "100-200".parse().unwrap(),
        interval: "5-10".parse().unwrap(),
        ..enabled()
    };
    let nodes = vec![
        (
            "probe-0".to_owned(),
            plain_node(),
            SocksEndpoint::local().unwrap(),
        ),
        (
            "probe-1".to_owned(),
            trojan_node(),
            SocksEndpoint::local().unwrap(),
        ),
    ];
    let probe = render_probe(&nodes, "Ethernet", &fragment).unwrap();
    check(
        "fragment-range-probe.json",
        FRAGMENTED_RANGE,
        pretty(&probe.body),
    );
}
