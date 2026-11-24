use std::path::{Path, PathBuf};
use std::process::Command;

use rosetun_config::{
    BalancerMember, BalancerStrategy, BurstObservatory, FinalMask, FragmentPackets,
    HeaderCustomItem, HeaderCustomPacket, HeaderCustomPacketType, HeaderCustomTcp,
    LeastLoadSettings, LogLevel, Node, NodeId, Outbound, RealityParams, StandardObservatory,
    StreamSettings, TcpFinalMask, TlsFragment, TlsMode, TlsParams, Transport, VlessParams,
    XhttpExtra, XhttpMode, XhttpRange, XhttpXmux, XrayBalancer, XrayObservatory,
};
use rosetun_engine_xray::{SUPPORTED_XRAY_VERSION, SocksEndpoint, render, render_probe};

fn xhttp_node(tls: TlsMode) -> Node {
    let range = |from, to| Some(XhttpRange { from, to });
    Node {
        id: NodeId::new("example-xhttp"),
        name: "Example".into(),
        server: "203.0.113.10".into(),
        port: 443,
        outbound: Outbound::Vless(VlessParams {
            uuid: "00000000-0000-4000-8000-000000000001".into(),
            flow: Some("xtls-rprx-vision".into()),
        }),
        stream: StreamSettings {
            transport: Transport::Xhttp {
                path: "/example".into(),
                host: Some("xhttp.example.com".into()),
                mode: XhttpMode::Auto,
                extra: XhttpExtra {
                    headers: [("X-Example".to_owned(), "example-value".to_owned())].into(),
                    x_padding_bytes: range(100, 1000),
                    no_grpc_header: true,
                    no_sse_header: false,
                    sc_max_each_post_bytes: range(1_000_000, 1_000_000),
                    sc_min_posts_interval_ms: range(10, 50),
                    sc_max_buffered_posts: Some(30),
                    xmux: Some(XhttpXmux {
                        max_concurrency: range(16, 32),
                        max_connections: None,
                        c_max_reuse_times: range(0, 8),
                        h_max_request_times: range(600, 900),
                        h_max_reusable_secs: range(1800, 3000),
                        h_keep_alive_period: Some(15),
                    }),
                },
            },
            tls,
            finalmask: None,
        },
        raw: None,
    }
}

fn balanced_node(observatory: Option<XrayObservatory>, strategy: BalancerStrategy) -> Node {
    let primary = BalancerMember {
        tag: "proxy".into(),
        server: "203.0.113.10".into(),
        port: 443,
        outbound: Outbound::Vless(VlessParams {
            uuid: "00000000-0000-4000-8000-000000000001".into(),
            flow: Some("xtls-rprx-vision".into()),
        }),
        stream: StreamSettings {
            transport: Transport::Tcp,
            tls: TlsMode::Reality(RealityParams {
                sni: Some("example.com".into()),
                public_key: "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc".into(),
                short_id: Some("0123abcd".into()),
                fingerprint: Some("firefox".into()),
            }),
            finalmask: None,
        },
    };
    let mask = BalancerMember {
        tag: "mask".into(),
        server: "203.0.113.11".into(),
        port: 443,
        outbound: Outbound::Vless(VlessParams {
            uuid: "00000000-0000-4000-8000-000000000001".into(),
            flow: Some("xtls-rprx-vision".into()),
        }),
        stream: StreamSettings {
            transport: Transport::Tcp,
            tls: TlsMode::Tls(TlsParams {
                sni: Some("mask.example.com".into()),
                alpn: vec!["http/1.1".into()],
                allow_insecure: false,
                fingerprint: Some("firefox".into()),
                enable_session_resumption: Some(false),
            }),
            finalmask: Some(FinalMask {
                tcp: vec![TcpFinalMask::HeaderCustom(HeaderCustomTcp {
                    clients: Vec::new(),
                    servers: vec![vec![HeaderCustomItem {
                        packet_type: Some(HeaderCustomPacketType::Str),
                        packet: Some(HeaderCustomPacket::Text(
                            "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20\r\n".into(),
                        )),
                        ..HeaderCustomItem::default()
                    }]],
                    errors: Vec::new(),
                })],
            }),
        },
    };
    Node {
        id: NodeId::new("example-balanced"),
        name: "Balanced".into(),
        server: "203.0.113.10".into(),
        port: 443,
        outbound: Outbound::XrayBalancer(Box::new(XrayBalancer {
            members: vec![primary, mask],
            selector: vec!["proxy".into()],
            strategy,
            fallback_tag: Some("mask".into()),
            observatory,
        })),
        stream: StreamSettings::default(),
        raw: None,
    }
}

#[test]
#[ignore = "requires the pinned Xray binary"]
fn xray_test_accepts_rendered_session_and_probe_configs() {
    let binary = std::env::var_os("ROSETUN_TEST_XRAY").map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/installer/xray")
                .join(if cfg!(windows) { "xray.exe" } else { "xray" })
        },
        PathBuf::from,
    );
    let version = Command::new(&binary).arg("version").output().unwrap();
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8_lossy(&version.stdout)
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>(),
        ["Xray", SUPPORTED_XRAY_VERSION]
    );

    let directory = std::env::temp_dir().join(format!("rosetun-xray-check-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let reality = TlsMode::Reality(RealityParams {
        sni: Some("example.com".into()),
        public_key: "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc".into(),
        short_id: Some("0123abcd".into()),
        fingerprint: None,
    });
    let tls = TlsMode::Tls(TlsParams {
        sni: Some("example.com".into()),
        alpn: Vec::new(),
        allow_insecure: false,
        fingerprint: None,
        enable_session_resumption: None,
    });
    let fragments = [
        ("off", TlsFragment::default()),
        (
            "hello",
            TlsFragment {
                enabled: true,
                ..TlsFragment::default()
            },
        ),
        (
            "range",
            TlsFragment {
                enabled: true,
                packets: FragmentPackets::Range("1-3".parse().unwrap()),
                length: "100-200".parse().unwrap(),
                interval: "10-20".parse().unwrap(),
            },
        ),
    ];
    for (name, tls) in [
        ("reality", reality.clone()),
        ("tls", tls.clone()),
        ("plain", TlsMode::Plain),
    ] {
        for (mode, fragment) in &fragments {
            let mut node = xhttp_node(tls.clone());
            // Plain VLESS is restricted to private, loopback or link-local servers.
            if matches!(tls, TlsMode::Plain) {
                node.server = "127.0.0.1".into();
            }
            let socks = SocksEndpoint::local().unwrap();
            let config = render(
                &[("proxy", &node, &socks)],
                "Ethernet",
                fragment,
                false,
                LogLevel::Info,
            )
            .unwrap();
            check_config(&binary, &directory, &format!("xhttp-{name}-{mode}"), config);
        }
    }
    for (name, tls) in [("reality-vision", reality.clone()), ("tls-vision", tls)] {
        let mut node = xhttp_node(tls);
        node.stream.transport = Transport::Tcp;
        for (mode, fragment) in &fragments {
            let socks = SocksEndpoint::local().unwrap();
            let config = render(
                &[("proxy", &node, &socks)],
                "Ethernet",
                fragment,
                false,
                LogLevel::Info,
            )
            .unwrap();
            check_config(&binary, &directory, &format!("tcp-{name}-{mode}"), config);
        }
    }

    let burst = balanced_node(
        Some(XrayObservatory::Burst(BurstObservatory {
            subject_selector: vec!["proxy".into()],
            destination: Some("https://connectivitycheck.gstatic.com/generate_204".into()),
            interval: Some("15s".into()),
            timeout: Some("5s".into()),
            sampling: Some(2),
            http_method: Some("GET".into()),
        })),
        BalancerStrategy::LeastLoad(LeastLoadSettings {
            max_rtt: Some("3000ms".into()),
            tolerance_bp: Some(5000),
            expected: None,
            baselines: Vec::new(),
        }),
    );
    let standard = balanced_node(
        Some(XrayObservatory::Standard(StandardObservatory {
            subject_selector: vec!["proxy".into()],
            probe_url: Some("https://connectivitycheck.gstatic.com/generate_204".into()),
            probe_interval: Some("30s".into()),
            enable_concurrency: true,
        })),
        BalancerStrategy::LeastPing,
    );
    for (name, node) in [("balanced-burst", &burst), ("balanced-standard", &standard)] {
        for (mode, fragment) in &fragments {
            let socks = SocksEndpoint::local().unwrap();
            let config = render(
                &[("proxy", node, &socks)],
                "Ethernet",
                fragment,
                false,
                LogLevel::Info,
            )
            .unwrap();
            check_config(&binary, &directory, &format!("{name}-{mode}"), config);
        }
    }

    let mut a = xhttp_node(reality.clone());
    a.stream.transport = Transport::Tcp;
    let exit = xhttp_node(reality);
    let a_socks = SocksEndpoint::local().unwrap();
    let exit_socks = SocksEndpoint::local().unwrap();
    let config = render(
        &[("proxy", &burst, &exit_socks), ("extra-A", &a, &a_socks)],
        "Ethernet",
        &fragments[1].1,
        false,
        LogLevel::Info,
    )
    .unwrap();
    check_config(&binary, &directory, "multiple-with-balanced-and-a", config);

    let config = render(
        &[("proxy", &exit, &exit_socks), ("extra-A", &a, &a_socks)],
        "Ethernet",
        &TlsFragment::default(),
        false,
        LogLevel::Info,
    )
    .unwrap();
    check_config(&binary, &directory, "multiple-with-two-hop-a", config);
    let config = render_probe(
        &[
            ("probe-0".into(), a, a_socks),
            ("probe-1".into(), exit, exit_socks),
        ],
        "Ethernet",
        &fragments[1].1,
    )
    .unwrap();
    check_config(&binary, &directory, "probes", config);
    std::fs::remove_dir_all(&directory).unwrap();
}

fn check_config(
    binary: &Path,
    directory: &Path,
    name: &str,
    config: rosetun_engine::RenderedConfig,
) {
    let path = directory.join(format!("{name}.json"));
    std::fs::write(&path, config.body).unwrap();
    let output = Command::new(binary)
        .args(["run", "-test", "-c"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "xray -test failed for {name}: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
