use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use rosetun_config::{
    DnsSettings, ExitId, ListId, ListRef, Node, NodeId, Outbound, Rule, RuleId, RuleMatcher,
    RuleSet, RuleSetId, RuleTarget, Settings, ShadowsocksParams, StreamSettings,
    UploadedListFormat, list_tag,
};
use rosetun_engine::{
    ControlEndpoint, EngineBackend, ExtraOutbound, PROXY_TAG, RenderRequest, SocksProxy, exit_tag,
};
use rosetun_engine_singbox::SingBoxBackend;

static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "rosetun-sing-box-check-{}-{}",
            std::process::id(),
            NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&directory).unwrap();
        Self(directory)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn pinned_binary() -> Option<PathBuf> {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/installer/sing-box")
        .join(if cfg!(windows) {
            "sing-box.exe"
        } else {
            "sing-box"
        });
    if !binary.exists() {
        eprintln!("pinned sing-box binary is absent; syntax check skipped");
        return None;
    }
    let version = Command::new(&binary).arg("version").output().unwrap();
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains("1.14.3"));
    Some(binary)
}

fn example_node() -> Node {
    Node {
        id: NodeId::new("example-node"),
        name: "Example".into(),
        server: "203.0.113.10".into(),
        port: 8388,
        outbound: Outbound::Shadowsocks(ShadowsocksParams {
            method: "aes-128-gcm".into(),
            password: "test-secret".into(),
        }),
        stream: StreamSettings::default(),
        raw: None,
    }
}

#[test]
#[ignore = "requires the pinned sing-box 1.14.3 binary"]
fn sing_box_check_accepts_the_delay_entry_and_its_rules() {
    let Some(binary) = pinned_binary() else {
        return;
    };
    let directory = TestDirectory::new();
    let node = example_node();
    let (first, last) = (ExitId::new("first"), ExitId::new("last"));
    let mut second = example_node();
    second.server = "198.51.100.2".into();
    second.outbound = Outbound::Http(rosetun_config::ProxyCredentials::default());
    let extra = [
        ExtraOutbound {
            index: 0,
            via: None,
            exit: &first,
            node: &node,
            socks: None,
        },
        ExtraOutbound {
            index: 1,
            via: Some(&first),
            exit: &last,
            node: &second,
            socks: None,
        },
    ];
    let control = ControlEndpoint::local()
        .unwrap()
        .with_delay_inbound([PROXY_TAG.to_owned(), exit_tag(0), exit_tag(1)])
        .unwrap();
    let mut rules = RuleSet::new(
        RuleSetId::new("example-rules"),
        "Example",
        RuleTarget::Proxy,
    );
    rules.rules.push(Rule {
        id: RuleId::new("example-rule"),
        enabled: true,
        matcher: RuleMatcher::Domain(rosetun_config::DomainMatch::Suffix("example.com".into())),
        target: RuleTarget::Exit,
        exit: Some(last.clone()),
    });
    let mut settings = Settings {
        dns: DnsSettings {
            server: "192.0.2.53".parse().unwrap(),
            server_name: "dns.example.com".into(),
            port: None,
            path: Some("/dns-query".into()),
        },
        kill_switch: true,
        ..Settings::default()
    };
    settings.tun.ipv4 = "198.51.100.1/30".into();
    for (name, listen) in [
        ("tunnel", None),
        (
            "proxy",
            Some(rosetun_engine::LocalProxyListen {
                addresses: vec!["127.0.0.1:10808".parse().unwrap()],
                dns: "127.0.0.1:53535".parse().unwrap(),
            }),
        ),
    ] {
        let config = SingBoxBackend::new(&directory.0)
            .render(&RenderRequest {
                extra: &extra,
                node: &node,
                socks: None,
                rules: &rules,
                lists: &[],
                settings: &settings,
                lan_segment: &[],
                lan_servers: &[],
                control: Some(&control),
                verbose_log: false,
                local_proxy: listen.as_ref(),
            })
            .unwrap();
        assert!(config.unsupported.is_empty());
        let path = directory.0.join(format!("delay-{name}.json"));
        std::fs::write(&path, config.body).unwrap();
        let output = Command::new(&binary)
            .arg("check")
            .arg("-c")
            .arg(&path)
            .current_dir(&directory.0)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "the {name} configuration with the delay entry was rejected: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
#[ignore = "requires the pinned sing-box 1.14.3 binary"]
fn sing_box_check_validates_local_rule_set_config() {
    let Some(binary) = pinned_binary() else {
        return;
    };

    let directory = TestDirectory::new();
    let list = ListId::new("example-list");
    let tag = list_tag(&list, None);
    let source = br#"{"rules":[{"domain_suffix":["example.com"]}],"version":3}"#;
    let source = rosetun_config::normalize_source(source).unwrap();
    std::fs::write(directory.0.join(format!("{tag}.json")), source).unwrap();
    let mut rules = RuleSet::new(
        RuleSetId::new("example-rules"),
        "Example",
        RuleTarget::Proxy,
    );
    rules.rules.push(Rule {
        id: RuleId::new("example-list-rule"),
        enabled: true,
        matcher: RuleMatcher::List {
            list,
            category: None,
        },
        target: RuleTarget::Block,
        exit: None,
    });
    let node = example_node();
    let mut settings = Settings {
        dns: DnsSettings {
            server: "192.0.2.53".parse().unwrap(),
            server_name: "dns.example.com".into(),
            port: None,
            path: Some("/dns-query".into()),
        },
        kill_switch: true,
        ..Settings::default()
    };
    settings.tun.ipv4 = "198.51.100.1/30".into();
    let lists = [ListRef {
        tag,
        sha256: "a".repeat(64),
        format: UploadedListFormat::Source,
    }];
    let config = SingBoxBackend::new(&directory.0)
        .render(&RenderRequest {
            extra: &[],
            node: &node,
            socks: None,
            rules: &rules,
            lists: &lists,
            settings: &settings,
            lan_segment: &[],
            lan_servers: &[],
            control: None,
            verbose_log: false,
            local_proxy: None,
        })
        .unwrap();
    assert!(config.unsupported.is_empty());
    let config_path = directory.0.join("config.json");
    std::fs::write(&config_path, config.body).unwrap();
    for protocol in ["http", "https", "socks5"] {
        let mut proxy = node.clone();
        let credentials = rosetun_config::ProxyCredentials {
            username: "fixture-user".into(),
            password: "fixture-password:@/%".into(),
        };
        proxy.outbound = if protocol == "socks5" {
            Outbound::Socks5(credentials)
        } else {
            Outbound::Http(credentials)
        };
        if protocol == "https" {
            proxy.stream.tls = rosetun_config::TlsMode::Tls(rosetun_config::TlsParams {
                sni: Some("proxy.example.com".into()),
                ..Default::default()
            });
        }
        let rendered = SingBoxBackend::new(&directory.0)
            .render(&RenderRequest {
                node: &proxy,
                socks: None,
                extra: &[],
                rules: &rules,
                lists: &lists,
                settings: &settings,
                lan_segment: &[],
                lan_servers: &[],
                control: None,
                verbose_log: false,
                local_proxy: None,
            })
            .unwrap();
        let path = directory.0.join(format!("{protocol}.json"));
        std::fs::write(&path, rendered.body).unwrap();
        assert!(
            Command::new(&binary)
                .arg("check")
                .arg("-c")
                .arg(&path)
                .current_dir(&directory.0)
                .status()
                .unwrap()
                .success(),
            "proxy configuration rejected: {protocol}"
        );
    }
    let mut tuic = node.clone();
    tuic.port = 8444;
    tuic.outbound = Outbound::Tuic(rosetun_config::TuicParams {
        uuid: "00000000-0000-4000-8000-000000000001".into(),
        password: "fixture-password".into(),
        congestion_control: Some(rosetun_config::TuicCongestionControl::Bbr),
        udp_relay_mode: Some(rosetun_config::TuicUdpRelayMode::Quic),
        zero_rtt_handshake: true,
        heartbeat: Some("10s".into()),
        disable_sni: true,
    });
    tuic.stream.tls = rosetun_config::TlsMode::Tls(rosetun_config::TlsParams {
        sni: Some("tuic.example.com".into()),
        alpn: vec!["h3".into()],
        allow_insecure: true,
        fingerprint: None,
    });
    let mut anytls = node.clone();
    anytls.port = 8445;
    anytls.outbound = Outbound::AnyTls(rosetun_config::AnyTlsParams {
        password: "fixture-password".into(),
        idle_session_check_interval: Some("30s".into()),
        idle_session_timeout: Some("60s".into()),
        min_idle_session: Some(2),
    });
    anytls.stream.tls = rosetun_config::TlsMode::Tls(rosetun_config::TlsParams {
        sni: Some("anytls.example.com".into()),
        alpn: vec!["h2".into()],
        allow_insecure: false,
        fingerprint: Some("firefox".into()),
    });
    let mut anytls_reality = anytls.clone();
    anytls_reality.stream.tls = rosetun_config::TlsMode::Reality(rosetun_config::RealityParams {
        sni: Some("anytls.example.com".into()),
        public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        short_id: Some("01234567".into()),
        fingerprint: Some("chrome".into()),
    });
    let mut wireguard = node.clone();
    wireguard.port = 51820;
    wireguard.outbound = Outbound::WireGuard(rosetun_config::WireGuardParams {
        private_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
        public_key: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".into(),
        pre_shared_key: Some("AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=".into()),
        address: vec!["10.0.0.2/32".into(), "fd00::2/128".into()],
        reserved: Some([1, 2, 3]),
        mtu: Some(1280),
        persistent_keepalive: Some(25),
    });
    wireguard.stream = StreamSettings::default();
    for (name, protocol_node) in [
        ("tuic", &tuic),
        ("anytls", &anytls),
        ("anytls-reality", &anytls_reality),
        ("wireguard", &wireguard),
    ] {
        let rendered = SingBoxBackend::new(&directory.0)
            .render(&RenderRequest {
                node: protocol_node,
                socks: None,
                extra: &[],
                rules: &rules,
                lists: &lists,
                settings: &settings,
                lan_segment: &[],
                lan_servers: &[],
                control: None,
                verbose_log: false,
                local_proxy: None,
            })
            .unwrap();
        let path = directory.0.join(format!("{name}.json"));
        std::fs::write(&path, rendered.body).unwrap();
        let output = Command::new(&binary)
            .arg("check")
            .arg("-c")
            .arg(&path)
            .current_dir(&directory.0)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "sing-box check rejected {name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    // Two-hop WireGuard -> SOCKS5 and probe config with WireGuard endpoint.
    let (wg_exit, socks_exit) = (ExitId::new("wg"), ExitId::new("socks"));
    let mut second_hop = node.clone();
    second_hop.server = "198.51.100.2".into();
    second_hop.port = 1080;
    second_hop.outbound = Outbound::Socks5(rosetun_config::ProxyCredentials::default());
    let wg_extra = [
        ExtraOutbound {
            index: 0,
            via: None,
            exit: &wg_exit,
            node: &wireguard,
            socks: None,
        },
        ExtraOutbound {
            index: 1,
            via: Some(&wg_exit),
            exit: &socks_exit,
            node: &second_hop,
            socks: None,
        },
    ];
    let wg_chain = SingBoxBackend::new(&directory.0)
        .render(&RenderRequest {
            node: &wireguard,
            socks: None,
            extra: &wg_extra,
            rules: &rules,
            lists: &lists,
            settings: &settings,
            lan_segment: &[],
            lan_servers: &[],
            control: None,
            verbose_log: false,
            local_proxy: None,
        })
        .unwrap();
    let wg_chain_path = directory.0.join("wireguard-chain.json");
    std::fs::write(&wg_chain_path, wg_chain.body).unwrap();
    let output = Command::new(&binary)
        .arg("check")
        .arg("-c")
        .arg(&wg_chain_path)
        .current_dir(&directory.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sing-box check rejected wireguard two-hop chain: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let probe_control = ControlEndpoint::local().unwrap();
    let wg_probe_nodes = [("probe-0".to_owned(), wireguard.clone())];
    let wg_probe = SingBoxBackend::new(&directory.0)
        .render_probe(&rosetun_engine::ProbeRenderRequest {
            nodes: &wg_probe_nodes,
            socks: &[],
            interface: None,
            control: &probe_control,
        })
        .unwrap();
    let wg_probe_path = directory.0.join("wireguard-probe.json");
    std::fs::write(&wg_probe_path, wg_probe.body).unwrap();
    let output = Command::new(&binary)
        .arg("check")
        .arg("-c")
        .arg(&wg_probe_path)
        .current_dir(&directory.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sing-box check rejected wireguard probe config: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    for address in ["127.0.0.1:10808", "[::]:10808"] {
        let config = SingBoxBackend::new(&directory.0)
            .render(&RenderRequest {
                extra: &[],
                node: &node,
                socks: None,
                rules: &rules,
                lists: &lists,
                settings: &settings,
                lan_segment: &[],
                lan_servers: &[],
                control: None,
                verbose_log: false,
                local_proxy: Some(&rosetun_engine::LocalProxyListen {
                    addresses: vec![address.parse().unwrap()],
                    dns: "127.0.0.1:53535".parse().unwrap(),
                }),
            })
            .unwrap();
        let path = directory.0.join("local-proxy.json");
        std::fs::write(&path, config.body).unwrap();
        assert!(
            Command::new(&binary)
                .arg("check")
                .arg("-c")
                .arg(&path)
                .current_dir(&directory.0)
                .status()
                .unwrap()
                .success(),
            "local proxy configuration rejected: {address}"
        );
    }
    for (path, body) in [
        (config_path, None),
        (
            directory.0.join("xray-chain.json"),
            Some(SocksProxy {
                address: "127.0.0.1:10801".parse().unwrap(),
                username: "fixture-user",
                password: "fixture-password",
            }),
        ),
    ] {
        if let Some(socks) = body {
            let chain = SingBoxBackend::new(&directory.0)
                .render(&RenderRequest {
                    extra: &[],
                    node: &node,
                    socks: Some(socks),
                    rules: &rules,
                    lists: &lists,
                    settings: &settings,
                    lan_segment: &[],
                    lan_servers: &[],
                    control: None,
                    verbose_log: false,
                    local_proxy: None,
                })
                .unwrap();
            std::fs::write(&path, chain.body).unwrap();
        }
        let status = Command::new(&binary)
            .arg("check")
            .arg("-c")
            .arg(&path)
            .current_dir(&directory.0)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "sing-box check failed for {} with exit code {:?}",
            path.display(),
            status.code()
        );
    }
}
