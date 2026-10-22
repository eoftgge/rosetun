use std::path::PathBuf;
use std::process::Command;

use rosetun_config::{
    LogLevel, Node, NodeId, Outbound, RealityParams, StreamSettings, TlsMode, TlsParams, Transport,
    VlessParams, XhttpExtra, XhttpMode, XhttpRange, XhttpXmux,
};
use rosetun_engine_xray::{SUPPORTED_XRAY_VERSION, SocksEndpoint, render};

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
        },
        raw: None,
    }
}

#[test]
#[ignore = "requires the pinned Xray binary"]
fn xray_test_accepts_rendered_xhttp_configs() {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/installer/xray")
        .join(if cfg!(windows) { "xray.exe" } else { "xray" });
    if !binary.exists() {
        eprintln!("pinned Xray binary is absent; syntax check skipped");
        return;
    }
    let version = Command::new(&binary).arg("version").output().unwrap();
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains(SUPPORTED_XRAY_VERSION));

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
    });
    for (name, tls) in [
        ("reality", reality),
        ("tls", tls),
        ("plain", TlsMode::Plain),
    ] {
        let node = xhttp_node(tls);
        let socks = SocksEndpoint::local().unwrap();
        let config = render(
            &[("proxy", &node, &socks)],
            "Ethernet",
            false,
            LogLevel::Info,
        )
        .unwrap();
        let path = directory.join(format!("xhttp-{name}.json"));
        std::fs::write(&path, config.body).unwrap();
        let output = Command::new(&binary)
            .args(["run", "-test", "-c"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "xray -test failed for {name}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    std::fs::remove_dir_all(&directory).unwrap();
}
