use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use rosetun_config::{
    DnsSettings, ListId, ListRef, Node, NodeId, Outbound, Rule, RuleId, RuleMatcher, RuleSet,
    RuleSetId, RuleTarget, Settings, ShadowsocksParams, StreamSettings, UploadedListFormat,
    list_tag,
};
use rosetun_engine::{EngineBackend, RenderRequest};
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

#[test]
#[ignore = "requires the pinned sing-box 1.14.1 binary"]
fn sing_box_check_validates_local_rule_set_config() {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/installer/sing-box")
        .join(if cfg!(windows) {
            "sing-box.exe"
        } else {
            "sing-box"
        });
    if !binary.exists() {
        eprintln!("pinned sing-box binary is absent; syntax check skipped");
        return;
    }
    let version = Command::new(&binary).arg("version").output().unwrap();
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains("1.14.1"));

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
    });
    let node = Node {
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
    };
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
            node: &node,
            rules: &rules,
            lists: &lists,
            fallback_block_rules: &[],
            settings: &settings,
            control: None,
            verbose_log: false,
        })
        .unwrap();
    assert!(config.unsupported.is_empty());
    let config_path = directory.0.join("config.json");
    std::fs::write(&config_path, config.body).unwrap();
    let status = Command::new(binary)
        .arg("check")
        .arg("-c")
        .arg(config_path)
        .current_dir(&directory.0)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "sing-box check failed with exit code {:?}",
        status.code()
    );
}
