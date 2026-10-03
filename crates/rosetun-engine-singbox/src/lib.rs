#![forbid(unsafe_code)]

mod readiness;
mod render;
mod version;

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::thread;

use readiness::Readiness;
use rosetun_config::{EngineKind, Traffic};
use rosetun_engine::{
    EngineBackend, EngineCapabilities, EngineIntegration, EngineProcess, RenderRequest,
    RenderedConfig, errors::EngineError,
};

pub use render::render;
pub use version::SUPPORTED_SING_BOX_VERSION;

const BINARY: &str = if cfg!(windows) {
    "sing-box.exe"
} else {
    "sing-box"
};

#[derive(Debug, Clone)]
pub struct SingBoxBackend {
    work_dir: PathBuf,
    binary: Option<PathBuf>,
}

impl SingBoxBackend {
    pub fn new(work_dir: impl Into<PathBuf>) -> Self {
        Self {
            work_dir: work_dir.into(),
            binary: None,
        }
    }

    pub fn with_binary(work_dir: impl Into<PathBuf>, binary: impl Into<PathBuf>) -> Self {
        Self {
            work_dir: work_dir.into(),
            binary: Some(binary.into()),
        }
    }
}

impl EngineBackend for SingBoxBackend {
    fn kind(&self) -> EngineKind {
        EngineKind::SingBox
    }

    fn integration(&self) -> EngineIntegration {
        EngineIntegration::EngineManagedTun
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            rules: render::RULE_CAPABILITIES,
        }
    }

    fn locate_binary(&self) -> Result<PathBuf, EngineError> {
        let binary = match &self.binary {
            Some(binary) if binary.is_file() => binary.clone(),
            Some(binary) => {
                return Err(EngineError::BinaryNotFound(binary.display().to_string()));
            }
            None => find_in_neighbours()
                .ok_or_else(|| EngineError::BinaryNotFound(BINARY.to_owned()))?,
        };
        let binary = std::fs::canonicalize(binary)?;

        version::check(&binary)?;
        Ok(binary)
    }

    fn render(&self, request: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError> {
        render::render(request)
    }

    fn spawn(
        &self,
        binary: &Path,
        config: &RenderedConfig,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        std::fs::create_dir_all(&self.work_dir)?;
        let config_path = self.work_dir.join(&config.file_name);
        std::fs::write(&config_path, &config.body)?;

        tracing::info!(binary = %binary.display(), config = %config_path.display(), "starting sing-box");
        let mut child = Command::new(binary)
            .arg("run")
            .arg("-c")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let (ready_sender, readiness) = Readiness::new();

        if let Some(stdout) = child.stdout.take()
            && let Err(error) = spawn_output_drain(stdout, "stdout", None)
        {
            stop_failed_spawn(&mut child);
            return Err(error.into());
        }

        let Some(stderr) = child.stderr.take() else {
            stop_failed_spawn(&mut child);
            return Err(std::io::Error::other("sing-box stderr pipe is unavailable").into());
        };

        if let Err(error) = spawn_output_drain(stderr, "stderr", Some(ready_sender)) {
            stop_failed_spawn(&mut child);
            return Err(error.into());
        }

        Ok(Box::new(SingBoxProcess { child, readiness }))
    }
}

fn stop_failed_spawn(child: &mut Child) {
    if let Err(error) = child.kill() {
        tracing::error!(%error, "failed to kill sing-box after startup setup failed");
    }
    if let Err(error) = child.wait() {
        tracing::error!(%error, "failed to reap sing-box after startup setup failed");
    }
}

fn spawn_output_drain<R>(
    reader: R,
    stream: &'static str,
    mut ready_sender: Option<Sender<()>>,
) -> std::io::Result<()>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .name(format!("sing-box-{stream}"))
        .spawn(move || {
            for line in BufReader::new(reader).lines() {
                match line {
                    Ok(line) => {
                        if ready_sender.is_some()
                            && readiness::is_startup_message(&line)
                            && let Some(sender) = ready_sender.take()
                        {
                            let _ = sender.send(());
                        }
                        tracing::info!(stream, "{line}");
                    }
                    Err(error) => {
                        tracing::debug!(
                            stream,
                            %error,
                            "sing-box output stream closed with a read error"
                        );
                        break;
                    }
                }
            }
            // Dropping the sender reports EOF if no readiness signal was sent.
            tracing::debug!(stream, "sing-box output stream closed");
        })
        .map(|_| ())
}

fn find_in_neighbours() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let candidate = exe.parent()?.join(BINARY);
    candidate.is_file().then_some(candidate)
}

#[derive(Debug)]
struct SingBoxProcess {
    child: Child,
    readiness: Readiness,
}

impl EngineProcess for SingBoxProcess {
    fn is_running(&mut self) -> Result<bool, EngineError> {
        match self.child.try_wait()? {
            Some(status) => Err(EngineError::Exited {
                code: status.code(),
            }),
            None => Ok(true),
        }
    }

    fn is_ready(&mut self) -> Result<bool, EngineError> {
        self.readiness.poll().map_err(EngineError::from)
    }

    fn traffic(&mut self) -> Result<Traffic, EngineError> {
        Err(EngineError::StatsUnavailable)
    }

    fn stop(&mut self) -> Result<(), EngineError> {
        if self.child.try_wait()?.is_some() {
            return Ok(());
        }

        // TODO: on Unix, first issue SIGTERM to allow the engine time to remove the routes,
        // and only then kill. It's rough now, but predictable.
        match self.child.kill() {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {}
            Err(error) => {
                // The process can exit between try_wait and kill.
                if self.child.try_wait()?.is_none() {
                    return Err(error.into());
                }
                return Ok(());
            }
        }
        self.child.wait()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rosetun_config::{
        DomainMatch, Node, NodeId, Outbound, ProcessMatch, RealityParams, Rule, RuleId,
        RuleMatcher, RuleSet, RuleSetId, RuleTarget, Settings, StreamSettings, TlsMode,
        VlessParams,
    };
    use rosetun_engine::RuleCapabilities;
    use serde_json::Value;

    fn node() -> Node {
        Node {
            id: NodeId::new("n1"),
            name: "Sakura-02".to_owned(),
            server: "203.0.113.10".to_owned(),
            port: 443,
            outbound: Outbound::Vless(VlessParams {
                uuid: "11111111-2222-3333-4444-555555555555".to_owned(),
                flow: Some("xtls-rprx-vision".to_owned()),
            }),
            stream: StreamSettings {
                transport: rosetun_config::Transport::Tcp,
                tls: TlsMode::Reality(RealityParams {
                    sni: Some("www.example.com".to_owned()),
                    public_key: "PUBKEY".to_owned(),
                    short_id: Some("ab".to_owned()),
                    fingerprint: None,
                }),
            },
            raw: None,
        }
    }

    fn rules() -> RuleSet {
        RuleSet {
            id: RuleSetId::new("base"),
            name: "Base".to_owned(),
            rules: vec![
                Rule {
                    id: RuleId::new("r1"),
                    enabled: true,
                    matcher: RuleMatcher::Domain(DomainMatch::Suffix("google.com".to_owned())),
                    target: RuleTarget::Proxy,
                },
                Rule {
                    id: RuleId::new("r2"),
                    enabled: true,
                    matcher: RuleMatcher::Process(ProcessMatch::Name("steam.exe".to_owned())),
                    target: RuleTarget::Direct,
                },
                Rule {
                    id: RuleId::new("r3"),
                    enabled: false,
                    matcher: RuleMatcher::Domain(DomainMatch::Exact("blocked.test".to_owned())),
                    target: RuleTarget::Block,
                },
            ],
            default_target: RuleTarget::Proxy,
        }
    }

    fn rendered() -> Value {
        let node = node();
        let rules = rules();
        let settings = Settings {
            allow_lan: true,
            ..Settings::default()
        };
        let request = RenderRequest {
            node: &node,
            rules: &rules,
            settings: &settings,
        };
        let config = render::render(&request).expect("config built");
        serde_json::from_slice(&config.body).expect("config is valid json")
    }

    #[test]
    fn reality_lands_inside_tls() {
        let config = rendered();
        let tls = &config["outbounds"][0]["tls"];
        assert_eq!(tls["server_name"], "www.example.com");
        assert_eq!(tls["reality"]["enabled"], true);
        assert_eq!(tls["reality"]["public_key"], "PUBKEY");
        assert_eq!(tls["utls"]["fingerprint"], "chrome");
    }

    #[test]
    fn disabled_rules_are_dropped() {
        let config = rendered();
        let rules = config["route"]["rules"].as_array().expect("rules array");
        assert_eq!(
            rules.len(),
            5,
            "sniff, DNS hijack, two enabled user rules, and LAN"
        );
        assert!(
            rules.iter().all(|rule| rule.get("domain").is_none()),
            "the disabled exact-domain rule must be absent"
        );
    }

    #[test]
    fn unsupported_enabled_rules_are_reported_and_omitted() {
        let rendered = render::route_section(
            &rules(),
            RuleCapabilities {
                domain_exact: true,
                domain_suffix: true,
                domain_keyword: true,
                process_name: false,
                process_path: false,
                ip_cidr: true,
            },
            true,
        );

        assert_eq!(rendered.1, vec![RuleId::new("r2")]);
        let rules = rendered.0["rules"].as_array().expect("rules array");
        assert_eq!(
            rules.len(),
            4,
            "sniff, DNS hijack, one supported user rule, and LAN"
        );
        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(rules[1]["action"], "hijack-dns");
        assert_eq!(rules[2]["domain_suffix"][0], "google.com");
        assert_eq!(rules[3]["ip_is_private"], true);
        assert!(rules.iter().all(|rule| rule.get("process_name").is_none()));
    }

    #[test]
    fn rule_order_is_preserved() {
        let config = rendered();
        let rules = config["route"]["rules"].as_array().expect("rules array");

        assert_eq!(rules.len(), 5);
        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(rules[1]["action"], "hijack-dns");
        assert_eq!(rules[2]["domain_suffix"][0], "google.com");
        assert_eq!(rules[2]["outbound"], "proxy");
        assert_eq!(rules[3]["process_name"][0], "steam.exe");
        assert_eq!(rules[3]["outbound"], "direct");
        assert_eq!(rules[4]["ip_is_private"], true);
        assert_eq!(rules[4]["outbound"], "direct");
    }

    #[test]
    fn every_advertised_matcher_is_rendered_after_sniff() {
        let cases = [
            (
                RuleMatcher::Domain(DomainMatch::Exact("exact.test".into())),
                "domain",
                "exact.test",
            ),
            (
                RuleMatcher::Domain(DomainMatch::Suffix("suffix.test".into())),
                "domain_suffix",
                "suffix.test",
            ),
            (
                RuleMatcher::Domain(DomainMatch::Keyword("keyword".into())),
                "domain_keyword",
                "keyword",
            ),
            (
                RuleMatcher::Process(ProcessMatch::Name("app.exe".into())),
                "process_name",
                "app.exe",
            ),
            (
                RuleMatcher::Process(ProcessMatch::Path(std::path::PathBuf::from("app.exe"))),
                "process_path",
                "app.exe",
            ),
            (
                RuleMatcher::IpCidr("192.0.2.0/24".into()),
                "ip_cidr",
                "192.0.2.0/24",
            ),
        ];

        let mut rule_set = rules();
        rule_set.rules = cases
            .iter()
            .enumerate()
            .map(|(index, (matcher, _, _))| Rule {
                id: RuleId::new(format!("cap-{index}")),
                enabled: true,
                matcher: matcher.clone(),
                target: RuleTarget::Direct,
            })
            .collect();

        let backend = SingBoxBackend::new("unused");
        assert_eq!(backend.capabilities().rules, render::RULE_CAPABILITIES);

        let node = node();
        let settings = Settings {
            allow_lan: true,
            ..Settings::default()
        };
        let config = render::render(&RenderRequest {
            node: &node,
            rules: &rule_set,
            settings: &settings,
        })
        .expect("rendered");

        assert!(config.unsupported.is_empty());
        let config: Value = serde_json::from_slice(&config.body).expect("json");
        let route = config["route"]["rules"].as_array().expect("rules");
        assert_eq!(route.len(), cases.len() + 3);
        assert_eq!(route[0]["action"], "sniff");
        assert_eq!(route[1]["action"], "hijack-dns");

        for (index, (matcher, field, expected)) in cases.iter().enumerate() {
            assert!(backend.capabilities().rules.supports(matcher));
            assert_eq!(route[index + 2][*field][0], *expected);
            assert_eq!(route[index + 2]["action"], "route");
            assert_eq!(route[index + 2]["outbound"], "direct");
        }

        let lan = route.last().expect("LAN rule");
        assert_eq!(lan["ip_is_private"], true);
        assert_eq!(lan["action"], "route");
        assert_eq!(lan["outbound"], "direct");
    }

    #[test]
    fn block_uses_reject_for_rule_and_default() {
        let mut rule_set = rules();
        rule_set.rules[0].target = RuleTarget::Block;
        rule_set.default_target = RuleTarget::Block;

        let (route, unsupported) =
            render::route_section(&rule_set, render::RULE_CAPABILITIES, true);

        assert!(unsupported.is_empty());
        let rules = route["rules"].as_array().expect("rules");
        assert_eq!(rules.len(), 6);

        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(rules[1]["action"], "hijack-dns");

        assert_eq!(rules[2]["domain_suffix"][0], "google.com");
        assert_eq!(rules[2]["action"], "reject");
        assert!(rules[2].get("outbound").is_none());

        assert_eq!(rules[3]["process_name"][0], "steam.exe");
        assert_eq!(rules[3]["outbound"], "direct");

        assert_eq!(rules[4]["ip_is_private"], true);
        assert_eq!(rules[4]["outbound"], "direct");

        let fallback = rules.last().expect("fallback");
        assert_eq!(fallback["action"], "reject");
        assert!(fallback.get("outbound").is_none());
    }

    #[test]
    fn sniff_precedes_every_domain_rule() {
        let mut rule_set = rules();
        rule_set.rules = vec![
            Rule {
                id: RuleId::new("exact"),
                enabled: true,
                matcher: RuleMatcher::Domain(DomainMatch::Exact("direct.example".to_owned())),
                target: RuleTarget::Direct,
            },
            Rule {
                id: RuleId::new("suffix"),
                enabled: true,
                matcher: RuleMatcher::Domain(DomainMatch::Suffix("proxy.example".to_owned())),
                target: RuleTarget::Proxy,
            },
            Rule {
                id: RuleId::new("keyword"),
                enabled: true,
                matcher: RuleMatcher::Domain(DomainMatch::Keyword("blocked".to_owned())),
                target: RuleTarget::Block,
            },
        ];
        rule_set.default_target = RuleTarget::Proxy;

        let node = node();
        let settings = Settings {
            allow_lan: true,
            ..Settings::default()
        };
        let rendered = render::render(&RenderRequest {
            node: &node,
            rules: &rule_set,
            settings: &settings,
        })
        .expect("config rendered");

        assert!(rendered.unsupported.is_empty());

        let config: Value = serde_json::from_slice(&rendered.body).expect("valid JSON");
        let route_rules = config["route"]["rules"]
            .as_array()
            .expect("route rules array");

        assert_eq!(route_rules.len(), 6);
        assert_eq!(route_rules[0]["action"], "sniff");
        assert_eq!(route_rules[1]["action"], "hijack-dns");

        // User rules retain their order after sniff and DNS hijack.
        assert_eq!(route_rules[2]["domain"][0], "direct.example");
        assert_eq!(route_rules[2]["action"], "route");
        assert_eq!(route_rules[2]["outbound"], "direct");

        assert_eq!(route_rules[3]["domain_suffix"][0], "proxy.example");
        assert_eq!(route_rules[3]["action"], "route");
        assert_eq!(route_rules[3]["outbound"], "proxy");

        assert_eq!(route_rules[4]["domain_keyword"][0], "blocked");
        assert_eq!(route_rules[4]["action"], "reject");

        assert_eq!(route_rules[5]["ip_is_private"], true);
        assert_eq!(route_rules[5]["action"], "route");
        assert_eq!(route_rules[5]["outbound"], "direct");

        let domain_fields = ["domain", "domain_suffix", "domain_keyword"];
        let domain_indices: Vec<usize> = route_rules
            .iter()
            .enumerate()
            .filter_map(|(index, rule)| {
                domain_fields
                    .iter()
                    .any(|field| rule.get(*field).is_some())
                    .then_some(index)
            })
            .collect();

        assert_eq!(domain_indices, vec![2, 3, 4]);
        assert!(domain_indices.iter().all(|&index| index > 1));
        assert_eq!(config["route"]["final"], "proxy");
    }

    #[test]
    fn default_target_becomes_final() {
        let config = rendered();
        assert_eq!(config["route"]["final"], "proxy");
    }

    #[test]
    fn tun_settings_reach_the_inbound() {
        let config = rendered();
        let inbound = &config["inbounds"][0];
        assert_eq!(inbound["type"], "tun");
        assert_eq!(inbound["interface_name"], "rosetun0");
        assert_eq!(inbound["address"][0], "172.19.0.1/30");
    }

    #[test]
    fn unknown_protocol_is_rejected() {
        let mut node = node();
        node.outbound = Outbound::Unknown {
            scheme: "hysteria2".to_owned(),
            params: Default::default(),
        };
        let rules = rules();
        let settings = Settings::default();
        let request = RenderRequest {
            node: &node,
            rules: &rules,
            settings: &settings,
        };
        assert!(matches!(
            render::render(&request),
            Err(EngineError::Unsupported(_))
        ));
    }

    #[test]
    fn dns_uses_one_typed_public_server_through_proxy() {
        let config = rendered();
        let servers = config["dns"]["servers"].as_array().expect("DNS servers");

        assert_eq!(servers.len(), 1);
        assert_eq!(
            servers[0],
            serde_json::json!({
                "type": "udp",
                "tag": "dns-proxy",
                "server": "1.1.1.1",
                "server_port": 53,
                "detour": "proxy",
            })
        );
        assert!(config["dns"].get("rules").is_none());
    }

    #[test]
    fn dns_hijack_precedes_user_rules_and_block_fallback() {
        let node = node();
        let settings = Settings {
            allow_lan: true,
            ..Settings::default()
        };
        let mut rule_set = rules();
        rule_set.default_target = RuleTarget::Block;

        let rendered = render::render(&RenderRequest {
            node: &node,
            rules: &rule_set,
            settings: &settings,
        })
        .expect("config rendered");
        assert!(rendered.unsupported.is_empty());

        let config: Value = serde_json::from_slice(&rendered.body).expect("valid JSON");
        let route_rules = config["route"]["rules"].as_array().expect("route rules");

        assert_eq!(
            route_rules,
            &vec![
                serde_json::json!({
                    "action": "sniff",
                    "sniffer": ["http", "tls", "quic", "dns"],
                }),
                serde_json::json!({
                    "protocol": "dns",
                    "action": "hijack-dns",
                }),
                serde_json::json!({
                    "domain_suffix": ["google.com"],
                    "action": "route",
                    "outbound": "proxy",
                }),
                serde_json::json!({
                    "process_name": ["steam.exe"],
                    "action": "route",
                    "outbound": "direct",
                }),
                serde_json::json!({
                    "ip_is_private": true,
                    "action": "route",
                    "outbound": "direct",
                }),
                serde_json::json!({
                    "action": "reject",
                }),
            ]
        );
    }

    #[test]
    fn private_direct_is_opt_in_and_follows_dns_hijack() {
        for allow_lan in [false, true] {
            let settings = Settings {
                allow_lan,
                ..Settings::default()
            };
            let node = node();
            let rules = rules();
            let rendered = render::render(&RenderRequest {
                node: &node,
                rules: &rules,
                settings: &settings,
            })
            .expect("rendered");
            let config: Value = serde_json::from_slice(&rendered.body).expect("JSON");
            let route = config["route"]["rules"].as_array().expect("rules");

            let dns = route
                .iter()
                .position(|rule| rule["action"] == "hijack-dns")
                .expect("DNS hijack");
            let private = route.iter().position(|rule| rule["ip_is_private"] == true);

            assert_eq!(private.is_some(), allow_lan);
            if let Some(private) = private {
                assert!(dns < private);
                assert_eq!(route[private]["outbound"], "direct");
            }
        }
    }
}
