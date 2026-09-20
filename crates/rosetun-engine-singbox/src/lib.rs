#![forbid(unsafe_code)]

mod render;

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;

use rosetun_config::{EngineKind, Traffic};
use rosetun_engine::{
    EngineBackend, EngineCapabilities, EngineIntegration, EngineProcess, RenderRequest,
    RenderedConfig, RuleCapabilities,
};

pub use render::render;
use rosetun_engine::errors::EngineError;

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
            rules: RuleCapabilities::ALL,
        }
    }

    fn locate_binary(&self) -> Result<PathBuf, EngineError> {
        if let Some(binary) = &self.binary {
            return if binary.is_file() {
                Ok(binary.clone())
            } else {
                Err(EngineError::BinaryNotFound(binary.display().to_string()))
            };
        }
        find_in_neighbours()
            .or_else(|| find_in_path())
            .ok_or_else(|| EngineError::BinaryNotFound(BINARY.to_owned()))
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

        if let Some(stdout) = child.stdout.take() {
            spawn_output_drain(stdout, "rosetun.engine.singbox.stdout");
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_output_drain(stderr, "rosetun.engine.singbox.stderr");
        }

        Ok(Box::new(SingBoxProcess { child }))
    }
}

fn spawn_output_drain<R>(reader: R, target: &'static str)
where
    R: Read + Send + 'static,
{
    let _ = thread::Builder::new()
        .name(target.to_owned())
        .spawn(move || {
            let reader = BufReader::new(reader);

            for line in reader.lines() {
                match line {
                    Ok(line) => match target {
                        "rosetun.engine.singbox.stdout" => {
                            tracing::info!(
                                target: "rosetun.engine.singbox.stdout",
                                "{line}"
                            );
                        }
                        "rosetun.engine.singbox.stderr" => {
                            tracing::info!(
                                target: "rosetun.engine.singbox.stderr",
                                "{line}"
                            );
                        }
                        _ => unreachable!("unknown sing-box output target"),
                    },
                    Err(error) => {
                        match target {
                            "rosetun.engine.singbox.stdout" => {
                                tracing::debug!(
                                    target: "rosetun.engine.singbox.stdout",
                                    %error,
                                    "sing-box output stream closed with a read error"
                                );
                            }
                            "rosetun.engine.singbox.stderr" => {
                                tracing::debug!(
                                    target: "rosetun.engine.singbox.stderr",
                                    %error,
                                    "sing-box output stream closed with a read error"
                                );
                            }
                            _ => unreachable!("unknown sing-box output target"),
                        }
                        break;
                    }
                }
            }

            match target {
                "rosetun.engine.singbox.stdout" => {
                    tracing::debug!(
                        target: "rosetun.engine.singbox.stdout",
                        "sing-box output stream closed"
                    );
                }
                "rosetun.engine.singbox.stderr" => {
                    tracing::debug!(
                        target: "rosetun.engine.singbox.stderr",
                        "sing-box output stream closed"
                    );
                }
                _ => unreachable!("unknown sing-box output target"),
            }
        });
}

fn find_in_neighbours() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let candidate = exe.parent()?.join(BINARY);
    candidate.is_file().then_some(candidate)
}

fn find_in_path() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(BINARY))
        .find(|candidate| candidate.is_file())
}

#[derive(Debug)]
struct SingBoxProcess {
    child: Child,
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

    fn traffic(&mut self) -> Result<Traffic, EngineError> {
        Err(EngineError::StatsUnavailable)
    }

    fn stop(&mut self) -> Result<(), EngineError> {
        // TODO: on Unix, first issue SIGTERM to allow the engine time to remove the routes,
        // and only then kill. It's rough now, but predictable.
        match self.child.kill() {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {}
            Err(error) => return Err(error.into()),
        }
        self.child.wait()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rosetun_config::{
        DomainMatch, Node, NodeId, Outbound, ProcessMatch, RealityParams, Rule, RuleId,
        RuleMatcher, RuleSet, RuleSetId, RuleTarget, Settings, StreamSettings, TlsMode,
        VlessParams,
    };
    use serde_json::Value;

    use super::*;

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
        let settings = Settings::default();
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
            2,
            "the disabled rule should not be included in the config"
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
        );

        assert_eq!(rendered.1, vec![RuleId::new("r2")]);
        assert_eq!(
            rendered.0["rules"].as_array().expect("rules array").len(),
            1
        );
    }

    #[test]
    fn rule_order_is_preserved() {
        let config = rendered();
        let rules = &config["route"]["rules"];
        assert_eq!(rules[0]["domain_suffix"][0], "google.com");
        assert_eq!(rules[0]["outbound"], "proxy");
        assert_eq!(rules[1]["process_name"][0], "steam.exe");
        assert_eq!(rules[1]["outbound"], "direct");
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
}
