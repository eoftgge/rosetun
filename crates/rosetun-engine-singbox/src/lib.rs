#![forbid(unsafe_code)]

mod output;
mod readiness;
mod render;
mod version;

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;

use serde::Deserialize;

use output::LineLevel;
use readiness::Readiness;
use rosetun_config::EngineKind;
use rosetun_engine::{
    ControlEndpoint, EngineBackend, EngineCapabilities, EngineIntegration, EngineProcess,
    ProbeRenderRequest, RenderRequest, RenderedConfig, TrafficProbe, TrafficTotals, UrlTestTarget,
    errors::EngineError,
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

    fn tunnel_dns_server(&self, tun: &rosetun_config::TunSettings) -> Option<std::net::SocketAddr> {
        let (address, prefix) = tun.ipv4.split_once('/')?;
        let address = u32::from(address.parse::<std::net::Ipv4Addr>().ok()?);
        let prefix = prefix.parse::<u32>().ok()?;
        if prefix > 32 {
            return None;
        }

        let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
        let next = address.checked_add(1)?;
        let network = address & mask;
        let broadcast = network | !mask;

        if next & mask != network || next == broadcast {
            return None;
        }

        // sing-tun intercepts DNS sent to the address immediately after the TUN address.
        Some(std::net::SocketAddr::from((
            std::net::Ipv4Addr::from(next),
            53,
        )))
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

    fn render_probe(
        &self,
        request: &ProbeRenderRequest<'_>,
    ) -> Result<RenderedConfig, EngineError> {
        render::render_probe(request)
    }

    fn probe_config_path(&self, config: &RenderedConfig) -> Option<PathBuf> {
        Some(self.work_dir.join(&config.file_name))
    }

    fn url_test(
        &self,
        control: &ControlEndpoint,
        target: UrlTestTarget<'_>,
        url: &str,
        timeout: Duration,
    ) -> Result<Duration, EngineError> {
        let tag = match target {
            UrlTestTarget::Session => render::TAG_PROXY,
            UrlTestTarget::Probe(tag) => tag,
        };
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .timeout_global(Some(timeout + Duration::from_secs(2)))
                .http_status_as_error(false)
                .proxy(None)
                .build(),
        );
        let mut response = agent
            .get(&format!("http://{}/proxies/{tag}/delay", control.address))
            .query("url", url)
            .query("timeout", timeout.as_millis().to_string())
            .header("Authorization", &format!("Bearer {}", control.secret))
            .call()
            .map_err(|_| EngineError::Stats("local URL test request failed".to_owned()))?;
        if response.status() != 200 {
            return Err(EngineError::Stats(format!(
                "URL test HTTP status {}",
                response.status().as_u16()
            )));
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(1024)
            .read_to_vec()
            .map_err(|_| EngineError::Stats("failed to read URL test response".to_owned()))?;
        #[derive(Deserialize)]
        struct Delay {
            delay: u64,
        }
        let delay: Delay = serde_json::from_slice(&body)
            .map_err(|_| EngineError::Stats("invalid URL test response".to_owned()))?;
        Ok(Duration::from_millis(delay.delay))
    }

    fn traffic_probe(&self, control: &ControlEndpoint) -> Option<Box<dyn TrafficProbe>> {
        Some(Box::new(ClashTrafficProbe::new(control)))
    }

    fn spawn(
        &self,
        binary: &Path,
        config: &RenderedConfig,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        std::fs::create_dir_all(&self.work_dir)?;
        let config_path = self.work_dir.join(&config.file_name);
        std::fs::write(&config_path, &config.body)?;

        let probe = config.file_name == "probe.json";
        if !probe {
            tracing::info!(binary = %binary.display(), config = %config_path.display(), "starting sing-box");
        }
        let mut child = Command::new(binary)
            .arg("run")
            .arg("--disable-color")
            .arg("-c")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let (ready_sender, readiness) = Readiness::new();
        let slow_tunnel = Arc::new(AtomicBool::new(false));
        let failures = Arc::new(output::FailureCounters::default());

        if let Some(stdout) = child.stdout.take()
            && let Err(error) =
                spawn_output_drain(stdout, "stdout", None, probe, None, Arc::clone(&failures))
        {
            stop_failed_spawn(&mut child);
            return Err(error.into());
        }

        let Some(stderr) = child.stderr.take() else {
            stop_failed_spawn(&mut child);
            return Err(std::io::Error::other("sing-box stderr pipe is unavailable").into());
        };

        if let Err(error) = spawn_output_drain(
            stderr,
            "stderr",
            Some(ready_sender),
            probe,
            Some(Arc::clone(&slow_tunnel)),
            Arc::clone(&failures),
        ) {
            stop_failed_spawn(&mut child);
            return Err(error.into());
        }

        Ok(Box::new(SingBoxProcess {
            child,
            readiness,
            slow_tunnel,
            failures,
        }))
    }
}

/// Polls `GET /connections` on the sing-box Clash API.
struct ClashTrafficProbe {
    agent: ureq::Agent,
    url: String,
    authorization: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    upload_total: u64,
    download_total: u64,
}

impl ClashTrafficProbe {
    fn new(control: &ControlEndpoint) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(1)))
            .http_status_as_error(false)
            // Environment proxy settings must not intercept the local control request.
            .proxy(None)
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
            url: format!("http://{}/connections", control.address),
            authorization: format!("Bearer {}", control.secret),
        }
    }
}

impl std::fmt::Debug for ClashTrafficProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClashTrafficProbe")
            .field("url", &self.url)
            .field("authorization", &"<redacted>")
            .finish()
    }
}

impl TrafficProbe for ClashTrafficProbe {
    fn totals(&mut self) -> Result<TrafficTotals, EngineError> {
        let mut response = self
            .agent
            .get(&self.url)
            .header("Authorization", &self.authorization)
            .call()
            .map_err(|error| {
                EngineError::Stats(format!("local control request failed: {error}"))
            })?;
        if response.status() != 200 {
            return Err(EngineError::Stats(format!(
                "HTTP status {}",
                response.status().as_u16()
            )));
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(16 * 1024 * 1024)
            .read_to_vec()
            .map_err(|_| EngineError::Stats("failed to read traffic response".to_owned()))?;
        let snapshot: Snapshot = serde_json::from_slice(&body)
            .map_err(|_| EngineError::Stats("invalid traffic response".to_owned()))?;
        Ok(TrafficTotals {
            up: snapshot.upload_total,
            down: snapshot.download_total,
        })
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
    probe: bool,
    slow_tunnel: Option<Arc<AtomicBool>>,
    failures: Arc<output::FailureCounters>,
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
                        failures.observe(&line);
                        if readiness::is_slow_tunnel_message(&line)
                            && let Some(hint) = &slow_tunnel
                        {
                            hint.store(true, Ordering::Release);
                        }
                        if ready_sender.is_some()
                            && readiness::is_startup_message(&line)
                            && let Some(sender) = ready_sender.take()
                        {
                            let _ = sender.send(());
                        }
                        if !probe {
                            log_output_line(stream, &line);
                        }
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

fn log_output_line(stream: &'static str, line: &str) {
    use rosetun_engine::ENGINE_OUTPUT_TARGET as TARGET;
    match output::line_level(line) {
        Some(LineLevel::Trace) => tracing::trace!(target: TARGET, stream, "{line}"),
        Some(LineLevel::Debug) => tracing::debug!(target: TARGET, stream, "{line}"),
        Some(LineLevel::Info) | None => tracing::info!(target: TARGET, stream, "{line}"),
        Some(LineLevel::Warn) => tracing::warn!(target: TARGET, stream, "{line}"),
        Some(LineLevel::Error) => tracing::error!(target: TARGET, stream, "{line}"),
    }
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
    slow_tunnel: Arc<AtomicBool>,
    failures: Arc<output::FailureCounters>,
}

impl EngineProcess for SingBoxProcess {
    fn outbound_failures(&self) -> rosetun_engine::OutboundFailures {
        self.failures.snapshot()
    }
    fn startup_hints(&self) -> rosetun_engine::StartupHints {
        rosetun_engine::StartupHints {
            slow_tunnel_creation: self.slow_tunnel.load(Ordering::Acquire),
        }
    }
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
        DomainMatch, LogLevel, Node, NodeId, Outbound, ProcessMatch, RealityParams, Rule, RuleId,
        RuleMatcher, RuleSet, RuleSetId, RuleTarget, Settings, StreamSettings, TlsMode,
        VlessParams,
    };
    use rosetun_engine::{PROBE_TIMEOUT, PROBE_URL, RuleCapabilities};
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

    #[test]
    fn render_debug_omits_node_credentials_and_config_body() {
        let node = node();
        let rules = rules();
        let settings = Settings::default();
        let control = ControlEndpoint {
            address: "127.0.0.1:12345".parse().unwrap(),
            secret: "private-secret".to_owned(),
        };
        let request = RenderRequest {
            node: &node,
            rules: &rules,
            settings: &settings,
            control: Some(&control),
            verbose_log: false,
        };
        let config = render::render(&request).unwrap();
        let nodes = vec![("probe-0".to_owned(), node.clone())];
        let probe = ProbeRenderRequest {
            nodes: &nodes,
            control: &control,
            interface: None,
        };
        let probe_config = render::render_probe(&probe).unwrap();
        for printed in [
            format!("{request:?}"),
            format!("{probe:?}"),
            format!("{config:?}"),
            format!("{probe_config:?}"),
        ] {
            for secret in [
                "11111111-2222-3333-4444-555555555555",
                "PUBKEY",
                "203.0.113.10",
                "Sakura-02",
                "private-secret",
            ] {
                assert!(!printed.contains(secret), "Debug leaked {secret}");
            }
        }
        assert!(format!("{config:?}").contains("body_len"));
        assert!(format!("{probe_config:?}").contains("body_len"));
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
            control: None,
            verbose_log: false,
        };
        let config = render::render(&request).expect("config built");
        serde_json::from_slice(&config.body).expect("config is valid json")
    }

    fn render_with_dns(dns: rosetun_config::DnsSettings) -> Result<Value, EngineError> {
        let node = node();
        let rules = rules();
        let settings = Settings {
            dns,
            ..Settings::default()
        };
        let config = render::render(&RenderRequest {
            node: &node,
            rules: &rules,
            settings: &settings,
            control: None,
            verbose_log: false,
        })?;
        Ok(serde_json::from_slice(&config.body).expect("valid JSON"))
    }

    #[test]
    fn log_level_depends_on_verbose_log() {
        let node = node();
        let rules = rules();
        let mut settings = Settings::default();
        for (verbose_log, log_level, expected) in [
            (false, LogLevel::Trace, "info"),
            (true, LogLevel::Error, "debug"),
            (true, LogLevel::Warn, "debug"),
            (true, LogLevel::Info, "debug"),
            (true, LogLevel::Debug, "debug"),
            (true, LogLevel::Trace, "trace"),
        ] {
            settings.log_level = log_level;
            let config = render::render(&RenderRequest {
                node: &node,
                rules: &rules,
                settings: &settings,
                control: None,
                verbose_log,
            })
            .expect("config rendered");
            let config: Value = serde_json::from_slice(&config.body).expect("valid JSON");
            assert_eq!(config["log"]["level"], expected);
        }
    }

    #[test]
    fn clash_api_is_rendered_only_with_control() {
        assert!(rendered().get("experimental").is_none());

        let node = node();
        let rules = rules();
        let settings = Settings::default();
        let control = ControlEndpoint {
            address: "127.0.0.1:12345".parse().expect("loopback address"),
            secret: "private-secret".to_owned(),
        };
        let config = render::render(&RenderRequest {
            node: &node,
            rules: &rules,
            settings: &settings,
            control: Some(&control),
            verbose_log: false,
        })
        .expect("config rendered");
        let config: Value = serde_json::from_slice(&config.body).expect("valid JSON");
        assert_eq!(
            config["experimental"],
            serde_json::json!({
                "clash_api": {
                    "external_controller": "127.0.0.1:12345",
                    "secret": "private-secret",
                }
            })
        );
    }

    #[test]
    fn probe_config_contains_only_outbounds_route_and_control() {
        let control = ControlEndpoint {
            address: "127.0.0.1:12345".parse().unwrap(),
            secret: "private-secret".to_owned(),
        };
        let mut unsupported = node();
        unsupported.outbound = Outbound::Unknown {
            scheme: "unsupported".to_owned(),
            params: Default::default(),
        };
        let nodes = vec![
            ("probe-0".to_owned(), node()),
            ("probe-1".to_owned(), node()),
            ("probe-2".to_owned(), unsupported),
        ];
        for interface in [Some("Ethernet 2"), None] {
            let config = render::render_probe(&ProbeRenderRequest {
                nodes: &nodes,
                control: &control,
                interface,
            })
            .unwrap();
            assert_eq!(config.file_name, "probe.json");
            assert!(config.unsupported.is_empty());
            assert_eq!(config.unsupported_probes, ["probe-2"]);
            let value: Value = serde_json::from_slice(&config.body).unwrap();
            assert!(value.get("dns").is_none());
            assert!(value.get("inbounds").is_none());
            assert_eq!(value["log"]["level"], "info");
            assert_eq!(value["route"]["final"], "direct");
            assert_eq!(value["route"]["default_interface"].as_str(), interface);
            assert_eq!(
                value["route"].get("auto_detect_interface").is_some(),
                interface.is_none()
            );
            assert_eq!(
                value["experimental"]["clash_api"],
                serde_json::json!({
                    "external_controller": "127.0.0.1:12345",
                    "secret": "private-secret"
                })
            );
            let outbounds = value["outbounds"].as_array().unwrap();
            assert_eq!(outbounds.len(), 3);
            assert_eq!(outbounds[0]["tag"], "probe-0");
            assert_eq!(outbounds[1]["tag"], "probe-1");
            assert_eq!(
                outbounds[2],
                serde_json::json!({ "type": "direct", "tag": "direct" })
            );
        }
    }

    fn delay_against_server(
        status: u16,
        target: UrlTestTarget<'_>,
    ) -> Result<Duration, EngineError> {
        use std::io::Write;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let control = ControlEndpoint {
            address: listener.local_addr().unwrap(),
            secret: "test-secret".to_owned(),
        };
        let expected_tag = match target {
            UrlTestTarget::Session => "proxy",
            UrlTestTarget::Probe(tag) => tag,
        }
        .to_owned();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut reader = BufReader::new(socket);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.starts_with(&format!("GET /proxies/{expected_tag}/delay?")));
            assert!(line.contains("/delay?"));
            assert!(line.contains("url=https%3A%2F%2Fcp.cloudflare.com%2Fgenerate_204"));
            assert!(line.contains("timeout=5000"));
            let mut authorized = false;
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("authorization")
                {
                    authorized = value.trim() == "Bearer test-secret";
                }
            }
            assert!(authorized);
            let body = r#"{"delay":42}"#;
            write!(
                reader.get_mut(),
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        let result =
            SingBoxBackend::new("unused").url_test(&control, target, PROBE_URL, PROBE_TIMEOUT);
        server.join().unwrap();
        result
    }

    #[test]
    fn url_test_reads_delay_and_reports_failure() {
        assert_eq!(
            delay_against_server(200, UrlTestTarget::Session).unwrap(),
            Duration::from_millis(42)
        );
        assert!(matches!(
            delay_against_server(504, UrlTestTarget::Probe("probe-1")),
            Err(EngineError::Stats(_))
        ));
    }

    fn probe_against_server(status: u16, chunked: bool) -> Result<TrafficTotals, EngineError> {
        use std::io::Write;
        use std::net::TcpListener;
        use std::time::Instant;

        let listener = TcpListener::bind("127.0.0.1:0").expect("test server");
        listener.set_nonblocking(true).expect("nonblocking accept");
        let control = ControlEndpoint {
            address: listener.local_addr().expect("server address"),
            secret: "test-secret".to_owned(),
        };
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("probe failed to connect: {error}"),
                }
            };
            socket.set_nonblocking(false).expect("blocking socket");
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read timeout");
            let mut reader = BufReader::new(socket);
            let mut request = String::new();
            reader.read_line(&mut request).expect("request line");
            assert_eq!(request, "GET /connections HTTP/1.1\r\n");
            let mut authorized = false;
            loop {
                request.clear();
                reader.read_line(&mut request).expect("request header");
                if request == "\r\n" {
                    break;
                }
                if let Some((key, value)) = request.split_once(':')
                    && key.eq_ignore_ascii_case("Authorization")
                {
                    authorized = value.trim() == "Bearer test-secret";
                }
            }
            assert!(authorized, "the probe must send bearer authorization");

            let body = r#"{"uploadTotal":10,"downloadTotal":20,"connections":[]}"#;
            let response = if chunked {
                format!(
                    "HTTP/1.1 {status} Test\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\n{body}\r\n0\r\n\r\n",
                    body.len()
                )
            } else {
                format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
            };
            reader
                .get_mut()
                .write_all(response.as_bytes())
                .expect("server response");
        });
        let mut probe = SingBoxBackend::new("unused")
            .traffic_probe(&control)
            .expect("sing-box supports traffic");
        let debug = format!("{probe:?}");
        assert!(!debug.contains(&control.secret));
        assert!(debug.contains("<redacted>"));
        let result = probe.totals();
        server.join().expect("test server completed");
        result
    }

    #[test]
    fn traffic_probe_reads_content_length_and_chunked_totals() {
        for chunked in [false, true] {
            assert_eq!(
                probe_against_server(200, chunked).expect("traffic totals"),
                TrafficTotals { up: 10, down: 20 }
            );
        }
    }

    #[test]
    fn traffic_probe_reports_http_failure() {
        assert!(matches!(
            probe_against_server(401, false),
            Err(EngineError::Stats(message)) if message.contains("401")
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
                "type": "https",
                "detour": "proxy",
                "tag": "dns-proxy",
                "server": "1.1.1.1",
                "tls": {
                    "server_name": "cloudflare-dns.com",
                }
            })
        );
        assert!(servers[0].get("server_port").is_none());
        assert!(servers[0].get("path").is_none());
        assert!(config["dns"].get("rules").is_none());
    }

    #[test]
    fn configured_dns_resolver_reaches_the_config() {
        let dns = rosetun_config::DnsSettings {
            server: "77.88.8.8".parse().expect("DNS IP"),
            server_name: "common.dot.dns.yandex.net".to_owned(),
            ..Default::default()
        };
        let config = render_with_dns(dns).expect("rendered");
        assert_eq!(
            config["dns"]["servers"],
            serde_json::json!([{
                "type": "https",
                "tag": "dns-proxy",
                "server": "77.88.8.8",
                "tls": { "server_name": "common.dot.dns.yandex.net" },
                "detour": "proxy"
            }])
        );
    }

    #[test]
    fn configured_dns_port_and_path_reach_the_config() {
        let dns = rosetun_config::DnsSettings {
            port: Some(8443),
            path: Some("/custom-dns-query".to_owned()),
            ..Default::default()
        };
        let config = render_with_dns(dns).expect("rendered");
        let server = &config["dns"]["servers"][0];
        assert_eq!(server["server_port"], 8443);
        assert_eq!(server["path"], "/custom-dns-query");
    }

    #[test]
    fn ipv6_dns_server_is_rendered_without_brackets() {
        let dns = rosetun_config::DnsSettings {
            server: "2001:4860:4860::8888".parse().expect("DNS IPv6"),
            ..Default::default()
        };
        let config = render_with_dns(dns).expect("rendered");
        assert_eq!(
            config["dns"]["servers"][0]["server"],
            "2001:4860:4860::8888"
        );
    }

    #[test]
    fn invalid_dns_server_names_are_rejected() {
        for server_name in ["", "dns google", " dns.google", "dns.google\t"] {
            let dns = rosetun_config::DnsSettings {
                server_name: server_name.to_owned(),
                ..Default::default()
            };
            assert!(matches!(
                render_with_dns(dns),
                Err(EngineError::Render(message))
                    if message.contains("server_name")
            ));
        }
    }

    #[test]
    fn invalid_dns_paths_are_rejected() {
        for path in ["", "dns-query"] {
            let dns = rosetun_config::DnsSettings {
                path: Some(path.to_owned()),
                ..Default::default()
            };
            assert!(matches!(
                render_with_dns(dns),
                Err(EngineError::Render(message))
                    if message.contains("path")
            ));
        }
    }

    #[test]
    fn zero_dns_port_is_rejected() {
        let dns = rosetun_config::DnsSettings {
            port: Some(0),
            ..Default::default()
        };
        assert!(matches!(
            render_with_dns(dns),
            Err(EngineError::Render(message))
                if message.contains("port")
        ));
    }

    #[test]
    fn tunnel_dns_server_uses_the_next_tun_address() {
        let backend = SingBoxBackend::new("unused");
        assert_eq!(
            backend.tunnel_dns_server(&rosetun_config::TunSettings::default()),
            Some("172.19.0.2:53".parse().expect("DNS address")),
        );
    }

    #[test]
    fn tunnel_dns_server_rejects_unusable_next_addresses() {
        let backend = SingBoxBackend::new("unused");

        for ipv4 in [
            "172.19.0.1/32",
            "172.19.0.1/31",
            "172.19.0.2/30",
            "172.19.0.3/30",
            "255.255.255.255/0",
            "172.19.0.1/33",
            "invalid",
        ] {
            let tun = rosetun_config::TunSettings {
                ipv4: ipv4.to_owned(),
                ..Default::default()
            };
            assert_eq!(backend.tunnel_dns_server(&tun), None, "{ipv4}");
        }
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
            control: None,
            verbose_log: false,
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
            control: None,
            verbose_log: false,
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
        assert_eq!(inbound["stack"], "gvisor");
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
            control: None,
            verbose_log: false,
        };
        assert!(matches!(
            render::render(&request),
            Err(EngineError::Unsupported(_))
        ));
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
            control: None,
            verbose_log: false,
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
                control: None,
                verbose_log: false,
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
