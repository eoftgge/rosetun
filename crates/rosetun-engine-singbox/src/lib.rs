#![deny(unsafe_code)]

mod connections;
#[cfg(windows)]
#[allow(unsafe_code)]
mod console;
mod output;
mod readiness;
mod render;
mod stop;
mod version;

use std::borrow::Cow;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use output::LineLevel;
use readiness::Readiness;
use rosetun_config::EngineKind;
use rosetun_engine::{
    ControlEndpoint, EngineBackend, EngineCapabilities, EngineIntegration, EngineProcess,
    ProbeRenderRequest, RenderRequest, RenderedConfig, TrafficProbe, TrafficSample, UrlTestTarget,
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
            UrlTestTarget::SessionExit(tag) | UrlTestTarget::Probe(tag) => tag,
        };
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .timeout_global(Some(timeout.saturating_add(Duration::from_secs(2))))
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

    fn close_connection(&self, control: &ControlEndpoint, id: &str) -> Result<(), EngineError> {
        if !rosetun_engine::valid_connection_id(id) {
            return Err(EngineError::Stats("invalid connection id".to_owned()));
        }
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(2)))
                .http_status_as_error(false)
                .proxy(None)
                .build(),
        );
        // sing-box answers 204 whether or not it knew the id.
        let response = agent
            .delete(&format!(
                "http://{}/connections/{}",
                control.address,
                path_segment(id)
            ))
            .header("Authorization", &format!("Bearer {}", control.secret))
            .call()
            .map_err(|_| EngineError::Stats("local close request failed".to_owned()))?;
        match response.status().as_u16() {
            200 | 204 => Ok(()),
            status => Err(EngineError::Stats(format!("close HTTP status {status}"))),
        }
    }

    fn spawn(
        &self,
        binary: &Path,
        config: &RenderedConfig,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        self.spawn_with_log_gate(binary, config, Arc::new(AtomicU64::new(0)))
    }

    fn spawn_with_log_gate(
        &self,
        binary: &Path,
        config: &RenderedConfig,
        verbose_until_unix: Arc<AtomicU64>,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        std::fs::create_dir_all(&self.work_dir)?;
        let config_path = self.work_dir.join(&config.file_name);
        std::fs::write(&config_path, &config.body)?;

        let probe = config.file_name == "probe.json";
        if !probe {
            tracing::info!(binary = %binary.display(), config = %config_path.display(), "starting sing-box");
        }
        let mut command = Command::new(binary);
        command
            .arg("run")
            .arg("--disable-color")
            .arg("-c")
            .arg(&config_path)
            .current_dir(&self.work_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        let mut child = console::spawn(&mut command)?;
        #[cfg(not(windows))]
        let mut child = command.spawn()?;

        let (ready_sender, readiness) = Readiness::new();
        let hints = Arc::new(HintFlags::default());
        let failures = Arc::new(output::FailureCounters::default());

        if let Some(stdout) = child.stdout.take()
            && let Err(error) = spawn_output_drain(
                stdout,
                "stdout",
                None,
                probe,
                None,
                Arc::clone(&failures),
                Arc::clone(&verbose_until_unix),
            )
        {
            stop_failed_spawn(&mut child);
            return Err(error.into());
        }

        let Some(stderr) = child.stderr.take() else {
            stop_failed_spawn(&mut child);
            return Err(std::io::Error::other("sing-box stderr pipe is unavailable").into());
        };

        let stderr_drain = match spawn_output_drain(
            stderr,
            "stderr",
            Some(ready_sender),
            probe,
            Some(Arc::clone(&hints)),
            Arc::clone(&failures),
            verbose_until_unix,
        ) {
            Ok(drain) => drain,
            Err(error) => {
                stop_failed_spawn(&mut child);
                return Err(error.into());
            }
        };

        Ok(Box::new(SingBoxProcess {
            child,
            readiness,
            hints,
            stderr_drain: Some(stderr_drain),
            failures,
            probe,
        }))
    }
}

/// Percent-encodes everything but RFC 3986 unreserved characters, so an id
/// cannot change the request path.
fn path_segment(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// Polls `GET /connections` on the sing-box Clash API.
struct ClashTrafficProbe {
    agent: ureq::Agent,
    url: String,
    authorization: String,
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
    fn sample(&mut self, connections: bool) -> Result<TrafficSample, EngineError> {
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
        let invalid = |_| EngineError::Stats("invalid traffic response".to_owned());
        if !connections {
            let totals: connections::Totals = serde_json::from_slice(&body).map_err(invalid)?;
            return Ok(TrafficSample {
                totals: totals.totals(),
                connections: None,
            });
        }
        let snapshot: connections::WithConnections =
            serde_json::from_slice(&body).map_err(invalid)?;
        Ok(TrafficSample {
            totals: snapshot.totals.totals(),
            connections: Some(snapshot.connections()),
        })
    }
}

fn stop_failed_spawn(child: &mut Child) {
    match stop::stop(&mut stop::ChildStop(child), stop::FAILED_SPAWN_GRACE) {
        Ok(outcome) => outcome.log(false),
        Err(error) => tracing::error!(%error, "failed to stop sing-box after startup setup failed"),
    }
}

fn spawn_output_drain<R>(
    reader: R,
    stream: &'static str,
    mut ready_sender: Option<Sender<()>>,
    probe: bool,
    hints: Option<Arc<HintFlags>>,
    failures: Arc<output::FailureCounters>,
    verbose_until_unix: Arc<AtomicU64>,
) -> std::io::Result<thread::JoinHandle<()>>
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
                        if let Some(hints) = &hints {
                            hints.observe(&line);
                        }
                        if ready_sender.is_some()
                            && readiness::is_startup_message(&line)
                            && let Some(sender) = ready_sender.take()
                        {
                            let _ = sender.send(());
                        }
                        if !probe {
                            log_output_line(stream, &line, &verbose_until_unix);
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
}

fn log_output_line(stream: &'static str, line: &str, verbose_until_unix: &AtomicU64) {
    use rosetun_engine::ENGINE_OUTPUT_TARGET as TARGET;
    let line = safe_output_line(line, verbose_until_unix, now_unix());
    match output::line_level(&line) {
        Some(LineLevel::Trace) => tracing::trace!(target: TARGET, stream, "{line}"),
        Some(LineLevel::Debug) => tracing::debug!(target: TARGET, stream, "{line}"),
        Some(LineLevel::Info) | None => tracing::info!(target: TARGET, stream, "{line}"),
        Some(LineLevel::Warn) => tracing::warn!(target: TARGET, stream, "{line}"),
        Some(LineLevel::Error) => tracing::error!(target: TARGET, stream, "{line}"),
    }
}

fn safe_output_line<'a>(line: &'a str, until_unix: &AtomicU64, now_unix: u64) -> Cow<'a, str> {
    if now_unix < until_unix.load(Ordering::Acquire) {
        Cow::Borrowed(line)
    } else {
        Cow::Owned(output::hide_destinations(line))
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default()
}

fn find_in_neighbours() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let candidate = exe.parent()?.join(BINARY);
    candidate.is_file().then_some(candidate)
}

/// Latched startup diagnostics, set by the stderr drain.
#[derive(Debug, Default)]
struct HintFlags {
    slow_tunnel: AtomicBool,
    adapter_still_removing: AtomicBool,
}

impl HintFlags {
    fn observe(&self, line: &str) {
        if readiness::is_slow_tunnel_message(line) {
            self.slow_tunnel.store(true, Ordering::Release);
        }
        if output::is_adapter_busy_message(line) {
            self.adapter_still_removing.store(true, Ordering::Release);
        }
    }
}

#[derive(Debug)]
struct SingBoxProcess {
    child: Child,
    readiness: Readiness,
    hints: Arc<HintFlags>,
    stderr_drain: Option<thread::JoinHandle<()>>,
    failures: Arc<output::FailureCounters>,
    probe: bool,
}

impl SingBoxProcess {
    /// The exit can be seen before the drain has read the last lines, and the
    /// FATAL that explains it is one of them: let the hints latch first.
    fn settle_stderr(&mut self) {
        let Some(drain) = self.stderr_drain.take() else {
            return;
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while !drain.is_finished() && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        if drain.is_finished() {
            let _ = drain.join();
        }
    }
}

impl EngineProcess for SingBoxProcess {
    fn outbound_failures(&self) -> rosetun_engine::OutboundFailures {
        self.failures.snapshot()
    }
    fn startup_hints(&self) -> rosetun_engine::StartupHints {
        rosetun_engine::StartupHints {
            slow_tunnel_creation: self.hints.slow_tunnel.load(Ordering::Acquire),
            adapter_still_removing: self.hints.adapter_still_removing.load(Ordering::Acquire),
        }
    }
    fn is_running(&mut self) -> Result<bool, EngineError> {
        match self.child.try_wait()? {
            Some(status) => {
                self.settle_stderr();
                Err(EngineError::Exited {
                    code: status.code(),
                })
            }
            None => Ok(true),
        }
    }

    fn is_ready(&mut self) -> Result<bool, EngineError> {
        self.readiness.poll().map_err(EngineError::from)
    }

    fn stop(&mut self) -> Result<(), EngineError> {
        stop::stop(&mut stop::ChildStop(&mut self.child), stop::STOP_GRACE)?.log(self.probe);
        Ok(())
    }
}

impl Drop for SingBoxProcess {
    fn drop(&mut self) {
        #[cfg(windows)]
        console::forget(self.child.id());
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
    use rosetun_engine::{PROBE_TIMEOUT, PROBE_URLS, RuleCapabilities, TrafficTotals};
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
    fn engine_output_masks_destinations_after_verbose_log_expires() {
        let line = "ERROR connection: connection download closed: close tcp 172.19.0.1:54626->198.51.100.7:443: endpoint not connected";
        let deadline = std::sync::atomic::AtomicU64::new(100);
        assert_eq!(super::safe_output_line(line, &deadline, 99), line);
        assert!(!super::safe_output_line(line, &deadline, 100).contains("198.51.100.7"));
        deadline.store(0, std::sync::atomic::Ordering::Release);
        let hidden = super::safe_output_line(line, &deadline, 99);
        assert!(!hidden.contains("198.51.100.7"));
        assert!(hidden.contains("172.19.0.1:54626->[hidden]:443: endpoint not connected"));
    }

    #[test]
    fn outbound_failure_is_counted_before_its_destination_is_hidden() {
        let line = "ERROR connection: open connection to 198.51.100.20:443 using outbound/vless[proxy]: dial tcp 203.0.113.10:443: i/o timeout";
        let failures = super::output::FailureCounters::default();
        failures.observe(line);
        let deadline = std::sync::atomic::AtomicU64::new(0);
        let safe = super::safe_output_line(line, &deadline, 100);
        assert_eq!(failures.snapshot().unreachable, 1);
        assert!(!safe.contains("198.51.100.20"));
        assert!(!safe.contains("203.0.113.10"));
        assert!(safe.contains("dial tcp [hidden]:443: i/o timeout"));
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
            extra: &[],
            node: &node,
            socks: None,
            rules: &rules,
            lists: &[],
            settings: &settings,
            control: Some(&control),
            verbose_log: false,
        };
        let config = render::render(&request).unwrap();
        let nodes = vec![("probe-0".to_owned(), node.clone())];
        let probe = ProbeRenderRequest {
            nodes: &nodes,
            socks: &[],
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
                    exit: None,
                },
                Rule {
                    id: RuleId::new("r2"),
                    enabled: true,
                    matcher: RuleMatcher::Process(ProcessMatch::Name("steam.exe".to_owned())),
                    target: RuleTarget::Direct,
                    exit: None,
                },
                Rule {
                    id: RuleId::new("r3"),
                    enabled: false,
                    matcher: RuleMatcher::Domain(DomainMatch::Exact("blocked.test".to_owned())),
                    target: RuleTarget::Block,
                    exit: None,
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
            extra: &[],
            node: &node,
            socks: None,
            rules: &rules,
            lists: &[],
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
            extra: &[],
            node: &node,
            socks: None,
            rules: &rules,
            lists: &[],
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
                extra: &[],
                node: &node,
                socks: None,
                rules: &rules,
                lists: &[],
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
            extra: &[],
            node: &node,
            socks: None,
            rules: &rules,
            lists: &[],
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
                socks: &[],
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
        timeout: Duration,
        response_delay: Duration,
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
            UrlTestTarget::SessionExit(tag) | UrlTestTarget::Probe(tag) => tag,
        }
        .to_owned();
        let expected_timeout = format!("timeout={}", timeout.as_millis());
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
            assert!(line.contains(&expected_timeout));
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
            thread::sleep(response_delay);
            let body = r#"{"delay":42}"#;
            write!(
                reader.get_mut(),
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        let result =
            SingBoxBackend::new("unused").url_test(&control, target, PROBE_URLS[0], timeout);
        server.join().unwrap();
        result
    }

    #[test]
    fn url_test_reads_delay_and_reports_failure() {
        assert_eq!(
            delay_against_server(200, UrlTestTarget::Session, PROBE_TIMEOUT, Duration::ZERO)
                .unwrap(),
            Duration::from_millis(42)
        );
        assert!(matches!(
            delay_against_server(
                504,
                UrlTestTarget::Probe("probe-1"),
                PROBE_TIMEOUT,
                Duration::ZERO,
            ),
            Err(EngineError::Stats(_))
        ));
    }

    #[test]
    fn url_test_waits_for_the_local_response_after_the_probe_deadline() {
        assert_eq!(
            delay_against_server(
                200,
                UrlTestTarget::Session,
                Duration::from_millis(80),
                Duration::from_millis(250),
            )
            .unwrap(),
            Duration::from_millis(42)
        );
    }

    #[test]
    fn url_test_any_falls_back_through_the_clash_api() {
        use std::io::Write;
        use std::net::TcpListener;
        use std::sync::Arc;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let control = ControlEndpoint {
            address: listener.local_addr().unwrap(),
            secret: "test-secret".to_owned(),
        };
        let server = thread::spawn(move || {
            let mut seen = [false; 2];
            for _ in PROBE_URLS {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = BufReader::new(socket);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert!(line.starts_with("GET /proxies/probe-0/delay?"));
                assert!(line.contains("timeout=5000"));
                let google = line.contains("url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204");
                if !google {
                    assert!(line.contains("url=https%3A%2F%2Fcp.cloudflare.com%2Fgenerate_204"));
                }
                seen[usize::from(google)] = true;
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                }
                let (status, body) = if google {
                    (200, r#"{"delay":73}"#)
                } else {
                    (503, "")
                };
                write!(
                    reader.get_mut(),
                    "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
            assert!(seen.into_iter().all(|seen| seen));
        });
        let delay = rosetun_engine::url_test_any(
            Arc::new(SingBoxBackend::new("unused")),
            &control,
            UrlTestTarget::Probe("probe-0"),
            PROBE_TIMEOUT,
        )
        .unwrap();
        assert_eq!(delay, Duration::from_millis(73));
        server.join().unwrap();
    }

    fn probe_against_server(
        status: u16,
        chunked: bool,
        connections: bool,
    ) -> Result<TrafficSample, EngineError> {
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

            let body = r#"{"uploadTotal":10,"downloadTotal":20,"connections":[{"id":1}]}"#;
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
        let result = probe.sample(connections);
        server.join().expect("test server completed");
        result
    }

    #[test]
    fn traffic_probe_reads_content_length_and_chunked_totals() {
        for chunked in [false, true] {
            assert_eq!(
                probe_against_server(200, chunked, false).expect("traffic totals"),
                TrafficSample {
                    totals: TrafficTotals { up: 10, down: 20 },
                    connections: None,
                }
            );
        }
    }

    #[test]
    fn traffic_probe_parses_connections_only_when_asked() {
        assert_eq!(
            probe_against_server(200, false, true).expect("traffic sample"),
            TrafficSample {
                totals: TrafficTotals { up: 10, down: 20 },
                connections: Some(Vec::new()),
            }
        );
    }

    /// Answers one request with `status` and returns its request line, or
    /// `None` when no request came within a second.
    fn close_against_server(id: &str, status: u16) -> (Result<(), EngineError>, Option<String>) {
        use std::io::Write;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let control = ControlEndpoint {
            address: listener.local_addr().unwrap(),
            secret: "test-secret".to_owned(),
        };
        let server = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(_) if std::time::Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return None,
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut reader = BufReader::new(socket);
            let mut request = String::new();
            reader.read_line(&mut request).unwrap();
            let mut line = String::new();
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
            write!(
                reader.get_mut(),
                "HTTP/1.1 {status} Test\r\nContent-Length: 0\r\n\r\n"
            )
            .unwrap();
            Some(request)
        });
        let result = SingBoxBackend::new("unused").close_connection(&control, id);
        (result, server.join().unwrap())
    }

    #[test]
    fn close_connection_deletes_by_encoded_id_and_maps_the_answer() {
        let (result, request) = close_against_server("0d5c1f2e-7a3b-4c9d-8e1f-2a3b4c5d6e7f", 204);
        assert!(result.is_ok());
        assert_eq!(
            request.as_deref(),
            Some("DELETE /connections/0d5c1f2e-7a3b-4c9d-8e1f-2a3b4c5d6e7f HTTP/1.1\r\n")
        );

        let (result, request) = close_against_server("../a b?x", 200);
        assert!(result.is_ok());
        assert_eq!(
            request.as_deref(),
            Some("DELETE /connections/..%2Fa%20b%3Fx HTTP/1.1\r\n")
        );

        let (result, _) = close_against_server("a", 401);
        assert!(matches!(result, Err(EngineError::Stats(message)) if message.contains("401")));
    }

    #[test]
    fn close_connection_refuses_a_bad_id_without_a_request() {
        for id in [
            String::new(),
            "a".repeat(rosetun_engine::MAX_CONNECTION_ID_CHARS + 1),
        ] {
            let (result, request) = close_against_server(&id, 204);
            assert!(matches!(result, Err(EngineError::Stats(_))));
            assert_eq!(request, None);
        }
    }

    #[test]
    fn traffic_probe_reports_http_failure() {
        assert!(matches!(
            probe_against_server(401, false, false),
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
            6,
            "sniff, DNS hijack, exit lookup, two enabled user rules, and LAN"
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
                lists: false,
                exits: false,
            },
            true,
        );

        assert_eq!(rendered.1, vec![RuleId::new("r2")]);
        let rules = rendered.0["rules"].as_array().expect("rules array");
        assert_eq!(
            rules.len(),
            5,
            "sniff, DNS hijack, exit lookup, one supported user rule, and LAN"
        );
        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(rules[1]["action"], "hijack-dns");
        assert_eq!(rules[2]["outbound"], "proxy");
        assert_eq!(rules[3]["domain_suffix"][0], "google.com");
        assert_eq!(rules[4]["ip_is_private"], true);
        assert_eq!(
            rules
                .iter()
                .filter(|rule| rule.get("process_path_regex").is_some())
                .count(),
            1
        );
    }

    #[test]
    fn rule_order_is_preserved() {
        let config = rendered();
        let rules = config["route"]["rules"].as_array().expect("rules array");

        assert_eq!(rules.len(), 6);
        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(rules[1]["action"], "hijack-dns");
        assert_eq!(rules[2]["outbound"], "proxy");
        assert_eq!(rules[3]["domain_suffix"][0], "google.com");
        assert_eq!(rules[3]["outbound"], "proxy");
        assert_eq!(
            rules[4]["process_path_regex"][0],
            r"(?i)(?:^|[\\/])steam\.exe$"
        );
        assert_eq!(rules[4]["outbound"], "direct");
        assert_eq!(rules[5]["ip_is_private"], true);
        assert_eq!(rules[5]["outbound"], "direct");
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
                "process_path_regex",
                r"(?i)(?:^|[\\/])app\.exe$",
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
                exit: None,
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
            extra: &[],
            node: &node,
            socks: None,
            rules: &rule_set,
            lists: &[],
            settings: &settings,
            control: None,
            verbose_log: false,
        })
        .expect("rendered");

        assert!(config.unsupported.is_empty());
        let config: Value = serde_json::from_slice(&config.body).expect("json");
        let route = config["route"]["rules"].as_array().expect("rules");
        assert_eq!(route.len(), cases.len() + 4);
        assert_eq!(route[0]["action"], "sniff");
        assert_eq!(route[1]["action"], "hijack-dns");
        assert_eq!(route[2]["outbound"], "proxy");

        for (index, (matcher, field, expected)) in cases.iter().enumerate() {
            assert!(backend.capabilities().rules.supports(matcher));
            assert_eq!(route[index + 3][*field][0], *expected);
            assert_eq!(route[index + 3]["action"], "route");
            assert_eq!(route[index + 3]["outbound"], "direct");
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
        assert_eq!(rules.len(), 7);

        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(rules[1]["action"], "hijack-dns");
        assert_eq!(rules[2]["outbound"], "proxy");

        assert_eq!(rules[3]["domain_suffix"][0], "google.com");
        assert_eq!(rules[3]["action"], "reject");
        assert!(rules[3].get("outbound").is_none());

        assert_eq!(
            rules[4]["process_path_regex"][0],
            r"(?i)(?:^|[\\/])steam\.exe$"
        );
        assert_eq!(rules[4]["outbound"], "direct");

        assert_eq!(rules[5]["ip_is_private"], true);
        assert_eq!(rules[5]["outbound"], "direct");

        let fallback = rules.last().expect("fallback");
        assert_eq!(fallback["action"], "reject");
        assert!(fallback.get("outbound").is_none());
    }

    #[test]
    fn exit_lookup_precedes_user_rules_and_all_default_targets() {
        let mut rule_set = rules();
        rule_set.rules.push(Rule {
            id: RuleId::new("gui-direct"),
            enabled: true,
            matcher: RuleMatcher::Process(ProcessMatch::Name("rosetun-gui.exe".into())),
            target: RuleTarget::Direct,
            exit: None,
        });

        for target in [RuleTarget::Proxy, RuleTarget::Direct, RuleTarget::Block] {
            rule_set.default_target = target;
            let (route, unsupported) =
                render::route_section(&rule_set, render::RULE_CAPABILITIES, false);
            assert!(unsupported.is_empty());
            let rules = route["rules"].as_array().expect("rules");
            assert_eq!(rules[0]["action"], "sniff");
            assert_eq!(rules[1]["action"], "hijack-dns");
            assert_eq!(
                rules[2],
                serde_json::json!({
                    "process_path_regex": [r"(?i)(?:^|[\\/])rosetun-gui\.exe$"],
                    "ip_cidr": ["1.1.1.1/32"],
                    "port": [443],
                    "action": "route",
                    "outbound": "proxy",
                })
            );
            assert_eq!(rules[3]["domain_suffix"][0], "google.com");
            assert_eq!(rules[5]["outbound"], "direct");
            assert_eq!(
                rules[5]["process_path_regex"],
                rules[2]["process_path_regex"]
            );
            assert_eq!(
                rules.last().unwrap()["action"] == "reject",
                target == RuleTarget::Block
            );
        }
    }

    /// sing-box looks up the program of every connection only when a route rule
    /// matches on one; the live connection list relies on that `processPath`.
    #[test]
    fn process_lookup_is_on_without_process_rules() {
        let rule_set = RuleSet {
            rules: Vec::new(),
            ..rules()
        };
        let (route, _) = render::route_section(&rule_set, render::RULE_CAPABILITIES, false);

        assert!(
            route["rules"]
                .as_array()
                .expect("rules")
                .iter()
                .any(|rule| rule.get("process_path_regex").is_some())
        );
        assert!(route.get("find_process").is_none());
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
                exit: None,
            },
            Rule {
                id: RuleId::new("suffix"),
                enabled: true,
                matcher: RuleMatcher::Domain(DomainMatch::Suffix("proxy.example".to_owned())),
                target: RuleTarget::Proxy,
                exit: None,
            },
            Rule {
                id: RuleId::new("keyword"),
                enabled: true,
                matcher: RuleMatcher::Domain(DomainMatch::Keyword("blocked".to_owned())),
                target: RuleTarget::Block,
                exit: None,
            },
        ];
        rule_set.default_target = RuleTarget::Proxy;

        let node = node();
        let settings = Settings {
            allow_lan: true,
            ..Settings::default()
        };
        let rendered = render::render(&RenderRequest {
            extra: &[],
            node: &node,
            socks: None,
            rules: &rule_set,
            lists: &[],
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

        assert_eq!(route_rules.len(), 7);
        assert_eq!(route_rules[0]["action"], "sniff");
        assert_eq!(route_rules[1]["action"], "hijack-dns");
        assert_eq!(route_rules[2]["outbound"], "proxy");

        // User rules retain their order after the service rules.
        assert_eq!(route_rules[3]["domain"][0], "direct.example");
        assert_eq!(route_rules[3]["action"], "route");
        assert_eq!(route_rules[3]["outbound"], "direct");

        assert_eq!(route_rules[4]["domain_suffix"][0], "proxy.example");
        assert_eq!(route_rules[4]["action"], "route");
        assert_eq!(route_rules[4]["outbound"], "proxy");

        assert_eq!(route_rules[5]["domain_keyword"][0], "blocked");
        assert_eq!(route_rules[5]["action"], "reject");

        assert_eq!(route_rules[6]["ip_is_private"], true);
        assert_eq!(route_rules[6]["action"], "route");
        assert_eq!(route_rules[6]["outbound"], "direct");

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

        assert_eq!(domain_indices, vec![3, 4, 5]);
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
            extra: &[],
            node: &node,
            socks: None,
            rules: &rules,
            lists: &[],
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
            extra: &[],
            node: &node,
            socks: None,
            rules: &rule_set,
            lists: &[],
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
                    "process_path_regex": [r"(?i)(?:^|[\\/])rosetun-gui\.exe$"],
                    "ip_cidr": ["1.1.1.1/32"],
                    "port": [443],
                    "action": "route",
                    "outbound": "proxy",
                }),
                serde_json::json!({
                    "domain_suffix": ["google.com"],
                    "action": "route",
                    "outbound": "proxy",
                }),
                serde_json::json!({
                    "process_path_regex": [r"(?i)(?:^|[\\/])steam\.exe$"],
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
                extra: &[],
                node: &node,
                socks: None,
                rules: &rules,
                lists: &[],
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
