mod dns;
#[cfg(test)]
mod tests;

use std::net::{IpAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rosetun_config::{ConnectionState, Node, RuleSet, Settings, Status, Traffic};
use rosetun_engine::{
    ControlEndpoint, EngineProcess, EngineRegistry, RenderRequest, TrafficProbe, TrafficTotals,
};
use rosetun_ipc::{ConnectRequest, ErrorCode, HelperError};
use rosetun_routing::{RoutingBackend, RoutingGuard, RoutingPlan, TunnelInterface};

const TUNNEL_READY_TIMEOUT: Duration = Duration::from_secs(15);
const TUNNEL_READY_POLL_INTERVAL: Duration = Duration::from_millis(100);
const TUNNEL_DNS_TIMEOUT: Duration = Duration::from_secs(10);
const TUNNEL_DNS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);

pub struct Helper {
    status: Arc<Mutex<Status>>,
    session: Mutex<Session>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartMode {
    Fresh,
    ProtectedReconnect,
}

#[derive(Debug, Clone)]
struct SuccessfulEndpoint {
    server: String,
    address: IpAddr,
}

struct Session {
    engines: EngineRegistry,
    routing: Box<dyn RoutingBackend>,
    status: Arc<Mutex<Status>>,
    process: Option<Box<dyn EngineProcess>>,
    control: Option<ControlEndpoint>,
    monitor: Option<TrafficMonitor>,
    guard: Option<RoutingGuard>,
    last_endpoint: Option<SuccessfulEndpoint>,
    stopping: bool,
    dns_timeout: Duration,
    dns_attempt_timeout: Duration,
}

impl std::fmt::Debug for Helper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Helper").finish_non_exhaustive()
    }
}

impl Helper {
    pub fn new(engines: EngineRegistry, routing: Box<dyn RoutingBackend>) -> Self {
        let status = Arc::new(Mutex::new(Status::default()));
        Self {
            status: Arc::clone(&status),
            session: Mutex::new(Session {
                engines,
                routing,
                status,
                process: None,
                control: None,
                monitor: None,
                guard: None,
                last_endpoint: None,
                stopping: false,
                dns_timeout: TUNNEL_DNS_TIMEOUT,
                dns_attempt_timeout: TUNNEL_DNS_ATTEMPT_TIMEOUT,
            }),
        }
    }

    pub fn status(&self) -> Status {
        if self.with_status(|status| matches!(status.state, ConnectionState::Connected))
            && let Ok(mut session) = self.session.try_lock()
        {
            let protected = session.guard.is_some();
            let exited = match session.process.as_mut() {
                Some(process) => match process.is_running() {
                    Ok(true) => None,
                    Ok(false) => Some("the engine process exited".to_owned()),
                    Err(error) => Some(error.to_string()),
                },
                None => None,
            };

            if let Some(reason) = exited {
                tracing::warn!(%reason, protected, "the engine terminated itself");
                self.with_status(|status| {
                    status.state = if protected {
                        ConnectionState::FailedProtected { reason }
                    } else {
                        ConnectionState::Failed { reason }
                    };
                    status.since_unix = None;
                });
            }
        }
        self.with_status(|status| status.clone())
    }

    pub fn connect(&self, request: &ConnectRequest) -> Result<(), HelperError> {
        let mut session = self.session()?;
        let state = self.with_status(|status| status.state.clone());

        let mode = match state {
            ConnectionState::Disconnected | ConnectionState::Failed { .. } => StartMode::Fresh,
            ConnectionState::FailedProtected { .. } => StartMode::ProtectedReconnect,
            _ => {
                return Err(HelperError::new(
                    ErrorCode::InvalidState,
                    format!("tunnel is already {state:?}"),
                ));
            }
        };

        tracing::info!(
            node = %request.node.id,
            engine = %request.settings.engine.as_str(),
            kill_switch = request.settings.kill_switch,
            allow_lan = request.settings.allow_lan,
            dns_server = %request.settings.dns.server,
            dns_server_name = %request.settings.dns.server_name,
            ?mode,
            "starting tunnel connection"
        );

        self.with_status(|status| status.state = ConnectionState::Connecting);

        match session.start(&request.node, &request.rule_set, &request.settings, mode) {
            Ok(()) => {
                self.with_status(|status| {
                    status.state = ConnectionState::Connected;
                    status.node = Some(request.node.id.clone());
                    status.engine = Some(request.settings.engine);
                    status.since_unix = Some(now_unix());
                });
                session.start_monitor(request.settings.engine);
                Ok(())
            }
            Err(error) => {
                match mode {
                    StartMode::Fresh => session.teardown(),
                    StartMode::ProtectedReconnect => {
                        if let Err(cleanup_error) = session.stop_engine() {
                            tracing::error!(
                                %cleanup_error,
                                "failed to stop engine after protected reconnect failure"
                            );
                        }
                    }
                }

                let reason = error.message.clone();
                self.with_status(|status| {
                    status.state = match mode {
                        StartMode::Fresh => ConnectionState::Failed { reason },
                        StartMode::ProtectedReconnect => {
                            ConnectionState::FailedProtected { reason }
                        }
                    };
                    status.since_unix = None;
                });
                Err(error)
            }
        }
    }

    pub fn disconnect(&self) -> Result<(), HelperError> {
        let mut session = self.session()?;
        session.teardown();
        self.with_status(|status| *status = Status::default());
        Ok(())
    }

    pub fn shutdown(&self) {
        tracing::info!("starting helper session teardown");
        let mut session = self
            .session
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        session.stopping = true;
        session.teardown();
        self.with_status(|status| *status = Status::default());
        tracing::info!("helper session teardown completed");
    }

    fn session(&self) -> Result<MutexGuard<'_, Session>, HelperError> {
        let session = match self.session.try_lock() {
            Ok(session) => session,
            Err(TryLockError::WouldBlock) => {
                return Err(HelperError::new(
                    ErrorCode::Busy,
                    "another tunnel operation is in progress",
                ));
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(HelperError::new(
                    ErrorCode::Internal,
                    "helper state poisoned by an earlier panic",
                ));
            }
        };
        if session.stopping {
            return Err(HelperError::new(
                ErrorCode::InvalidState,
                "helper is shutting down",
            ));
        }
        Ok(session)
    }

    fn with_status<T>(&self, apply: impl FnOnce(&mut Status) -> T) -> T {
        let mut status = self
            .status
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        apply(&mut status)
    }
}

/// Polls the engine once a second and publishes traffic into the status.
struct TrafficMonitor {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    status: Arc<Mutex<Status>>,
}

impl TrafficMonitor {
    fn start(mut probe: Box<dyn TrafficProbe>, status: Arc<Mutex<Status>>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker_status = Arc::clone(&status);
        let thread = thread::Builder::new()
            .name("engine-traffic".to_owned())
            .spawn(move || {
                let mut previous = None;
                let mut failed = false;
                loop {
                    for _ in 0..10 {
                        if worker_stop.load(Ordering::Acquire) {
                            return;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                    if worker_stop.load(Ordering::Acquire) {
                        return;
                    }

                    match probe.totals() {
                        Ok(totals) => {
                            if failed {
                                tracing::info!("engine traffic polling recovered");
                                failed = false;
                            }
                            let current = (totals, Instant::now());
                            let (up_bps, down_bps) = previous
                                .map(|previous| rates(previous, current))
                                .unwrap_or_default();
                            previous = Some(current);
                            let mut status = worker_status
                                .lock()
                                .unwrap_or_else(|error| error.into_inner());
                            status.traffic = Traffic {
                                up_bps,
                                down_bps,
                                up_total: totals.up,
                                down_total: totals.down,
                            };
                        }
                        Err(error) => {
                            if !failed {
                                tracing::warn!(%error, "engine traffic polling failed");
                                failed = true;
                            }
                            let mut status = worker_status
                                .lock()
                                .unwrap_or_else(|error| error.into_inner());
                            status.traffic.up_bps = 0;
                            status.traffic.down_bps = 0;
                        }
                    }
                }
            })
            .expect("traffic monitor thread starts");
        Self {
            stop,
            thread: Some(thread),
            status,
        }
    }

    /// Stops the thread, waits for it and clears the published traffic.
    fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::warn!("engine traffic monitor thread panicked");
        }
        self.status
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .traffic = Traffic::default();
    }
}

/// Bytes per second between two samples. A smaller total means the engine
/// restarted, which reads as zero rather than a huge number.
fn rates(previous: (TrafficTotals, Instant), current: (TrafficTotals, Instant)) -> (u64, u64) {
    let elapsed = current
        .1
        .checked_duration_since(previous.1)
        .unwrap_or_default()
        .as_nanos();
    if elapsed == 0 {
        return (0, 0);
    }
    let rate = |before: u64, after: u64| {
        let bytes = u128::from(after.saturating_sub(before));
        u64::try_from(bytes * 1_000_000_000 / elapsed).unwrap_or(u64::MAX)
    };
    (
        rate(previous.0.up, current.0.up),
        rate(previous.0.down, current.0.down),
    )
}

impl Session {
    fn start(
        &mut self,
        node: &Node,
        rules: &RuleSet,
        settings: &Settings,
        mode: StartMode,
    ) -> Result<(), HelperError> {
        // Dispose of the old process before borrowing the backend or spawning another.
        // A stop failure retains its handle and prevents a second engine from starting.
        self.stop_engine()?;

        if mode == StartMode::ProtectedReconnect {
            if self.guard.is_none() {
                return Err(HelperError::new(
                    ErrorCode::RoutingFailed,
                    "protected reconnect is impossible: the routing guard is missing",
                ));
            }
            if !settings.kill_switch {
                return Err(HelperError::new(
                    ErrorCode::InvalidState,
                    "disconnect first to turn protection off",
                ));
            }
        }

        let endpoint = if mode == StartMode::ProtectedReconnect {
            Some(protected_endpoint(node, self.last_endpoint.as_ref())?)
        } else if settings.engine == rosetun_config::EngineKind::SingBox {
            Some(select_endpoint(&resolve(&node.server, node.port)?)?)
        } else {
            None
        };

        let resolved_node = endpoint.map(|address| node_with_endpoint(node, address));
        let backend = self.engines.get(settings.engine).ok_or_else(|| {
            HelperError::new(
                ErrorCode::EngineFailed,
                format!("engine {} is not registered", settings.engine.as_str()),
            )
        })?;
        let dns_server = backend.tunnel_dns_server(&settings.tun);
        let control = match ControlEndpoint::local() {
            Ok(control) => Some(control),
            Err(error) => {
                tracing::warn!(%error, "traffic control endpoint is unavailable");
                None
            }
        };

        let config = backend
            .render(&RenderRequest {
                node: resolved_node.as_ref().unwrap_or(node),
                rules,
                settings,
                control: control.as_ref(),
            })
            .map_err(|error| HelperError::new(ErrorCode::EngineFailed, error.to_string()))?;

        if !config.unsupported.is_empty() {
            let rule_ids = config
                .unsupported
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            return Err(HelperError::new(
                ErrorCode::UnsupportedRules,
                format!(
                    "engine {} cannot represent enabled rules: {rule_ids}",
                    backend.kind().as_str()
                ),
            ));
        }

        let binary = backend
            .locate_binary()
            .map_err(|error| HelperError::new(ErrorCode::EngineFailed, error.to_string()))?;

        tracing::debug!(
            engine = %backend.kind().as_str(),
            binary = %binary.display(),
            "engine binary located"
        );

        let tunnel = settings
            .kill_switch
            .then(|| TunnelInterface::try_from(&settings.tun))
            .transpose()
            .map_err(|error| HelperError::new(ErrorCode::RoutingFailed, error.to_string()))?;

        if settings.kill_switch {
            let plan = RoutingPlan {
                allow_lan: settings.allow_lan,
            };

            match mode {
                StartMode::Fresh => {
                    self.routing.preflight().map_err(|error| {
                        HelperError::new(ErrorCode::RoutingFailed, error.to_string())
                    })?;
                    self.guard = Some(self.routing.begin_protection(&plan, &binary).map_err(
                        |error| HelperError::new(ErrorCode::RoutingFailed, error.to_string()),
                    )?);
                }
                StartMode::ProtectedReconnect => {
                    self.guard
                        .as_mut()
                        .expect("protected reconnect validated the guard")
                        .prepare_reconnect(&plan, &binary)
                        .map_err(|error| {
                            HelperError::new(ErrorCode::RoutingFailed, error.to_string())
                        })?;
                }
            }
        }

        tracing::info!(engine = %backend.kind().as_str(), "spawning tunnel engine");
        self.process = Some(
            backend
                .spawn(&binary, &config)
                .map_err(|error| HelperError::new(ErrorCode::EngineFailed, error.to_string()))?,
        );
        self.control = control;

        self.wait_for_engine_ready()?;

        if let Some(tunnel) = tunnel.as_ref() {
            self.wait_for_tunnel(tunnel)?;

            let running = self
                .process
                .as_mut()
                .expect("engine process was stored before tunnel readiness")
                .is_running()
                .map_err(|error| HelperError::new(ErrorCode::EngineFailed, error.to_string()))?;

            if !running {
                return Err(HelperError::new(
                    ErrorCode::EngineFailed,
                    "engine exited during tunnel readiness",
                ));
            }
        }

        if let Some(server) = dns_server {
            let process = self.process.as_mut().ok_or_else(|| {
                HelperError::new(
                    ErrorCode::EngineFailed,
                    "engine process disappeared before DNS check",
                )
            })?;
            dns::check(server, self.dns_timeout, self.dns_attempt_timeout, || {
                process.is_running()
            })?;
        } else {
            tracing::info!(
                engine = %settings.engine.as_str(),
                "backend does not provide a tunnel DNS server; skipping DNS check"
            );
        }

        // Do not poison the successful endpoint cache with a failed attempt.
        self.last_endpoint = endpoint.map(|address| SuccessfulEndpoint {
            server: normalize_server(&node.server),
            address,
        });
        Ok(())
    }

    fn start_monitor(&mut self, kind: rosetun_config::EngineKind) {
        let Some(control) = self.control.as_ref() else {
            return;
        };
        let Some(backend) = self.engines.get(kind) else {
            return;
        };
        if let Some(probe) = backend.traffic_probe(control) {
            self.monitor = Some(TrafficMonitor::start(probe, Arc::clone(&self.status)));
        }
    }

    fn wait_for_engine_ready(&mut self) -> Result<(), HelperError> {
        let deadline = Instant::now() + TUNNEL_READY_TIMEOUT;

        loop {
            let process = self.process.as_mut().ok_or_else(|| {
                HelperError::new(
                    ErrorCode::EngineFailed,
                    "engine process disappeared before startup readiness",
                )
            })?;

            let running = process
                .is_running()
                .map_err(|error| HelperError::new(ErrorCode::EngineFailed, error.to_string()))?;

            if !running {
                return Err(HelperError::new(
                    ErrorCode::EngineFailed,
                    "engine exited before startup readiness",
                ));
            }

            let ready = process
                .is_ready()
                .map_err(|error| HelperError::new(ErrorCode::EngineFailed, error.to_string()))?;

            if ready {
                // The process may have exited while the signal was being read.
                let running = process.is_running().map_err(|error| {
                    HelperError::new(ErrorCode::EngineFailed, error.to_string())
                })?;

                if !running {
                    return Err(HelperError::new(
                        ErrorCode::EngineFailed,
                        "engine exited during startup readiness",
                    ));
                }

                tracing::info!("engine startup readiness confirmed");
                return Ok(());
            }

            if Instant::now() >= deadline {
                return Err(HelperError::new(
                    ErrorCode::EngineFailed,
                    format!(
                        "engine startup readiness was not confirmed within {} seconds",
                        TUNNEL_READY_TIMEOUT.as_secs()
                    ),
                ));
            }

            std::thread::sleep(TUNNEL_READY_POLL_INTERVAL);
        }
    }

    fn wait_for_tunnel(&mut self, tunnel: &TunnelInterface) -> Result<(), HelperError> {
        let deadline = Instant::now() + TUNNEL_READY_TIMEOUT;

        loop {
            let running = self
                .process
                .as_mut()
                .ok_or_else(|| {
                    HelperError::new(
                        ErrorCode::EngineFailed,
                        "engine process disappeared before tunnel readiness",
                    )
                })?
                .is_running()
                .map_err(|error| HelperError::new(ErrorCode::EngineFailed, error.to_string()))?;

            if !running {
                return Err(HelperError::new(
                    ErrorCode::EngineFailed,
                    "engine exited before creating its tunnel interface",
                ));
            }

            let guard = self.guard.as_mut().ok_or_else(|| {
                HelperError::new(
                    ErrorCode::RoutingFailed,
                    "routing protection disappeared before tunnel authorization",
                )
            })?;

            match guard.authorize_tunnel(tunnel) {
                Ok(()) => {
                    tracing::info!(
                        alias = %tunnel.alias,
                        ipv4 = %tunnel.ipv4,
                        "tunnel readiness authorization completed"
                    );
                    return Ok(());
                }
                Err(error) if error.is_tunnel_not_ready() && Instant::now() < deadline => {
                    tracing::debug!(
                        alias = %tunnel.alias,
                        %error,
                        "tunnel is not ready yet; retrying"
                    );
                    std::thread::sleep(TUNNEL_READY_POLL_INTERVAL);
                }
                Err(error) if error.is_tunnel_not_ready() => {
                    return Err(HelperError::new(
                        ErrorCode::RoutingFailed,
                        format!(
                            "tunnel interface {} did not become ready within {} seconds: {error}",
                            tunnel.alias,
                            TUNNEL_READY_TIMEOUT.as_secs()
                        ),
                    ));
                }
                Err(error) => {
                    return Err(HelperError::new(
                        ErrorCode::RoutingFailed,
                        error.to_string(),
                    ));
                }
            }
        }
    }

    fn stop_engine(&mut self) -> Result<(), HelperError> {
        if let Some(monitor) = self.monitor.take() {
            monitor.stop();
        } else {
            self.status
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .traffic = Traffic::default();
        }
        if let Some(process) = self.process.as_mut() {
            process
                .stop()
                .map_err(|error| HelperError::new(ErrorCode::EngineFailed, error.to_string()))?;
        }
        self.process.take();
        self.control.take();
        Ok(())
    }

    fn teardown(&mut self) {
        if let Err(error) = self.stop_engine() {
            tracing::error!(%error, "failed to stop the engine");
        }
        if let Some(guard) = self.guard.take()
            && let Err(error) = guard.revert()
        {
            tracing::error!(%error, "failed to roll back routes");
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.teardown();
    }
}

fn normalize_server(server: &str) -> String {
    server.trim_end_matches('.').to_ascii_lowercase()
}

fn protected_endpoint(
    node: &Node,
    cached: Option<&SuccessfulEndpoint>,
) -> Result<IpAddr, HelperError> {
    if let Ok(address) = node.server.parse::<IpAddr>() {
        return Ok(address);
    }

    cached
        .filter(|endpoint| endpoint.server == normalize_server(&node.server))
        .map(|endpoint| endpoint.address)
        .ok_or_else(|| {
            HelperError::new(
                ErrorCode::RoutingFailed,
                "cannot resolve a new server name while protection is active; use an IP address or the last connected server",
            )
        })
}

fn resolve(server: &str, port: u16) -> Result<Vec<IpAddr>, HelperError> {
    let addresses = (server, port)
        .to_socket_addrs()
        .map_err(|error| {
            tracing::warn!(%server, %error, "failed to resolve the VPN endpoint");
            HelperError::new(
                ErrorCode::RoutingFailed,
                format!("failed to resolve VPN endpoint {server}: {error}"),
            )
        })?
        .map(|address| address.ip())
        .collect::<Vec<_>>();

    if addresses.is_empty() {
        return Err(HelperError::new(
            ErrorCode::RoutingFailed,
            format!("VPN endpoint {server} resolved to no addresses"),
        ));
    }

    Ok(addresses)
}

fn select_endpoint(addresses: &[IpAddr]) -> Result<IpAddr, HelperError> {
    addresses
        .iter()
        .copied()
        .find(IpAddr::is_ipv4)
        .or_else(|| addresses.first().copied())
        .ok_or_else(|| {
            HelperError::new(
                ErrorCode::RoutingFailed,
                "VPN endpoint resolved to no addresses",
            )
        })
}

fn node_with_endpoint(node: &Node, endpoint: IpAddr) -> Node {
    use rosetun_config::{TlsMode, Transport};

    let mut prepared = node.clone();
    if node.server.parse::<IpAddr>().is_err() {
        match &mut prepared.stream.tls {
            TlsMode::Tls(params) => {
                params.sni.get_or_insert_with(|| node.server.clone());
            }
            TlsMode::Reality(params) => {
                params.sni.get_or_insert_with(|| node.server.clone());
            }
            TlsMode::Plain => {}
        }

        match &mut prepared.stream.transport {
            Transport::Ws { host, .. } | Transport::HttpUpgrade { host, .. } => {
                host.get_or_insert_with(|| node.server.clone());
            }
            Transport::Tcp | Transport::Grpc { .. } => {}
        }
    }
    prepared.server = endpoint.to_string();
    prepared
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default()
}
