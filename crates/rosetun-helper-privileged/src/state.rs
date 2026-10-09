mod apply;
mod dns;
mod path;
mod probe;
#[cfg(test)]
mod tests;
mod watchdog;

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use rosetun_config::{
    ConnectionState, Node, Rule, RuleMatcher, RuleSet, Settings, Status, Traffic,
};
use rosetun_engine::{
    ControlEndpoint, EngineBackend, EngineProcess, EngineRegistry, RenderRequest, RenderedConfig,
    TrafficProbe, TrafficTotals,
};
use rosetun_ipc::{ConnectRequest, ErrorCode, HelperError, MAX_TEMPORARY_RULES};
use rosetun_routing::{
    ProtectionScope, RoutingBackend, RoutingGuard, RoutingPlan, TunnelInterface,
};

use crate::log_gate::VerboseGate;
use watchdog::{DnsWatchdog, WatchdogTiming};

const TUNNEL_READY_TIMEOUT: Duration = Duration::from_secs(15);
const TUNNEL_READY_POLL_INTERVAL: Duration = Duration::from_millis(100);
const TUNNEL_DNS_TIMEOUT: Duration = Duration::from_secs(10);
const TUNNEL_DNS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);
const WATCHDOG_TIMING: WatchdogTiming = WatchdogTiming {
    interval: Duration::from_secs(30),
    retry: Duration::from_secs(5),
    dns_timeout: Duration::from_secs(5),
    path_timeout: Duration::from_secs(5),
    failures: 3,
    path_server: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)), 80),
};
/// Failed automatic attempts before the helper gives up.
const RECONNECT_ATTEMPTS: u32 = 5;
/// Waits before the second to fifth attempt.
const RECONNECT_BACKOFF: [Duration; 4] = [
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(20),
];
/// The network needs a moment after a resume.
const RESUME_DELAY: Duration = Duration::from_secs(2);
const SUPERVISOR_TICK: Duration = Duration::from_millis(500);
/// A wall-clock jump this large between two ticks means the machine slept.
const SLEEP_GAP: Duration = Duration::from_secs(30);

pub struct Helper {
    status: Arc<Mutex<Status>>,
    session: Mutex<Session>,
    engines: Arc<EngineRegistry>,
    probe: Mutex<()>,
    shutting_down: AtomicBool,
    resumed: AtomicBool,
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

/// A pending automatic reconnect.
#[derive(Debug)]
struct Reconnect {
    failures: u32,
    next_at: Instant,
    cause: &'static str,
}

/// Routing protection that outlives one engine process.
struct Guard {
    routing: RoutingGuard,
    scope: ProtectionScope,
}

struct Session {
    engines: Arc<EngineRegistry>,
    routing: Box<dyn RoutingBackend>,
    gate: VerboseGate,
    status: Arc<Mutex<Status>>,
    process: Option<Box<dyn EngineProcess>>,
    control: Option<ControlEndpoint>,
    monitor: Option<TrafficMonitor>,
    watchdog: Option<DnsWatchdog>,
    tunnel_dns: Option<SocketAddr>,
    guard: Option<Guard>,
    last_endpoint: Option<SuccessfulEndpoint>,
    request: Option<ConnectRequest>,
    reconnect: Option<Reconnect>,
    stopping: bool,
    dns_timeout: Duration,
    dns_attempt_timeout: Duration,
    watchdog_timing: WatchdogTiming,
    adapter_lookup: fn(&str) -> std::io::Result<bool>,
}

impl std::fmt::Debug for Helper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Helper").finish_non_exhaustive()
    }
}

impl Helper {
    pub fn new(
        engines: EngineRegistry,
        routing: Box<dyn RoutingBackend>,
        gate: VerboseGate,
    ) -> Self {
        let status = Arc::new(Mutex::new(Status::default()));
        let engines = Arc::new(engines);
        Self {
            status: Arc::clone(&status),
            engines: Arc::clone(&engines),
            probe: Mutex::new(()),
            shutting_down: AtomicBool::new(false),
            resumed: AtomicBool::new(false),
            session: Mutex::new(Session {
                engines,
                routing,
                gate,
                status,
                process: None,
                control: None,
                monitor: None,
                watchdog: None,
                tunnel_dns: None,
                guard: None,
                last_endpoint: None,
                request: None,
                reconnect: None,
                stopping: false,
                dns_timeout: TUNNEL_DNS_TIMEOUT,
                dns_attempt_timeout: TUNNEL_DNS_ATTEMPT_TIMEOUT,
                watchdog_timing: WATCHDOG_TIMING,
                #[cfg(not(test))]
                adapter_lookup: rosetun_routing::tunnel_adapter_present,
                #[cfg(test)]
                adapter_lookup: |_| Ok(false),
            }),
        }
    }

    pub fn status(&self) -> Status {
        self.with_status(|status| status.clone())
    }

    pub fn temporary_rules(&self) -> Result<Vec<Rule>, HelperError> {
        let session = self.session()?;
        Ok(session
            .request
            .as_ref()
            .map(|request| request.temporary_rules.clone())
            .unwrap_or_default())
    }

    /// The machine woke from sleep; the supervisor restarts a live tunnel.
    pub fn notify_resume(&self) {
        self.resumed.store(true, Ordering::Release);
    }

    pub fn supervise(&self, now: Instant) {
        let Ok(mut session) = self.session.try_lock() else {
            return;
        };
        if session.stopping {
            return;
        }
        let Some(auto_reconnect) = session
            .request
            .as_ref()
            .map(|request| request.settings.auto_reconnect)
        else {
            self.resumed.store(false, Ordering::Release);
            return;
        };

        if let Some(reconnect) = &session.reconnect {
            if now < reconnect.next_at {
                return;
            }
        } else {
            let exited = match session.process.as_mut() {
                Some(process) => match process.is_running() {
                    Ok(true) => None,
                    Ok(false) => Some("the engine process exited".to_owned()),
                    Err(error) => Some(error.to_string()),
                },
                None => Some("the engine process is missing".to_owned()),
            };
            if let Some(reason) = exited {
                let protected = session.keeps_protection();
                if !auto_reconnect {
                    tracing::warn!(%reason, protected, "the engine terminated itself");
                    if !protected {
                        session.teardown();
                    }
                    self.with_status(|status| {
                        status.state = if protected {
                            ConnectionState::FailedProtected { reason }
                        } else {
                            ConnectionState::Failed { reason }
                        };
                        status.since_unix = None;
                    });
                    session.request = None;
                    return;
                }
                tracing::warn!(%reason, protected, "the engine terminated; reconnecting");
                self.with_status(|status| status.state = ConnectionState::Reconnecting);
                session.reconnect = Some(Reconnect {
                    failures: 0,
                    next_at: now,
                    cause: "engine exited",
                });
            } else if self.resumed.swap(false, Ordering::AcqRel) {
                if !auto_reconnect {
                    return;
                }
                tracing::info!("resumed from sleep; reconnecting tunnel");
                self.with_status(|status| status.state = ConnectionState::Reconnecting);
                session.reconnect = Some(Reconnect {
                    failures: 0,
                    next_at: now + RESUME_DELAY,
                    cause: "resume",
                });
                return;
            } else if session
                .watchdog
                .as_ref()
                .is_some_and(DnsWatchdog::take_stalled)
            {
                if !auto_reconnect {
                    tracing::warn!("DNS through the tunnel stalled; auto-reconnect is disabled");
                    return;
                }
                tracing::warn!("DNS through the tunnel stalled; reconnecting");
                self.with_status(|status| status.state = ConnectionState::Reconnecting);
                session.reconnect = Some(Reconnect {
                    failures: 0,
                    next_at: now,
                    cause: "dns stalled",
                });
            } else {
                return;
            }
        }

        self.resumed.store(false, Ordering::Release);
        let request = session.request.clone().expect("active request is present");
        let reconnect = session.reconnect.take().expect("reconnect is scheduled");
        let attempt = reconnect.failures + 1;
        let mode = if session.guard.is_some() {
            StartMode::ProtectedReconnect
        } else {
            StartMode::Fresh
        };
        match session.start(
            &request.node,
            &request.effective_rule_set(),
            &request.settings,
            mode,
            None,
        ) {
            Ok(()) => {
                self.with_status(|status| {
                    status.state = ConnectionState::Connected;
                    status.since_unix.get_or_insert_with(now_unix);
                });
                session.start_monitor(request.settings.engine);
                session.start_watchdog();
                tracing::info!(cause = reconnect.cause, attempt, "tunnel reconnected");
            }
            Err(error) => {
                let failures = attempt;
                if failures < RECONNECT_ATTEMPTS {
                    if let Err(cleanup_error) = session.stop_engine() {
                        tracing::error!(%cleanup_error, "failed to stop engine after reconnect failure");
                    }
                    session.reconnect = Some(Reconnect {
                        failures,
                        next_at: Instant::now() + RECONNECT_BACKOFF[(failures - 1) as usize],
                        cause: reconnect.cause,
                    });
                    tracing::warn!(cause = reconnect.cause, attempt, %error, "tunnel reconnect failed; retrying");
                } else {
                    let protected = session.keeps_protection();
                    if protected {
                        if let Err(cleanup_error) = session.stop_engine() {
                            tracing::error!(%cleanup_error, "failed to stop engine after protected reconnect failure");
                        }
                    } else {
                        session.teardown();
                    }
                    tracing::warn!(cause = reconnect.cause, attempt, %error, "tunnel reconnect attempts exhausted");
                    let reason = error.message;
                    self.with_status(|status| {
                        status.state = if protected {
                            ConnectionState::FailedProtected { reason }
                        } else {
                            ConnectionState::Failed { reason }
                        };
                        status.since_unix = None;
                    });
                    session.request = None;
                }
            }
        }
    }

    pub fn connect(&self, request: &ConnectRequest) -> Result<(), HelperError> {
        let mut session = self.session()?;
        validate_temporary_rules(request)?;
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
            verbose_log = request.settings.verbose_log_active(now_unix()),
            ?mode,
            "starting tunnel connection"
        );

        session.request = None;
        session.reconnect = None;
        self.with_status(|status| status.state = ConnectionState::Connecting);

        match session.start(
            &request.node,
            &request.effective_rule_set(),
            &request.settings,
            mode,
            None,
        ) {
            Ok(()) => {
                self.with_status(|status| {
                    status.state = ConnectionState::Connected;
                    status.node = Some(request.node.id.clone());
                    status.engine = Some(request.settings.engine);
                    status.since_unix = Some(now_unix());
                });
                session.request = Some(request.clone());
                self.resumed.store(false, Ordering::Release);
                session.start_monitor(request.settings.engine);
                session.start_watchdog();
                Ok(())
            }
            Err(error) => {
                let protected = mode == StartMode::ProtectedReconnect && session.keeps_protection();
                if protected {
                    if let Err(cleanup_error) = session.stop_engine() {
                        tracing::error!(
                            %cleanup_error,
                            "failed to stop engine after protected reconnect failure"
                        );
                    }
                } else {
                    session.teardown();
                }

                let reason = error.message.clone();
                self.with_status(|status| {
                    status.state = if protected {
                        ConnectionState::FailedProtected { reason }
                    } else {
                        ConnectionState::Failed { reason }
                    };
                    status.since_unix = None;
                });
                Err(error)
            }
        }
    }

    pub fn disconnect(&self) -> Result<(), HelperError> {
        let mut session = self.session()?;
        session.request = None;
        session.reconnect = None;
        session.teardown();
        self.with_status(|status| *status = Status::default());
        Ok(())
    }

    pub fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::Release);
        tracing::info!("starting helper session teardown");
        let mut session = self
            .session
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        session.stopping = true;
        session.request = None;
        session.reconnect = None;
        session.teardown();
        self.with_status(|status| *status = Status::default());
        drop(session);
        // The service must not exit with a live probe process or its secret config.
        let _probe = self.probe.lock().unwrap_or_else(|error| error.into_inner());
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

fn validate_temporary_rules(request: &ConnectRequest) -> Result<(), HelperError> {
    if request.temporary_rules.len() > MAX_TEMPORARY_RULES
        || request
            .temporary_rules
            .iter()
            .any(|rule| matches!(rule.matcher, RuleMatcher::Template(_)))
    {
        return Err(HelperError::new(
            ErrorCode::UnsupportedRules,
            "temporary rules exceed the limit or contain a template",
        ));
    }
    Ok(())
}

/// Runs `supervise` every tick and reports a resume when the wall clock jumps.
pub fn spawn_supervisor(helper: Arc<Helper>) -> std::io::Result<()> {
    thread::Builder::new()
        .name("engine-supervisor".to_owned())
        .spawn(move || {
            loop {
                let before = SystemTime::now();
                thread::sleep(SUPERVISOR_TICK);
                // Only the pause counts: a long reconnect attempt inside `supervise` is not sleep.
                if slept(before, SystemTime::now()) {
                    helper.notify_resume();
                }
                helper.supervise(Instant::now());
            }
        })?;
    Ok(())
}

/// The machine slept between two ticks: the wall clock moved much further than the tick.
fn slept(previous: SystemTime, now: SystemTime) -> bool {
    now.duration_since(previous)
        .is_ok_and(|gap| gap > SLEEP_GAP)
}

/// Polls the engine once a second and publishes traffic into the status.
struct TrafficMonitor {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    status: Arc<Mutex<Status>>,
}

impl TrafficMonitor {
    fn start(
        mut probe: Box<dyn TrafficProbe>,
        status: Arc<Mutex<Status>>,
    ) -> std::io::Result<Self> {
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
            })?;
        Ok(Self {
            stop,
            thread: Some(thread),
            status,
        })
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

impl Drop for TrafficMonitor {
    fn drop(&mut self) {
        // A forgotten stop must not leave the worker polling the engine forever.
        self.stop.store(true, Ordering::Release);
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
    /// Only the kill switch keeps blocking after a failure. The DNS lock goes
    /// with the session.
    fn keeps_protection(&self) -> bool {
        self.guard
            .as_ref()
            .is_some_and(|guard| guard.scope == ProtectionScope::AllTraffic)
    }

    fn start(
        &mut self,
        node: &Node,
        rules: &RuleSet,
        settings: &Settings,
        mode: StartMode,
        endpoint: Option<IpAddr>,
    ) -> Result<(), HelperError> {
        // Dispose of the old process before borrowing the backend or spawning another.
        // A stop failure retains its handle and prevents a second engine from starting.
        self.stop_engine()?;

        wait_for_previous_adapter(
            &settings.tun.name,
            Duration::from_secs(20),
            Duration::from_millis(250),
            self.adapter_lookup,
        )?;

        if mode == StartMode::Fresh
            && let Some(guard) = self.guard.take()
            && let Err(error) = guard.routing.revert()
        {
            tracing::error!(%error, "failed to roll back stale routing protection");
        }

        if mode == StartMode::ProtectedReconnect {
            if self.guard.is_none() {
                return Err(HelperError::new(
                    ErrorCode::RoutingFailed,
                    "protected reconnect is impossible: the routing guard is missing",
                ));
            }
            if !settings.kill_switch && self.keeps_protection() {
                return Err(HelperError::new(
                    ErrorCode::InvalidState,
                    "disconnect first to turn protection off",
                ));
            }
        }

        let endpoint = if endpoint.is_some() {
            endpoint
        } else if mode == StartMode::ProtectedReconnect {
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

        let verbose_until = settings
            .verbose_log_until
            .filter(|until| now_unix() < *until);
        if let Some(until) = verbose_until {
            self.gate.open_until(until);
            tracing::info!(until, "verbose engine log is on");
        } else {
            self.gate.close();
        }
        let config = render_config(
            backend,
            resolved_node.as_ref().unwrap_or(node),
            rules,
            settings,
            control.as_ref(),
            verbose_until.is_some(),
        )?;

        let binary = backend
            .locate_binary()
            .map_err(|error| HelperError::new(ErrorCode::EngineFailed, error.to_string()))?;

        tracing::debug!(
            engine = %backend.kind().as_str(),
            binary = %binary.display(),
            "engine binary located"
        );

        let scope = match mode {
            StartMode::Fresh => {
                if settings.kill_switch {
                    Some(ProtectionScope::AllTraffic)
                } else if dns_server.is_some() {
                    Some(ProtectionScope::DnsOnly)
                } else {
                    None
                }
            }
            // The guard stays; only the kill switch may widen it.
            StartMode::ProtectedReconnect => Some(if settings.kill_switch {
                ProtectionScope::AllTraffic
            } else {
                ProtectionScope::DnsOnly
            }),
        };
        let tunnel = scope
            .map(|_| TunnelInterface::try_from(&settings.tun))
            .transpose()
            .map_err(|error| HelperError::new(ErrorCode::RoutingFailed, error.to_string()))?;

        if let Some(scope) = scope {
            let plan = RoutingPlan {
                scope,
                allow_lan: settings.allow_lan,
            };

            match mode {
                StartMode::Fresh => {
                    let result = self
                        .routing
                        .preflight()
                        .and_then(|()| self.routing.begin_protection(&plan, &binary));
                    match result {
                        Ok(routing) => {
                            self.guard = Some(Guard { routing, scope });
                            tracing::info!(?scope, "routing protection installed");
                        }
                        Err(error) if scope == ProtectionScope::DnsOnly => {
                            tracing::warn!(%error, "DNS lock is unavailable; connecting without it");
                        }
                        Err(error) => {
                            return Err(HelperError::new(
                                ErrorCode::RoutingFailed,
                                error.to_string(),
                            ));
                        }
                    }
                }
                StartMode::ProtectedReconnect => {
                    let guard = self
                        .guard
                        .as_mut()
                        .expect("protected reconnect validated the guard");
                    guard
                        .routing
                        .prepare_reconnect(&plan, &binary)
                        .map_err(|error| {
                            HelperError::new(ErrorCode::RoutingFailed, error.to_string())
                        })?;
                    guard.scope = scope;
                }
            }
        }
        // Without a guard there is no filter to authorize on the tunnel.
        let tunnel = tunnel.filter(|_| self.guard.is_some());

        tracing::info!(engine = %backend.kind().as_str(), "spawning tunnel engine");
        self.process = Some(
            backend
                .spawn(&binary, &config)
                .map_err(|error| HelperError::new(ErrorCode::EngineFailed, error.to_string()))?,
        );
        self.control = control;

        wait_for_engine_ready(
            self.process
                .as_mut()
                .expect("engine process was stored before readiness")
                .as_mut(),
        )?;
        tracing::info!("engine startup readiness confirmed");

        if let Some(tunnel) = tunnel.as_ref() {
            match self.wait_for_tunnel(tunnel) {
                Ok(()) => {}
                // A lock that cannot authorize the tunnel would block DNS into it as well.
                Err(error)
                    if mode == StartMode::Fresh
                        && error.code == ErrorCode::RoutingFailed
                        && self
                            .guard
                            .as_ref()
                            .is_some_and(|guard| guard.scope == ProtectionScope::DnsOnly) =>
                {
                    tracing::warn!(reason = %error.message, "DNS lock cannot authorize the tunnel; connecting without it");
                    if let Some(guard) = self.guard.take()
                        && let Err(error) = guard.routing.revert()
                    {
                        tracing::error!(%error, "failed to roll back DNS lock");
                    }
                }
                Err(error) => return Err(error),
            }

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
            self.tunnel_dns = Some(server);
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
            match TrafficMonitor::start(probe, Arc::clone(&self.status)) {
                Ok(monitor) => self.monitor = Some(monitor),
                Err(error) => tracing::warn!(%error, "traffic monitor is unavailable"),
            }
        }
    }

    fn start_watchdog(&mut self) {
        let Some(server) = self.tunnel_dns else {
            return;
        };
        match DnsWatchdog::start(Arc::clone(&self.status), server, self.watchdog_timing) {
            Ok(watchdog) => self.watchdog = Some(watchdog),
            Err(error) => tracing::warn!(%error, "DNS watchdog is unavailable"),
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

            let guard = self
                .guard
                .as_mut()
                .map(|guard| &mut guard.routing)
                .ok_or_else(|| {
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
        self.gate.close();
        self.tunnel_dns = None;
        if let Some(watchdog) = self.watchdog.take() {
            watchdog.stop();
        }
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
            && let Err(error) = guard.routing.revert()
        {
            tracing::error!(%error, "failed to roll back routes");
        }
    }
}

fn render_config(
    backend: &dyn EngineBackend,
    node: &Node,
    rules: &RuleSet,
    settings: &Settings,
    control: Option<&ControlEndpoint>,
    verbose_log: bool,
) -> Result<RenderedConfig, HelperError> {
    let config = backend
        .render(&RenderRequest {
            node,
            rules,
            settings,
            control,
            verbose_log,
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
    Ok(config)
}

fn wait_for_previous_adapter(
    alias: &str,
    timeout: Duration,
    interval: Duration,
    mut lookup: impl FnMut(&str) -> std::io::Result<bool>,
) -> Result<(), HelperError> {
    let started = Instant::now();
    let mut waiting = false;
    loop {
        match lookup(alias) {
            Ok(false) => {
                if waiting {
                    tracing::info!(
                        elapsed_ms = started.elapsed().as_millis(),
                        "previous tunnel adapter removed"
                    );
                }
                return Ok(());
            }
            Err(error) => {
                tracing::warn!(%error, "could not look up previous tunnel adapter; continuing startup");
                return Ok(());
            }
            Ok(true) => {}
        }
        if !waiting {
            tracing::info!("waiting for Windows to remove the previous tunnel adapter");
            waiting = true;
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            tracing::warn!(
                elapsed_ms = elapsed.as_millis(),
                "previous tunnel adapter removal timed out"
            );
            return Err(HelperError::new(
                ErrorCode::EngineFailed,
                "previous tunnel adapter is still present after the removal deadline",
            ));
        }
        thread::sleep(interval.min(timeout.saturating_sub(elapsed)));
    }
}

fn wait_for_engine_ready(process: &mut dyn EngineProcess) -> Result<(), HelperError> {
    let deadline = Instant::now() + TUNNEL_READY_TIMEOUT;
    loop {
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
            let running = process
                .is_running()
                .map_err(|error| HelperError::new(ErrorCode::EngineFailed, error.to_string()))?;
            if !running {
                return Err(HelperError::new(
                    ErrorCode::EngineFailed,
                    "engine exited during startup readiness",
                ));
            }
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
        thread::sleep(TUNNEL_READY_POLL_INTERVAL);
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
    let result = resolve_quiet(server, port);
    if let Err(error) = &result {
        tracing::warn!(%server, %error, "failed to resolve the VPN endpoint");
    }
    result
}

fn resolve_quiet(server: &str, port: u16) -> Result<Vec<IpAddr>, HelperError> {
    let addresses = (server, port)
        .to_socket_addrs()
        .map_err(|error| {
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

#[cfg(test)]
mod hysteria2_endpoint_tests {
    use super::*;
    use rosetun_config::{Hysteria2Params, NodeId, Outbound, StreamSettings, TlsMode, TlsParams};

    #[test]
    fn resolved_hysteria2_endpoint_keeps_the_server_name_for_tls() {
        let node = Node {
            id: NodeId::new("test"),
            name: "Test".into(),
            server: "example.com".into(),
            port: 443,
            outbound: Outbound::Hysteria2(Hysteria2Params {
                password: "test-secret".into(),
                obfs_password: None,
                port_ranges: Vec::new(),
                up_mbps: None,
                down_mbps: None,
            }),
            stream: StreamSettings {
                tls: TlsMode::Tls(TlsParams::default()),
                ..Default::default()
            },
            raw: None,
        };
        let prepared = node_with_endpoint(&node, "192.0.2.1".parse().unwrap());
        assert_eq!(prepared.server, "192.0.2.1");
        let TlsMode::Tls(tls) = prepared.stream.tls else {
            panic!("expected TLS");
        };
        assert_eq!(tls.sni.as_deref(), Some("example.com"));
    }
}
