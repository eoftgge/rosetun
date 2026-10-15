mod apply;
mod dns;
mod path;
mod probe;
#[cfg(test)]
mod tests;
mod watchdog;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use rosetun_config::{
    ConnectionState, ListRef, Node, Rule, RuleMatcher, RuleSet, Settings, Status, Traffic,
    list_tag, uses_xray,
};
use rosetun_engine::{
    ControlEndpoint, EngineBackend, EngineProcess, EngineRegistry, RenderRequest, RenderedConfig,
    SocksProxy, TrafficProbe, TrafficTotals, UrlTestTarget, errors::EngineError, url_test_any,
};
use rosetun_engine_xray::{SocksEndpoint, XrayHelper};
use rosetun_ipc::transport::PeerIdentity;
use rosetun_ipc::{ConnectRequest, ErrorCode, HelperError, ListFormat, MAX_TEMPORARY_RULES};
use rosetun_routing::{
    ProtectionScope, RoutingBackend, RoutingGuard, RoutingPlan, TunnelInterface,
};

use crate::list_store::{ListChunk, ListStore, valid_hash, valid_tag};
use crate::log_gate::VerboseGate;
use watchdog::{DnsWatchdog, WatchdogTiming};

const TUNNEL_READY_TIMEOUT: Duration = Duration::from_secs(15);
const TUNNEL_READY_POLL_INTERVAL: Duration = Duration::from_millis(100);
const TUNNEL_DNS_TIMEOUT: Duration = Duration::from_secs(60);
const TUNNEL_DNS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);
const PATH_LOOKUP_TIMEOUT: Duration = Duration::from_secs(1);
const SERVER_CHECK_INTERVAL: Duration = Duration::from_secs(4);
const SERVER_CHECK_GRACE: Duration = Duration::from_secs(30);
const SERVER_CHECK_TIMEOUT: Duration = Duration::from_secs(4);
const SERVER_CHECK_FAILURES: u64 = 3;
const WATCHDOG_TIMING: WatchdogTiming = WatchdogTiming {
    interval: Duration::from_secs(30),
    retry: Duration::from_secs(5),
    dns_timeout: Duration::from_secs(5),
    path_timeout: Duration::from_secs(5),
    failures: 3,
    path_server: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 80),
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

#[cfg(test)]
fn test_physical_interface(_: &str) -> Option<String> {
    Some("Ethernet".to_owned())
}

pub(crate) struct Caller {
    sid: Vec<u8>,
    administrator: bool,
}

#[cfg(test)]
impl Caller {
    pub(crate) fn fake(sid: &[u8], administrator: bool) -> Self {
        Self {
            sid: sid.to_vec(),
            administrator,
        }
    }
}

impl From<PeerIdentity> for Caller {
    fn from(peer: PeerIdentity) -> Self {
        Self {
            sid: peer.user_sid().to_vec(),
            administrator: peer.is_administrator(),
        }
    }
}

pub struct Helper {
    status: Arc<Mutex<Status>>,
    session: Mutex<Session>,
    owner: Arc<Mutex<Option<Vec<u8>>>>,
    last_owner: Mutex<Option<Vec<u8>>>,
    engines: Arc<EngineRegistry>,
    xray: Option<Arc<dyn XrayRunner>>,
    physical_interface: fn(&str) -> Option<String>,
    probe: Mutex<()>,
    lists: Option<Arc<Mutex<ListStore>>>,
    shutting_down: AtomicBool,
    resumed: AtomicBool,
    cancelled: Arc<AtomicBool>,
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

trait XrayRunner: Send + Sync + std::fmt::Debug {
    fn binary_path(&self) -> Result<PathBuf, EngineError>;
    fn locate_binary(&self) -> Result<PathBuf, EngineError>;
    fn probe_config_path(&self) -> PathBuf;
    fn spawn(
        &self,
        binary: &Path,
        config: &RenderedConfig,
        endpoints: &[&SocksEndpoint],
        verbose_until_unix: Arc<AtomicU64>,
    ) -> Result<Box<dyn EngineProcess>, EngineError>;
}

impl XrayRunner for XrayHelper {
    fn binary_path(&self) -> Result<PathBuf, EngineError> {
        XrayHelper::binary_path(self)
    }

    fn locate_binary(&self) -> Result<PathBuf, EngineError> {
        XrayHelper::locate_binary(self)
    }

    fn probe_config_path(&self) -> PathBuf {
        XrayHelper::probe_config_path(self)
    }

    fn spawn(
        &self,
        binary: &Path,
        config: &RenderedConfig,
        endpoints: &[&SocksEndpoint],
        verbose_until_unix: Arc<AtomicU64>,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        XrayHelper::spawn(self, binary, config, endpoints, verbose_until_unix)
    }
}

/// Routing protection that outlives one engine process.
struct Guard {
    routing: Arc<Mutex<RoutingGuard>>,
    scope: ProtectionScope,
}

struct Session {
    engines: Arc<EngineRegistry>,
    routing: Box<dyn RoutingBackend>,
    gate: VerboseGate,
    status: Arc<Mutex<Status>>,
    process: Option<Box<dyn EngineProcess>>,
    xray_process: Option<Box<dyn EngineProcess>>,
    xray: Option<Arc<dyn XrayRunner>>,
    physical_interface: fn(&str) -> Option<String>,
    control: Option<ControlEndpoint>,
    monitor: Option<TrafficMonitor>,
    watchdog: Option<DnsWatchdog>,
    tunnel_dns: Option<SocketAddr>,
    path_addresses: Arc<Mutex<Vec<Ipv4Addr>>>,
    guard: Option<Guard>,
    last_endpoint: Option<SuccessfulEndpoint>,
    request: Option<ConnectRequest>,
    owner: Arc<Mutex<Option<Vec<u8>>>>,
    reconnect: Option<Reconnect>,
    missing_route_ticks: u8,
    stopping: bool,
    dns_timeout: Duration,
    dns_attempt_timeout: Duration,
    server_check_interval: Duration,
    server_check_grace: Duration,
    watchdog_timing: WatchdogTiming,
    adapter_lookup: fn(&str) -> std::io::Result<bool>,
    cancelled: Arc<AtomicBool>,
    lists: Option<Arc<Mutex<ListStore>>>,
    list_run_dir: Option<PathBuf>,
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
        let cancelled = Arc::new(AtomicBool::new(false));
        let owner = Arc::new(Mutex::new(None));
        Self {
            status: Arc::clone(&status),
            owner: Arc::clone(&owner),
            last_owner: Mutex::new(None),
            engines: Arc::clone(&engines),
            xray: None,
            #[cfg(not(test))]
            physical_interface: rosetun_routing::physical_default_interface,
            #[cfg(test)]
            physical_interface: test_physical_interface,
            probe: Mutex::new(()),
            lists: None,
            shutting_down: AtomicBool::new(false),
            resumed: AtomicBool::new(false),
            cancelled: Arc::clone(&cancelled),
            session: Mutex::new(Session {
                engines,
                routing,
                gate,
                status,
                process: None,
                xray_process: None,
                xray: None,
                #[cfg(not(test))]
                physical_interface: rosetun_routing::physical_default_interface,
                #[cfg(test)]
                physical_interface: test_physical_interface,
                control: None,
                monitor: None,
                watchdog: None,
                tunnel_dns: None,
                path_addresses: Arc::new(Mutex::new(Vec::new())),
                guard: None,
                last_endpoint: None,
                request: None,
                owner,
                reconnect: None,
                missing_route_ticks: 0,
                stopping: false,
                dns_timeout: TUNNEL_DNS_TIMEOUT,
                dns_attempt_timeout: TUNNEL_DNS_ATTEMPT_TIMEOUT,
                server_check_interval: SERVER_CHECK_INTERVAL,
                server_check_grace: SERVER_CHECK_GRACE,
                watchdog_timing: WATCHDOG_TIMING,
                cancelled,
                lists: None,
                list_run_dir: None,
                #[cfg(not(test))]
                adapter_lookup: rosetun_routing::tunnel_adapter_present,
                #[cfg(test)]
                adapter_lookup: |_| Ok(false),
            }),
        }
    }

    pub(crate) fn with_xray(self, xray: XrayHelper) -> Self {
        self.with_xray_runner(Arc::new(xray))
    }

    fn with_xray_runner(mut self, xray: Arc<dyn XrayRunner>) -> Self {
        self.session
            .get_mut()
            .expect("new session is not poisoned")
            .xray = Some(Arc::clone(&xray));
        self.xray = Some(xray);
        self
    }

    #[cfg(test)]
    fn with_test_physical_interface(mut self, lookup: fn(&str) -> Option<String>) -> Self {
        self.physical_interface = lookup;
        self.session
            .get_mut()
            .expect("new session is not poisoned")
            .physical_interface = lookup;
        self
    }

    pub(crate) fn with_list_store(mut self, store: ListStore, run_dir: PathBuf) -> Self {
        let lists = Arc::new(Mutex::new(store));
        self.session
            .get_mut()
            .expect("new session is not poisoned")
            .lists = Some(Arc::clone(&lists));
        self.session
            .get_mut()
            .expect("new session is not poisoned")
            .list_run_dir = Some(run_dir);
        self.lists = Some(lists);
        self
    }

    fn list_store(&self) -> Result<MutexGuard<'_, ListStore>, HelperError> {
        self.lists
            .as_ref()
            .ok_or_else(|| HelperError::new(ErrorCode::Internal, "list storage is unavailable"))?
            .lock()
            .map_err(|_| HelperError::new(ErrorCode::Internal, "list storage is unavailable"))
    }

    pub fn list_status(&self, hashes: &[String]) -> Result<Vec<String>, HelperError> {
        self.list_store()?.status(hashes, Instant::now())
    }

    pub fn put_list_chunk(
        &self,
        owner: u64,
        hash: &str,
        format: ListFormat,
        total_size: u64,
        offset: u64,
        data: &str,
    ) -> Result<(), HelperError> {
        self.list_store()?.put_chunk(
            owner,
            ListChunk {
                hash,
                format,
                total_size,
                offset,
                encoded: data,
            },
            Instant::now(),
        )
    }

    pub fn abort_list_uploads(&self, owner: u64) {
        if let Ok(mut store) = self.list_store() {
            store.abort_owner(owner);
        }
    }

    fn expire_list_uploads(&self, now: Instant) {
        if let Ok(mut store) = self.list_store() {
            store.expire(now);
        }
    }

    pub fn status(&self) -> Status {
        self.with_status(|status| status.clone())
    }

    pub(crate) fn temporary_rules_as(&self, caller: &Caller) -> Result<Vec<Rule>, HelperError> {
        self.check_owner(caller)?;
        let session = self.session()?;
        self.check_owner(caller)?;
        Ok(session
            .request
            .as_ref()
            .map(|request| request.temporary_rules.clone())
            .unwrap_or_default())
    }

    #[cfg(test)]
    pub fn temporary_rules(&self) -> Result<Vec<Rule>, HelperError> {
        self.temporary_rules_as(&test_caller())
    }

    pub(crate) fn diagnostic_log_as(&self, caller: &Caller) -> Result<String, HelperError> {
        self.check_diagnostic_owner(caller)?;
        #[cfg(windows)]
        let text = {
            let dir = crate::data_dir::data_dir().map_err(report_log_error)?;
            crate::log_file::report_tail(&dir.join("logs")).map_err(report_log_error)?
        };
        #[cfg(not(windows))]
        let text = String::new();
        self.check_diagnostic_owner(caller)?;
        let printable: String = text
            .chars()
            .map(|ch| if ch.is_control() && !matches!(ch, '\n' | '\r' | '\t') { ' ' } else { ch })
            .collect();
        Ok(rosetun_config::redact_report_text(&printable))
    }

    fn check_diagnostic_owner(&self, caller: &Caller) -> Result<(), HelperError> {
        let owner = self.owner.lock().map_err(|_| access_denied())?;
        let last_owner = self.last_owner.lock().map_err(|_| access_denied())?;
        let expected = owner.as_ref().or(last_owner.as_ref());
        if expected != Some(&caller.sid) {
            return Err(HelperError::new(
                ErrorCode::AccessDenied,
                "only the account that started the most recent session can read the diagnostic log",
            ));
        }
        Ok(())
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
            session.missing_route_ticks = 0;
            self.resumed.store(false, Ordering::Release);
            return;
        };

        let network_available = (session.physical_interface)(
            &session
                .request
                .as_ref()
                .expect("active request")
                .settings
                .tun
                .name,
        )
        .is_some();
        if network_available {
            session.missing_route_ticks = 0;
        } else {
            session.missing_route_ticks = (session.missing_route_ticks + 1).min(2);
            if session.missing_route_ticks < 2 {
                return;
            }
        }
        if !network_available && !auto_reconnect {
            let protected = session.keeps_protection();
            if protected {
                if let Err(error) = session.stop_engine() {
                    tracing::error!(%error, "failed to stop engine after network loss");
                }
            } else {
                session.teardown();
            }
            self.with_status(|status| {
                let reason = "physical network is unavailable".to_owned();
                let failure_kind = Some(rosetun_config::FailureKind::NoNetwork);
                status.state = if protected {
                    ConnectionState::FailedProtected {
                        reason,
                        failure_kind,
                    }
                } else {
                    ConnectionState::Failed {
                        reason,
                        failure_kind,
                    }
                };
                status.reconnect_failure_kind = None;
                status.since_unix = None;
                status.connect_stage = None;
                status.stage_since_unix = None;
            });
            session.request = None;
            session.pin_lists(&[]);
            return;
        }
        if !network_available {
            if session.reconnect.is_none() {
                self.begin_attempt(ConnectionState::Reconnecting);
                if let Err(error) = session.stop_engine() {
                    tracing::error!(%error, "failed to stop engine after network loss");
                }
                session.reconnect = Some(Reconnect {
                    failures: 0,
                    next_at: now,
                    cause: "network lost",
                });
            }
            self.with_status(|status| {
                status.reconnect_failure_kind = Some(rosetun_config::FailureKind::NoNetwork);
                status.connect_stage = None;
                status.stage_since_unix = None;
            });
            return;
        }
        if let Some(reconnect) = &mut session.reconnect {
            if self
                .with_status(|status| status.reconnect_failure_kind.take())
                .is_some()
            {
                reconnect.next_at = now;
            }
            if now < reconnect.next_at {
                return;
            }
        } else {
            let xray_exited = if session
                .request
                .as_ref()
                .is_some_and(|request| uses_xray(&request.node, request.settings.xray))
            {
                match session.xray_process.as_mut() {
                    Some(process) => !matches!(process.is_running(), Ok(true)),
                    None => true,
                }
            } else {
                false
            };
            let exited = if xray_exited {
                Some("Xray stopped".to_owned())
            } else {
                match session.process.as_mut() {
                    Some(process) => match process.is_running() {
                        Ok(true) => None,
                        Ok(false) => Some("the engine process exited".to_owned()),
                        Err(error) => Some(error.to_string()),
                    },
                    None => Some("the engine process is missing".to_owned()),
                }
            };
            if let Some(reason) = exited {
                if xray_exited {
                    self.with_status(|status| status.xray_stopped = true);
                }
                let protected = session.keeps_protection();
                if !auto_reconnect {
                    tracing::warn!(%reason, protected, "the engine terminated itself");
                    if !protected {
                        session.teardown();
                    } else if xray_exited && let Err(error) = session.stop_engine() {
                        tracing::error!(%error, "failed to stop the engine after Xray stopped");
                    }
                    self.with_status(|status| {
                        let failure_kind =
                            xray_exited.then_some(rosetun_config::FailureKind::XrayStopped);
                        status.state = if protected {
                            ConnectionState::FailedProtected {
                                reason,
                                failure_kind,
                            }
                        } else {
                            ConnectionState::Failed {
                                reason,
                                failure_kind,
                            }
                        };
                        status.since_unix = None;
                        status.connect_stage = None;
                        status.stage_since_unix = None;
                    });
                    session.request = None;
                    session.pin_lists(&[]);
                    return;
                }
                tracing::warn!(%reason, protected, "the engine terminated; reconnecting");
                self.begin_attempt(ConnectionState::Reconnecting);
                session.reconnect = Some(Reconnect {
                    failures: 0,
                    next_at: now,
                    cause: if xray_exited {
                        "xray stopped"
                    } else {
                        "engine exited"
                    },
                });
            } else if self.resumed.swap(false, Ordering::AcqRel) {
                if !auto_reconnect {
                    return;
                }
                tracing::info!("resumed from sleep; reconnecting tunnel");
                self.begin_attempt(ConnectionState::Reconnecting);
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
                self.begin_attempt(ConnectionState::Reconnecting);
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
        match session
            .start(
                &request.node,
                &request.effective_rule_set(),
                &request.lists,
                &request.settings,
                mode,
                None,
            )
            .and_then(|()| {
                self.publish_terminal(|status| {
                    status.state = ConnectionState::Connected;
                    status.reconnect_failure_kind = None;
                    status.xray = uses_xray(&request.node, request.settings.xray);
                    status.xray_use = Some(request.settings.xray);
                    status.xray_stopped = false;
                    status.since_unix.get_or_insert_with(now_unix);
                })
            }) {
            Ok(()) => {
                session.start_monitor(request.settings.engine);
                session.start_watchdog();
                tracing::info!(cause = reconnect.cause, attempt, "tunnel reconnected");
            }
            Err(error) => {
                if error.code == ErrorCode::Cancelled {
                    self.finish_cancelled(&mut session);
                    return;
                }
                self.with_status(|status| {
                    status.connect_stage = None;
                    status.stage_since_unix = None;
                });
                if error.code == ErrorCode::NoNetwork {
                    if let Err(cleanup_error) = session.stop_engine() {
                        tracing::error!(%cleanup_error, "failed to stop engine after network loss");
                    }
                    session.reconnect = Some(Reconnect {
                        failures: reconnect.failures,
                        next_at: Instant::now(),
                        cause: reconnect.cause,
                    });
                    self.with_status(|status| {
                        status.reconnect_failure_kind =
                            Some(rosetun_config::FailureKind::NoNetwork);
                    });
                    return;
                }
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
                            ConnectionState::FailedProtected {
                                reason,
                                failure_kind: if reconnect.cause == "xray stopped" {
                                    Some(rosetun_config::FailureKind::XrayStopped)
                                } else {
                                    failure_kind(error.code)
                                },
                            }
                        } else {
                            ConnectionState::Failed {
                                reason,
                                failure_kind: if reconnect.cause == "xray stopped" {
                                    Some(rosetun_config::FailureKind::XrayStopped)
                                } else {
                                    failure_kind(error.code)
                                },
                            }
                        };
                        status.since_unix = None;
                        status.connect_stage = None;
                        status.stage_since_unix = None;
                    });
                    session.request = None;
                    session.pin_lists(&[]);
                }
                if self.cancelled.load(Ordering::Acquire) {
                    self.finish_cancelled(&mut session);
                }
            }
        }
    }

    pub(crate) fn connect_as(
        &self,
        caller: &Caller,
        request: &ConnectRequest,
    ) -> Result<(), HelperError> {
        self.check_owner(caller)?;
        let mut session = self.session()?;
        self.check_owner(caller)?;
        validate_request(request)?;
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
        session.reserve_lists(request, None)?;

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

        let previous_owner = self.begin_connect(caller)?;
        session.request = None;
        session.reconnect = None;
        session.missing_route_ticks = 0;

        match session
            .start(
                &request.node,
                &request.effective_rule_set(),
                &request.lists,
                &request.settings,
                mode,
                None,
            )
            .and_then(|()| {
                self.publish_terminal(|status| {
                    status.state = ConnectionState::Connected;
                    status.node = Some(request.node.id.clone());
                    status.engine = Some(request.settings.engine);
                    status.xray = uses_xray(&request.node, request.settings.xray);
                    status.xray_use = Some(request.settings.xray);
                    status.xray_stopped = false;
                    status.since_unix = Some(now_unix());
                })
            }) {
            Ok(()) => {
                session.request = Some(request.clone());
                self.resumed.store(false, Ordering::Release);
                session.start_monitor(request.settings.engine);
                session.start_watchdog();
                if caller.administrator
                    && previous_owner
                        .as_ref()
                        .is_some_and(|previous| previous != &caller.sid)
                {
                    tracing::info!("session owner changed by an administrator");
                }
                Ok(())
            }
            Err(error) => {
                if error.code == ErrorCode::Cancelled {
                    self.finish_cancelled(&mut session);
                    return Err(error);
                }
                let protected = session.keeps_protection()
                    && (mode == StartMode::ProtectedReconnect
                        || error.code == ErrorCode::XrayStartFailed);
                if protected {
                    if let Err(cleanup_error) = session.stop_engine() {
                        tracing::error!(
                            %cleanup_error,
                            "failed to stop engine after protected reconnect failure"
                        );
                    }
                    session.pin_lists(&[]);
                } else {
                    session.teardown();
                }

                let reason = error.message.clone();
                if let Err(cancelled) = self.publish_terminal(|status| {
                    status.state = if protected {
                        ConnectionState::FailedProtected {
                            reason,
                            failure_kind: failure_kind(error.code),
                        }
                    } else {
                        ConnectionState::Failed {
                            reason,
                            failure_kind: failure_kind(error.code),
                        }
                    };
                    status.since_unix = None;
                    status.connect_stage = None;
                    status.stage_since_unix = None;
                    if protected {
                        *self
                            .owner
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner()) = previous_owner.clone();
                        self.owner.clear_poison();
                    }
                }) {
                    self.finish_cancelled(&mut session);
                    return Err(cancelled);
                }
                Err(error)
            }
        }
    }

    #[cfg(test)]
    pub fn connect(&self, request: &ConnectRequest) -> Result<(), HelperError> {
        self.connect_as(&test_caller(), request)
    }

    pub(crate) fn disconnect_as(&self, caller: &Caller) -> Result<(), HelperError> {
        let (mut session, poisoned) = match self.session.try_lock() {
            Ok(session) => (session, false),
            Err(TryLockError::Poisoned(error)) => (error.into_inner(), true),
            Err(TryLockError::WouldBlock) => {
                return self.with_status(|status| {
                    let owner = self.owner.lock().map_err(|_| access_denied())?;
                    if owner
                        .as_ref()
                        .is_some_and(|sid| sid != &caller.sid && !caller.administrator)
                        || (owner.is_none() && status.state.is_transitional())
                    {
                        return Err(access_denied());
                    }
                    if status.state.is_transitional() {
                        self.cancelled.store(true, Ordering::Release);
                        Ok(())
                    } else {
                        Err(HelperError::new(
                            ErrorCode::Busy,
                            "another tunnel operation is in progress",
                        ))
                    }
                });
            }
        };
        self.check_owner(caller)?;
        if session.stopping {
            return Err(HelperError::new(
                ErrorCode::InvalidState,
                "helper is shutting down",
            ));
        }
        session.request = None;
        session.reconnect = None;
        session.teardown();
        self.with_status(|status| *status = Status::default());
        if poisoned {
            self.session.clear_poison();
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn disconnect(&self) -> Result<(), HelperError> {
        self.disconnect_as(&test_caller())
    }

    pub fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::Release);
        self.cancelled.store(true, Ordering::Release);
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

    fn check_owner(&self, caller: &Caller) -> Result<(), HelperError> {
        let owner = self.owner.lock().map_err(|_| access_denied())?;
        if owner
            .as_ref()
            .is_some_and(|sid| sid != &caller.sid && !caller.administrator)
        {
            return Err(access_denied());
        }
        Ok(())
    }

    fn begin_connect(&self, caller: &Caller) -> Result<Option<Vec<u8>>, HelperError> {
        self.with_status(|status| {
            let mut owner = self.owner.lock().map_err(|_| access_denied())?;
            let previous = owner.replace(caller.sid.clone());
            *self.last_owner.lock().map_err(|_| access_denied())? = Some(caller.sid.clone());
            self.cancelled.store(false, Ordering::Release);
            if self.shutting_down.load(Ordering::Acquire) {
                self.cancelled.store(true, Ordering::Release);
            }
            status.state = ConnectionState::Connecting;
            status.reconnect_failure_kind = None;
            status.connect_stage = None;
            status.stage_since_unix = None;
            Ok(previous)
        })
    }

    fn begin_attempt(&self, state: ConnectionState) {
        self.with_status(|status| {
            self.cancelled.store(false, Ordering::Release);
            if self.shutting_down.load(Ordering::Acquire) {
                self.cancelled.store(true, Ordering::Release);
            }
            status.state = state;
            status.reconnect_failure_kind = None;
            status.connect_stage = None;
            status.stage_since_unix = None;
        });
    }

    fn publish_terminal(&self, publish: impl FnOnce(&mut Status)) -> Result<(), HelperError> {
        self.with_status(|status| {
            check_cancelled(&self.cancelled)?;
            publish(status);
            status.connect_stage = None;
            status.stage_since_unix = None;
            Ok(())
        })
    }

    fn finish_cancelled(&self, session: &mut Session) {
        session.request = None;
        session.reconnect = None;
        session.teardown();
        self.with_status(|status| *status = Status::default());
    }
}

#[cfg(test)]
fn test_caller() -> Caller {
    Caller::fake(b"test-session-owner", false)
}

pub(crate) fn access_denied() -> HelperError {
    HelperError::new(
        ErrorCode::AccessDenied,
        "the tunnel belongs to another Windows account; only that account or an administrator can control it",
    )
}

#[cfg(windows)]
fn report_log_error(_: std::io::Error) -> HelperError {
    HelperError::new(ErrorCode::Internal, "could not read the helper diagnostic log")
}

fn validate_tun_name(name: &str) -> Result<(), HelperError> {
    if !(1..=64).contains(&name.len())
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'_' | b'.' | b'-'))
    {
        return Err(HelperError::new(
            ErrorCode::InvalidState,
            "TUN name must contain 1 to 64 characters from [A-Za-z0-9 _.-]",
        ));
    }
    Ok(())
}

fn validate_request(request: &ConnectRequest) -> Result<(), HelperError> {
    validate_tun_name(&request.settings.tun.name)?;
    if request
        .rule_set
        .rules
        .iter()
        .any(|rule| matches!(rule.matcher, RuleMatcher::Template(_)))
    {
        return Err(HelperError::new(
            ErrorCode::UnsupportedRules,
            "rule set contains a template; expand templates before sending the request",
        ));
    }
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
    if request.lists.len() > MAX_TEMPORARY_RULES {
        return Err(HelperError::new(
            ErrorCode::InvalidState,
            "too many list references",
        ));
    }
    let rules = request.effective_rule_set();
    if request.settings.engine != rosetun_config::EngineKind::SingBox
        && rules
            .enabled()
            .any(|rule| matches!(rule.matcher, RuleMatcher::List { .. }))
    {
        return Err(HelperError::new(
            ErrorCode::UnsupportedRules,
            "engine does not support list rules",
        ));
    }
    let expected: std::collections::HashSet<_> = rules
        .enabled()
        .filter_map(|rule| match &rule.matcher {
            RuleMatcher::List { list, category } => Some(list_tag(list, category.as_deref())),
            _ => None,
        })
        .collect();
    let mut tags = std::collections::HashSet::new();
    for reference in &request.lists {
        if !valid_tag(&reference.tag) || !valid_hash(&reference.sha256) {
            return Err(HelperError::new(
                ErrorCode::InvalidState,
                "invalid list reference",
            ));
        }
        if !expected.contains(&reference.tag) || !tags.insert(&reference.tag) {
            return Err(HelperError::new(
                ErrorCode::InvalidState,
                "unexpected or duplicate list reference",
            ));
        }
    }
    if tags.len() != expected.len() {
        return Err(HelperError::new(
            ErrorCode::ListMissing,
            "a list rule does not have exactly one matching reference",
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

pub fn spawn_list_reaper(helper: Arc<Helper>) -> std::io::Result<()> {
    thread::Builder::new()
        .name("list-upload-reaper".to_owned())
        .spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(5));
                helper.expire_list_uploads(Instant::now());
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
    fn stage(&self, stage: rosetun_config::ConnectStage) -> Result<(), HelperError> {
        let mut status = self
            .status
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        check_cancelled(&self.cancelled)?;
        status.connect_stage = Some(stage);
        status.stage_since_unix = Some(now_unix());
        Ok(())
    }

    /// Only the kill switch keeps blocking after a failure. The DNS lock goes
    /// with the session.
    fn keeps_protection(&self) -> bool {
        self.guard
            .as_ref()
            .is_some_and(|guard| guard.scope == ProtectionScope::AllTraffic)
    }

    fn reserve_lists(
        &self,
        request: &ConnectRequest,
        previous: Option<&ConnectRequest>,
    ) -> Result<(), HelperError> {
        let Some(lists) = &self.lists else {
            return if request.lists.is_empty() {
                Ok(())
            } else {
                Err(HelperError::new(
                    ErrorCode::ListMissing,
                    "list storage is unavailable",
                ))
            };
        };
        let mut store = lists
            .lock()
            .map_err(|_| HelperError::new(ErrorCode::Internal, "list storage is unavailable"))?;
        for reference in &request.lists {
            store.verified_path(reference)?;
        }
        let mut pinned = request.lists.clone();
        if let Some(previous) = previous {
            pinned.extend(previous.lists.iter().cloned());
        }
        store.pin(&pinned);
        Ok(())
    }

    fn pin_lists(&self, references: &[ListRef]) {
        if let Some(lists) = &self.lists
            && let Ok(mut store) = lists.lock()
        {
            store.pin(references);
        }
    }

    fn clear_staged_lists(&self) -> Result<(), HelperError> {
        let Some(directory) = &self.list_run_dir else {
            return Ok(());
        };
        if !directory.exists() {
            return Ok(());
        }
        for entry in std::fs::read_dir(directory)
            .map_err(|_| HelperError::new(ErrorCode::Internal, "cannot inspect staged lists"))?
        {
            let entry = entry.map_err(|_| {
                HelperError::new(ErrorCode::Internal, "cannot inspect staged lists")
            })?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let file_name = name
                .strip_prefix('.')
                .and_then(|name| name.strip_suffix(".part"))
                .unwrap_or(&name);
            let Some((tag, extension)) = file_name.rsplit_once('.') else {
                continue;
            };
            if tag.starts_with("list-") && valid_tag(tag) && matches!(extension, "srs" | "json") {
                std::fs::remove_file(entry.path()).map_err(|_| {
                    HelperError::new(ErrorCode::Internal, "cannot remove a staged list")
                })?;
            }
        }
        Ok(())
    }

    fn stage_lists(&self, references: &[ListRef]) -> Result<(), HelperError> {
        self.clear_staged_lists()?;
        if references.is_empty() {
            return Ok(());
        }
        let directory = self.list_run_dir.as_ref().ok_or_else(|| {
            HelperError::new(ErrorCode::Internal, "list run directory is unavailable")
        })?;
        std::fs::create_dir_all(directory).map_err(|_| {
            HelperError::new(ErrorCode::Internal, "cannot create the list run directory")
        })?;
        let lists = self.lists.as_ref().ok_or_else(|| {
            HelperError::new(ErrorCode::ListMissing, "list storage is unavailable")
        })?;
        for reference in references {
            let source = lists
                .lock()
                .map_err(|_| HelperError::new(ErrorCode::Internal, "list storage is unavailable"))?
                .verified_path_for_staging(reference)?;
            let name = format!("{}.{}", reference.tag, reference.format.extension());
            let destination = directory.join(&name);
            let temporary = directory.join(format!(".{name}.part"));
            if let Err(error) = std::fs::copy(&source, &temporary) {
                let _ = std::fs::remove_file(&temporary);
                return Err(HelperError::new(
                    if error.kind() == std::io::ErrorKind::NotFound {
                        ErrorCode::ListMissing
                    } else {
                        ErrorCode::Internal
                    },
                    "cannot stage a required list",
                ));
            }
            if std::fs::rename(&temporary, &destination).is_err() {
                let _ = std::fs::remove_file(&temporary);
                return Err(HelperError::new(
                    ErrorCode::Internal,
                    "cannot publish a staged list",
                ));
            }
        }
        Ok(())
    }

    fn start(
        &mut self,
        node: &Node,
        rules: &RuleSet,
        lists: &[ListRef],
        settings: &Settings,
        mode: StartMode,
        endpoint: Option<IpAddr>,
    ) -> Result<(), HelperError> {
        // Dispose of the old process before borrowing the backend or spawning another.
        // A stop failure retains its handle and prevents a second engine from starting.
        self.stop_engine()?;
        if (self.physical_interface)(&settings.tun.name).is_none() {
            return Err(HelperError::new(
                ErrorCode::NoNetwork,
                "physical network is unavailable",
            ));
        }

        self.stage(rosetun_config::ConnectStage::WaitingForAdapter)?;
        wait_for_previous_adapter_cancellable(
            &settings.tun.name,
            Duration::from_secs(20),
            Duration::from_millis(250),
            self.adapter_lookup,
            &self.cancelled,
        )?;
        self.stage(rosetun_config::ConnectStage::StartingEngine)?;

        if mode == StartMode::Fresh
            && let Some(guard) = self.guard.take()
            && let Err(error) = guard
                .routing
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .revert_in_place()
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
        let chain = settings.engine == rosetun_config::EngineKind::SingBox
            && uses_xray(node, settings.xray);
        let socks = if chain {
            Some(SocksEndpoint::local().map_err(|_| {
                HelperError::new(
                    ErrorCode::XrayStartFailed,
                    "Xray SOCKS endpoint is unavailable",
                )
            })?)
        } else {
            None
        };
        let socks_proxy = socks.as_ref().map(|socks| SocksProxy {
            address: socks.address(),
            username: socks.username(),
            password: socks.password(),
        });
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
            &RenderRequest {
                node: resolved_node.as_ref().unwrap_or(node),
                socks: socks_proxy,
                rules,
                lists,
                settings,
                control: control.as_ref(),
                verbose_log: verbose_until.is_some(),
            },
        )?;

        self.stage_lists(lists)?;

        let binary = backend
            .locate_binary()
            .map_err(|error| HelperError::new(ErrorCode::EngineFailed, error.to_string()))?;

        tracing::debug!(
            engine = %backend.kind().as_str(),
            binary = %binary.display(),
            "engine binary located"
        );
        let xray_path = if chain {
            self.xray.as_ref().and_then(|xray| xray.binary_path().ok())
        } else {
            None
        };
        let xray_path = xray_path.and_then(|path| std::fs::canonicalize(path).ok());
        let mut binaries = vec![binary.as_path()];
        if let Some(path) = xray_path.as_ref() {
            binaries.push(path.as_path());
        }

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
                        .and_then(|()| self.routing.begin_protection(&plan, &binaries));
                    match result {
                        Ok(routing) => {
                            self.guard = Some(Guard {
                                routing: Arc::new(Mutex::new(routing)),
                                scope,
                            });
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
                        .lock()
                        .map_err(|_| {
                            HelperError::new(ErrorCode::RoutingFailed, "routing guard is poisoned")
                        })?
                        .prepare_reconnect(&plan, &binaries)
                        .map_err(|error| {
                            HelperError::new(ErrorCode::RoutingFailed, error.to_string())
                        })?;
                    guard.scope = scope;
                }
            }
        }
        // Without a guard there is no filter to authorize on the tunnel.
        let tunnel = tunnel.filter(|_| self.guard.is_some());

        if let Some(socks) = socks.as_ref() {
            let xray = self.xray.as_ref().ok_or_else(|| {
                HelperError::new(ErrorCode::XrayStartFailed, "Xray helper is unavailable")
            })?;
            let xray_binary = xray
                .locate_binary()
                .map_err(|error| HelperError::new(ErrorCode::XrayStartFailed, error.to_string()))?;
            let interface = (self.physical_interface)(&settings.tun.name).ok_or_else(|| {
                HelperError::new(
                    ErrorCode::XrayStartFailed,
                    "physical interface is unavailable for Xray",
                )
            })?;
            let xray_config = rosetun_engine_xray::render(
                resolved_node.as_ref().unwrap_or(node),
                socks,
                &interface,
                verbose_until.is_some(),
                settings.log_level,
            )
            .map_err(|error| HelperError::new(ErrorCode::XrayStartFailed, error.to_string()))?;
            tracing::info!("engine chain: sing-box + xray");
            check_cancelled(&self.cancelled)?;
            let spawned_at = Instant::now();
            self.xray_process = Some(
                xray.spawn(&xray_binary, &xray_config, &[socks], self.gate.deadline())
                    .map_err(|error| {
                        HelperError::new(ErrorCode::XrayStartFailed, error.to_string())
                    })?,
            );
            wait_for_engine_ready_from(
                self.xray_process
                    .as_mut()
                    .expect("Xray process stored before readiness")
                    .as_mut(),
                spawned_at,
                &self.cancelled,
            )
            .map_err(|error| {
                if error.code == ErrorCode::Cancelled {
                    error
                } else {
                    HelperError::new(ErrorCode::XrayStartFailed, error.message)
                }
            })?;
        } else {
            tracing::info!("engine chain: sing-box");
        }

        tracing::info!(engine = %backend.kind().as_str(), "spawning tunnel engine");
        let spawned_at = Instant::now();
        check_cancelled(&self.cancelled)?;
        self.process = Some(
            backend
                .spawn_with_log_gate(&binary, &config, self.gate.deadline())
                .map_err(|error| HelperError::new(ErrorCode::EngineFailed, error.to_string()))?,
        );
        self.control = control;

        wait_for_engine_ready_from(
            self.process
                .as_mut()
                .expect("engine process was stored before readiness")
                .as_mut(),
            spawned_at,
            &self.cancelled,
        )?;
        let ready_at = Instant::now();
        let grace_deadline = server_check_grace_deadline(
            self.process
                .as_ref()
                .expect("engine process was stored before readiness")
                .startup_hints(),
            spawned_at,
            ready_at,
            self.server_check_grace,
        );
        tracing::info!("engine startup readiness confirmed");
        self.ensure_xray_running(ErrorCode::XrayStartFailed)?;

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
                        && let Err(error) = guard
                            .routing
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner())
                            .revert_in_place()
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
            if grace_deadline.is_some() {
                tracing::info!("slow tunnel adapter: server check grace 30 s");
            }
            self.stage(rosetun_config::ConnectStage::CheckingServer)?;
            let engines = Arc::clone(&self.engines);
            let backend = engines
                .get_shared(settings.engine)
                .expect("engine was registered before spawn");
            let control = self.control.clone();
            let interval = self.server_check_interval;
            let started = AtomicBool::new(false);
            let stopped = AtomicBool::new(false);
            let failures = AtomicU64::new(0);
            let cancelled = Arc::clone(&self.cancelled);
            let dns_result = thread::scope(|scope| {
                let _stop = StopServerCheck(&stopped);
                let worker = control.and_then(|control| {
                    let worker_started = &started;
                    let worker_stopped = &stopped;
                    let worker_cancelled = &cancelled;
                    let worker_failures = &failures;
                    match thread::Builder::new()
                        .name("rosetun-server-check".to_owned())
                        .spawn_scoped(scope, move || {
                            check_server_outbound(
                                backend,
                                &control,
                                interval,
                                worker_started,
                                worker_stopped,
                                worker_cancelled,
                                worker_failures,
                            );
                        }) {
                        Ok(worker) => Some(worker),
                        Err(error) => {
                            tracing::warn!(%error, "server check worker is unavailable");
                            None
                        }
                    }
                });
                let result = {
                    let process = self
                        .process
                        .as_mut()
                        .expect("engine process was stored before DNS check");
                    let mut xray_process = self.xray_process.as_mut();
                    dns::check_cancellable(
                        server,
                        self.dns_timeout,
                        self.dns_attempt_timeout,
                        grace_deadline,
                        || {
                            let running = process.is_running()?;
                            let mut counters = process.outbound_failures();
                            let xray_running = match xray_process.as_mut() {
                                Some(xray) => {
                                    let running = xray.is_running()?;
                                    let xray_failures = xray.outbound_failures();
                                    counters.unreachable = counters
                                        .unreachable
                                        .saturating_add(xray_failures.unreachable);
                                    counters.rejected =
                                        counters.rejected.saturating_add(xray_failures.rejected);
                                    counters.closed =
                                        counters.closed.saturating_add(xray_failures.closed);
                                    running
                                }
                                None => true,
                            };
                            counters.unreachable = counters
                                .unreachable
                                .saturating_add(failures.load(Ordering::Acquire));
                            // DNS must capture its baseline before the first check can fail.
                            started.store(true, Ordering::Release);
                            Ok((running && xray_running, counters))
                        },
                        || cancelled.load(Ordering::Acquire),
                    )
                };
                stopped.store(true, Ordering::Release);
                let mut engine_stopped = false;
                if matches!(result, Err(ref error) if error.code == ErrorCode::Cancelled) {
                    if let Err(error) = self.stop_engine() {
                        tracing::error!(%error, "failed to stop engine after cancellation");
                    }
                    engine_stopped = true;
                }
                if let Some(worker) = worker {
                    while !worker.is_finished() {
                        if cancelled.load(Ordering::Acquire) && !engine_stopped {
                            if let Err(error) = self.stop_engine() {
                                tracing::error!(%error, "failed to stop engine after cancellation");
                            }
                            engine_stopped = true;
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    if worker.join().is_err() {
                        return Err(HelperError::new(
                            ErrorCode::Internal,
                            "server check worker panicked",
                        ));
                    }
                }
                check_cancelled(&cancelled)?;
                let count = failures.load(Ordering::Acquire);
                if count != 0 && result.is_err() {
                    tracing::warn!(
                        "server check during connect failed: {count} of {SERVER_CHECK_FAILURES}"
                    );
                }
                result
            });
            self.ensure_xray_running(ErrorCode::XrayStartFailed)?;
            dns_result.map_err(|error| {
                if matches!(
                    error.code,
                    ErrorCode::ServerUnreachable | ErrorCode::DnsTimeout
                ) && (self.physical_interface)(&settings.tun.name).is_none()
                {
                    HelperError::new(ErrorCode::NoNetwork, "physical network is unavailable")
                } else {
                    error
                }
            })?;
            self.tunnel_dns = Some(server);
            self.refresh_path_addresses();
        } else {
            tracing::info!(
                engine = %settings.engine.as_str(),
                "backend does not provide a tunnel DNS server; skipping DNS check"
            );
        }

        self.ensure_xray_running(ErrorCode::XrayStartFailed)?;
        // Do not poison the successful endpoint cache with a failed attempt.
        self.last_endpoint = endpoint.map(|address| SuccessfulEndpoint {
            server: normalize_server(&node.server),
            address,
        });
        check_cancelled(&self.cancelled)
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

    fn refresh_path_addresses(&mut self) {
        let Some(server) = self.tunnel_dns else {
            return;
        };
        let addresses = dns::resolve_path_addresses(server, PATH_LOOKUP_TIMEOUT, || {
            self.cancelled.load(Ordering::Acquire)
        });
        if addresses.is_empty() {
            tracing::info!("path check: second target unavailable");
        }
        *self
            .path_addresses
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = addresses;
    }

    fn start_watchdog(&mut self) {
        let Some(server) = self.tunnel_dns else {
            return;
        };
        match DnsWatchdog::start(
            Arc::clone(&self.status),
            server,
            Arc::clone(&self.path_addresses),
            self.watchdog_timing,
        ) {
            Ok(watchdog) => self.watchdog = Some(watchdog),
            Err(error) => tracing::warn!(%error, "DNS watchdog is unavailable"),
        }
    }

    fn wait_for_tunnel(&mut self, tunnel: &TunnelInterface) -> Result<(), HelperError> {
        let deadline = Instant::now() + TUNNEL_READY_TIMEOUT;

        loop {
            check_cancelled(&self.cancelled)?;
            self.ensure_xray_running(ErrorCode::XrayStartFailed)?;
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

            let routing = self.guard.as_ref().ok_or_else(|| {
                HelperError::new(
                    ErrorCode::RoutingFailed,
                    "routing protection disappeared before tunnel authorization",
                )
            })?;
            let mut guard = routing.routing.lock().map_err(|_| {
                HelperError::new(ErrorCode::RoutingFailed, "routing guard is poisoned")
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

    fn ensure_xray_running(&mut self, code: ErrorCode) -> Result<(), HelperError> {
        if let Some(process) = self.xray_process.as_mut() {
            match process.is_running() {
                Ok(true) => {}
                Ok(false) => return Err(HelperError::new(code, "Xray stopped")),
                Err(_) => return Err(HelperError::new(code, "Xray stopped")),
            }
        }
        Ok(())
    }

    fn stop_engine(&mut self) -> Result<(), HelperError> {
        self.gate.close();
        self.tunnel_dns = None;
        if let Some(watchdog) = self.watchdog.take() {
            watchdog.stop();
        }
        self.path_addresses
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
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
        if let Some(process) = self.xray_process.as_mut() {
            process
                .stop()
                .map_err(|error| HelperError::new(ErrorCode::XrayStopped, error.to_string()))?;
        }
        self.xray_process.take();
        Ok(())
    }

    fn teardown(&mut self) {
        match self.stop_engine() {
            Ok(()) => {
                if let Err(error) = self.clear_staged_lists() {
                    tracing::warn!(code = ?error.code, "could not clean staged lists");
                }
            }
            Err(error) => tracing::error!(%error, "failed to stop the engine"),
        }
        self.pin_lists(&[]);
        if let Some(guard) = self.guard.take()
            && let Err(error) = guard
                .routing
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .revert_in_place()
        {
            tracing::error!(%error, "failed to roll back routes");
        }
        *self.owner.lock().unwrap_or_else(|error| error.into_inner()) = None;
        self.owner.clear_poison();
    }
}

struct StopServerCheck<'a>(&'a AtomicBool);

impl Drop for StopServerCheck<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn check_server_outbound(
    backend: Arc<dyn EngineBackend>,
    control: &ControlEndpoint,
    interval: Duration,
    started: &AtomicBool,
    stopped: &AtomicBool,
    cancelled: &AtomicBool,
    failures: &AtomicU64,
) {
    while !started.load(Ordering::Acquire) && !stopped.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(10));
    }

    let mut next = Instant::now();
    while !stopped.load(Ordering::Acquire) && !cancelled.load(Ordering::Acquire) {
        let result = url_test_any(
            Arc::clone(&backend),
            control,
            UrlTestTarget::Session,
            SERVER_CHECK_TIMEOUT,
        );
        if stopped.load(Ordering::Acquire) || cancelled.load(Ordering::Acquire) {
            return;
        }
        match result {
            Ok(_) => {}
            Err(rosetun_engine::errors::EngineError::Unsupported(_)) => return,
            Err(_) => {
                failures.fetch_add(1, Ordering::AcqRel);
            }
        }

        next += interval;
        while !stopped.load(Ordering::Acquire)
            && !cancelled.load(Ordering::Acquire)
            && Instant::now() < next
        {
            thread::sleep(
                next.saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(20)),
            );
        }
    }
}

fn render_config(
    backend: &dyn EngineBackend,
    request: &RenderRequest<'_>,
) -> Result<RenderedConfig, HelperError> {
    let config = backend
        .render(request)
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

#[cfg(test)]
fn wait_for_previous_adapter(
    alias: &str,
    timeout: Duration,
    interval: Duration,
    lookup: impl FnMut(&str) -> std::io::Result<bool>,
) -> Result<(), HelperError> {
    wait_for_previous_adapter_cancellable(alias, timeout, interval, lookup, &AtomicBool::new(false))
}

fn failure_kind(code: ErrorCode) -> Option<rosetun_config::FailureKind> {
    use rosetun_config::FailureKind;
    match code {
        ErrorCode::EngineNotReady => Some(FailureKind::EngineNotReady),
        ErrorCode::XrayStartFailed => Some(FailureKind::XrayStartFailed),
        ErrorCode::XrayStopped => Some(FailureKind::XrayStopped),
        ErrorCode::NoNetwork => Some(FailureKind::NoNetwork),
        ErrorCode::ServerUnreachable => Some(FailureKind::ServerUnreachable),
        ErrorCode::ServerRejected => Some(FailureKind::ServerRejected),
        ErrorCode::ServerClosed => Some(FailureKind::ServerClosed),
        ErrorCode::DnsTimeout => Some(FailureKind::DnsTimeout),
        _ => None,
    }
}

fn check_cancelled(cancelled: &AtomicBool) -> Result<(), HelperError> {
    if cancelled.load(Ordering::Acquire) {
        Err(HelperError::new(
            ErrorCode::Cancelled,
            "connection cancelled",
        ))
    } else {
        Ok(())
    }
}

fn wait_for_previous_adapter_cancellable(
    alias: &str,
    timeout: Duration,
    interval: Duration,
    mut lookup: impl FnMut(&str) -> std::io::Result<bool>,
    cancelled: &AtomicBool,
) -> Result<(), HelperError> {
    let started = Instant::now();
    let mut waiting = false;
    loop {
        check_cancelled(cancelled)?;
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
                if waiting {
                    tracing::info!(
                        elapsed_ms = started.elapsed().as_millis(),
                        "previous tunnel adapter wait finished"
                    );
                }
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
            tracing::info!(
                elapsed_ms = elapsed.as_millis(),
                "previous tunnel adapter wait finished"
            );
            tracing::warn!(
                elapsed_ms = elapsed.as_millis(),
                "previous tunnel adapter removal timed out"
            );
            return Ok(());
        }
        thread::sleep(interval.min(timeout.saturating_sub(elapsed)));
    }
}

fn server_check_grace_deadline(
    hints: rosetun_engine::StartupHints,
    spawned_at: Instant,
    ready_at: Instant,
    grace: Duration,
) -> Option<Instant> {
    (hints.slow_tunnel_creation
        || ready_at.saturating_duration_since(spawned_at) > Duration::from_secs(5))
    .then_some(ready_at + grace)
}

fn startup_timeout(hints: rosetun_engine::StartupHints) -> Duration {
    if hints.slow_tunnel_creation {
        Duration::from_secs(45)
    } else {
        TUNNEL_READY_TIMEOUT
    }
}

fn wait_for_engine_ready(process: &mut dyn EngineProcess) -> Result<(), HelperError> {
    wait_for_engine_ready_from(process, Instant::now(), &AtomicBool::new(false))
}

fn wait_for_engine_ready_from(
    process: &mut dyn EngineProcess,
    spawned_at: Instant,
    cancelled: &AtomicBool,
) -> Result<(), HelperError> {
    loop {
        check_cancelled(cancelled)?;
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
        let timeout = startup_timeout(process.startup_hints());
        if Instant::now() >= spawned_at + timeout {
            return Err(HelperError::new(
                ErrorCode::EngineNotReady,
                format!(
                    "engine startup readiness was not confirmed within {} seconds",
                    timeout.as_secs()
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
