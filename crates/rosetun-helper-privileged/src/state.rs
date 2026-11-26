mod apply;
mod bypass;
mod connections;
mod dns;
mod dns_cache;
mod exits;
mod lan;
mod local_proxy;
mod lockdown;
#[cfg(target_os = "linux")]
#[path = "state/native_tun_linux.rs"]
mod native_tun;
#[cfg(target_os = "macos")]
#[path = "state/native_tun_macos.rs"]
mod native_tun;
#[cfg(all(windows, target_arch = "x86_64"))]
#[path = "state/native_tun_windows.rs"]
mod native_tun;
mod probe;
mod protection;
mod proxy_session;
mod repeated;
mod session_lock;
#[cfg(target_os = "linux")]
mod system_dns_linux;
#[cfg(target_os = "macos")]
mod system_dns_macos;
#[cfg(test)]
mod tests;
mod watchdog;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use rosetun_config::{
    ConnectionState, ExitId, ListRef, LiveConnection, LocalProxySettings, Node,
    ProtectionCapabilities, Rule, RuleMatcher, RuleTarget, Status, Traffic, list_tag,
};
use rosetun_engine::{
    EngineProcess, EngineRegistry, EngineRights, RenderedConfig, TrafficProbe, TrafficTotals,
    errors::EngineError,
};
use rosetun_engine_xray::{SocksEndpoint, XrayHelper};
use rosetun_ipc::transport::{AccountIdentity, PeerIdentity};
use rosetun_ipc::{
    ConnectRequest, ErrorCode, HelperError, ListFormat, MAX_EXTRA_NODES, MAX_TEMPORARY_RULES,
    SessionExit,
};
use rosetun_routing::{LockdownApps, ProtectionScope, RoutingBackend, RoutingPlan};

use crate::list_store::{ListChunk, ListStore, valid_hash, valid_tag};
use crate::log_gate::VerboseGate;
use connections::{ConnectionBook, Translation};
use session_lock::{Acquired, SESSION_POLL, SESSION_WAIT, SessionGuard, SessionHolder};
use watchdog::{DnsWatchdog, WatchdogTiming};

const TUNNEL_READY_TIMEOUT: Duration = Duration::from_secs(15);
const SLOW_START_READY_TIMEOUT: Duration = Duration::from_secs(45);
const TUNNEL_READY_POLL_INTERVAL: Duration = Duration::from_millis(100);
const TUNNEL_DNS_TIMEOUT: Duration = Duration::from_secs(60);
const TUNNEL_DNS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);
const TRAFFIC_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// A connection that opens and closes between two polls is never seen, so
/// the list is polled more often while someone reads it.
const WATCHED_POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Rates span about a second whatever the poll interval, so a quicker poll
/// does not make them jump; a little under the idle interval so that the idle
/// poll's jitter does not skip a window.
const RATE_WINDOW: Duration = Duration::from_millis(900);
const MONITOR_TICK: Duration = Duration::from_millis(50);
/// Starts repeated when the engine reports that Windows is still removing the
/// previous tunnel adapter; the next start one or two seconds later succeeds.
const WATCHDOG_TIMING: WatchdogTiming = WatchdogTiming {
    interval: Duration::from_secs(30),
    retry: Duration::from_secs(5),
    dns_timeout: Duration::from_secs(5),
    path_timeout: Duration::from_secs(5),
    failures: 3,
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
const NETWORK_GRACE: Duration = Duration::from_secs(15);
const NETWORK_DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// A wall-clock jump this large between two ticks means the machine slept.
const SLEEP_GAP: Duration = Duration::from_secs(30);
/// Right after power-on the adapter is up before the network carries
/// anything, and a connect at startup fails at once without this wait.
#[cfg(not(test))]
const NETWORK_WAIT: Duration = Duration::from_secs(30);
#[cfg(not(test))]
const NETWORK_WAIT_INTERVAL: Duration = Duration::from_secs(2);
#[cfg(test)]
const NETWORK_WAIT_INTERVAL: Duration = Duration::from_millis(10);
/// How long a connect asks the network's DNS servers whether the network is
/// up after the system resolver failed.
#[cfg(not(test))]
const NETWORK_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(test)]
fn test_physical_interface(_: &str) -> Option<String> {
    Some("Ethernet".to_owned())
}

fn connection_state_name(state: &ConnectionState) -> &'static str {
    match state {
        ConnectionState::Disconnected => "disconnected",
        ConnectionState::Connecting => "connecting",
        ConnectionState::Connected => "connected",
        ConnectionState::Reconnecting => "reconnecting",
        ConnectionState::Failed { .. } => "failed",
        ConnectionState::FailedProtected { .. } => "failed_protected",
    }
}

pub(crate) struct Caller {
    account: AccountIdentity,
    administrator: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Caller {
    pub(crate) fn is_administrator(&self) -> bool {
        self.administrator
    }
}

#[cfg(test)]
impl Caller {
    pub(crate) fn fake(sid: &[u8], administrator: bool) -> Self {
        Self {
            account: AccountIdentity::WindowsSid(sid.to_vec()),
            administrator,
        }
    }
}

impl From<PeerIdentity> for Caller {
    fn from(peer: PeerIdentity) -> Self {
        Self {
            account: peer.account().clone(),
            administrator: peer.is_administrator(),
        }
    }
}

pub struct Helper {
    status: Arc<Mutex<Status>>,
    connections: Arc<Mutex<ConnectionBook>>,
    session: Mutex<Session>,
    /// Who took `session`, for the log line of a request that waited in vain.
    session_holder: AtomicU8,
    owner: Arc<Mutex<Option<AccountIdentity>>>,
    last_owner: Mutex<Option<AccountIdentity>>,
    engines: Arc<EngineRegistry>,
    xray: Option<Arc<dyn XrayRunner>>,
    physical_interface: fn(&str) -> Option<String>,
    /// Mirror of `Session::active_tun_name` for concurrent server probes.
    active_tun: Arc<Mutex<Option<String>>>,
    probe: Mutex<()>,
    lists: Option<Arc<Mutex<ListStore>>>,
    shutting_down: AtomicBool,
    /// Present when the package's upgrade stops the service. Its folder is
    /// writable by root alone.
    upgrade_marker: Option<PathBuf>,
    resumed: AtomicBool,
    cancelled: Arc<AtomicBool>,
    lockdown: lockdown::SharedLockdown,
    protection_report: protection::SharedReport,
    /// What the routing backend implements, read once when the helper is built.
    protection: ProtectionCapabilities,
    /// Why the kill switch is missing, for the refusal of a connect.
    protection_unavailable: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartMode {
    Fresh,
    ProtectedReconnect,
}

struct StartOptions {
    mode: StartMode,
    endpoint: Option<ResolvedNodeEndpoints>,
    /// Extra node addresses in request order; `None` resolves them for `mode`.
    extra_endpoints: Option<Vec<Option<ResolvedNodeEndpoints>>>,
    dns_timeout: Duration,
}

#[derive(Debug, Clone)]
pub(super) struct SuccessfulEndpoint {
    server: String,
    address: IpAddr,
    /// Normalized host -> IP for all resolved hosts of this node (used by Xray balancers).
    members: HashMap<String, IpAddr>,
}

impl SuccessfulEndpoint {
    pub(super) fn lookup(&self, server: &str) -> Option<IpAddr> {
        let key = normalize_server(server);
        self.members
            .get(&key)
            .copied()
            .or_else(|| (self.server == key).then_some(self.address))
    }

    pub(super) fn contains_address(&self, address: IpAddr) -> bool {
        self.address == address || self.members.values().any(|&ip| ip == address)
    }
}

/// Resolved IP addresses for one node (single server or all resolved members of
/// an [`rosetun_config::Outbound::XrayBalancer`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResolvedNodeEndpoints {
    pub(super) primary: IpAddr,
    pub(super) members: HashMap<String, IpAddr>,
}

impl ResolvedNodeEndpoints {
    pub(super) fn single(server: &str, address: IpAddr) -> Self {
        let mut members = HashMap::new();
        members.insert(normalize_server(server), address);
        Self {
            primary: address,
            members,
        }
    }

    pub(super) fn from_members(primary: IpAddr, members: HashMap<String, IpAddr>) -> Self {
        Self { primary, members }
    }

    pub(super) fn ip_for(&self, server: &str) -> Option<IpAddr> {
        server
            .parse::<IpAddr>()
            .ok()
            .or_else(|| self.members.get(&normalize_server(server)).copied())
    }

    pub(super) fn push_unique_ips(&self, out: &mut Vec<IpAddr>) {
        if !out.contains(&self.primary) {
            out.push(self.primary);
        }
        for &ip in self.members.values() {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }

    pub(super) fn into_successful(self, server: &str) -> SuccessfulEndpoint {
        SuccessfulEndpoint {
            server: normalize_server(server),
            address: self.primary,
            members: self.members,
        }
    }
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
    fn locate_outbound_worker(&self) -> Result<PathBuf, EngineError> {
        self.locate_binary()
    }
    fn probe_config_path(&self) -> PathBuf;
    fn spawn_outbound_worker(
        &self,
        binary: &Path,
        config: &RenderedConfig,
        endpoints: &[&SocksEndpoint],
        verbose_until_unix: Arc<AtomicU64>,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        self.spawn(binary, config, endpoints, verbose_until_unix)
    }
    fn spawn(
        &self,
        binary: &Path,
        config: &RenderedConfig,
        endpoints: &[&SocksEndpoint],
        verbose_until_unix: Arc<AtomicU64>,
    ) -> Result<Box<dyn EngineProcess>, EngineError>;
}

impl XrayRunner for XrayHelper {
    fn spawn_outbound_worker(
        &self,
        binary: &Path,
        config: &RenderedConfig,
        endpoints: &[&SocksEndpoint],
        verbose_until_unix: Arc<AtomicU64>,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        XrayHelper::spawn_outbound_worker(self, binary, config, endpoints, verbose_until_unix)
    }

    fn binary_path(&self) -> Result<PathBuf, EngineError> {
        XrayHelper::binary_path(self)
    }

    fn locate_outbound_worker(&self) -> Result<PathBuf, EngineError> {
        XrayHelper::locate_outbound_worker(self)
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

struct Session {
    engines: Arc<EngineRegistry>,
    routing: Box<dyn RoutingBackend>,
    gate: VerboseGate,
    status: Arc<Mutex<Status>>,
    xray: Option<Arc<dyn XrayRunner>>,
    physical_interface: fn(&str) -> Option<String>,
    tunnel_egress: Option<String>,
    proxy_session: Option<proxy_session::ProxySession>,
    monitor: Option<TrafficMonitor>,
    connections: Arc<Mutex<ConnectionBook>>,
    watchdog: Option<DnsWatchdog>,
    tunnel_dns: Option<SocketAddr>,
    /// Actual kernel tunnel interface name reported by the engine (for example
    /// `utun6` on macOS when the configured name is `rosetun0`).
    active_tun_name: Option<String>,
    shared_active_tun: Arc<Mutex<Option<String>>>,
    protection: protection::ProtectionRuntime,
    last_endpoint: Option<SuccessfulEndpoint>,
    /// Last addresses of extra nodes by exit, for reconnects that cannot resolve.
    last_extra_endpoints: HashMap<ExitId, SuccessfulEndpoint>,
    /// Each exit's outbound tag in the running config, `None` without an address.
    exit_tags: Vec<(ExitId, Option<String>)>,
    request: Option<ConnectRequest>,
    owner: Arc<Mutex<Option<AccountIdentity>>>,
    reconnect: Option<Reconnect>,
    missing_route_ticks: u8,
    bypass: bypass::BypassWatch,
    missing_route_since: Option<Instant>,
    stopping: bool,
    dns_timeout: Duration,
    dns_attempt_timeout: Duration,
    watchdog_timing: WatchdogTiming,
    adapter_lookup: fn(&str) -> std::io::Result<bool>,
    name_lookup: fn(&str, u16, NameLookup) -> Result<Vec<IpAddr>, Unresolved>,
    /// How long a connect waits for the network to look the server name up.
    network_wait: Duration,
    /// Whether the network is not up yet, asked after the system resolver
    /// failed on connect.
    network_down: fn(&str) -> bool,
    cancelled: Arc<AtomicBool>,
    lists: Option<Arc<Mutex<ListStore>>>,
    list_run_dir: Option<PathBuf>,
    lockdown: lockdown::SharedLockdown,
    /// The programs Lockdown permits; a hook for tests.
    lockdown_apps: fn() -> LockdownApps,
    /// No engine has been started since the service started. After a power
    /// cut an antivirus may scan the engine again on its first run, so that
    /// start gets the slow-start deadline. Cleared by the first start,
    /// whether it succeeds or not.
    cold_start: bool,
    /// Reads the computer's segment; a hook for tests.
    /// Reads where a shared proxy may listen; a hook for tests.
    shared_proxy_addresses: fn() -> Vec<IpAddr>,
    /// What the running session's proxy was given.
    shared_addresses: Vec<IpAddr>,
    shared_address_watch: lan::LanWatch<Vec<IpAddr>>,
    lan: lan::LanRuntime,
    /// Stands in for the engine's loopback DNS in the proxy mode.
    #[cfg(test)]
    test_local_dns: Option<SocketAddr>,
    #[cfg(test)]
    test_tun_name: Option<String>,
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
        let lockdown = lockdown::SharedLockdown::default();
        let protection_report = protection::SharedReport::default();
        let connections = Arc::new(Mutex::new(ConnectionBook::default()));
        let protection = routing.capabilities();
        let protection_unavailable = if protection.kill_switch {
            None
        } else {
            routing.unavailable_reason()
        };
        if let Some(reason) = protection_unavailable.as_deref() {
            tracing::warn!(reason, "the kill switch is not available");
        }
        let active_tun = Arc::new(Mutex::new(None));
        Self {
            protection,
            protection_unavailable,
            lockdown: Arc::clone(&lockdown),
            protection_report: Arc::clone(&protection_report),
            status: Arc::clone(&status),
            connections: Arc::clone(&connections),
            owner: Arc::clone(&owner),
            last_owner: Mutex::new(None),
            engines: Arc::clone(&engines),
            xray: None,
            #[cfg(not(test))]
            physical_interface: rosetun_routing::physical_default_interface,
            #[cfg(test)]
            physical_interface: test_physical_interface,
            active_tun: Arc::clone(&active_tun),
            probe: Mutex::new(()),
            lists: None,
            shutting_down: AtomicBool::new(false),
            upgrade_marker: None,
            resumed: AtomicBool::new(false),
            cancelled: Arc::clone(&cancelled),
            session_holder: AtomicU8::new(SessionHolder::Nobody as u8),
            session: Mutex::new(Session {
                engines,
                routing,
                gate,
                status,
                xray: None,
                #[cfg(not(test))]
                physical_interface: rosetun_routing::physical_default_interface,
                #[cfg(test)]
                physical_interface: test_physical_interface,
                tunnel_egress: None,
                proxy_session: None,
                monitor: None,
                connections,
                watchdog: None,
                tunnel_dns: None,
                active_tun_name: None,
                shared_active_tun: active_tun,
                protection: protection::ProtectionRuntime::new(protection_report),
                last_endpoint: None,
                last_extra_endpoints: HashMap::new(),
                exit_tags: Vec::new(),
                request: None,
                owner,
                reconnect: None,
                missing_route_ticks: 0,
                bypass: bypass::BypassWatch::default(),
                missing_route_since: None,
                stopping: false,
                dns_timeout: TUNNEL_DNS_TIMEOUT,
                dns_attempt_timeout: TUNNEL_DNS_ATTEMPT_TIMEOUT,
                watchdog_timing: WATCHDOG_TIMING,
                cancelled,
                lists: None,
                list_run_dir: None,
                lockdown,
                #[cfg(not(test))]
                lockdown_apps: lockdown::lockdown_apps,
                #[cfg(test)]
                lockdown_apps: lockdown::test_apps,
                cold_start: true,
                #[cfg(not(test))]
                shared_proxy_addresses: rosetun_routing::shared_proxy_addresses,
                #[cfg(test)]
                shared_proxy_addresses: Vec::new,
                shared_addresses: Vec::new(),
                shared_address_watch: lan::LanWatch::default(),
                lan: lan::LanRuntime::default(),
                #[cfg(test)]
                test_local_dns: None,
                #[cfg(test)]
                test_tun_name: None,
                #[cfg(not(test))]
                adapter_lookup: rosetun_routing::tunnel_adapter_present,
                #[cfg(test)]
                adapter_lookup: |_| Ok(false),
                name_lookup: lookup_name,
                #[cfg(not(test))]
                network_wait: NETWORK_WAIT,
                #[cfg(test)]
                network_wait: Duration::ZERO,
                #[cfg(not(test))]
                network_down,
                #[cfg(test)]
                network_down: |_| false,
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
    fn with_lan_scan(mut self, scan: lan::LanScan) -> Self {
        self.session
            .get_mut()
            .expect("new session is not poisoned")
            .lan
            .scan = scan;
        self
    }

    #[cfg(test)]
    fn with_broadcast_route_release(mut self, release: lan::BroadcastRouteRelease) -> Self {
        self.session
            .get_mut()
            .expect("new session is not poisoned")
            .lan
            .broadcast_route_release = release;
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

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn with_upgrade_marker(mut self, marker: PathBuf) -> Self {
        self.upgrade_marker = Some(marker);
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

    /// The protection this system can give; clients learn it from `Hello`.
    pub fn protection_capabilities(&self) -> ProtectionCapabilities {
        self.protection
    }

    /// Refuses a request for a kill switch this system cannot give, before
    /// anything of the session is touched. A connect never goes ahead
    /// silently without the protection it was asked for; Lockdown asks for
    /// the kill switch too.
    fn require_protection(&self, request: &ConnectRequest) -> Result<(), HelperError> {
        let wanted = request.settings.kill_switch || lockdown::read(&self.lockdown).enabled;
        if wanted && !self.protection.kill_switch {
            let message = match self.protection_unavailable.as_deref() {
                Some(reason) => {
                    format!("the kill switch is not available on this system: {reason}")
                }
                None => "the kill switch is not available on this system".to_owned(),
            };
            return Err(HelperError::new(ErrorCode::ProtectionUnavailable, message));
        }
        Ok(())
    }

    /// Refuses rules by program where the engine cannot be given what they need,
    /// before anything of the session is touched: a rule that never matches sends
    /// the program's traffic another way without a word.
    fn require_engine_rights(&self, request: &ConnectRequest) -> Result<(), HelperError> {
        if request.settings.connection_mode == rosetun_config::ConnectionMode::SystemProxy
            && EngineRights::for_rules(&request.effective_rule_set())
                == EngineRights::NetworkAndProcesses
        {
            return Err(HelperError::new(
                ErrorCode::UnsupportedRules,
                "rules by program are unavailable in local proxy mode",
            ));
        }
        Ok(())
    }

    pub fn status(&self) -> Status {
        let mut status = self.with_status(|status| status.clone());
        let lockdown = lockdown::read(&self.lockdown);
        status.lockdown = lockdown.enabled && !lockdown.upgrade_hold;
        status.upgrade_hold = lockdown.enabled && lockdown.upgrade_hold;
        status.protection = self
            .protection_report
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .state(lockdown);
        status
    }

    pub(crate) fn temporary_rules_as(&self, caller: &Caller) -> Result<Vec<Rule>, HelperError> {
        self.check_owner(caller)?;
        let session = self.session_for(SessionHolder::Query)?;
        self.check_owner(caller)?;
        Ok(session
            .request
            .as_ref()
            .map(|request| request.temporary_rules.clone())
            .unwrap_or_default())
    }

    pub(crate) fn session_exits_as(
        &self,
        caller: &Caller,
    ) -> Result<Vec<SessionExit>, HelperError> {
        self.check_owner(caller)?;
        let session = self.session_for(SessionHolder::Query)?;
        self.check_owner(caller)?;
        Ok(session
            .request
            .as_ref()
            .map(|request| {
                request
                    .extra_nodes
                    .iter()
                    .map(|extra| SessionExit {
                        exit: extra.exit.clone(),
                        selection: extra.selection.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// The running session's connections. Only the account that connected the
    /// tunnel may read them, administrators included: they are its browsing
    /// history. Each request keeps the list collected for a few more seconds.
    pub(crate) fn connections_as(
        &self,
        caller: &Caller,
    ) -> Result<(Vec<LiveConnection>, Vec<LiveConnection>), HelperError> {
        if !self.check_connections_owner(caller)? {
            return Ok((Vec::new(), Vec::new()));
        }
        let session = self.session_for(SessionHolder::Query)?;
        if !self.check_connections_owner(caller)? || session.monitor.is_none() {
            return Ok((Vec::new(), Vec::new()));
        }
        let mut book = self
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        book.watch(Instant::now());
        Ok(book.snapshot())
    }

    /// Closes one connection of the running session, for the same account as
    /// [`Self::connections_as`]. Without a session there is nothing to close,
    /// and an id the engine no longer knows is not an error: the connection
    /// may have closed on its own.
    pub(crate) fn close_connection_as(&self, caller: &Caller, id: &str) -> Result<(), HelperError> {
        if !rosetun_engine::valid_connection_id(id) {
            return Err(HelperError::new(
                ErrorCode::InvalidRequest,
                "the connection id is empty or too long",
            ));
        }
        if !self.check_connections_owner(caller)? {
            return Ok(());
        }
        let session = self.session_for(SessionHolder::Query)?;
        if !self.check_connections_owner(caller)? {
            return Ok(());
        }
        if let Some(proxy) = &session.proxy_session {
            proxy.dataplane.close_connection(id);
        }
        Ok(())
    }

    /// Returns false without a session owner, so there is nothing to show.
    fn check_connections_owner(&self, caller: &Caller) -> Result<bool, HelperError> {
        let owner = self.owner.lock().map_err(|_| access_denied())?;
        match owner.as_ref() {
            None => Ok(false),
            Some(account) if account == &caller.account => Ok(true),
            Some(_) => Err(HelperError::new(
                ErrorCode::AccessDenied,
                "only the account that connected the tunnel can read its connections",
            )),
        }
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
            .map(|ch| {
                if ch.is_control() && !matches!(ch, '\n' | '\r' | '\t') {
                    ' '
                } else {
                    ch
                }
            })
            .collect();
        Ok(rosetun_config::redact_report_text(&printable))
    }

    fn check_diagnostic_owner(&self, caller: &Caller) -> Result<(), HelperError> {
        let owner = self.owner.lock().map_err(|_| access_denied())?;
        let last_owner = self.last_owner.lock().map_err(|_| access_denied())?;
        let expected = owner.as_ref().or(last_owner.as_ref());
        if expected != Some(&caller.account) {
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

    pub(super) fn effective_tun_name(&self, tun: &rosetun_config::TunSettings) -> String {
        self.active_tun
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .unwrap_or_else(|| tun.name.clone())
    }

    pub fn supervise(&self, now: Instant) {
        let Some(Acquired::Locked(mut session)) = self.try_session(SessionHolder::Supervisor)
        else {
            return;
        };
        if session.stopping {
            return;
        }
        session.observe_bypass(now);
        {
            let session = &mut *session;
            session
                .protection
                .check_rules(session.routing.as_ref(), now);
        }
        let Some(auto_reconnect) = session
            .request
            .as_ref()
            .map(|request| request.settings.auto_reconnect)
        else {
            session.missing_route_ticks = 0;
            session.missing_route_since = None;
            self.resumed.store(false, Ordering::Release);
            session.follow_lan_in_lockdown();
            return;
        };

        let active_tun = session
            .effective_tun_name(
                &session
                    .request
                    .as_ref()
                    .expect("active request")
                    .settings
                    .tun,
            )
            .to_owned();
        let current_physical = (session.physical_interface)(&active_tun);
        let network_available = current_physical.is_some();
        let loss_duration = session
            .missing_route_since
            .map(|since| now.saturating_duration_since(since));
        if network_available {
            if session.missing_route_ticks >= 2
                && let Some(duration) = loss_duration
            {
                tracing::info!(
                    elapsed_ms = duration.as_millis() as u64,
                    "physical network returned"
                );
            }
            session.missing_route_since = None;
            session.missing_route_ticks = 0;
        } else {
            session.missing_route_since.get_or_insert(now);
            let first_confirmed = session.missing_route_ticks == 1;
            session.missing_route_ticks = (session.missing_route_ticks + 1).min(2);
            if session.missing_route_ticks < 2 {
                return;
            }
            if first_confirmed {
                tracing::info!("physical network lost");
            }
        }
        if !network_available && auto_reconnect {
            if session.reconnect.is_none() {
                self.begin_attempt(ConnectionState::Reconnecting);
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
            let expired = session
                .missing_route_since
                .is_some_and(|since| now.saturating_duration_since(since) >= NETWORK_GRACE);
            let has_engine = session.proxy_session.is_some();
            let exited = has_engine && !session.live_engine_running();
            if has_engine && (expired || exited) {
                tracing::info!(
                    expired,
                    exited,
                    "stopping engine while waiting for physical network"
                );
                if let Err(error) = session.stop_engine() {
                    tracing::error!(%error, "failed to stop engine after network loss");
                }
            }
            return;
        }
        if session.reconnect.is_some() {
            let from_network_loss = session
                .reconnect
                .as_ref()
                .is_some_and(|reconnect| reconnect.cause == "network lost");
            if from_network_loss
                && loss_duration.is_some_and(|duration| duration < NETWORK_GRACE)
                && session.proxy_session.is_some()
                && session
                    .tunnel_egress
                    .as_ref()
                    .is_none_or(|interface| Some(interface) == current_physical.as_ref())
                && session.live_engine_running()
            {
                tracing::info!("checking live tunnel after physical network returned");
                let remaining = NETWORK_GRACE
                    .saturating_sub(loss_duration.expect("short network loss has a start time"));
                match session.check_live_tunnel(remaining.min(NETWORK_DNS_TIMEOUT)) {
                    Ok(()) => {
                        if let Err(error) = self.publish_terminal(|status| {
                            status.state = ConnectionState::Connected;
                            status.reconnect_failure_kind = None;
                        }) {
                            if error.code == ErrorCode::Cancelled {
                                self.finish_cancelled(&mut session);
                                return;
                            }
                            tracing::warn!(code = ?error.code, "could not confirm tunnel recovery; restarting");
                        } else {
                            session.reconnect = None;
                            if let Some(watchdog) = session.watchdog.take() {
                                watchdog.stop();
                            }
                            session.start_watchdog();
                            tracing::info!("tunnel recovered without an engine restart");
                            return;
                        }
                    }
                    Err(error) if error.code == ErrorCode::Cancelled => {
                        self.finish_cancelled(&mut session);
                        return;
                    }
                    Err(error) => {
                        tracing::warn!(code = ?error.code, "live tunnel did not recover; restarting");
                    }
                }
            }
            let had_no_network = self.with_status(|status| {
                status.reconnect_failure_kind == Some(rosetun_config::FailureKind::NoNetwork)
            });
            if had_no_network {
                session
                    .reconnect
                    .as_mut()
                    .expect("pending reconnect")
                    .next_at = now;
            }
            if now
                < session
                    .reconnect
                    .as_ref()
                    .expect("pending reconnect")
                    .next_at
            {
                return;
            }
        } else {
            let (xray_exited, exited) = session.proxy_session.as_mut().map_or_else(
                || (false, Some("the dataplane is missing".to_owned())),
                proxy_session::ProxySession::exited,
            );
            if let Some(reason) = exited {
                if xray_exited {
                    self.with_status(|status| status.xray_stopped = true);
                }
                let protected = session.protection.keeps_protection();
                if !auto_reconnect {
                    tracing::warn!(%reason, protected, "the engine terminated itself");
                    if !protected {
                        session.teardown();
                    } else if let Err(error) = session.stop_engine() {
                        tracing::error!(%error, "failed to stop the remaining engine processes");
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
            } else if session
                .tunnel_egress
                .as_ref()
                .is_some_and(|interface| Some(interface) != current_physical.as_ref())
            {
                if !auto_reconnect {
                    tracing::warn!("the physical TUN egress changed; auto-reconnect is disabled");
                    return;
                }
                self.begin_attempt(ConnectionState::Reconnecting);
                session.reconnect = Some(Reconnect {
                    failures: 0,
                    next_at: now,
                    cause: "physical interface changed",
                });
            } else if session.local_network_changed() {
                if !auto_reconnect {
                    tracing::warn!(
                        "the new local network stays closed until the next connect: auto-reconnect is off"
                    );
                    return;
                }
                // The new segment's filters and the engine's routes come
                // with the restart; the protection stays up meanwhile.
                self.begin_attempt(ConnectionState::Reconnecting);
                session.reconnect = Some(Reconnect {
                    failures: 0,
                    next_at: now,
                    cause: "local network changed",
                });
            } else {
                return;
            }
        }

        self.resumed.store(false, Ordering::Release);
        let request = session.request.clone().expect("active request is present");
        let reconnect = session.reconnect.take().expect("reconnect is scheduled");
        let attempt = reconnect.failures + 1;
        let mode = session.protection.restart_mode();
        tracing::info!(
            cause = reconnect.cause,
            attempt,
            ?mode,
            "attempting tunnel reconnect"
        );
        let dns_timeout = if reconnect.cause == "network lost" {
            session.dns_timeout.min(NETWORK_DNS_TIMEOUT)
        } else {
            session.dns_timeout
        };
        match session
            .start_with_options(
                &request,
                StartOptions {
                    mode,
                    endpoint: None,
                    extra_endpoints: None,
                    dns_timeout,
                },
            )
            .and_then(|()| {
                self.publish_terminal(|status| {
                    status.state = ConnectionState::Connected;
                    status.reconnect_failure_kind = None;
                    session.record_chain(status, &request);
                    status.since_unix.get_or_insert_with(now_unix);
                })
            }) {
            Ok(()) => {
                session.start_monitor();
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
                    tracing::warn!(cause = reconnect.cause, attempt, code = ?error.code, "tunnel reconnect deferred until network returns");
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
                self.with_status(|status| status.reconnect_failure_kind = None);
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
                    let protected = session.protection.keeps_protection();
                    if protected {
                        if let Err(cleanup_error) = session.stop_engine() {
                            tracing::error!(%cleanup_error, "failed to stop engine after protected reconnect failure");
                        }
                    } else {
                        session.teardown();
                    }
                    tracing::warn!(cause = reconnect.cause, attempt, %error, "tunnel reconnect attempts exhausted");
                    let reason = error.message.clone();
                    self.with_status(|status| {
                        status.state = if protected {
                            ConnectionState::FailedProtected {
                                reason,
                                failure_kind: if reconnect.cause == "xray stopped" {
                                    Some(rosetun_config::FailureKind::XrayStopped)
                                } else {
                                    failure_kind(&error)
                                },
                            }
                        } else {
                            ConnectionState::Failed {
                                reason,
                                failure_kind: if reconnect.cause == "xray stopped" {
                                    Some(rosetun_config::FailureKind::XrayStopped)
                                } else {
                                    failure_kind(&error)
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
        let mut session = self.session_for(SessionHolder::Connect)?;
        self.check_owner(caller)?;
        validate_request(request)?;
        self.require_protection(request)?;
        self.require_engine_rights(request)?;
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
            extra_nodes = request.extra_nodes.len(),
            ?mode,
            "starting tunnel connection"
        );

        let lockdown_lan = session.lockdown_lan(
            request.settings.allow_lan,
            request.settings.private_networks,
        );
        lockdown::sync_lan(
            session.routing.as_ref(),
            &session.lockdown,
            &session.lockdown_programs(),
            caller,
            lockdown_lan.as_ref(),
        )?;
        let previous_owner = self.begin_connect(caller)?;
        session.request = None;
        session.reconnect = None;
        session.missing_route_ticks = 0;
        session.missing_route_since = None;

        match session.start(request, mode, None, None).and_then(|()| {
            self.publish_terminal(|status| {
                status.state = ConnectionState::Connected;
                status.node = Some(request.node.id.clone());
                status.engine = Some(request.settings.engine);
                session.record_chain(status, request);
                status.since_unix = Some(now_unix());
            })
        }) {
            Ok(()) => {
                session.request = Some(request.clone());
                self.resumed.store(false, Ordering::Release);
                // The tunnel is up under the hold's block; the hold is
                // lifted only now. A failure keeps the network closed and
                // the session connected through its permits above the block.
                if let Err(error) = session.release_upgrade_hold("connected") {
                    tracing::error!(%error, "could not lift the upgrade hold after connecting");
                }
                session.start_monitor();
                session.start_watchdog();
                if caller.administrator
                    && previous_owner
                        .as_ref()
                        .is_some_and(|previous| previous != &caller.account)
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
                let protected = session.protection.keeps_protection()
                    && (mode == StartMode::ProtectedReconnect
                        || native_tun_requested(request)
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
                            failure_kind: failure_kind(&error),
                        }
                    } else {
                        ConnectionState::Failed {
                            reason,
                            failure_kind: failure_kind(&error),
                        }
                    };
                    status.since_unix = None;
                    status.connect_stage = None;
                    status.stage_since_unix = None;
                    if protected {
                        *self
                            .owner
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                            previous_owner.clone();
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
        // Cancelling a connect in progress never waits. Anything else gets
        // the same short wait for the session as every client request.
        let deadline = Instant::now() + SESSION_WAIT;
        let (mut session, poisoned) = loop {
            match self.try_session(SessionHolder::Disconnect) {
                Some(Acquired::Locked(session)) => break (session, false),
                Some(Acquired::Poisoned(session)) => break (session, true),
                None => {}
            }
            if self.cancel_transitional(caller)? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(self.session_busy(
                    SessionHolder::Disconnect,
                    "another tunnel operation is in progress",
                ));
            }
            thread::sleep(SESSION_POLL);
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
        // The user chose to be disconnected, so nothing is left to hold for.
        if let Err(error) = session.release_upgrade_hold("disconnected") {
            tracing::error!(%error, "could not lift the upgrade hold after disconnecting");
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
        let mut session = SessionGuard::new(
            self.session
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            &self.session_holder,
            SessionHolder::Teardown,
        );
        session.stopping = true;
        session.request = None;
        session.reconnect = None;
        if self
            .upgrade_marker
            .as_deref()
            .is_some_and(|marker| marker.try_exists().unwrap_or(true))
        {
            tracing::info!("stopping for an upgrade: the firewall stays as it is");
            session.routing.keep_protection_on_stop();
        }
        session.teardown();
        // A normal stop leaves nothing behind; only a crash keeps the
        // network closed.
        if let Err(error) = session.routing.release_on_stop() {
            tracing::error!(%error, "could not remove protection left from before");
        }
        self.with_status(|status| *status = Status::default());
        drop(session);
        // The service must not exit with a live probe process or its secret config.
        let _probe = self
            .probe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tracing::info!("helper session teardown completed");
    }

    /// For a disconnect that finds the session busy: checks the caller's
    /// right to cancel and, when a connect or reconnect is in progress, sets
    /// the cancel flag and says so (`true`). Nothing else is touched, so the
    /// caller may go on waiting.
    fn cancel_transitional(&self, caller: &Caller) -> Result<bool, HelperError> {
        self.with_status(|status| {
            let owner = self.owner.lock().map_err(|_| access_denied())?;
            if owner
                .as_ref()
                .is_some_and(|account| account != &caller.account && !caller.administrator)
                || (owner.is_none() && status.state.is_transitional())
            {
                return Err(access_denied());
            }
            if status.state.is_transitional() {
                self.cancelled.store(true, Ordering::Release);
                Ok(true)
            } else {
                Ok(false)
            }
        })
    }

    fn with_status<T>(&self, apply: impl FnOnce(&mut Status) -> T) -> T {
        let mut status = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous_state = status.state.clone();
        let result = apply(&mut status);
        if status.state != ConnectionState::Connected {
            status.bypass_detected = false;
            status.tunnel_dns_unregistered = false;
        }
        let previous = connection_state_name(&previous_state);
        let current = connection_state_name(&status.state);
        if previous != current {
            tracing::debug!(previous, current, "connection state changed");
        }
        let flush = dns_cache::flushes_dns_cache(&previous_state, &status.state);
        // Outside the fast status lock: a client reading status must not wait
        // for the DNS client service.
        drop(status);
        if flush {
            dns_cache::flush();
        }
        result
    }

    fn check_owner(&self, caller: &Caller) -> Result<(), HelperError> {
        let owner = self.owner.lock().map_err(|_| access_denied())?;
        if owner
            .as_ref()
            .is_some_and(|account| account != &caller.account && !caller.administrator)
        {
            return Err(access_denied());
        }
        Ok(())
    }

    fn begin_connect(&self, caller: &Caller) -> Result<Option<AccountIdentity>, HelperError> {
        self.with_status(|status| {
            let mut owner = self.owner.lock().map_err(|_| access_denied())?;
            let previous = owner.replace(caller.account.clone());
            *self.last_owner.lock().map_err(|_| access_denied())? = Some(caller.account.clone());
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
        "the tunnel belongs to another account; only that account or an administrator can control it",
    )
}

#[cfg(windows)]
fn report_log_error(_: std::io::Error) -> HelperError {
    HelperError::new(
        ErrorCode::Internal,
        "could not read the helper diagnostic log",
    )
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

fn native_tun_requested(request: &ConnectRequest) -> bool {
    request.settings.connection_mode == rosetun_config::ConnectionMode::Tun
}

fn validate_request(request: &ConnectRequest) -> Result<(), HelperError> {
    if native_tun_requested(request)
        && !cfg!(any(
            target_os = "linux",
            target_os = "macos",
            all(windows, target_arch = "x86_64")
        ))
    {
        return Err(HelperError::new(
            ErrorCode::ProtectionUnavailable,
            "native TUN is unavailable on this platform",
        ));
    }
    for node in
        std::iter::once(&request.node).chain(request.extra_nodes.iter().map(|extra| &extra.node))
    {
        node.validate_proxy()
            .map_err(|message| HelperError::new(ErrorCode::InvalidRequest, message))?;
    }
    validate_tun_name(&request.settings.tun.name)?;
    if !LocalProxySettings::port_is_valid(request.settings.local_proxy.port) {
        return Err(HelperError::new(
            ErrorCode::InvalidRequest,
            "the local proxy port is outside the allowed range",
        ));
    }
    if request
        .rule_set
        .rules
        .iter()
        .any(|rule| matches!(rule.matcher, RuleMatcher::Group { .. }))
    {
        return Err(HelperError::new(
            ErrorCode::UnsupportedRules,
            "rule set contains a group; expand groups before sending the request",
        ));
    }
    if request.temporary_rules.len() > MAX_TEMPORARY_RULES
        || request
            .temporary_rules
            .iter()
            .any(|rule| matches!(rule.matcher, RuleMatcher::Group { .. }))
    {
        return Err(HelperError::new(
            ErrorCode::UnsupportedRules,
            "temporary rules exceed the limit or contain a group",
        ));
    }
    if request.lists.len() > MAX_TEMPORARY_RULES {
        return Err(HelperError::new(
            ErrorCode::InvalidState,
            "too many list references",
        ));
    }
    if request.extra_nodes.len() > MAX_EXTRA_NODES {
        return Err(HelperError::new(
            ErrorCode::InvalidRequest,
            "too many extra nodes",
        ));
    }
    let mut exits = std::collections::HashSet::new();
    if request
        .extra_nodes
        .iter()
        .any(|extra| !exits.insert(&extra.exit))
    {
        return Err(HelperError::new(
            ErrorCode::InvalidRequest,
            "duplicate extra node for an exit",
        ));
    }
    for extra in &request.extra_nodes {
        if let Some(via) = &extra.via {
            let parent = request.extra_nodes.iter().find(|entry| &entry.exit == via);
            if via == &extra.exit || parent.is_none_or(|entry| entry.via.is_some()) {
                return Err(HelperError::new(
                    ErrorCode::InvalidRequest,
                    "invalid exit dependency graph",
                ));
            }
        }
    }
    request
        .validate_exit_chains()
        .map_err(|error| HelperError::new(ErrorCode::UnsupportedRules, error.to_string()))?;
    let rules = request.effective_rule_set();
    if rules.enabled().any(|rule| {
        rule.target == RuleTarget::Exit && rule.exit.as_ref().is_none_or(|id| !exits.contains(id))
    }) {
        return Err(HelperError::new(
            ErrorCode::InvalidRequest,
            "exit rule has no matching extra node",
        ));
    }
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

/// Polls the engine and publishes traffic into the status.
struct TrafficMonitor {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    status: Arc<Mutex<Status>>,
    connections: Arc<Mutex<ConnectionBook>>,
}

impl TrafficMonitor {
    /// Also collects the session's connections while someone reads them.
    fn start(
        mut probe: Box<dyn TrafficProbe>,
        status: Arc<Mutex<Status>>,
        connections: Arc<Mutex<ConnectionBook>>,
        translation: Translation,
    ) -> std::io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker_status = Arc::clone(&status);
        let worker_connections = Arc::clone(&connections);
        let thread = thread::Builder::new()
            .name("engine-traffic".to_owned())
            .spawn(move || {
                let mut previous: Option<(TrafficTotals, Instant)> = None;
                let mut failed = false;
                let mut polled = Instant::now();
                loop {
                    let watched = loop {
                        if worker_stop.load(Ordering::Acquire) {
                            return;
                        }
                        let now = Instant::now();
                        let watched = worker_connections
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .watched(now);
                        if now.saturating_duration_since(polled) >= poll_interval(watched) {
                            break watched;
                        }
                        thread::sleep(MONITOR_TICK);
                    };
                    polled = Instant::now();

                    match probe.sample(watched) {
                        Ok(sample) => {
                            let totals = sample.totals;
                            let mut book = worker_connections
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            match sample.connections {
                                Some(list) if book.watched(Instant::now()) => book.record(
                                    translation.translate(list),
                                    connections::now_unix_ms(),
                                ),
                                _ if !book.is_empty() => book.forget(),
                                _ => {}
                            }
                            drop(book);
                            if failed {
                                tracing::info!("engine traffic polling recovered");
                                failed = false;
                            }
                            let current = (totals, Instant::now());
                            let mut status = worker_status
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            match previous {
                                Some(start)
                                    if current.1.saturating_duration_since(start.1)
                                        < RATE_WINDOW => {}
                                _ => {
                                    (status.traffic.up_bps, status.traffic.down_bps) = previous
                                        .map(|previous| rates(previous, current))
                                        .unwrap_or_default();
                                    previous = Some(current);
                                }
                            }
                            status.traffic.up_total = totals.up;
                            status.traffic.down_total = totals.down;
                        }
                        Err(error) => {
                            if !failed {
                                tracing::warn!(%error, "engine traffic polling failed");
                                failed = true;
                            }
                            let mut status = worker_status
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            connections,
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
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .traffic = Traffic::default();
        self.connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}

impl Drop for TrafficMonitor {
    fn drop(&mut self) {
        // A forgotten stop must not leave the worker polling the engine forever.
        self.stop.store(true, Ordering::Release);
    }
}

fn poll_interval(watched: bool) -> Duration {
    if watched {
        WATCHED_POLL_INTERVAL
    } else {
        TRAFFIC_POLL_INTERVAL
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
    pub(super) fn effective_tun_name<'a>(
        &'a self,
        tun: &'a rosetun_config::TunSettings,
    ) -> &'a str {
        self.active_tun_name.as_deref().unwrap_or(&tun.name)
    }

    fn wait_for_previous_adapter(&self, alias: &str) -> Result<(), HelperError> {
        self.stage(rosetun_config::ConnectStage::WaitingForAdapter)?;
        wait_for_previous_adapter_cancellable(
            alias,
            Duration::from_secs(20),
            Duration::from_millis(250),
            self.adapter_lookup,
            &self.cancelled,
        )?;
        self.stage(rosetun_config::ConnectStage::StartingEngine)
    }

    /// The addresses of the main node's server. While the network is not up
    /// yet it tries again every `NETWORK_WAIT_INTERVAL` up to `network_wait`;
    /// a name that does not exist fails at once.
    fn resolve_server(
        &self,
        server: &str,
        port: u16,
        lookup: NameLookup,
    ) -> Result<Vec<IpAddr>, HelperError> {
        let started = Instant::now();
        let mut waiting = false;
        loop {
            let failure = match (self.name_lookup)(server, port, lookup) {
                Ok(addresses) => {
                    if waiting {
                        let elapsed_ms = started.elapsed().as_millis();
                        tracing::info!(elapsed_ms, "the network is up");
                        self.stage(rosetun_config::ConnectStage::StartingEngine)?;
                    }
                    return Ok(addresses);
                }
                Err(failure) => failure,
            };
            let left = self.network_wait.saturating_sub(started.elapsed());
            if left.is_zero() || !self.network_is_down(&failure, server, lookup) {
                if waiting {
                    let elapsed_ms = started.elapsed().as_millis();
                    tracing::info!(elapsed_ms, "stopped waiting for the network");
                }
                let error = &failure.error;
                tracing::warn!(%server, %error, ?lookup, "failed to resolve the VPN endpoint");
                return Err(failure.error);
            }
            if !waiting {
                tracing::info!(
                    ?lookup,
                    "waiting for the network to look up the server name"
                );
                self.stage(rosetun_config::ConnectStage::WaitingForNetwork)?;
                waiting = true;
            }
            sleep_cancellable(left.min(NETWORK_WAIT_INTERVAL), &self.cancelled)?;
        }
    }

    /// Whether a failed lookup means the network is not up yet. Windows
    /// answers alike for a name that does not exist and a network that is not
    /// up, so a failure of the system resolver is checked with the network's
    /// own DNS servers. A connect asks before any protection is installed,
    /// so that question leaves the way the system resolver's did.
    fn network_is_down(&self, failure: &Unresolved, server: &str, lookup: NameLookup) -> bool {
        failure.offline || (lookup == NameLookup::System && (self.network_down)(server))
    }

    fn stage(&self, stage: rosetun_config::ConnectStage) -> Result<(), HelperError> {
        let mut status = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        check_cancelled(&self.cancelled)?;
        status.connect_stage = Some(stage);
        status.stage_since_unix = Some(now_unix());
        Ok(())
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

    fn resolve_node_endpoints(
        &self,
        node: &Node,
        lookup: NameLookup,
    ) -> Result<ResolvedNodeEndpoints, HelperError> {
        let rosetun_config::Outbound::XrayBalancer(balancer) = &node.outbound else {
            let ip = select_endpoint(&self.resolve_server(&node.server, node.port, lookup)?)?;
            return Ok(ResolvedNodeEndpoints::single(&node.server, ip));
        };
        let mut members = HashMap::new();
        let mut primary = None;
        let mut first_error = None;
        for member in &balancer.members {
            let key = normalize_server(&member.server);
            if let Some(&existing) = members.get(&key) {
                primary.get_or_insert(existing);
                continue;
            }
            if let Ok(ip) = member.server.parse::<IpAddr>() {
                members.insert(key, ip);
                primary.get_or_insert(ip);
                continue;
            }
            match (self.name_lookup)(&member.server, member.port, lookup)
                .map_err(|failure| failure.error)
                .and_then(|addresses| select_endpoint(&addresses))
            {
                Ok(ip) => {
                    members.insert(key, ip);
                    primary.get_or_insert(ip);
                }
                Err(error) => {
                    tracing::warn!(
                        server = %member.server,
                        %error,
                        ?lookup,
                        "failed to resolve an Xray balancer member endpoint"
                    );
                    first_error.get_or_insert(error);
                }
            }
        }
        if let Some(primary) = primary {
            return Ok(ResolvedNodeEndpoints::from_members(primary, members));
        }
        // Zero members resolved: if network_wait is active, wait on the first
        // member so offline startup still retries until the network comes up.
        if !self.network_wait.is_zero()
            && let Some(first) = balancer.members.first()
        {
            let ip = select_endpoint(&self.resolve_server(&first.server, first.port, lookup)?)?;
            members.insert(normalize_server(&first.server), ip);
            for member in balancer.members.iter().skip(1) {
                let key = normalize_server(&member.server);
                if members.contains_key(&key) {
                    continue;
                }
                if let Ok(addr) = member.server.parse::<IpAddr>() {
                    members.insert(key, addr);
                } else if let Ok(addr) = (self.name_lookup)(&member.server, member.port, lookup)
                    .map_err(|failure| failure.error)
                    .and_then(|addresses| select_endpoint(&addresses))
                {
                    members.insert(key, addr);
                }
            }
            return Ok(ResolvedNodeEndpoints::from_members(ip, members));
        }
        Err(first_error.unwrap_or_else(|| {
            HelperError::new(
                ErrorCode::ServerNameUnresolved,
                "failed to resolve any Xray balancer member endpoint",
            )
        }))
    }

    fn start(
        &mut self,
        request: &ConnectRequest,
        mode: StartMode,
        endpoint: Option<ResolvedNodeEndpoints>,
        extra_endpoints: Option<Vec<Option<ResolvedNodeEndpoints>>>,
    ) -> Result<(), HelperError> {
        self.start_with_options(
            request,
            StartOptions {
                mode,
                endpoint,
                extra_endpoints,
                dns_timeout: self.dns_timeout,
            },
        )
    }

    fn start_with_options(
        &mut self,
        request: &ConnectRequest,
        options: StartOptions,
    ) -> Result<(), HelperError> {
        validate_request(request)?;
        let StartOptions {
            mode,
            endpoint,
            extra_endpoints,
            dns_timeout,
        } = options;
        let settings = &request.settings;
        // Dispose of the old process before borrowing the backend or spawning another.
        // A stop failure retains its handle and prevents a second engine from starting.
        self.stop_engine()?;
        self.protection.begin_attempt(settings);
        let physical = (self.physical_interface)(&settings.tun.name).ok_or_else(|| {
            HelperError::new(ErrorCode::NoNetwork, "physical network is unavailable")
        })?;

        if settings.connection_mode == rosetun_config::ConnectionMode::Tun {
            self.wait_for_previous_adapter(&settings.tun.name)?;
            self.tunnel_egress = Some(physical);
        }

        if mode == StartMode::Fresh {
            self.protection
                .release("failed to roll back stale routing protection");
        }

        if mode == StartMode::ProtectedReconnect {
            if !self.protection.is_active() {
                return Err(HelperError::new(
                    ErrorCode::RoutingFailed,
                    "protected reconnect is impossible: the routing guard is missing",
                ));
            }
            if !settings.kill_switch
                && self.protection.keeps_protection()
                && !lockdown::read(&self.lockdown).enabled
            {
                return Err(HelperError::new(
                    ErrorCode::InvalidState,
                    "disconnect first to turn protection off",
                ));
            }
        }

        self.start_proxy(
            request,
            StartOptions {
                mode,
                endpoint,
                extra_endpoints,
                dns_timeout,
            },
        )
    }

    /// Who looks a new server's name up during this session.
    fn engine_lookup(&self) -> NameLookup {
        self.tunnel_dns
            .map_or(NameLookup::System, NameLookup::Engine)
    }

    fn record_chain(&self, status: &mut Status, request: &ConnectRequest) {
        status.record_chain(&request.node, &request.settings);
        status.xray = self
            .proxy_session
            .as_ref()
            .is_some_and(proxy_session::ProxySession::main_uses_xray);
        status.fragmented &= status.xray;
    }

    fn start_monitor(&mut self) {
        if let Some(proxy) = &self.proxy_session {
            let probe = proxy.dataplane.traffic_probe();
            let mut hidden: Vec<PathBuf> = std::env::current_exe().into_iter().collect();
            if let Some(xray) = self.xray.as_ref()
                && let Ok(binary) = xray.binary_path()
            {
                hidden.push(binary);
            }
            let translation = Translation {
                exit_tags: self.exit_tags.clone(),
                hidden,
            };
            match TrafficMonitor::start(
                probe,
                Arc::clone(&self.status),
                Arc::clone(&self.connections),
                translation,
            ) {
                Ok(monitor) => self.monitor = Some(monitor),
                Err(error) => tracing::warn!(%error, "traffic monitor is unavailable"),
            }
        }
    }

    fn start_watchdog(&mut self) {
        let Some(server) = self.tunnel_dns else {
            return;
        };
        #[cfg(target_os = "linux")]
        if !cfg!(test)
            && let Some(request) = &self.request
            && request.settings.connection_mode == rosetun_config::ConnectionMode::Tun
            && system_dns_linux::registered(&request.settings.tun.name, server.ip()) == Some(false)
        {
            tracing::warn!("systemd-resolved has not registered the tunnel DNS server");
            self.status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .tunnel_dns_unregistered = true;
        }
        let Some(proxy) = &self.proxy_session else {
            return;
        };
        let watchdog = DnsWatchdog::start_proxy(
            Arc::clone(&self.status),
            server,
            proxy.entry.clone(),
            self.watchdog_timing,
        );
        match watchdog {
            Ok(watchdog) => self.watchdog = Some(watchdog),
            Err(error) => tracing::warn!(%error, "DNS watchdog is unavailable"),
        }
    }

    fn live_engine_running(&mut self) -> bool {
        self.proxy_session
            .as_mut()
            .is_some_and(|proxy| proxy.exited().1.is_none())
    }

    fn check_live_tunnel(&mut self, timeout: Duration) -> Result<(), HelperError> {
        self.check_proxy_dns(timeout)
    }

    fn stop_engine(&mut self) -> Result<(), HelperError> {
        self.bypass.reset();
        self.tunnel_egress = None;
        self.active_tun_name = None;
        *self
            .shared_active_tun
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        self.status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .bypass_detected = false;
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
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .traffic = Traffic::default();
            self.connections
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
        }
        let mut reconnect_plan = None;
        if let Some(proxy) = self.proxy_session.as_mut() {
            proxy.stop()?;
            if let Some(scope) = self
                .protection
                .scope()
                .filter(|scope| *scope == ProtectionScope::AllTraffic)
            {
                let plan = RoutingPlan {
                    proxy_application: None,
                    shared_proxy: None,
                    scope,
                    lockdown: lockdown::read(&self.lockdown).enabled,
                    ..proxy.plan.clone()
                };
                reconnect_plan = Some(plan);
            }
        }
        self.proxy_session.take();
        if let Some(plan) = reconnect_plan {
            self.protection.prepare_reconnect(&plan)?;
        }
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
        self.protection.release("failed to roll back routes");
        self.protection.session_over();
        // Without a session no server is special: Lockdown's segment opens whole.
        if self.protection.programs_withdrawn() {
            self.lan.forget_servers();
            self.restore_lockdown_programs();
        } else if let Err(error) = self.follow_servers_in_lockdown(&[]) {
            tracing::error!(%error, "Lockdown's local network keeps a VPN server's address closed");
        }
        *self
            .owner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        self.owner.clear_poison();
    }
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

/// Writes what is visible about a tunnel that Windows still holds, without
/// changing anything. The node's address and the user's addresses are not
/// part of it; the tunnel's own address is.
fn failure_kind(error: &HelperError) -> Option<rosetun_config::FailureKind> {
    use rosetun_config::FailureKind;
    match error.code {
        ErrorCode::EngineNotReady => Some(FailureKind::EngineNotReady),
        ErrorCode::XrayStartFailed => Some(FailureKind::XrayStartFailed),
        ErrorCode::XrayStopped => Some(FailureKind::XrayStopped),
        ErrorCode::NoNetwork => Some(FailureKind::NoNetwork),
        ErrorCode::ServerUnreachable => Some(FailureKind::ServerUnreachable),
        ErrorCode::ServerRejected => Some(FailureKind::ServerRejected),
        ErrorCode::ServerClosed => Some(FailureKind::ServerClosed),
        ErrorCode::DnsTimeout => Some(FailureKind::DnsTimeout),
        ErrorCode::ServerNameUnresolved => Some(FailureKind::ServerNameUnresolved),
        ErrorCode::LocalProxyPortBusy => error
            .local_proxy_port()
            .map(|port| FailureKind::LocalProxyPortBusy { port }),
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

fn sleep_cancellable(duration: Duration, cancelled: &AtomicBool) -> Result<(), HelperError> {
    let deadline = Instant::now() + duration;
    loop {
        check_cancelled(cancelled)?;
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(());
        }
        thread::sleep(left.min(TUNNEL_READY_POLL_INTERVAL));
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

fn startup_timeout(hints: rosetun_engine::StartupHints, cold_start: bool) -> Duration {
    // Windows can stall in post-start after creating the TUN without emitting
    // the open-interface warning. Only observed progress gets that extra time.
    if hints.slow_tunnel_creation || cold_start || (cfg!(windows) && hints.tunnel_created) {
        SLOW_START_READY_TIMEOUT
    } else {
        TUNNEL_READY_TIMEOUT
    }
}

fn wait_for_engine_ready(process: &mut dyn EngineProcess) -> Result<(), HelperError> {
    wait_for_engine_ready_from(process, Instant::now(), false, &AtomicBool::new(false))
}

fn wait_for_engine_ready_from(
    process: &mut dyn EngineProcess,
    spawned_at: Instant,
    cold_start: bool,
    cancelled: &AtomicBool,
) -> Result<(), HelperError> {
    let mut progress_grace_logged = false;
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
        let hints = process.startup_hints();
        let timeout = startup_timeout(hints, cold_start);
        if !progress_grace_logged
            && !cold_start
            && hints.tunnel_created
            && spawned_at.elapsed() >= TUNNEL_READY_TIMEOUT
            && timeout > TUNNEL_READY_TIMEOUT
        {
            progress_grace_logged = true;
            tracing::warn!(
                elapsed_ms = spawned_at.elapsed().as_millis(),
                timeout_seconds = timeout.as_secs(),
                "TUN created; still waiting for final engine readiness"
            );
        }
        if Instant::now() >= spawned_at + timeout {
            tracing::warn!(
                elapsed_ms = spawned_at.elapsed().as_millis(),
                timeout_seconds = timeout.as_secs(),
                cold_start,
                tunnel_created = hints.tunnel_created,
                slow_tunnel_creation = hints.slow_tunnel_creation,
                adapter_still_removing = hints.adapter_still_removing,
                "engine startup readiness timed out"
            );
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

pub(super) fn protected_endpoints(
    node: &Node,
    cached: Option<&SuccessfulEndpoint>,
) -> Result<ResolvedNodeEndpoints, HelperError> {
    let err = || {
        HelperError::new(
            ErrorCode::RoutingFailed,
            "cannot resolve a new server name while protection is active; use an IP address or the last connected server",
        )
    };
    let rosetun_config::Outbound::XrayBalancer(balancer) = &node.outbound else {
        if let Ok(address) = node.server.parse::<IpAddr>() {
            return Ok(ResolvedNodeEndpoints::single(&node.server, address));
        }
        let address = cached
            .and_then(|endpoint| endpoint.lookup(&node.server))
            .ok_or_else(err)?;
        return Ok(ResolvedNodeEndpoints::single(&node.server, address));
    };
    let mut members = HashMap::new();
    let mut primary = None;
    for member in &balancer.members {
        let key = normalize_server(&member.server);
        if let Some(&existing) = members.get(&key) {
            primary.get_or_insert(existing);
            continue;
        }
        let ip = member
            .server
            .parse::<IpAddr>()
            .ok()
            .or_else(|| cached.and_then(|endpoint| endpoint.lookup(&member.server)));
        if let Some(ip) = ip {
            members.insert(key, ip);
            primary.get_or_insert(ip);
        }
    }
    primary
        .map(|primary| ResolvedNodeEndpoints::from_members(primary, members))
        .ok_or_else(err)
}

#[cfg(test)]
fn protected_endpoint(
    node: &Node,
    cached: Option<&SuccessfulEndpoint>,
) -> Result<IpAddr, HelperError> {
    protected_endpoints(node, cached).map(|resolved| resolved.primary)
}

/// Who looks a server name up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameLookup {
    System,
    /// The service's own queries to the network's DNS servers. Under Lockdown
    /// without a tunnel the system resolver cannot get out: on Windows its
    /// queries leave from Dnscache, which Lockdown must never permit, since
    /// every program's lookups go through it.
    Direct,
    /// The engine's own DNS on loopback, in the proxy mode: there is no tunnel
    /// to carry the system resolver's queries, and with a kill switch they
    /// could not leave at all.
    Engine(SocketAddr),
}

impl NameLookup {
    /// Direct only while Lockdown is on and no tunnel carries the system
    /// resolver's queries; through the tunnel they do not leak.
    fn new(lockdown: bool, tunnel_up: bool) -> Self {
        if lockdown && !tunnel_up {
            Self::Direct
        } else {
            Self::System
        }
    }
}

/// Matches the server check's wait for the system resolver.
const DIRECT_RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// A server name that was not looked up.
#[derive(Debug)]
struct Unresolved {
    error: HelperError,
    /// The network is not up yet, so a later try may succeed.
    offline: bool,
}

fn resolve_quiet(server: &str, port: u16, lookup: NameLookup) -> Result<Vec<IpAddr>, HelperError> {
    lookup_name(server, port, lookup).map_err(|failure| failure.error)
}

fn lookup_name(server: &str, port: u16, lookup: NameLookup) -> Result<Vec<IpAddr>, Unresolved> {
    // The status carries this message to the GUI and to reports; the
    // server's name stays in the log line of `Session::resolve_server`.
    let failed = |error: &dyn std::fmt::Display, offline| Unresolved {
        error: HelperError::new(
            ErrorCode::ServerNameUnresolved,
            format!("failed to resolve the VPN server name: {error}"),
        ),
        offline,
    };
    let addresses = match lookup {
        NameLookup::System => (server, port)
            .to_socket_addrs()
            .map_err(|error| failed(&error, false))?
            .map(|address| address.ip())
            .collect::<Vec<_>>(),
        NameLookup::Direct => {
            rosetun_dns::resolve(server, DIRECT_RESOLVE_TIMEOUT).map_err(|error| {
                let offline = matches!(
                    error,
                    rosetun_dns::ResolveError::NoServers | rosetun_dns::ResolveError::Unreachable
                );
                failed(&error, offline)
            })?
        }
        NameLookup::Engine(address) => dns::resolve_name(address, server, DIRECT_RESOLVE_TIMEOUT)
            .into_iter()
            .map(IpAddr::V4)
            .collect(),
    };

    if addresses.is_empty() {
        return Err(Unresolved {
            error: HelperError::new(
                ErrorCode::ServerNameUnresolved,
                "the VPN server name resolved to no addresses",
            ),
            offline: false,
        });
    }

    Ok(addresses)
}

/// Asks the network's DNS servers directly: no server, or sockets that fail
/// before any reply, mean the network is not up yet.
#[cfg(not(test))]
fn network_down(server: &str) -> bool {
    rosetun_dns::wire::labels(server).is_some()
        && matches!(
            rosetun_dns::resolve(server, NETWORK_PROBE_TIMEOUT),
            Err(rosetun_dns::ResolveError::NoServers | rosetun_dns::ResolveError::Unreachable)
        )
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

fn preserve_stream_host(original_server: &str, stream: &mut rosetun_config::StreamSettings) {
    use rosetun_config::{TlsMode, Transport};

    if original_server.parse::<IpAddr>().is_err() {
        match &mut stream.tls {
            TlsMode::Tls(params) => {
                params.sni.get_or_insert_with(|| original_server.to_owned());
            }
            TlsMode::Reality(params) => {
                params.sni.get_or_insert_with(|| original_server.to_owned());
            }
            TlsMode::Plain => {}
        }

        match &mut stream.transport {
            Transport::Ws { host, .. }
            | Transport::HttpUpgrade { host, .. }
            | Transport::Xhttp { host, .. } => {
                host.get_or_insert_with(|| original_server.to_owned());
            }
            Transport::Tcp | Transport::Grpc { .. } => {}
        }
    }
}

fn node_with_endpoint(node: &Node, endpoint: IpAddr) -> Node {
    let mut prepared = node.clone();
    preserve_stream_host(&node.server, &mut prepared.stream);
    prepared.server = endpoint.to_string();
    prepared
}

pub(super) fn node_with_endpoints(node: &Node, endpoints: &ResolvedNodeEndpoints) -> Node {
    let mut prepared = node.clone();
    let rosetun_config::Outbound::XrayBalancer(balancer) = &mut prepared.outbound else {
        preserve_stream_host(&node.server, &mut prepared.stream);
        prepared.server = endpoints.primary.to_string();
        return prepared;
    };

    let mut kept = Vec::with_capacity(balancer.members.len());
    for mut member in std::mem::take(&mut balancer.members) {
        if let Some(ip) = endpoints.ip_for(&member.server) {
            preserve_stream_host(&member.server, &mut member.stream);
            member.server = ip.to_string();
            kept.push(member);
        }
    }
    if kept.is_empty() {
        // Unreachable when `endpoints` came from resolving `node`, but never emit
        // an empty balancer.
        prepared.server = endpoints.primary.to_string();
        return prepared;
    }

    prepared.server = kept[0].server.clone();
    prepared.port = kept[0].port;
    balancer.members = kept;

    if let Some(fallback) = balancer.fallback_tag.as_deref()
        && !balancer.members.iter().any(|m| m.tag == fallback)
    {
        balancer.fallback_tag = None;
    }

    balancer.selector.retain(|prefix| {
        balancer
            .members
            .iter()
            .any(|m| m.tag.starts_with(prefix.as_str()))
    });
    if balancer.selector.is_empty() {
        let first_tag = balancer.members[0].tag.clone();
        if balancer.fallback_tag.as_deref() == Some(first_tag.as_str()) {
            balancer.fallback_tag = None;
        }
        balancer.selector.push(first_tag);
    }

    if let Some(observatory) = &mut balancer.observatory {
        let subject_selector = match observatory {
            rosetun_config::XrayObservatory::Standard(obs) => &mut obs.subject_selector,
            rosetun_config::XrayObservatory::Burst(obs) => &mut obs.subject_selector,
        };
        subject_selector.retain(|prefix| {
            balancer
                .members
                .iter()
                .any(|m| m.tag.starts_with(prefix.as_str()))
        });
        if subject_selector.is_empty() {
            *subject_selector = balancer.selector.clone();
        }
    }

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
