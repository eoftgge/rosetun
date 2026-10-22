use rosetun_config::{
    DomainMatch, EngineKind, ExitId, NodeId, Outbound, Rule, RuleId, RuleMatcher, RuleSet,
    RuleSetId, RuleTarget, RuleTemplate, Selection, Settings, SubscriptionId, Traffic, VlessParams,
};
use rosetun_engine::errors::EngineError;
use rosetun_engine::{
    EngineBackend, EngineCapabilities, EngineConnection, EngineIntegration, EngineRoute,
    RenderedConfig, RuleCapabilities, TrafficSample,
};
use rosetun_ipc::{ExtraNode, SessionExit, TunnelDelays};
use rosetun_routing::errors::RoutingError;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

use super::*;

static DNS_SLOTS: Mutex<()> = Mutex::new(());
static ROUTE_TEST_LOCK: Mutex<()> = Mutex::new(());
static ROUTE_SCRIPT: Mutex<VecDeque<bool>> = Mutex::new(VecDeque::new());
static ROUTE_CHECKS: AtomicUsize = AtomicUsize::new(0);
static NETWORK_PRESENT: AtomicBool = AtomicBool::new(true);

fn route_then_disappears(_: &str) -> Option<String> {
    (ROUTE_CHECKS.fetch_add(1, Ordering::AcqRel) == 0).then(|| "Ethernet".to_owned())
}

fn changing_route(_: &str) -> Option<String> {
    NETWORK_PRESENT
        .load(Ordering::Acquire)
        .then(|| "Ethernet".to_owned())
}

fn scripted_route(_: &str) -> Option<String> {
    ROUTE_SCRIPT
        .lock()
        .unwrap()
        .pop_front()
        .expect("unexpected physical route lookup")
        .then(|| "Ethernet".to_owned())
}

fn set_route_script(down_ticks: usize) {
    let mut script = ROUTE_SCRIPT.lock().unwrap();
    *script = std::iter::once(true)
        .chain(std::iter::repeat_n(false, down_ticks))
        .chain(std::iter::repeat_n(true, 20))
        .collect();
}

#[test]
fn startup_hint_extends_only_slow_tunnel_deadline() {
    assert_eq!(
        startup_timeout(rosetun_engine::StartupHints::default(), false),
        Duration::from_secs(15)
    );
    assert_eq!(
        startup_timeout(
            rosetun_engine::StartupHints {
                slow_tunnel_creation: true,
                ..Default::default()
            },
            false
        ),
        Duration::from_secs(45)
    );
}

#[test]
fn a_cold_start_gets_the_slow_start_deadline() {
    assert_eq!(
        startup_timeout(rosetun_engine::StartupHints::default(), true),
        Duration::from_secs(45)
    );
}

#[test]
fn the_first_engine_start_is_cold_and_clears_it_on_success() {
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(StubEngine));
    let helper = Helper::new(engines, Box::new(UnusedRouting), VerboseGate::default());
    assert!(helper.session().unwrap().cold_start);
    let mut request = connect_request();
    request.settings.kill_switch = false;

    helper.connect(&request).expect("connect succeeds");
    assert!(!helper.session().unwrap().cold_start);

    helper.disconnect().unwrap();
    helper.connect(&request).expect("connect succeeds again");
    assert!(!helper.session().unwrap().cold_start);
    helper.disconnect().unwrap();
}

#[test]
fn a_failed_first_engine_start_clears_the_cold_start_too() {
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(ExitedEngine));
    let helper = Helper::new(engines, Box::new(UnusedRouting), VerboseGate::default());
    let mut request = connect_request();
    request.settings.kill_switch = false;

    helper
        .connect(&request)
        .expect_err("an exited process cannot complete startup readiness");
    assert!(!helper.session().unwrap().cold_start);
}

#[test]
fn a_connect_refused_before_the_engine_starts_stays_cold() {
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(UnsupportedRuleEngine));
    let helper = Helper::new(engines, Box::new(UnusedRouting), VerboseGate::default());

    helper
        .connect(&connect_request())
        .expect_err("unsupported rules reject the connection");
    assert!(helper.session().unwrap().cold_start);
}

#[test]
fn server_check_grace_needs_a_slow_hint_or_late_readiness() {
    let spawned_at = Instant::now();
    let fast = spawned_at + Duration::from_secs(5);
    let late = fast + Duration::from_millis(1);
    let hints = rosetun_engine::StartupHints::default();
    assert_eq!(
        server_check_grace_deadline(hints, spawned_at, fast, SERVER_CHECK_GRACE),
        None
    );
    assert_eq!(
        server_check_grace_deadline(hints, spawned_at, late, SERVER_CHECK_GRACE),
        Some(late + SERVER_CHECK_GRACE)
    );
    let slow = rosetun_engine::StartupHints {
        slow_tunnel_creation: true,
        ..Default::default()
    };
    assert_eq!(
        server_check_grace_deadline(slow, spawned_at, spawned_at, SERVER_CHECK_GRACE),
        Some(spawned_at + SERVER_CHECK_GRACE)
    );
}

#[test]
fn previous_adapter_waits_until_it_disappears() {
    let mut calls = 0;
    wait_for_previous_adapter(
        "test-tun",
        Duration::from_secs(1),
        Duration::from_millis(1),
        |_| {
            calls += 1;
            Ok(calls < 3)
        },
    )
    .unwrap();
    assert_eq!(calls, 3);
}

#[test]
fn previous_adapter_wait_has_a_deadline() {
    let started = Instant::now();
    let result = wait_for_previous_adapter(
        "test-tun",
        Duration::from_millis(5),
        Duration::from_millis(1),
        |_| Ok(true),
    );
    assert!(result.is_ok(), "start after the adapter removal deadline");
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn previous_adapter_lookup_errors_do_not_block_startup() {
    wait_for_previous_adapter(
        "test-tun",
        Duration::from_secs(1),
        Duration::from_millis(1),
        |_| Err(std::io::Error::other("test lookup failure")),
    )
    .unwrap();
}

fn reserve_apply_worker() -> super::probe::ApplyDnsWorkerSlot {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(slot) = super::probe::ApplyDnsWorkerSlot::acquire() {
            return slot;
        }
        assert!(Instant::now() < deadline, "apply DNS worker remained busy");
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[derive(Debug)]
struct BlockingRouting {
    entered: Sender<()>,
    release: Receiver<()>,
    received_plan: Arc<Mutex<Option<RoutingPlan>>>,
}

impl RoutingBackend for BlockingRouting {
    fn name(&self) -> &'static str {
        "test-blocking"
    }

    fn preflight(&self) -> Result<(), RoutingError> {
        Ok(())
    }

    fn begin_protection(
        &mut self,
        plan: &RoutingPlan,
        _engine_binaries: &[&Path],
    ) -> Result<RoutingGuard, RoutingError> {
        *self
            .received_plan
            .lock()
            .expect("test routing plan mutex is not poisoned") = Some(plan.clone());
        self.entered
            .send(())
            .expect("test observes protection setup");
        self.release.recv().expect("test releases protection setup");
        Ok(RoutingGuard::noop())
    }
}

#[derive(Debug)]
struct UnusedRouting;

impl RoutingBackend for UnusedRouting {
    fn name(&self) -> &'static str {
        "test-unused"
    }

    fn preflight(&self) -> Result<(), RoutingError> {
        panic!("routing must not run without the kill switch or a tunnel DNS server");
    }

    fn begin_protection(
        &mut self,
        _plan: &RoutingPlan,
        _engine_binaries: &[&Path],
    ) -> Result<RoutingGuard, RoutingError> {
        panic!("routing must not run without the kill switch or a tunnel DNS server");
    }
}

#[derive(Debug)]
struct AuthorizingRouting {
    spawned: Option<Receiver<()>>,
    authorized: Sender<TunnelInterface>,
}

impl RoutingBackend for AuthorizingRouting {
    fn name(&self) -> &'static str {
        "test-authorizing"
    }

    fn preflight(&self) -> Result<(), RoutingError> {
        Ok(())
    }

    fn begin_protection(
        &mut self,
        _plan: &RoutingPlan,
        _engine_binaries: &[&Path],
    ) -> Result<RoutingGuard, RoutingError> {
        let spawned = self
            .spawned
            .take()
            .expect("bootstrap protection is created only once");
        let authorized = self.authorized.clone();

        Ok(RoutingGuard::new_with_authorizer(
            move |tunnel| {
                spawned
                    .recv()
                    .expect("engine must spawn before phase-2 authorization");
                authorized
                    .send(tunnel.clone())
                    .expect("test observes tunnel authorization");
                Ok(())
            },
            || Ok(()),
        ))
    }
}

#[derive(Debug)]
struct StubEngine;

#[derive(Debug)]
struct UnsupportedRuleEngine;

impl EngineBackend for UnsupportedRuleEngine {
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

    fn tunnel_dns_server(
        &self,
        _tun: &rosetun_config::TunSettings,
    ) -> Option<std::net::SocketAddr> {
        None
    }

    fn locate_binary(&self) -> Result<PathBuf, EngineError> {
        panic!("the helper must reject unsupported rules before locating the engine binary");
    }

    fn render(&self, _request: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError> {
        Ok(RenderedConfig {
            file_name: "config.json".to_owned(),
            body: Vec::new(),
            unsupported: vec![RuleId::new("unsupported-rule")],
            unsupported_probes: Vec::new(),
        })
    }

    fn spawn(
        &self,
        _binary: &Path,
        _config: &RenderedConfig,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        panic!("the helper must reject unsupported rules before spawning the engine");
    }
}

impl EngineBackend for StubEngine {
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
        Ok(PathBuf::from("sing-box"))
    }

    fn tunnel_dns_server(
        &self,
        _tun: &rosetun_config::TunSettings,
    ) -> Option<std::net::SocketAddr> {
        None
    }

    fn render(&self, _request: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError> {
        Ok(RenderedConfig {
            file_name: "config.json".to_owned(),
            body: Vec::new(),
            unsupported: Vec::new(),
            unsupported_probes: Vec::new(),
        })
    }

    fn spawn(
        &self,
        _binary: &Path,
        _config: &RenderedConfig,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        Ok(Box::new(StubProcess))
    }
}

#[derive(Debug)]
struct StubProcess;

impl EngineProcess for StubProcess {
    fn is_running(&mut self) -> Result<bool, EngineError> {
        Ok(true)
    }

    fn stop(&mut self) -> Result<(), EngineError> {
        Ok(())
    }
}

#[derive(Debug)]
struct SpawnSignalingEngine {
    spawned: Sender<()>,
}

impl EngineBackend for SpawnSignalingEngine {
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

    fn tunnel_dns_server(
        &self,
        _tun: &rosetun_config::TunSettings,
    ) -> Option<std::net::SocketAddr> {
        None
    }

    fn locate_binary(&self) -> Result<PathBuf, EngineError> {
        Ok(PathBuf::from("sing-box"))
    }

    fn render(&self, _request: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError> {
        Ok(RenderedConfig {
            file_name: "config.json".to_owned(),
            body: Vec::new(),
            unsupported: Vec::new(),
            unsupported_probes: Vec::new(),
        })
    }

    fn spawn(
        &self,
        _binary: &Path,
        _config: &RenderedConfig,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        self.spawned
            .send(())
            .expect("routing authorization observes engine spawn");
        Ok(Box::new(StubProcess))
    }
}

#[derive(Debug)]
struct ExitedProcess;

impl EngineProcess for ExitedProcess {
    fn is_running(&mut self) -> Result<bool, EngineError> {
        Ok(false)
    }

    fn stop(&mut self) -> Result<(), EngineError> {
        Ok(())
    }
}

#[derive(Debug)]
struct ExitedEngine;

impl EngineBackend for ExitedEngine {
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

    fn tunnel_dns_server(
        &self,
        _tun: &rosetun_config::TunSettings,
    ) -> Option<std::net::SocketAddr> {
        None
    }

    fn locate_binary(&self) -> Result<PathBuf, EngineError> {
        Ok(PathBuf::from("sing-box"))
    }

    fn render(&self, _request: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError> {
        Ok(RenderedConfig {
            file_name: "config.json".to_owned(),
            body: Vec::new(),
            unsupported: Vec::new(),
            unsupported_probes: Vec::new(),
        })
    }

    fn spawn(
        &self,
        _binary: &Path,
        _config: &RenderedConfig,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        Ok(Box::new(ExitedProcess))
    }
}

#[derive(Debug)]
struct RunningThenExitedProcess {
    running: Arc<AtomicBool>,
}

impl EngineProcess for RunningThenExitedProcess {
    fn is_running(&mut self) -> Result<bool, EngineError> {
        Ok(self.running.load(Ordering::Acquire))
    }

    fn stop(&mut self) -> Result<(), EngineError> {
        Ok(())
    }
}

#[derive(Debug)]
struct RunningThenExitedEngine {
    running: Arc<AtomicBool>,
}

impl EngineBackend for RunningThenExitedEngine {
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

    fn tunnel_dns_server(
        &self,
        _tun: &rosetun_config::TunSettings,
    ) -> Option<std::net::SocketAddr> {
        None
    }

    fn locate_binary(&self) -> Result<PathBuf, EngineError> {
        Ok(PathBuf::from("sing-box"))
    }

    fn render(&self, _request: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError> {
        Ok(RenderedConfig {
            file_name: "config.json".to_owned(),
            body: Vec::new(),
            unsupported: Vec::new(),
            unsupported_probes: Vec::new(),
        })
    }

    fn spawn(
        &self,
        _binary: &Path,
        _config: &RenderedConfig,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        Ok(Box::new(RunningThenExitedProcess {
            running: Arc::clone(&self.running),
        }))
    }
}

#[derive(Debug, Default)]
struct EngineControls {
    spawns: AtomicUsize,
    events: Mutex<Vec<&'static str>>,
    running: Mutex<Option<Arc<AtomicBool>>>,
    outcomes: Mutex<VecDeque<bool>>,
    readiness: Mutex<VecDeque<bool>>,
    adapter_busy: Mutex<VecDeque<bool>>,
    rendered_rules: Mutex<Vec<RuleSet>>,
    /// Server addresses of the extra nodes in each render.
    rendered_extra: Mutex<Vec<Vec<String>>>,
    render_block: Mutex<Option<(Sender<()>, Receiver<()>)>>,
}

impl EngineControls {
    fn fail_next(&self, count: usize) {
        self.outcomes
            .lock()
            .expect("test outcomes mutex")
            .extend(std::iter::repeat_n(false, count));
    }

    /// The next starts exit like sing-box while Windows removes the old adapter.
    fn adapter_busy_next(&self, count: usize) {
        self.adapter_busy
            .lock()
            .unwrap()
            .extend(std::iter::repeat_n(true, count));
    }

    fn fail_readiness_next(&self, count: usize) {
        self.readiness
            .lock()
            .expect("test readiness mutex")
            .extend(std::iter::repeat_n(false, count));
    }

    fn kill(&self) {
        self.running
            .lock()
            .expect("test process mutex")
            .as_ref()
            .expect("engine is running")
            .store(false, Ordering::Release);
    }

    fn spawns(&self) -> usize {
        self.spawns.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
struct ControlledEngine {
    controls: Arc<EngineControls>,
    dns_server: Option<SocketAddr>,
}

impl EngineBackend for ControlledEngine {
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

    fn tunnel_dns_server(
        &self,
        _tun: &rosetun_config::TunSettings,
    ) -> Option<std::net::SocketAddr> {
        self.dns_server
    }

    fn locate_binary(&self) -> Result<PathBuf, EngineError> {
        Ok(PathBuf::from("sing-box"))
    }

    fn render(&self, request: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError> {
        if let Some((entered, release)) = self.controls.render_block.lock().unwrap().take() {
            entered.send(()).unwrap();
            release.recv().unwrap();
        }
        self.controls
            .rendered_rules
            .lock()
            .expect("test rendered rules mutex")
            .push(request.rules.clone());
        self.controls.rendered_extra.lock().unwrap().push(
            request
                .extra
                .iter()
                .map(|extra| extra.node.server.clone())
                .collect(),
        );
        Ok(RenderedConfig {
            file_name: "config.json".to_owned(),
            body: Vec::new(),
            unsupported: request
                .rules
                .rules
                .iter()
                .filter(|rule| rule.id == RuleId::new("unsupported-rule"))
                .map(|rule| rule.id.clone())
                .collect(),
            unsupported_probes: Vec::new(),
        })
    }

    fn spawn(
        &self,
        _binary: &Path,
        _config: &RenderedConfig,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        self.controls.events.lock().unwrap().push("sing-box");
        self.controls.spawns.fetch_add(1, Ordering::AcqRel);
        if self
            .controls
            .outcomes
            .lock()
            .expect("test outcomes mutex")
            .pop_front()
            == Some(false)
        {
            return Err(EngineError::BinaryNotFound("test engine".to_owned()));
        }
        let adapter_busy = self
            .controls
            .adapter_busy
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(false);
        let running = Arc::new(AtomicBool::new(!adapter_busy));
        *self.controls.running.lock().expect("test process mutex") = Some(Arc::clone(&running));
        let ready = self
            .controls
            .readiness
            .lock()
            .expect("test readiness mutex")
            .pop_front()
            .unwrap_or(true);
        Ok(Box::new(ControlledProcess {
            running,
            ready,
            adapter_busy,
        }))
    }
}

#[derive(Debug)]
struct ControlledProcess {
    running: Arc<AtomicBool>,
    ready: bool,
    adapter_busy: bool,
}

impl EngineProcess for ControlledProcess {
    fn startup_hints(&self) -> rosetun_engine::StartupHints {
        rosetun_engine::StartupHints {
            adapter_still_removing: self.adapter_busy,
            ..Default::default()
        }
    }

    fn is_running(&mut self) -> Result<bool, EngineError> {
        Ok(self.running.load(Ordering::Acquire))
    }

    fn is_ready(&mut self) -> Result<bool, EngineError> {
        if !self.ready {
            self.running.store(false, Ordering::Release);
        }
        Ok(self.ready)
    }

    fn stop(&mut self) -> Result<(), EngineError> {
        self.running.store(false, Ordering::Release);
        Ok(())
    }
}

#[derive(Debug)]
struct ReconnectRouting {
    prepared: Arc<AtomicUsize>,
    reverted: Arc<AtomicUsize>,
}

impl RoutingBackend for ReconnectRouting {
    fn name(&self) -> &'static str {
        "test-reconnect"
    }

    fn preflight(&self) -> Result<(), RoutingError> {
        Ok(())
    }

    fn begin_protection(
        &mut self,
        _plan: &RoutingPlan,
        _engine_binaries: &[&Path],
    ) -> Result<RoutingGuard, RoutingError> {
        let prepared = Arc::clone(&self.prepared);
        let reverted = Arc::clone(&self.reverted);
        Ok(RoutingGuard::new_with_reconnector(
            move |_, _| {
                prepared.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
            |_| Ok(()),
            move || {
                reverted.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        ))
    }
}

fn supervised_helper(
    protected: bool,
) -> (
    Helper,
    Arc<EngineControls>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    supervised_helper_with_dns(protected, None)
}

fn supervised_helper_with_dns(
    protected: bool,
    dns_server: Option<SocketAddr>,
) -> (
    Helper,
    Arc<EngineControls>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let controls = Arc::new(EngineControls::default());
    let prepared = Arc::new(AtomicUsize::new(0));
    let reverted = Arc::new(AtomicUsize::new(0));
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(ControlledEngine {
        controls: Arc::clone(&controls),
        dns_server,
    }));
    let routing: Box<dyn RoutingBackend> = if protected || dns_server.is_some() {
        Box::new(ReconnectRouting {
            prepared: Arc::clone(&prepared),
            reverted: Arc::clone(&reverted),
        })
    } else {
        Box::new(UnusedRouting)
    };
    (
        Helper::new(engines, routing, VerboseGate::default()),
        controls,
        prepared,
        reverted,
    )
}

#[derive(Debug)]
struct CountingRouting {
    reverted: Arc<AtomicUsize>,
}

impl RoutingBackend for CountingRouting {
    fn name(&self) -> &'static str {
        "test-counting"
    }

    fn preflight(&self) -> Result<(), RoutingError> {
        Ok(())
    }

    fn begin_protection(
        &mut self,
        _plan: &RoutingPlan,
        _engine_binaries: &[&Path],
    ) -> Result<RoutingGuard, RoutingError> {
        let reverted = Arc::clone(&self.reverted);

        Ok(RoutingGuard::new_with_authorizer(
            |_tunnel| Ok(()),
            move || {
                reverted.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        ))
    }
}

#[derive(Debug)]
struct RejectingTunnelRouting {
    reverted: Arc<AtomicUsize>,
}

impl RoutingBackend for RejectingTunnelRouting {
    fn name(&self) -> &'static str {
        "test-rejecting-tunnel"
    }

    fn preflight(&self) -> Result<(), RoutingError> {
        Ok(())
    }

    fn begin_protection(
        &mut self,
        _plan: &RoutingPlan,
        _engine_binaries: &[&Path],
    ) -> Result<RoutingGuard, RoutingError> {
        let reverted = Arc::clone(&self.reverted);
        Ok(RoutingGuard::new_with_authorizer(
            |_tunnel| Err(RoutingError::Route("test rejection".to_owned())),
            move || {
                reverted.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        ))
    }
}

#[derive(Debug)]
struct FailingRouting;

impl RoutingBackend for FailingRouting {
    fn name(&self) -> &'static str {
        "test-failing"
    }

    fn preflight(&self) -> Result<(), RoutingError> {
        Err(RoutingError::Unsupported)
    }

    fn begin_protection(
        &mut self,
        _plan: &RoutingPlan,
        _engine_binaries: &[&Path],
    ) -> Result<RoutingGuard, RoutingError> {
        panic!("preflight failure must prevent installation");
    }
}

#[derive(Debug)]
struct DnsEngine {
    server: Option<std::net::SocketAddr>,
    stopped: Arc<AtomicUsize>,
}

impl EngineBackend for DnsEngine {
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

    fn tunnel_dns_server(
        &self,
        _tun: &rosetun_config::TunSettings,
    ) -> Option<std::net::SocketAddr> {
        self.server
    }

    fn locate_binary(&self) -> Result<PathBuf, EngineError> {
        Ok(PathBuf::from("sing-box"))
    }

    fn render(&self, _request: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError> {
        Ok(RenderedConfig {
            file_name: "config.json".to_owned(),
            body: Vec::new(),
            unsupported: Vec::new(),
            unsupported_probes: Vec::new(),
        })
    }

    fn spawn(
        &self,
        _binary: &Path,
        _config: &RenderedConfig,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        Ok(Box::new(DnsProcess {
            stopped: Arc::clone(&self.stopped),
        }))
    }
}

#[derive(Debug)]
struct DnsProcess {
    stopped: Arc<AtomicUsize>,
}

impl EngineProcess for DnsProcess {
    fn is_running(&mut self) -> Result<bool, EngineError> {
        Ok(true)
    }

    fn stop(&mut self) -> Result<(), EngineError> {
        self.stopped.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

#[derive(Debug)]
struct TrafficEngine {
    totals: TrafficTotals,
    dropped: Arc<AtomicUsize>,
    /// Polls that asked for the connection list.
    asked: Arc<AtomicUsize>,
    controls: Arc<Mutex<Vec<ControlEndpoint>>>,
    verbose_logs: Arc<Mutex<Vec<bool>>>,
    /// Ids the helper asked the engine to close.
    closed: Arc<Mutex<Vec<String>>>,
}

impl EngineBackend for TrafficEngine {
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

    fn tunnel_dns_server(
        &self,
        _tun: &rosetun_config::TunSettings,
    ) -> Option<std::net::SocketAddr> {
        None
    }

    fn locate_binary(&self) -> Result<PathBuf, EngineError> {
        Ok(PathBuf::from("sing-box"))
    }

    fn render(&self, request: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError> {
        self.controls
            .lock()
            .expect("test controls mutex")
            .push(request.control.expect("session control endpoint").clone());
        self.verbose_logs
            .lock()
            .expect("test verbose logs mutex")
            .push(request.verbose_log);
        Ok(RenderedConfig {
            file_name: "config.json".to_owned(),
            body: Vec::new(),
            unsupported: Vec::new(),
            unsupported_probes: Vec::new(),
        })
    }

    fn traffic_probe(&self, _control: &ControlEndpoint) -> Option<Box<dyn TrafficProbe>> {
        Some(Box::new(StubTrafficProbe {
            totals: self.totals,
            dropped: Arc::clone(&self.dropped),
            asked: Arc::clone(&self.asked),
        }))
    }

    fn close_connection(&self, _control: &ControlEndpoint, id: &str) -> Result<(), EngineError> {
        self.closed
            .lock()
            .expect("test closed mutex")
            .push(id.to_owned());
        Ok(())
    }

    fn spawn(
        &self,
        _binary: &Path,
        _config: &RenderedConfig,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        Ok(Box::new(StubProcess))
    }
}

#[derive(Debug)]
struct StubTrafficProbe {
    totals: TrafficTotals,
    dropped: Arc<AtomicUsize>,
    asked: Arc<AtomicUsize>,
}

impl TrafficProbe for StubTrafficProbe {
    fn sample(&mut self, connections: bool) -> Result<TrafficSample, EngineError> {
        if connections {
            self.asked.fetch_add(1, Ordering::AcqRel);
        }
        Ok(TrafficSample {
            totals: self.totals,
            connections: connections.then(|| {
                vec![EngineConnection {
                    id: "connection".to_owned(),
                    start_unix_ms: 1,
                    process: Some(r"C:\Program Files\Example\app.exe".to_owned()),
                    host: "example.com".to_owned(),
                    ip: None,
                    port: 443,
                    network: rosetun_config::ConnectionNetwork::Tcp,
                    route: EngineRoute::Proxy,
                    upload: 1,
                    download: 2,
                }]
            }),
        })
    }
}

impl Drop for StubTrafficProbe {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::AcqRel);
    }
}

fn wait_for_totals(helper: &Helper, totals: TrafficTotals) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let traffic = helper.status().traffic;
        if traffic.up_total == totals.up && traffic.down_total == totals.down {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "traffic totals were not published"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Records when it was asked and whether for connections; the first poll
/// that asks sees one connection, every later one sees none.
#[derive(Debug, Default)]
struct PollRecorder {
    polls: Arc<Polls>,
}

type Polls = Mutex<Vec<(Instant, bool)>>;

impl TrafficProbe for PollRecorder {
    fn sample(&mut self, connections: bool) -> Result<TrafficSample, EngineError> {
        let mut polls = self.polls.lock().expect("test polls mutex");
        polls.push((Instant::now(), connections));
        let first = polls.iter().filter(|(_, connections)| *connections).count() == 1;
        Ok(TrafficSample {
            totals: TrafficTotals::default(),
            connections: connections.then(|| {
                first
                    .then(|| EngineConnection {
                        id: "short".to_owned(),
                        start_unix_ms: 1,
                        process: None,
                        host: "example.com".to_owned(),
                        ip: None,
                        port: 443,
                        network: rosetun_config::ConnectionNetwork::Tcp,
                        route: EngineRoute::Proxy,
                        upload: 1,
                        download: 2,
                    })
                    .into_iter()
                    .collect()
            }),
        })
    }
}

fn start_recorded_monitor(
    book: ConnectionBook,
) -> (TrafficMonitor, Arc<Polls>, Arc<Mutex<ConnectionBook>>) {
    let probe = PollRecorder::default();
    let polls = Arc::clone(&probe.polls);
    let book = Arc::new(Mutex::new(book));
    let monitor = TrafficMonitor::start(
        Box::new(probe),
        Arc::new(Mutex::new(Status::default())),
        Arc::clone(&book),
        Translation::default(),
    )
    .expect("monitor thread starts");
    (monitor, polls, book)
}

fn wait_for_polls(polls: &Polls, count: usize) -> Vec<(Instant, bool)> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let seen = polls.lock().expect("test polls mutex").clone();
        if seen.len() >= count {
            return seen;
        }
        assert!(Instant::now() < deadline, "the engine was not polled");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_connection_seen_in_one_poll_is_closed_by_the_next_while_the_list_is_read() {
    let mut book = ConnectionBook::default();
    book.watch(Instant::now());
    let (monitor, polls, book) = start_recorded_monitor(book);

    let deadline = Instant::now() + Duration::from_secs(5);
    let closed = loop {
        let (_, closed) = book.lock().expect("test book mutex").snapshot();
        if !closed.is_empty() {
            break closed;
        }
        assert!(
            Instant::now() < deadline,
            "the short connection never closed"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let seen = polls.lock().expect("test polls mutex").clone();
    monitor.stop();

    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].host, "example.com");
    assert!(seen.iter().all(|(_, connections)| *connections));
    let gap = seen[1].0.saturating_duration_since(seen[0].0);
    assert!(
        gap < TRAFFIC_POLL_INTERVAL,
        "polled {gap:?} apart while read"
    );
}

#[test]
fn without_a_reader_the_engine_is_polled_once_a_second() {
    let (monitor, polls, _book) = start_recorded_monitor(ConnectionBook::default());
    let seen = wait_for_polls(&polls, 2);
    monitor.stop();

    assert!(seen.iter().all(|(_, connections)| !*connections));
    let gap = seen[1].0.saturating_duration_since(seen[0].0);
    assert!(
        gap >= TRAFFIC_POLL_INTERVAL - MONITOR_TICK,
        "polled {gap:?} apart without a reader"
    );
}

#[test]
fn rates_handle_elapsed_time_resets_and_zero_interval() {
    let instant = Instant::now();
    let first = (TrafficTotals { up: 500, down: 900 }, instant);
    let later = instant + Duration::from_millis(500);
    assert_eq!(
        rates(
            first,
            (
                TrafficTotals {
                    up: 1500,
                    down: 1900
                },
                later
            )
        ),
        (2000, 2000)
    );
    assert_eq!(
        rates(first, (TrafficTotals { up: 100, down: 200 }, later)),
        (0, 0)
    );
    assert_eq!(
        rates(
            first,
            (
                TrafficTotals {
                    up: 1500,
                    down: 1900
                },
                instant
            )
        ),
        (0, 0)
    );
}

#[test]
fn traffic_monitor_publishes_totals_and_stops_on_disconnect() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let controls = Arc::new(Mutex::new(Vec::new()));
    let totals = TrafficTotals {
        up: 1234,
        down: 5678,
    };
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(TrafficEngine {
        totals,
        dropped: Arc::clone(&dropped),
        asked: Arc::default(),
        controls: Arc::clone(&controls),
        verbose_logs: Arc::new(Mutex::new(Vec::new())),
        closed: Arc::default(),
    }));
    let helper = Helper::new(engines, Box::new(UnusedRouting), VerboseGate::default());
    let mut request = connect_request();
    request.settings.kill_switch = false;
    helper
        .connect(&request)
        .expect("connect with traffic probe");
    wait_for_totals(&helper, totals);
    assert_eq!(controls.lock().expect("test controls mutex").len(), 1);
    assert_eq!(dropped.load(Ordering::Acquire), 0);

    helper.disconnect().expect("disconnect stops monitor");
    assert_eq!(helper.status().traffic, Traffic::default());
    assert_eq!(dropped.load(Ordering::Acquire), 1);
}

fn connections_helper(asked: &Arc<AtomicUsize>) -> Helper {
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(TrafficEngine {
        totals: TrafficTotals { up: 1, down: 2 },
        dropped: Arc::default(),
        asked: Arc::clone(asked),
        controls: Arc::default(),
        verbose_logs: Arc::default(),
        closed: Arc::default(),
    }));
    Helper::new(engines, Box::new(UnusedRouting), VerboseGate::default())
}

fn closing_helper() -> (Helper, Arc<Mutex<Vec<String>>>) {
    let closed = Arc::new(Mutex::new(Vec::new()));
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(TrafficEngine {
        totals: TrafficTotals::default(),
        dropped: Arc::default(),
        asked: Arc::default(),
        controls: Arc::default(),
        verbose_logs: Arc::default(),
        closed: Arc::clone(&closed),
    }));
    let helper = Helper::new(engines, Box::new(UnusedRouting), VerboseGate::default());
    (helper, closed)
}

#[test]
fn the_owner_closes_a_connection_and_an_unknown_id_is_not_an_error() {
    let (helper, closed) = closing_helper();
    let owner = Caller::fake(b"owner", false);
    let mut request = connect_request();
    request.settings.kill_switch = false;
    helper.connect_as(&owner, &request).expect("owner connects");

    helper
        .close_connection_as(&owner, "connection")
        .expect("owner closes");
    helper
        .close_connection_as(&owner, "gone")
        .expect("an id that already closed");
    assert_eq!(*closed.lock().expect("closed"), ["connection", "gone"]);
    helper.disconnect_as(&owner).expect("owner disconnects");
}

#[test]
fn only_the_session_owner_closes_connections() {
    let (helper, closed) = closing_helper();
    let owner = Caller::fake(b"owner", false);
    let mut request = connect_request();
    request.settings.kill_switch = false;
    helper.connect_as(&owner, &request).expect("owner connects");

    for caller in [
        &Caller::fake(b"other", false),
        &Caller::fake(b"admin", true),
    ] {
        assert_eq!(
            helper
                .close_connection_as(caller, "connection")
                .unwrap_err()
                .code,
            ErrorCode::AccessDenied
        );
    }
    assert!(closed.lock().expect("closed").is_empty());
    helper.disconnect_as(&owner).expect("owner disconnects");
}

#[test]
fn closing_without_a_session_reads_like_the_list_and_sends_nothing() {
    let (helper, closed) = closing_helper();
    let owner = test_caller();
    assert_eq!(
        helper.connections_as(&owner).expect("no session"),
        (Vec::new(), Vec::new())
    );
    helper
        .close_connection_as(&owner, "connection")
        .expect("nothing to close");

    let mut request = connect_request();
    request.settings.kill_switch = false;
    helper.connect(&request).expect("connect");
    helper.disconnect().expect("disconnect");
    helper
        .close_connection_as(&owner, "connection")
        .expect("nothing to close after a disconnect");
    assert!(closed.lock().expect("closed").is_empty());
}

#[test]
fn an_empty_or_long_connection_id_is_refused_before_the_engine() {
    let (helper, closed) = closing_helper();
    let owner = test_caller();
    let mut request = connect_request();
    request.settings.kill_switch = false;
    helper.connect(&request).expect("connect");

    for id in [
        String::new(),
        "a".repeat(rosetun_engine::MAX_CONNECTION_ID_CHARS + 1),
    ] {
        assert_eq!(
            helper.close_connection_as(&owner, &id).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
    }
    helper
        .close_connection_as(&owner, &"a".repeat(rosetun_engine::MAX_CONNECTION_ID_CHARS))
        .expect("the longest id is accepted");
    assert_eq!(closed.lock().expect("closed").len(), 1);
    helper.disconnect().expect("disconnect");
}

fn wait_for_active(helper: &Helper, caller: &Caller) -> Vec<LiveConnection> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let (active, _) = helper
            .connections_as(caller)
            .expect("owner reads connections");
        if !active.is_empty() {
            return active;
        }
        assert!(Instant::now() < deadline, "connections were not collected");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn connections_are_collected_only_while_read_and_cleared_on_disconnect() {
    let asked = Arc::new(AtomicUsize::new(0));
    let helper = connections_helper(&asked);
    let owner = test_caller();
    let mut request = connect_request();
    request.settings.kill_switch = false;
    assert_eq!(
        helper.connections_as(&owner).expect("no session"),
        (Vec::new(), Vec::new())
    );
    helper.connect(&request).expect("connect");
    wait_for_totals(&helper, TrafficTotals { up: 1, down: 2 });
    std::thread::sleep(Duration::from_millis(1200));
    assert_eq!(asked.load(Ordering::Acquire), 0, "nobody reads the list");

    let active = wait_for_active(&helper, &owner);
    assert!(asked.load(Ordering::Acquire) > 0);
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, "connection");
    assert_eq!(active[0].host, "example.com");
    assert_eq!(active[0].route, rosetun_config::ConnectionRoute::Proxy);

    helper.disconnect().expect("disconnect");
    assert!(helper.connections.lock().expect("book").is_empty());
    assert_eq!(
        helper.connections_as(&owner).expect("after disconnect"),
        (Vec::new(), Vec::new())
    );
}

#[test]
fn only_the_session_owner_reads_connections() {
    let asked = Arc::new(AtomicUsize::new(0));
    let helper = connections_helper(&asked);
    let owner = Caller::fake(b"owner", false);
    let other = Caller::fake(b"other", false);
    let admin = Caller::fake(b"admin", true);
    let mut request = connect_request();
    request.settings.kill_switch = false;
    helper.connect_as(&owner, &request).expect("owner connects");

    for caller in [&other, &admin] {
        assert_eq!(
            helper.connections_as(caller).unwrap_err().code,
            ErrorCode::AccessDenied
        );
    }
    assert_eq!(
        asked.load(Ordering::Acquire),
        0,
        "a denied read does not start collecting"
    );
    assert_eq!(wait_for_active(&helper, &owner).len(), 1);
    helper.disconnect_as(&owner).expect("owner disconnects");
}

#[test]
fn verbose_log_is_passed_to_engine_and_closed_on_disconnect_or_expiry() {
    let verbose_logs = Arc::new(Mutex::new(Vec::new()));
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(TrafficEngine {
        totals: TrafficTotals::default(),
        dropped: Arc::new(AtomicUsize::new(0)),
        asked: Arc::default(),
        controls: Arc::new(Mutex::new(Vec::new())),
        verbose_logs: Arc::clone(&verbose_logs),
        closed: Arc::default(),
    }));
    let gate = VerboseGate::default();
    let helper = Helper::new(engines, Box::new(UnusedRouting), gate.clone());
    let mut request = connect_request();
    request.settings.kill_switch = false;
    request.settings.verbose_log_until = Some(now_unix() + 60);

    helper.connect(&request).expect("verbose connect");
    assert_eq!(
        *verbose_logs.lock().expect("test verbose logs mutex"),
        [true]
    );
    assert!(gate.is_open(now_unix()));
    helper.disconnect().expect("disconnect closes verbose log");
    assert!(!gate.is_open(now_unix()));

    request.settings.verbose_log_until = Some(now_unix().saturating_sub(1));
    helper.connect(&request).expect("expired verbose connect");
    assert_eq!(
        *verbose_logs.lock().expect("test verbose logs mutex"),
        [true, false]
    );
    assert!(!gate.is_open(now_unix()));
}

fn shorten_dns_timeouts(helper: &Helper) {
    let mut session = helper.session().expect("session");
    session.dns_timeout = Duration::from_millis(80);
    session.dns_attempt_timeout = Duration::from_millis(20);
}

#[test]
fn fresh_connect_waits_for_dns_with_and_without_kill_switch() {
    use super::dns::test_support::{Behavior, Server};

    for kill_switch in [false, true] {
        let server = Server::new(Behavior::Noerror);
        let stopped = Arc::new(AtomicUsize::new(0));
        let reverted = Arc::new(AtomicUsize::new(0));
        let mut engines = EngineRegistry::new();
        engines.register(Box::new(DnsEngine {
            server: Some(server.address()),
            stopped: Arc::clone(&stopped),
        }));

        let routing: Box<dyn RoutingBackend> = Box::new(CountingRouting {
            reverted: Arc::clone(&reverted),
        });
        let helper = Helper::new(engines, routing, VerboseGate::default());
        shorten_dns_timeouts(&helper);

        let mut request = connect_request();
        request.settings.kill_switch = kill_switch;
        helper.connect(&request).expect("DNS responds");

        assert!(matches!(helper.status().state, ConnectionState::Connected));
        assert_eq!(stopped.load(Ordering::Acquire), 0);
        assert_eq!(reverted.load(Ordering::Acquire), 0);
        assert!(helper.session().expect("session").last_endpoint.is_some());
        assert_eq!(
            helper.session().expect("session").tunnel_dns,
            Some(server.address())
        );
        assert!(helper.session().expect("session").watchdog.is_some());
        assert!(
            helper
                .session()
                .expect("session")
                .path_addresses
                .lock()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            helper
                .session()
                .expect("session")
                .guard
                .as_ref()
                .map(|guard| guard.scope),
            Some(if kill_switch {
                ProtectionScope::AllTraffic
            } else {
                ProtectionScope::DnsOnly
            }),
        );
    }
}

#[test]
fn fresh_dns_timeout_stops_engine_and_releases_protection() {
    use super::dns::test_support::{Behavior, Server};

    for kill_switch in [false, true] {
        let server = Server::new(Behavior::Silent);
        let stopped = Arc::new(AtomicUsize::new(0));
        let reverted = Arc::new(AtomicUsize::new(0));
        let mut engines = EngineRegistry::new();
        engines.register(Box::new(DnsEngine {
            server: Some(server.address()),
            stopped: Arc::clone(&stopped),
        }));

        let helper = Helper::new(
            engines,
            Box::new(CountingRouting {
                reverted: Arc::clone(&reverted),
            }),
            VerboseGate::default(),
        );
        shorten_dns_timeouts(&helper);

        let mut request = connect_request();
        request.settings.kill_switch = kill_switch;
        let error = helper.connect(&request).expect_err("DNS is silent");

        assert_eq!(error.code, ErrorCode::DnsTimeout);
        assert!(error.message.contains("last: timeout"));
        assert!(matches!(
            helper.status().state,
            ConnectionState::Failed { ref reason, .. } if reason == &error.message
        ));
        assert_eq!(stopped.load(Ordering::Acquire), 1);
        assert_eq!(reverted.load(Ordering::Acquire), 1);

        let session = helper.session().expect("session");
        assert!(session.guard.is_none());
        assert!(session.process.is_none());
        assert!(session.last_endpoint.is_none());
        assert!(session.tunnel_dns.is_none());
        assert!(session.watchdog.is_none());
    }
}

#[derive(Clone, Copy)]
enum ClashReply {
    Works,
    Fails,
    Hangs,
}

struct FakeClashApi {
    control: ControlEndpoint,
    calls: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl FakeClashApi {
    fn start(reply: ClashReply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("fake Clash API");
        listener.set_nonblocking(true).unwrap();
        let control = ControlEndpoint {
            address: listener.local_addr().unwrap(),
            secret: "test-secret".to_owned(),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let calls = Arc::clone(&calls);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let (socket, _) = match listener.accept() {
                        Ok(connection) => connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(error) => panic!("fake Clash API accept failed: {error}"),
                    };
                    socket.set_nonblocking(false).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut reader = BufReader::new(socket);
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    assert!(line.starts_with("GET /proxies/proxy/delay?"));
                    assert!(
                        line.contains(&format!("timeout={}", SERVER_CHECK_TIMEOUT.as_millis()))
                    );
                    assert!(line.contains("url=https%3A%2F%2F"));
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
                    calls.fetch_add(1, Ordering::AcqRel);
                    match reply {
                        ClashReply::Works | ClashReply::Fails => {
                            let (status, body) = match reply {
                                ClashReply::Works => (200, r#"{"delay":12}"#),
                                ClashReply::Fails => (503, ""),
                                ClashReply::Hangs => unreachable!(),
                            };
                            write!(
                                reader.get_mut(),
                                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\n\r\n{body}",
                                body.len()
                            )
                            .unwrap();
                        }
                        ClashReply::Hangs => {
                            while !stop.load(Ordering::Acquire) {
                                thread::sleep(Duration::from_millis(5));
                            }
                        }
                    }
                }
            })
        };
        Self {
            control,
            calls,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for FakeClashApi {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            if thread::panicking() {
                let _ = worker.join();
            } else {
                worker.join().expect("fake Clash API worker");
            }
        }
    }
}

#[derive(Debug)]
struct ServerCheckEngine {
    server: SocketAddr,
    control: ControlEndpoint,
    stopped: Arc<AtomicUsize>,
    api_stop: Arc<AtomicBool>,
    api_calls: Arc<AtomicUsize>,
    log_failures: bool,
    slow_adapter: bool,
}

impl EngineBackend for ServerCheckEngine {
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

    fn tunnel_dns_server(&self, _: &rosetun_config::TunSettings) -> Option<SocketAddr> {
        Some(self.server)
    }

    fn locate_binary(&self) -> Result<PathBuf, EngineError> {
        Ok(PathBuf::from("sing-box"))
    }

    fn render(&self, _: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError> {
        Ok(RenderedConfig {
            file_name: "config.json".to_owned(),
            body: Vec::new(),
            unsupported: Vec::new(),
            unsupported_probes: Vec::new(),
        })
    }

    fn url_test(
        &self,
        _: &ControlEndpoint,
        target: UrlTestTarget<'_>,
        url: &str,
        timeout: Duration,
    ) -> Result<Duration, EngineError> {
        rosetun_engine_singbox::SingBoxBackend::new("unused").url_test(
            &self.control,
            target,
            url,
            timeout,
        )
    }

    fn spawn(&self, _: &Path, _: &RenderedConfig) -> Result<Box<dyn EngineProcess>, EngineError> {
        Ok(Box::new(ServerCheckProcess {
            stopped: Arc::clone(&self.stopped),
            api_stop: Arc::clone(&self.api_stop),
            api_calls: Arc::clone(&self.api_calls),
            log_failures: self.log_failures,
            slow_adapter: self.slow_adapter,
        }))
    }
}

#[derive(Debug)]
struct ServerCheckProcess {
    stopped: Arc<AtomicUsize>,
    api_stop: Arc<AtomicBool>,
    api_calls: Arc<AtomicUsize>,
    log_failures: bool,
    slow_adapter: bool,
}

impl EngineProcess for ServerCheckProcess {
    fn is_running(&mut self) -> Result<bool, EngineError> {
        Ok(true)
    }

    fn startup_hints(&self) -> rosetun_engine::StartupHints {
        rosetun_engine::StartupHints {
            slow_tunnel_creation: self.slow_adapter,
            ..Default::default()
        }
    }

    fn outbound_failures(&self) -> rosetun_engine::OutboundFailures {
        rosetun_engine::OutboundFailures {
            unreachable: u64::from(self.log_failures && self.api_calls.load(Ordering::Acquire) > 0)
                * 2,
            ..Default::default()
        }
    }

    fn stop(&mut self) -> Result<(), EngineError> {
        self.api_stop.store(true, Ordering::Release);
        self.stopped.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

fn server_check_helper(
    server: SocketAddr,
    api: &FakeClashApi,
    stopped: Arc<AtomicUsize>,
) -> Helper {
    server_check_helper_with_logs(server, api, stopped, false)
}

fn server_check_helper_with_logs(
    server: SocketAddr,
    api: &FakeClashApi,
    stopped: Arc<AtomicUsize>,
    log_failures: bool,
) -> Helper {
    server_check_helper_with_startup(server, api, stopped, log_failures, false)
}

fn server_check_helper_with_startup(
    server: SocketAddr,
    api: &FakeClashApi,
    stopped: Arc<AtomicUsize>,
    log_failures: bool,
    slow_adapter: bool,
) -> Helper {
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(ServerCheckEngine {
        server,
        control: api.control.clone(),
        stopped,
        api_stop: Arc::clone(&api.stop),
        api_calls: Arc::clone(&api.calls),
        log_failures,
        slow_adapter,
    }));
    let helper = Helper::new(
        engines,
        Box::new(CountingRouting {
            reverted: Arc::new(AtomicUsize::new(0)),
        }),
        VerboseGate::default(),
    );
    {
        let mut session = helper.session().unwrap();
        session.dns_timeout = Duration::from_secs(2);
        session.dns_attempt_timeout = Duration::from_millis(20);
        session.server_check_interval = Duration::from_millis(20);
    }
    helper
}

#[test]
fn slow_adapter_connects_when_dns_recovers_after_early_server_failures() {
    use super::dns::test_support::{Behavior, Server};

    let dns = Server::new(Behavior::AnswerAfter(8));
    let api = FakeClashApi::start(ClashReply::Fails);
    let stopped = Arc::new(AtomicUsize::new(0));
    let helper =
        server_check_helper_with_startup(dns.address(), &api, Arc::clone(&stopped), true, true);
    helper.session().unwrap().server_check_grace = Duration::from_millis(450);

    helper
        .connect(&connect_request())
        .expect("late DNS answer wins");
    assert!(api.calls.load(Ordering::Acquire) >= 3);
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    helper.disconnect().unwrap();
    assert_eq!(stopped.load(Ordering::Acquire), 1);
}

#[test]
fn dead_server_is_not_rejected_until_slow_adapter_grace_expires() {
    use super::dns::test_support::{Behavior, Server};

    let dns = Server::new(Behavior::Silent);
    let api = FakeClashApi::start(ClashReply::Fails);
    let stopped = Arc::new(AtomicUsize::new(0));
    let helper =
        server_check_helper_with_startup(dns.address(), &api, Arc::clone(&stopped), true, true);
    helper.session().unwrap().server_check_grace = Duration::from_millis(300);
    let started = Instant::now();
    let error = helper
        .connect(&connect_request())
        .expect_err("dead server is rejected after grace");

    assert_eq!(error.code, ErrorCode::ServerUnreachable);
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(api.calls.load(Ordering::Acquire) >= 3);
    assert_eq!(stopped.load(Ordering::Acquire), 1);
}

#[test]
fn three_server_checks_fail_before_the_dns_deadline() {
    use super::dns::test_support::{Behavior, Server};

    let dns = Server::new(Behavior::Silent);
    let api = FakeClashApi::start(ClashReply::Fails);
    let stopped = Arc::new(AtomicUsize::new(0));
    let helper = server_check_helper(dns.address(), &api, Arc::clone(&stopped));
    let started = Instant::now();
    let error = helper
        .connect(&connect_request())
        .expect_err("server is unreachable");

    assert_eq!(error.code, ErrorCode::ServerUnreachable);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(api.calls.load(Ordering::Acquire) >= 3);
    assert_eq!(stopped.load(Ordering::Acquire), 1);
    assert!(matches!(
        helper.status().state,
        ConnectionState::Failed { .. }
    ));
}

#[test]
fn lost_route_during_server_check_is_no_network() {
    use super::dns::test_support::{Behavior, Server};

    ROUTE_CHECKS.store(0, Ordering::Release);
    let dns = Server::new(Behavior::Silent);
    let api = FakeClashApi::start(ClashReply::Fails);
    let stopped = Arc::new(AtomicUsize::new(0));
    let helper = server_check_helper(dns.address(), &api, Arc::clone(&stopped))
        .with_test_physical_interface(route_then_disappears);
    let error = helper
        .connect(&connect_request())
        .expect_err("network went away");

    assert_eq!(error.code, ErrorCode::NoNetwork);
    assert!(ROUTE_CHECKS.load(Ordering::Acquire) >= 2);
    assert!(matches!(
        helper.status().state,
        ConnectionState::Failed {
            failure_kind: Some(rosetun_config::FailureKind::NoNetwork),
            ..
        }
    ));
    assert_eq!(stopped.load(Ordering::Acquire), 1);
}

#[test]
fn server_check_and_engine_log_failures_share_the_threshold() {
    use super::dns::test_support::{Behavior, Server};

    let dns = Server::new(Behavior::Silent);
    let api = FakeClashApi::start(ClashReply::Fails);
    let stopped = Arc::new(AtomicUsize::new(0));
    let helper = server_check_helper_with_logs(dns.address(), &api, Arc::clone(&stopped), true);
    helper.session().unwrap().server_check_interval = Duration::from_millis(400);
    let error = helper
        .connect(&connect_request())
        .expect_err("failures combine");

    assert_eq!(error.code, ErrorCode::ServerUnreachable);
    assert!(api.calls.load(Ordering::Acquire) < 3);
    assert_eq!(stopped.load(Ordering::Acquire), 1);
}

#[test]
fn successful_server_checks_do_not_fail_slow_dns_early() {
    use super::dns::test_support::{Behavior, Server};

    let dns = Server::new(Behavior::Silent);
    let api = FakeClashApi::start(ClashReply::Works);
    let stopped = Arc::new(AtomicUsize::new(0));
    let helper = server_check_helper(dns.address(), &api, Arc::clone(&stopped));
    helper.session().unwrap().dns_timeout = Duration::from_millis(150);
    let error = helper
        .connect(&connect_request())
        .expect_err("DNS remains silent");

    assert_eq!(error.code, ErrorCode::DnsTimeout);
    assert!(api.calls.load(Ordering::Acquire) >= 3);
    assert_eq!(stopped.load(Ordering::Acquire), 1);
}

#[test]
fn server_checks_stop_after_dns_connects() {
    use super::dns::test_support::{Behavior, Server};

    let dns = Server::new(Behavior::DelayedNoerror);
    let api = FakeClashApi::start(ClashReply::Works);
    let stopped = Arc::new(AtomicUsize::new(0));
    let helper = server_check_helper(dns.address(), &api, Arc::clone(&stopped));
    helper.connect(&connect_request()).expect("DNS answers");

    assert!(matches!(helper.status().state, ConnectionState::Connected));
    let calls = api.calls.load(Ordering::Acquire);
    assert!(calls > 0);
    thread::sleep(Duration::from_millis(100));
    assert_eq!(api.calls.load(Ordering::Acquire), calls);
    helper.disconnect().unwrap();
    assert_eq!(stopped.load(Ordering::Acquire), 1);
}

#[test]
fn cancelling_a_server_check_stops_the_worker() {
    use super::dns::test_support::{Behavior, Server};

    let dns = Server::new(Behavior::Silent);
    let api = FakeClashApi::start(ClashReply::Hangs);
    let stopped = Arc::new(AtomicUsize::new(0));
    let helper = Arc::new(server_check_helper(
        dns.address(),
        &api,
        Arc::clone(&stopped),
    ));
    let worker = {
        let helper = Arc::clone(&helper);
        thread::spawn(move || helper.connect(&connect_request()))
    };
    let deadline = Instant::now() + Duration::from_secs(1);
    while api.calls.load(Ordering::Acquire) == 0 {
        assert!(Instant::now() < deadline, "server check never started");
        thread::sleep(Duration::from_millis(5));
    }
    let started = Instant::now();
    helper.disconnect().expect("cancel during server check");
    assert_eq!(
        worker.join().unwrap().unwrap_err().code,
        ErrorCode::Cancelled
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(helper.status(), Status::default());
    assert_eq!(stopped.load(Ordering::Acquire), 1);
    let calls = api.calls.load(Ordering::Acquire);
    thread::sleep(Duration::from_millis(50));
    assert_eq!(api.calls.load(Ordering::Acquire), calls);
}

#[test]
fn cancellation_after_dns_answer_aborts_an_inflight_server_check() {
    use super::dns::test_support::{Behavior, Server};

    let dns = Server::new(Behavior::DelayedNoerror);
    let api = FakeClashApi::start(ClashReply::Hangs);
    let stopped = Arc::new(AtomicUsize::new(0));
    let helper = Arc::new(server_check_helper(
        dns.address(),
        &api,
        Arc::clone(&stopped),
    ));
    let worker = {
        let helper = Arc::clone(&helper);
        thread::spawn(move || helper.connect(&connect_request()))
    };
    let deadline = Instant::now() + Duration::from_secs(1);
    while api.calls.load(Ordering::Acquire) == 0 {
        assert!(Instant::now() < deadline, "server check never started");
        thread::sleep(Duration::from_millis(5));
    }
    thread::sleep(Duration::from_millis(80));
    assert!(matches!(helper.status().state, ConnectionState::Connecting));
    let started = Instant::now();
    helper.disconnect().expect("cancel during server check");
    assert_eq!(
        worker.join().unwrap().unwrap_err().code,
        ErrorCode::Cancelled
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(helper.status(), Status::default());
    assert_eq!(stopped.load(Ordering::Acquire), 1);
}

#[test]
fn dns_lock_failure_does_not_block_connect() {
    use super::dns::test_support::{Behavior, Server};

    for kill_switch in [false, true] {
        let server = Server::new(Behavior::Noerror);
        let stopped = Arc::new(AtomicUsize::new(0));
        let mut engines = EngineRegistry::new();
        engines.register(Box::new(DnsEngine {
            server: Some(server.address()),
            stopped: Arc::clone(&stopped),
        }));
        let helper = Helper::new(engines, Box::new(FailingRouting), VerboseGate::default());
        shorten_dns_timeouts(&helper);
        let mut request = connect_request();
        request.settings.kill_switch = kill_switch;

        if kill_switch {
            let error = helper
                .connect(&request)
                .expect_err("kill switch cannot be skipped");
            assert_eq!(error.code, ErrorCode::RoutingFailed);
            assert!(matches!(
                helper.status().state,
                ConnectionState::Failed { .. }
            ));
            assert!(helper.session().expect("session").watchdog.is_none());
        } else {
            helper
                .connect(&request)
                .expect("DNS lock failure is optional");
            assert!(matches!(helper.status().state, ConnectionState::Connected));
            let session = helper.session().expect("session");
            assert!(session.guard.is_none());
            assert_eq!(session.tunnel_dns, Some(server.address()));
            assert!(session.watchdog.is_some());
            assert_eq!(stopped.load(Ordering::Acquire), 0);
        }
    }
}

#[test]
fn dns_lock_is_dropped_when_the_tunnel_cannot_be_authorized() {
    use super::dns::test_support::{Behavior, Server};

    for kill_switch in [false, true] {
        let server = Server::new(Behavior::Noerror);
        let stopped = Arc::new(AtomicUsize::new(0));
        let reverted = Arc::new(AtomicUsize::new(0));
        let mut engines = EngineRegistry::new();
        engines.register(Box::new(DnsEngine {
            server: Some(server.address()),
            stopped: Arc::clone(&stopped),
        }));
        let helper = Helper::new(
            engines,
            Box::new(RejectingTunnelRouting {
                reverted: Arc::clone(&reverted),
            }),
            VerboseGate::default(),
        );
        shorten_dns_timeouts(&helper);
        let mut request = connect_request();
        request.settings.kill_switch = kill_switch;

        if kill_switch {
            let error = helper
                .connect(&request)
                .expect_err("kill switch cannot be skipped");
            assert_eq!(error.code, ErrorCode::RoutingFailed);
            assert!(matches!(
                helper.status().state,
                ConnectionState::Failed { .. }
            ));
            assert!(helper.session().expect("session").guard.is_none());
        } else {
            helper.connect(&request).expect("DNS lock is optional");
            assert!(matches!(helper.status().state, ConnectionState::Connected));
            let session = helper.session().expect("session");
            assert!(session.guard.is_none());
            assert_eq!(session.tunnel_dns, Some(server.address()));
        }
        assert_eq!(reverted.load(Ordering::Acquire), 1);
    }
}

#[test]
fn protected_dns_timeout_stops_engine_but_retains_guard_and_cache() {
    use super::dns::test_support::{Behavior, Server};

    let server = Server::new(Behavior::Silent);
    let stopped = Arc::new(AtomicUsize::new(0));
    let (helper, prepared, authorized, reverted) = protected_helper(Box::new(DnsEngine {
        server: Some(server.address()),
        stopped: Arc::clone(&stopped),
    }));
    shorten_dns_timeouts(&helper);

    let error = helper
        .connect(&protected_request())
        .expect_err("DNS is silent");

    assert_eq!(error.code, ErrorCode::DnsTimeout);
    assert!(error.message.contains("last: timeout"));
    assert!(matches!(
        helper.status().state,
        ConnectionState::FailedProtected { ref reason, .. } if reason == &error.message
    ));
    assert_eq!(prepared.load(Ordering::Acquire), 1);
    assert_eq!(authorized.load(Ordering::Acquire), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
    assert_eq!(stopped.load(Ordering::Acquire), 1);

    let session = helper.session().expect("session");
    assert!(session.guard.is_some());
    assert!(session.process.is_none());
    assert!(session.tunnel_dns.is_none());
    assert!(session.watchdog.is_none());
    let cached = session.last_endpoint.as_ref().expect("retained cache");
    assert_eq!(cached.server, "cached.invalid");
    assert_eq!(
        cached.address,
        "203.0.113.10".parse::<IpAddr>().expect("cached address"),
    );
}

#[test]
fn backend_without_dns_server_connects_without_checking_dns() {
    let stopped = Arc::new(AtomicUsize::new(0));
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(DnsEngine {
        server: None,
        stopped: Arc::clone(&stopped),
    }));

    let helper = Helper::new(engines, Box::new(UnusedRouting), VerboseGate::default());
    {
        let mut session = helper.session().expect("session");
        session.dns_timeout = Duration::ZERO;
        session.dns_attempt_timeout = Duration::ZERO;
    }

    let mut request = connect_request();
    request.settings.kill_switch = false;
    helper.connect(&request).expect("DNS check is skipped");

    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(stopped.load(Ordering::Acquire), 0);
    assert!(helper.session().expect("session").tunnel_dns.is_none());
    assert!(helper.session().expect("session").watchdog.is_none());
}

#[test]
fn status_answers_while_connect_holds_the_session() {
    let (entered, entered_rx) = channel();
    let (release_tx, release) = channel();
    let received_plan = Arc::new(Mutex::new(None));

    let mut engines = EngineRegistry::new();
    engines.register(Box::new(StubEngine));

    let helper = Arc::new(Helper::new(
        engines,
        Box::new(BlockingRouting {
            entered,
            release,
            received_plan: Arc::clone(&received_plan),
        }),
        VerboseGate::default(),
    ));

    let mut request = connect_request();
    request.settings.kill_switch = true;

    let worker = {
        let helper = Arc::clone(&helper);
        std::thread::spawn(move || helper.connect(&request))
    };

    entered_rx.recv().expect("connect reached routing apply");

    let plan = received_plan
        .lock()
        .expect("test routing plan mutex is not poisoned")
        .clone()
        .expect("routing receives a protection plan");
    assert!(!plan.allow_lan);

    assert!(matches!(helper.status().state, ConnectionState::Connecting));

    release_tx.send(()).expect("release apply");
    worker
        .join()
        .expect("worker thread")
        .expect("connect succeeds");
    assert!(matches!(helper.status().state, ConnectionState::Connected));
}

#[test]
fn disconnect_cancels_while_a_second_connect_reports_busy() {
    let (entered, entered_rx) = channel();
    let (release_tx, release) = channel();
    let received_plan = Arc::new(Mutex::new(None));

    let mut engines = EngineRegistry::new();
    engines.register(Box::new(StubEngine));

    let helper = Arc::new(Helper::new(
        engines,
        Box::new(BlockingRouting {
            entered,
            release,
            received_plan,
        }),
        VerboseGate::default(),
    ));
    let mut request = connect_request();
    request.settings.kill_switch = true;

    let worker = {
        let helper = Arc::clone(&helper);
        std::thread::spawn(move || helper.connect(&request))
    };

    entered_rx.recv().expect("connect reached routing apply");
    let error = helper
        .connect(&connect_request())
        .expect_err("session is held");
    assert_eq!(error.code, ErrorCode::Busy);
    helper
        .disconnect()
        .expect("disconnect accepts cancellation");

    release_tx.send(()).expect("release apply");
    assert_eq!(
        worker.join().expect("worker thread").unwrap_err().code,
        ErrorCode::Cancelled
    );
    assert_eq!(helper.status(), Status::default());
}

fn owned_helper() -> Helper {
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(StubEngine));
    Helper::new(engines, Box::new(UnusedRouting), VerboseGate::default())
}

#[test]
fn session_owner_controls_connected_operations_and_releases_it_on_disconnect() {
    let helper = owned_helper();
    let owner = Caller::fake(b"owner", false);
    let other = Caller::fake(b"other", false);
    let mut request = connect_request();
    request.settings.kill_switch = false;
    request.temporary_rules.push(temporary_rule());

    helper.connect_as(&owner, &request).expect("owner connects");
    assert_eq!(
        helper.temporary_rules_as(&owner).unwrap(),
        request.temporary_rules
    );
    helper.apply_as(&owner, &request).expect("owner applies");
    assert!(!matches!(
        helper.tunnel_delay_as(&owner),
        Err(HelperError {
            code: ErrorCode::AccessDenied,
            ..
        })
    ));
    helper.disconnect_as(&owner).expect("owner disconnects");

    helper
        .connect_as(&other, &request)
        .expect("another account connects after disconnect");
    assert_eq!(
        helper.disconnect_as(&owner).unwrap_err().code,
        ErrorCode::AccessDenied
    );
    helper.disconnect_as(&other).expect("new owner disconnects");
}

#[test]
fn diagnostic_log_is_only_available_to_the_last_session_owner() {
    let helper = owned_helper();
    let owner = Caller::fake(b"owner", false);
    let other = Caller::fake(b"other", false);
    let admin = Caller::fake(b"admin", true);
    assert_eq!(
        helper.diagnostic_log_as(&owner).unwrap_err().code,
        ErrorCode::AccessDenied
    );

    let mut request = connect_request();
    request.settings.kill_switch = false;
    helper.connect_as(&owner, &request).expect("owner connects");
    for caller in [&other, &admin] {
        assert_eq!(
            helper.diagnostic_log_as(caller).unwrap_err().code,
            ErrorCode::AccessDenied
        );
    }
    assert!(helper.diagnostic_log_as(&owner).is_ok());
    helper.disconnect_as(&owner).expect("owner disconnects");
    assert!(helper.diagnostic_log_as(&owner).is_ok());
    assert_eq!(
        helper.diagnostic_log_as(&other).unwrap_err().code,
        ErrorCode::AccessDenied
    );

    helper
        .connect_as(&other, &request)
        .expect("new owner connects");
    assert_eq!(
        helper.diagnostic_log_as(&owner).unwrap_err().code,
        ErrorCode::AccessDenied
    );
    helper.disconnect_as(&other).expect("new owner disconnects");
}

#[test]
fn another_account_cannot_change_or_read_an_active_session() {
    let helper = owned_helper();
    let owner = Caller::fake(b"owner", false);
    let other = Caller::fake(b"other", false);
    let admin = Caller::fake(b"admin", true);
    let mut request = connect_request();
    request.settings.kill_switch = false;
    request.temporary_rules.push(temporary_rule());
    helper.connect_as(&owner, &request).expect("owner connects");

    for result in [
        helper.connect_as(&other, &request),
        helper.apply_as(&other, &request),
        helper.temporary_rules_as(&other).map(|_| ()),
        helper.session_exits_as(&other).map(|_| ()),
        helper.tunnel_delay_as(&other).map(|_| ()),
        helper.disconnect_as(&other),
    ] {
        assert_eq!(result.unwrap_err().code, ErrorCode::AccessDenied);
    }
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(
        helper.temporary_rules_as(&owner).unwrap(),
        request.temporary_rules
    );
    assert_eq!(
        helper.connect_as(&admin, &request).unwrap_err().code,
        ErrorCode::InvalidState
    );
    helper.apply_as(&admin, &request).expect("admin applies");
    assert_eq!(
        helper.temporary_rules_as(&admin).unwrap(),
        request.temporary_rules
    );
    assert!(!matches!(
        helper.tunnel_delay_as(&admin),
        Err(HelperError {
            code: ErrorCode::AccessDenied,
            ..
        })
    ));
    helper.disconnect_as(&admin).expect("admin disconnects");
}

#[test]
fn another_account_cannot_cancel_a_connect_holding_the_session() {
    let (entered, entered_rx) = channel();
    let (release_tx, release) = channel();
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(StubEngine));
    let helper = Arc::new(Helper::new(
        engines,
        Box::new(BlockingRouting {
            entered,
            release,
            received_plan: Arc::new(Mutex::new(None)),
        }),
        VerboseGate::default(),
    ));
    let owner = Caller::fake(b"owner", false);
    let other = Caller::fake(b"other", false);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    let worker = {
        let helper = Arc::clone(&helper);
        let caller = Caller::fake(b"owner", false);
        let request = request.clone();
        std::thread::spawn(move || helper.connect_as(&caller, &request))
    };
    entered_rx.recv().expect("connect holds the session");

    assert_eq!(
        helper.connect_as(&other, &request).unwrap_err().code,
        ErrorCode::AccessDenied
    );
    assert_eq!(
        helper.disconnect_as(&other).unwrap_err().code,
        ErrorCode::AccessDenied
    );
    assert_eq!(
        helper.apply_as(&other, &request).unwrap_err().code,
        ErrorCode::AccessDenied
    );
    assert_eq!(
        helper.temporary_rules_as(&other).unwrap_err().code,
        ErrorCode::AccessDenied
    );
    assert_eq!(
        helper.tunnel_delay_as(&other).unwrap_err().code,
        ErrorCode::AccessDenied
    );
    assert!(!helper.cancelled.load(Ordering::Acquire));
    helper.disconnect_as(&owner).expect("owner cancels");
    release_tx.send(()).expect("release routing");
    assert_eq!(
        worker.join().unwrap().unwrap_err().code,
        ErrorCode::Cancelled
    );
    assert_eq!(helper.status(), Status::default());
}

#[test]
fn failed_connect_releases_owner_for_another_account() {
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(StubEngine));
    let helper = Helper::new(engines, Box::new(FailingRouting), VerboseGate::default());
    let owner = Caller::fake(b"owner", false);
    let other = Caller::fake(b"other", false);
    let mut request = connect_request();
    request.settings.kill_switch = true;

    assert_eq!(
        helper.connect_as(&owner, &request).unwrap_err().code,
        ErrorCode::RoutingFailed
    );
    assert!(matches!(
        helper.status().state,
        ConnectionState::Failed { .. }
    ));
    request.settings.kill_switch = false;
    helper
        .connect_as(&other, &request)
        .expect("new owner after failure");
    assert_eq!(
        helper.disconnect_as(&owner).unwrap_err().code,
        ErrorCode::AccessDenied
    );
    helper.disconnect_as(&other).expect("new owner disconnects");
}

#[test]
fn administrator_takes_over_a_protected_session() {
    let (helper, _, _, _) = protected_helper(Box::new(StubEngine));
    let owner = Caller::fake(b"owner", false);
    let admin = Caller::fake(b"admin", true);
    *helper.owner.lock().unwrap() = Some(owner.sid.clone());

    helper
        .connect_as(&admin, &protected_request())
        .expect("admin reconnects");
    assert_eq!(
        helper.disconnect_as(&owner).unwrap_err().code,
        ErrorCode::AccessDenied
    );
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    helper
        .disconnect_as(&admin)
        .expect("administrator disconnects");
}

#[test]
fn failed_protected_connect_keeps_the_previous_owner() {
    let (helper, _, _, _) = protected_helper(Box::new(ExitedEngine));
    let owner = Caller::fake(b"owner", false);
    let other = Caller::fake(b"other", false);
    let admin = Caller::fake(b"admin", true);
    *helper.owner.lock().unwrap() = Some(owner.sid.clone());

    helper
        .connect_as(&admin, &protected_request())
        .expect_err("engine exits");
    assert!(matches!(
        helper.status().state,
        ConnectionState::FailedProtected { .. }
    ));
    assert_eq!(
        helper.disconnect_as(&other).unwrap_err().code,
        ErrorCode::AccessDenied
    );
    assert_eq!(*helper.owner.lock().unwrap(), Some(owner.sid.clone()));
    assert!(helper.temporary_rules_as(&admin).is_ok());
    helper
        .disconnect_as(&owner)
        .expect("previous owner retains protected session");
}

#[test]
fn connect_without_kill_switch_does_not_use_routing_backend() {
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(StubEngine));

    let helper = Helper::new(engines, Box::new(UnusedRouting), VerboseGate::default());
    let mut request = connect_request();
    request.settings.kill_switch = false;

    helper.connect(&request).expect("connect succeeds");

    let status = helper.status();
    assert!(matches!(status.state, ConnectionState::Connected));
    assert_eq!(status.node, Some(request.node.id));
    assert_eq!(status.traffic, Traffic::default());

    helper.disconnect().expect("disconnect succeeds");
    assert!(matches!(
        helper.status().state,
        ConnectionState::Disconnected
    ));
}

#[test]
fn connect_rejects_unsupported_rules_before_starting_the_engine() {
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(UnsupportedRuleEngine));

    let helper = Helper::new(engines, Box::new(UnusedRouting), VerboseGate::default());
    let error = helper
        .connect(&connect_request())
        .expect_err("unsupported rules reject the connection");

    assert_eq!(error.code, ErrorCode::UnsupportedRules);
    assert!(error.message.contains("unsupported-rule"));
    assert!(matches!(
        helper.status().state,
        ConnectionState::Failed { .. }
    ));
}

#[test]
fn kill_switch_rejects_an_unresolvable_vpn_endpoint_before_routing() {
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(StubEngine));

    let helper = Helper::new(engines, Box::new(UnusedRouting), VerboseGate::default());
    let mut request = connect_request();
    request.node.server = "invalid host name with spaces".to_owned();
    request.settings.kill_switch = true;

    let error = helper
        .connect(&request)
        .expect_err("an invalid VPN endpoint rejects the connection");

    assert_eq!(error.code, ErrorCode::ServerNameUnresolved);
    assert!(
        error
            .message
            .contains("failed to resolve the VPN server name")
    );
    assert!(!error.message.contains("invalid host name"));
    assert!(matches!(
        helper.status().state,
        ConnectionState::Failed {
            failure_kind: Some(rosetun_config::FailureKind::ServerNameUnresolved),
            ..
        }
    ));
}

#[test]
fn kill_switch_authorizes_the_configured_tunnel_after_spawning_the_engine() {
    let (spawned, spawn_observed) = channel();
    let (authorized, authorized_rx) = channel();

    let mut engines = EngineRegistry::new();
    engines.register(Box::new(SpawnSignalingEngine { spawned }));

    let helper = Helper::new(
        engines,
        Box::new(AuthorizingRouting {
            spawned: Some(spawn_observed),
            authorized,
        }),
        VerboseGate::default(),
    );
    let mut request = connect_request();
    request.settings.kill_switch = true;
    request.settings.tun.name = "rosetun-test".to_owned();
    request.settings.tun.ipv4 = "172.29.10.1/30".to_owned();

    helper
        .connect(&request)
        .expect("the spawned engine tunnel is authorized");

    assert_eq!(
        authorized_rx
            .recv()
            .expect("helper authorizes the tunnel after spawn"),
        TunnelInterface {
            alias: "rosetun-test".to_owned(),
            ipv4: "172.29.10.1".parse().expect("valid test IPv4"),
        }
    );
    assert!(matches!(helper.status().state, ConnectionState::Connected));
}

#[test]
fn missing_route_fails_before_starting_engine_or_protection() {
    let controls = Arc::new(EngineControls::default());
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(ControlledEngine {
        controls: Arc::clone(&controls),
        dns_server: None,
    }));
    let helper = Helper::new(engines, Box::new(UnusedRouting), VerboseGate::default())
        .with_test_physical_interface(|_| None);
    let mut request = connect_request();
    request.settings.kill_switch = true;

    let started = Instant::now();
    let error = helper.connect(&request).expect_err("no physical route");
    assert_eq!(error.code, ErrorCode::NoNetwork);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(controls.spawns(), 0);
    assert!(helper.session().unwrap().guard.is_none());
    assert!(matches!(
        helper.status().state,
        ConnectionState::Failed {
            failure_kind: Some(rosetun_config::FailureKind::NoNetwork),
            ..
        }
    ));
}

#[test]
fn supervisor_marks_the_session_failed_when_reconnect_is_disabled() {
    let running = Arc::new(AtomicBool::new(true));

    let mut engines = EngineRegistry::new();
    engines.register(Box::new(RunningThenExitedEngine {
        running: Arc::clone(&running),
    }));

    let helper = Helper::new(engines, Box::new(UnusedRouting), VerboseGate::default());
    let mut request = connect_request();
    request.settings.kill_switch = false;
    request.settings.auto_reconnect = false;

    helper
        .connect(&request)
        .expect("connection succeeds while the engine is running");

    let connected = helper.status();
    assert!(matches!(connected.state, ConnectionState::Connected));
    assert!(connected.since_unix.is_some());

    // Exit only after connect has completed its readiness checks.
    running.store(false, Ordering::Release);
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    helper.supervise(Instant::now());
    let status = helper.status();

    assert!(matches!(
        status.state,
        ConnectionState::Failed { ref reason, .. } if reason == "the engine process exited"
    ));
    assert!(status.since_unix.is_none());
}

#[test]
fn connect_rejects_an_engine_that_exits_before_startup_readiness() {
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(ExitedEngine));

    let helper = Helper::new(engines, Box::new(UnusedRouting), VerboseGate::default());
    let mut request = connect_request();
    request.settings.kill_switch = false;

    let error = helper
        .connect(&request)
        .expect_err("an exited process cannot complete startup readiness");

    assert_eq!(error.code, ErrorCode::EngineFailed);
    assert_eq!(error.message, "engine exited before startup readiness");

    let status = helper.status();
    assert!(matches!(
        status.state,
        ConnectionState::Failed { ref reason, .. }
            if reason == "engine exited before startup readiness"
    ));
    assert!(status.since_unix.is_none());
}

#[test]
fn supervisor_reports_failed_protected_when_reconnect_is_disabled() {
    let running = Arc::new(AtomicBool::new(true));
    let reverted = Arc::new(AtomicUsize::new(0));

    let mut engines = EngineRegistry::new();
    engines.register(Box::new(RunningThenExitedEngine {
        running: Arc::clone(&running),
    }));

    let helper = Helper::new(
        engines,
        Box::new(CountingRouting {
            reverted: Arc::clone(&reverted),
        }),
        VerboseGate::default(),
    );

    let mut request = connect_request();
    request.settings.kill_switch = true;
    request.settings.tun.name = "rosetun-test".to_owned();
    request.settings.tun.ipv4 = "172.29.10.1/30".to_owned();
    request.settings.auto_reconnect = false;

    helper
        .connect(&request)
        .expect("connection succeeds while the engine is running");

    running.store(false, Ordering::Release);
    helper.supervise(Instant::now());

    let status = helper.status();
    assert!(matches!(
        status.state,
        ConnectionState::FailedProtected { ref reason, .. }
            if reason == "the engine process exited"
    ));
    assert_eq!(
        reverted.load(Ordering::Acquire),
        0,
        "routing protection must remain active after engine failure"
    );

    helper
        .disconnect()
        .expect("disconnect tears down failed protected state");

    assert!(matches!(
        helper.status().state,
        ConnectionState::Disconnected
    ));
    assert_eq!(
        reverted.load(Ordering::Acquire),
        1,
        "disconnect must revert the routing protection"
    );
}

#[test]
fn disconnect_from_failed_protected_state_returns_to_disconnected() {
    let running = Arc::new(AtomicBool::new(true));

    let mut engines = EngineRegistry::new();
    engines.register(Box::new(RunningThenExitedEngine {
        running: Arc::clone(&running),
    }));

    let helper = Helper::new(
        engines,
        Box::new(CountingRouting {
            reverted: Arc::new(AtomicUsize::new(0)),
        }),
        VerboseGate::default(),
    );

    let mut request = connect_request();
    request.settings.kill_switch = true;
    request.settings.tun.name = "rosetun-test".to_owned();
    request.settings.tun.ipv4 = "172.29.10.1/30".to_owned();

    request.settings.auto_reconnect = false;
    helper.connect(&request).expect("connection succeeds");
    running.store(false, Ordering::Release);
    helper.supervise(Instant::now());

    assert!(matches!(
        helper.status().state,
        ConnectionState::FailedProtected { .. }
    ));

    helper
        .disconnect()
        .expect("disconnect succeeds from failed protected state");

    assert!(matches!(
        helper.status().state,
        ConnectionState::Disconnected
    ));
}

#[test]
fn supervisor_restarts_unprotected_engine_after_exit() {
    let (helper, controls, _, _) = supervised_helper(false);
    let mut request = connect_request();
    request.settings.kill_switch = false;
    helper.connect(&request).expect("first connect");
    let since = helper.status().since_unix;

    controls.kill();
    helper.supervise(Instant::now());

    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(helper.status().since_unix, since);
    assert_eq!(controls.spawns(), 2);
}

#[test]
fn supervisor_reuses_protection_after_exit() {
    let (helper, controls, prepared, reverted) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("first protected connect");

    controls.kill();
    helper.supervise(Instant::now());

    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(controls.spawns(), 2);
    assert_eq!(prepared.load(Ordering::Acquire), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

#[test]
fn supervisor_waits_for_route_and_recovers_without_releasing_protection() {
    let _lock = ROUTE_TEST_LOCK.lock().unwrap();
    NETWORK_PRESENT.store(true, Ordering::Release);
    let (helper, controls, prepared, reverted) = supervised_helper(true);
    let helper = helper.with_test_physical_interface(changing_route);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("first protected connect");

    NETWORK_PRESENT.store(false, Ordering::Release);
    let now = Instant::now();
    helper.supervise(now);
    assert_eq!(helper.status().state, ConnectionState::Connected);
    assert!(helper.session().unwrap().reconnect.is_none());
    assert_eq!(controls.spawns(), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);

    helper.supervise(now + SUPERVISOR_TICK);
    let status = helper.status();
    assert_eq!(status.state, ConnectionState::Reconnecting);
    assert_eq!(
        status.reconnect_failure_kind,
        Some(rosetun_config::FailureKind::NoNetwork)
    );
    assert_eq!(controls.spawns(), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);

    helper.supervise(now + Duration::from_secs(3600));
    assert_eq!(
        controls.spawns(),
        1,
        "missing route must not consume retries"
    );
    assert_eq!(
        helper
            .session()
            .unwrap()
            .reconnect
            .as_ref()
            .unwrap()
            .failures,
        0
    );
    assert_eq!(reverted.load(Ordering::Acquire), 0);

    NETWORK_PRESENT.store(true, Ordering::Release);
    helper.supervise(now + Duration::from_secs(3601));
    assert_eq!(helper.status().state, ConnectionState::Connected);
    assert_eq!(helper.status().reconnect_failure_kind, None);
    assert_eq!(controls.spawns(), 2);
    assert_eq!(prepared.load(Ordering::Acquire), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

#[test]
fn supervisor_resets_missing_route_ticks_after_network_returns() {
    let _lock = ROUTE_TEST_LOCK.lock().unwrap();
    NETWORK_PRESENT.store(true, Ordering::Release);
    let (helper, controls, _, reverted) = supervised_helper(true);
    let helper = helper.with_test_physical_interface(changing_route);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("first protected connect");

    let now = Instant::now();
    NETWORK_PRESENT.store(false, Ordering::Release);
    helper.supervise(now);
    NETWORK_PRESENT.store(true, Ordering::Release);
    helper.supervise(now + SUPERVISOR_TICK);
    NETWORK_PRESENT.store(false, Ordering::Release);
    helper.supervise(now + 2 * SUPERVISOR_TICK);

    assert_eq!(helper.status().state, ConnectionState::Connected);
    assert!(helper.session().unwrap().reconnect.is_none());
    assert_eq!(controls.spawns(), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);

    helper.supervise(now + 3 * SUPERVISOR_TICK);
    assert_eq!(helper.status().state, ConnectionState::Reconnecting);
    assert_eq!(controls.spawns(), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
    NETWORK_PRESENT.store(true, Ordering::Release);
}

fn assert_waiting_for_network(
    helper: &Helper,
    controls: &EngineControls,
    reverted: &AtomicUsize,
    expected_spawns: usize,
) {
    let status = helper.status();
    assert_eq!(status.state, ConnectionState::Reconnecting);
    assert_eq!(
        status.reconnect_failure_kind,
        Some(rosetun_config::FailureKind::NoNetwork)
    );
    assert_eq!(controls.spawns(), expected_spawns);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

#[test]
fn network_loss_for_twenty_ticks_reuses_a_live_tunnel() {
    use super::dns::test_support::{Behavior, Server};

    let _lock = ROUTE_TEST_LOCK.lock().unwrap();
    set_route_script(20);
    let server = Server::new(Behavior::Addresses);
    let (helper, controls, prepared, reverted) =
        supervised_helper_with_dns(true, Some(server.address()));
    let helper = helper.with_test_physical_interface(scripted_route);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("initial tunnel");
    let since = helper.status().since_unix;
    let now = Instant::now();

    for tick in 0..20 {
        helper.supervise(now + tick * SUPERVISOR_TICK);
        if tick == 0 {
            assert_eq!(helper.status().state, ConnectionState::Connected);
            assert_eq!(helper.status().reconnect_failure_kind, None);
        } else {
            assert_waiting_for_network(&helper, &controls, &reverted, 1);
        }
        assert_eq!(controls.spawns(), 1);
        assert_eq!(reverted.load(Ordering::Acquire), 0);
    }
    helper.supervise(now + 20 * SUPERVISOR_TICK);
    assert_eq!(helper.status().state, ConnectionState::Connected);
    assert_eq!(helper.status().reconnect_failure_kind, None);
    assert_eq!(helper.status().since_unix, since);
    assert_eq!(
        controls.spawns(),
        1,
        "the live tunnel must not be restarted"
    );
    assert_eq!(prepared.load(Ordering::Acquire), 0);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

#[test]
fn engine_exit_during_network_loss_restarts_only_when_route_returns() {
    use super::dns::test_support::{Behavior, Server};

    let _lock = ROUTE_TEST_LOCK.lock().unwrap();
    set_route_script(20);
    let server = Server::new(Behavior::Addresses);
    let (helper, controls, prepared, reverted) =
        supervised_helper_with_dns(true, Some(server.address()));
    let helper = helper.with_test_physical_interface(scripted_route);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("initial tunnel");
    let now = Instant::now();

    for tick in 0..20 {
        if tick == 3 {
            controls.kill();
        }
        helper.supervise(now + tick * SUPERVISOR_TICK);
        if tick == 0 {
            assert_eq!(helper.status().state, ConnectionState::Connected);
        } else {
            assert_waiting_for_network(&helper, &controls, &reverted, 1);
        }
    }
    assert!(helper.session().unwrap().process.is_none());
    helper.supervise(now + 20 * SUPERVISOR_TICK);
    assert_eq!(helper.status().state, ConnectionState::Connected);
    assert_eq!(helper.status().reconnect_failure_kind, None);
    assert_eq!(controls.spawns(), 2);
    assert_eq!(prepared.load(Ordering::Acquire), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

#[test]
fn brief_network_change_keeps_the_engine_and_protection() {
    use super::dns::test_support::{Behavior, Server};

    let _lock = ROUTE_TEST_LOCK.lock().unwrap();
    set_route_script(3);
    let server = Server::new(Behavior::Addresses);
    let (helper, controls, prepared, reverted) =
        supervised_helper_with_dns(true, Some(server.address()));
    let helper = helper.with_test_physical_interface(scripted_route);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("initial tunnel");
    let now = Instant::now();

    for tick in 0..3 {
        helper.supervise(now + tick * SUPERVISOR_TICK);
        if tick == 0 {
            assert_eq!(helper.status().state, ConnectionState::Connected);
            assert_eq!(helper.status().reconnect_failure_kind, None);
        } else {
            assert_waiting_for_network(&helper, &controls, &reverted, 1);
        }
    }
    helper.supervise(now + 3 * SUPERVISOR_TICK);
    assert_eq!(helper.status().state, ConnectionState::Connected);
    assert_eq!(helper.status().reconnect_failure_kind, None);
    assert_eq!(controls.spawns(), 1);
    assert_eq!(prepared.load(Ordering::Acquire), 0);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

#[test]
fn network_loss_longer_than_grace_stops_engine_and_restarts_on_return() {
    use super::dns::test_support::{Behavior, Server};

    let _lock = ROUTE_TEST_LOCK.lock().unwrap();
    set_route_script(65);
    let server = Server::new(Behavior::Addresses);
    let (helper, controls, prepared, reverted) =
        supervised_helper_with_dns(true, Some(server.address()));
    let helper = helper.with_test_physical_interface(scripted_route);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("initial tunnel");
    let now = Instant::now();

    for tick in 0..65 {
        helper.supervise(now + tick * SUPERVISOR_TICK);
        if tick == 0 {
            assert_eq!(helper.status().state, ConnectionState::Connected);
        } else {
            assert_waiting_for_network(&helper, &controls, &reverted, 1);
        }
        if tick < 30 {
            assert!(helper.session().unwrap().process.is_some());
        } else {
            assert!(helper.session().unwrap().process.is_none());
        }
    }
    helper.supervise(now + 65 * SUPERVISOR_TICK);
    assert_eq!(helper.status().state, ConnectionState::Connected);
    assert_eq!(helper.status().reconnect_failure_kind, None);
    assert_eq!(controls.spawns(), 2);
    assert_eq!(prepared.load(Ordering::Acquire), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

#[test]
fn failed_live_dns_check_restarts_inside_existing_protection() {
    use super::dns::test_support::{Behavior, Server};

    let _lock = ROUTE_TEST_LOCK.lock().unwrap();
    set_route_script(3);
    let server = Server::new(Behavior::Addresses);
    let (helper, controls, prepared, reverted) =
        supervised_helper_with_dns(true, Some(server.address()));
    let helper = helper.with_test_physical_interface(scripted_route);
    shorten_dns_timeouts(&helper);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("initial tunnel");
    drop(server);
    let now = Instant::now();
    for tick in 0..3 {
        helper.supervise(now + tick * SUPERVISOR_TICK);
    }
    assert_waiting_for_network(&helper, &controls, &reverted, 1);

    helper.supervise(now + 3 * SUPERVISOR_TICK);
    assert_eq!(helper.status().state, ConnectionState::Reconnecting);
    assert_eq!(helper.status().reconnect_failure_kind, None);
    assert_eq!(
        controls.spawns(),
        2,
        "failed DNS must trigger an immediate restart"
    );
    assert_eq!(prepared.load(Ordering::Acquire), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

#[test]
fn network_reconnect_does_not_wait_for_the_full_dns_timeout() {
    use super::dns::test_support::{Behavior, Server};

    let _lock = ROUTE_TEST_LOCK.lock().unwrap();
    set_route_script(32);
    let server = Server::new(Behavior::Addresses);
    let (helper, controls, prepared, reverted) =
        supervised_helper_with_dns(true, Some(server.address()));
    let helper = helper.with_test_physical_interface(scripted_route);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("initial tunnel");
    drop(server);
    let now = Instant::now();

    for tick in 0..32 {
        helper.supervise(now + tick * SUPERVISOR_TICK);
        if tick == 0 {
            assert_eq!(helper.status().state, ConnectionState::Connected);
        } else {
            assert_waiting_for_network(&helper, &controls, &reverted, 1);
        }
    }
    assert!(helper.session().unwrap().process.is_none());
    let started = Instant::now();
    helper.supervise(now + 32 * SUPERVISOR_TICK);
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "retry must not wait for the full 60-second DNS deadline"
    );
    assert_eq!(helper.status().state, ConnectionState::Reconnecting);
    assert_eq!(controls.spawns(), 2);
    assert_eq!(prepared.load(Ordering::Acquire), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

#[test]
fn network_loss_without_auto_reconnect_keeps_live_session() {
    let _lock = ROUTE_TEST_LOCK.lock().unwrap();
    set_route_script(20);
    let (helper, controls, prepared, reverted) = supervised_helper(true);
    let helper = helper.with_test_physical_interface(scripted_route);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    request.settings.auto_reconnect = false;
    helper.connect(&request).expect("first protected connect");
    let since = helper.status().since_unix;
    let now = Instant::now();

    for tick in 0..20 {
        helper.supervise(now + tick * SUPERVISOR_TICK);
        assert_eq!(helper.status().state, ConnectionState::Connected);
        assert_eq!(helper.status().reconnect_failure_kind, None);
        assert_eq!(helper.status().since_unix, since);
        assert!(helper.session().unwrap().request.is_some());
        assert!(helper.session().unwrap().process.is_some());
        assert_eq!(controls.spawns(), 1);
        assert_eq!(prepared.load(Ordering::Acquire), 0);
        assert_eq!(reverted.load(Ordering::Acquire), 0);
    }

    helper.supervise(now + 20 * SUPERVISOR_TICK);
    assert_eq!(helper.status().state, ConnectionState::Connected);
    assert_eq!(controls.spawns(), 1);
    assert_eq!(prepared.load(Ordering::Acquire), 0);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

#[test]
fn engine_exit_without_auto_reconnect_still_fails_protected_during_network_loss() {
    let _lock = ROUTE_TEST_LOCK.lock().unwrap();
    set_route_script(20);
    let (helper, controls, prepared, reverted) = supervised_helper(true);
    let helper = helper.with_test_physical_interface(scripted_route);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    request.settings.auto_reconnect = false;
    helper.connect(&request).expect("first protected connect");
    let now = Instant::now();

    for tick in 0..4 {
        helper.supervise(now + tick * SUPERVISOR_TICK);
        assert_eq!(helper.status().state, ConnectionState::Connected);
    }
    controls.kill();
    helper.supervise(now + 4 * SUPERVISOR_TICK);
    assert!(matches!(
        helper.status().state,
        ConnectionState::FailedProtected {
            ref reason,
            failure_kind: None,
        } if reason == "the engine process exited"
    ));
    assert!(helper.session().unwrap().request.is_none());
    assert_eq!(controls.spawns(), 1);
    assert_eq!(prepared.load(Ordering::Acquire), 0);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

fn signal_dns_stall(helper: &Helper) {
    let mut session = helper.session().expect("session");
    if let Some(watchdog) = session.watchdog.take() {
        watchdog.stop();
    }
    session.watchdog = Some(DnsWatchdog::stalled_for_test());
}

#[test]
fn dns_stall_reuses_supervisor_retry_pipeline_and_cause() {
    for protected in [false, true] {
        let (helper, controls, prepared, reverted) = supervised_helper(protected);
        let mut request = connect_request();
        request.settings.kill_switch = protected;
        helper.connect(&request).expect("first connect");
        let since = helper.status().since_unix;
        controls.fail_next(1);
        signal_dns_stall(&helper);

        let now = Instant::now();
        helper.supervise(now);
        assert!(matches!(
            helper.status().state,
            ConnectionState::Reconnecting
        ));
        assert_eq!(helper.status().since_unix, since);
        assert_eq!(controls.spawns(), 2);
        let session = helper.session().expect("session");
        let pending = session.reconnect.as_ref().expect("retry scheduled");
        assert_eq!(pending.cause, "dns stalled");
        assert_eq!(pending.failures, 1);
        assert!(session.watchdog.is_none());
        drop(session);

        helper.supervise(now + Duration::from_secs(60));
        assert!(matches!(helper.status().state, ConnectionState::Connected));
        assert_eq!(helper.status().since_unix, since);
        assert_eq!(controls.spawns(), 3);
        assert_eq!(prepared.load(Ordering::Acquire), usize::from(protected) * 2);
        assert_eq!(reverted.load(Ordering::Acquire), 0);
        helper.supervise(now + Duration::from_secs(120));
        assert_eq!(controls.spawns(), 3, "old stall must not recur");
    }
}

#[test]
fn disabled_auto_reconnect_consumes_stall_but_stays_connected() {
    for protected in [false, true] {
        let (helper, controls, _, reverted) = supervised_helper(protected);
        let mut request = connect_request();
        request.settings.kill_switch = protected;
        request.settings.auto_reconnect = false;
        helper.connect(&request).expect("first connect");
        signal_dns_stall(&helper);

        helper.supervise(Instant::now());
        helper.supervise(Instant::now() + Duration::from_secs(60));
        assert!(matches!(helper.status().state, ConnectionState::Connected));
        assert!(helper.status().since_unix.is_some());
        assert_eq!(controls.spawns(), 1);
        assert_eq!(reverted.load(Ordering::Acquire), 0);
        assert!(
            !helper
                .session()
                .expect("session")
                .watchdog
                .as_ref()
                .expect("test watchdog")
                .take_stalled()
        );
    }
}

#[test]
fn dns_stall_reconnect_starts_a_fresh_watchdog_and_disconnect_cleans_up() {
    use super::dns::test_support::{Behavior, Server};

    let server = Server::new(Behavior::Noerror);
    let (helper, controls, _, _) = supervised_helper_with_dns(false, Some(server.address()));
    shorten_dns_timeouts(&helper);
    let mut request = connect_request();
    request.settings.kill_switch = false;
    helper.connect(&request).expect("first DNS-checked connect");
    assert_eq!(
        helper.session().expect("session").tunnel_dns,
        Some(server.address())
    );
    assert!(helper.session().expect("session").watchdog.is_some());
    signal_dns_stall(&helper);

    helper.supervise(Instant::now());
    let session = helper.session().expect("session");
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(session.tunnel_dns, Some(server.address()));
    assert!(
        !session
            .watchdog
            .as_ref()
            .expect("new watchdog")
            .take_stalled()
    );
    drop(session);
    assert_eq!(controls.spawns(), 2);

    helper.disconnect().expect("disconnect stops watchdog");
    let session = helper.session().expect("session");
    assert!(session.watchdog.is_none());
    assert!(session.tunnel_dns.is_none());
    drop(session);
    helper.supervise(Instant::now() + Duration::from_secs(60));
    assert_eq!(controls.spawns(), 2);
}

#[test]
fn dns_lock_survives_engine_restarts() {
    use super::dns::test_support::{Behavior, Server};

    let server = Server::new(Behavior::Noerror);
    let (helper, controls, prepared, reverted) =
        supervised_helper_with_dns(false, Some(server.address()));
    shorten_dns_timeouts(&helper);
    let mut request = connect_request();
    request.settings.kill_switch = false;
    helper
        .connect(&request)
        .expect("first connect with DNS lock");
    assert_eq!(
        helper
            .session()
            .expect("session")
            .guard
            .as_ref()
            .map(|guard| guard.scope),
        Some(ProtectionScope::DnsOnly)
    );

    controls.kill();
    helper.supervise(Instant::now());
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(controls.spawns(), 2);
    assert_eq!(prepared.load(Ordering::Acquire), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
    assert_eq!(
        helper
            .session()
            .expect("session")
            .guard
            .as_ref()
            .map(|guard| guard.scope),
        Some(ProtectionScope::DnsOnly)
    );
}

#[test]
fn dns_lock_is_released_when_reconnects_are_exhausted() {
    use super::dns::test_support::{Behavior, Server};

    let server = Server::new(Behavior::Noerror);
    let (helper, controls, prepared, reverted) =
        supervised_helper_with_dns(false, Some(server.address()));
    shorten_dns_timeouts(&helper);
    let mut request = connect_request();
    request.settings.kill_switch = false;
    helper
        .connect(&request)
        .expect("first connect with DNS lock");
    controls.fail_next(RECONNECT_ATTEMPTS as usize);
    controls.kill();
    let now = Instant::now();
    helper.supervise(now);
    assert!(matches!(
        helper.status().state,
        ConnectionState::Reconnecting
    ));
    assert_eq!(reverted.load(Ordering::Acquire), 0);
    for attempt in 2..=RECONNECT_ATTEMPTS {
        helper.supervise(now + Duration::from_secs(u64::from(attempt) * 60));
    }

    assert!(matches!(
        helper.status().state,
        ConnectionState::Failed { .. }
    ));
    assert_eq!(
        prepared.load(Ordering::Acquire),
        RECONNECT_ATTEMPTS as usize
    );
    assert_eq!(reverted.load(Ordering::Acquire), 1);
    let session = helper.session().expect("session");
    assert!(session.guard.is_none());
    assert!(session.process.is_none());
    assert!(session.tunnel_dns.is_none());
    assert!(session.watchdog.is_none());
}

#[test]
fn dns_lock_is_released_when_auto_reconnect_is_off() {
    use super::dns::test_support::{Behavior, Server};

    let server = Server::new(Behavior::Noerror);
    let (helper, controls, _, reverted) = supervised_helper_with_dns(false, Some(server.address()));
    shorten_dns_timeouts(&helper);
    let mut request = connect_request();
    request.settings.kill_switch = false;
    request.settings.auto_reconnect = false;
    helper
        .connect(&request)
        .expect("first connect with DNS lock");
    controls.kill();
    helper.supervise(Instant::now());

    assert!(matches!(
        helper.status().state,
        ConnectionState::Failed { .. }
    ));
    assert_eq!(reverted.load(Ordering::Acquire), 1);
    let session = helper.session().expect("session");
    assert!(session.guard.is_none());
    assert!(session.process.is_none());
    assert!(session.tunnel_dns.is_none());
    assert!(session.watchdog.is_none());
}

#[test]
fn disconnect_releases_dns_lock() {
    use super::dns::test_support::{Behavior, Server};

    let server = Server::new(Behavior::Noerror);
    let (helper, _, _, reverted) = supervised_helper_with_dns(false, Some(server.address()));
    shorten_dns_timeouts(&helper);
    let mut request = connect_request();
    request.settings.kill_switch = false;
    helper.connect(&request).expect("connect with DNS lock");
    helper.disconnect().expect("disconnect releases DNS lock");

    assert!(matches!(
        helper.status().state,
        ConnectionState::Disconnected
    ));
    assert_eq!(reverted.load(Ordering::Acquire), 1);
    assert!(helper.session().expect("session").guard.is_none());
}

#[test]
fn disabled_reconnect_leaves_both_session_types_failed() {
    for protected in [false, true] {
        let (helper, controls, _, reverted) = supervised_helper(protected);
        let mut request = connect_request();
        request.settings.kill_switch = protected;
        request.settings.auto_reconnect = false;
        helper.connect(&request).expect("first connect");
        controls.kill();
        helper.supervise(Instant::now());
        if protected {
            assert!(matches!(
                helper.status().state,
                ConnectionState::FailedProtected { .. }
            ));
        } else {
            assert!(matches!(
                helper.status().state,
                ConnectionState::Failed { .. }
            ));
        }
        helper.supervise(Instant::now() + Duration::from_secs(60));
        assert_eq!(controls.spawns(), 1);
        assert_eq!(reverted.load(Ordering::Acquire), 0);
    }
}

#[test]
fn supervisor_backs_off_and_gives_up_after_five_failures() {
    for protected in [false, true] {
        let (helper, controls, prepared, reverted) = supervised_helper(protected);
        let mut request = connect_request();
        request.settings.kill_switch = protected;
        helper.connect(&request).expect("first connect");
        controls.fail_next(RECONNECT_ATTEMPTS as usize);
        controls.kill();
        let now = Instant::now();
        helper.supervise(now);
        assert!(matches!(
            helper.status().state,
            ConnectionState::Reconnecting
        ));
        assert_eq!(controls.spawns(), 2);
        helper.supervise(now);
        assert_eq!(controls.spawns(), 2, "backoff prevents immediate retry");

        for attempt in 2..=RECONNECT_ATTEMPTS {
            helper.supervise(now + Duration::from_secs(u64::from(attempt) * 60));
            assert_eq!(controls.spawns(), (attempt + 1) as usize);
        }
        let status = helper.status();
        if protected {
            assert!(matches!(
                status.state,
                ConnectionState::FailedProtected { .. }
            ));
        } else {
            assert!(matches!(status.state, ConnectionState::Failed { .. }));
        }
        assert!(status.since_unix.is_none());
        assert!(helper.session().expect("session").request.is_none());
        assert!(helper.session().expect("session").reconnect.is_none());
        assert_eq!(reverted.load(Ordering::Acquire), 0);
        if protected {
            assert_eq!(
                prepared.load(Ordering::Acquire),
                RECONNECT_ATTEMPTS as usize
            );
            assert!(helper.session().expect("session").guard.is_some());
        }
        helper.supervise(now + Duration::from_secs(600));
        assert_eq!(controls.spawns(), (RECONNECT_ATTEMPTS + 1) as usize);
    }
}

#[test]
fn supervisor_delays_resume_reconnect_and_consumes_resume_flag() {
    let (helper, controls, _, _) = supervised_helper(false);
    let mut request = connect_request();
    request.settings.kill_switch = false;
    helper.connect(&request).expect("first connect");
    let now = Instant::now();
    helper.notify_resume();
    helper.supervise(now);
    assert!(matches!(
        helper.status().state,
        ConnectionState::Reconnecting
    ));
    assert_eq!(controls.spawns(), 1);
    helper.supervise(now + Duration::from_secs(3));
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(controls.spawns(), 2);
    helper.supervise(now + Duration::from_secs(10));
    assert_eq!(controls.spawns(), 2);
}

#[test]
fn disabled_reconnect_ignores_resume_while_engine_is_running() {
    let (helper, controls, _, _) = supervised_helper(false);
    let mut request = connect_request();
    request.settings.kill_switch = false;
    request.settings.auto_reconnect = false;
    helper.connect(&request).expect("first connect");
    helper.notify_resume();
    helper.supervise(Instant::now());
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert!(!helper.resumed.load(Ordering::Acquire));
    assert_eq!(controls.spawns(), 1);
}

#[test]
fn supervisor_does_not_wait_for_a_busy_session() {
    let (helper, controls, _, _) = supervised_helper(false);
    let mut request = connect_request();
    request.settings.kill_switch = false;
    helper.connect(&request).expect("first connect");
    controls.kill();
    let session = helper.session().expect("hold session lock");
    helper.supervise(Instant::now());
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(controls.spawns(), 1);
    drop(session);
    helper.supervise(Instant::now());
    assert_eq!(controls.spawns(), 2);
}

#[test]
fn supervisor_ignores_resume_without_a_tunnel() {
    let (helper, controls, _, _) = supervised_helper(false);
    helper.notify_resume();
    helper.supervise(Instant::now());
    assert!(matches!(
        helper.status().state,
        ConnectionState::Disconnected
    ));
    assert!(!helper.resumed.load(Ordering::Acquire));
    assert_eq!(controls.spawns(), 0);
}

#[test]
fn disconnect_cancels_pending_reconnect() {
    let (helper, controls, _, reverted) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("first connect");
    controls.fail_next(1);
    controls.kill();
    let now = Instant::now();
    helper.supervise(now);
    assert!(matches!(
        helper.status().state,
        ConnectionState::Reconnecting
    ));

    helper.disconnect().expect("disconnect during backoff");
    helper.supervise(now + Duration::from_secs(60));
    assert!(matches!(
        helper.status().state,
        ConnectionState::Disconnected
    ));
    assert_eq!(controls.spawns(), 2);
    assert_eq!(reverted.load(Ordering::Acquire), 1);
}

#[test]
fn wall_clock_gap_detects_sleep_only_for_large_forward_jumps() {
    let now = SystemTime::now();
    assert!(slept(now, now + Duration::from_secs(31)));
    assert!(!slept(now, now + Duration::from_secs(1)));
    assert!(!slept(now, now - Duration::from_secs(31)));
}

fn protected_helper(
    engine: Box<dyn EngineBackend>,
) -> (Helper, Arc<AtomicUsize>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let prepared = Arc::new(AtomicUsize::new(0));
    let authorized = Arc::new(AtomicUsize::new(0));
    let reverted = Arc::new(AtomicUsize::new(0));
    let mut engines = EngineRegistry::new();
    engines.register(engine);
    let helper = Helper::new(engines, Box::new(UnusedRouting), VerboseGate::default());

    {
        let mut session = helper.session().expect("session");
        let prepare_count = Arc::clone(&prepared);
        let authorize_count = Arc::clone(&authorized);
        let revert_count = Arc::clone(&reverted);
        session.guard = Some(Guard {
            routing: Arc::new(Mutex::new(RoutingGuard::new_with_reconnector(
                move |plan, _| {
                    assert!(plan.allow_lan);
                    prepare_count.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                },
                move |_| {
                    authorize_count.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                },
                move || {
                    revert_count.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                },
            ))),
            scope: ProtectionScope::AllTraffic,
        });
        session.last_endpoint = Some(SuccessfulEndpoint {
            // This domain must never be resolved during reconnect.
            server: "cached.invalid".to_owned(),
            address: "203.0.113.10".parse().expect("IP"),
        });
        session.process = Some(Box::new(ExitedProcess));
    }
    helper.with_status(|status| {
        status.state = ConnectionState::FailedProtected {
            failure_kind: None,
            reason: "old failure".into(),
        };
    });
    (helper, prepared, authorized, reverted)
}

fn protected_request() -> ConnectRequest {
    let mut request = connect_request();
    request.node.server = "CACHED.INVALID.".to_owned();
    request.settings.kill_switch = true;
    request.settings.allow_lan = true;
    request
}

#[test]
fn protected_reconnect_reuses_guard_and_cached_domain_endpoint() {
    let (helper, prepared, authorized, reverted) = protected_helper(Box::new(StubEngine));
    helper
        .connect(&protected_request())
        .expect("protected reconnect");

    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(prepared.load(Ordering::Acquire), 1);
    assert_eq!(authorized.load(Ordering::Acquire), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);

    helper.disconnect().expect("disconnect");
    assert_eq!(reverted.load(Ordering::Acquire), 1);
}

#[test]
fn protected_reconnect_replaces_the_traffic_monitor_and_control() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let controls = Arc::new(Mutex::new(Vec::new()));
    let totals = TrafficTotals { up: 100, down: 200 };
    let (helper, _, _, _) = protected_helper(Box::new(TrafficEngine {
        totals,
        dropped: Arc::clone(&dropped),
        asked: Arc::default(),
        controls: Arc::clone(&controls),
        verbose_logs: Arc::new(Mutex::new(Vec::new())),
        closed: Arc::default(),
    }));
    helper.connect(&protected_request()).expect("first connect");
    wait_for_totals(&helper, totals);

    helper.with_status(|status| {
        status.state = ConnectionState::FailedProtected {
            failure_kind: None,
            reason: "engine failed".to_owned(),
        };
    });
    helper.connect(&protected_request()).expect("reconnect");
    assert_eq!(dropped.load(Ordering::Acquire), 1);
    wait_for_totals(&helper, totals);
    let controls = controls.lock().expect("test controls mutex");
    assert_eq!(controls.len(), 2);
    assert_ne!(controls[0].secret, controls[1].secret);
    drop(controls);

    helper.disconnect().expect("disconnect");
    assert_eq!(helper.status().traffic, Traffic::default());
    assert_eq!(dropped.load(Ordering::Acquire), 2);
}

#[test]
fn failed_protected_reconnect_does_not_revert_guard() {
    let (helper, prepared, _, reverted) = protected_helper(Box::new(ExitedEngine));
    helper
        .connect(&protected_request())
        .expect_err("new engine exits");

    assert!(matches!(
        helper.status().state,
        ConnectionState::FailedProtected { .. }
    ));
    assert_eq!(prepared.load(Ordering::Acquire), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
    assert!(helper.session().expect("session").guard.is_some());
}

#[test]
fn protected_reconnect_to_other_domain_fails_without_dns_or_guard_release() {
    let (helper, prepared, _, reverted) = protected_helper(Box::new(StubEngine));
    let mut request = protected_request();
    request.node.server = "another.invalid".into();

    let error = helper.connect(&request).expect_err("different domain");
    assert_eq!(
        error.message,
        "cannot resolve a new server name while protection is active; use an IP address or the last connected server",
    );
    assert!(matches!(
        helper.status().state,
        ConnectionState::FailedProtected { .. }
    ));
    assert_eq!(prepared.load(Ordering::Acquire), 0);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

#[test]
fn protected_reconnect_cannot_disable_kill_switch() {
    let (helper, prepared, _, reverted) = protected_helper(Box::new(StubEngine));
    let mut request = protected_request();
    request.settings.kill_switch = false;

    helper
        .connect(&request)
        .expect_err("explicit disconnect required");
    assert!(matches!(
        helper.status().state,
        ConnectionState::FailedProtected { .. }
    ));
    assert_eq!(prepared.load(Ordering::Acquire), 0);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

#[test]
fn connect_from_connected_is_still_rejected() {
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(StubEngine));
    let helper = Helper::new(engines, Box::new(UnusedRouting), VerboseGate::default());
    let request = connect_request();

    helper.connect(&request).expect("fresh connect");
    let error = helper.connect(&request).expect_err("already connected");
    assert_eq!(error.code, ErrorCode::InvalidState);
    assert!(matches!(helper.status().state, ConnectionState::Connected));
}

#[test]
fn disconnect_recovers_poisoned_session_and_releases_protection() {
    let reverted = Arc::new(AtomicUsize::new(0));
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(StubEngine));
    let helper = Arc::new(Helper::new(
        engines,
        Box::new(CountingRouting {
            reverted: Arc::clone(&reverted),
        }),
        VerboseGate::default(),
    ));
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper
        .connect(&request)
        .expect("protected connection starts");

    let panicking_helper = Arc::clone(&helper);
    let worker = thread::spawn(move || {
        let _session = panicking_helper.session.lock().unwrap();
        panic!("simulated session panic");
    });
    assert!(worker.join().is_err());
    assert_eq!(
        helper.connect(&request).unwrap_err().code,
        ErrorCode::Internal
    );

    helper.disconnect().expect("poisoned session is torn down");
    assert_eq!(reverted.load(Ordering::Acquire), 1);
    assert_eq!(helper.status(), Status::default());
    helper
        .connect(&request)
        .expect("a new connection is accepted");
    helper.disconnect().expect("new connection is torn down");
    assert_eq!(reverted.load(Ordering::Acquire), 2);
}

#[test]
fn protected_endpoint_requires_matching_cache_but_accepts_literal_ip() {
    let mut request = protected_request();
    assert!(protected_endpoint(&request.node, None).is_err());

    request.node.server = "198.51.100.7".into();
    assert_eq!(
        protected_endpoint(&request.node, None).expect("literal IP"),
        "198.51.100.7".parse::<IpAddr>().expect("IP"),
    );
}

#[derive(Debug)]
struct RecordingRouting {
    controls: Arc<EngineControls>,
    binaries: Arc<Mutex<Vec<Vec<PathBuf>>>>,
    prepared: Arc<AtomicUsize>,
    reverted: Arc<AtomicUsize>,
}

impl RoutingBackend for RecordingRouting {
    fn name(&self) -> &'static str {
        "test-chain"
    }

    fn preflight(&self) -> Result<(), RoutingError> {
        Ok(())
    }

    fn begin_protection(
        &mut self,
        _plan: &RoutingPlan,
        binaries: &[&Path],
    ) -> Result<RoutingGuard, RoutingError> {
        self.binaries
            .lock()
            .unwrap()
            .push(binaries.iter().map(|path| (*path).to_owned()).collect());
        self.controls.events.lock().unwrap().push("protect");
        let controls = Arc::clone(&self.controls);
        let binaries = Arc::clone(&self.binaries);
        let prepared = Arc::clone(&self.prepared);
        let reverted = Arc::clone(&self.reverted);
        Ok(RoutingGuard::new_with_reconnector(
            move |_, paths| {
                binaries
                    .lock()
                    .unwrap()
                    .push(paths.iter().map(|path| (*path).to_owned()).collect());
                prepared.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
            move |_| {
                controls.events.lock().unwrap().push("tunnel");
                Ok(())
            },
            move || {
                reverted.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        ))
    }
}

#[derive(Debug)]
struct FakeXrayRunner {
    controls: Arc<EngineControls>,
    running: Mutex<Option<Arc<AtomicBool>>>,
    starts: AtomicUsize,
    endpoint_count: AtomicUsize,
    fail_next: AtomicBool,
    probe_path: PathBuf,
    binary: Option<PathBuf>,
}

impl FakeXrayRunner {
    fn kill(&self) {
        self.running
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .store(false, Ordering::Release);
    }
}

impl Drop for FakeXrayRunner {
    fn drop(&mut self) {
        if let Some(binary) = &self.binary {
            std::fs::remove_file(binary).unwrap();
            std::fs::remove_dir(binary.parent().unwrap()).unwrap();
        }
    }
}

impl XrayRunner for FakeXrayRunner {
    fn binary_path(&self) -> Result<PathBuf, EngineError> {
        self.binary
            .clone()
            .map_or_else(|| std::env::current_exe().map_err(Into::into), Ok)
    }

    fn locate_binary(&self) -> Result<PathBuf, EngineError> {
        self.binary_path()
    }

    fn probe_config_path(&self) -> PathBuf {
        self.probe_path.clone()
    }

    fn spawn(
        &self,
        _binary: &Path,
        config: &RenderedConfig,
        endpoints: &[&SocksEndpoint],
        _verbose_until_unix: Arc<AtomicU64>,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        assert!(!endpoints.is_empty());
        assert!(!config.body.is_empty());
        if config.file_name == "probe.json" {
            std::fs::write(&self.probe_path, &config.body)?;
        }
        self.controls.events.lock().unwrap().push("xray");
        self.endpoint_count
            .store(endpoints.len(), Ordering::Release);
        self.starts.fetch_add(1, Ordering::AcqRel);
        if self.fail_next.swap(false, Ordering::AcqRel) {
            return Err(EngineError::BinaryNotFound("test Xray".into()));
        }
        let running = Arc::new(AtomicBool::new(true));
        *self.running.lock().unwrap() = Some(Arc::clone(&running));
        Ok(Box::new(ControlledProcess {
            running,
            ready: true,
            adapter_busy: false,
        }))
    }
}

/// Helper, engine controls, Xray runner, binaries passed to routing, and the
/// prepare and revert counters of the routing guard.
type XrayChainHelper = (
    Helper,
    Arc<EngineControls>,
    Arc<FakeXrayRunner>,
    Arc<Mutex<Vec<Vec<PathBuf>>>>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
);

fn xray_chain_helper() -> XrayChainHelper {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let controls = Arc::new(EngineControls::default());
    let binaries = Arc::new(Mutex::new(Vec::new()));
    let prepared = Arc::new(AtomicUsize::new(0));
    let reverted = Arc::new(AtomicUsize::new(0));
    let dir = std::env::temp_dir().join(format!(
        "rosetun-xray-chain-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).unwrap();
    let binary = dir.join("xray.exe");
    std::fs::write(&binary, []).unwrap();
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(ControlledEngine {
        controls: Arc::clone(&controls),
        dns_server: None,
    }));
    let runner = Arc::new(FakeXrayRunner {
        controls: Arc::clone(&controls),
        running: Mutex::new(None),
        starts: AtomicUsize::new(0),
        endpoint_count: AtomicUsize::new(0),
        fail_next: AtomicBool::new(false),
        probe_path: dir.join("probe.json"),
        binary: Some(binary),
    });
    let helper = Helper::new(
        engines,
        Box::new(RecordingRouting {
            controls: Arc::clone(&controls),
            binaries: Arc::clone(&binaries),
            prepared: Arc::clone(&prepared),
            reverted: Arc::clone(&reverted),
        }),
        VerboseGate::default(),
    )
    .with_xray_runner(Arc::clone(&runner) as Arc<dyn XrayRunner>)
    .with_test_physical_interface(|_| Some("Ethernet".into()));
    (helper, controls, runner, binaries, prepared, reverted)
}

fn reality_request() -> ConnectRequest {
    let mut request = connect_request();
    request.settings.kill_switch = true;
    request.node.stream.tls = rosetun_config::TlsMode::Reality(rosetun_config::RealityParams {
        sni: Some("example.com".into()),
        public_key: "test-public-key".into(),
        short_id: None,
        fingerprint: None,
    });
    request
}

#[test]
fn xray_chain_protects_then_starts_xray_then_singbox() {
    let (helper, controls, runner, binaries, _, _) = xray_chain_helper();
    let mut plain = connect_request();
    plain.settings.kill_switch = true;
    helper.connect(&plain).unwrap();
    assert_eq!(binaries.lock().unwrap()[0].len(), 1);
    assert_eq!(runner.starts.load(Ordering::Acquire), 0);
    helper.disconnect().unwrap();

    controls.events.lock().unwrap().clear();
    helper.connect(&reality_request()).unwrap();
    assert_eq!(binaries.lock().unwrap()[1].len(), 2);
    assert_eq!(
        *controls.events.lock().unwrap(),
        ["protect", "xray", "sing-box", "tunnel"]
    );
    assert_eq!(runner.starts.load(Ordering::Acquire), 1);
    assert!(helper.status().xray);
    assert_eq!(
        helper.status().xray_use,
        Some(rosetun_config::XrayUse::Auto)
    );
    helper.disconnect().unwrap();
    assert!(
        !runner
            .running
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .load(Ordering::Acquire)
    );
}

#[test]
fn xray_crash_keeps_protection_and_distinguishes_stopped_from_not_started() {
    let (helper, controls, runner, _, _, _) = xray_chain_helper();
    let request = reality_request();
    helper.connect(&request).unwrap();
    runner.kill();
    runner.fail_next.store(true, Ordering::Release);
    helper.supervise(Instant::now());
    assert_eq!(helper.status().state, ConnectionState::Reconnecting);
    assert!(helper.status().xray_stopped);
    assert_eq!(controls.spawns(), 1);
    assert!(helper.session().unwrap().guard.is_some());
    helper.supervise(Instant::now() + Duration::from_secs(3));
    assert_eq!(helper.status().state, ConnectionState::Connected);
    assert!(!helper.status().xray_stopped);

    helper.disconnect().unwrap();
    runner.fail_next.store(true, Ordering::Release);
    let error = helper.connect(&request).unwrap_err();
    assert_eq!(error.code, ErrorCode::XrayStartFailed);
    assert!(matches!(
        helper.status().state,
        ConnectionState::FailedProtected {
            failure_kind: Some(rosetun_config::FailureKind::XrayStartFailed),
            ..
        }
    ));
    assert!(helper.session().unwrap().guard.is_some());
    helper.disconnect().unwrap();
}

#[test]
fn xray_stop_without_auto_reconnect_is_a_protected_failure() {
    let (helper, controls, runner, _, _, _) = xray_chain_helper();
    let mut request = reality_request();
    request.settings.auto_reconnect = false;
    helper.connect(&request).unwrap();
    runner.kill();
    helper.supervise(Instant::now());
    assert!(matches!(
        helper.status().state,
        ConnectionState::FailedProtected {
            failure_kind: Some(rosetun_config::FailureKind::XrayStopped),
            ..
        }
    ));
    assert!(
        !controls
            .running
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .load(Ordering::Acquire)
    );
    assert!(helper.session().unwrap().guard.is_some());
    helper.disconnect().unwrap();
}

#[test]
fn apply_plain_to_xray_restarts_under_the_guard() {
    let (helper, controls, runner, binaries, prepared, reverted) = xray_chain_helper();
    let mut plain = connect_request();
    plain.settings.kill_switch = true;
    helper.connect(&plain).unwrap();

    let reality = reality_request();
    assert!(!super::apply::needs_reconnect(&plain, &reality));
    helper.apply(&reality).unwrap();

    assert_eq!(controls.spawns(), 2);
    assert_eq!(runner.starts.load(Ordering::Acquire), 1);
    assert_eq!(prepared.load(Ordering::Acquire), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
    let binaries = binaries.lock().unwrap();
    assert_eq!(binaries.len(), 2);
    assert_eq!(binaries[0].len(), 1);
    assert_eq!(binaries[1].len(), 2);
    assert_eq!(binaries[1][1].file_name().unwrap(), "xray.exe");
    assert!(helper.status().xray);
}

#[test]
fn apply_another_xray_node_restarts_under_the_guard() {
    let (helper, controls, runner, binaries, prepared, reverted) = xray_chain_helper();
    let current = reality_request();
    helper.connect(&current).unwrap();

    let mut next = current.clone();
    next.node.id = NodeId::new("another-reality");
    next.selection.node = next.node.id.clone();
    next.node.server = "192.0.2.2".into();
    assert!(!super::apply::needs_reconnect(&current, &next));
    helper.apply(&next).unwrap();

    assert_eq!(controls.spawns(), 2);
    assert_eq!(runner.starts.load(Ordering::Acquire), 2);
    assert_eq!(prepared.load(Ordering::Acquire), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
    let binaries = binaries.lock().unwrap();
    assert_eq!(binaries.len(), 2);
    assert!(
        binaries
            .iter()
            .all(|paths| paths.len() == 2 && paths[1].file_name().unwrap() == "xray.exe")
    );
    assert_eq!(helper.status().node, Some(next.node.id));
}

#[test]
fn apply_xray_to_plain_restarts_under_the_guard() {
    let (helper, controls, runner, binaries, prepared, reverted) = xray_chain_helper();
    let current = reality_request();
    helper.connect(&current).unwrap();

    let mut plain = connect_request();
    plain.settings.kill_switch = true;
    assert!(!super::apply::needs_reconnect(&current, &plain));
    helper.apply(&plain).unwrap();

    assert_eq!(controls.spawns(), 2);
    assert_eq!(runner.starts.load(Ordering::Acquire), 1);
    assert!(
        !runner
            .running
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .load(Ordering::Acquire)
    );
    assert_eq!(prepared.load(Ordering::Acquire), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
    let binaries = binaries.lock().unwrap();
    assert_eq!(binaries.len(), 2);
    assert_eq!(binaries[0].len(), 2);
    assert_eq!(binaries[0][1].file_name().unwrap(), "xray.exe");
    assert_eq!(binaries[1].len(), 1);
    assert!(!helper.status().xray);
}

fn connect_request() -> ConnectRequest {
    ConnectRequest {
        selection: Selection {
            subscription: SubscriptionId::new("sub"),
            node: NodeId::new("node"),
        },
        node: Node {
            id: NodeId::new("node"),
            name: "test".to_owned(),
            server: "127.0.0.1".to_owned(),
            port: 443,
            outbound: Outbound::Vless(VlessParams {
                uuid: "00000000-0000-0000-0000-000000000000".to_owned(),
                flow: None,
            }),
            stream: Default::default(),
            raw: None,
        },
        rule_set: RuleSet::new(RuleSetId::new("base"), "base", RuleTarget::Proxy),
        extra_nodes: Vec::new(),
        temporary_rules: Vec::new(),
        lists: Vec::new(),
        settings: Settings::default(),
        rule_templates: Vec::new(),
    }
}

fn request_with_new_rules(request: &ConnectRequest) -> ConnectRequest {
    let mut updated = request.clone();
    updated.rule_set.rules.push(Rule {
        id: RuleId::new("block-example"),
        enabled: true,
        matcher: RuleMatcher::IpCidr("192.0.2.0/24".to_owned()),
        target: RuleTarget::Block,
        exit: None,
    });
    updated
}

fn temporary_rule() -> Rule {
    Rule {
        id: RuleId::new("temporary-domain"),
        enabled: true,
        matcher: RuleMatcher::Domain(DomainMatch::Exact("example.com".to_owned())),
        target: RuleTarget::Direct,
        exit: None,
    }
}

#[test]
fn temporary_rules_are_empty_without_a_session() {
    let (helper, _, _, _) = supervised_helper(true);
    assert!(helper.temporary_rules().unwrap().is_empty());
}

#[test]
fn apply_requires_a_connected_and_unlocked_session() {
    let (helper, controls, _, _) = supervised_helper(false);
    let request = connect_request();
    assert_eq!(
        helper.apply(&request).unwrap_err().code,
        ErrorCode::InvalidState
    );
    let session = helper.session().expect("session");
    assert_eq!(helper.apply(&request).unwrap_err().code, ErrorCode::Busy);
    drop(session);
    assert_eq!(controls.spawns(), 0);
}

#[test]
fn apply_identical_request_does_not_restart_the_engine() {
    let (helper, controls, _, _) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("connect");
    let since = helper.status().since_unix;

    helper.apply(&request).expect("no changes");
    assert_eq!(controls.spawns(), 1);
    assert_eq!(helper.status().since_unix, since);
}

#[test]
fn apply_rejects_each_protection_change_without_a_restart() {
    let (helper, controls, prepared, reverted) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("connect");
    let mut changes = Vec::new();
    let mut engine = request.clone();
    engine.settings.engine = EngineKind::Xray;
    changes.push(engine);
    let mut tun = request.clone();
    tun.settings.tun.name = "other-tun".to_owned();
    changes.push(tun);
    let mut kill_switch = request.clone();
    kill_switch.settings.kill_switch = false;
    changes.push(kill_switch);
    let mut allow_lan = request.clone();
    allow_lan.settings.allow_lan = true;
    changes.push(allow_lan);

    for changed in changes {
        assert!(super::apply::needs_reconnect(&request, &changed));
        let error = helper.apply(&changed).expect_err("reconnect required");
        assert_eq!(error.code, ErrorCode::InvalidState);
        assert_eq!(error.message, "reconnect to change protection settings");
        assert_eq!(helper.session().unwrap().request.as_ref(), Some(&request));
    }
    assert!(!super::apply::needs_reconnect(&request, &request));
    assert_eq!(controls.spawns(), 1);
    assert_eq!(prepared.load(Ordering::Acquire), 0);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

#[test]
fn apply_metadata_only_updates_supervisor_without_restarting() {
    let (helper, controls, prepared, _) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    request.settings.auto_reconnect = false;
    helper.connect(&request).expect("connect");
    let mut changed = request.clone();
    changed.settings.autostart = !request.settings.autostart;
    helper.apply(&changed).expect("update autostart");
    assert_eq!(controls.spawns(), 1);
    assert_eq!(helper.session().unwrap().request.as_ref(), Some(&changed));

    changed.settings.auto_reconnect = true;
    helper.apply(&changed).expect("update auto-reconnect");
    assert_eq!(controls.spawns(), 1);
    assert_eq!(helper.session().unwrap().request.as_ref(), Some(&changed));
    controls.kill();
    helper.supervise(Instant::now());
    assert_eq!(controls.spawns(), 2);
    assert_eq!(prepared.load(Ordering::Acquire), 1);
    assert!(matches!(helper.status().state, ConnectionState::Connected));
}

#[test]
fn path_addresses_refresh_on_connect_and_every_successful_apply() {
    use super::dns::test_support::{Behavior, Server};

    let server = Server::new(Behavior::Addresses);
    let (helper, controls, _, _) = supervised_helper_with_dns(false, Some(server.address()));
    shorten_dns_timeouts(&helper);
    let mut request = connect_request();
    request.settings.kill_switch = false;
    helper
        .connect(&request)
        .expect("connect with path addresses");
    let addresses = Arc::clone(&helper.session().unwrap().path_addresses);
    let expected = [
        std::net::Ipv4Addr::new(192, 0, 2, 1),
        std::net::Ipv4Addr::new(192, 0, 2, 2),
    ];
    assert_eq!(*addresses.lock().unwrap(), expected);

    addresses.lock().unwrap().clear();
    helper.apply(&request).expect("refresh on unchanged apply");
    assert_eq!(*addresses.lock().unwrap(), expected);
    assert_eq!(controls.spawns(), 1);

    addresses.lock().unwrap().clear();
    let mut metadata = request.clone();
    metadata.settings.autostart = !request.settings.autostart;
    helper.apply(&metadata).expect("refresh on metadata apply");
    assert_eq!(*addresses.lock().unwrap(), expected);
    assert_eq!(controls.spawns(), 1);

    let changed = request_with_new_rules(&metadata);
    helper.apply(&changed).expect("refresh on restarting apply");
    assert_eq!(*addresses.lock().unwrap(), expected);
    assert_eq!(controls.spawns(), 2);
    helper
        .disconnect()
        .expect("disconnect clears path addresses");
    assert!(addresses.lock().unwrap().is_empty());
}

#[test]
fn apply_rules_restarts_under_the_guard_and_supervisor_uses_new_rules() {
    let (helper, controls, prepared, reverted) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("connect");
    let changed = request_with_new_rules(&request);
    let since = helper.status().since_unix;

    helper.apply(&changed).expect("apply rules");
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(helper.status().since_unix, since);
    assert_eq!(controls.spawns(), 2);
    assert_eq!(prepared.load(Ordering::Acquire), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
    assert_eq!(helper.session().unwrap().request.as_ref(), Some(&changed));

    controls.kill();
    helper.supervise(Instant::now());
    assert_eq!(controls.spawns(), 3);
    assert_eq!(prepared.load(Ordering::Acquire), 2);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
    assert_eq!(
        controls.rendered_rules.lock().unwrap().last(),
        Some(&changed.rule_set)
    );
}

#[test]
fn connect_retries_while_the_old_adapter_is_removed_under_the_same_guard() {
    let (helper, controls, prepared, reverted) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    controls.adapter_busy_next(1);

    helper.connect(&request).expect("second start connects");
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(controls.spawns(), 2);
    assert_eq!(prepared.load(Ordering::Acquire), 0);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

#[test]
fn apply_retries_while_the_old_adapter_is_removed_without_rollback() {
    let (helper, controls, prepared, reverted) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("connect");
    let changed = request_with_new_rules(&request);
    controls.adapter_busy_next(2);

    helper
        .apply(&changed)
        .expect("third start applies the change");
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(controls.spawns(), 4);
    assert_eq!(prepared.load(Ordering::Acquire), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
    assert_eq!(helper.session().unwrap().request.as_ref(), Some(&changed));
    assert_eq!(
        controls.rendered_rules.lock().unwrap().last(),
        Some(&changed.rule_set)
    );
}

#[test]
fn engine_start_retries_end_after_two_and_other_exits_are_not_retried() {
    let (helper, controls, _, _) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    controls.adapter_busy_next(3);

    let error = helper.connect(&request).expect_err("retries run out");
    assert_eq!(error.code, ErrorCode::EngineFailed);
    assert_eq!(controls.spawns(), 3);

    let (helper, controls, _, _) = supervised_helper(true);
    controls.fail_readiness_next(1);
    let error = helper
        .connect(&request)
        .expect_err("an ordinary exit fails");
    assert_eq!(error.code, ErrorCode::EngineFailed);
    assert_eq!(controls.spawns(), 1);
}

#[test]
fn apply_temporary_rule_precedes_base_and_survives_supervisor_restart() {
    let (helper, controls, prepared, reverted) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    let base = Rule {
        id: RuleId::new("base-domain"),
        enabled: true,
        matcher: RuleMatcher::Domain(DomainMatch::Exact("example.com".to_owned())),
        target: RuleTarget::Block,
        exit: None,
    };
    request.rule_set.rules.push(base.clone());
    helper.connect(&request).expect("connect");
    let since = helper.status().since_unix;
    let mut changed = request.clone();
    changed.temporary_rules.push(temporary_rule());

    helper.apply(&changed).expect("apply temporary rule");
    assert_eq!(controls.spawns(), 2);
    assert_eq!(prepared.load(Ordering::Acquire), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
    assert_eq!(helper.status().since_unix, since);
    assert_eq!(helper.temporary_rules().unwrap(), changed.temporary_rules);
    assert_eq!(helper.session().unwrap().request.as_ref(), Some(&changed));
    let rendered = controls.rendered_rules.lock().unwrap();
    assert_eq!(
        rendered.last().unwrap().rules,
        vec![temporary_rule(), base.clone()]
    );
    assert_eq!(request.rule_set.rules, vec![base.clone()]);
    drop(rendered);

    controls.kill();
    helper.supervise(Instant::now());
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(helper.temporary_rules().unwrap(), changed.temporary_rules);
    assert_eq!(controls.spawns(), 3);
    assert_eq!(
        controls
            .rendered_rules
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .rules,
        vec![temporary_rule(), base]
    );
}

#[test]
fn temporary_rules_end_on_disconnect_and_new_connect() {
    let (helper, controls, _, _) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    request.temporary_rules.push(temporary_rule());
    helper
        .connect(&request)
        .expect("connect with temporary rule");
    assert_eq!(helper.temporary_rules().unwrap(), request.temporary_rules);

    helper.disconnect().expect("disconnect");
    assert!(helper.temporary_rules().unwrap().is_empty());
    let mut next = request.clone();
    next.temporary_rules.clear();
    helper.connect(&next).expect("new session");
    assert!(helper.temporary_rules().unwrap().is_empty());
    assert_eq!(
        controls.rendered_rules.lock().unwrap().last(),
        Some(&next.rule_set)
    );
}

#[test]
fn temporary_rules_end_when_reconnect_attempts_are_exhausted() {
    let (helper, controls, _, _) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    request.temporary_rules.push(temporary_rule());
    helper.connect(&request).expect("connect");
    controls.fail_next(RECONNECT_ATTEMPTS as usize);
    controls.kill();
    let now = Instant::now();
    for attempt in 1..=RECONNECT_ATTEMPTS {
        helper.supervise(now + Duration::from_secs(u64::from(attempt) * 60));
    }
    assert!(matches!(
        helper.status().state,
        ConnectionState::FailedProtected { .. }
    ));
    assert!(helper.temporary_rules().unwrap().is_empty());
}

#[test]
fn apply_new_ip_and_named_node_updates_status_without_releasing_protection() {
    let _dns_slots = DNS_SLOTS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let (helper, controls, prepared, reverted) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("connect");
    let since = helper.status().since_unix;
    let mut changed = request.clone();
    changed.node.id = NodeId::new("second-node");
    changed.selection.node = changed.node.id.clone();
    changed.node.server = "127.0.0.2".to_owned();
    helper.apply(&changed).expect("apply IP node");
    assert_eq!(helper.status().node, Some(changed.node.id.clone()));
    assert_eq!(helper.status().since_unix, since);

    let mut named = changed.clone();
    named.node.id = NodeId::new("local-node");
    named.selection.node = named.node.id.clone();
    named.node.server = "localhost".to_owned();
    helper.apply(&named).expect("resolve name through tunnel");
    assert_eq!(helper.status().node, Some(named.node.id.clone()));
    assert_eq!(helper.status().since_unix, since);
    assert_eq!(controls.spawns(), 3);
    assert_eq!(prepared.load(Ordering::Acquire), 2);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
    assert_eq!(
        helper
            .session()
            .unwrap()
            .last_endpoint
            .as_ref()
            .unwrap()
            .server,
        "localhost"
    );
}

#[test]
fn apply_waits_for_a_busy_resolver_slot() {
    let _dns_slots = DNS_SLOTS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let (ready_tx, ready_rx) = channel();
    let holder = std::thread::spawn(move || {
        let _slot = reserve_apply_worker();
        ready_tx.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(100));
    });
    ready_rx.recv().unwrap();

    let mut node = connect_request().node;
    node.server = "localhost".to_owned();
    let address = super::probe::resolve_for_apply(&node);
    holder.join().unwrap();
    assert!(address.is_some());
}

#[test]
fn apply_resolver_slot_wait_respects_the_deadline() {
    let _dns_slots = DNS_SLOTS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let (ready_tx, ready_rx) = channel();
    let (release_tx, release_rx) = channel();
    let holder = std::thread::spawn(move || {
        let _slot = reserve_apply_worker();
        ready_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    });
    ready_rx.recv().unwrap();

    let mut node = connect_request().node;
    node.server = "localhost".to_owned();
    let timeout = Duration::from_millis(250);
    let started = Instant::now();
    let address = super::probe::resolve_for_apply_with_timeout(&node, timeout);
    let elapsed = started.elapsed();
    release_tx.send(()).unwrap();
    holder.join().unwrap();
    assert_eq!(address, None);
    assert!(
        elapsed >= timeout,
        "resolver returned before the deadline: {elapsed:?}"
    );
    assert!(
        elapsed <= timeout + Duration::from_millis(250),
        "resolver exceeded the deadline: {elapsed:?}"
    );
}

#[test]
fn apply_resolves_named_node_when_server_check_workers_are_full() {
    let _dns_slots = DNS_SLOTS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let (helper, controls, _, _) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("connect");
    let slots: Vec<_> = (0..super::probe::RESOLVE_WORKERS)
        .map(|_| super::probe::DnsWorkerSlot::acquire().expect("reserve check worker"))
        .collect();
    let mut changed = request.clone();
    changed.node.id = NodeId::new("local-node");
    changed.selection.node = changed.node.id.clone();
    changed.node.server = "localhost".to_owned();

    helper
        .apply(&changed)
        .expect("resolve outside check workers");
    assert_eq!(helper.status().node, Some(changed.node.id));
    assert_eq!(controls.spawns(), 2);
    drop(slots);
}

#[test]
fn apply_reuses_normalized_cached_server_name() {
    let (helper, controls, prepared, reverted) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("connect");
    let address = helper
        .session()
        .unwrap()
        .last_endpoint
        .as_ref()
        .unwrap()
        .address;
    helper.session().unwrap().last_endpoint = Some(SuccessfulEndpoint {
        server: "cached.invalid".to_owned(),
        address,
    });
    let mut changed = request.clone();
    changed.node.server = "CACHED.INVALID.".to_owned();
    changed.node.port = 8443;

    helper.apply(&changed).expect("reuse cached address");
    assert_eq!(
        helper
            .session()
            .unwrap()
            .last_endpoint
            .as_ref()
            .unwrap()
            .address,
        address
    );
    assert_eq!(controls.spawns(), 2);
    assert_eq!(prepared.load(Ordering::Acquire), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

#[test]
fn apply_dns_lock_reuses_guard() {
    use super::dns::test_support::{Behavior, Server};

    let server = Server::new(Behavior::Noerror);
    let (helper, controls, prepared, reverted) =
        supervised_helper_with_dns(false, Some(server.address()));
    shorten_dns_timeouts(&helper);
    let request = connect_request();
    helper.connect(&request).expect("connect under DNS lock");

    helper
        .apply(&request_with_new_rules(&request))
        .expect("apply under DNS lock");
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(
        helper.session().unwrap().guard.as_ref().unwrap().scope,
        ProtectionScope::DnsOnly
    );
    assert_eq!(controls.spawns(), 2);
    assert_eq!(prepared.load(Ordering::Acquire), 1);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

#[test]
fn apply_unresolvable_node_leaves_the_running_session_intact() {
    let _dns_slots = DNS_SLOTS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let (helper, controls, prepared, reverted) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("connect");
    let mut changed = request.clone();
    changed.node.server = "name.invalid".to_owned();

    let error = helper.apply(&changed).expect_err("name cannot be resolved");
    assert_eq!(error.code, ErrorCode::RoutingFailed);
    assert_eq!(
        error.message,
        "cannot resolve the new server through the tunnel"
    );
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(helper.session().unwrap().request.as_ref(), Some(&request));
    assert_eq!(controls.spawns(), 1);
    assert_eq!(prepared.load(Ordering::Acquire), 0);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

#[test]
fn apply_unsupported_rules_does_not_restart_or_change_request() {
    let (helper, controls, prepared, _) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("connect");
    let mut changed = request_with_new_rules(&request);
    changed.rule_set.rules[0].id = RuleId::new("unsupported-rule");

    let error = helper.apply(&changed).expect_err("unsupported rules");
    assert_eq!(error.code, ErrorCode::UnsupportedRules);
    assert!(error.message.contains("unsupported-rule"));
    assert_eq!(controls.spawns(), 1);
    assert_eq!(prepared.load(Ordering::Acquire), 0);
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(helper.session().unwrap().request.as_ref(), Some(&request));
}

#[test]
fn invalid_temporary_rules_leave_connect_and_apply_untouched() {
    let (helper, controls, prepared, _) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    let mut too_many = request.clone();
    too_many.temporary_rules = vec![temporary_rule(); MAX_TEMPORARY_RULES + 1];
    let mut template = request.clone();
    template.temporary_rules.push(Rule {
        matcher: RuleMatcher::Template(RuleTemplate::Youtube),
        enabled: false,
        ..temporary_rule()
    });

    for invalid in [&too_many, &template] {
        let error = helper.connect(invalid).expect_err("invalid connect");
        assert_eq!(error.code, ErrorCode::UnsupportedRules);
        assert!(matches!(
            helper.status().state,
            ConnectionState::Disconnected
        ));
        assert_eq!(controls.spawns(), 0);
    }

    helper.connect(&request).expect("connect");
    for invalid in [&too_many, &template] {
        let error = helper.apply(invalid).expect_err("invalid apply");
        assert_eq!(error.code, ErrorCode::UnsupportedRules);
        assert!(matches!(helper.status().state, ConnectionState::Connected));
        assert_eq!(helper.session().unwrap().request.as_ref(), Some(&request));
        assert!(helper.temporary_rules().unwrap().is_empty());
        assert_eq!(controls.spawns(), 1);
        assert_eq!(prepared.load(Ordering::Acquire), 0);
    }
}

#[test]
fn invalid_extra_nodes_are_rejected_before_connect_and_apply() {
    let (helper, controls, prepared, _) = supervised_helper(true);
    let mut request = connect_request();
    request.node.server = "203.0.113.10".into();
    let mut other = request.node.clone();
    other.id = NodeId::new("other");
    other.server = "192.0.2.10".into();
    let extra = ExtraNode {
        exit: ExitId::new("other"),
        selection: Selection {
            subscription: SubscriptionId::new("sub"),
            node: other.id.clone(),
        },
        node: other,
    };
    let mut too_many = request.clone();
    too_many.extra_nodes = vec![extra.clone(); MAX_EXTRA_NODES + 1];
    let mut duplicate = request.clone();
    duplicate.extra_nodes = vec![extra.clone(), extra.clone()];
    let mut missing = request.clone();
    missing.rule_set.rules.push(Rule {
        id: RuleId::new("exit"),
        enabled: true,
        matcher: RuleMatcher::IpCidr("192.0.2.0/24".into()),
        target: RuleTarget::Exit,
        exit: Some(extra.exit.clone()),
    });
    let invalid = [&too_many, &duplicate, &missing];
    for candidate in invalid {
        let error = helper.connect(candidate).expect_err("invalid connect");
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        assert_eq!(controls.spawns(), 0);
    }

    helper.connect(&request).expect("connect");
    for candidate in invalid {
        let error = helper.apply(candidate).expect_err("invalid apply");
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        assert_eq!(helper.session().unwrap().request.as_ref(), Some(&request));
        assert_eq!(controls.spawns(), 1);
        assert_eq!(prepared.load(Ordering::Acquire), 0);
    }

    missing.extra_nodes.push(extra);
    assert!(validate_request(&missing).is_ok());
    let effective = missing.effective_rule_set();
    let unresolved = super::exits::ExtraNodes::new(&missing.extra_nodes, &[None], &effective);
    let safe = unresolved.rules(&effective);
    assert_eq!(unresolved.blocked_rules(), 1);
    assert_eq!(safe.rules[0].target, RuleTarget::Block);
    assert_eq!(missing.rule_set.rules[0].target, RuleTarget::Exit);
    let rendered = rosetun_engine_singbox::render(&RenderRequest {
        extra: &[],
        node: &missing.node,
        socks: None,
        rules: safe,
        lists: &[],
        settings: &missing.settings,
        control: None,
        verbose_log: false,
    })
    .expect("render blocked exit rule");
    assert!(rendered.unsupported.is_empty());
    let body = String::from_utf8(rendered.body).unwrap();
    assert!(body.contains("\"action\": \"reject\""));
}

#[test]
fn invalid_tun_names_leave_connect_and_apply_untouched() {
    let (helper, controls, prepared, _) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    assert!(validate_tun_name("a").is_ok());
    assert!(validate_tun_name(&"a".repeat(64)).is_ok());

    let too_long = "a".repeat(65);
    for name in ["", too_long.as_str(), "bad/name", "tün"] {
        let mut invalid = request.clone();
        invalid.settings.tun.name = name.to_owned();
        let error = helper.connect(&invalid).expect_err("invalid TUN name");
        assert_eq!(error.code, ErrorCode::InvalidState);
        assert!(error.message.contains("TUN name"));
        assert_eq!(helper.status(), Status::default());
        assert_eq!(controls.spawns(), 0);
    }

    helper.connect(&request).expect("connect");
    let mut invalid = request.clone();
    invalid.settings.tun.name = "bad/name".to_owned();
    let error = helper.apply(&invalid).expect_err("invalid TUN name");
    assert_eq!(error.code, ErrorCode::InvalidState);
    assert!(error.message.contains("TUN name"));
    assert_eq!(helper.session().unwrap().request.as_ref(), Some(&request));
    assert_eq!(controls.spawns(), 1);
    assert_eq!(prepared.load(Ordering::Acquire), 0);
}

#[test]
fn base_rule_set_templates_leave_connect_and_apply_untouched() {
    let (helper, controls, prepared, _) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    let mut invalid = request.clone();
    invalid.rule_set.rules.push(Rule {
        matcher: RuleMatcher::Template(RuleTemplate::Youtube),
        enabled: false,
        ..temporary_rule()
    });

    let error = helper
        .connect(&invalid)
        .expect_err("base template rejected");
    assert_eq!(error.code, ErrorCode::UnsupportedRules);
    assert!(error.message.contains("rule set contains a template"));
    assert_eq!(helper.status(), Status::default());
    assert_eq!(controls.spawns(), 0);

    helper.connect(&request).expect("connect");
    let error = helper.apply(&invalid).expect_err("base template rejected");
    assert_eq!(error.code, ErrorCode::UnsupportedRules);
    assert!(error.message.contains("rule set contains a template"));
    assert_eq!(helper.session().unwrap().request.as_ref(), Some(&request));
    assert_eq!(controls.spawns(), 1);
    assert_eq!(prepared.load(Ordering::Acquire), 0);
}

#[test]
fn temporary_rules_are_busy_while_apply_holds_the_session() {
    let (helper, controls, _, _) = supervised_helper(true);
    let helper = Arc::new(helper);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("connect");
    let mut changed = request.clone();
    changed.temporary_rules.push(temporary_rule());
    let (entered, entered_rx) = channel();
    let (release_tx, release) = channel();
    *controls.render_block.lock().unwrap() = Some((entered, release));

    let worker = {
        let helper = Arc::clone(&helper);
        std::thread::spawn(move || helper.apply(&changed))
    };
    entered_rx.recv().expect("apply reached config render");
    assert_eq!(helper.temporary_rules().unwrap_err().code, ErrorCode::Busy);
    release_tx.send(()).expect("release apply");
    worker
        .join()
        .expect("apply thread")
        .expect("apply succeeds");
    assert_eq!(helper.temporary_rules().unwrap(), vec![temporary_rule()]);
}

#[test]
fn apply_failed_start_rolls_back_to_original_node_and_endpoint() {
    let (helper, controls, prepared, reverted) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("connect");
    let since = helper.status().since_unix;
    let previous = helper
        .session()
        .unwrap()
        .last_endpoint
        .as_ref()
        .unwrap()
        .address;
    let mut changed = request.clone();
    changed.node.id = NodeId::new("second-node");
    changed.node.server = "127.0.0.2".to_owned();
    changed.selection.node = changed.node.id.clone();
    controls.fail_readiness_next(1);

    let error = helper.apply(&changed).expect_err("new engine not ready");
    assert_eq!(error.code, ErrorCode::EngineFailed);
    assert!(error.message.starts_with("changes were not applied: "));
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(helper.status().node, Some(request.node.id.clone()));
    assert_eq!(helper.status().since_unix, since);
    let session = helper.session().unwrap();
    assert_eq!(session.request.as_ref(), Some(&request));
    assert_eq!(session.last_endpoint.as_ref().unwrap().address, previous);
    drop(session);
    assert_eq!(controls.spawns(), 3);
    assert_eq!(prepared.load(Ordering::Acquire), 2);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

#[test]
fn failed_apply_rolls_back_temporary_rules() {
    let (helper, controls, _, _) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    request.temporary_rules.push(temporary_rule());
    helper.connect(&request).expect("connect");
    let mut changed = request.clone();
    changed.temporary_rules.clear();
    controls.fail_readiness_next(1);

    helper.apply(&changed).expect_err("new start fails");
    assert_eq!(controls.spawns(), 3);
    assert_eq!(helper.temporary_rules().unwrap(), request.temporary_rules);
    assert_eq!(
        controls.rendered_rules.lock().unwrap().last(),
        Some(&request.effective_rule_set())
    );
}

#[test]
fn apply_failed_start_and_rollback_schedule_original_request() {
    let (helper, controls, prepared, reverted) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).expect("connect");
    let since = helper.status().since_unix;
    let changed = request_with_new_rules(&request);
    controls.fail_readiness_next(2);

    let error = helper.apply(&changed).expect_err("both starts fail");
    assert_eq!(error.code, ErrorCode::EngineFailed);
    assert!(matches!(
        helper.status().state,
        ConnectionState::Reconnecting
    ));
    assert_eq!(helper.status().since_unix, since);
    let session = helper.session().unwrap();
    assert_eq!(session.request.as_ref(), Some(&request));
    let reconnect = session.reconnect.as_ref().expect("retry scheduled");
    assert_eq!(reconnect.failures, 1);
    assert_eq!(reconnect.cause, "apply failed");
    drop(session);
    assert_eq!(controls.spawns(), 3);
    assert_eq!(reverted.load(Ordering::Acquire), 0);

    helper.supervise(Instant::now() + Duration::from_secs(60));
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(helper.status().since_unix, since);
    assert_eq!(helper.status().node, Some(request.node.id.clone()));
    assert_eq!(controls.spawns(), 4);
    assert_eq!(prepared.load(Ordering::Acquire), 3);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
    assert_eq!(
        controls.rendered_rules.lock().unwrap().last(),
        Some(&request.rule_set)
    );
}

#[test]
fn apply_failed_start_and_rollback_without_reconnect_remain_protected() {
    let (helper, controls, prepared, reverted) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    request.settings.auto_reconnect = false;
    helper.connect(&request).expect("connect");
    controls.fail_readiness_next(2);

    let error = helper.apply(&request_with_new_rules(&request)).unwrap_err();
    assert_eq!(error.code, ErrorCode::EngineFailed);
    assert!(matches!(
        helper.status().state,
        ConnectionState::FailedProtected { .. }
    ));
    assert!(helper.status().since_unix.is_none());
    let session = helper.session().unwrap();
    assert!(session.request.is_none());
    assert!(session.guard.is_some());
    drop(session);
    assert_eq!(controls.spawns(), 3);
    assert_eq!(prepared.load(Ordering::Acquire), 2);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
}

#[test]
fn apply_failed_start_and_rollback_without_a_guard_tear_down() {
    let (helper, controls, _, _) = supervised_helper(false);
    let mut request = connect_request();
    request.settings.auto_reconnect = false;
    helper.connect(&request).expect("connect");
    controls.fail_readiness_next(2);

    helper
        .apply(&request_with_new_rules(&request))
        .expect_err("both starts fail");
    assert!(matches!(
        helper.status().state,
        ConnectionState::Failed { .. }
    ));
    assert!(helper.status().since_unix.is_none());
    assert!(helper.session().unwrap().request.is_none());
    assert_eq!(controls.spawns(), 3);
}

#[derive(Debug)]
struct ProbeEngine {
    dir: PathBuf,
    stopped: Arc<AtomicUsize>,
    completed: Arc<AtomicUsize>,
    ready: bool,
    fail_spawn: bool,
    panic_url: bool,
    outcomes: std::collections::HashMap<String, Option<u32>>,
    blocked: Mutex<Option<(Sender<()>, Receiver<()>)>>,
}

impl EngineBackend for ProbeEngine {
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

    fn tunnel_dns_server(&self, _: &rosetun_config::TunSettings) -> Option<SocketAddr> {
        None
    }

    fn locate_binary(&self) -> Result<PathBuf, EngineError> {
        Ok(PathBuf::from("sing-box"))
    }

    fn render(&self, _: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError> {
        Ok(RenderedConfig {
            file_name: "config.json".to_owned(),
            body: Vec::new(),
            unsupported: Vec::new(),
            unsupported_probes: Vec::new(),
        })
    }

    fn render_probe(
        &self,
        request: &rosetun_engine::ProbeRenderRequest<'_>,
    ) -> Result<RenderedConfig, EngineError> {
        for (tag, socks) in request.socks {
            assert!(request.nodes.iter().any(|(name, _)| name == tag));
            assert!(socks.address.ip().is_loopback());
        }
        Ok(RenderedConfig {
            file_name: "probe.json".to_owned(),
            body: Vec::new(),
            unsupported: Vec::new(),
            unsupported_probes: request
                .nodes
                .iter()
                .filter(|(_, node)| matches!(node.outbound, Outbound::Unknown { .. }))
                .map(|(tag, _)| tag.clone())
                .collect(),
        })
    }

    fn probe_config_path(&self, config: &RenderedConfig) -> Option<PathBuf> {
        Some(self.dir.join(&config.file_name))
    }

    fn url_test(
        &self,
        _: &ControlEndpoint,
        target: rosetun_engine::UrlTestTarget<'_>,
        _: &str,
        _: Duration,
    ) -> Result<Duration, EngineError> {
        assert!(!self.panic_url, "test URL worker panicked");
        let tag = match target {
            rosetun_engine::UrlTestTarget::Session => "proxy",
            rosetun_engine::UrlTestTarget::SessionExit(tag)
            | rosetun_engine::UrlTestTarget::Probe(tag) => tag,
        };
        let blocked = (tag == "probe-0")
            .then(|| self.blocked.lock().unwrap().take())
            .flatten();
        if let Some((entered, release)) = blocked {
            entered.send(()).unwrap();
            release.recv().unwrap();
        }
        self.completed.fetch_add(1, Ordering::AcqRel);
        self.outcomes
            .get(tag)
            .copied()
            .flatten()
            .map(|millis| Duration::from_millis(u64::from(millis)))
            .ok_or_else(|| EngineError::Stats("test URL request failed".to_owned()))
    }

    fn spawn(
        &self,
        _: &Path,
        config: &RenderedConfig,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        std::fs::write(self.dir.join(&config.file_name), &config.body)?;
        if self.fail_spawn {
            return Err(EngineError::Stats("test spawn failed".to_owned()));
        }
        Ok(Box::new(ProbeEngineProcess {
            stopped: Arc::clone(&self.stopped),
            ready: self.ready,
        }))
    }
}

#[derive(Debug)]
struct ProbeEngineProcess {
    stopped: Arc<AtomicUsize>,
    ready: bool,
}

impl EngineProcess for ProbeEngineProcess {
    fn is_running(&mut self) -> Result<bool, EngineError> {
        Ok(true)
    }

    fn is_ready(&mut self) -> Result<bool, EngineError> {
        if self.ready {
            Ok(true)
        } else {
            Err(EngineError::Stats("not ready".to_owned()))
        }
    }

    fn stop(&mut self) -> Result<(), EngineError> {
        self.stopped.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

fn probe_fixture(
    ready: bool,
    blocked: Option<(Sender<()>, Receiver<()>)>,
) -> (Helper, Arc<AtomicUsize>, PathBuf) {
    probe_fixture_with_failures(ready, blocked, false, false)
}

fn probe_fixture_with_failures(
    ready: bool,
    blocked: Option<(Sender<()>, Receiver<()>)>,
    fail_spawn: bool,
    panic_url: bool,
) -> (Helper, Arc<AtomicUsize>, PathBuf) {
    probe_fixture_with_counter(
        ready,
        blocked,
        fail_spawn,
        panic_url,
        Arc::new(AtomicUsize::new(0)),
    )
}

fn probe_fixture_with_counter(
    ready: bool,
    blocked: Option<(Sender<()>, Receiver<()>)>,
    fail_spawn: bool,
    panic_url: bool,
    completed: Arc<AtomicUsize>,
) -> (Helper, Arc<AtomicUsize>, PathBuf) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "rosetun-probe-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).unwrap();
    let stopped = Arc::new(AtomicUsize::new(0));
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(ProbeEngine {
        dir: dir.clone(),
        stopped: Arc::clone(&stopped),
        completed,
        ready,
        fail_spawn,
        panic_url,
        outcomes: [
            ("probe-0".to_owned(), Some(17)),
            ("probe-4".to_owned(), Some(45)),
            ("proxy".to_owned(), Some(23)),
            ("exit-0".to_owned(), Some(61)),
        ]
        .into(),
        blocked: Mutex::new(blocked),
    }));
    (
        Helper::new(engines, Box::new(UnusedRouting), VerboseGate::default()),
        stopped,
        dir,
    )
}

#[test]
fn probe_mixes_plain_and_reality_nodes_in_one_xray_process() {
    let _dns_slots = DNS_SLOTS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let (helper, stopped, dir) = probe_fixture(true, None);
    let runner = Arc::new(FakeXrayRunner {
        controls: Arc::new(EngineControls::default()),
        running: Mutex::new(None),
        starts: AtomicUsize::new(0),
        endpoint_count: AtomicUsize::new(0),
        fail_next: AtomicBool::new(false),
        probe_path: dir.join("xray-probe.json"),
        binary: None,
    });
    let helper = helper
        .with_xray_runner(Arc::clone(&runner) as Arc<dyn XrayRunner>)
        .with_test_physical_interface(|_| Some("Ethernet".into()));
    let mut request = probe_request();
    request.nodes[0].stream.tls = reality_request().node.stream.tls;
    let mut plain = connect_request().node;
    plain.id = NodeId::new("plain");
    request.nodes.push(plain);
    let mut second = request.nodes[0].clone();
    second.id = NodeId::new("second-reality");
    request.nodes.push(second);
    let results = helper.probe_nodes(&request).unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(runner.starts.load(Ordering::Acquire), 1);
    assert_eq!(runner.endpoint_count.load(Ordering::Acquire), 2);
    assert_eq!(stopped.load(Ordering::Acquire), 1);
    assert!(!runner.probe_path.exists());
    std::fs::remove_dir(&dir).unwrap();
}

fn probe_request() -> rosetun_ipc::ProbeRequest {
    let settings = Settings {
        kill_switch: false,
        ..Settings::default()
    };
    let node = connect_request().node;
    rosetun_ipc::ProbeRequest {
        nodes: vec![node],
        settings,
    }
}

#[test]
fn probe_results_keep_request_order_and_cleanup_secrets() {
    let _dns_slots = DNS_SLOTS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    use rosetun_ipc::ProbeOutcome;

    let (helper, stopped, dir) = probe_fixture(true, None);
    let mut request = probe_request();
    let mut failed = request.nodes[0].clone();
    failed.id = NodeId::new("failed");
    request.nodes.push(failed);
    let mut unsupported = request.nodes[0].clone();
    unsupported.id = NodeId::new("unsupported");
    unsupported.outbound = Outbound::Unknown {
        scheme: "unknown".into(),
        params: Default::default(),
    };
    request.nodes.push(unsupported);
    let mut unresolved = request.nodes[0].clone();
    unresolved.id = NodeId::new("unresolved");
    unresolved.server = "name.invalid".into();
    request.nodes.push(unresolved);
    let mut last = request.nodes[0].clone();
    last.id = NodeId::new("last");
    request.nodes.push(last);

    let results = helper.probe_nodes(&request).unwrap();
    assert_eq!(
        results
            .iter()
            .map(|result| &result.node)
            .collect::<Vec<_>>(),
        request
            .nodes
            .iter()
            .map(|node| &node.id)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        results
            .iter()
            .map(|result| result.outcome)
            .collect::<Vec<_>>(),
        [
            ProbeOutcome::Works { millis: 17 },
            ProbeOutcome::Fails,
            ProbeOutcome::Unsupported,
            ProbeOutcome::Unresolved,
            ProbeOutcome::Works { millis: 45 },
        ]
    );
    assert_eq!(stopped.load(Ordering::Acquire), 1);
    assert!(!dir.join("probe.json").exists());
    std::fs::remove_dir(dir).unwrap();
}

#[test]
fn probe_workers_advance_past_a_blocked_url_test() {
    use rosetun_ipc::ProbeOutcome;
    use std::time::Instant;

    let (entered, entered_rx) = channel();
    let (release_tx, release) = channel();
    let completed = Arc::new(AtomicUsize::new(0));
    let (helper, stopped, dir) = probe_fixture_with_counter(
        true,
        Some((entered, release)),
        false,
        false,
        Arc::clone(&completed),
    );
    let mut request = probe_request();
    request.nodes = (0..20)
        .map(|index| {
            let mut node = request.nodes[0].clone();
            node.id = NodeId::new(format!("node-{index}"));
            node
        })
        .collect();
    let worker = std::thread::spawn(move || helper.probe_nodes(&request));
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while completed.load(Ordering::Acquire) < 39 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let completed_while_blocked = completed.load(Ordering::Acquire);
    while !worker.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        worker.is_finished(),
        "slow losing URL test held the probe worker"
    );
    release_tx.send(()).unwrap();
    let results = worker.join().unwrap().unwrap();
    assert_eq!(completed_while_blocked, 39);
    assert_eq!(results.len(), 20);
    assert!(results.iter().all(|result| matches!(
        result.outcome,
        ProbeOutcome::Works { .. } | ProbeOutcome::Fails
    )));
    while completed.load(Ordering::Acquire) < 40 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(completed.load(Ordering::Acquire), 40);
    assert_eq!(stopped.load(Ordering::Acquire), 1);
    assert!(!dir.join("probe.json").exists());
    std::fs::remove_dir(dir).unwrap();
}

#[test]
fn probe_cleans_up_when_engine_is_not_ready() {
    let (helper, stopped, dir) = probe_fixture(false, None);
    assert_eq!(
        helper.probe_nodes(&probe_request()).unwrap_err().code,
        ErrorCode::EngineFailed
    );
    assert_eq!(stopped.load(Ordering::Acquire), 1);
    assert!(!dir.join("probe.json").exists());
    std::fs::remove_dir(dir).unwrap();
}

#[test]
fn probe_cleans_up_after_spawn_error_and_worker_panic() {
    use rosetun_ipc::ProbeOutcome;

    let (helper, stopped, dir) = probe_fixture_with_failures(true, None, true, false);
    assert_eq!(
        helper.probe_nodes(&probe_request()).unwrap_err().code,
        ErrorCode::EngineFailed
    );
    assert_eq!(stopped.load(Ordering::Acquire), 0);
    assert!(!dir.join("probe.json").exists());
    std::fs::remove_dir(dir).unwrap();

    let (helper, stopped, dir) = probe_fixture_with_failures(true, None, false, true);
    let outcomes = helper
        .probe_nodes(&probe_request())
        .expect("worker panic is contained");
    assert!(
        outcomes
            .iter()
            .all(|result| result.outcome == ProbeOutcome::Fails)
    );
    assert_eq!(stopped.load(Ordering::Acquire), 1);
    assert!(!dir.join("probe.json").exists());
    std::fs::remove_dir(dir).unwrap();
}

#[test]
fn slow_losing_url_test_does_not_hold_probe_or_tunnel_operations() {
    let (entered, entered_rx) = channel();
    let (release_tx, release) = channel();
    let (helper, stopped, dir) = probe_fixture(true, Some((entered, release)));
    let helper = Arc::new(helper);
    let request = probe_request();
    let worker = {
        let helper = Arc::clone(&helper);
        let request = request.clone();
        std::thread::spawn(move || helper.probe_nodes(&request))
    };
    entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !worker.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(worker.is_finished(), "slow losing request held the probe");
    worker.join().unwrap().unwrap();
    assert_eq!(helper.probe_nodes(&request).unwrap().len(), 1);
    assert!(matches!(
        helper.status().state,
        ConnectionState::Disconnected
    ));
    helper.connect(&connect_request()).unwrap();
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    helper.disconnect().unwrap();
    release_tx.send(()).unwrap();
    assert_eq!(stopped.load(Ordering::Acquire), 3);
    assert!(!dir.join("probe.json").exists());
    drop(helper);
    std::fs::remove_file(dir.join("config.json")).unwrap();
    std::fs::remove_dir(dir).unwrap();
}

#[test]
fn probe_rejects_empty_and_oversized_batches() {
    let (helper, _, dir) = probe_fixture(true, None);
    let mut request = probe_request();
    request.nodes.clear();
    assert_eq!(
        helper.probe_nodes(&request).unwrap_err().code,
        ErrorCode::InvalidState
    );
    request.nodes = vec![connect_request().node; rosetun_ipc::MAX_PROBE_NODES + 1];
    assert_eq!(
        helper.probe_nodes(&request).unwrap_err().code,
        ErrorCode::InvalidState
    );
    request.nodes = vec![connect_request().node];
    request.settings.tun.name = "bad/name".into();
    let error = helper.probe_nodes(&request).expect_err("invalid TUN name");
    assert_eq!(error.code, ErrorCode::InvalidState);
    assert!(error.message.contains("TUN name"));
    std::fs::remove_dir(dir).unwrap();
}

#[test]
fn tunnel_delay_requires_connection_and_uses_its_control() {
    use rosetun_ipc::ProbeOutcome;

    let (helper, stopped, dir) = probe_fixture(true, None);
    assert_eq!(
        helper.tunnel_delay().unwrap_err().code,
        ErrorCode::InvalidState
    );
    helper.connect(&connect_request()).unwrap();
    assert_eq!(
        helper.tunnel_delay().unwrap(),
        TunnelDelays {
            proxy: ProbeOutcome::Works { millis: 23 },
            exits: Vec::new(),
        }
    );
    assert!(helper.session_exits().unwrap().is_empty());
    helper.disconnect().unwrap();
    assert_eq!(stopped.load(Ordering::Acquire), 1);
    std::fs::remove_file(dir.join("config.json")).unwrap();
    std::fs::remove_dir(dir).unwrap();
}

#[test]
fn tunnel_delay_checks_each_exit_by_its_tag() {
    use rosetun_ipc::{ExitDelay, ExitOutcome, ProbeOutcome};

    let (helper, _, dir) = probe_fixture(true, None);
    let mut request = connect_request();
    request.extra_nodes = vec![
        extra_node("first", "192.0.2.20"),
        extra_node("missing", "missing.invalid"),
        extra_node("silent", "192.0.2.30"),
    ];
    for exit in ["first", "missing", "silent"] {
        request.rule_set.rules.push(Rule {
            id: RuleId::new(format!("through-{exit}")),
            enabled: true,
            matcher: RuleMatcher::IpCidr("198.51.100.0/24".into()),
            target: RuleTarget::Exit,
            exit: Some(ExitId::new(exit)),
        });
    }
    helper.connect(&request).unwrap();

    assert_eq!(
        helper.tunnel_delay().unwrap(),
        TunnelDelays {
            proxy: ProbeOutcome::Works { millis: 23 },
            exits: vec![
                ExitDelay {
                    exit: ExitId::new("first"),
                    outcome: ExitOutcome::Probed(ProbeOutcome::Works { millis: 61 }),
                },
                ExitDelay {
                    exit: ExitId::new("missing"),
                    outcome: ExitOutcome::NoAddress,
                },
                ExitDelay {
                    exit: ExitId::new("silent"),
                    outcome: ExitOutcome::Probed(ProbeOutcome::Fails),
                },
            ],
        }
    );
    assert_eq!(
        helper.session_exits().unwrap(),
        request
            .extra_nodes
            .iter()
            .map(|extra| SessionExit {
                exit: extra.exit.clone(),
                selection: extra.selection.clone(),
            })
            .collect::<Vec<_>>()
    );
    helper.disconnect().unwrap();
    std::fs::remove_file(dir.join("config.json")).unwrap();
    std::fs::remove_dir(dir).unwrap();
}

#[derive(Debug)]
struct CancellableEngine {
    ready: Arc<AtomicBool>,
    stopped: Arc<AtomicUsize>,
    dns: Option<SocketAddr>,
}

impl EngineBackend for CancellableEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::SingBox
    }
    fn integration(&self) -> EngineIntegration {
        EngineIntegration::EngineManagedTun
    }
    fn capabilities(&self) -> EngineCapabilities {
        StubEngine.capabilities()
    }
    fn locate_binary(&self) -> Result<PathBuf, EngineError> {
        StubEngine.locate_binary()
    }
    fn render(&self, request: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError> {
        StubEngine.render(request)
    }
    fn tunnel_dns_server(&self, _: &rosetun_config::TunSettings) -> Option<SocketAddr> {
        self.dns
    }
    fn spawn(&self, _: &Path, _: &RenderedConfig) -> Result<Box<dyn EngineProcess>, EngineError> {
        Ok(Box::new(CancellableProcess {
            ready: Arc::clone(&self.ready),
            stopped: Arc::clone(&self.stopped),
        }))
    }
}

#[derive(Debug)]
struct CancellableProcess {
    ready: Arc<AtomicBool>,
    stopped: Arc<AtomicUsize>,
}

impl EngineProcess for CancellableProcess {
    fn is_running(&mut self) -> Result<bool, EngineError> {
        Ok(true)
    }
    fn is_ready(&mut self) -> Result<bool, EngineError> {
        Ok(self.ready.load(Ordering::Acquire))
    }
    fn stop(&mut self) -> Result<(), EngineError> {
        self.stopped.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

fn wait_for_stage(helper: &Helper, expected: rosetun_config::ConnectStage) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while helper.status().connect_stage != Some(expected) {
        assert!(
            Instant::now() < deadline,
            "startup never reached {expected:?}"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn cancellation_at_each_stage_releases_the_session_and_guard() {
    use super::dns::test_support::{Behavior, Server};
    use rosetun_config::ConnectStage;
    for stage in [
        ConnectStage::WaitingForAdapter,
        ConnectStage::StartingEngine,
        ConnectStage::CheckingServer,
    ] {
        let dns = Server::new(Behavior::Silent);
        let ready = Arc::new(AtomicBool::new(stage != ConnectStage::StartingEngine));
        let stopped = Arc::new(AtomicUsize::new(0));
        let reverted = Arc::new(AtomicUsize::new(0));
        let mut engines = EngineRegistry::new();
        engines.register(Box::new(CancellableEngine {
            ready: Arc::clone(&ready),
            stopped: Arc::clone(&stopped),
            dns: (stage == ConnectStage::CheckingServer).then_some(dns.address()),
        }));
        let helper = Arc::new(Helper::new(
            engines,
            Box::new(CountingRouting {
                reverted: Arc::clone(&reverted),
            }),
            VerboseGate::default(),
        ));
        if stage == ConnectStage::WaitingForAdapter {
            helper.session().unwrap().adapter_lookup = |_| Ok(true);
        }
        let mut request = connect_request();
        request.settings.kill_switch = true;
        let worker = {
            let helper = Arc::clone(&helper);
            let request = request.clone();
            thread::spawn(move || helper.connect(&request))
        };
        wait_for_stage(&helper, stage);
        helper
            .disconnect()
            .expect("cancellation is accepted while startup owns session");
        assert_eq!(
            worker.join().unwrap().unwrap_err().code,
            ErrorCode::Cancelled
        );
        assert_eq!(helper.status(), Status::default());
        let session = helper.session().expect("session lock is released");
        assert!(session.guard.is_none());
        assert!(session.process.is_none());
        assert!(session.request.is_none());
        drop(session);
        if stage != ConnectStage::WaitingForAdapter {
            assert_eq!(reverted.load(Ordering::Acquire), 1);
        }
        if stage != ConnectStage::CheckingServer {
            ready.store(true, Ordering::Release);
            helper.session().unwrap().adapter_lookup = |_| Ok(false);
            helper
                .connect(&request)
                .expect("the next connection resets cancellation");
            helper.disconnect().unwrap();
        }
    }
}

#[test]
fn shutdown_cancels_a_running_connect_before_waiting_for_session() {
    use rosetun_config::ConnectStage;

    let ready = Arc::new(AtomicBool::new(false));
    let reverted = Arc::new(AtomicUsize::new(0));
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(CancellableEngine {
        ready: Arc::clone(&ready),
        stopped: Arc::new(AtomicUsize::new(0)),
        dns: None,
    }));
    let helper = Arc::new(Helper::new(
        engines,
        Box::new(CountingRouting {
            reverted: Arc::clone(&reverted),
        }),
        VerboseGate::default(),
    ));
    let mut request = connect_request();
    request.settings.kill_switch = true;
    let (connect_tx, connect_rx) = channel();
    let connecting = {
        let helper = Arc::clone(&helper);
        thread::spawn(move || connect_tx.send(helper.connect(&request)).unwrap())
    };
    wait_for_stage(&helper, ConnectStage::StartingEngine);

    let started = Instant::now();
    let (shutdown_tx, shutdown_rx) = channel();
    let stopping = {
        let helper = Arc::clone(&helper);
        thread::spawn(move || {
            helper.shutdown();
            shutdown_tx.send(()).unwrap();
        })
    };
    assert_eq!(
        connect_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("connect cancels promptly")
            .unwrap_err()
            .code,
        ErrorCode::Cancelled,
    );
    shutdown_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("shutdown completes promptly");
    assert!(started.elapsed() < Duration::from_secs(3));
    connecting.join().unwrap();
    stopping.join().unwrap();
    assert_eq!(reverted.load(Ordering::Acquire), 1);
    assert_eq!(helper.status(), Status::default());
}

#[test]
fn cancellation_during_protected_apply_does_not_roll_back() {
    use rosetun_config::ConnectStage;
    let (helper, controls, _, reverted) = supervised_helper(true);
    let helper = Arc::new(helper);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    helper.connect(&request).unwrap();
    helper.session().unwrap().adapter_lookup = |_| Ok(true);
    let changed = request_with_new_rules(&request);
    let worker = {
        let helper = Arc::clone(&helper);
        thread::spawn(move || helper.apply(&changed))
    };
    wait_for_stage(&helper, ConnectStage::WaitingForAdapter);
    helper.disconnect().unwrap();
    assert_eq!(
        worker.join().unwrap().unwrap_err().code,
        ErrorCode::Cancelled
    );
    assert_eq!(
        controls.spawns(),
        1,
        "apply cancellation must not spawn a rollback engine"
    );
    assert_eq!(reverted.load(Ordering::Acquire), 1);
    assert_eq!(helper.status(), Status::default());
}

#[test]
fn accepted_cancellation_cannot_publish_connected() {
    let (helper, _, _, _) = supervised_helper(false);
    helper.begin_connect(&test_caller()).unwrap();
    let _session = helper.session().unwrap();
    helper.disconnect().unwrap();
    assert_eq!(
        helper
            .publish_terminal(|status| status.state = ConnectionState::Connected)
            .unwrap_err()
            .code,
        ErrorCode::Cancelled
    );
    assert_ne!(helper.status().state, ConnectionState::Connected);
}

static NEXT_LIST_SESSION: AtomicUsize = AtomicUsize::new(0);

struct ListSessionDirectory(PathBuf);

impl ListSessionDirectory {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "rosetun-list-session-{}-{}",
            std::process::id(),
            NEXT_LIST_SESSION.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(directory.join("lists")).unwrap();
        Self(directory)
    }

    fn reference(&self, id: &rosetun_config::ListId, domain: &str) -> rosetun_config::ListRef {
        use sha2::Digest;
        let source = format!(r#"{{"version":3,"rules":[{{"domain":["{domain}"]}}]}}"#);
        let bytes = rosetun_config::normalize_source(source.as_bytes()).unwrap();
        let hash = rosetun_config::digest_hex(&sha2::Sha256::digest(&bytes));
        std::fs::write(self.0.join("lists").join(format!("{hash}.json")), bytes).unwrap();
        rosetun_config::ListRef {
            tag: rosetun_config::list_tag(id, None),
            sha256: hash,
            format: rosetun_config::UploadedListFormat::Source,
        }
    }

    fn helper(&self) -> (Helper, Arc<EngineControls>) {
        let (helper, controls, _, _) = supervised_helper(true);
        let lists = ListStore::open_for_test(self.0.join("lists")).unwrap();
        (helper.with_list_store(lists, self.0.join("run")), controls)
    }
}

impl Drop for ListSessionDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn with_list_rule(
    mut request: ConnectRequest,
    list: rosetun_config::ListId,
    reference: rosetun_config::ListRef,
) -> ConnectRequest {
    request.rule_set.rules.push(Rule {
        id: RuleId::new("list-rule"),
        enabled: true,
        matcher: RuleMatcher::List {
            list,
            category: None,
        },
        target: RuleTarget::Direct,
        exit: None,
    });
    request.lists = vec![reference];
    request
}

#[test]
fn missing_list_is_rejected_before_engine_spawn() {
    let directory = ListSessionDirectory::new();
    let (helper, controls) = directory.helper();
    let id = rosetun_config::ListId::new("missing");
    let request = with_list_rule(
        connect_request(),
        id.clone(),
        rosetun_config::ListRef {
            tag: rosetun_config::list_tag(&id, None),
            sha256: "0".repeat(64),
            format: rosetun_config::UploadedListFormat::Source,
        },
    );
    let error = helper.connect(&request).expect_err("list is not stored");
    assert_eq!(error.code, ErrorCode::ListMissing);
    assert_eq!(controls.spawns(), 0);
    assert!(matches!(
        helper.status().state,
        ConnectionState::Disconnected
    ));
}

#[test]
fn invalid_list_tag_is_rejected_before_spawn() {
    let directory = ListSessionDirectory::new();
    let list_id = rosetun_config::ListId::new("one");
    let reference = directory.reference(&list_id, "example.com");
    let (helper, controls) = directory.helper();
    let mut request = with_list_rule(connect_request(), list_id, reference);
    request.lists[0].tag = "../bad".into();
    assert_eq!(
        helper.connect(&request).unwrap_err().code,
        ErrorCode::InvalidState
    );
    assert_eq!(controls.spawns(), 0);
}

#[test]
fn missing_rule_reference_retries_but_extra_references_are_invalid() {
    let directory = ListSessionDirectory::new();
    let list_id = rosetun_config::ListId::new("one");
    let reference = directory.reference(&list_id, "example.com");
    let (helper, controls) = directory.helper();
    let mut request = with_list_rule(connect_request(), list_id, reference.clone());

    request.lists.clear();
    assert_eq!(
        helper.connect(&request).unwrap_err().code,
        ErrorCode::ListMissing
    );
    request.lists = vec![reference.clone(), reference.clone()];
    assert_eq!(
        helper.connect(&request).unwrap_err().code,
        ErrorCode::InvalidState
    );
    request.lists = vec![reference];
    request.lists[0].tag = rosetun_config::list_tag(&rosetun_config::ListId::new("other"), None);
    assert_eq!(
        helper.connect(&request).unwrap_err().code,
        ErrorCode::InvalidState
    );
    assert_eq!(controls.spawns(), 0);
    assert!(matches!(
        helper.status().state,
        ConnectionState::Disconnected
    ));
}

#[test]
fn enabled_temporary_list_rule_without_reference_is_list_missing() {
    let directory = ListSessionDirectory::new();
    let (helper, controls) = directory.helper();
    let mut request = connect_request();
    request.temporary_rules.push(Rule {
        id: RuleId::new("temporary-list"),
        enabled: true,
        matcher: RuleMatcher::List {
            list: rosetun_config::ListId::new("temporary"),
            category: None,
        },
        target: RuleTarget::Block,
        exit: None,
    });
    assert_eq!(
        helper.connect(&request).unwrap_err().code,
        ErrorCode::ListMissing
    );
    assert_eq!(controls.spawns(), 0);
}

#[test]
fn skipped_category_rule_does_not_require_a_stored_list() {
    let directory = ListSessionDirectory::new();
    let (helper, controls) = directory.helper();
    let mut request = connect_request();
    request.rule_set.rules.push(Rule {
        id: RuleId::new("vanished"),
        enabled: false,
        matcher: RuleMatcher::List {
            list: rosetun_config::ListId::new("dat"),
            category: Some("removed".into()),
        },
        target: RuleTarget::Block,
        exit: None,
    });
    helper
        .connect(&request)
        .expect("disabled list rule does not need list bytes");
    assert_eq!(controls.spawns(), 1);
    helper.disconnect().unwrap();
}

#[test]
fn failed_apply_restages_the_previous_list_under_protection() {
    let directory = ListSessionDirectory::new();
    let first_id = rosetun_config::ListId::new("first");
    let second_id = rosetun_config::ListId::new("second");
    let first = directory.reference(&first_id, "example.com");
    let second = directory.reference(&second_id, "example.org");
    let (helper, controls) = directory.helper();
    let mut request = with_list_rule(connect_request(), first_id, first.clone());
    request.settings.kill_switch = true;
    helper.connect(&request).expect("first list connects");
    let first_path = directory.0.join("run").join(format!("{}.json", first.tag));
    assert!(first_path.exists());

    let mut changed = request.clone();
    changed.rule_set.rules[0].matcher = RuleMatcher::List {
        list: second_id,
        category: None,
    };
    changed.lists = vec![second.clone()];
    controls.fail_readiness_next(1);
    assert!(helper.apply(&changed).is_err());
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(helper.session().unwrap().request.as_ref(), Some(&request));
    assert!(first_path.exists());
    assert!(
        !directory
            .0
            .join("run")
            .join(format!("{}.json", second.tag))
            .exists()
    );
    helper.disconnect().unwrap();
}

fn extra_node(exit: &str, server: &str) -> ExtraNode {
    let mut node = connect_request().node;
    node.id = NodeId::new(exit);
    node.server = server.into();
    ExtraNode {
        exit: ExitId::new(exit),
        selection: Selection {
            subscription: SubscriptionId::new("sub"),
            node: node.id.clone(),
        },
        node,
    }
}

/// A protected request whose `198.51.100.0/24` rule leaves through `exit`.
fn exit_request(exit: &str, server: &str) -> ConnectRequest {
    let mut request = connect_request();
    request.settings.kill_switch = true;
    request.node.server = "203.0.113.10".into();
    request.extra_nodes = vec![extra_node(exit, server)];
    request.rule_set.rules.push(Rule {
        id: RuleId::new("through-exit"),
        enabled: true,
        matcher: RuleMatcher::IpCidr("198.51.100.0/24".into()),
        target: RuleTarget::Exit,
        exit: Some(ExitId::new(exit)),
    });
    request
}

fn last_exit_target(controls: &EngineControls) -> RuleTarget {
    let rendered = controls.rendered_rules.lock().unwrap();
    rendered
        .last()
        .unwrap()
        .rules
        .iter()
        .find(|rule| rule.id == RuleId::new("through-exit"))
        .unwrap()
        .target
}

fn last_extra_servers(controls: &EngineControls) -> Vec<String> {
    controls
        .rendered_extra
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone()
}

#[test]
fn protected_reconnect_blocks_rules_of_an_extra_name_without_an_address() {
    let (helper, controls, _, reverted) = supervised_helper(true);
    helper
        .connect(&exit_request("other", "198.51.100.20"))
        .unwrap();
    assert_eq!(last_exit_target(&controls), RuleTarget::Exit);
    assert_eq!(last_extra_servers(&controls), ["198.51.100.20"]);
    {
        let mut session = helper.session().unwrap();
        // This name must never be resolved under the kill switch.
        session.request.as_mut().unwrap().extra_nodes[0].node.server = "exit.invalid".into();
        session.last_extra_endpoints.clear();
    }

    controls.kill();
    helper.supervise(Instant::now());

    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(helper.status().node, Some(NodeId::new("node")));
    assert_eq!(controls.spawns(), 2);
    assert_eq!(reverted.load(Ordering::Acquire), 0);
    assert_eq!(last_exit_target(&controls), RuleTarget::Block);
    assert!(last_extra_servers(&controls).is_empty());
    let session = helper.session().unwrap();
    assert_eq!(
        session.last_endpoint.as_ref().unwrap().address,
        "203.0.113.10".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn protected_reconnect_uses_the_remembered_extra_address() {
    let (helper, controls, _, _) = supervised_helper(true);
    helper
        .connect(&exit_request("other", "198.51.100.20"))
        .unwrap();
    {
        let mut session = helper.session().unwrap();
        assert_eq!(
            session.last_extra_endpoints[&ExitId::new("other")].address,
            "198.51.100.20".parse::<IpAddr>().unwrap()
        );
        session.request.as_mut().unwrap().extra_nodes[0].node.server = "EXIT.INVALID.".into();
        session.last_extra_endpoints.insert(
            ExitId::new("other"),
            SuccessfulEndpoint {
                server: "exit.invalid".into(),
                address: "198.51.100.21".parse().unwrap(),
            },
        );
    }

    controls.kill();
    helper.supervise(Instant::now());

    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(last_exit_target(&controls), RuleTarget::Exit);
    assert_eq!(last_extra_servers(&controls), ["198.51.100.21"]);
}

#[test]
fn apply_with_other_extra_nodes_restarts_and_rollback_restores_them() {
    let (helper, controls, _, _) = supervised_helper(true);
    let first = exit_request("other", "198.51.100.20");
    helper.connect(&first).unwrap();

    let mut second = first.clone();
    second.extra_nodes[0].node.server = "198.51.100.30".into();
    helper.apply(&second).unwrap();
    assert_eq!(controls.spawns(), 2);
    assert_eq!(last_extra_servers(&controls), ["198.51.100.30"]);
    assert_eq!(
        helper.session().unwrap().last_extra_endpoints[&ExitId::new("other")].address,
        "198.51.100.30".parse::<IpAddr>().unwrap()
    );

    let mut third = second.clone();
    third.extra_nodes[0].node.server = "198.51.100.40".into();
    controls.fail_next(1);
    helper.apply(&third).expect_err("the new engine fails");
    assert_eq!(controls.spawns(), 4);
    assert_eq!(last_extra_servers(&controls), ["198.51.100.30"]);
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    assert_eq!(helper.session().unwrap().request.as_ref(), Some(&second));
}

#[test]
fn xray_is_permitted_when_only_an_extra_node_needs_it() {
    let (helper, _, runner, binaries, _, _) = xray_chain_helper();
    let mut request = exit_request("other", "198.51.100.20");
    request.extra_nodes[0].node.stream.tls = reality_request().node.stream.tls;
    helper.connect(&request).unwrap();

    let permitted = binaries.lock().unwrap()[0].clone();
    assert_eq!(permitted.len(), 2);
    assert_eq!(permitted[1].file_name().unwrap(), "xray.exe");
    assert_eq!(runner.starts.load(Ordering::Acquire), 1);
    assert_eq!(runner.endpoint_count.load(Ordering::Acquire), 1);
    assert!(helper.session().unwrap().xray_chain);
    assert!(!helper.status().xray);
}

#[test]
fn xray_is_not_permitted_when_no_node_needs_it() {
    let (helper, _, runner, binaries, _, _) = xray_chain_helper();
    helper
        .connect(&exit_request("other", "198.51.100.20"))
        .unwrap();

    assert_eq!(binaries.lock().unwrap()[0].len(), 1);
    assert_eq!(runner.starts.load(Ordering::Acquire), 0);
    assert!(!helper.session().unwrap().xray_chain);
}

#[test]
fn main_and_extra_nodes_share_one_xray_process() {
    let (helper, _, runner, binaries, _, _) = xray_chain_helper();
    let mut request = exit_request("other", "198.51.100.20");
    request.node.stream.tls = reality_request().node.stream.tls;
    request.extra_nodes[0].node.stream.tls = reality_request().node.stream.tls;
    helper.connect(&request).unwrap();

    assert_eq!(binaries.lock().unwrap()[0].len(), 2);
    assert_eq!(runner.starts.load(Ordering::Acquire), 1);
    assert_eq!(runner.endpoint_count.load(Ordering::Acquire), 2);
    assert!(helper.status().xray);
}

#[test]
fn names_are_resolved_directly_only_under_lockdown_without_a_tunnel() {
    assert_eq!(NameLookup::new(false, false), NameLookup::System);
    assert_eq!(NameLookup::new(false, true), NameLookup::System);
    assert_eq!(NameLookup::new(true, true), NameLookup::System);
    assert_eq!(NameLookup::new(true, false), NameLookup::Direct);
    // An IP literal needs no server under either.
    for lookup in [NameLookup::System, NameLookup::Direct] {
        assert_eq!(
            resolve_quiet("192.0.2.7", 443, lookup).unwrap(),
            [IpAddr::from([192, 0, 2, 7])]
        );
    }
}

#[derive(Debug)]
struct SlowCheckEngine {
    checked: Arc<AtomicBool>,
}

impl EngineBackend for SlowCheckEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::SingBox
    }
    fn integration(&self) -> EngineIntegration {
        EngineIntegration::EngineManagedTun
    }
    fn capabilities(&self) -> EngineCapabilities {
        StubEngine.capabilities()
    }
    fn tunnel_dns_server(&self, _: &rosetun_config::TunSettings) -> Option<SocketAddr> {
        None
    }
    fn locate_binary(&self) -> Result<PathBuf, EngineError> {
        while !self.checked.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(1));
        }
        StubEngine.locate_binary()
    }
    fn render(&self, request: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError> {
        StubEngine.render(request)
    }
    fn spawn(
        &self,
        binary: &Path,
        config: &RenderedConfig,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        StubEngine.spawn(binary, config)
    }
}

#[test]
fn status_shows_the_engine_check_while_a_connect_waits_for_it() {
    let checked = Arc::new(AtomicBool::new(false));
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(SlowCheckEngine {
        checked: Arc::clone(&checked),
    }));
    let helper = Arc::new(Helper::new(
        engines,
        Box::new(UnusedRouting),
        VerboseGate::default(),
    ));
    let mut request = connect_request();
    request.settings.kill_switch = false;
    let worker = {
        let helper = Arc::clone(&helper);
        thread::spawn(move || helper.connect(&request))
    };

    wait_for_stage(&helper, rosetun_config::ConnectStage::CheckingEngine);
    assert!(helper.status().state.is_transitional());
    checked.store(true, Ordering::Release);
    worker.join().unwrap().expect("connect succeeds after the check");
    assert_eq!(helper.status().connect_stage, None);
    helper.disconnect().unwrap();
}
