use rosetun_config::{
    DomainMatch, EngineKind, NodeId, Outbound, Rule, RuleId, RuleMatcher, RuleSetId, RuleTarget,
    RuleTemplate, Selection, SubscriptionId, Traffic, VlessParams,
};
use rosetun_engine::errors::EngineError;
use rosetun_engine::{
    EngineBackend, EngineCapabilities, EngineIntegration, RenderedConfig, RuleCapabilities,
};
use rosetun_routing::errors::RoutingError;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

use super::*;

static DNS_SLOTS: Mutex<()> = Mutex::new(());

#[test]
fn startup_hint_extends_only_slow_tunnel_deadline() {
    assert_eq!(
        startup_timeout(rosetun_engine::StartupHints::default()),
        Duration::from_secs(15)
    );
    assert_eq!(
        startup_timeout(rosetun_engine::StartupHints {
            slow_tunnel_creation: true
        }),
        Duration::from_secs(45)
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
        _engine_binary: &Path,
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
        _engine_binary: &Path,
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
        _engine_binary: &Path,
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
    running: Mutex<Option<Arc<AtomicBool>>>,
    outcomes: Mutex<VecDeque<bool>>,
    readiness: Mutex<VecDeque<bool>>,
    rendered_rules: Mutex<Vec<RuleSet>>,
    render_block: Mutex<Option<(Sender<()>, Receiver<()>)>>,
}

impl EngineControls {
    fn fail_next(&self, count: usize) {
        self.outcomes
            .lock()
            .expect("test outcomes mutex")
            .extend(std::iter::repeat_n(false, count));
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
        let running = Arc::new(AtomicBool::new(true));
        *self.controls.running.lock().expect("test process mutex") = Some(Arc::clone(&running));
        let ready = self
            .controls
            .readiness
            .lock()
            .expect("test readiness mutex")
            .pop_front()
            .unwrap_or(true);
        Ok(Box::new(ControlledProcess { running, ready }))
    }
}

#[derive(Debug)]
struct ControlledProcess {
    running: Arc<AtomicBool>,
    ready: bool,
}

impl EngineProcess for ControlledProcess {
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
        _engine_binary: &Path,
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
        _engine_binary: &Path,
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
        _engine_binary: &Path,
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
        _engine_binary: &Path,
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
    controls: Arc<Mutex<Vec<ControlEndpoint>>>,
    verbose_logs: Arc<Mutex<Vec<bool>>>,
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
        }))
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
}

impl TrafficProbe for StubTrafficProbe {
    fn totals(&mut self) -> Result<TrafficTotals, EngineError> {
        Ok(self.totals)
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
        controls: Arc::clone(&controls),
        verbose_logs: Arc::new(Mutex::new(Vec::new())),
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

#[test]
fn verbose_log_is_passed_to_engine_and_closed_on_disconnect_or_expiry() {
    let verbose_logs = Arc::new(Mutex::new(Vec::new()));
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(TrafficEngine {
        totals: TrafficTotals::default(),
        dropped: Arc::new(AtomicUsize::new(0)),
        controls: Arc::new(Mutex::new(Vec::new())),
        verbose_logs: Arc::clone(&verbose_logs),
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
            ConnectionState::Failed { ref reason } if reason == &error.message
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
        ConnectionState::FailedProtected { ref reason } if reason == &error.message
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

    assert_eq!(error.code, ErrorCode::RoutingFailed);
    assert!(error.message.contains("failed to resolve VPN endpoint"));
    assert!(matches!(
        helper.status().state,
        ConnectionState::Failed { .. }
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
        ConnectionState::Failed { ref reason } if reason == "the engine process exited"
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
        ConnectionState::Failed { ref reason }
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
        ConnectionState::FailedProtected { ref reason }
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
            routing: RoutingGuard::new_with_reconnector(
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
            ),
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
        controls: Arc::clone(&controls),
        verbose_logs: Arc::new(Mutex::new(Vec::new())),
    }));
    helper.connect(&protected_request()).expect("first connect");
    wait_for_totals(&helper, totals);

    helper.with_status(|status| {
        status.state = ConnectionState::FailedProtected {
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
fn protected_endpoint_requires_matching_cache_but_accepts_literal_ip() {
    let mut request = protected_request();
    assert!(protected_endpoint(&request.node, None).is_err());

    request.node.server = "198.51.100.7".into();
    assert_eq!(
        protected_endpoint(&request.node, None).expect("literal IP"),
        "198.51.100.7".parse::<IpAddr>().expect("IP"),
    );
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
        temporary_rules: Vec::new(),
        settings: Settings::default(),
    }
}

fn request_with_new_rules(request: &ConnectRequest) -> ConnectRequest {
    let mut updated = request.clone();
    updated.rule_set.rules.push(Rule {
        id: RuleId::new("block-example"),
        enabled: true,
        matcher: RuleMatcher::IpCidr("192.0.2.0/24".to_owned()),
        target: RuleTarget::Block,
    });
    updated
}

fn temporary_rule() -> Rule {
    Rule {
        id: RuleId::new("temporary-domain"),
        enabled: true,
        matcher: RuleMatcher::Domain(DomainMatch::Exact("example.com".to_owned())),
        target: RuleTarget::Direct,
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
        assert!(super::apply::needs_reconnect(
            &request.settings,
            &changed.settings
        ));
        let error = helper.apply(&changed).expect_err("reconnect required");
        assert_eq!(error.code, ErrorCode::InvalidState);
        assert_eq!(error.message, "reconnect to change protection settings");
        assert_eq!(helper.session().unwrap().request.as_ref(), Some(&request));
    }
    assert!(!super::apply::needs_reconnect(
        &request.settings,
        &request.settings
    ));
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
fn apply_temporary_rule_precedes_base_and_survives_supervisor_restart() {
    let (helper, controls, prepared, reverted) = supervised_helper(true);
    let mut request = connect_request();
    request.settings.kill_switch = true;
    let base = Rule {
        id: RuleId::new("base-domain"),
        enabled: true,
        matcher: RuleMatcher::Domain(DomainMatch::Exact("example.com".to_owned())),
        target: RuleTarget::Block,
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
            rosetun_engine::UrlTestTarget::Probe(tag) => tag,
        };
        let blocked = self.blocked.lock().unwrap().take();
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
    while completed.load(Ordering::Acquire) < 19 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let completed_while_blocked = completed.load(Ordering::Acquire);
    release_tx.send(()).unwrap();
    let results = worker.join().unwrap().unwrap();
    assert_eq!(completed_while_blocked, 19);
    assert_eq!(results.len(), 20);
    assert!(results.iter().all(|result| matches!(
        result.outcome,
        ProbeOutcome::Works { .. } | ProbeOutcome::Fails
    )));
    assert_eq!(completed.load(Ordering::Acquire), 20);
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
    let (helper, stopped, dir) = probe_fixture_with_failures(true, None, true, false);
    assert_eq!(
        helper.probe_nodes(&probe_request()).unwrap_err().code,
        ErrorCode::EngineFailed
    );
    assert_eq!(stopped.load(Ordering::Acquire), 0);
    assert!(!dir.join("probe.json").exists());
    std::fs::remove_dir(dir).unwrap();

    let (helper, stopped, dir) = probe_fixture_with_failures(true, None, false, true);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        helper.probe_nodes(&probe_request())
    }));
    assert!(outcome.is_err());
    assert_eq!(stopped.load(Ordering::Acquire), 1);
    assert!(!dir.join("probe.json").exists());
    std::fs::remove_dir(dir).unwrap();
}

#[test]
fn probing_does_not_block_tunnel_operations_and_rejects_second_probe() {
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
    assert_eq!(
        helper.probe_nodes(&request).unwrap_err().code,
        ErrorCode::Busy
    );
    assert!(matches!(
        helper.status().state,
        ConnectionState::Disconnected
    ));
    helper.connect(&connect_request()).unwrap();
    assert!(matches!(helper.status().state, ConnectionState::Connected));
    helper.disconnect().unwrap();
    release_tx.send(()).unwrap();
    worker.join().unwrap().unwrap();
    assert_eq!(stopped.load(Ordering::Acquire), 2);
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
        ProbeOutcome::Works { millis: 23 }
    );
    helper.disconnect().unwrap();
    assert_eq!(stopped.load(Ordering::Acquire), 1);
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
    helper.begin_attempt(ConnectionState::Connecting);
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
