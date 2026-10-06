use rosetun_config::{
    EngineKind, NodeId, Outbound, RuleId, RuleSetId, RuleTarget, Selection, SubscriptionId,
    Traffic, VlessParams,
};
use rosetun_engine::errors::EngineError;
use rosetun_engine::{
    EngineBackend, EngineCapabilities, EngineIntegration, RenderedConfig, RuleCapabilities,
};
use rosetun_routing::errors::RoutingError;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

use super::*;

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
        panic!("routing preflight must not run when the kill switch is disabled");
    }

    fn begin_protection(
        &mut self,
        _plan: &RoutingPlan,
        _engine_binary: &Path,
    ) -> Result<RoutingGuard, RoutingError> {
        panic!("routing protection must not run when the kill switch is disabled");
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
        Ok(RenderedConfig {
            file_name: "config.json".to_owned(),
            body: Vec::new(),
            unsupported: Vec::new(),
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
    }));
    let helper = Helper::new(engines, Box::new(UnusedRouting));
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

        let routing: Box<dyn RoutingBackend> = if kill_switch {
            Box::new(CountingRouting {
                reverted: Arc::clone(&reverted),
            })
        } else {
            Box::new(UnusedRouting)
        };
        let helper = Helper::new(engines, routing);
        shorten_dns_timeouts(&helper);

        let mut request = connect_request();
        request.settings.kill_switch = kill_switch;
        helper.connect(&request).expect("DNS responds");

        assert!(matches!(helper.status().state, ConnectionState::Connected));
        assert_eq!(stopped.load(Ordering::Acquire), 0);
        assert_eq!(reverted.load(Ordering::Acquire), 0);
        assert!(helper.session().expect("session").last_endpoint.is_some());
    }
}

#[test]
fn fresh_dns_timeout_stops_engine_and_releases_protection() {
    use super::dns::test_support::{Behavior, Server};

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
    );
    shorten_dns_timeouts(&helper);

    let mut request = connect_request();
    request.settings.kill_switch = true;
    let error = helper.connect(&request).expect_err("DNS is silent");

    assert_eq!(error.code, ErrorCode::EngineFailed);
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

    assert_eq!(error.code, ErrorCode::EngineFailed);
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

    let helper = Helper::new(engines, Box::new(UnusedRouting));
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
fn second_operation_reports_busy() {
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
    ));
    let mut request = connect_request();
    request.settings.kill_switch = true;

    let worker = {
        let helper = Arc::clone(&helper);
        std::thread::spawn(move || helper.connect(&request))
    };

    entered_rx.recv().expect("connect reached routing apply");
    let error = helper.disconnect().expect_err("session is held");
    assert_eq!(error.code, ErrorCode::Busy);

    release_tx.send(()).expect("release apply");
    worker
        .join()
        .expect("worker thread")
        .expect("connect succeeds");
}

#[test]
fn connect_without_kill_switch_does_not_use_routing_backend() {
    let mut engines = EngineRegistry::new();
    engines.register(Box::new(StubEngine));

    let helper = Helper::new(engines, Box::new(UnusedRouting));
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

    let helper = Helper::new(engines, Box::new(UnusedRouting));
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

    let helper = Helper::new(engines, Box::new(UnusedRouting));
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
fn status_marks_the_session_failed_when_the_engine_returns_not_running() {
    let running = Arc::new(AtomicBool::new(true));

    let mut engines = EngineRegistry::new();
    engines.register(Box::new(RunningThenExitedEngine {
        running: Arc::clone(&running),
    }));

    let helper = Helper::new(engines, Box::new(UnusedRouting));
    let mut request = connect_request();
    request.settings.kill_switch = false;

    helper
        .connect(&request)
        .expect("connection succeeds while the engine is running");

    let connected = helper.status();
    assert!(matches!(connected.state, ConnectionState::Connected));
    assert!(connected.since_unix.is_some());

    // Exit only after connect has completed its readiness checks.
    running.store(false, Ordering::Release);

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

    let helper = Helper::new(engines, Box::new(UnusedRouting));
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
fn status_reports_failed_protected_when_connected_engine_exits() {
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
    );

    let mut request = connect_request();
    request.settings.kill_switch = true;
    request.settings.tun.name = "rosetun-test".to_owned();
    request.settings.tun.ipv4 = "172.29.10.1/30".to_owned();

    helper
        .connect(&request)
        .expect("connection succeeds while the engine is running");

    running.store(false, Ordering::Release);

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
    );

    let mut request = connect_request();
    request.settings.kill_switch = true;
    request.settings.tun.name = "rosetun-test".to_owned();
    request.settings.tun.ipv4 = "172.29.10.1/30".to_owned();

    helper.connect(&request).expect("connection succeeds");
    running.store(false, Ordering::Release);

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

fn protected_helper(
    engine: Box<dyn EngineBackend>,
) -> (Helper, Arc<AtomicUsize>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let prepared = Arc::new(AtomicUsize::new(0));
    let authorized = Arc::new(AtomicUsize::new(0));
    let reverted = Arc::new(AtomicUsize::new(0));
    let mut engines = EngineRegistry::new();
    engines.register(engine);
    let helper = Helper::new(engines, Box::new(UnusedRouting));

    {
        let mut session = helper.session().expect("session");
        let prepare_count = Arc::clone(&prepared);
        let authorize_count = Arc::clone(&authorized);
        let revert_count = Arc::clone(&reverted);
        session.guard = Some(RoutingGuard::new_with_reconnector(
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
        ));
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
    let helper = Helper::new(engines, Box::new(UnusedRouting));
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
        settings: Settings::default(),
    }
}
