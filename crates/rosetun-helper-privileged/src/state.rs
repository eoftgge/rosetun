use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{Mutex, MutexGuard, TryLockError};

use rosetun_config::{ConnectionState, Node, RuleSet, Settings, Status};
use rosetun_engine::{EngineProcess, EngineRegistry, RenderRequest};
use rosetun_ipc::{ConnectRequest, ErrorCode, HelperError};
use rosetun_routing::{RoutingBackend, RoutingGuard, RoutingPlan};

pub struct Helper {
    status: Mutex<Status>,
    session: Mutex<Session>,
}

struct Session {
    engines: EngineRegistry,
    routing: Box<dyn RoutingBackend>,
    process: Option<Box<dyn EngineProcess>>,
    guard: Option<RoutingGuard>,
}

impl std::fmt::Debug for Helper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Helper").finish_non_exhaustive()
    }
}

impl Helper {
    pub fn new(engines: EngineRegistry, routing: Box<dyn RoutingBackend>) -> Self {
        Self {
            status: Mutex::new(Status::default()),
            session: Mutex::new(Session {
                engines,
                routing,
                process: None,
                guard: None,
            }),
        }
    }

    pub fn status(&self) -> Status {
        if self.with_status(|status| status.state.is_active())
            && let Ok(mut session) = self.session.try_lock()
        {
            let exited = match session.process.as_mut() {
                Some(process) => process.is_running().err().map(|error| error.to_string()),
                None => None,
            };
            if let Some(reason) = exited {
                tracing::warn!(%reason, "the engine terminated itself");
                self.with_status(|status| {
                    status.state = ConnectionState::Failed { reason };
                    status.since_unix = None;
                });
            }
        }
        self.with_status(|status| status.clone())
    }

    pub fn connect(&self, request: &ConnectRequest) -> Result<(), HelperError> {
        let mut session = self.session()?;

        let state = self.with_status(|status| status.state.clone());
        if !matches!(
            state,
            ConnectionState::Disconnected | ConnectionState::Failed { .. }
        ) {
            return Err(HelperError::new(
                ErrorCode::InvalidState,
                format!("tunnel is already {state:?}"),
            ));
        }

        self.with_status(|status| status.state = ConnectionState::Connecting);

        match session.start(&request.node, &request.rule_set, &request.settings) {
            Ok(()) => {
                self.with_status(|status| {
                    status.state = ConnectionState::Connected;
                    status.node = Some(request.node.id.clone());
                    status.engine = Some(request.settings.engine);
                    status.since_unix = Some(now_unix());
                });
                Ok(())
            }
            Err(error) => {
                session.teardown();
                let reason = error.message.clone();
                self.with_status(|status| {
                    status.state = ConnectionState::Failed { reason };
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

    fn session(&self) -> Result<MutexGuard<'_, Session>, HelperError> {
        match self.session.try_lock() {
            Ok(session) => Ok(session),
            Err(TryLockError::WouldBlock) => Err(HelperError::new(
                ErrorCode::Busy,
                "another tunnel operation is in progress",
            )),
            Err(TryLockError::Poisoned(_)) => Err(HelperError::new(
                ErrorCode::Internal,
                "helper state poisoned by an earlier panic",
            )),
        }
    }

    fn with_status<T>(&self, apply: impl FnOnce(&mut Status) -> T) -> T {
        let mut status = self
            .status
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        apply(&mut status)
    }
}

impl Session {
    fn start(
        &mut self,
        node: &Node,
        rules: &RuleSet,
        settings: &Settings,
    ) -> Result<(), HelperError> {
        let backend = self.engines.get(settings.engine).ok_or_else(|| {
            HelperError::new(
                ErrorCode::EngineFailed,
                format!("engine {} is not registered", settings.engine.as_str()),
            )
        })?;

        let config = backend
            .render(&RenderRequest {
                node,
                rules,
                settings,
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

        if settings.kill_switch {
            let plan = RoutingPlan {
                bypass: resolve(&node.server, node.port)?,
                kill_switch: true,
            };

            self.routing
                .preflight()
                .map_err(|error| HelperError::new(ErrorCode::RoutingFailed, error.to_string()))?;

            let guard = self
                .routing
                .apply(&plan)
                .map_err(|error| HelperError::new(ErrorCode::RoutingFailed, error.to_string()))?;
            self.guard = Some(guard);
        }

        let process = backend
            .spawn(&binary, &config)
            .map_err(|error| HelperError::new(ErrorCode::EngineFailed, error.to_string()))?;
        self.process = Some(process);
        Ok(())
    }

    fn teardown(&mut self) {
        if let Some(mut process) = self.process.take()
            && let Err(error) = process.stop()
        {
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

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::sync::{Arc, Mutex};

    use rosetun_config::{
        EngineKind, NodeId, Outbound, RuleId, RuleSetId, RuleTarget, Selection, SubscriptionId,
        Traffic, VlessParams,
    };
    use rosetun_engine::errors::EngineError;
    use rosetun_engine::{
        EngineBackend, EngineCapabilities, EngineIntegration, RenderedConfig, RuleCapabilities,
    };
    use rosetun_routing::errors::RoutingError;

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

        fn apply(&mut self, plan: &RoutingPlan) -> Result<RoutingGuard, RoutingError> {
            *self
                .received_plan
                .lock()
                .expect("test routing plan mutex is not poisoned") = Some(plan.clone());
            self.entered.send(()).expect("test observes apply");
            self.release.recv().expect("test releases apply");
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

        fn apply(&mut self, _plan: &RoutingPlan) -> Result<RoutingGuard, RoutingError> {
            panic!("routing apply must not run when the kill switch is disabled");
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

        fn traffic(&mut self) -> Result<Traffic, EngineError> {
            Err(EngineError::StatsUnavailable)
        }

        fn stop(&mut self) -> Result<(), EngineError> {
            Ok(())
        }
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
        assert_eq!(
            plan.bypass,
            vec!["127.0.0.1".parse::<IpAddr>().expect("valid test address")]
        );
        assert!(plan.kill_switch);

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
}
