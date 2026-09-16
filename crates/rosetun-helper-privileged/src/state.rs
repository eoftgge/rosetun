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

        let binary = backend
            .locate_binary()
            .map_err(|error| HelperError::new(ErrorCode::EngineFailed, error.to_string()))?;
        let config = backend
            .render(&RenderRequest {
                node,
                rules,
                settings,
            })
            .map_err(|error| HelperError::new(ErrorCode::EngineFailed, error.to_string()))?;

        self.routing
            .preflight()
            .map_err(|error| HelperError::new(ErrorCode::RoutingFailed, error.to_string()))?;

        let plan = RoutingPlan {
            tun: settings.tun.clone(),
            bypass: resolve(&node.server, node.port),
            dns: Vec::new(),
            default_route: true,
            kill_switch: settings.kill_switch,
        };
        let guard = self
            .routing
            .apply(&plan)
            .map_err(|error| HelperError::new(ErrorCode::RoutingFailed, error.to_string()))?;
        self.guard = Some(guard);

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

fn resolve(server: &str, port: u16) -> Vec<IpAddr> {
    match (server, port).to_socket_addrs() {
        Ok(addrs) => addrs.map(|addr| addr.ip()).collect(),
        Err(error) => {
            tracing::warn!(%server, %error, "failed to resolve server address");
            Vec::new()
        }
    }
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
    use std::sync::Arc;
    use std::sync::mpsc::{Receiver, Sender, channel};

    use rosetun_config::{
        EngineKind, NodeId, Outbound, RuleSetId, RuleTarget, Selection, SubscriptionId, Traffic,
        VlessParams,
    };
    use rosetun_engine::errors::EngineError;
    use rosetun_engine::{EngineBackend, RenderedConfig};
    use rosetun_routing::RoutingError;

    use super::*;

    #[derive(Debug)]
    struct BlockingRouting {
        entered: Sender<()>,
        release: Receiver<()>,
    }

    impl RoutingBackend for BlockingRouting {
        fn name(&self) -> &'static str {
            "test-blocking"
        }

        fn preflight(&self) -> Result<(), RoutingError> {
            Ok(())
        }

        fn apply(&mut self, _plan: &RoutingPlan) -> Result<RoutingGuard, RoutingError> {
            self.entered.send(()).expect("test observes apply");
            self.release.recv().expect("test releases apply");
            Ok(RoutingGuard::noop())
        }
    }

    #[derive(Debug)]
    struct StubEngine;

    impl EngineBackend for StubEngine {
        fn kind(&self) -> EngineKind {
            EngineKind::SingBox
        }

        fn locate_binary(&self) -> Result<PathBuf, EngineError> {
            Ok(PathBuf::from("sing-box"))
        }

        fn render(&self, _request: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError> {
            Ok(RenderedConfig {
                file_name: "config.json".to_owned(),
                body: Vec::new(),
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

        let mut engines = EngineRegistry::new();
        engines.register(Box::new(StubEngine));

        let helper = Arc::new(Helper::new(
            engines,
            Box::new(BlockingRouting { entered, release }),
        ));

        let worker = {
            let helper = Arc::clone(&helper);
            std::thread::spawn(move || helper.connect(&connect_request()))
        };

        entered_rx.recv().expect("connect reached routing apply");
        assert!(matches!(
            helper.status().state,
            ConnectionState::Connecting
        ));

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

        let mut engines = EngineRegistry::new();
        engines.register(Box::new(StubEngine));

        let helper = Arc::new(Helper::new(
            engines,
            Box::new(BlockingRouting { entered, release }),
        ));

        let worker = {
            let helper = Arc::clone(&helper);
            std::thread::spawn(move || helper.connect(&connect_request()))
        };

        entered_rx.recv().expect("connect reached routing apply");
        let error = helper.disconnect().expect_err("session is held");
        assert_eq!(error.code, ErrorCode::Busy);

        release_tx.send(()).expect("release apply");
        worker.join().expect("worker thread").expect("connect succeeds");
    }
}