use std::net::{IpAddr, ToSocketAddrs};
use std::path::PathBuf;

use rosetun_config::{ConnectionState, Node, RuleSet, Settings, Status};
use rosetun_core_engine::{EngineProcess, EngineRegistry, RenderRequest};
use rosetun_ipc::{ConnectRequest, ErrorCode, HelperError};
use rosetun_routing::{RoutingBackend, RoutingGuard, RoutingPlan};

pub struct HelperState {
    status: Status,
    engines: EngineRegistry,
    routing: Box<dyn RoutingBackend>,
    process: Option<Box<dyn EngineProcess>>,
    guard: Option<RoutingGuard>,
    work_dir: PathBuf,
}

impl std::fmt::Debug for HelperState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelperState")
            .field("state", &self.status.state)
            .field("routing", &self.routing.name())
            .finish()
    }
}

impl HelperState {
    pub fn new(engines: EngineRegistry, routing: Box<dyn RoutingBackend>, work_dir: PathBuf) -> Self {
        Self {
            status: Status::default(),
            engines,
            routing,
            process: None,
            guard: None,
            work_dir,
        }
    }

    pub fn work_dir(&self) -> &std::path::Path {
        &self.work_dir
    }

    pub fn status(&mut self) -> Status {
        if self.status.state.is_active() {
            let exited = match self.process.as_mut() {
                Some(process) => process.is_running().err().map(|error| error.to_string()),
                None => None,
            };
            if let Some(reason) = exited {
                tracing::warn!(%reason, "the kernel terminated itself");
                self.fail(reason);
            }
        }
        self.status.clone()
    }

    pub fn connect(&mut self, request: &ConnectRequest) -> Result<(), HelperError> {
        if !matches!(
            self.status.state,
            ConnectionState::Disconnected | ConnectionState::Failed { .. }
        ) {
            return Err(HelperError::new(
                ErrorCode::InvalidState,
                format!("the tunnel is already in condition {:?}", self.status.state),
            ));
        }

        self.status.state = ConnectionState::Connecting;
        match self.start(&request.node, &request.rule_set, &request.settings) {
            Ok(()) => {
                self.status.state = ConnectionState::Connected;
                self.status.node = Some(request.node.id.clone());
                self.status.engine = Some(request.settings.engine);
                self.status.since_unix = Some(now_unix());
                Ok(())
            }
            Err(error) => {
                self.teardown();
                self.fail(error.message.clone());
                Err(error)
            }
        }
    }

    fn start(
        &mut self,
        node: &Node,
        rules: &RuleSet,
        settings: &Settings,
    ) -> Result<(), HelperError> {
        let backend = self.engines.get(settings.engine).ok_or_else(|| {
            HelperError::new(
                ErrorCode::EngineFailed,
                format!("engine {} unavailable", settings.engine.as_str()),
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

    pub fn disconnect(&mut self) -> Result<(), HelperError> {
        self.teardown();
        self.status = Status::default();
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

    fn fail(&mut self, reason: String) {
        self.status.state = ConnectionState::Failed { reason };
        self.status.since_unix = None;
    }
}

impl Drop for HelperState {
    fn drop(&mut self) {
        self.teardown();
    }
}

fn resolve(server: &str, port: u16) -> Vec<IpAddr> {
    match (server, port).to_socket_addrs() {
        Ok(addrs) => addrs.map(|addr| addr.ip()).collect(),
        Err(error) => {
            tracing::warn!(%server, %error, "the server address could not be resolved");
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