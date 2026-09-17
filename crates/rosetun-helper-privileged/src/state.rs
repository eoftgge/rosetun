#[cfg(test)]
mod tests;

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
                .begin_protection(&plan, &binary)
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
