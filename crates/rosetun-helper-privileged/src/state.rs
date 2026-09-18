#[cfg(test)]
mod tests;

use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use rosetun_config::{ConnectionState, Node, RuleSet, Settings, Status};
use rosetun_engine::{EngineProcess, EngineRegistry, RenderRequest};
use rosetun_ipc::{ConnectRequest, ErrorCode, HelperError};
use rosetun_routing::{RoutingBackend, RoutingGuard, RoutingPlan, TunnelInterface};

const TUNNEL_READY_TIMEOUT: Duration = Duration::from_secs(15);
const TUNNEL_READY_POLL_INTERVAL: Duration = Duration::from_millis(100);

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

        let tunnel = settings
            .kill_switch
            .then(|| TunnelInterface::try_from(&settings.tun))
            .transpose()
            .map_err(|error| HelperError::new(ErrorCode::RoutingFailed, error.to_string()))?;

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

        if let Some(tunnel) = tunnel.as_ref() {
            self.wait_for_tunnel(tunnel)?;
        }

        Ok(())
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

            let guard = self.guard.as_mut().ok_or_else(|| {
                HelperError::new(
                    ErrorCode::RoutingFailed,
                    "routing protection disappeared before tunnel authorization",
                )
            })?;

            match guard.authorize_tunnel(tunnel) {
                Ok(()) => return Ok(()),
                Err(error) if error.is_tunnel_not_ready() && Instant::now() < deadline => {
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
                    return Err(HelperError::new(ErrorCode::RoutingFailed, error.to_string()));
                }
            }
        }
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
