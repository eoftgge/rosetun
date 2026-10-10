use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use rosetun_ipc::{
    Connection, ErrorCode, Frame, HelperError, Listener, PROTOCOL_VERSION, Request, Response,
};

pub(crate) use crate::state::Helper;

const HELPER_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_ACTIVE_CONNECTIONS: usize = 32;

enum ServerEvent {
    Accepted(Connection, ConnectionPermit),
    Shutdown,
}

struct ConnectionPermit(Arc<AtomicUsize>);

impl ConnectionPermit {
    fn acquire(active: &Arc<AtomicUsize>) -> Option<Self> {
        active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_ACTIVE_CONNECTIONS).then_some(count + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(active)))
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) struct Server {
    tx: Sender<ServerEvent>,
    rx: Receiver<ServerEvent>,
    ipc_shutdown: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ShutdownHandle(Sender<ServerEvent>);

impl Server {
    pub(crate) fn new(ipc_shutdown: bool) -> Self {
        let (tx, rx) = channel();
        Self {
            tx,
            rx,
            ipc_shutdown,
        }
    }

    pub(crate) fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle(self.tx.clone())
    }

    pub(crate) fn serve(self, listener: Listener, helper: Arc<Helper>) -> io::Result<()> {
        tracing::info!(endpoint = %listener.path().display(), "helper listener started");

        let accept_tx = self.tx.clone();
        let active = Arc::new(AtomicUsize::new(0));
        std::thread::Builder::new()
            .name("rosetun-ipc-accept".to_owned())
            .spawn(move || {
                let mut last_limit_warning: Option<Instant> = None;
                loop {
                    match listener.accept() {
                        Ok(connection) => {
                            let Some(permit) = ConnectionPermit::acquire(&active) else {
                                let now = Instant::now();
                                if last_limit_warning.is_none_or(|last| {
                                    now.duration_since(last) >= Duration::from_secs(60)
                                }) {
                                    tracing::warn!(
                                        limit = MAX_ACTIVE_CONNECTIONS,
                                        "helper pipe connection limit reached"
                                    );
                                    last_limit_warning = Some(now);
                                }
                                continue;
                            };
                            if accept_tx
                                .send(ServerEvent::Accepted(connection, permit))
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(error) => {
                            tracing::error!(%error, "failed to accept connection");
                            std::thread::sleep(Duration::from_millis(100));
                        }
                    }
                }
            })?;

        while let Ok(event) = self.rx.recv() {
            match event {
                ServerEvent::Accepted(connection, permit) => {
                    let helper = Arc::clone(&helper);
                    let event_tx = self.tx.clone();
                    let ipc_shutdown = self.ipc_shutdown;
                    std::thread::spawn(move || {
                        let _permit = permit;
                        if let Err(error) = handle(connection, helper, event_tx, ipc_shutdown) {
                            tracing::warn!(%error, "the connection was closed with an error");
                        }
                    });
                }
                ServerEvent::Shutdown => {
                    helper.shutdown();
                    tracing::info!("helper shutdown completed");
                    return Ok(());
                }
            }
        }

        helper.shutdown();
        Err(io::Error::other("helper event channel closed unexpectedly"))
    }
}

impl ShutdownHandle {
    pub(crate) fn request(&self) {
        let _ = self.0.send(ServerEvent::Shutdown);
    }
}

fn handle(
    mut connection: Connection,
    helper: Arc<Helper>,
    event_tx: Sender<ServerEvent>,
    ipc_shutdown: bool,
) -> Result<(), String> {
    let mut greeted = false;

    loop {
        let frame = match connection.read() {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(()),
            Err(error) => return Err(error.to_string()),
        };

        let Frame::Request { id, body } = frame else {
            return Err("a frame was received that the client should not send".to_owned());
        };

        if !greeted && !matches!(body, Request::Hello { .. }) {
            let _ = reply(
                &mut connection,
                id,
                Response::Error(HelperError::new(
                    ErrorCode::HandshakeRequired,
                    "first message must be hello",
                )),
            );
            return Err("client did not handshake".to_owned());
        }

        tracing::debug!(request = ?body, "handling helper request");
        let response = dispatch(&body, &helper, &mut greeted, ipc_shutdown);
        let fatal = matches!(
            response,
            Response::Error(HelperError {
                code: ErrorCode::ProtocolMismatch,
                ..
            })
        );
        let shutdown = matches!(body, Request::Shutdown) && matches!(response, Response::Ok);

        reply(&mut connection, id, response)?;

        if fatal {
            return Err("protocol version mismatch".to_owned());
        }

        if shutdown {
            tracing::info!("shutdown requested");
            event_tx
                .send(ServerEvent::Shutdown)
                .map_err(|_| "failed to signal helper shutdown".to_owned())?;
            return Ok(());
        }
    }
}

fn dispatch(
    request: &Request,
    helper: &Helper,
    greeted: &mut bool,
    ipc_shutdown: bool,
) -> Response {
    match request {
        Request::Hello {
            client,
            protocol_version,
        } => {
            if *protocol_version != PROTOCOL_VERSION {
                return Response::Error(HelperError::new(
                    ErrorCode::ProtocolMismatch,
                    format!(
                        "client speaks protocol {protocol_version}, helper speaks {PROTOCOL_VERSION}"
                    ),
                ));
            }
            *greeted = true;
            tracing::info!(%client, "client connected");
            Response::Hello {
                helper_version: HELPER_VERSION.to_owned(),
                protocol_version: PROTOCOL_VERSION,
            }
        }
        Request::Status => Response::Status(helper.status()),
        Request::TemporaryRules => match helper.temporary_rules() {
            Ok(rules) => Response::TemporaryRules(rules),
            Err(error) => Response::Error(error),
        },
        Request::ListStatus { .. } | Request::PutListChunk { .. } => Response::Error(
            HelperError::new(ErrorCode::NotImplemented, "list uploads are not available yet"),
        ),
        Request::Connect(connect) => match helper.connect(connect) {
            Ok(()) => Response::Ok,
            Err(error) => Response::Error(error),
        },
        Request::ProbeNodes(request) => match helper.probe_nodes(request) {
            Ok(results) => Response::Probe(results),
            Err(error) => Response::Error(error),
        },
        Request::TunnelDelay => match helper.tunnel_delay() {
            Ok(outcome) => Response::Delay(outcome),
            Err(error) => Response::Error(error),
        },
        Request::Disconnect => match helper.disconnect() {
            Ok(()) => Response::Ok,
            Err(error) => Response::Error(error),
        },
        Request::Apply(request) => match helper.apply(request) {
            Ok(()) => Response::Ok,
            Err(error) => Response::Error(error),
        },
        Request::Subscribe => Response::Error(HelperError::new(
            ErrorCode::NotImplemented,
            "events are not pushed yet; poll with status",
        )),
        Request::Shutdown if !ipc_shutdown => Response::Error(HelperError::new(
            ErrorCode::InvalidState,
            "the helper runs as a service; stop the Rosetun service instead",
        )),
        Request::Shutdown => Response::Ok,
    }
}

fn reply(connection: &mut Connection, id: u64, body: Response) -> Result<(), String> {
    connection
        .write(&Frame::Response { id, body })
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_limit_releases_permits_on_drop() {
        let active = Arc::new(AtomicUsize::new(0));
        let permits = (0..MAX_ACTIVE_CONNECTIONS)
            .map(|_| ConnectionPermit::acquire(&active).expect("permit available"))
            .collect::<Vec<_>>();
        assert_eq!(active.load(Ordering::Acquire), MAX_ACTIVE_CONNECTIONS);
        assert!(ConnectionPermit::acquire(&active).is_none());

        drop(permits);
        assert_eq!(active.load(Ordering::Acquire), 0);
        assert!(ConnectionPermit::acquire(&active).is_some());
        assert_eq!(active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn shutdown_is_rejected_only_in_service_mode() {
        let helper = Helper::new(
            rosetun_engine::EngineRegistry::new(),
            rosetun_routing::backend(),
            crate::log_gate::VerboseGate::default(),
        );
        let mut greeted = true;
        assert!(matches!(
            dispatch(&Request::Shutdown, &helper, &mut greeted, false),
            Response::Error(HelperError {
                code: ErrorCode::InvalidState,
                ..
            })
        ));
        assert!(matches!(
            dispatch(&Request::Shutdown, &helper, &mut greeted, true),
            Response::Ok
        ));
    }

    #[test]
    fn server_check_and_delay_dispatch_return_helper_errors() {
        let helper = Helper::new(
            rosetun_engine::EngineRegistry::new(),
            rosetun_routing::backend(),
            crate::log_gate::VerboseGate::default(),
        );
        let mut greeted = true;
        let probe = Request::ProbeNodes(Box::new(rosetun_ipc::ProbeRequest {
            nodes: Vec::new(),
            settings: rosetun_config::Settings::default(),
        }));
        assert!(matches!(
            dispatch(&probe, &helper, &mut greeted, false),
            Response::Error(HelperError {
                code: ErrorCode::InvalidState,
                ..
            })
        ));
        assert!(matches!(
            dispatch(&Request::TunnelDelay, &helper, &mut greeted, false),
            Response::Error(HelperError {
                code: ErrorCode::InvalidState,
                ..
            })
        ));
    }
}
