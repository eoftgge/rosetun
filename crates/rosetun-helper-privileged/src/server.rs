use std::io;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

use rosetun_ipc::{
    Connection, ErrorCode, Frame, HelperError, Listener, PROTOCOL_VERSION, Request, Response,
};

pub(crate) use crate::state::Helper;

const HELPER_VERSION: &str = env!("CARGO_PKG_VERSION");

enum ServerEvent {
    Accepted(Connection),
    Shutdown,
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
        std::thread::Builder::new()
            .name("rosetun-ipc-accept".to_owned())
            .spawn(move || {
                loop {
                    match listener.accept() {
                        Ok(connection) => {
                            if accept_tx.send(ServerEvent::Accepted(connection)).is_err() {
                                break;
                            }
                        }
                        Err(error) => {
                            tracing::error!(%error, "failed to accept connection");
                        }
                    }
                }
            })?;

        while let Ok(event) = self.rx.recv() {
            match event {
                ServerEvent::Accepted(connection) => {
                    let helper = Arc::clone(&helper);
                    let event_tx = self.tx.clone();
                    let ipc_shutdown = self.ipc_shutdown;
                    std::thread::spawn(move || {
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
