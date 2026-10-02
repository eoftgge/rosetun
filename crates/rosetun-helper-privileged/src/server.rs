use std::sync::Arc;
use std::sync::mpsc::{Sender, channel};

use rosetun_ipc::{Connection, ErrorCode, Frame, HelperError, Listener, Request, Response, PROTOCOL_VERSION};

pub(crate) use crate::state::Helper;

const HELPER_VERSION: &str = env!("CARGO_PKG_VERSION");

enum ServerEvent {
    Accepted(Connection),
    Shutdown,
}

pub fn serve(listener: Listener, helper: Arc<Helper>) -> std::io::Result<()> {
    tracing::info!(endpoint = %listener.path().display(), "helper listener started");

    let (event_tx, event_rx) = channel::<ServerEvent>();
    let accept_tx = event_tx.clone();

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

    while let Ok(event) = event_rx.recv() {
        match event {
            ServerEvent::Accepted(connection) => {
                let helper = Arc::clone(&helper);
                let event_tx = event_tx.clone();
                std::thread::spawn(move || {
                    if let Err(error) = handle(connection, helper, event_tx) {
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
    Err(std::io::Error::other("helper event channel closed unexpectedly"))
}

fn handle(
    mut connection: Connection,
    helper: Arc<Helper>,
    event_tx: Sender<ServerEvent>,
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
        let response = dispatch(&body, &helper, &mut greeted);
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

fn dispatch(request: &Request, helper: &Helper, greeted: &mut bool) -> Response {
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
        Request::Disconnect => match helper.disconnect() {
            Ok(()) => Response::Ok,
            Err(error) => Response::Error(error),
        },
        Request::ApplyRules { .. } => Response::Error(HelperError::new(
            ErrorCode::NotImplemented,
            "live rule updates require an engine config reload",
        )),
        Request::Subscribe => Response::Error(HelperError::new(
            ErrorCode::NotImplemented,
            "events are not pushed yet; poll with status",
        )),
        Request::Shutdown => Response::Ok,
    }
}

fn reply(connection: &mut Connection, id: u64, body: Response) -> Result<(), String> {
    connection
        .write(&Frame::Response { id, body })
        .map_err(|error| error.to_string())
}
