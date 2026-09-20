use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

use rosetun_ipc::{connect, Connection, ErrorCode, Frame, HelperError, Listener, Request, Response, PROTOCOL_VERSION};

pub(crate) use crate::state::Helper;

const HELPER_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn serve(listener: Listener, helper: Arc<Helper>) -> std::io::Result<()> {
    tracing::info!(endpoint = %listener.path().display(), "helper listener started");

    let endpoint = listener.path().to_owned();
    let (shutdown_tx, shutdown_rx) = channel();

    loop {
        if shutdown_requested(&shutdown_rx) {
            tracing::info!("helper shutdown completed");
            return Ok(());
        }

        let connection = match listener.accept() {
            Ok(connection) => connection,
            Err(error) => {
                tracing::error!(%error, "failed to accept connection");
                continue;
            }
        };

        let helper = Arc::clone(&helper);
        let shutdown_tx = shutdown_tx.clone();
        let endpoint = endpoint.clone();

        std::thread::spawn(move || {
            if let Err(error) = handle(connection, helper, shutdown_tx, endpoint) {
                tracing::warn!(%error, "the connection was closed with an error");
            }
        });
    }
}

fn shutdown_requested(receiver: &Receiver<()>) -> bool {
    receiver.try_recv().is_ok()
}

fn handle(
    mut connection: Connection,
    helper: Arc<Helper>,
    shutdown_tx: Sender<()>,
    endpoint: PathBuf,
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

            shutdown_tx
                .send(())
                .map_err(|_| "failed to signal helper shutdown".to_owned())?;

            // Wake the blocking accept() call. The connection itself is only
            // a wake-up mechanism and carries no protocol frame.
            let _ = connect(&endpoint);

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
