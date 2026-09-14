use std::sync::{Arc, Mutex};
use rosetun_config::Status;
use rosetun_engine::{EngineProcess, EngineRegistry};
use rosetun_ipc::{
    Connection, ErrorCode, Frame, HelperError, Listener, PROTOCOL_VERSION, Request, Response,
};
use rosetun_routing::{RoutingBackend, RoutingGuard};
use crate::state::HelperState;

const HELPER_VERSION: &str = env!("CARGO_PKG_VERSION");

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

pub fn serve(listener: Listener, state: Arc<Mutex<HelperState>>) -> std::io::Result<()> {
    tracing::info!(endpoint = %listener.path().display(), "helper listener started");
    loop {
        let connection = match listener.accept() {
            Ok(connection) => connection,
            Err(error) => {
                tracing::error!(%error, "failed to accept connection");
                continue;
            }
        };
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            if let Err(error) = handle(connection, state) {
                tracing::warn!(%error, "the connection was closed with an error");
            }
        });
    }
}

fn handle(mut connection: Connection, state: Arc<Mutex<HelperState>>) -> Result<(), String> {
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

        let response = dispatch(&body, &state, &mut greeted);
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
            std::process::exit(0);
        }
    }
}

fn dispatch(
    request: &Request,
    state: &Arc<Mutex<HelperState>>,
    greeted: &mut bool,
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
        Request::Status => match state.lock() {
            Ok(mut state) => Response::Status(state.status()),
            Err(_) => poisoned(),
        },
        Request::Connect(connect) => match state.lock() {
            Ok(mut state) => match state.connect(connect) {
                Ok(()) => Response::Ok,
                Err(error) => Response::Error(error),
            },
            Err(_) => poisoned(),
        },
        Request::Disconnect => match state.lock() {
            Ok(mut state) => match state.disconnect() {
                Ok(()) => Response::Ok,
                Err(error) => Response::Error(error),
            },
            Err(_) => poisoned(),
        },
        Request::ApplyRules { .. } => Response::Error(HelperError::new(
            ErrorCode::NotImplemented,
            "on-the-fly rule changes will appear live rule updates require an engine config reload",
        )),
        Request::Subscribe => Response::Error(HelperError::new(
            ErrorCode::NotImplemented,
            "events are not pushed yet; poll with status",
        )),
        Request::Shutdown => Response::Ok,
    }
}

fn poisoned() -> Response {
    Response::Error(HelperError::new(
        ErrorCode::Internal,
        "helper state poisoned by an earlier panic",
    ))
}

fn reply(connection: &mut Connection, id: u64, body: Response) -> Result<(), String> {
    connection
        .write(&Frame::Response { id, body })
        .map_err(|error| error.to_string())
}