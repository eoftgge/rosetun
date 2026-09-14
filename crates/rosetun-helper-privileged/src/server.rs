use rosetun_ipc::{
    Connection, ErrorCode, Frame, HelperError, Listener, PROTOCOL_VERSION, Request, Response,
};

use crate::state::HelperState;

const HELPER_VERSION: &str = env!("CARGO_PKG_VERSION");

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
            return Err("получен кадр, который клиент слать не должен".to_owned());
        };

        if !greeted && !matches!(body, Request::Hello { .. }) {
            let _ = reply(
                &mut connection,
                id,
                Response::Error(HelperError::new(
                    ErrorCode::HandshakeRequired,
                    "the first message should be hello",
                )),
            );
            return Err("the client did not introduce himself".to_owned());
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
            return Err("version protocol doesn't match".to_owned());
        }
        if shutdown {
            tracing::info!("got command exit");
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
                        "the client speaks version {protocol_version}, helper on {PROTOCOL_VERSION}"
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
            "on-the-fly rule changes will appear along with the kernel config reboot",
        )),
        Request::Subscribe => Response::Error(HelperError::new(
            ErrorCode::NotImplemented,
            "events are not yet sent, the status is retrieved by the status request",
        )),
        Request::Shutdown => Response::Ok,
    }
}

fn poisoned() -> Response {
    Response::Error(HelperError::new(
        ErrorCode::Internal,
        "the helper's state is damaged by the previous panic",
    ))
}

fn reply(connection: &mut Connection, id: u64, body: Response) -> Result<(), String> {
    connection
        .write(&Frame::Response { id, body })
        .map_err(|error| error.to_string())
}