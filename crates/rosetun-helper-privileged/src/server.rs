use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rosetun_ipc::{
    CodecError, Connection, ErrorCode, Frame, HelperError, Listener, PROTOCOL_VERSION, Request,
    Response,
};

use crate::state::Caller;
pub(crate) use crate::state::Helper;

const HELPER_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_ACTIVE_CONNECTIONS: usize = 32;
static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
struct ReadTimeouts {
    hello: Duration,
    frame: Duration,
    idle: Duration,
}

impl Default for ReadTimeouts {
    fn default() -> Self {
        Self {
            hello: Duration::from_secs(5),
            frame: Duration::from_secs(10),
            idle: Duration::from_secs(120),
        }
    }
}

enum ServerEvent {
    Accepted(Connection, ConnectionPermit, Instant),
    Shutdown,
}

struct HandleConfig {
    ipc_shutdown: bool,
    accepted_at: Instant,
    timeouts: ReadTimeouts,
    last_timeout_warning: Arc<Mutex<Option<Instant>>>,
    #[cfg(test)]
    status_delay: Duration,
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

struct UploadOwner {
    helper: Arc<Helper>,
    id: u64,
}

impl Drop for UploadOwner {
    fn drop(&mut self) {
        self.helper.abort_list_uploads(self.id);
    }
}

struct AcceptThread {
    listener: Arc<Listener>,
    stopping: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl AcceptThread {
    fn stop(&mut self) -> io::Result<()> {
        self.stopping.store(true, Ordering::Release);
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        let interrupted = self.listener.interrupt_accept(&thread);
        let joined = thread
            .join()
            .map_err(|_| io::Error::other("helper accept thread panicked"));
        interrupted.and(joined)
    }
}

impl Drop for AcceptThread {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            tracing::error!(%error, "failed to stop helper accept thread");
        }
    }
}

pub(crate) struct Server {
    tx: Sender<ServerEvent>,
    rx: Receiver<ServerEvent>,
    ipc_shutdown: bool,
    read_timeouts: ReadTimeouts,
    active: Arc<AtomicUsize>,
    #[cfg(test)]
    status_delay: Duration,
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone)]
pub(crate) struct ShutdownHandle(Sender<ServerEvent>);

impl Server {
    pub(crate) fn new(ipc_shutdown: bool) -> Self {
        let (tx, rx) = channel();
        Self {
            tx,
            rx,
            ipc_shutdown,
            read_timeouts: ReadTimeouts::default(),
            active: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            status_delay: Duration::ZERO,
        }
    }

    #[cfg(any(windows, test))]
    pub(crate) fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle(self.tx.clone())
    }

    pub(crate) fn serve(self, listener: Listener, helper: Arc<Helper>) -> io::Result<()> {
        tracing::info!(endpoint = %listener.path().display(), "helper listener started");

        let accept_tx = self.tx.clone();
        let active = Arc::clone(&self.active);
        let last_timeout_warning = Arc::new(Mutex::new(None));
        let listener = Arc::new(listener);
        let accept_listener = Arc::clone(&listener);
        let stopping = Arc::new(AtomicBool::new(false));
        let accept_stopping = Arc::clone(&stopping);
        let thread = std::thread::Builder::new()
            .name("rosetun-ipc-accept".to_owned())
            .spawn(move || {
                let mut last_limit_warning: Option<Instant> = None;
                loop {
                    if accept_stopping.load(Ordering::Acquire) {
                        break;
                    }
                    let accepted = accept_listener.accept();
                    // Check before admission: shutdown never waits for a client
                    // slot, even when a real client wins the race with cancellation.
                    if accept_stopping.load(Ordering::Acquire) {
                        break;
                    }
                    match accepted {
                        Ok(connection) => {
                            let accepted_at = Instant::now();
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
                                .send(ServerEvent::Accepted(connection, permit, accepted_at))
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
        let mut accept_thread = AcceptThread {
            listener,
            stopping,
            thread: Some(thread),
        };

        while let Ok(event) = self.rx.recv() {
            match event {
                ServerEvent::Accepted(connection, permit, accepted_at) => {
                    let helper = Arc::clone(&helper);
                    let event_tx = self.tx.clone();
                    let config = HandleConfig {
                        ipc_shutdown: self.ipc_shutdown,
                        accepted_at,
                        timeouts: self.read_timeouts,
                        last_timeout_warning: Arc::clone(&last_timeout_warning),
                        #[cfg(test)]
                        status_delay: self.status_delay,
                    };
                    if let Err(error) = std::thread::Builder::new()
                        .name("rosetun-ipc-client".to_owned())
                        .spawn(move || {
                            let _permit = permit;
                            if let Err(error) = handle(connection, helper, event_tx, config) {
                                tracing::warn!(%error, "the connection was closed with an error");
                            }
                        })
                    {
                        tracing::warn!(%error, "failed to start helper pipe client thread");
                    }
                }
                ServerEvent::Shutdown => {
                    helper.shutdown();
                    accept_thread.stop()?;
                    tracing::info!("helper shutdown completed");
                    return Ok(());
                }
            }
        }

        helper.shutdown();
        accept_thread.stop()?;
        Err(io::Error::other("helper event channel closed unexpectedly"))
    }
}

#[cfg(any(windows, test))]
impl ShutdownHandle {
    pub(crate) fn request(&self) {
        let _ = self.0.send(ServerEvent::Shutdown);
    }
}

fn warn_read_timeout(last_warning: &Mutex<Option<Instant>>) {
    let mut last = last_warning
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = Instant::now();
    if last.is_none_or(|previous| now.duration_since(previous) >= Duration::from_secs(60)) {
        tracing::warn!("helper pipe client read timed out");
        *last = Some(now);
    }
}

fn handle(
    mut connection: Connection,
    helper: Arc<Helper>,
    event_tx: Sender<ServerEvent>,
    config: HandleConfig,
) -> Result<(), String> {
    let mut greeted = false;
    let mut caller = None;
    let owner = UploadOwner {
        helper: Arc::clone(&helper),
        id: NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed),
    };
    let mut idle_since = config.accepted_at;

    loop {
        let first_byte_deadline = idle_since
            + if greeted {
                config.timeouts.idle
            } else {
                config.timeouts.hello
            };
        let hard_deadline = (!greeted).then_some(config.accepted_at + config.timeouts.hello);
        let frame = match connection.read_bounded(
            first_byte_deadline,
            config.timeouts.frame,
            hard_deadline,
        ) {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(()),
            Err(CodecError::Io(error)) if error.kind() == io::ErrorKind::TimedOut => {
                warn_read_timeout(&config.last_timeout_warning);
                return Ok(());
            }
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

        if !greeted && matches!(body, Request::Hello { .. }) {
            match connection.identify_peer() {
                Ok(identity) => caller = Some(Caller::from(identity)),
                Err(error) => tracing::warn!(%error, "could not identify helper pipe client"),
            }
        }

        tracing::debug!("handling helper request");
        let response = dispatch(
            &body,
            &helper,
            &mut greeted,
            caller.as_ref(),
            config.ipc_shutdown,
            owner.id,
        );
        let fatal = matches!(
            response,
            Response::Error(HelperError {
                code: ErrorCode::ProtocolMismatch,
                ..
            })
        );
        let shutdown = matches!(body, Request::Shutdown) && matches!(response, Response::Ok);

        #[cfg(test)]
        if matches!(body, Request::Status) {
            std::thread::sleep(config.status_delay);
        }
        reply(&mut connection, id, response)?;
        idle_since = Instant::now();

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
    caller: Option<&Caller>,
    ipc_shutdown: bool,
    owner: u64,
) -> Response {
    match request {
        Request::Hello {
            client: _,
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
            tracing::info!("client connected");
            Response::Hello {
                helper_version: HELPER_VERSION.to_owned(),
                protocol_version: PROTOCOL_VERSION,
                sing_box_version: Some(
                    rosetun_engine_singbox::SUPPORTED_SING_BOX_VERSION.to_owned(),
                ),
                xray_version: Some(rosetun_engine_xray::SUPPORTED_XRAY_VERSION.to_owned()),
            }
        }
        Request::Status => Response::Status(helper.status()),
        _ if caller.is_none() => Response::Error(HelperError::new(
            ErrorCode::AccessDenied,
            "the account for this connection could not be verified",
        )),
        Request::TemporaryRules => match helper.temporary_rules_as(caller.expect("caller checked"))
        {
            Ok(rules) => Response::TemporaryRules(rules),
            Err(error) => Response::Error(error),
        },
        Request::SessionExits => match helper.session_exits_as(caller.expect("caller checked")) {
            Ok(exits) => Response::SessionExits(exits),
            Err(error) => Response::Error(error),
        },
        Request::DiagnosticLog => match helper.diagnostic_log_as(caller.expect("caller checked")) {
            Ok(text) => Response::DiagnosticLog { text },
            Err(error) => Response::Error(error),
        },
        Request::Connections => match helper.connections_as(caller.expect("caller checked")) {
            Ok((active, closed)) => Response::Connections { active, closed },
            Err(error) => Response::Error(error),
        },
        Request::CloseConnection { id } => {
            match helper.close_connection_as(caller.expect("caller checked"), id) {
                Ok(()) => Response::Ok,
                Err(error) => Response::Error(error),
            }
        }
        Request::ListStatus { hashes } => match helper.list_status(hashes) {
            Ok(missing) => Response::ListStatus { missing },
            Err(error) => Response::Error(error),
        },
        Request::PutListChunk {
            sha256,
            format,
            total_size,
            offset,
            data,
        } => match helper.put_list_chunk(owner, sha256, *format, *total_size, *offset, data) {
            Ok(()) => Response::Ok,
            Err(error) => Response::Error(error),
        },
        Request::Connect(connect) => {
            match helper.connect_as(caller.expect("caller checked"), connect) {
                Ok(()) => Response::Ok,
                Err(error) => Response::Error(error),
            }
        }
        Request::ProbeNodes(request) => match helper.probe_nodes(request) {
            Ok(results) => Response::Probe(results),
            Err(error) => Response::Error(error),
        },
        Request::TunnelDelay => match helper.tunnel_delay_as(caller.expect("caller checked")) {
            Ok(delays) => Response::Delay(delays),
            Err(error) => Response::Error(error),
        },
        Request::Disconnect => match helper.disconnect_as(caller.expect("caller checked")) {
            Ok(()) => Response::Ok,
            Err(error) => Response::Error(error),
        },
        Request::SetLockdown { enabled, allow_lan } => {
            match helper.set_lockdown_as(caller.expect("caller checked"), *enabled, *allow_lan) {
                Ok(()) => Response::Ok,
                Err(error) => Response::Error(error),
            }
        }
        Request::Apply(request) => {
            match helper.apply_as(caller.expect("caller checked"), request) {
                Ok(()) => Response::Ok,
                Err(error) => Response::Error(error),
            }
        }
        Request::Subscribe => Response::Error(HelperError::new(
            ErrorCode::NotImplemented,
            "events are not pushed yet; poll with status",
        )),
        Request::Shutdown if !ipc_shutdown => Response::Error(HelperError::new(
            ErrorCode::InvalidState,
            "the helper runs as a service; stop the Rosetun service instead",
        )),
        #[cfg(target_os = "linux")]
        Request::Shutdown if !caller.expect("caller checked").is_administrator() => {
            Response::Error(HelperError::new(
                ErrorCode::AccessDenied,
                "shutdown requires an administrator",
            ))
        }
        Request::Shutdown => Response::Ok,
    }
}

fn reply(connection: &mut Connection, id: u64, body: Response) -> Result<(), String> {
    connection
        .write(&Frame::Response { id, body })
        .map_err(|error| error.to_string())
}

#[cfg(test)]
#[path = "server/read_tests.rs"]
mod read_tests;

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
    fn shutdown_requires_the_platform_policy() {
        let helper = Helper::new(
            rosetun_engine::EngineRegistry::new(),
            rosetun_routing::backend(),
            crate::log_gate::VerboseGate::default(),
        );
        let mut greeted = true;
        let caller = Caller::fake(b"owner", true);
        assert!(matches!(
            dispatch(
                &Request::Shutdown,
                &helper,
                &mut greeted,
                Some(&caller),
                false,
                0
            ),
            Response::Error(HelperError {
                code: ErrorCode::InvalidState,
                ..
            })
        ));
        assert!(matches!(
            dispatch(
                &Request::Shutdown,
                &helper,
                &mut greeted,
                Some(&caller),
                true,
                0
            ),
            Response::Ok
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_shutdown_rejects_an_authenticated_non_administrator() {
        let helper = Helper::new(
            rosetun_engine::EngineRegistry::new(),
            rosetun_routing::backend(),
            crate::log_gate::VerboseGate::default(),
        );
        let caller = Caller::fake(b"ordinary", false);
        assert!(matches!(
            dispatch(
                &Request::Shutdown,
                &helper,
                &mut true,
                Some(&caller),
                true,
                0
            ),
            Response::Error(HelperError {
                code: ErrorCode::AccessDenied,
                ..
            })
        ));
    }

    #[test]
    fn unidentified_caller_can_only_hello_and_read_status() {
        let helper = Helper::new(
            rosetun_engine::EngineRegistry::new(),
            rosetun_routing::backend(),
            crate::log_gate::VerboseGate::default(),
        );
        let mut greeted = false;
        assert!(matches!(
            dispatch(
                &Request::Hello {
                    client: "test".to_owned(),
                    protocol_version: PROTOCOL_VERSION,
                },
                &helper,
                &mut greeted,
                None,
                false,
                0,
            ),
            Response::Hello {
                protocol_version: PROTOCOL_VERSION,
                ..
            }
        ));
        assert!(greeted);
        assert!(matches!(
            dispatch(&Request::Status, &helper, &mut greeted, None, false, 0),
            Response::Status(_)
        ));
        for request in [
            Request::TemporaryRules,
            Request::SessionExits,
            Request::DiagnosticLog,
            Request::Connections,
            Request::CloseConnection { id: "a".to_owned() },
            Request::TunnelDelay,
            Request::Disconnect,
            Request::SetLockdown {
                enabled: true,
                allow_lan: false,
            },
            Request::Shutdown,
            Request::ListStatus { hashes: Vec::new() },
            Request::PutListChunk {
                sha256: "0".repeat(64),
                format: rosetun_ipc::ListFormat::Source,
                total_size: 1,
                offset: 0,
                data: String::new(),
            },
            Request::ProbeNodes(Box::new(rosetun_ipc::ProbeRequest {
                nodes: Vec::new(),
                settings: rosetun_config::Settings::default(),
            })),
            Request::Subscribe,
        ] {
            assert!(matches!(
                dispatch(&request, &helper, &mut greeted, None, true, 0),
                Response::Error(HelperError {
                    code: ErrorCode::AccessDenied,
                    ..
                })
            ));
        }
    }

    #[test]
    fn identified_account_can_use_public_list_and_probe_requests() {
        let helper = Helper::new(
            rosetun_engine::EngineRegistry::new(),
            rosetun_routing::backend(),
            crate::log_gate::VerboseGate::default(),
        );
        let caller = Caller::fake(b"other", false);
        let mut greeted = true;
        for request in [
            Request::ListStatus { hashes: Vec::new() },
            Request::PutListChunk {
                sha256: "0".repeat(64),
                format: rosetun_ipc::ListFormat::Source,
                total_size: 1,
                offset: 0,
                data: String::new(),
            },
            Request::ProbeNodes(Box::new(rosetun_ipc::ProbeRequest {
                nodes: Vec::new(),
                settings: rosetun_config::Settings::default(),
            })),
        ] {
            assert!(!matches!(
                dispatch(&request, &helper, &mut greeted, Some(&caller), false, 0),
                Response::Error(HelperError {
                    code: ErrorCode::AccessDenied,
                    ..
                })
            ));
        }
    }

    #[test]
    fn server_check_and_delay_dispatch_return_helper_errors() {
        let helper = Helper::new(
            rosetun_engine::EngineRegistry::new(),
            rosetun_routing::backend(),
            crate::log_gate::VerboseGate::default(),
        );
        let mut greeted = true;
        let caller = Caller::fake(b"owner", false);
        let probe = Request::ProbeNodes(Box::new(rosetun_ipc::ProbeRequest {
            nodes: Vec::new(),
            settings: rosetun_config::Settings::default(),
        }));
        assert!(matches!(
            dispatch(&probe, &helper, &mut greeted, Some(&caller), false, 0),
            Response::Error(HelperError {
                code: ErrorCode::InvalidState,
                ..
            })
        ));
        assert!(matches!(
            dispatch(
                &Request::TunnelDelay,
                &helper,
                &mut greeted,
                Some(&caller),
                false,
                0
            ),
            Response::Error(HelperError {
                code: ErrorCode::InvalidState,
                ..
            })
        ));
    }
}
