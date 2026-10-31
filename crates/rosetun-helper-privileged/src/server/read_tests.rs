use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use rosetun_ipc::{Connection, Frame, Listener, PROTOCOL_VERSION, Request, Response};

use super::{Helper, MAX_ACTIVE_CONNECTIONS, ReadTimeouts, Server, ShutdownHandle};

static NEXT_ENDPOINT: AtomicU64 = AtomicU64::new(1);

fn unique_endpoint() -> PathBuf {
    let suffix = format!(
        "rosetun-read-{}-{}",
        std::process::id(),
        NEXT_ENDPOINT.fetch_add(1, Ordering::Relaxed)
    );
    #[cfg(windows)]
    {
        PathBuf::from(format!(r"\\.\pipe\{suffix}"))
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        let directory = std::env::temp_dir().join(suffix);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .expect("private test directory");
        directory.join("helper.sock")
    }
}

fn open_with_writer(endpoint: &Path) -> io::Result<(Connection, Box<dyn Write + Send>)> {
    #[cfg(unix)]
    {
        let stream = std::os::unix::net::UnixStream::connect(endpoint)?;
        let writer = stream.try_clone()?;
        let partial = stream.try_clone()?;
        Ok((
            Connection::new(Box::new(stream), Box::new(writer)),
            Box::new(partial),
        ))
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_WRITE_DATA};

        let deadline = Instant::now() + Duration::from_secs(2);
        let file = loop {
            match std::fs::OpenOptions::new()
                .access_mode(FILE_GENERIC_READ | FILE_WRITE_DATA)
                .open(endpoint)
            {
                Ok(file) => break file,
                Err(error)
                    if matches!(error.raw_os_error(), Some(2 | 231))
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error),
            }
        };
        let writer = file.try_clone()?;
        let partial = file.try_clone()?;
        Ok((
            Connection::new(Box::new(file), Box::new(writer)),
            Box::new(partial),
        ))
    }
}

fn open_raw(endpoint: &Path) -> io::Result<Connection> {
    open_with_writer(endpoint).map(|(connection, _)| connection)
}

struct TestServer {
    endpoint: PathBuf,
    active: Arc<AtomicUsize>,
    shutdown: ShutdownHandle,
    finished: mpsc::Receiver<()>,
    thread: Option<thread::JoinHandle<io::Result<()>>>,
}

impl TestServer {
    fn start(timeouts: ReadTimeouts) -> Self {
        Self::start_with_status_delay(timeouts, Duration::ZERO)
    }

    fn start_with_status_delay(timeouts: ReadTimeouts, status_delay: Duration) -> Self {
        let endpoint = unique_endpoint();
        #[cfg(windows)]
        let listener = Listener::bind(&endpoint).expect("bind test endpoint");
        #[cfg(target_os = "linux")]
        let listener =
            Listener::bind_test_fixture(endpoint.parent().unwrap()).expect("bind owned fixture");
        let mut server = Server::new(false);
        server.read_timeouts = timeouts;
        server.status_delay = status_delay;
        let active = Arc::clone(&server.active);
        let shutdown = server.shutdown_handle();
        let helper = Arc::new(Helper::new(
            rosetun_engine::EngineRegistry::new(),
            rosetun_routing::backend(),
            crate::log_gate::VerboseGate::default(),
        ));
        let (finished_tx, finished) = mpsc::channel();
        let thread = thread::spawn(move || {
            let result = server.serve(listener, helper);
            let _ = finished_tx.send(());
            result
        });
        Self {
            endpoint,
            active,
            shutdown,
            finished,
            thread: Some(thread),
        }
    }

    fn stop(&mut self) -> io::Result<()> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        self.shutdown.request();
        // Detach on timeout so a regression fails instead of hanging the test
        // runner. Neither a synthetic client nor unlink may wake the accept loop.
        self.finished
            .recv_timeout(Duration::from_secs(4))
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "serve did not stop"))?;
        thread
            .join()
            .map_err(|_| io::Error::other("server thread panicked"))?
    }

    fn connect(&self) -> Connection {
        open_raw(&self.endpoint).expect("connect to test endpoint")
    }

    fn wait_active(&self, expected: usize, limit: Duration) {
        let deadline = Instant::now() + limit;
        while self.active.load(Ordering::Acquire) != expected && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(self.active.load(Ordering::Acquire), expected);
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let stopped = self.stop();
        if !thread::panicking() {
            stopped.expect("server shutdown");
        }
        #[cfg(target_os = "linux")]
        if !thread::panicking() {
            std::fs::remove_dir(self.endpoint.parent().unwrap())
                .expect("remove empty test directory");
        }
    }
}

fn timeouts() -> ReadTimeouts {
    ReadTimeouts {
        hello: Duration::from_millis(800),
        frame: Duration::from_millis(200),
        idle: Duration::from_millis(400),
    }
}

fn bounded<T: Send + 'static>(limit: Duration, run: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(run());
    });
    rx.recv_timeout(limit).expect("test operation timed out")
}

fn exchange(connection: &mut Connection, id: u64, body: Request) -> Response {
    connection
        .write(&Frame::Request { id, body })
        .expect("write request");
    let Some(Frame::Response { id: reply_id, body }) = connection.read().expect("read response")
    else {
        panic!("expected a response frame");
    };
    assert_eq!(reply_id, id);
    body
}

fn hello(connection: &mut Connection) {
    assert!(matches!(
        exchange(
            connection,
            1,
            Request::Hello {
                client: "read-timeout-test".to_owned(),
                protocol_version: PROTOCOL_VERSION,
            }
        ),
        Response::Hello { .. }
    ));
}

fn expect_closed(connection: Connection) {
    let result = bounded(Duration::from_secs(4), move || {
        let mut connection = connection;
        connection.read()
    });
    assert!(matches!(result, Ok(None) | Err(_)), "server left pipe open");
}

#[test]
fn shutdown_without_clients_closes_listener_before_serve_returns() {
    let mut server = TestServer::start(timeouts());
    // Cover shutdown with accept already waiting, as well as immediately after
    // spawning it (the other shutdown tests do not delay).
    thread::sleep(Duration::from_millis(30));
    server.stop().expect("bounded shutdown without clients");
    assert!(open_raw(&server.endpoint).is_err(), "accept survived serve");
    #[cfg(target_os = "linux")]
    {
        assert!(!server.endpoint.exists(), "owned endpoint survived serve");
        let rebound = Listener::bind_test_fixture(server.endpoint.parent().unwrap())
            .expect("rebind after shutdown");
        drop(rebound);
        assert!(!server.endpoint.exists());
    }
    #[cfg(windows)]
    drop(Listener::bind(&server.endpoint).expect("rebind after shutdown"));
}

#[test]
fn shutdown_with_full_client_limit_and_concurrent_connect_does_not_wait_for_clients() {
    let mut server = TestServer::start(ReadTimeouts {
        hello: Duration::from_secs(30),
        ..timeouts()
    });
    let connections: Vec<_> = (0..MAX_ACTIVE_CONNECTIONS)
        .map(|_| server.connect())
        .collect();
    server.wait_active(MAX_ACTIVE_CONNECTIONS, Duration::from_secs(2));
    let endpoint = server.endpoint.clone();
    let (started_tx, started) = mpsc::channel();
    let racing_client = thread::spawn(move || {
        started_tx.send(()).unwrap();
        open_raw(&endpoint)
    });
    started.recv_timeout(Duration::from_secs(2)).unwrap();
    server
        .stop()
        .expect("shutdown must not wait for a free slot");
    assert_eq!(
        server.active.load(Ordering::Acquire),
        MAX_ACTIVE_CONNECTIONS
    );
    assert!(
        open_raw(&server.endpoint).is_err(),
        "accept survived shutdown"
    );
    drop(bounded(Duration::from_secs(4), move || {
        racing_client.join().unwrap()
    }));
    drop(connections);
    server.wait_active(0, Duration::from_secs(2));
}

#[cfg(target_os = "linux")]
#[test]
fn shutdown_cleanup_preserves_a_replacement_endpoint() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::os::unix::net::{UnixListener, UnixStream};

    for replacement in ["file", "symlink", "socket"] {
        let mut server = TestServer::start(timeouts());
        let path = server.endpoint.clone();
        // Deliberate substitution is the tested attack, never shutdown teardown.
        std::fs::remove_file(&path).unwrap();
        let other_socket = match replacement {
            "file" => {
                std::fs::write(&path, b"replacement").unwrap();
                None
            }
            "symlink" => {
                symlink("missing-fixture", &path).unwrap();
                None
            }
            "socket" => {
                let socket = UnixListener::bind(&path).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
                Some(socket)
            }
            _ => unreachable!(),
        };
        let original = std::fs::symlink_metadata(&path).unwrap();
        server.stop().expect("shutdown despite replaced endpoint");
        let after = std::fs::symlink_metadata(&path).expect("replacement retained");
        assert_eq!((after.dev(), after.ino()), (original.dev(), original.ino()));
        if let Some(socket) = other_socket {
            // The foreign listener remains live; shutdown targeted only the
            // original descriptor, never a connection to the substituted path.
            socket.set_nonblocking(true).unwrap();
            let _client = UnixStream::connect(&path).unwrap();
            let _accepted = socket.accept().unwrap();
        } else if replacement == "file" {
            assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        } else {
            assert_eq!(
                std::fs::read_link(&path).unwrap(),
                Path::new("missing-fixture")
            );
        }
        // Only now remove the verified test replacement to leave an empty fixture
        // directory. stop() already joined the real accept worker and ran Drop.
        std::fs::remove_file(&path).unwrap();
    }
}

#[test]
fn silent_clients_release_all_slots_after_hello_timeout() {
    let server = TestServer::start(ReadTimeouts {
        hello: Duration::from_millis(3_000),
        ..timeouts()
    });
    let connections: Vec<_> = (0..MAX_ACTIVE_CONNECTIONS)
        .map(|_| server.connect())
        .collect();
    server.wait_active(MAX_ACTIVE_CONNECTIONS, Duration::from_secs(2));

    let refused = open_raw(&server.endpoint).expect("open refused client");
    let started = Instant::now();
    bounded(Duration::from_millis(900), move || expect_closed(refused));
    assert!(started.elapsed() < Duration::from_millis(900));

    server.wait_active(0, Duration::from_secs(4));
    drop(connections);
    let mut client = server.connect();
    hello(&mut client);
    assert!(matches!(
        exchange(&mut client, 2, Request::Status),
        Response::Status(_)
    ));
}

#[test]
fn partial_frame_and_idle_client_close_on_their_own_deadlines() {
    let server = TestServer::start(timeouts());
    let (mut partial, mut writer) =
        open_with_writer(&server.endpoint).expect("open partial client");
    hello(&mut partial);
    writer
        .write_all(b"{\"request\":")
        .expect("write partial frame");
    let started = Instant::now();
    thread::sleep(Duration::from_millis(90));
    writer.write_all(b"42").expect("continue partial frame");
    server.wait_active(1, Duration::from_secs(1));
    expect_closed(partial);
    assert!(started.elapsed() < Duration::from_millis(360));
    server.wait_active(0, Duration::from_secs(1));

    let mut stalled = server.connect();
    hello(&mut stalled);
    let started = Instant::now();
    server.wait_active(1, Duration::from_secs(1));
    expect_closed(stalled);
    assert!(started.elapsed() >= Duration::from_millis(300));
    server.wait_active(0, Duration::from_secs(1));
}

#[test]
fn partial_hello_cannot_outlast_the_handshake_deadline() {
    let server = TestServer::start(ReadTimeouts {
        hello: Duration::from_millis(270),
        frame: Duration::from_secs(2),
        idle: Duration::from_secs(2),
    });
    let (client, mut writer) = open_with_writer(&server.endpoint).expect("open partial client");
    writer
        .write_all(b"{\"request\":")
        .expect("start hello frame");
    server.wait_active(1, Duration::from_millis(180));
    expect_closed(client);
    server.wait_active(0, Duration::from_secs(1));
}

#[test]
fn frequent_status_requests_keep_connection_alive() {
    let server = TestServer::start(timeouts());
    bounded(Duration::from_secs(4), {
        let mut client = server.connect();
        move || {
            hello(&mut client);
            for id in 2..8 {
                thread::sleep(Duration::from_millis(160));
                assert!(matches!(
                    exchange(&mut client, id, Request::Status),
                    Response::Status(_)
                ));
            }
        }
    });
}

#[test]
fn a_slow_request_does_not_count_as_idle_time() {
    let timeouts = timeouts();
    let server = TestServer::start_with_status_delay(timeouts, timeouts.idle * 2);
    bounded(Duration::from_secs(4), {
        let mut client = server.connect();
        move || {
            hello(&mut client);
            assert!(matches!(
                exchange(&mut client, 2, Request::Status),
                Response::Status(_)
            ));
            assert!(matches!(
                exchange(&mut client, 3, Request::Status),
                Response::Status(_)
            ));
        }
    });
}

#[test]
fn malformed_frames_and_disconnects_release_their_permits() {
    let server = TestServer::start(timeouts());
    let (mut malformed, mut writer) =
        open_with_writer(&server.endpoint).expect("open malformed client");
    hello(&mut malformed);
    writer
        .write_all(b"not json\n")
        .expect("write malformed frame");
    expect_closed(malformed);
    server.wait_active(0, Duration::from_secs(1));

    let mut disconnected = server.connect();
    hello(&mut disconnected);
    server.wait_active(1, Duration::from_secs(1));
    drop(disconnected);
    server.wait_active(0, Duration::from_secs(1));

    let mut client = server.connect();
    hello(&mut client);
    assert!(matches!(
        exchange(&mut client, 2, Request::Status),
        Response::Status(_)
    ));
}
