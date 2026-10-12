use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, Instant};

const IO_SLICE: Duration = Duration::from_millis(250);
const CONNECT_ATTEMPTS: usize = 3;
const MAX_STATUS_LINE: usize = 256;

fn remaining(deadline: Instant) -> Option<Duration> {
    let time = deadline.saturating_duration_since(Instant::now());
    (!time.is_zero()).then_some(time.min(IO_SLICE))
}

const SECONDARY_REQUEST: &[u8] =
    b"HEAD /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\nConnection: close\r\n\r\n";

fn primary_request(server: SocketAddr) -> String {
    let host = match server.ip() {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    };
    format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
}

/// Both paths share one deadline; a successful HTTP response stops the loser.
pub(super) fn probe_any(
    primary: SocketAddr,
    secondary: &[SocketAddr],
    timeout: Duration,
    stopped: impl Fn() -> bool + Sync,
) -> bool {
    if timeout.is_zero() || stopped() {
        return false;
    }
    let deadline = Instant::now() + timeout;
    let request = primary_request(primary);
    if secondary.is_empty() {
        return probe_until(primary, request.as_bytes(), deadline, &stopped);
    }

    let done = AtomicBool::new(false);
    let cancel = || stopped() || done.load(Ordering::Acquire);
    thread::scope(|scope| {
        let (tx, rx) = mpsc::channel();
        let done = &done;
        let primary_tx = tx.clone();
        let primary_cancel = &cancel;
        scope.spawn(move || {
            let result = probe_until(primary, request.as_bytes(), deadline, primary_cancel);
            if result {
                done.store(true, Ordering::Release);
            }
            let _ = primary_tx.send(result);
        });
        let secondary_cancel = &cancel;
        scope.spawn(move || {
            let result = secondary.iter().copied().any(|server| {
                !secondary_cancel()
                    && probe_until(server, SECONDARY_REQUEST, deadline, secondary_cancel)
            });
            if result {
                done.store(true, Ordering::Release);
            }
            let _ = tx.send(result);
        });
        for result in rx.into_iter().take(2) {
            if result {
                return true;
            }
        }
        false
    })
}

/// A TCP handshake alone can succeed while the tunnel's HTTP path is stalled.
#[cfg(test)]
pub(super) fn probe(server: SocketAddr, timeout: Duration, stopped: impl Fn() -> bool) -> bool {
    if timeout.is_zero() || stopped() {
        return false;
    }
    probe_until(
        server,
        primary_request(server).as_bytes(),
        Instant::now() + timeout,
        &stopped,
    )
}

fn probe_until(
    server: SocketAddr,
    request: &[u8],
    deadline: Instant,
    stopped: &impl Fn() -> bool,
) -> bool {
    for _ in 0..CONNECT_ATTEMPTS {
        if stopped() {
            return false;
        }
        let Some(slice) = remaining(deadline) else {
            return false;
        };
        match TcpStream::connect_timeout(&server, slice) {
            Ok(mut stream) => return check_http(&mut stream, request, deadline, stopped),
            Err(_) => continue,
        }
    }
    false
}

fn check_http(
    stream: &mut TcpStream,
    request: &[u8],
    deadline: Instant,
    stopped: &impl Fn() -> bool,
) -> bool {
    let mut pending = request;
    while !pending.is_empty() {
        if stopped() {
            return false;
        }
        let Some(slice) = remaining(deadline) else {
            return false;
        };
        if stream.set_write_timeout(Some(slice)).is_err() {
            return false;
        }
        match stream.write(pending) {
            Ok(0) => return false,
            Ok(length) => pending = &pending[length..],
            Err(error) if retry(&error) => continue,
            Err(_) => return false,
        }
    }

    let mut line = Vec::with_capacity(MAX_STATUS_LINE);
    while line.len() < MAX_STATUS_LINE {
        if stopped() {
            return false;
        }
        let Some(slice) = remaining(deadline) else {
            return false;
        };
        if stream.set_read_timeout(Some(slice)).is_err() {
            return false;
        }
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => return false,
            Ok(_) if byte[0] == b'\n' => return line.starts_with(b"HTTP/"),
            Ok(_) => line.push(byte[0]),
            Err(error) if retry(&error) => continue,
            Err(_) => return false,
        }
    }
    false
}

fn retry(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::thread;

    fn server(response: &'static [u8]) -> (SocketAddr, thread::JoinHandle<()>) {
        server_with_request(response, b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\n")
    }

    fn server_with_request(
        response: &'static [u8],
        expected: &'static [u8],
    ) -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind HTTP test server");
        let address = listener.local_addr().expect("HTTP test address");
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept HTTP test connection");
            if !response.is_empty() {
                let mut reader = BufReader::new(stream);
                let mut buffer = vec![0u8; expected.len()];
                reader
                    .read_exact(&mut buffer)
                    .expect("read HTTP test request");
                assert_eq!(buffer, expected);
                let mut line = String::new();
                loop {
                    line.clear();
                    reader.read_line(&mut line).expect("read HTTP test header");
                    if line == "\r\n" {
                        break;
                    }
                }
                reader
                    .get_mut()
                    .write_all(response)
                    .expect("write HTTP test response");
            }
        });
        (address, worker)
    }

    fn silent_server() -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind silent server");
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept silent connection");
            thread::sleep(Duration::from_millis(400));
            drop(stream);
        });
        (address, worker)
    }

    #[test]
    fn second_http_path_succeeds_while_the_first_is_silent() {
        let (silent, silent_worker) = silent_server();
        let (working, working_worker) = server_with_request(
            b"HTTP/1.1 204 No Content\r\n\r\n",
            b"HEAD /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\n",
        );
        let started = Instant::now();
        assert!(probe_any(
            silent,
            &[working],
            Duration::from_secs(1),
            || { false }
        ));
        assert!(started.elapsed() < Duration::from_millis(350));
        silent_worker.join().unwrap();
        working_worker.join().unwrap();
    }

    #[test]
    fn another_cached_address_is_tried_after_a_failed_http_path() {
        let (primary, primary_worker) = server(b"");
        let (failed, failed_worker) = server(b"");
        let (working, working_worker) = server_with_request(
            b"HTTP/1.1 302 Found\r\n\r\n",
            b"HEAD /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\n",
        );
        assert!(probe_any(
            primary,
            &[failed, working],
            Duration::from_secs(1),
            || false
        ));
        primary_worker.join().unwrap();
        failed_worker.join().unwrap();
        working_worker.join().unwrap();
    }

    #[test]
    fn two_silent_http_paths_fail_by_the_shared_deadline() {
        let (first, first_worker) = silent_server();
        let (second, second_worker) = silent_server();
        let started = Instant::now();
        assert!(!probe_any(
            first,
            &[second],
            Duration::from_millis(80),
            || false
        ));
        assert!(started.elapsed() < Duration::from_millis(300));
        first_worker.join().unwrap();
        second_worker.join().unwrap();
    }

    #[test]
    fn missing_second_target_uses_only_the_original_http_path() {
        let (primary, worker) = server(b"HTTP/1.1 404 Not Found\r\n\r\n");
        assert!(probe_any(primary, &[], Duration::from_secs(1), || false));
        worker.join().unwrap();
        let (primary, worker) = server(b"");
        assert!(!probe_any(primary, &[], Duration::from_millis(80), || {
            false
        }));
        worker.join().unwrap();
    }

    #[test]
    fn accepts_http_status_line_but_not_arbitrary_data() {
        for (response, expected) in [
            (b"HTTP/1.1 404 Not Found\r\n\r\n".as_slice(), true),
            (b"HELLO\r\n".as_slice(), false),
        ] {
            let (address, worker) = server(response);
            assert_eq!(probe(address, Duration::from_secs(1), || false), expected);
            worker.join().expect("HTTP test server");
        }
    }

    #[test]
    fn immediate_close_and_refusal_fail() {
        let (address, worker) = server(b"");
        assert!(!probe(address, Duration::from_millis(200), || false));
        worker.join().expect("closing test server");
        assert!(!probe(address, Duration::from_millis(200), || false));
    }

    #[test]
    fn silence_obeys_deadline_and_stop() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind silent server");
        let address = listener.local_addr().expect("silent server address");
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept silent connection");
            thread::sleep(Duration::from_millis(400));
            drop(stream);
        });
        let started = Instant::now();
        assert!(!probe(address, Duration::from_millis(80), || false));
        assert!(started.elapsed() < Duration::from_millis(300));
        worker.join().expect("silent server");
        assert!(!probe(address, Duration::from_secs(1), || true));
    }

    #[test]
    fn stop_interrupts_a_silent_http_read() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind silent server");
        let address = listener.local_addr().expect("silent server address");
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept silent connection");
            thread::sleep(Duration::from_millis(400));
            drop(stream);
        });
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let signal = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            worker_stop.store(true, Ordering::Release);
        });
        let started = Instant::now();
        assert!(!probe(address, Duration::from_secs(2), || stop
            .load(Ordering::Acquire)));
        assert!(started.elapsed() < Duration::from_secs(1));
        signal.join().expect("stop signal thread");
        worker.join().expect("silent server");
    }
}
