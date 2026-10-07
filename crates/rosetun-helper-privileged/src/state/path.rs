use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const IO_SLICE: Duration = Duration::from_millis(250);
const CONNECT_ATTEMPTS: usize = 3;
const MAX_STATUS_LINE: usize = 256;

fn remaining(deadline: Instant) -> Option<Duration> {
    let time = deadline.saturating_duration_since(Instant::now());
    (!time.is_zero()).then_some(time.min(IO_SLICE))
}

/// A TCP handshake alone can succeed while the tunnel's HTTP path is stalled.
pub(super) fn probe(server: SocketAddr, timeout: Duration, stopped: impl Fn() -> bool) -> bool {
    if timeout.is_zero() || stopped() {
        return false;
    }
    let deadline = Instant::now() + timeout;
    for _ in 0..CONNECT_ATTEMPTS {
        if stopped() {
            return false;
        }
        let Some(slice) = remaining(deadline) else {
            return false;
        };
        match TcpStream::connect_timeout(&server, slice) {
            Ok(mut stream) => return check_http(&mut stream, server, deadline, &stopped),
            Err(_) => continue,
        }
    }
    false
}

fn check_http(
    stream: &mut TcpStream,
    server: SocketAddr,
    deadline: Instant,
    stopped: &impl Fn() -> bool,
) -> bool {
    let host = match server.ip() {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    };
    let request = format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let mut pending = request.as_bytes();
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
    use std::net::TcpListener;
    use std::thread;

    fn server(response: &'static [u8]) -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind HTTP test server");
        let address = listener.local_addr().expect("HTTP test address");
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept HTTP test connection");
            if !response.is_empty() {
                let mut buffer = [0u8; 256];
                let length = stream.read(&mut buffer).expect("read HTTP test request");
                assert!(buffer[..length].starts_with(b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\n"));
                stream
                    .write_all(response)
                    .expect("write HTTP test response");
            }
        });
        (address, worker)
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
