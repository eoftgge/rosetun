use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// How long one server may take to accept a TCP connection.
pub const PING_TIMEOUT: Duration = Duration::from_secs(2);
/// Servers measured at the same time.
pub const PING_PARALLEL: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ping {
    Answered(Duration),
    NoAnswer,
}

/// TCP connect time to `server:port`. The name is resolved first; its time
/// does not count. IPv4 is preferred, as for the tunnel itself.
pub fn tcp_ping(server: &str, port: u16, timeout: Duration) -> Ping {
    let Ok(addresses) = (server, port).to_socket_addrs() else {
        return Ping::NoAnswer;
    };
    let addresses: Vec<_> = addresses.collect();
    let Some(address) = addresses
        .iter()
        .find(|address| address.is_ipv4())
        .or_else(|| addresses.first())
    else {
        return Ping::NoAnswer;
    };
    let start = Instant::now();
    match TcpStream::connect_timeout(address, timeout) {
        Ok(_stream) => Ping::Answered(start.elapsed()),
        Err(_) => Ping::NoAnswer,
    }
}

/// Pings every target, at most `parallel` at once, and reports each result
/// by its index as soon as it is known.
pub fn ping_all(
    targets: &[(String, u16)],
    parallel: usize,
    timeout: Duration,
    report: impl Fn(usize, Ping) + Sync,
) {
    let next = AtomicUsize::new(0);
    thread::scope(|scope| {
        for _ in 0..parallel.min(targets.len()) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some((server, port)) = targets.get(index) else {
                        break;
                    };
                    // System DNS has no timeout; a stalled lookup occupies only this worker.
                    report(index, tcp_ping(server, *port, timeout));
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn listening_server_answers_quickly() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(matches!(
            tcp_ping("127.0.0.1", listener.local_addr().unwrap().port(), PING_TIMEOUT),
            Ping::Answered(elapsed) if elapsed < Duration::from_secs(1)
        ));
    }

    #[test]
    fn closed_port_does_not_answer() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert_eq!(tcp_ping("127.0.0.1", port, PING_TIMEOUT), Ping::NoAnswer);
    }

    #[test]
    fn parallel_results_keep_their_target_indices() {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed);
        let targets = [
            ("127.0.0.1".into(), first.local_addr().unwrap().port()),
            ("127.0.0.1".into(), closed_port),
            ("127.0.0.1".into(), second.local_addr().unwrap().port()),
        ];
        let results = Mutex::new(Vec::new());
        ping_all(&targets, 2, PING_TIMEOUT, |index, ping| {
            results.lock().unwrap().push((index, ping));
        });
        let mut results = results.into_inner().unwrap();
        results.sort_by_key(|(index, _)| *index);
        assert_eq!(results.len(), 3);
        assert!(matches!(results[0], (0, Ping::Answered(_))));
        assert_eq!(results[1], (1, Ping::NoAnswer));
        assert!(matches!(results[2], (2, Ping::Answered(_))));
    }
}
