//! Moving bytes between a client and an outbound, counted per connection.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::thread;
use std::time::Duration;

use crate::conntable::Registration;

const BUFFER_BYTES: usize = 16 * 1024;
// Windows can keep an in-flight receive blocked after shutdown on a cloned socket.
const CANCELLATION_POLL: Duration = Duration::from_millis(250);

/// Copies both directions until both sides finish. `preface` goes to the
/// outbound first (bytes the sniffer or the HTTP parser already consumed).
/// Closing the connection through the table shuts both sockets down, which
/// ends the copy.
pub(crate) fn relay(
    client: &TcpStream,
    upstream: &TcpStream,
    registration: &Registration,
    preface: &[u8],
) {
    for stream in [client, upstream] {
        if stream.set_read_timeout(Some(CANCELLATION_POLL)).is_err()
            || stream.set_write_timeout(Some(CANCELLATION_POLL)).is_err()
        {
            shutdown_both(client, upstream);
            return;
        }
        registration.attach(stream);
    }
    let counters = registration.counters();
    let stopped = || registration.is_closed();
    if !preface.is_empty() {
        if !write_cancellable(upstream, preface, &stopped) {
            shutdown_both(client, upstream);
            return;
        }
        counters.add_up(preface.len() as u64);
    }
    thread::scope(|scope| {
        let down = thread::Builder::new()
            .name("dataplane-relay".to_owned())
            .spawn_scoped(scope, || {
                pump(upstream, client, &stopped, |bytes| counters.add_down(bytes));
            });
        if down.is_err() {
            shutdown_both(client, upstream);
            return;
        }
        pump(client, upstream, &stopped, |bytes| counters.add_up(bytes));
    });
}

fn pump(from: &TcpStream, to: &TcpStream, stopped: &impl Fn() -> bool, count: impl Fn(u64)) {
    let mut buffer = vec![0u8; BUFFER_BYTES];
    let mut reader = from;
    while !stopped() {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if !write_cancellable(to, &buffer[..read], stopped) {
                    shutdown_both(from, to);
                    return;
                }
                count(read as u64);
            }
            Err(error) if retry(&error) => {}
            Err(_) => {
                shutdown_both(from, to);
                return;
            }
        }
    }
    to.shutdown(Shutdown::Write).ok();
}

fn write_cancellable(mut stream: &TcpStream, mut data: &[u8], stopped: &impl Fn() -> bool) -> bool {
    while !data.is_empty() && !stopped() {
        match stream.write(data) {
            Ok(0) => return false,
            Ok(written) => data = &data[written..],
            Err(error) if retry(&error) => {}
            Err(_) => return false,
        }
    }
    data.is_empty()
}

fn retry(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn shutdown_both(a: &TcpStream, b: &TcpStream) {
    a.shutdown(Shutdown::Both).ok();
    b.shutdown(Shutdown::Both).ok();
}
