//! Moving bytes between a client and an outbound, counted per connection.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::thread;

use crate::conntable::Registration;

const BUFFER_BYTES: usize = 16 * 1024;

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
    registration.attach(client);
    registration.attach(upstream);
    let counters = registration.counters();
    if !preface.is_empty() {
        if (&*upstream).write_all(preface).is_err() {
            shutdown_both(client, upstream);
            return;
        }
        counters.add_up(preface.len() as u64);
    }
    thread::scope(|scope| {
        let down = thread::Builder::new()
            .name("dataplane-relay".to_owned())
            .spawn_scoped(scope, || {
                pump(upstream, client, |bytes| counters.add_down(bytes));
            });
        if down.is_err() {
            shutdown_both(client, upstream);
            return;
        }
        pump(client, upstream, |bytes| counters.add_up(bytes));
    });
}

fn pump(from: &TcpStream, to: &TcpStream, count: impl Fn(u64)) {
    let mut buffer = vec![0u8; BUFFER_BYTES];
    let mut reader = from;
    let mut writer = to;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if writer.write_all(&buffer[..read]).is_err() {
                    shutdown_both(from, to);
                    return;
                }
                count(read as u64);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                shutdown_both(from, to);
                return;
            }
        }
    }
    to.shutdown(Shutdown::Write).ok();
}

fn shutdown_both(a: &TcpStream, b: &TcpStream) {
    a.shutdown(Shutdown::Both).ok();
    b.shutdown(Shutdown::Both).ok();
}
