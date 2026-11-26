//! Moving bytes between a client and an outbound, counted per connection.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use crate::conntable::Registration;

const BUFFER_BYTES: usize = 32 * 1024;
// Windows can keep an in-flight receive blocked after shutdown on a cloned socket.
const CANCELLATION_POLL: Duration = Duration::from_millis(250);

#[derive(Clone, Copy)]
enum SocketIo {
    #[cfg(not(windows))]
    Timeouts,
    #[cfg(windows)]
    Readiness,
}

struct DownstreamStats {
    started: Instant,
    first_read_us: Option<u64>,
    read_bytes: u64,
    forwarded_bytes: u64,
    max_write_us: u64,
}

impl DownstreamStats {
    fn start(io: SocketIo) -> Option<Self> {
        match io {
            #[cfg(windows)]
            SocketIo::Readiness if tracing::enabled!(tracing::Level::DEBUG) => Some(Self {
                started: Instant::now(),
                first_read_us: None,
                read_bytes: 0,
                forwarded_bytes: 0,
                max_write_us: 0,
            }),
            _ => None,
        }
    }
}

impl Drop for DownstreamStats {
    fn drop(&mut self) {
        tracing::debug!(
            first_read_us = ?self.first_read_us,
            read_bytes = self.read_bytes,
            forwarded_bytes = self.forwarded_bytes,
            max_write_us = self.max_write_us,
            "native TCP downstream counters"
        );
    }
}

impl SocketIo {
    fn configure(self, stream: &TcpStream) -> io::Result<()> {
        match self {
            #[cfg(not(windows))]
            Self::Timeouts => {
                stream.set_read_timeout(Some(CANCELLATION_POLL))?;
                stream.set_write_timeout(Some(CANCELLATION_POLL))
            }
            #[cfg(windows)]
            Self::Readiness => stream.set_nonblocking(true),
        }
    }

    fn retry(self, error: &io::Error, _stream: &TcpStream, _receiving: bool) -> bool {
        match self {
            #[cfg(not(windows))]
            Self::Timeouts => matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            #[cfg(windows)]
            Self::Readiness => match error.kind() {
                io::ErrorKind::Interrupted => true,
                io::ErrorKind::WouldBlock => {
                    let wait = if _receiving {
                        crate::socket_ready::readable
                    } else {
                        crate::socket_ready::writable
                    };
                    wait(_stream, CANCELLATION_POLL).is_ok()
                }
                _ => false,
            },
        }
    }
}

/// Copies both directions until both sides finish. `preface` goes to the
/// outbound first (bytes the sniffer or the HTTP parser already consumed).
/// Closing the connection through the table shuts both sockets down, which
/// ends the copy.
#[cfg(not(windows))]
pub(crate) fn relay(
    client: &TcpStream,
    upstream: &TcpStream,
    registration: &Registration,
    preface: &[u8],
) {
    relay_inner(client, upstream, registration, preface, SocketIo::Timeouts);
}

#[cfg(windows)]
pub(crate) fn relay_ready(
    client: &TcpStream,
    upstream: &TcpStream,
    registration: &Registration,
    preface: &[u8],
) {
    relay_inner(client, upstream, registration, preface, SocketIo::Readiness);
}

fn relay_inner(
    client: &TcpStream,
    upstream: &TcpStream,
    registration: &Registration,
    preface: &[u8],
    io: SocketIo,
) {
    for stream in [client, upstream] {
        if io.configure(stream).is_err() {
            shutdown_both(client, upstream);
            return;
        }
        registration.attach(stream);
    }
    let counters = registration.counters();
    let stopped = || registration.is_closed();
    if !preface.is_empty() {
        if !write_cancellable(upstream, preface, &stopped, io) {
            shutdown_both(client, upstream);
            return;
        }
        counters.add_up(preface.len() as u64);
    }
    thread::scope(|scope| {
        let down = thread::Builder::new()
            .name("dataplane-relay".to_owned())
            .spawn_scoped(scope, || {
                pump(
                    upstream,
                    client,
                    &stopped,
                    io,
                    DownstreamStats::start(io),
                    |bytes| {
                        counters.add_down(bytes);
                    },
                );
            });
        if down.is_err() {
            shutdown_both(client, upstream);
            return;
        }
        pump(client, upstream, &stopped, io, None, |bytes| {
            counters.add_up(bytes);
        });
    });
}

fn pump(
    from: &TcpStream,
    to: &TcpStream,
    stopped: &impl Fn() -> bool,
    io: SocketIo,
    mut stats: Option<DownstreamStats>,
    count: impl Fn(u64),
) {
    let mut buffer = vec![0u8; BUFFER_BYTES];
    let mut reader = from;
    while !stopped() {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                let start = stats.as_ref().map(|_| Instant::now());
                let forwarded = write_cancellable(to, &buffer[..read], stopped, io);
                if let (Some(stats), Some(start)) = (&mut stats, start) {
                    let elapsed = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                    stats.first_read_us.get_or_insert_with(|| {
                        u64::try_from((start - stats.started).as_micros()).unwrap_or(u64::MAX)
                    });
                    stats.read_bytes += read as u64;
                    stats.max_write_us = stats.max_write_us.max(elapsed);
                    if forwarded {
                        stats.forwarded_bytes += read as u64;
                    }
                }
                if !forwarded {
                    shutdown_both(from, to);
                    return;
                }
                count(read as u64);
            }
            Err(error) if io.retry(&error, from, true) => {}
            Err(_) => {
                shutdown_both(from, to);
                return;
            }
        }
    }
    to.shutdown(Shutdown::Write).ok();
}

fn write_cancellable(
    mut stream: &TcpStream,
    mut data: &[u8],
    stopped: &impl Fn() -> bool,
    io: SocketIo,
) -> bool {
    while !data.is_empty() && !stopped() {
        match stream.write(data) {
            Ok(0) => return false,
            Ok(written) => data = &data[written..],
            Err(error) if io.retry(&error, stream, false) => {}
            Err(_) => return false,
        }
    }
    data.is_empty()
}

fn shutdown_both(a: &TcpStream, b: &TcpStream) {
    a.shutdown(Shutdown::Both).ok();
    b.shutdown(Shutdown::Both).ok();
}
