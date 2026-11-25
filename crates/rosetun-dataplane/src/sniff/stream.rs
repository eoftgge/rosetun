//! Deadline-bounded TCP stream sniffer that buffers every byte read for replay.

use std::fmt;
use std::io::{self, ErrorKind, Read};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use super::http::probe_http;
use super::tls::probe_tls;
use super::{Probe, Sniffed};

const DEFAULT_MAX_BYTES: usize = 16 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(300);
const READ_CHUNK_BYTES: usize = 4096;

/// Byte and wall-clock caps applied to a single [`sniff_stream`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SniffLimits {
    pub max_bytes: usize,
    pub timeout: Duration,
}

impl Default for SniffLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// Result of sniffing a TCP stream, including every byte already read so the
/// caller can replay them verbatim to the upstream connection.
#[derive(Clone, PartialEq, Eq)]
pub struct StreamSniff {
    pub sniffed: Option<Sniffed>,
    pub buffered: Vec<u8>,
}

impl fmt::Debug for StreamSniff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamSniff")
            .field("sniffed", &self.sniffed)
            .field("buffered_len", &self.buffered.len())
            .finish()
    }
}

struct RestoreReadTimeout<'a> {
    stream: &'a mut TcpStream,
    previous: Option<Duration>,
}

impl Drop for RestoreReadTimeout<'_> {
    fn drop(&mut self) {
        let _ = self.stream.set_read_timeout(self.previous);
    }
}

/// Sniffs TLS or HTTP from `stream` under a hard total deadline and byte cap.
///
/// Always restores the stream's prior read timeout before returning. A deadline
/// expiry, clean EOF, or peer reset after bytes were buffered is not treated as
/// an error; whatever bytes were read are returned for replay.
pub fn sniff_stream(stream: &mut TcpStream, limits: &SniffLimits) -> io::Result<StreamSniff> {
    let previous = stream.read_timeout().ok().flatten();
    let guard = RestoreReadTimeout { stream, previous };
    sniff_stream_inner(guard.stream, limits)
}

fn sniff_stream_inner(stream: &mut TcpStream, limits: &SniffLimits) -> io::Result<StreamSniff> {
    if limits.max_bytes == 0 || limits.timeout.is_zero() {
        return Ok(StreamSniff {
            sniffed: None,
            buffered: Vec::new(),
        });
    }

    let deadline = Instant::now().checked_add(limits.timeout);
    let mut buffered = Vec::with_capacity(limits.max_bytes.min(2048));
    let mut chunk = [0u8; READ_CHUNK_BYTES];

    while buffered.len() < limits.max_bytes {
        let remaining = match deadline {
            Some(end) => end.saturating_duration_since(Instant::now()),
            None => limits.timeout,
        };
        if remaining.is_zero() {
            break;
        }
        stream.set_read_timeout(Some(remaining))?;

        let want = chunk.len().min(limits.max_bytes - buffered.len());
        match stream.read(&mut chunk[..want]) {
            Ok(0) => break,
            Ok(n) => {
                buffered.extend_from_slice(&chunk[..n]);
                let tls = probe_tls(&buffered);
                if let Probe::Found(sniffed) = tls {
                    return Ok(StreamSniff {
                        sniffed: Some(sniffed),
                        buffered,
                    });
                }
                let http = probe_http(&buffered);
                if let Probe::Found(sniffed) = http {
                    return Ok(StreamSniff {
                        sniffed: Some(sniffed),
                        buffered,
                    });
                }
                if matches!(tls, Probe::NotThis) && matches!(http, Probe::NotThis) {
                    break;
                }
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                break;
            }
            Err(err)
                if !buffered.is_empty()
                    && matches!(
                        err.kind(),
                        ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionAborted
                            | ErrorKind::UnexpectedEof
                    ) =>
            {
                break;
            }
            Err(err) => return Err(err),
        }
    }

    Ok(StreamSniff {
        sniffed: None,
        buffered,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;

    use super::super::Protocol;
    use super::super::testing::{
        build_client_hello_message, wrap_tls_record, wrap_tls_records_split,
    };
    use super::*;

    fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn sniffs_client_hello_arriving_in_two_chunks_and_clears_read_timeout() {
        let (mut client, mut server) = loopback_pair();
        let msg = build_client_hello_message(Some(b"chunked.example.com"));
        let wire = wrap_tls_record(&msg);
        let split = wire.len() / 2;

        let expected_wire = wire.clone();
        let sender = thread::spawn(move || {
            client.write_all(&wire[..split]).unwrap();
            client.flush().unwrap();
            thread::sleep(Duration::from_millis(25));
            client.write_all(&wire[split..]).unwrap();
            client.flush().unwrap();
        });

        let limits = SniffLimits {
            max_bytes: 16 * 1024,
            timeout: Duration::from_secs(2),
        };
        let result = sniff_stream(&mut server, &limits).unwrap();
        sender.join().unwrap();

        assert_eq!(
            result.sniffed,
            Some(Sniffed {
                protocol: Protocol::Tls,
                domain: Some("chunked.example.com".to_owned()),
            })
        );
        assert_eq!(result.buffered, expected_wire);
        assert_eq!(server.read_timeout().unwrap(), None);
    }

    #[test]
    fn returns_buffered_bytes_when_slow_client_hits_the_total_deadline() {
        let (mut client, mut server) = loopback_pair();
        let partial = b"GET /slow HTTP/1.1\r\nUser-Agent: trickle\r\n";

        let sender = thread::spawn(move || {
            client.write_all(partial).unwrap();
            client.flush().unwrap();
            thread::sleep(Duration::from_millis(400));
            drop(client);
        });

        let timeout = Duration::from_millis(120);
        let limits = SniffLimits {
            max_bytes: 4096,
            timeout,
        };
        let started = Instant::now();
        let result = sniff_stream(&mut server, &limits).unwrap();
        let elapsed = started.elapsed();

        assert_eq!(result.sniffed, None);
        assert_eq!(result.buffered, partial);
        assert!(
            elapsed < timeout + Duration::from_millis(200),
            "sniff_stream blocked too long: {elapsed:?}"
        );
        assert_eq!(server.read_timeout().unwrap(), None);
        sender.join().unwrap();
    }

    #[test]
    fn returns_buffered_bytes_when_peer_closes_before_completing_headers() {
        let (mut client, mut server) = loopback_pair();
        let partial = b"GET /closed HTTP/1.1\r\n";
        client.write_all(partial).unwrap();
        drop(client);

        let result = sniff_stream(&mut server, &SniffLimits::default()).unwrap();
        assert_eq!(result.sniffed, None);
        assert_eq!(result.buffered, partial);
        assert_eq!(server.read_timeout().unwrap(), None);
    }

    #[test]
    fn stops_at_max_bytes_cap_without_reading_further() {
        let (mut client, mut server) = loopback_pair();
        let mut req = b"GET / HTTP/1.1\r\nX-Pad: ".to_vec();
        req.extend(std::iter::repeat_n(b'a', 200));
        req.extend_from_slice(b"\r\nHost: example.com\r\n\r\n");

        let sender = thread::spawn(move || {
            let _ = client.write_all(&req);
            let _ = client.flush();
            thread::sleep(Duration::from_millis(50));
        });

        let limits = SniffLimits {
            max_bytes: 64,
            timeout: Duration::from_secs(1),
        };
        let result = sniff_stream(&mut server, &limits).unwrap();
        assert_eq!(result.sniffed, None);
        assert_eq!(result.buffered.len(), 64);
        assert_eq!(server.read_timeout().unwrap(), None);
        sender.join().unwrap();
    }

    #[test]
    fn sniffs_client_hello_split_across_records_and_reads() {
        let (mut client, mut server) = loopback_pair();
        let msg = build_client_hello_message(Some(b"split-stream.example.com"));
        let wire = wrap_tls_records_split(&msg, 18);
        let first_record_end = 5 + 18;

        let expected_wire = wire.clone();
        let sender = thread::spawn(move || {
            client.write_all(&wire[..first_record_end]).unwrap();
            client.flush().unwrap();
            thread::sleep(Duration::from_millis(20));
            client.write_all(&wire[first_record_end..]).unwrap();
            client.flush().unwrap();
        });

        let limits = SniffLimits {
            max_bytes: 16 * 1024,
            timeout: Duration::from_secs(2),
        };
        let result = sniff_stream(&mut server, &limits).unwrap();
        sender.join().unwrap();

        assert_eq!(
            result.sniffed,
            Some(Sniffed {
                protocol: Protocol::Tls,
                domain: Some("split-stream.example.com".to_owned()),
            })
        );
        assert_eq!(result.buffered, expected_wire);
        assert_eq!(server.read_timeout().unwrap(), None);
    }

    #[test]
    fn stream_sniff_debug_hides_raw_wire_bytes() {
        let sniff = StreamSniff {
            sniffed: Some(Sniffed {
                protocol: Protocol::Http,
                domain: Some("hidden.example.com".to_owned()),
            }),
            buffered: b"GET / HTTP/1.1\r\nHost: hidden.example.com\r\n\r\n".to_vec(),
        };
        let rendered = format!("{sniff:?}");
        assert!(rendered.contains("buffered_len: 44"));
        assert!(!rendered.contains("hidden"));
        assert!(!rendered.contains("example.com"));
    }

    #[test]
    fn restores_the_callers_prior_read_timeout() {
        let (mut client, mut server) = loopback_pair();
        let prior = Some(Duration::from_secs(7));
        server.set_read_timeout(prior).unwrap();
        let msg = build_client_hello_message(Some(b"keep-timeout.example.com"));
        let wire = wrap_tls_record(&msg);
        client.write_all(&wire).unwrap();

        let result = sniff_stream(&mut server, &SniffLimits::default()).unwrap();
        assert!(result.sniffed.is_some());
        assert_eq!(server.read_timeout().unwrap(), prior);
    }
}
