use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use rosetun_engine::errors::EngineError;
use rosetun_ipc::{ErrorCode, HelperError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reply {
    Success,
    Rcode(u8),
}

#[derive(Debug, Clone, Copy)]
enum LastResult {
    Timeout,
    Rcode(u8),
}

impl std::fmt::Display for LastResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("timeout"),
            Self::Rcode(1) => formatter.write_str("FORMERR"),
            Self::Rcode(2) => formatter.write_str("SERVFAIL"),
            Self::Rcode(4) => formatter.write_str("NOTIMP"),
            Self::Rcode(5) => formatter.write_str("REFUSED"),
            Self::Rcode(code) => write!(formatter, "RCODE {code}"),
        }
    }
}

fn query(id: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(29);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(b"\x07example\x03com\x00");
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    packet
}

fn word(packet: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *packet.get(offset)?,
        *packet.get(offset + 1)?,
    ]))
}

fn skip_name(packet: &[u8], offset: &mut usize) -> Option<()> {
    let mut cursor = *offset;
    let mut end = None;
    let mut expanded_length = 0usize;

    for _ in 0..packet.len() {
        let length = *packet.get(cursor)?;
        match length & 0xc0 {
            0x00 => {
                cursor += 1;
                expanded_length += usize::from(length) + 1;
                if expanded_length > 255 {
                    return None;
                }
                if length == 0 {
                    *offset = end.unwrap_or(cursor);
                    return Some(());
                }
                cursor = cursor.checked_add(usize::from(length))?;
                if cursor > packet.len() {
                    return None;
                }
            }
            0xc0 => {
                let target = usize::from(word(packet, cursor)? & 0x3fff);
                if target < 12 || target >= cursor {
                    return None;
                }
                end.get_or_insert(cursor + 2);
                cursor = target;
            }
            _ => return None,
        }
    }

    None
}

fn parse_reply(packet: &[u8], id: u16) -> Option<Reply> {
    if packet.len() < 12 || word(packet, 0)? != id {
        return None;
    }

    let flags = word(packet, 2)?;
    // A truncated response does not prove that a complete DNS reply arrived.
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 || flags & 0x0200 != 0 {
        return None;
    }

    let mut offset = 12usize;
    for _ in 0..word(packet, 4)? {
        skip_name(packet, &mut offset)?;
        offset = offset.checked_add(4)?;
        if offset > packet.len() {
            return None;
        }
    }

    let records = usize::from(word(packet, 6)?)
        + usize::from(word(packet, 8)?)
        + usize::from(word(packet, 10)?);

    for _ in 0..records {
        skip_name(packet, &mut offset)?;
        let data_length = usize::from(word(packet, offset + 8)?);
        offset = offset.checked_add(10)?.checked_add(data_length)?;
        if offset > packet.len() {
            return None;
        }
    }

    if offset != packet.len() {
        return None;
    }

    let rcode = (flags & 0x000f) as u8;
    Some(match rcode {
        0 | 3 => Reply::Success,
        code => Reply::Rcode(code),
    })
}

fn failed(message: impl Into<String>) -> HelperError {
    HelperError::new(ErrorCode::EngineFailed, message)
}

fn socket_error(error: io::Error) -> HelperError {
    failed(format!(
        "DNS through the tunnel could not be checked: {error}"
    ))
}

fn ensure_running(
    is_running: &mut impl FnMut() -> Result<bool, EngineError>,
) -> Result<(), HelperError> {
    match is_running() {
        Ok(true) => Ok(()),
        Ok(false) => Err(failed("engine exited during DNS check")),
        Err(error) => Err(failed(format!("engine exited during DNS check: {error}"))),
    }
}

fn attempt(
    socket: &UdpSocket,
    server: SocketAddr,
    packet: &[u8],
    id: u16,
    deadline: Instant,
    buffer: &mut [u8],
) -> Result<LastResult, HelperError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Ok(LastResult::Timeout);
    }

    socket
        .set_write_timeout(Some(remaining))
        .map_err(socket_error)?;
    match socket.send_to(packet, server) {
        Ok(_) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            return Ok(LastResult::Timeout);
        }
        Err(error) => return Err(socket_error(error)),
    }

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(LastResult::Timeout);
        }
        socket
            .set_read_timeout(Some(remaining))
            .map_err(socket_error)?;

        match socket.recv_from(buffer) {
            Ok((length, source)) if source == server => match parse_reply(&buffer[..length], id) {
                Some(Reply::Success) => return Ok(LastResult::Rcode(0)),
                Some(Reply::Rcode(code)) => return Ok(LastResult::Rcode(code)),
                None => {}
            },
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Ok(LastResult::Timeout);
            }
            Err(error) => return Err(socket_error(error)),
        }
    }
}

pub(super) fn check(
    server: SocketAddr,
    timeout: Duration,
    attempt_timeout: Duration,
    mut is_running: impl FnMut() -> Result<bool, EngineError>,
) -> Result<(), HelperError> {
    if timeout.is_zero() || attempt_timeout.is_zero() {
        return Err(failed("DNS check timeouts must be nonzero"));
    }

    let started = Instant::now();
    let deadline = started + timeout;
    ensure_running(&mut is_running)?;

    let socket = UdpSocket::bind(("0.0.0.0", 0)).map_err(socket_error)?;
    let mut buffer = vec![0u8; 65_535];
    let mut attempts = 0usize;
    let mut last = LastResult::Timeout;

    while Instant::now() < deadline {
        ensure_running(&mut is_running)?;

        let attempt_deadline = (Instant::now() + attempt_timeout).min(deadline);
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_usize(attempts);
        let id = hasher.finish() as u16;

        attempts += 1;
        last = attempt(
            &socket,
            server,
            &query(id),
            id,
            attempt_deadline,
            &mut buffer,
        )?;

        if matches!(last, LastResult::Rcode(0)) {
            ensure_running(&mut is_running)?;
            tracing::info!(
                %server,
                elapsed_ms = started.elapsed().as_millis() as u64,
                attempts,
                "DNS through the tunnel answered"
            );
            return Ok(());
        }

        tracing::debug!(
            %server,
            attempt = attempts,
            result = %last,
            "DNS through the tunnel check attempt failed"
        );

        ensure_running(&mut is_running)?;

        // Pace immediate negative replies instead of flooding the resolver.
        std::thread::sleep(attempt_deadline.saturating_duration_since(Instant::now()));
    }

    ensure_running(&mut is_running)?;
    Err(failed(format!(
        "DNS through the tunnel did not answer within {} seconds \
         (last: {last}); the resolver may be unreachable from the node",
        timeout.as_secs_f64(),
    )))
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread::{self, JoinHandle};

    #[derive(Debug, Clone, Copy)]
    pub(crate) enum Behavior {
        Noerror,
        Servfail,
        Silent,
        WrongIdThenNoerror,
    }

    pub(crate) struct Server {
        address: SocketAddr,
        stop: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }

    impl Server {
        pub(crate) fn new(behavior: Behavior) -> Self {
            let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind test DNS");
            socket
                .set_read_timeout(Some(Duration::from_millis(10)))
                .expect("set test DNS timeout");

            let address = socket.local_addr().expect("test DNS address");
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = Arc::clone(&stop);
            let worker = thread::spawn(move || {
                let mut buffer = [0u8; 512];
                while !worker_stop.load(Ordering::Acquire) {
                    let (length, peer) = match socket.recv_from(&mut buffer) {
                        Ok(received) => received,
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::TimedOut
                                    | io::ErrorKind::WouldBlock
                                    | io::ErrorKind::Interrupted
                            ) =>
                        {
                            continue;
                        }
                        Err(error) => panic!("test DNS receive failed: {error}"),
                    };

                    if matches!(behavior, Behavior::Silent) {
                        continue;
                    }

                    let mut response = buffer[..length].to_vec();
                    response[2] = 0x81;
                    response[3] = if matches!(behavior, Behavior::Servfail) {
                        0x82
                    } else {
                        0x80
                    };

                    if matches!(behavior, Behavior::WrongIdThenNoerror) {
                        let mut wrong = response.clone();
                        wrong[0] ^= 0xff;
                        socket.send_to(&wrong, peer).expect("send wrong ID");
                    }

                    socket.send_to(&response, peer).expect("send DNS reply");
                }
            });

            Self {
                address,
                stop,
                worker: Some(worker),
            }
        }

        pub(crate) fn address(&self) -> SocketAddr {
            self.address
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            self.worker
                .take()
                .expect("test worker")
                .join()
                .expect("join DNS");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{Behavior, Server};
    use super::*;

    const TIMEOUT: Duration = Duration::from_millis(80);
    const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(20);

    fn response(id: u16, rcode: u8) -> Vec<u8> {
        let mut packet = query(id);
        packet[2] = 0x81;
        packet[3] = 0x80 | rcode;
        packet
    }

    #[test]
    fn example_query_matches_wire_bytes() {
        assert_eq!(
            query(0x1234),
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
              \x07example\x03com\x00\x00\x01\x00\x01",
        );
    }

    #[test]
    fn noerror_and_nxdomain_are_successful() {
        for rcode in [0, 3] {
            assert_eq!(
                parse_reply(&response(123, rcode), 123),
                Some(Reply::Success),
            );
        }
    }

    #[test]
    fn servfail_preserves_the_rcode() {
        assert_eq!(parse_reply(&response(123, 2), 123), Some(Reply::Rcode(2)),);
    }

    #[test]
    fn wrong_id_queries_and_truncated_packets_are_ignored() {
        let packet = response(123, 0);
        assert_eq!(parse_reply(&packet, 456), None);
        assert_eq!(parse_reply(&query(123), 123), None);

        for length in 0..packet.len() {
            assert_eq!(parse_reply(&packet[..length], 123), None);
        }

        let mut truncated = packet.clone();
        truncated[2] |= 0x02;
        assert_eq!(parse_reply(&truncated, 123), None);

        let mut missing_answer = packet;
        missing_answer[7] = 1;
        assert_eq!(parse_reply(&missing_answer, 123), None);
    }

    #[test]
    fn broken_names_are_ignored() {
        let mut packet = response(123, 0);
        packet[12] = 0xc0;
        packet[13] = 12;
        assert_eq!(parse_reply(&packet, 123), None);
    }

    #[test]
    fn udp_noerror_succeeds() {
        let server = Server::new(Behavior::Noerror);
        check(server.address(), TIMEOUT, ATTEMPT_TIMEOUT, || Ok(true)).expect("DNS succeeds");
    }

    #[test]
    fn udp_servfail_reaches_deadline_with_rcode() {
        let server = Server::new(Behavior::Servfail);
        let error = check(server.address(), TIMEOUT, ATTEMPT_TIMEOUT, || Ok(true))
            .expect_err("SERVFAIL fails");

        assert_eq!(error.code, ErrorCode::EngineFailed);
        assert!(error.message.contains("within 0.08 seconds"));
        assert!(error.message.contains("last: SERVFAIL"));
    }

    #[test]
    fn silent_udp_server_reaches_deadline_with_timeout() {
        let server = Server::new(Behavior::Silent);
        let error = check(server.address(), TIMEOUT, ATTEMPT_TIMEOUT, || Ok(true))
            .expect_err("silence fails");

        assert_eq!(error.code, ErrorCode::EngineFailed);
        assert!(error.message.contains("last: timeout"));
    }

    #[test]
    fn wrong_id_does_not_end_the_attempt() {
        let server = Server::new(Behavior::WrongIdThenNoerror);
        check(server.address(), TIMEOUT, ATTEMPT_TIMEOUT, || Ok(true))
            .expect("correct reply follows wrong ID");
    }

    #[test]
    fn exited_engine_fails_without_sending_a_query() {
        let server = Server::new(Behavior::Silent);
        let started = Instant::now();
        let error = check(server.address(), TIMEOUT, ATTEMPT_TIMEOUT, || Ok(false))
            .expect_err("engine exited");

        assert_eq!(error.message, "engine exited during DNS check");
        assert!(started.elapsed() < TIMEOUT);
    }

    #[test]
    fn engine_exit_between_attempts_is_detected() {
        let server = Server::new(Behavior::Silent);
        let mut checks = 0;
        let error = check(server.address(), TIMEOUT, ATTEMPT_TIMEOUT, || {
            checks += 1;
            Ok(checks < 3)
        })
        .expect_err("engine exits after first attempt");

        assert_eq!(error.message, "engine exited during DNS check");
        assert_eq!(checks, 3);
    }
}
