//! SOCKS5 UDP ASSOCIATE relay: per-destination routing, QUIC/UDP sniffing
//! on the first datagram, byte counting and connection-table close support.

use std::collections::HashMap;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use rosetun_config::ConnectionNetwork;

use super::router::Router;
use super::socks;
use crate::conntable::{Counters, Registration};
use crate::net::{Host, Target, UdpPath, write_address};

const MAX_UDP_PACKET: usize = 65_507;
const MAX_FLOWS_PER_ASSOCIATION: usize = 64;
const POLL_INTERVAL: Duration = Duration::from_millis(100);

enum FlowEntry {
    Active(ActiveFlow),
    Blocked(Instant),
}

struct ActiveFlow {
    path: UdpPath,
    registration: Registration,
    counters: Counters,
    last_active_ms: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

/// Runs one SOCKS5 UDP association until the TCP control connection closes
/// or `shutdown` is set.
pub(crate) fn associate(
    router: &Router,
    mut control: TcpStream,
    bind_ip: IpAddr,
    peer_ip: IpAddr,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let client_socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))?;
    let local_addr = client_socket.local_addr()?;
    socks::write_reply(&mut control, 0x00, local_addr)?;

    control.set_read_timeout(None).ok();
    control.set_write_timeout(None).ok();
    client_socket.set_read_timeout(Some(POLL_INTERVAL))?;

    let started = Instant::now();
    let idle_ms = u64::try_from(router.config().udp_idle.as_millis()).unwrap_or(u64::MAX);
    let assoc_closed = Arc::new(AtomicBool::new(false));
    let client_peer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let watcher_control = control.try_clone()?;
    let watcher_closed = Arc::clone(&assoc_closed);

    thread::scope(|scope| {
        let _watcher = thread::Builder::new()
            .name("dataplane-udp-ctrl".to_owned())
            .spawn_scoped(scope, move || {
                let mut control = watcher_control;
                let mut byte = [0u8; 16];
                loop {
                    match control.read(&mut byte) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
                watcher_closed.store(true, Ordering::Release);
            });

        let mut flows: HashMap<Target, FlowEntry> = HashMap::new();
        let mut buffer = vec![0u8; MAX_UDP_PACKET];

        while !assoc_closed.load(Ordering::Acquire) && !shutdown.load(Ordering::Acquire) {
            let now_ms = elapsed_ms(started);
            prune_flows(&mut flows, now_ms, idle_ms);

            let (length, from) = match client_socket.recv_from(&mut buffer) {
                Ok(pair) => pair,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(_) => break,
            };

            // Only accept datagrams from the peer that opened the control socket.
            if from.ip().to_canonical() != peer_ip.to_canonical() {
                continue;
            }
            *client_peer.lock().unwrap_or_else(PoisonError::into_inner) = Some(from);

            let Some((target, header_len)) = parse_client_datagram(&buffer[..length]) else {
                continue;
            };
            let payload = &buffer[header_len..length];

            if !flows.contains_key(&target) {
                if flows.len() >= MAX_FLOWS_PER_ASSOCIATION {
                    continue;
                }
                let entry = open_flow(
                    scope,
                    router,
                    &target,
                    payload,
                    &client_socket,
                    &client_peer,
                    &assoc_closed,
                    shutdown,
                    started,
                    idle_ms,
                );
                if let Some(entry) = entry {
                    flows.insert(target.clone(), entry);
                } else {
                    continue;
                }
            }

            if let Some(FlowEntry::Active(flow)) = flows.get(&target) {
                if flow.registration.is_closed() {
                    flow.stop.store(true, Ordering::Release);
                    flows.remove(&target);
                    continue;
                }
                flow.last_active_ms.store(now_ms, Ordering::Relaxed);
                if flow.path.send_to(payload, &target).is_ok() {
                    flow.counters.add_up(payload.len() as u64);
                }
            }
        }

        for flow in flows.values() {
            if let FlowEntry::Active(active) = flow {
                active.stop.store(true, Ordering::Release);
            }
        }
        assoc_closed.store(true, Ordering::Release);
        control.shutdown(Shutdown::Both).ok();
    });

    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "scoped worker borrows the association's shared state without boxing"
)]
fn open_flow<'scope, 'env>(
    scope: &'scope thread::Scope<'scope, 'env>,
    router: &'env Router,
    target: &Target,
    first_payload: &[u8],
    client_socket: &UdpSocket,
    client_peer: &Arc<Mutex<Option<SocketAddr>>>,
    assoc_closed: &Arc<AtomicBool>,
    shutdown: &'env AtomicBool,
    started: Instant,
    idle_ms: u64,
) -> Option<FlowEntry> {
    let sniffed = if matches!(target.host, Host::Ip(_)) {
        router
            .sniffing()
            .and_then(|sniffing| sniffing.sniff_udp(first_payload))
    } else {
        None
    };
    let (verdict, domain) = router.decide(target, sniffed.as_deref(), ConnectionNetwork::Udp);
    let Some((dialer, route)) = router.outbounds().select(&verdict) else {
        return Some(FlowEntry::Blocked(Instant::now()));
    };
    let path = dialer
        .udp_for(target, router.config().connect_timeout)
        .ok()?;
    path.set_read_timeout(Some(POLL_INTERVAL)).ok()?;
    let reply_path = path.try_clone().ok()?;
    let reply_client = client_socket.try_clone().ok()?;

    let registration = router
        .table()
        .register(Router::meta(
            target,
            domain.as_deref(),
            route,
            ConnectionNetwork::Udp,
        ))
        .ok()?;
    let counters = registration.counters();
    let reply_counters = counters.clone();
    let last_active_ms = Arc::new(AtomicU64::new(elapsed_ms(started)));
    let reply_active = Arc::clone(&last_active_ms);
    let stop = Arc::new(AtomicBool::new(false));
    let reply_stop = Arc::clone(&stop);
    let reply_assoc_closed = Arc::clone(assoc_closed);
    let reply_peer = Arc::clone(client_peer);
    let fallback_target = target.clone();

    thread::Builder::new()
        .name("dataplane-udp-flow".to_owned())
        .spawn_scoped(scope, move || {
            let mut buffer = vec![0u8; MAX_UDP_PACKET];
            while !reply_stop.load(Ordering::Acquire)
                && !reply_assoc_closed.load(Ordering::Acquire)
                && !shutdown.load(Ordering::Acquire)
                && !reply_counters.is_closed()
            {
                let now_ms = elapsed_ms(started);
                let last = reply_active.load(Ordering::Relaxed);
                if now_ms.saturating_sub(last) > idle_ms {
                    break;
                }
                match reply_path.recv_from(&mut buffer) {
                    Ok((length, origin)) => {
                        reply_active.store(elapsed_ms(started), Ordering::Relaxed);
                        let peer = *reply_peer.lock().unwrap_or_else(PoisonError::into_inner);
                        let Some(peer) = peer else {
                            continue;
                        };
                        let source = origin.map_or_else(|| fallback_target.clone(), Target::socket);
                        let mut frame = Vec::with_capacity(length + 24);
                        frame.extend_from_slice(&[0, 0, 0]);
                        if write_address(&mut frame, &source).is_err() {
                            continue;
                        }
                        frame.extend_from_slice(&buffer[..length]);
                        if reply_client.send_to(&frame, peer).is_ok() {
                            reply_counters.add_down(length as u64);
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => break,
                }
            }
            reply_stop.store(true, Ordering::Release);
        })
        .ok()?;

    Some(FlowEntry::Active(ActiveFlow {
        path,
        registration,
        counters,
        last_active_ms,
        stop,
    }))
}

fn prune_flows(flows: &mut HashMap<Target, FlowEntry>, now_ms: u64, idle_ms: u64) {
    let now = Instant::now();
    flows.retain(|_, entry| match entry {
        FlowEntry::Active(flow) => {
            let expired = now_ms.saturating_sub(flow.last_active_ms.load(Ordering::Relaxed))
                > idle_ms
                || flow.registration.is_closed()
                || flow.stop.load(Ordering::Acquire);
            if expired {
                flow.stop.store(true, Ordering::Release);
            }
            !expired
        }
        FlowEntry::Blocked(since) => {
            now.saturating_duration_since(*since) < Duration::from_millis(idle_ms)
        }
    });
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Parses a SOCKS5 UDP request header into `(Target, header_len)`.
/// Fragmented frames (`FRAG != 0`) are dropped.
pub(crate) fn parse_client_datagram(frame: &[u8]) -> Option<(Target, usize)> {
    if frame.len() < 4 || frame[0] != 0 || frame[1] != 0 || frame[2] != 0 {
        return None;
    }
    match frame[3] {
        0x01 => {
            let octets: [u8; 4] = frame.get(4..8)?.try_into().ok()?;
            let port = u16::from_be_bytes(frame.get(8..10)?.try_into().ok()?);
            Some((Target::ip(IpAddr::V4(Ipv4Addr::from(octets)), port), 10))
        }
        0x04 => {
            let octets: [u8; 16] = frame.get(4..20)?.try_into().ok()?;
            let port = u16::from_be_bytes(frame.get(20..22)?.try_into().ok()?);
            Some((Target::ip(IpAddr::V6(Ipv6Addr::from(octets)), port), 22))
        }
        0x03 => {
            let length = usize::from(*frame.get(4)?);
            if length == 0 {
                return None;
            }
            let name_bytes = frame.get(5..5 + length)?;
            let name = std::str::from_utf8(name_bytes).ok()?;
            let host = crate::net::normalize_host(name)?;
            let port = u16::from_be_bytes(frame.get(5 + length..7 + length)?.try_into().ok()?);
            Some((Target { host, port }, 7 + length))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_datagram_header_parses_v4_v6_and_domain() {
        let mut frame = vec![0, 0, 0];
        write_address(&mut frame, &Target::domain("Example.COM", 443)).unwrap();
        frame.extend_from_slice(b"hello");
        let (target, offset) = parse_client_datagram(&frame).unwrap();
        assert_eq!(target, Target::domain("example.com", 443));
        assert_eq!(&frame[offset..], b"hello");

        let mut v4 = vec![0, 0, 0];
        write_address(&mut v4, &Target::ip("192.0.2.5".parse().unwrap(), 53)).unwrap();
        let (target, offset) = parse_client_datagram(&v4).unwrap();
        assert_eq!(target, Target::ip("192.0.2.5".parse().unwrap(), 53));
        assert_eq!(offset, 10);

        assert!(parse_client_datagram(&[0, 0, 1, 1, 192, 0, 2, 1, 0, 53]).is_none());
        assert!(parse_client_datagram(&[0, 0, 0, 3, 0, 0, 53]).is_none());

        // Trailing dots and IP literals inside ATYP=0x03 are normalized.
        let mut trailing = vec![0, 0, 0];
        write_address(&mut trailing, &Target::domain("Blocked.Example.COM.", 443)).unwrap();
        let (target, _) = parse_client_datagram(&trailing).unwrap();
        assert_eq!(target, Target::domain("blocked.example.com", 443));

        let mut ip_in_domain = vec![0, 0, 0];
        write_address(&mut ip_in_domain, &Target::domain("192.0.2.9", 53)).unwrap();
        let (target, _) = parse_client_datagram(&ip_in_domain).unwrap();
        assert_eq!(target, Target::ip("192.0.2.9".parse().unwrap(), 53));
    }
}
