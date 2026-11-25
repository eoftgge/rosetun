//! Local UDP and TCP DNS listener backed by [`DnsService`].
//!
//! Binds both UDP and TCP on every requested address, runs UDP queries on a
//! bounded worker pool, accepts up to 64 concurrent TCP clients with 2-byte
//! length framing and 5-second idle/read timeouts, and enforces UDP truncation
//! according to RFC 1035 / EDNS0 (capped at 1232 bytes).

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::{DnsService, wire};

const UDP_WORKER_COUNT: usize = 16;
const UDP_QUEUE_CAPACITY: usize = 128;
const MAX_TCP_CLIENTS: usize = 64;
const TCP_IO_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_POLL: Duration = Duration::from_millis(50);
const MAX_UDP_PACKET: usize = 4096;
const EPHEMERAL_BIND_ATTEMPTS: usize = 32;

struct UdpJob {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    query: Vec<u8>,
}

struct UdpQueue {
    jobs: Mutex<VecDeque<UdpJob>>,
    ready: Condvar,
}

struct TcpClientTracker {
    active: AtomicUsize,
    finished: Mutex<()>,
    zero_cv: Condvar,
}

impl TcpClientTracker {
    fn new() -> Self {
        Self {
            active: AtomicUsize::new(0),
            finished: Mutex::new(()),
            zero_cv: Condvar::new(),
        }
    }

    fn try_acquire(&self) -> bool {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= MAX_TCP_CLIENTS {
                return false;
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    fn release(&self) {
        if self.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            let _guard = self.finished.lock();
            self.zero_cv.notify_all();
        }
    }

    fn wait_all(&self) {
        let Ok(mut guard) = self.finished.lock() else {
            return;
        };
        while self.active.load(Ordering::Acquire) > 0 {
            let Ok(next) = self.zero_cv.wait(guard) else {
                return;
            };
            guard = next;
        }
    }
}

struct TcpClientGuard<'a> {
    tracker: &'a TcpClientTracker,
}

impl Drop for TcpClientGuard<'_> {
    fn drop(&mut self) {
        self.tracker.release();
    }
}

/// UDP and TCP DNS server that forwards queries into a [`DnsService`].
pub struct DnsServer {
    addrs: Vec<SocketAddr>,
    shutdown: Arc<AtomicBool>,
    udp_queue: Arc<UdpQueue>,
    tcp_tracker: Arc<TcpClientTracker>,
    threads: Vec<JoinHandle<()>>,
}

impl fmt::Debug for DnsServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsServer")
            .field("listeners", &self.addrs.len())
            .finish_non_exhaustive()
    }
}

impl DnsServer {
    /// Binds UDP and TCP listeners on every address in `addresses`.
    /// When a requested port is `0`, UDP and TCP are bound to the same
    /// ephemeral port.
    pub fn bind(service: Arc<DnsService>, addresses: &[SocketAddr]) -> io::Result<Self> {
        let mut pairs = Vec::with_capacity(addresses.len());
        let mut addrs = Vec::with_capacity(addresses.len());

        for &addr in addresses {
            let (udp, tcp, bound) = bind_pair(addr)?;
            pairs.push((Arc::new(udp), tcp));
            addrs.push(bound);
        }

        let shutdown = Arc::new(AtomicBool::new(false));
        let udp_queue = Arc::new(UdpQueue {
            jobs: Mutex::new(VecDeque::with_capacity(UDP_QUEUE_CAPACITY)),
            ready: Condvar::new(),
        });
        let tcp_tracker = Arc::new(TcpClientTracker::new());
        let mut server = Self {
            addrs,
            shutdown,
            udp_queue,
            tcp_tracker,
            threads: Vec::new(),
        };

        if !pairs.is_empty() {
            for idx in 0..UDP_WORKER_COUNT {
                let svc = Arc::clone(&service);
                let queue = Arc::clone(&server.udp_queue);
                let stop = Arc::clone(&server.shutdown);
                let handle = thread::Builder::new()
                    .name(format!("dns-udp-worker-{idx}"))
                    .spawn(move || udp_worker_loop(&svc, &queue, &stop))?;
                server.threads.push(handle);
            }
        }

        for (idx, (udp, tcp)) in pairs.into_iter().enumerate() {
            let queue = Arc::clone(&server.udp_queue);
            let stop = Arc::clone(&server.shutdown);
            let udp_handle = thread::Builder::new()
                .name(format!("dns-udp-recv-{idx}"))
                .spawn(move || udp_recv_loop(&udp, &queue, &stop))?;
            server.threads.push(udp_handle);

            let svc = Arc::clone(&service);
            let stop = Arc::clone(&server.shutdown);
            let tracker = Arc::clone(&server.tcp_tracker);
            let tcp_handle = thread::Builder::new()
                .name(format!("dns-tcp-accept-{idx}"))
                .spawn(move || tcp_accept_loop(tcp, &svc, &tracker, &stop))?;
            server.threads.push(tcp_handle);
        }

        Ok(server)
    }

    /// Local addresses the server is bound to (shared by UDP and TCP).
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.addrs.clone()
    }

    /// Stops all listeners and joins every worker thread. Idempotent.
    pub fn shutdown(&mut self) {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return;
        }
        // Wake blocked UDP receivers and TCP acceptors via loopback so shutdown
        // completes immediately instead of waiting for timeouts.
        for &addr in &self.addrs {
            let wake = wake_addr(addr);
            let _ = TcpStream::connect_timeout(&wake, Duration::from_millis(50));
            let bind_ip = if wake.is_ipv4() {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            } else {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            };
            if let Ok(sock) = UdpSocket::bind(SocketAddr::new(bind_ip, 0)) {
                let _ = sock.send_to(&[0], wake);
            }
        }
        // Lock the queue before notifying so no worker can miss the wakeup
        // between checking `shutdown` and entering `wait`.
        {
            let mut jobs = self
                .udp_queue
                .jobs
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            jobs.clear();
            self.udp_queue.ready.notify_all();
        }

        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
        self.tcp_tracker.wait_all();
    }
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn bind_pair(addr: SocketAddr) -> io::Result<(UdpSocket, TcpListener, SocketAddr)> {
    let attempts = if addr.port() == 0 {
        EPHEMERAL_BIND_ATTEMPTS
    } else {
        1
    };
    let mut last_err = None;
    for _ in 0..attempts {
        let tcp = TcpListener::bind(addr)?;
        let bound = tcp.local_addr()?;
        match UdpSocket::bind(bound) {
            Ok(udp) => {
                udp.set_read_timeout(Some(SHUTDOWN_POLL))?;
                return Ok((udp, tcp, bound));
            }
            // On Windows, excluded UDP port ranges return WSAEACCES (PermissionDenied).
            Err(err)
                if addr.port() == 0
                    && matches!(
                        err.kind(),
                        io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
                    ) =>
            {
                last_err = Some(err);
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::AddrInUse, "could not bind port")))
}

fn wake_addr(addr: SocketAddr) -> SocketAddr {
    let ip = match addr.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    };
    SocketAddr::new(ip, addr.port())
}

fn udp_recv_loop(socket: &Arc<UdpSocket>, queue: &UdpQueue, shutdown: &AtomicBool) {
    let mut buf = [0u8; MAX_UDP_PACKET];
    while !shutdown.load(Ordering::Acquire) {
        match socket.recv_from(&mut buf) {
            Ok((len, peer)) => {
                if shutdown.load(Ordering::Acquire) || len == 0 {
                    continue;
                }
                let query = buf[..len].to_vec();
                let mut pushed = false;
                if let Ok(mut jobs) = queue.jobs.lock()
                    && jobs.len() < UDP_QUEUE_CAPACITY
                {
                    jobs.push_back(UdpJob {
                        socket: Arc::clone(socket),
                        peer,
                        query: query.clone(),
                    });
                    pushed = true;
                    queue.ready.notify_one();
                }
                if !pushed {
                    let reply = wire::error_response(&query, wire::RCODE_SERVFAIL);
                    let _ = socket.send_to(&reply, peer);
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(_) => {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                // Windows raises ConnectionReset on UDP when an earlier reply hit
                // an unreachable client port; ignore it and keep serving.
            }
        }
    }
}

fn udp_worker_loop(service: &DnsService, queue: &UdpQueue, shutdown: &AtomicBool) {
    loop {
        let job = {
            let Ok(mut jobs) = queue.jobs.lock() else {
                return;
            };
            loop {
                if shutdown.load(Ordering::Acquire) {
                    break None;
                }
                if let Some(job) = jobs.pop_front() {
                    break Some(job);
                }
                let Ok(next) = queue.ready.wait(jobs) else {
                    return;
                };
                jobs = next;
            }
        };
        let Some(job) = job else {
            return;
        };
        let mut response = service
            .exchange(&job.query)
            .unwrap_or_else(|_| wire::error_response(&job.query, wire::RCODE_SERVFAIL));
        let limit = wire::udp_limit(&job.query);
        if response.len() > limit {
            response = wire::truncated_response(&response);
        }
        let _ = job.socket.send_to(&response, job.peer);
    }
}

fn tcp_accept_loop(
    listener: TcpListener,
    service: &Arc<DnsService>,
    tracker: &Arc<TcpClientTracker>,
    shutdown: &Arc<AtomicBool>,
) {
    for incoming in listener.incoming() {
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        let Ok(stream) = incoming else {
            continue;
        };
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        if !tracker.try_acquire() {
            drop(stream);
            continue;
        }
        let svc = Arc::clone(service);
        let trk = Arc::clone(tracker);
        let stop = Arc::clone(shutdown);
        if thread::Builder::new()
            .name("dns-tcp-client".to_owned())
            .spawn(move || {
                let _guard = TcpClientGuard { tracker: &trk };
                handle_tcp_client(stream, &svc, &stop);
            })
            .is_err()
        {
            tracker.release();
        }
    }
}

fn handle_tcp_client(mut stream: TcpStream, service: &DnsService, shutdown: &AtomicBool) {
    let _ = stream.set_nodelay(true);
    if stream.set_read_timeout(Some(SHUTDOWN_POLL)).is_err()
        || stream.set_write_timeout(Some(TCP_IO_TIMEOUT)).is_err()
    {
        return;
    }
    loop {
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        let mut len_buf = [0u8; 2];
        if !read_exact_interruptible(&mut stream, &mut len_buf, TCP_IO_TIMEOUT, shutdown) {
            break;
        }
        let msg_len = usize::from(u16::from_be_bytes(len_buf));
        if msg_len == 0 {
            break;
        }
        let mut query = vec![0u8; msg_len];
        if !read_exact_interruptible(&mut stream, &mut query, TCP_IO_TIMEOUT, shutdown) {
            break;
        }
        let response = service
            .exchange(&query)
            .unwrap_or_else(|_| wire::error_response(&query, wire::RCODE_SERVFAIL));
        let Ok(reply_len) = u16::try_from(response.len()) else {
            let fallback = wire::error_response(&query, wire::RCODE_SERVFAIL);
            let Ok(fb_len) = u16::try_from(fallback.len()) else {
                break;
            };
            if stream.write_all(&fb_len.to_be_bytes()).is_err()
                || stream.write_all(&fallback).is_err()
            {
                break;
            }
            continue;
        };
        if stream.write_all(&reply_len.to_be_bytes()).is_err()
            || stream.write_all(&response).is_err()
        {
            break;
        }
    }
}

/// Reads exactly `buf.len()` bytes while checking `shutdown` every
/// `SHUTDOWN_POLL` interval and enforcing an overall `timeout`.
fn read_exact_interruptible(
    stream: &mut TcpStream,
    buf: &mut [u8],
    timeout: Duration,
    shutdown: &AtomicBool,
) -> bool {
    let deadline = Instant::now() + timeout;
    let mut read = 0;
    while read < buf.len() {
        if shutdown.load(Ordering::Acquire) || Instant::now() >= deadline {
            return false;
        }
        match stream.read(&mut buf[read..]) {
            Ok(0) => return false,
            Ok(n) => read += n,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return false,
        }
    }
    true
}
