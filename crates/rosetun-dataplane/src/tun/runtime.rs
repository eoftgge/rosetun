use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Condvar, Mutex, PoisonError, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rosetun_config::ConnectionNetwork;
use rosetun_engine::{EngineRoute, TrafficProbe};

use super::packet::udp_reply_into;
use super::{
    DeviceSettings, FullConeNat, MappingKey, MixedTcp, Packet, PacketDevice, PacketError, TcpFlow,
    TcpRedirect, TcpStack, Transport,
};
use crate::conntable::{ConnectionMeta, ConnectionTable, Registration};
use crate::dns::DnsService;
use crate::net::{Dialer, Host, Target, UdpPath};
#[cfg(not(windows))]
use crate::proxy::relay::relay as native_relay;
#[cfg(windows)]
use crate::proxy::relay::relay_ready as native_relay;
use crate::proxy::{Outbounds, Verdict, server::Clients};
use crate::rules::{Flow, Route, RuleEngine};
#[cfg(not(windows))]
use crate::sniff::sniff_stream as native_sniff;
#[cfg(windows)]
use crate::sniff::sniff_stream_ready as native_sniff;
use crate::sniff::{SniffLimits, sniff_quic_datagram};

const PUMP_INTERVAL: Duration = Duration::from_millis(5);
const FLOW_TIMEOUT: Duration = Duration::from_secs(5);
const UDP_IDLE: Duration = Duration::from_secs(60);
const UDP_READ_TIMEOUT: Duration = Duration::from_millis(50);
const UDP_SWEEP_INTERVAL: Duration = Duration::from_millis(100);
const UDP_MAPPINGS: usize = 512;
const UDP_PEERS: usize = 32;
const UDP_QUEUE: usize = 512;
const UDP_FLOW_CACHE_LIMIT: usize = 4096;
const UDP_BUFFER_POOL: usize = 64;
const UDP_POOL_MAX_CAPACITY: usize = 2048;
const MAX_CLIENTS: usize = 512;
const DNS_WORKERS: usize = 4;
const DNS_QUEUE_CAPACITY: usize = 128;
const PACKET_BUDGET: usize = 64;

/// Determines the owner of the original, untranslated local connection.
pub trait ProcessLookup: Send + Sync {
    fn image(&self, flow: &TcpFlow, network: ConnectionNetwork) -> Option<String>;
}

impl<F> ProcessLookup for F
where
    F: Fn(&TcpFlow, ConnectionNetwork) -> Option<String> + Send + Sync,
{
    fn image(&self, flow: &TcpFlow, network: ConnectionNetwork) -> Option<String> {
        self(flow, network)
    }
}

struct Policy {
    generation: u64,
    rules: Arc<RuleEngine>,
    outbounds: Arc<Outbounds>,
}

/// Live rule table and outbound selection for original tunnel connections.
pub struct TunnelPolicy {
    policy: RwLock<Policy>,
    dns: Arc<DnsService>,
    process: Arc<dyn ProcessLookup>,
}

impl fmt::Debug for TunnelPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelPolicy").finish_non_exhaustive()
    }
}

impl TunnelPolicy {
    pub fn new(
        rules: RuleEngine,
        outbounds: Outbounds,
        dns: Arc<DnsService>,
        process: Arc<dyn ProcessLookup>,
    ) -> Self {
        Self {
            policy: RwLock::new(Policy {
                generation: 0,
                rules: Arc::new(rules),
                outbounds: Arc::new(outbounds),
            }),
            dns,
            process,
        }
    }

    /// Publishes rules and egresses together. The next UDP batch closes
    /// mappings from the previous policy, including their SOCKS associations.
    pub fn replace(&self, rules: RuleEngine, outbounds: Outbounds) {
        let mut policy = self.policy.write().unwrap_or_else(PoisonError::into_inner);
        *policy = Policy {
            generation: policy.generation.wrapping_add(1),
            rules: Arc::new(rules),
            outbounds: Arc::new(outbounds),
        };
    }

    pub fn replace_rules(&self, rules: RuleEngine) {
        let mut policy = self.policy.write().unwrap_or_else(PoisonError::into_inner);
        policy.generation = policy.generation.wrapping_add(1);
        policy.rules = Arc::new(rules);
    }

    pub fn replace_outbounds(&self, outbounds: Outbounds) {
        let mut policy = self.policy.write().unwrap_or_else(PoisonError::into_inner);
        policy.generation = policy.generation.wrapping_add(1);
        policy.outbounds = Arc::new(outbounds);
    }

    fn generation(&self) -> u64 {
        self.policy
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .generation
    }

    fn select(
        &self,
        flow: &TcpFlow,
        network: ConnectionNetwork,
        domain: Option<String>,
    ) -> Option<Selected> {
        let (rules, outbounds, generation) = {
            let policy = self.policy.read().unwrap_or_else(PoisonError::into_inner);
            (
                Arc::clone(&policy.rules),
                Arc::clone(&policy.outbounds),
                policy.generation,
            )
        };
        let ip = flow.destination.ip();
        let domain = domain.or_else(|| self.dns.domain_for(ip));
        let process = self.process.image(flow, network);
        let verdict = match rules
            .decide(
                &Flow {
                    domain: domain.as_deref(),
                    ip: Some(ip),
                    process: process.as_deref(),
                },
                self.dns.as_ref(),
            )
            .route
        {
            Route::Direct => Verdict::Direct,
            Route::Proxy => Verdict::Proxy,
            Route::Exit(exit) => Verdict::Exit(exit),
            Route::Block => return None,
        };
        let (dialer, route) = outbounds.select(&verdict)?;
        Some(Selected {
            generation,
            dialer,
            meta: ConnectionMeta {
                process,
                host: domain.unwrap_or_else(|| ip.to_string()),
                ip: Some(ip),
                port: flow.destination.port(),
                network,
                route,
            },
        })
    }
}

struct Selected {
    generation: u64,
    dialer: Arc<dyn Dialer>,
    meta: ConnectionMeta,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct UdpEgress {
    generation: u64,
    route: EngineRoute,
}

struct UdpMapping {
    path: Arc<UdpPath>,
    peers: Arc<Mutex<HashMap<SocketAddr, Registration>>>,
    received: Arc<AtomicBool>,
    closed: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
}

impl Drop for UdpMapping {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
    }
}

struct UdpReader {
    key: MappingKey<UdpEgress>,
    path: Arc<UdpPath>,
    peers: Arc<Mutex<HashMap<SocketAddr, Registration>>>,
    received: Arc<AtomicBool>,
    closed: Arc<AtomicBool>,
    device: Arc<dyn PacketDevice>,
    policy: Arc<TunnelPolicy>,
    table: ConnectionTable,
    stopped: Arc<AtomicBool>,
    mtu: usize,
}

struct Datagram {
    flow: TcpFlow,
    payload: Vec<u8>,
}

/// Non-blocking pool of reusable UDP payload buffers between the TUN reader
/// and the UDP sender worker so steady-state gaming/QUIC traffic avoids
/// per-packet heap allocations.
#[derive(Default)]
struct BufferPool(Mutex<Vec<Vec<u8>>>);

impl BufferPool {
    fn take(&self, payload: &[u8]) -> Vec<u8> {
        if let Ok(mut pool) = self.0.try_lock()
            && let Some(mut buffer) = pool.pop()
        {
            buffer.clear();
            buffer.extend_from_slice(payload);
            return buffer;
        }
        payload.to_vec()
    }

    fn put(&self, mut buffer: Vec<u8>) {
        if buffer.capacity() > UDP_POOL_MAX_CAPACITY {
            return;
        }
        if let Ok(mut pool) = self.0.try_lock()
            && pool.len() < UDP_BUFFER_POOL
        {
            buffer.clear();
            pool.push(buffer);
        }
    }
}

struct CachedUdpFlow {
    generation: u64,
    path: Arc<UdpPath>,
    counters: crate::conntable::Counters,
    closed: Arc<AtomicBool>,
    mapping_key: MappingKey<UdpEgress>,
    last_touch: Instant,
}

struct DnsQueue {
    queries: Mutex<VecDeque<Datagram>>,
    ready: Condvar,
    capacity: usize,
}

impl DnsQueue {
    fn new(capacity: usize) -> Self {
        Self {
            queries: Mutex::new(VecDeque::with_capacity(capacity)),
            ready: Condvar::new(),
            capacity,
        }
    }

    fn try_push(&self, query: Datagram) -> bool {
        let mut queries = self.queries.lock().unwrap_or_else(PoisonError::into_inner);
        if queries.len() >= self.capacity {
            return false;
        }
        queries.push_back(query);
        self.ready.notify_one();
        true
    }

    fn pop(&self, stopped: &AtomicBool) -> Option<Datagram> {
        let mut queries = self.queries.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if stopped.load(Ordering::Acquire) {
                return None;
            }
            if let Some(query) = queries.pop_front() {
                return Some(query);
            }
            queries = self
                .ready
                .wait(queries)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn shutdown(&self) {
        let mut queries = self.queries.lock().unwrap_or_else(PoisonError::into_inner);
        queries.clear();
        self.ready.notify_all();
    }
}

struct Pump {
    device: Arc<dyn PacketDevice>,
    policy: Arc<TunnelPolicy>,
    table: ConnectionTable,
    listeners: Vec<TcpListener>,
    local_ips: Vec<IpAddr>,
    tcp: MixedTcp,
    udp: SyncSender<Datagram>,
    udp_pool: Arc<BufferPool>,
    dns: Arc<DnsQueue>,
    clients: Arc<Clients>,
    stopped: Arc<AtomicBool>,
    mtu: usize,
    counters: PumpCounters,
}

struct UdpPump {
    device: Arc<dyn PacketDevice>,
    policy: Arc<TunnelPolicy>,
    table: ConnectionTable,
    udp: FullConeNat<UdpEgress, UdpMapping>,
    flow_cache: HashMap<TcpFlow, CachedUdpFlow>,
    pool: Arc<BufferPool>,
    stopped: Arc<AtomicBool>,
    last_generation: u64,
    last_sweep: Instant,
    mtu: usize,
}

#[derive(Default)]
struct PumpCounters {
    frames: u64,
    bad_checksum: u64,
    tcp: u64,
    written: u64,
    write_errors: u64,
    accepted: u64,
}

impl Drop for Pump {
    fn drop(&mut self) {
        let totals = self.table.totals();
        tracing::debug!(
            frames = self.counters.frames,
            bad_checksum = self.counters.bad_checksum,
            tcp = self.counters.tcp,
            written = self.counters.written,
            write_errors = self.counters.write_errors,
            accepted = self.counters.accepted,
            relay_up = totals.up,
            relay_down = totals.down,
            "native packet pump counters"
        );
    }
}

/// Mixed TCP and UDP packet pump. Its owner retains the adapter, routes and
/// platform firewall and stops this pump before reverting them.
pub struct TunnelRuntime {
    device: Arc<dyn PacketDevice>,
    table: ConnectionTable,
    stopped: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<()>>>,
    dns_queue: Arc<DnsQueue>,
    dns_threads: Vec<JoinHandle<()>>,
    udp_thread: Option<JoinHandle<()>>,
    clients: Arc<Clients>,
    redirects: Vec<TcpRedirect>,
}

impl fmt::Debug for TunnelRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelRuntime")
            .field("running", &self.running())
            .finish_non_exhaustive()
    }
}

impl TunnelRuntime {
    pub fn start(
        device: Arc<dyn PacketDevice>,
        settings: &DeviceSettings,
        policy: Arc<TunnelPolicy>,
    ) -> io::Result<Self> {
        let mut listeners = Vec::new();
        let mut redirects = Vec::new();
        for address in [Some(settings.ipv4), settings.ipv6].into_iter().flatten() {
            let listener = TcpListener::bind(SocketAddr::new(address.local, 0))?;
            listener.set_nonblocking(true)?;
            redirects.push(TcpRedirect {
                listener: listener.local_addr()?,
                peer: address.peer,
            });
            listeners.push(listener);
        }
        let tcp = MixedTcp::new(redirects.iter().copied()).map_err(io::Error::other)?;
        let mut runtime = Self {
            device,
            table: ConnectionTable::new(),
            stopped: Arc::new(AtomicBool::new(false)),
            thread: None,
            dns_queue: Arc::new(DnsQueue::new(DNS_QUEUE_CAPACITY)),
            dns_threads: Vec::new(),
            udp_thread: None,
            clients: Arc::new(Clients::default()),
            redirects,
        };
        let mtu = usize::from(settings.mtu);
        runtime.start_dns_workers(&policy.dns, mtu)?;
        let udp_pool = Arc::new(BufferPool::default());
        let udp = runtime.start_udp_worker(&policy, Arc::clone(&udp_pool), mtu)?;
        let mut pump = Pump {
            device: Arc::clone(&runtime.device),
            policy,
            table: runtime.table.clone(),
            listeners,
            local_ips: [
                Some(settings.ipv4.local),
                settings.ipv6.map(|address| address.local),
            ]
            .into_iter()
            .flatten()
            .collect(),
            tcp,
            udp,
            udp_pool,
            dns: Arc::clone(&runtime.dns_queue),
            clients: Arc::clone(&runtime.clients),
            stopped: Arc::clone(&runtime.stopped),
            mtu,
            counters: PumpCounters::default(),
        };
        runtime.thread = Some(
            thread::Builder::new()
                .name("rosetun-tun".into())
                .spawn(move || pump.run())?,
        );
        Ok(runtime)
    }

    fn start_udp_worker(
        &mut self,
        policy: &Arc<TunnelPolicy>,
        pool: Arc<BufferPool>,
        mtu: usize,
    ) -> io::Result<SyncSender<Datagram>> {
        let (sender, receiver) = mpsc::sync_channel(UDP_QUEUE);
        let stopped = Arc::clone(&self.stopped);
        let generation = policy.generation();
        let mut pump = UdpPump {
            device: Arc::clone(&self.device),
            policy: Arc::clone(policy),
            table: self.table.clone(),
            udp: FullConeNat::new(UDP_MAPPINGS, UDP_IDLE),
            flow_cache: HashMap::new(),
            pool,
            stopped,
            last_generation: generation,
            last_sweep: Instant::now(),
            mtu,
        };
        self.udp_thread = Some(
            thread::Builder::new()
                .name("rosetun-tun-udp".into())
                .spawn(move || pump.run(&receiver))?,
        );
        Ok(sender)
    }

    fn start_dns_workers(&mut self, dns: &Arc<DnsService>, mtu: usize) -> io::Result<()> {
        for _ in 0..DNS_WORKERS {
            let queue = Arc::clone(&self.dns_queue);
            let device = Arc::clone(&self.device);
            let dns = Arc::clone(dns);
            let stopped = Arc::clone(&self.stopped);
            self.dns_threads.push(
                thread::Builder::new()
                    .name("rosetun-tun-dns".into())
                    .spawn(move || {
                        let mut reply_packet = Vec::with_capacity(mtu);
                        while let Some(query) = queue.pop(&stopped) {
                            if let Ok(reply) = dns.exchange(&query.payload) {
                                let header_overhead =
                                    if query.flow.source.is_ipv4() { 28 } else { 48 };
                                let max_payload = mtu.saturating_sub(header_overhead);
                                let reply = crate::dns::truncate_udp_reply(
                                    &query.payload,
                                    reply,
                                    max_payload,
                                );
                                write_reply_into(
                                    device.as_ref(),
                                    query.flow.destination,
                                    query.flow.source,
                                    &reply,
                                    mtu,
                                    &mut reply_packet,
                                );
                            }
                        }
                    })?,
            );
        }
        Ok(())
    }

    pub fn running(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
            && self
                .udp_thread
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
    }

    pub fn redirects(&self) -> &[TcpRedirect] {
        &self.redirects
    }

    pub fn traffic_probe(&self) -> Box<dyn TrafficProbe> {
        Box::new(self.table.probe())
    }

    pub fn close_connection(&self, id: &str) -> bool {
        self.table.close_connection(id)
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        self.stopped.store(true, Ordering::Release);
        self.dns_queue.shutdown();
        let interrupted = self.device.interrupt();
        self.table.shutdown();
        let result = self.thread.take().map_or(Ok(()), |worker| {
            worker
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("tunnel packet worker panicked")))
        });
        if let Some(worker) = self.udp_thread.take() {
            let _ = worker.join();
        }
        self.clients.close_and_wait();
        for worker in self.dns_threads.drain(..) {
            let _ = worker.join();
        }
        result.and(interrupted)
    }
}

impl Drop for TunnelRuntime {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

impl Pump {
    fn run(&mut self) -> io::Result<()> {
        let mut frame = vec![0; self.mtu + 1];
        let (closed_tx, closed_rx) = mpsc::channel();
        while !self.stopped.load(Ordering::Acquire) {
            let now = Instant::now();
            for peer in closed_rx.try_iter() {
                self.tcp.close(peer, now);
            }
            self.accept(&closed_tx);
            for index in 0..PACKET_BUDGET {
                let wait = if index == 0 {
                    PUMP_INTERVAL
                } else {
                    Duration::ZERO
                };
                match self.device.receive(&mut frame, wait) {
                    Ok(size) => {
                        self.counters.frames += 1;
                        if size <= self.mtu
                            && let Some(contents) = frame.get_mut(..size)
                        {
                            self.dispatch(contents, now);
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::Interrupted
                        ) =>
                    {
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    fn accept(&mut self, closed: &mpsc::Sender<SocketAddr>) {
        for listener in &self.listeners {
            for _ in 0..PACKET_BUDGET {
                let Ok((stream, peer)) = listener.accept() else {
                    break;
                };
                let Some(flow) = self.tcp.accept(peer) else {
                    continue;
                };
                self.counters.accepted += 1;
                let Some(client) = self.clients.track(&stream, MAX_CLIENTS) else {
                    self.tcp.close(peer, Instant::now());
                    continue;
                };
                let policy = Arc::clone(&self.policy);
                let table = self.table.clone();
                let stopped = Arc::clone(&self.stopped);
                let closed = closed.clone();
                if thread::Builder::new()
                    .name("rosetun-tun-tcp".into())
                    .spawn(move || {
                        let _client = client;
                        if let Err(error) = tunnel_tcp(stream, flow, &policy, &table, &stopped) {
                            tracing::debug!(kind = ?error.kind(), "native TCP worker ended with an error");
                        }
                        let _ = closed.send(peer);
                    })
                    .is_err()
                {
                    self.tcp.close(peer, Instant::now());
                }
            }
        }
    }

    fn dispatch(&mut self, frame: &mut [u8], now: Instant) {
        let parsed = match Packet::parse(frame) {
            Ok(packet) => packet,
            Err(PacketError::Checksum) => {
                self.counters.bad_checksum += 1;
                return;
            }
            Err(_) => return,
        };
        if parsed.transport() == Transport::Tcp {
            self.counters.tcp += 1;
            let offset = parsed.header_offset();
            let length = parsed.len();
            let flow = TcpFlow {
                source: parsed.source(),
                destination: parsed.destination(),
            };
            let starts_connection = parsed.tcp_starts_connection();
            if let Ok(true) = self.tcp.redirect_in_place(
                &mut frame[..length],
                offset,
                flow,
                starts_connection,
                now,
            ) {
                if self.device.send(&frame[..length]).is_ok() {
                    self.counters.written += 1;
                } else {
                    self.counters.write_errors += 1;
                }
            }
            return;
        }
        if !self.local_ips.contains(&parsed.source().ip()) {
            return;
        }
        let Some(payload) = parsed.udp_payload() else {
            return;
        };
        let flow = TcpFlow {
            source: parsed.source(),
            destination: parsed.destination(),
        };
        if flow.destination.port() == 53 {
            let _ = self.dns.try_push(Datagram {
                flow,
                payload: payload.to_vec(),
            });
            return;
        }
        // Opening a SOCKS association, looking up processes, and resolving
        // rule addresses can block. The device reader only queues a datagram.
        let buffered = self.udp_pool.take(payload);
        if let Err(mpsc::TrySendError::Full(dropped) | mpsc::TrySendError::Disconnected(dropped)) =
            self.udp.try_send(Datagram {
                flow,
                payload: buffered,
            })
        {
            self.udp_pool.put(dropped.payload);
        }
    }
}

impl UdpPump {
    fn run(&mut self, receiver: &Receiver<Datagram>) {
        while !self.stopped.load(Ordering::Acquire) {
            match receiver.recv_timeout(UDP_SWEEP_INTERVAL) {
                Ok(datagram) if !self.stopped.load(Ordering::Acquire) => {
                    let now = Instant::now();
                    self.sweep(now);
                    self.send(&datagram, now);
                    self.pool.put(datagram.payload);
                    for _ in 1..PACKET_BUDGET {
                        match receiver.try_recv() {
                            Ok(datagram) if !self.stopped.load(Ordering::Acquire) => {
                                self.send(&datagram, Instant::now());
                                self.pool.put(datagram.payload);
                            }
                            Ok(datagram) => {
                                self.pool.put(datagram.payload);
                                self.shutdown_readers();
                                return;
                            }
                            Err(mpsc::TryRecvError::Disconnected) => {
                                self.shutdown_readers();
                                return;
                            }
                            Err(mpsc::TryRecvError::Empty) => break,
                        }
                    }
                }
                Ok(datagram) => {
                    self.pool.put(datagram.payload);
                    break;
                }
                Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {
                    self.sweep(Instant::now());
                }
            }
        }
        self.shutdown_readers();
    }

    fn sweep(&mut self, now: Instant) {
        let generation = self.policy.generation();
        if generation != self.last_generation {
            self.last_generation = generation;
            self.flow_cache.clear();
            self.udp
                .retain(|key, _| key.egress.generation == generation);
        }
        if now.saturating_duration_since(self.last_sweep) >= Duration::from_secs(1) {
            self.last_sweep = now;
            self.udp.receive(now, |_, mapping| {
                mapping.received.swap(false, Ordering::AcqRel)
            });
            self.flow_cache.retain(|_, cached| {
                cached.generation == generation
                    && !cached.closed.load(Ordering::Acquire)
                    && !cached.counters.is_closed()
            });
        }
    }

    fn shutdown_readers(&mut self) {
        self.flow_cache.clear();
        let mut handles = Vec::new();
        for mut mapping in self.udp.drain() {
            mapping.closed.store(true, Ordering::Release);
            if let Some(handle) = mapping.reader.take() {
                handles.push(handle);
            }
        }
        for handle in handles {
            let _ = handle.join();
        }
    }

    fn send(&mut self, datagram: &Datagram, now: Instant) {
        let flow = datagram.flow;
        let payload = &datagram.payload;
        let remote = target(flow.destination);
        let generation = self.policy.generation();
        if let Some(cached) = self.flow_cache.get_mut(&flow) {
            let valid = cached.generation == generation
                && !cached.closed.load(Ordering::Acquire)
                && !cached.counters.is_closed()
                && (now.saturating_duration_since(cached.last_touch) < Duration::from_secs(1) || {
                    cached.last_touch = now;
                    self.udp.touch(&cached.mapping_key, now)
                });
            if valid {
                if cached.path.send_to(payload, &remote).is_ok() {
                    cached.counters.add_up(payload.len() as u64);
                }
                return;
            }
            self.flow_cache.remove(&flow);
        }
        let domain = sniff_quic_datagram(payload).and_then(|sniffed| sniffed.domain);
        let Some(selected) = self.policy.select(&flow, ConnectionNetwork::Udp, domain) else {
            return;
        };
        let key = MappingKey {
            source: flow.source,
            egress: UdpEgress {
                generation: selected.generation,
                route: selected.meta.route.clone(),
            },
        };
        let cache_key = key.clone();
        let reader_key = key.clone();
        let device = Arc::clone(&self.device);
        let policy = Arc::clone(&self.policy);
        let table = self.table.clone();
        let stopped = Arc::clone(&self.stopped);
        let mtu = self.mtu;
        let Ok(mapping) = self.udp.path(key, now, || -> io::Result<UdpMapping> {
            let path = selected.dialer.udp_for(&remote, FLOW_TIMEOUT)?;
            path.set_nonblocking(false)?;
            path.set_read_timeout(Some(UDP_READ_TIMEOUT))?;
            let path = Arc::new(path);
            let peers = Arc::new(Mutex::new(HashMap::new()));
            let received = Arc::new(AtomicBool::new(false));
            let closed = Arc::new(AtomicBool::new(false));
            let reader_context = UdpReader {
                key: reader_key,
                path: Arc::clone(&path),
                peers: Arc::clone(&peers),
                received: Arc::clone(&received),
                closed: Arc::clone(&closed),
                device,
                policy,
                table,
                stopped,
                mtu,
            };
            let reader = thread::Builder::new()
                .name("rosetun-tun-udp-in".into())
                .spawn(move || run_udp_reader(reader_context))?;
            Ok(UdpMapping {
                path,
                peers,
                received,
                closed,
                reader: Some(reader),
            })
        }) else {
            return;
        };
        let registration = {
            let mut peers = mapping.peers.lock().unwrap_or_else(PoisonError::into_inner);
            if peers
                .get(&flow.destination)
                .is_some_and(Registration::is_closed)
            {
                peers.remove(&flow.destination);
            }
            udp_registration(&mut peers, flow.destination, &self.table, selected.meta)
        };
        let Some(registration) = registration else {
            return;
        };
        let path = Arc::clone(&mapping.path);
        let closed = Arc::clone(&mapping.closed);
        if path.send_to(payload, &remote).is_ok() {
            registration.add_up(payload.len() as u64);
        }
        if self.flow_cache.len() >= UDP_FLOW_CACHE_LIMIT {
            self.flow_cache.retain(|_, cached| {
                cached.generation == selected.generation
                    && !cached.closed.load(Ordering::Acquire)
                    && !cached.counters.is_closed()
            });
        }
        if self.flow_cache.len() < UDP_FLOW_CACHE_LIMIT {
            self.flow_cache.insert(
                flow,
                CachedUdpFlow {
                    generation: selected.generation,
                    path,
                    counters: registration,
                    closed,
                    mapping_key: cache_key,
                    last_touch: now,
                },
            );
        }
    }
}

fn run_udp_reader(reader: UdpReader) {
    let mut response = vec![0; reader.mtu + 1];
    let mut scratch = Vec::new();
    let mut reply_packet = Vec::with_capacity(reader.mtu);
    while !reader.stopped.load(Ordering::Acquire) && !reader.closed.load(Ordering::Acquire) {
        let (length, remote) = match reader.path.recv_from_into(&mut response, &mut scratch) {
            Ok((length, Some(remote))) => (length, remote),
            Ok((_, None)) => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionReset
                ) || error.raw_os_error() == Some(10040) =>
            {
                continue;
            }
            Err(_) => break,
        };
        if length > reader.mtu
            || remote.port() == 53
            || remote.is_ipv4() != reader.key.source.is_ipv4()
        {
            continue;
        }
        let registration = {
            let mut peers = reader.peers.lock().unwrap_or_else(PoisonError::into_inner);
            match peers.get(&remote) {
                Some(registration) if registration.is_closed() => {
                    peers.remove(&remote);
                    continue;
                }
                Some(registration) => Some(registration.counters()),
                None => None,
            }
        };
        let registration = match registration {
            Some(counters) => counters,
            None => {
                let flow = TcpFlow {
                    source: reader.key.source,
                    destination: remote,
                };
                let Some(selected) = reader.policy.select(&flow, ConnectionNetwork::Udp, None)
                else {
                    continue;
                };
                if selected.generation != reader.key.egress.generation
                    || selected.meta.route != reader.key.egress.route
                {
                    continue;
                }
                let mut peers = reader.peers.lock().unwrap_or_else(PoisonError::into_inner);
                let Some(counters) =
                    udp_registration(&mut peers, remote, &reader.table, selected.meta)
                else {
                    continue;
                };
                counters
            }
        };
        if write_reply_into(
            reader.device.as_ref(),
            remote,
            reader.key.source,
            &response[..length],
            reader.mtu,
            &mut reply_packet,
        ) {
            registration.add_down(length as u64);
            reader.received.store(true, Ordering::Release);
        }
    }
}

fn udp_registration(
    peers: &mut HashMap<SocketAddr, Registration>,
    peer: SocketAddr,
    table: &ConnectionTable,
    meta: ConnectionMeta,
) -> Option<crate::conntable::Counters> {
    let at_capacity = peers.len() >= UDP_PEERS;
    let registration = match peers.entry(peer) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) if !at_capacity => entry.insert(table.register(meta).ok()?),
        Entry::Vacant(_) => return None,
    };
    Some(registration.counters())
}

fn tunnel_tcp(
    mut stream: TcpStream,
    flow: TcpFlow,
    policy: &TunnelPolicy,
    table: &ConnectionTable,
    stopped: &AtomicBool,
) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true).ok();
    stream.set_read_timeout(Some(FLOW_TIMEOUT))?;
    stream.set_write_timeout(Some(FLOW_TIMEOUT))?;
    if flow.destination.port() == 53 {
        return tcp_dns(&mut stream, policy.dns.as_ref(), stopped);
    }
    let sniffed = native_sniff(&mut stream, &SniffLimits::default())?;
    let domain = sniffed.sniffed.and_then(|sniffed| sniffed.domain);
    let Some(selected) = policy.select(&flow, ConnectionNetwork::Tcp, domain) else {
        return Ok(());
    };
    let Ok(registration) = table.register(selected.meta) else {
        return Ok(());
    };
    registration.attach(&stream);
    let upstream = selected
        .dialer
        .connect(&target(flow.destination), FLOW_TIMEOUT)?;
    native_relay(&stream, &upstream, &registration, &sniffed.buffered);
    Ok(())
}

fn tcp_dns(client: &mut TcpStream, dns: &DnsService, stopped: &AtomicBool) -> io::Result<()> {
    while !stopped.load(Ordering::Acquire) {
        let mut size = [0; 2];
        client.read_exact(&mut size)?;
        let mut request = vec![0; usize::from(u16::from_be_bytes(size))];
        client.read_exact(&mut request)?;
        let reply = dns.exchange(&request).map_err(io::Error::other)?;
        let length = u16::try_from(reply.len()).map_err(io::Error::other)?;
        client.write_all(&length.to_be_bytes())?;
        client.write_all(&reply)?;
    }
    Ok(())
}

fn target(address: SocketAddr) -> Target {
    Target {
        host: Host::Ip(address.ip()),
        port: address.port(),
    }
}

fn write_reply_into(
    device: &dyn PacketDevice,
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
    mtu: usize,
    out: &mut Vec<u8>,
) -> bool {
    udp_reply_into(source, destination, payload, mtu, out).is_ok() && device.send(out).is_ok()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, UdpSocket};
    use std::sync::Mutex;

    use rosetun_config::{
        DnsSettings, ProcessMatch, Rule, RuleId, RuleMatcher, RuleSet, RuleSetId, RuleTarget,
    };
    use rustls::pki_types::CertificateDer;

    use super::*;
    use crate::dns::{DnsOptions, testcerts};
    use crate::net::DirectDialer;
    use crate::rules::RulePlan;
    use crate::tun::udp_reply;

    #[derive(Default)]
    struct MockTun(Mutex<Vec<Vec<u8>>>);

    impl PacketDevice for MockTun {
        fn receive(&self, _: &mut [u8], _: Duration) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }

        fn send(&self, packet: &[u8]) -> io::Result<()> {
            self.0.lock().unwrap().push(packet.to_vec());
            Ok(())
        }

        fn interrupt(&self) -> io::Result<()> {
            Ok(())
        }
    }

    fn outbounds() -> Outbounds {
        Outbounds {
            direct: Arc::new(DirectDialer::default()),
            proxy: None,
            exits: HashMap::new(),
        }
    }

    fn policy(with_process: bool) -> Arc<TunnelPolicy> {
        let mut rules = RuleSet::new(RuleSetId::new("test"), "Test", RuleTarget::Block);
        if with_process {
            rules.rules.push(Rule {
                id: RuleId::new("permit"),
                enabled: true,
                matcher: RuleMatcher::Process(ProcessMatch::Name("example.exe".into())),
                target: RuleTarget::Direct,
                exit: None,
            });
        }
        let rules = RuleEngine::compile(&RulePlan {
            rules,
            temporary_count: 0,
            allow_lan: false,
            lan_segment: Vec::new(),
            lan_servers: Vec::new(),
            private_networks: false,
            exits: Vec::new(),
            lists: Vec::new(),
        })
        .unwrap();
        let root = testcerts::CA_CERT_HEX.join("");
        let bytes: Vec<_> = (0..root.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&root[i..i + 2], 16).unwrap())
            .collect();
        let dns = DnsService::with_roots(
            &DnsSettings {
                server: "192.0.2.53".parse().unwrap(),
                server_name: "doh.example.com".into(),
                port: None,
                path: None,
            },
            Arc::new(DirectDialer::default()),
            DnsOptions::default(),
            vec![CertificateDer::from(bytes)],
        )
        .unwrap();
        Arc::new(TunnelPolicy::new(
            rules,
            outbounds(),
            Arc::new(dns),
            Arc::new(|_: &TcpFlow, _: ConnectionNetwork| Some("example.exe".into())),
        ))
    }

    #[test]
    fn a_tunnel_udp_packet_uses_process_policy_and_replies_through_the_virtual_device() {
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        upstream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let target = upstream.local_addr().unwrap();
        let client: SocketAddr = "192.0.2.1:49151".parse().unwrap();
        let tun = Arc::new(MockTun::default());
        let stopped = Arc::new(AtomicBool::new(false));
        let test_policy = policy(true);
        let generation = test_policy.generation();
        let mut pump = UdpPump {
            device: tun.clone(),
            policy: test_policy,
            table: ConnectionTable::new(),
            udp: FullConeNat::new(8, UDP_IDLE),
            flow_cache: HashMap::new(),
            pool: Arc::new(BufferPool::default()),
            stopped: Arc::clone(&stopped),
            last_generation: generation,
            last_sweep: Instant::now(),
            mtu: 1500,
        };
        let datagram = Datagram {
            flow: TcpFlow {
                source: client,
                destination: target,
            },
            payload: b"data".to_vec(),
        };
        pump.send(&datagram, Instant::now());
        let mut buffer = [0; 16];
        let (length, mapped_peer) = upstream.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..length], b"data");
        upstream.send_to(b"reply", mapped_peer).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while tun.0.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        let frames = tun.0.lock().unwrap();
        let response = Packet::parse(&frames[0]).unwrap();
        assert_eq!(response.source(), target);
        assert_eq!(response.destination(), client);
        assert_eq!(response.udp_payload(), Some(&b"reply"[..]));
        let entries = pump.table.active();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].process.as_deref(), Some("example.exe"));
        stopped.store(true, Ordering::Release);
        pump.shutdown_readers();
    }

    #[test]
    fn repeated_udp_datagrams_reuse_cached_policy_until_policy_changes() {
        use std::sync::atomic::AtomicUsize;

        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        upstream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let target = upstream.local_addr().unwrap();
        let client: SocketAddr = "192.0.2.1:49152".parse().unwrap();
        let lookups = Arc::new(AtomicUsize::new(0));
        let lookups_for_policy = Arc::clone(&lookups);
        let rules = RuleEngine::compile(&RulePlan {
            rules: RuleSet::new(RuleSetId::new("test"), "Test", RuleTarget::Direct),
            temporary_count: 0,
            allow_lan: false,
            lan_segment: Vec::new(),
            lan_servers: Vec::new(),
            private_networks: false,
            exits: Vec::new(),
            lists: Vec::new(),
        })
        .unwrap();
        let base_policy = policy(false);
        let test_policy = Arc::new(TunnelPolicy::new(
            rules,
            outbounds(),
            Arc::clone(&base_policy.dns),
            Arc::new(move |_: &TcpFlow, _: ConnectionNetwork| {
                lookups_for_policy.fetch_add(1, Ordering::Relaxed);
                Some("game.exe".into())
            }),
        ));
        let stopped = Arc::new(AtomicBool::new(false));
        let mut pump = UdpPump {
            device: Arc::new(MockTun::default()),
            policy: Arc::clone(&test_policy),
            table: ConnectionTable::new(),
            udp: FullConeNat::new(8, UDP_IDLE),
            flow_cache: HashMap::new(),
            pool: Arc::new(BufferPool::default()),
            stopped: Arc::clone(&stopped),
            last_generation: test_policy.generation(),
            last_sweep: Instant::now(),
            mtu: 1500,
        };
        let datagram = Datagram {
            flow: TcpFlow {
                source: client,
                destination: target,
            },
            payload: b"tick".to_vec(),
        };
        let now = Instant::now();
        for _ in 0..5 {
            pump.send(&datagram, now);
        }
        assert_eq!(
            lookups.load(Ordering::Relaxed),
            1,
            "policy lookup should run once per cached UDP flow"
        );
        let new_rules = RuleEngine::compile(&RulePlan {
            rules: RuleSet::new(RuleSetId::new("test"), "Test", RuleTarget::Direct),
            temporary_count: 0,
            allow_lan: false,
            lan_segment: Vec::new(),
            lan_servers: Vec::new(),
            private_networks: false,
            exits: Vec::new(),
            lists: Vec::new(),
        })
        .unwrap();
        test_policy.replace_rules(new_rules);
        pump.send(&datagram, now);
        assert_eq!(
            lookups.load(Ordering::Relaxed),
            2,
            "policy generation bump must invalidate cached UDP flow"
        );
        stopped.store(true, Ordering::Release);
        pump.shutdown_readers();
    }

    #[test]
    fn a_slow_udp_association_does_not_hold_up_the_tcp_device_reader() {
        #[derive(Debug)]
        struct SlowUdp {
            entered: SyncSender<()>,
            release: Mutex<Receiver<()>>,
        }

        impl Dialer for SlowUdp {
            fn connect(&self, _: &Target, _: Duration) -> io::Result<TcpStream> {
                Err(io::ErrorKind::Unsupported.into())
            }

            fn udp(&self, timeout: Duration) -> io::Result<UdpPath> {
                let _ = self.entered.send(());
                let _ = self.release.lock().unwrap().recv_timeout(timeout);
                Err(io::ErrorKind::TimedOut.into())
            }
        }

        let (entered, opening) = mpsc::sync_channel(1);
        let (release, blocked) = mpsc::sync_channel(1);
        let policy = policy(true);
        policy.policy.write().unwrap().outbounds = Arc::new(Outbounds {
            direct: Arc::new(SlowUdp {
                entered,
                release: Mutex::new(blocked),
            }),
            ..outbounds()
        });
        let client: SocketAddr = "192.0.2.1:55100".parse().unwrap();
        let destination: SocketAddr = "198.51.100.2:443".parse().unwrap();
        let device = Arc::new(MockTun::default());
        let stopped = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::sync_channel(UDP_QUEUE);
        let table = ConnectionTable::new();
        let generation = policy.generation();
        let udp_pool = Arc::new(BufferPool::default());
        let mut udp = UdpPump {
            device: device.clone(),
            policy: Arc::clone(&policy),
            table: table.clone(),
            udp: FullConeNat::new(8, UDP_IDLE),
            flow_cache: HashMap::new(),
            pool: Arc::clone(&udp_pool),
            stopped: Arc::clone(&stopped),
            last_generation: generation,
            last_sweep: Instant::now(),
            mtu: 1500,
        };
        let mut pump = Pump {
            device: device.clone(),
            policy,
            table,
            listeners: Vec::new(),
            local_ips: vec![client.ip()],
            tcp: MixedTcp::new([TcpRedirect {
                listener: "192.0.2.1:45000".parse().unwrap(),
                peer: "192.0.2.2".parse().unwrap(),
            }])
            .unwrap(),
            udp: sender,
            udp_pool,
            dns: Arc::new(DnsQueue::new(DNS_QUEUE_CAPACITY)),
            clients: Arc::new(Clients::default()),
            stopped: Arc::clone(&stopped),
            mtu: 1500,
            counters: PumpCounters::default(),
        };
        let worker = thread::spawn(move || udp.run(&receiver));
        let mut datagram = udp_reply(client, destination, b"first datagram", 1500).unwrap();
        pump.dispatch(&mut datagram, Instant::now());
        opening.recv_timeout(Duration::from_secs(2)).unwrap();
        let mut syn = crate::tun::packet::tcp_test_packet(client, destination, 0x02);
        pump.dispatch(&mut syn, Instant::now());
        let written = device.0.lock().unwrap().len();
        stopped.store(true, Ordering::Release);
        release.send(()).unwrap();
        worker.join().unwrap();
        assert_eq!(written, 1, "the SYN was redirected before UDP was released");
    }

    #[test]
    fn tunnel_tcp_dns_answers_through_the_builtin_resolver_under_a_block_policy() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (stream, _) = listener.accept().unwrap();
        let flow = TcpFlow {
            source: "192.0.2.1:5000".parse().unwrap(),
            destination: "198.51.100.53:53".parse().unwrap(),
        };
        let worker = thread::spawn(move || {
            tunnel_tcp(
                stream,
                flow,
                &policy(false),
                &ConnectionTable::new(),
                &AtomicBool::new(false),
            )
        });
        let query = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03doh\x07example\x03com\x00\x00\x01\x00\x01";
        client
            .write_all(&(query.len() as u16).to_be_bytes())
            .unwrap();
        client.write_all(query).unwrap();
        let mut size = [0; 2];
        client.read_exact(&mut size).unwrap();
        let mut reply = vec![0; usize::from(u16::from_be_bytes(size))];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply[..2], &[0, 1]);
        assert_eq!(&reply[6..8], &[0, 1]);
        assert!(reply.ends_with(&[192, 0, 2, 53]));
        drop(client);
        assert_eq!(
            worker.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
