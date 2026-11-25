use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, PoisonError, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rosetun_config::ConnectionNetwork;
use rosetun_engine::{EngineRoute, TrafficProbe};

use super::{
    DeviceSettings, FullConeNat, MappingKey, MixedTcp, Packet, PacketDevice, PacketError, TcpFlow,
    TcpRedirect, TcpStack, Transport, udp_reply,
};
use crate::conntable::{ConnectionMeta, ConnectionTable, Registration};
use crate::dns::DnsService;
use crate::net::{Dialer, Host, Target, UdpPath};
use crate::proxy::{Outbounds, Verdict, relay::relay, server::Clients};
use crate::rules::{Flow, Route, RuleEngine};
use crate::sniff::{SniffLimits, sniff_quic_datagram, sniff_stream};

const PUMP_INTERVAL: Duration = Duration::from_millis(5);
const FLOW_TIMEOUT: Duration = Duration::from_secs(5);
const UDP_IDLE: Duration = Duration::from_secs(60);
const UDP_MAPPINGS: usize = 512;
const UDP_PEERS: usize = 32;
const UDP_QUEUE: usize = 64;
const MAX_CLIENTS: usize = 512;
const DNS_WORKERS: usize = 4;
const DNS_QUEUE: usize = 32;
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
    path: UdpPath,
    peers: HashMap<SocketAddr, Registration>,
}

struct Datagram {
    flow: TcpFlow,
    payload: Vec<u8>,
}

struct Pump {
    device: Arc<dyn PacketDevice>,
    policy: Arc<TunnelPolicy>,
    table: ConnectionTable,
    listeners: Vec<TcpListener>,
    local_ips: Vec<IpAddr>,
    tcp: MixedTcp,
    udp: SyncSender<Datagram>,
    dns: Vec<SyncSender<Datagram>>,
    dns_worker: usize,
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
    response: Vec<u8>,
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
            dns_threads: Vec::new(),
            udp_thread: None,
            clients: Arc::new(Clients::default()),
            redirects,
        };
        let mtu = usize::from(settings.mtu);
        let dns = runtime.start_dns_workers(&policy.dns, mtu)?;
        let udp = runtime.start_udp_worker(&policy, mtu)?;
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
            dns,
            dns_worker: 0,
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
        mtu: usize,
    ) -> io::Result<SyncSender<Datagram>> {
        let (sender, receiver) = mpsc::sync_channel(UDP_QUEUE);
        let stopped = Arc::clone(&self.stopped);
        let mut pump = UdpPump {
            device: Arc::clone(&self.device),
            policy: Arc::clone(policy),
            table: self.table.clone(),
            udp: FullConeNat::new(UDP_MAPPINGS, UDP_IDLE),
            response: vec![0; usize::from(u16::MAX)],
            mtu,
        };
        self.udp_thread = Some(
            thread::Builder::new()
                .name("rosetun-tun-udp".into())
                .spawn(move || pump.run(&receiver, &stopped))?,
        );
        Ok(sender)
    }

    fn start_dns_workers(
        &mut self,
        dns: &Arc<DnsService>,
        mtu: usize,
    ) -> io::Result<Vec<SyncSender<Datagram>>> {
        let mut senders = Vec::new();
        for _ in 0..DNS_WORKERS {
            let (tx, rx) = mpsc::sync_channel::<Datagram>(DNS_QUEUE);
            let device = Arc::clone(&self.device);
            let dns = Arc::clone(dns);
            let stopped = Arc::clone(&self.stopped);
            self.dns_threads.push(
                thread::Builder::new()
                    .name("rosetun-tun-dns".into())
                    .spawn(move || {
                        while let Ok(query) = rx.recv() {
                            if stopped.load(Ordering::Acquire) {
                                break;
                            }
                            if let Ok(reply) = dns.exchange(&query.payload) {
                                write_reply(
                                    device.as_ref(),
                                    query.flow.destination,
                                    query.flow.source,
                                    &reply,
                                    mtu,
                                );
                            }
                        }
                    })?,
            );
            senders.push(tx);
        }
        Ok(senders)
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
                        if let Some(contents) = frame.get(..size)
                            && size <= self.mtu
                        {
                            match Packet::parse(contents) {
                                Ok(packet) => self.dispatch(&packet, now),
                                Err(PacketError::Checksum) => self.counters.bad_checksum += 1,
                                Err(_) => {}
                            }
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

    fn dispatch(&mut self, packet: &Packet<'_>, now: Instant) {
        if packet.transport() == Transport::Tcp {
            self.counters.tcp += 1;
            if let Ok(Some(redirected)) = self.tcp.redirect(packet, now) {
                if self.device.send(&redirected).is_ok() {
                    self.counters.written += 1;
                } else {
                    self.counters.write_errors += 1;
                }
            }
            return;
        }
        if !self.local_ips.contains(&packet.source().ip()) {
            return;
        }
        let Some(payload) = packet.udp_payload() else {
            return;
        };
        let flow = TcpFlow {
            source: packet.source(),
            destination: packet.destination(),
        };
        if flow.destination.port() == 53 {
            let query = Datagram {
                flow,
                payload: payload.to_vec(),
            };
            let mut pending = query;
            for _ in 0..self.dns.len() {
                let index = self.dns_worker;
                self.dns_worker = (index + 1) % self.dns.len();
                match self.dns[index].try_send(pending) {
                    Ok(()) => return,
                    Err(TrySendError::Full(query) | TrySendError::Disconnected(query)) => {
                        pending = query;
                    }
                }
            }
            return;
        }
        // Opening a SOCKS association, looking up processes, and resolving
        // rule addresses can block. The device reader only queues a datagram.
        let _ = self.udp.try_send(Datagram {
            flow,
            payload: payload.to_vec(),
        });
    }
}

impl UdpPump {
    fn run(&mut self, receiver: &Receiver<Datagram>, stopped: &AtomicBool) {
        while !stopped.load(Ordering::Acquire) {
            let now = Instant::now();
            let generation = self.policy.generation();
            self.udp
                .retain(|key, _| key.egress.generation == generation);
            self.receive_udp(now);
            match receiver.recv_timeout(PUMP_INTERVAL) {
                Ok(datagram) if !stopped.load(Ordering::Acquire) => {
                    self.send(&datagram, Instant::now());
                }
                Ok(_) | Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }

    fn send(&mut self, datagram: &Datagram, now: Instant) {
        let flow = datagram.flow;
        let payload = &datagram.payload;
        let domain = sniff_quic_datagram(payload).and_then(|sniffed| sniffed.domain);
        let Some(selected) = self.policy.select(&flow, ConnectionNetwork::Udp, domain) else {
            return;
        };
        let remote = target(flow.destination);
        let key = MappingKey {
            source: flow.source,
            egress: UdpEgress {
                generation: selected.generation,
                route: selected.meta.route.clone(),
            },
        };
        let Ok(mapping) = self.udp.path(key, now, || -> io::Result<UdpMapping> {
            let path = selected.dialer.udp_for(&remote, FLOW_TIMEOUT)?;
            path.set_nonblocking(true)?;
            Ok(UdpMapping {
                path,
                peers: HashMap::new(),
            })
        }) else {
            return;
        };
        if mapping
            .peers
            .get(&flow.destination)
            .is_some_and(Registration::is_closed)
        {
            mapping.peers.remove(&flow.destination);
        }
        let Some(registration) =
            udp_registration(mapping, flow.destination, &self.table, selected.meta)
        else {
            return;
        };
        if mapping.path.send_to(payload, &remote).is_ok() {
            registration.add_up(payload.len() as u64);
        }
    }

    fn receive_udp(&mut self, now: Instant) {
        self.udp.receive(now, |key, mapping| {
            let Ok((length, Some(remote))) = mapping.path.recv_from(&mut self.response) else {
                return false;
            };
            if length > self.mtu || remote.port() == 53 || remote.is_ipv4() != key.source.is_ipv4()
            {
                return false;
            }
            let registration = match mapping.peers.get(&remote) {
                Some(registration) if registration.is_closed() => return false,
                Some(registration) => registration.counters(),
                None => {
                    let flow = TcpFlow {
                        source: key.source,
                        destination: remote,
                    };
                    let Some(selected) = self.policy.select(&flow, ConnectionNetwork::Udp, None)
                    else {
                        return false;
                    };
                    if selected.generation != key.egress.generation
                        || selected.meta.route != key.egress.route
                    {
                        return false;
                    }
                    let Some(registration) =
                        udp_registration(mapping, remote, &self.table, selected.meta)
                    else {
                        return false;
                    };
                    registration
                }
            };
            if write_reply(
                self.device.as_ref(),
                remote,
                key.source,
                &self.response[..length],
                self.mtu,
            ) {
                registration.add_down(length as u64);
                true
            } else {
                false
            }
        });
    }
}

fn udp_registration(
    mapping: &mut UdpMapping,
    peer: SocketAddr,
    table: &ConnectionTable,
    meta: ConnectionMeta,
) -> Option<crate::conntable::Counters> {
    let at_capacity = mapping.peers.len() >= UDP_PEERS;
    let registration = match mapping.peers.entry(peer) {
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
    stream.set_read_timeout(Some(FLOW_TIMEOUT))?;
    stream.set_write_timeout(Some(FLOW_TIMEOUT))?;
    if flow.destination.port() == 53 {
        return tcp_dns(&mut stream, policy.dns.as_ref(), stopped);
    }
    let sniffed = sniff_stream(&mut stream, &SniffLimits::default())?;
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
    relay(&stream, &upstream, &registration, &sniffed.buffered);
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

fn write_reply(
    device: &dyn PacketDevice,
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
    mtu: usize,
) -> bool {
    udp_reply(source, destination, payload, mtu).is_ok_and(|packet| device.send(&packet).is_ok())
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
        let mut pump = UdpPump {
            device: tun.clone(),
            policy: policy(true),
            table: ConnectionTable::new(),
            udp: FullConeNat::new(8, UDP_IDLE),
            response: vec![0; 1500],
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
        loop {
            pump.receive_udp(Instant::now());
            if !tun.0.lock().unwrap().is_empty() {
                break;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        let frames = tun.0.lock().unwrap();
        let response = Packet::parse(&frames[0]).unwrap();
        assert_eq!(response.source(), target);
        assert_eq!(response.destination(), client);
        assert_eq!(response.udp_payload(), Some(&b"reply"[..]));
        let entries = pump.table.active();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].process.as_deref(), Some("example.exe"));
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
        let mut udp = UdpPump {
            device: device.clone(),
            policy: Arc::clone(&policy),
            table: table.clone(),
            udp: FullConeNat::new(8, UDP_IDLE),
            response: vec![0; 1500],
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
            dns: Vec::new(),
            dns_worker: 0,
            clients: Arc::new(Clients::default()),
            stopped: Arc::clone(&stopped),
            mtu: 1500,
            counters: PumpCounters::default(),
        };
        let stopped_for_worker = Arc::clone(&stopped);
        let worker = thread::spawn(move || udp.run(&receiver, &stopped_for_worker));
        let datagram = udp_reply(client, destination, b"first datagram", 1500).unwrap();
        pump.dispatch(&Packet::parse(&datagram).unwrap(), Instant::now());
        opening.recv_timeout(Duration::from_secs(2)).unwrap();
        let syn = crate::tun::packet::tcp_test_packet(client, destination, 0x02);
        pump.dispatch(&Packet::parse(&syn).unwrap(), Instant::now());
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
