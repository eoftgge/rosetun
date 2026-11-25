use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rosetun_config::DnsSettings;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use super::cache::Clock;
use super::{DnsError, DnsOptions, DnsServer, DnsService, testcerts, wire};
use crate::net::{Credentials, Dialer, DirectDialer, Resolve, Socks5Dialer, Target, UdpPath};

fn decode_hex(chunks: &[&str]) -> Vec<u8> {
    let joined: String = chunks.iter().copied().collect();
    let bytes = joined.as_bytes();
    assert_eq!(bytes.len() % 2, 0);
    (0..bytes.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&joined[i..i + 2], 16).unwrap())
        .collect()
}

fn ca_cert() -> CertificateDer<'static> {
    CertificateDer::from(decode_hex(testcerts::CA_CERT_HEX))
}

fn leaf_cert() -> CertificateDer<'static> {
    CertificateDer::from(decode_hex(testcerts::LEAF_CERT_HEX))
}

fn leaf_key() -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(decode_hex(
        testcerts::LEAF_KEY_HEX,
    )))
}

struct ManualClock {
    now: Arc<Mutex<Instant>>,
}

impl ManualClock {
    fn new() -> (Self, Clock) {
        let now = Arc::new(Mutex::new(Instant::now()));
        let shared = Arc::clone(&now);
        let clock: Clock = Arc::new(move || *shared.lock().unwrap());
        (Self { now }, clock)
    }

    fn advance(&self, delta: Duration) {
        *self.now.lock().unwrap() += delta;
    }
}

fn append_name(buf: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        buf.push(u8::try_from(label.len()).unwrap());
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
}

fn append_rr(buf: &mut Vec<u8>, name: &[u8], rtype: u16, ttl: u32, rdata: &[u8]) {
    buf.extend_from_slice(name);
    buf.extend_from_slice(&rtype.to_be_bytes());
    buf.extend_from_slice(&wire::CLASS_IN.to_be_bytes());
    buf.extend_from_slice(&ttl.to_be_bytes());
    buf.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
    buf.extend_from_slice(rdata);
}

fn canned_a_response(query: &[u8], ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    let parsed = wire::parse_query(query).unwrap();
    let mut msg = Vec::new();
    msg.extend_from_slice(&parsed.id.to_be_bytes());
    msg.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    msg.extend_from_slice(&query[wire::HEADER_LEN..parsed.question_end]);
    append_rr(&mut msg, &[0xc0, 0x0c], wire::TYPE_A, ttl, &ip.octets());
    msg
}

fn canned_cname_a_response(
    query: &[u8],
    cname_target: &str,
    ip: Ipv4Addr,
    cname_ttl: u32,
    a_ttl: u32,
) -> Vec<u8> {
    let parsed = wire::parse_query(query).unwrap();
    let mut msg = Vec::new();
    msg.extend_from_slice(&parsed.id.to_be_bytes());
    msg.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0]);
    msg.extend_from_slice(&query[wire::HEADER_LEN..parsed.question_end]);

    let mut target_wire = Vec::new();
    append_name(&mut target_wire, cname_target);
    append_rr(
        &mut msg,
        &[0xc0, 0x0c],
        wire::TYPE_CNAME,
        cname_ttl,
        &target_wire,
    );
    append_rr(&mut msg, &target_wire, wire::TYPE_A, a_ttl, &ip.octets());
    msg
}

fn canned_nxdomain_with_soa(query: &[u8], soa_ttl: u32, soa_min: u32) -> Vec<u8> {
    let parsed = wire::parse_query(query).unwrap();
    let mut msg = Vec::new();
    msg.extend_from_slice(&parsed.id.to_be_bytes());
    msg.extend_from_slice(&[0x81, 0x83, 0, 1, 0, 0, 0, 1, 0, 0]);
    msg.extend_from_slice(&query[wire::HEADER_LEN..parsed.question_end]);

    let mut rdata = Vec::new();
    append_name(&mut rdata, "ns1.example.com");
    append_name(&mut rdata, "admin.example.com");
    for val in [1u32, 3600, 600, 86400, soa_min] {
        rdata.extend_from_slice(&val.to_be_bytes());
    }
    let mut zone = Vec::new();
    append_name(&mut zone, "example.com");
    append_rr(&mut msg, &zone, wire::TYPE_SOA, soa_ttl, &rdata);
    msg
}

fn canned_nodata_with_soa(query: &[u8], soa_ttl: u32, soa_min: u32) -> Vec<u8> {
    let mut msg = canned_nxdomain_with_soa(query, soa_ttl, soa_min);
    msg[3] = 0x80; // NOERROR
    msg
}

fn canned_large_a_response(query: &[u8], count: usize) -> Vec<u8> {
    let parsed = wire::parse_query(query).unwrap();
    let mut msg = Vec::new();
    msg.extend_from_slice(&parsed.id.to_be_bytes());
    msg.extend_from_slice(&[0x81, 0x80, 0, 1]);
    msg.extend_from_slice(&u16::try_from(count).unwrap().to_be_bytes());
    msg.extend_from_slice(&[0, 0, 0, 0]);
    msg.extend_from_slice(&query[wire::HEADER_LEN..parsed.question_end]);
    for i in 0..count {
        let last = u8::try_from((i % 250) + 1).unwrap();
        append_rr(
            &mut msg,
            &[0xc0, 0x0c],
            wire::TYPE_A,
            120,
            &[192, 0, 2, last],
        );
    }
    msg
}

type DohHandler = Arc<dyn Fn(&[u8]) -> (Vec<u8>, bool) + Send + Sync>;

struct MockDohServer {
    addr: SocketAddr,
    requests: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MockDohServer {
    fn start(handler: DohHandler) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf_cert(), ca_cert()], leaf_key())
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls_config = Arc::new(config);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));

        let req_count = Arc::clone(&requests);
        let conn_count = Arc::clone(&connections);
        let stop = Arc::clone(&shutdown);

        let handle = thread::spawn(move || {
            let mut workers = Vec::new();
            for incoming in listener.incoming() {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let Ok(stream) = incoming else {
                    continue;
                };
                if stop.load(Ordering::Acquire) {
                    break;
                }
                conn_count.fetch_add(1, Ordering::AcqRel);
                let cfg = Arc::clone(&tls_config);
                let h = Arc::clone(&handler);
                let rc = Arc::clone(&req_count);
                let s = Arc::clone(&stop);
                workers.push(thread::spawn(move || {
                    serve_doh_connection(stream, cfg, h, rc, s);
                }));
            }
            for w in workers {
                let _ = w.join();
            }
        });

        Self {
            addr,
            requests,
            connections,
            shutdown,
            handle: Some(handle),
        }
    }

    fn settings(&self) -> DnsSettings {
        DnsSettings {
            server: self.addr.ip(),
            server_name: "doh.example.com".to_owned(),
            port: Some(self.addr.port()),
            path: Some("/dns-query".to_owned()),
        }
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::Acquire)
    }

    fn connection_count(&self) -> usize {
        self.connections.load(Ordering::Acquire)
    }
}

impl Drop for MockDohServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(50));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn serve_doh_connection(
    tcp: TcpStream,
    config: Arc<ServerConfig>,
    handler: DohHandler,
    requests: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
) {
    let _ = tcp.set_read_timeout(Some(Duration::from_millis(200)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(2)));
    let Ok(conn) = ServerConnection::new(config) else {
        return;
    };
    let mut tls = StreamOwned::new(conn, tcp);
    let mut buf = Vec::new();
    loop {
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        let header_end = loop {
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break Some(pos);
            }
            if shutdown.load(Ordering::Acquire) {
                break None;
            }
            let mut tmp = [0u8; 2048];
            match tls.read(&mut tmp) {
                Ok(0) => break None,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => break None,
            }
        };
        let Some(end) = header_end else {
            break;
        };
        let header_str = std::str::from_utf8(&buf[..end]).unwrap();
        let mut lines = header_str.split("\r\n");
        let req_line = lines.next().unwrap();
        assert!(req_line.starts_with("POST /dns-query HTTP/1.1"));
        let mut content_len = 0usize;
        for line in lines {
            if let Some((k, v)) = line.split_once(':')
                && k.trim().eq_ignore_ascii_case("content-length")
            {
                content_len = v.trim().parse().unwrap();
            }
        }
        buf.drain(..end + 4);
        while buf.len() < content_len {
            let mut tmp = [0u8; 2048];
            match tls.read(&mut tmp) {
                Ok(0) => return,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    if shutdown.load(Ordering::Acquire) {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
        let body: Vec<u8> = buf.drain(..content_len).collect();
        // Verify RFC 8484 zeroed ID on the wire.
        assert_eq!(wire::message_id(&body), Some(0));

        requests.fetch_add(1, Ordering::AcqRel);
        let (reply, chunked) = handler(&body);
        let mut resp = Vec::new();
        if chunked {
            resp.extend_from_slice(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
            );
            let split = (reply.len() / 2).max(1).min(reply.len());
            let _ = write!(resp, "{split:x}\r\n");
            resp.extend_from_slice(&reply[..split]);
            resp.extend_from_slice(b"\r\n");
            if split < reply.len() {
                let _ = write!(resp, "{:x}\r\n", reply.len() - split);
                resp.extend_from_slice(&reply[split..]);
                resp.extend_from_slice(b"\r\n");
            }
            resp.extend_from_slice(b"0\r\n\r\n");
        } else {
            let _ = write!(
                resp,
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                reply.len()
            );
            resp.extend_from_slice(&reply);
        }
        if tls.write_all(&resp).is_err() || tls.flush().is_err() {
            break;
        }
    }
}

fn default_canned_handler() -> DohHandler {
    Arc::new(|query| {
        let parsed = wire::parse_query(query).unwrap();
        let reply = match (parsed.question.name.as_str(), parsed.question.qtype) {
            ("www.example.com", wire::TYPE_A) => {
                canned_a_response(query, Ipv4Addr::new(192, 0, 2, 7), 120)
            }
            ("www.example.com", wire::TYPE_AAAA) => canned_nodata_with_soa(query, 60, 30),
            ("alias.example.com", wire::TYPE_A) => canned_cname_a_response(
                query,
                "target.example.com",
                Ipv4Addr::new(198, 51, 100, 42),
                300,
                90,
            ),
            ("big.example.com", wire::TYPE_A) => canned_large_a_response(query, 40),
            ("nx.example.com", _) => canned_nxdomain_with_soa(query, 300, 20),
            ("nodata.example.com", _) => canned_nodata_with_soa(query, 300, 15),
            ("servfail.example.com", _) => wire::error_response(query, wire::RCODE_SERVFAIL),
            ("trunc.example.com", _) => {
                let mut r = canned_a_response(query, Ipv4Addr::new(203, 0, 113, 5), 60);
                r[2] |= 0x02; // TC
                r
            }
            ("chunked.example.com", wire::TYPE_A) => {
                return (
                    canned_a_response(query, Ipv4Addr::new(203, 0, 113, 9), 60),
                    true,
                );
            }
            _ => canned_nxdomain_with_soa(query, 60, 30),
        };
        (reply, false)
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SeenSocksTarget {
    Ip(SocketAddr),
    Domain(String, u16),
}

struct MockSocks5Server {
    addr: SocketAddr,
    targets: Arc<Mutex<Vec<SeenSocksTarget>>>,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MockSocks5Server {
    fn start(expected_auth: Option<Credentials>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let targets = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let seen = Arc::clone(&targets);
        let stop = Arc::clone(&shutdown);
        let handle = thread::spawn(move || {
            let mut workers = Vec::new();
            for incoming in listener.incoming() {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let Ok(stream) = incoming else {
                    continue;
                };
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let auth = expected_auth.clone();
                let seen_ref = Arc::clone(&seen);
                let stop_worker = Arc::clone(&stop);
                workers.push(thread::spawn(move || {
                    handle_socks5(stream, auth.as_ref(), &seen_ref, &stop_worker);
                }));
            }
            for w in workers {
                let _ = w.join();
            }
        });

        Self {
            addr,
            targets,
            shutdown,
            handle: Some(handle),
        }
    }

    fn seen_targets(&self) -> Vec<SeenSocksTarget> {
        self.targets.lock().unwrap().clone()
    }
}

impl Drop for MockSocks5Server {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(50));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn handle_socks5(
    mut client: TcpStream,
    expected_auth: Option<&Credentials>,
    seen: &Mutex<Vec<SeenSocksTarget>>,
    shutdown: &Arc<AtomicBool>,
) {
    let mut head = [0u8; 2];
    if client.read_exact(&mut head).is_err() || head[0] != 5 {
        return;
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    if client.read_exact(&mut methods).is_err() {
        return;
    }
    if let Some(cred) = expected_auth {
        if !methods.contains(&0x02) {
            let _ = client.write_all(&[5, 0xff]);
            return;
        }
        if client.write_all(&[5, 0x02]).is_err() {
            return;
        }
        let mut ver_ulen = [0u8; 2];
        if client.read_exact(&mut ver_ulen).is_err() || ver_ulen[0] != 1 {
            return;
        }
        let mut user = vec![0u8; usize::from(ver_ulen[1])];
        if client.read_exact(&mut user).is_err() {
            return;
        }
        let mut plen = [0u8; 1];
        if client.read_exact(&mut plen).is_err() {
            return;
        }
        let mut pass = vec![0u8; usize::from(plen[0])];
        if client.read_exact(&mut pass).is_err() {
            return;
        }
        if user != cred.username.as_bytes() || pass != cred.password.as_bytes() {
            let _ = client.write_all(&[1, 1]);
            return;
        }
        if client.write_all(&[1, 0]).is_err() {
            return;
        }
    } else {
        if !methods.contains(&0x00) {
            let _ = client.write_all(&[5, 0xff]);
            return;
        }
        if client.write_all(&[5, 0x00]).is_err() {
            return;
        }
    }

    let mut req = [0u8; 4];
    if client.read_exact(&mut req).is_err() || req[0] != 5 || req[1] != 1 {
        return;
    }
    let target = match req[3] {
        1 => {
            let mut octets = [0u8; 4];
            let mut port = [0u8; 2];
            if client.read_exact(&mut octets).is_err() || client.read_exact(&mut port).is_err() {
                return;
            }
            SeenSocksTarget::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(octets)),
                u16::from_be_bytes(port),
            ))
        }
        4 => {
            let mut octets = [0u8; 16];
            let mut port = [0u8; 2];
            if client.read_exact(&mut octets).is_err() || client.read_exact(&mut port).is_err() {
                return;
            }
            SeenSocksTarget::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                u16::from_be_bytes(port),
            ))
        }
        3 => {
            let mut len = [0u8; 1];
            if client.read_exact(&mut len).is_err() {
                return;
            }
            let mut name = vec![0u8; usize::from(len[0])];
            let mut port = [0u8; 2];
            if client.read_exact(&mut name).is_err() || client.read_exact(&mut port).is_err() {
                return;
            }
            SeenSocksTarget::Domain(
                String::from_utf8_lossy(&name).into_owned(),
                u16::from_be_bytes(port),
            )
        }
        _ => return,
    };

    seen.lock().unwrap().push(target.clone());
    let SeenSocksTarget::Ip(dest) = target else {
        let _ = client.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]);
        return;
    };
    let Ok(mut upstream) = TcpStream::connect(dest) else {
        let _ = client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
        return;
    };
    let _ = client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]);

    let _ = client.set_read_timeout(Some(Duration::from_millis(100)));
    let _ = upstream.set_read_timeout(Some(Duration::from_millis(100)));
    let Ok(mut c_read) = client.try_clone() else {
        return;
    };
    let Ok(mut u_write) = upstream.try_clone() else {
        return;
    };
    let stop1 = Arc::clone(shutdown);
    let t1 = thread::spawn(move || {
        relay_until_shutdown(&mut c_read, &mut u_write, &stop1);
        let _ = u_write.shutdown(std::net::Shutdown::Write);
    });
    relay_until_shutdown(&mut upstream, &mut client, shutdown);
    let _ = client.shutdown(std::net::Shutdown::Write);
    let _ = t1.join();
}

fn relay_until_shutdown(src: &mut TcpStream, dst: &mut TcpStream, shutdown: &AtomicBool) {
    let mut buf = [0u8; 4096];
    while !shutdown.load(Ordering::Acquire) {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
    }
}

#[test]
fn doh_exchange_over_direct_dialer_reuses_one_connection_and_handles_chunked() {
    let doh = MockDohServer::start(default_canned_handler());
    let service = DnsService::with_roots(
        &doh.settings(),
        Arc::new(DirectDialer::default()),
        DnsOptions::default(),
        vec![ca_cert()],
    )
    .unwrap();

    let q1 = wire::build_query(0x1111, "www.example.com", wire::TYPE_A).unwrap();
    let r1 = service.exchange(&q1).unwrap();
    assert_eq!(wire::message_id(&r1), Some(0x1111));
    let a1 = wire::parse_response(&r1, "www.example.com").unwrap();
    assert_eq!(
        a1.addresses,
        vec![(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 120)]
    );

    let q2 = wire::build_query(0x2222, "chunked.example.com", wire::TYPE_A).unwrap();
    let r2 = service.exchange(&q2).unwrap();
    assert_eq!(wire::message_id(&r2), Some(0x2222));
    let a2 = wire::parse_response(&r2, "chunked.example.com").unwrap();
    assert_eq!(
        a2.addresses,
        vec![(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 60)]
    );

    assert_eq!(doh.request_count(), 2);
    assert_eq!(doh.connection_count(), 1);
}

#[test]
fn doh_over_socks5_no_auth_and_password_dials_literal_resolver_ip() {
    let doh = MockDohServer::start(default_canned_handler());

    // No-auth SOCKS5.
    let socks_open = MockSocks5Server::start(None);
    let dialer_open = Arc::new(Socks5Dialer::new(socks_open.addr, None));
    let service = DnsService::with_roots(
        &doh.settings(),
        dialer_open,
        DnsOptions::default(),
        vec![ca_cert()],
    )
    .unwrap();
    let addrs = service.resolve("www.example.com").unwrap();
    assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))]);
    assert_eq!(
        socks_open.seen_targets(),
        vec![SeenSocksTarget::Ip(doh.addr)]
    );

    // User/password SOCKS5 swapped in at runtime via set_dialer; cache stays warm,
    // and an uncached name uses the new authenticated SOCKS5 outbound.
    let creds = Credentials {
        username: "test-user".to_owned(),
        password: "test-password".to_owned(),
    };
    let socks_auth = MockSocks5Server::start(Some(creds.clone()));
    service.set_dialer(Arc::new(Socks5Dialer::new(socks_auth.addr, Some(creds))));

    // Cached query still served without hitting the new proxy.
    let cached_q = wire::build_query(0x3333, "www.example.com", wire::TYPE_A).unwrap();
    let _ = service.exchange(&cached_q).unwrap();
    assert!(socks_auth.seen_targets().is_empty());

    // Fresh name traverses the authenticated SOCKS5 proxy to the literal IP.
    let fresh_q = wire::build_query(0x4444, "alias.example.com", wire::TYPE_A).unwrap();
    let reply = service.exchange(&fresh_q).unwrap();
    let ans = wire::parse_response(&reply, "alias.example.com").unwrap();
    assert_eq!(
        ans.addresses,
        vec![(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)), 90)]
    );
    assert_eq!(
        socks_auth.seen_targets(),
        vec![SeenSocksTarget::Ip(doh.addr)]
    );
}

#[test]
fn cache_decrements_ttls_expires_with_clock_and_caches_negatives_only_when_allowed() {
    let doh = MockDohServer::start(default_canned_handler());
    let (clock_ctl, clock) = ManualClock::new();
    let service = DnsService::with_roots_and_clock(
        &doh.settings(),
        Arc::new(DirectDialer::default()),
        DnsOptions::default(),
        vec![ca_cert()],
        clock,
    )
    .unwrap();

    // Positive cache hit rewrites ID and decrements TTL.
    let q1 = wire::build_query(0x0101, "www.example.com", wire::TYPE_A).unwrap();
    let r1 = service.exchange(&q1).unwrap();
    assert_eq!(
        wire::parse_response(&r1, "www.example.com")
            .unwrap()
            .answer_ttl,
        Some(120)
    );
    assert_eq!(doh.request_count(), 1);
    assert_eq!(service.cache_len(), 1);

    clock_ctl.advance(Duration::from_secs(25));
    let q2 = wire::build_query(0x0202, "www.example.com", wire::TYPE_A).unwrap();
    let r2 = service.exchange(&q2).unwrap();
    assert_eq!(wire::message_id(&r2), Some(0x0202));
    assert_eq!(
        wire::parse_response(&r2, "www.example.com")
            .unwrap()
            .answer_ttl,
        Some(95)
    );
    assert_eq!(doh.request_count(), 1);

    // Expiry triggers a fresh upstream fetch.
    clock_ctl.advance(Duration::from_secs(96));
    let r3 = service.exchange(&q2).unwrap();
    assert_eq!(
        wire::parse_response(&r3, "www.example.com")
            .unwrap()
            .answer_ttl,
        Some(120)
    );
    assert_eq!(doh.request_count(), 2);

    // Negative NXDOMAIN cached by SOA minimum (20s < negative_ttl 30s).
    let nx_q = wire::build_query(10, "nx.example.com", wire::TYPE_A).unwrap();
    let nx_r1 = service.exchange(&nx_q).unwrap();
    assert_eq!(wire::rcode_of(&nx_r1), Some(wire::RCODE_NXDOMAIN));
    let before = doh.request_count();
    clock_ctl.advance(Duration::from_secs(19));
    let _ = service.exchange(&nx_q).unwrap();
    assert_eq!(doh.request_count(), before);
    clock_ctl.advance(Duration::from_secs(2));
    let _ = service.exchange(&nx_q).unwrap();
    assert_eq!(doh.request_count(), before + 1);

    // Negative NODATA cached by SOA minimum (15s).
    let nd_q = wire::build_query(11, "nodata.example.com", wire::TYPE_AAAA).unwrap();
    let _ = service.exchange(&nd_q).unwrap();
    let before_nd = doh.request_count();
    clock_ctl.advance(Duration::from_secs(10));
    let _ = service.exchange(&nd_q).unwrap();
    assert_eq!(doh.request_count(), before_nd);
    clock_ctl.advance(Duration::from_secs(6));
    let _ = service.exchange(&nd_q).unwrap();
    assert_eq!(doh.request_count(), before_nd + 1);

    // SERVFAIL and truncated answers are never cached.
    let sf_q = wire::build_query(12, "servfail.example.com", wire::TYPE_A).unwrap();
    let before_sf = doh.request_count();
    let _ = service.exchange(&sf_q).unwrap();
    let _ = service.exchange(&sf_q).unwrap();
    assert_eq!(doh.request_count(), before_sf + 2);

    let tr_q = wire::build_query(13, "trunc.example.com", wire::TYPE_A).unwrap();
    let before_tr = doh.request_count();
    let _ = service.exchange(&tr_q).unwrap();
    let _ = service.exchange(&tr_q).unwrap();
    assert_eq!(doh.request_count(), before_tr + 2);

    service.flush();
    assert_eq!(service.cache_len(), 0);
}

#[test]
fn reverse_cache_uses_question_name_not_cname_and_honors_ttl_and_lru_bound() {
    let doh = MockDohServer::start(default_canned_handler());
    let (clock_ctl, clock) = ManualClock::new();
    let options = DnsOptions {
        reverse_entries: 2,
        min_ttl: Duration::from_secs(30),
        ..DnsOptions::default()
    };
    let service = DnsService::with_roots_and_clock(
        &doh.settings(),
        Arc::new(DirectDialer::default()),
        options,
        vec![ca_cert()],
        clock,
    )
    .unwrap();

    // CNAME answer: reverse entry must hold question name ("alias.example.com"),
    // NOT the CNAME target ("target.example.com").
    let q_alias = wire::build_query(1, "ALIAS.Example.COM.", wire::TYPE_A).unwrap();
    let _ = service.exchange(&q_alias).unwrap();
    let alias_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42));
    assert_eq!(
        service.domain_for(alias_ip).as_deref(),
        Some("alias.example.com")
    );

    let q_www = wire::build_query(2, "www.example.com", wire::TYPE_A).unwrap();
    let _ = service.exchange(&q_www).unwrap();
    let www_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

    // Touch alias_ip so www_ip becomes LRU, then insert a third IP via chunked.example.com.
    assert_eq!(
        service.domain_for(alias_ip).as_deref(),
        Some("alias.example.com")
    );
    let q_chunk = wire::build_query(3, "chunked.example.com", wire::TYPE_A).unwrap();
    let _ = service.exchange(&q_chunk).unwrap();
    let chunk_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));

    assert_eq!(service.domain_for(www_ip), None);
    assert_eq!(
        service.domain_for(alias_ip).as_deref(),
        Some("alias.example.com")
    );
    assert_eq!(
        service.domain_for(chunk_ip).as_deref(),
        Some("chunked.example.com")
    );

    // chunk_ip has TTL 60s, alias_ip has TTL 90s.
    clock_ctl.advance(Duration::from_secs(61));
    assert_eq!(service.domain_for(chunk_ip), None);
    assert_eq!(
        service.domain_for(alias_ip).as_deref(),
        Some("alias.example.com")
    );

    clock_ctl.advance(Duration::from_secs(30));
    assert_eq!(service.domain_for(alias_ip), None);
}

#[test]
fn queries_for_resolver_server_name_are_answered_locally_without_upstream() {
    let doh = MockDohServer::start(default_canned_handler());
    let service = DnsService::with_roots(
        &doh.settings(),
        Arc::new(DirectDialer::default()),
        DnsOptions::default(),
        vec![ca_cert()],
    )
    .unwrap();

    let q_a = wire::build_query(77, "DOH.Example.COM", wire::TYPE_A).unwrap();
    let r_a = service.exchange(&q_a).unwrap();
    let ans_a = wire::parse_response(&r_a, "doh.example.com").unwrap();
    assert_eq!(ans_a.rcode, wire::RCODE_NOERROR);
    assert_eq!(ans_a.addresses, vec![(doh.addr.ip(), 30)]);

    let q_aaaa = wire::build_query(78, "doh.example.com", wire::TYPE_AAAA).unwrap();
    let r_aaaa = service.exchange(&q_aaaa).unwrap();
    let ans_aaaa = wire::parse_response(&r_aaaa, "doh.example.com").unwrap();
    assert_eq!(ans_aaaa.rcode, wire::RCODE_NOERROR);
    assert!(ans_aaaa.addresses.is_empty());

    assert_eq!(doh.request_count(), 0);
}

struct ReentrantDialer {
    service: Mutex<Option<Arc<DnsService>>>,
    saw_loop_error: AtomicBool,
}

impl std::fmt::Debug for ReentrantDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReentrantDialer").finish_non_exhaustive()
    }
}

impl Dialer for ReentrantDialer {
    fn connect(&self, _target: &Target, _timeout: Duration) -> io::Result<TcpStream> {
        let svc = self.service.lock().unwrap().as_ref().cloned().unwrap();
        let nested_q = wire::build_query(99, "nested.example.com", wire::TYPE_A).unwrap();
        if matches!(svc.exchange(&nested_q), Err(DnsError::Loop))
            && svc.lookup("nested.example.com").is_err()
        {
            self.saw_loop_error.store(true, Ordering::Release);
            return Err(io::Error::other(DnsError::Loop));
        }
        Err(io::Error::other("unexpected re-entrancy outcome"))
    }

    fn udp(&self, _timeout: Duration) -> io::Result<UdpPath> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "not used"))
    }
}

#[test]
fn reentrant_exchange_and_lookup_during_doh_fail_with_loop_error() {
    let dialer = Arc::new(ReentrantDialer {
        service: Mutex::new(None),
        saw_loop_error: AtomicBool::new(false),
    });
    let settings = DnsSettings {
        server: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        server_name: "doh.example.com".to_owned(),
        port: Some(443),
        path: None,
    };
    let service = Arc::new(
        DnsService::with_roots(
            &settings,
            Arc::clone(&dialer) as Arc<dyn Dialer>,
            DnsOptions::default(),
            vec![ca_cert()],
        )
        .unwrap(),
    );
    *dialer.service.lock().unwrap() = Some(Arc::clone(&service));

    let query = wire::build_query(1, "www.example.com", wire::TYPE_A).unwrap();
    let result = service.exchange(&query);
    assert!(result.is_err());
    assert!(dialer.saw_loop_error.load(Ordering::Acquire));

    // After the failed exchange unwinds, the thread-local guard must be cleared.
    let anchor_q = wire::build_query(2, "doh.example.com", wire::TYPE_A).unwrap();
    assert!(service.exchange(&anchor_q).is_ok());
}

#[test]
fn excess_concurrent_in_flight_queries_get_servfail_immediately() {
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let e_clone = Arc::clone(&entered);
    let r_clone = Arc::clone(&release);

    let handler: DohHandler = Arc::new(move |query| {
        e_clone.wait();
        r_clone.wait();
        (
            canned_a_response(query, Ipv4Addr::new(192, 0, 2, 8), 60),
            false,
        )
    });
    let doh = MockDohServer::start(handler);
    let service = Arc::new(
        DnsService::with_roots(
            &doh.settings(),
            Arc::new(DirectDialer::default()),
            DnsOptions {
                max_in_flight: 1,
                ..DnsOptions::default()
            },
            vec![ca_cert()],
        )
        .unwrap(),
    );

    let svc_bg = Arc::clone(&service);
    let first = thread::spawn(move || {
        let q = wire::build_query(1, "first.example.com", wire::TYPE_A).unwrap();
        svc_bg.exchange(&q).unwrap()
    });

    // Wait until the first query is actively inside the upstream DoH server.
    entered.wait();

    let second_q = wire::build_query(2, "second.example.com", wire::TYPE_A).unwrap();
    let second_r = service.exchange(&second_q).unwrap();
    assert_eq!(wire::rcode_of(&second_r), Some(wire::RCODE_SERVFAIL));
    assert_eq!(wire::message_id(&second_r), Some(2));

    release.wait();
    let first_r = first.join().unwrap();
    assert_eq!(wire::rcode_of(&first_r), Some(wire::RCODE_NOERROR));
    assert_eq!(doh.request_count(), 1);
}

#[test]
fn dns_server_serves_udp_tcp_truncation_cache_reverse_and_shuts_down_promptly() {
    let doh = MockDohServer::start(default_canned_handler());
    let service = Arc::new(
        DnsService::with_roots(
            &doh.settings(),
            Arc::new(DirectDialer::default()),
            DnsOptions::default(),
            vec![ca_cert()],
        )
        .unwrap(),
    );

    let mut server = DnsServer::bind(
        Arc::clone(&service),
        &[SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)],
    )
    .unwrap();
    let addrs = server.local_addrs();
    assert_eq!(addrs.len(), 1);
    let addr = addrs[0];

    // UDP query #1 hits upstream and populates forward + reverse cache.
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let q1 = wire::build_query(0x5001, "www.example.com", wire::TYPE_A).unwrap();
    udp.send_to(&q1, addr).unwrap();
    let mut buf = [0u8; 2048];
    let (n, _) = udp.recv_from(&mut buf).unwrap();
    let ans1 = wire::parse_response(&buf[..n], "www.example.com").unwrap();
    assert_eq!(wire::message_id(&buf[..n]), Some(0x5001));
    assert_eq!(
        ans1.addresses,
        vec![(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 120)]
    );
    assert_eq!(doh.request_count(), 1);
    assert_eq!(
        service
            .domain_for(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)))
            .as_deref(),
        Some("www.example.com")
    );

    // UDP query #2 with a new ID hits cache without contacting upstream.
    let q2 = wire::build_query(0x5002, "www.example.com", wire::TYPE_A).unwrap();
    udp.send_to(&q2, addr).unwrap();
    let (n, _) = udp.recv_from(&mut buf).unwrap();
    assert_eq!(wire::message_id(&buf[..n]), Some(0x5002));
    assert_eq!(doh.request_count(), 1);

    // Large answer over plain UDP (> 512 bytes) is truncated with TC=1.
    let q_big = wire::build_query(0x5003, "big.example.com", wire::TYPE_A).unwrap();
    udp.send_to(&q_big, addr).unwrap();
    let (n, _) = udp.recv_from(&mut buf).unwrap();
    let trunc = wire::parse_response(&buf[..n], "big.example.com").unwrap();
    assert!(trunc.truncated);

    // Same large answer over TCP (2-byte length prefix) arrives complete, plus a
    // second query on the same TCP connection.
    let mut tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    for (id, name, expected_count) in [
        (0x6001, "big.example.com", 40usize),
        (0x6002, "www.example.com", 1),
    ] {
        let q = wire::build_query(id, name, wire::TYPE_A).unwrap();
        tcp.write_all(&u16::try_from(q.len()).unwrap().to_be_bytes())
            .unwrap();
        tcp.write_all(&q).unwrap();

        let mut len_buf = [0u8; 2];
        tcp.read_exact(&mut len_buf).unwrap();
        let mut resp = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
        tcp.read_exact(&mut resp).unwrap();
        let ans = wire::parse_response(&resp, name).unwrap();
        assert_eq!(wire::message_id(&resp), Some(id));
        assert!(!ans.truncated);
        assert_eq!(ans.answer_count, expected_count);
    }

    // Malformed UDP query gets FORMERR.
    udp.send_to(&[0x70, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], addr)
        .unwrap();
    let (n, _) = udp.recv_from(&mut buf).unwrap();
    assert_eq!(wire::rcode_of(&buf[..n]), Some(wire::RCODE_FORMERR));

    // Shutdown joins promptly even with an idle TCP client still connected, and is idempotent.
    let start = Instant::now();
    server.shutdown();
    server.shutdown();
    assert!(start.elapsed() < Duration::from_secs(2));
    drop(tcp);
}

#[test]
fn redacted_debug_and_errors_never_leak_names_or_addresses() {
    let settings = DnsSettings {
        server: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
        server_name: "doh.example.com".to_owned(),
        port: Some(8443),
        path: Some("/dns-query".to_owned()),
    };
    let service = Arc::new(
        DnsService::with_roots(
            &settings,
            Arc::new(DirectDialer::default()),
            DnsOptions::default(),
            vec![ca_cert()],
        )
        .unwrap(),
    );
    let mut server = DnsServer::bind(
        Arc::clone(&service),
        &[SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)],
    )
    .unwrap();

    for text in [
        format!("{service:?}"),
        format!("{server:?}"),
        format!("{}", DnsError::Loop),
        format!("{}", DnsError::InvalidServerName),
        format!("{}", DnsError::HttpStatus(502)),
    ] {
        assert!(!text.contains("example.com"));
        assert!(!text.contains("192.0.2"));
        assert!(!text.contains("127.0.0.1"));
        assert!(!text.contains("8443"));
    }

    // Also verify DnsService::new constructs with the system trust store.
    let prod_service = DnsService::new(
        &settings,
        Arc::new(DirectDialer::default()),
        DnsOptions::default(),
    )
    .unwrap();
    assert!(!format!("{prod_service:?}").contains("example.com"));

    // IPv6 local anchor works too.
    let v6_settings = DnsSettings {
        server: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 53)),
        server_name: "doh.example.com".to_owned(),
        port: None,
        path: None,
    };
    let v6_service = DnsService::new(
        &v6_settings,
        Arc::new(DirectDialer::default()),
        DnsOptions::default(),
    )
    .unwrap();
    let q_v6 = wire::build_query(5, "doh.example.com", wire::TYPE_AAAA).unwrap();
    let r_v6 = v6_service.exchange(&q_v6).unwrap();
    let a_v6 = wire::parse_response(&r_v6, "doh.example.com").unwrap();
    assert_eq!(a_v6.addresses, vec![(v6_settings.server, 30)]);

    server.shutdown();
}
