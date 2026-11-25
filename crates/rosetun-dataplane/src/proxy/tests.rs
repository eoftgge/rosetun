use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use rosetun_config::{ConnectionNetwork, ExitId};
use rosetun_engine::{DelayInbound, EngineRoute, PROXY_TAG, SUBSCRIPTION_PROXY_USER};

use super::*;
use crate::conntable::ConnectionTable;
use crate::net::{Credentials, Dialer, DirectDialer, Resolve, Socks5Dialer, Target, write_address};

/// A deterministic loopback resolver that maps every test domain to 127.0.0.1.
struct LoopbackResolver;

impl Resolve for LoopbackResolver {
    fn resolve(&self, _name: &str) -> io::Result<Vec<IpAddr>> {
        Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
    }
}

/// Spawns a loopback TCP echo server prefixed with `tag`.
struct EchoServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl EchoServer {
    fn start(tag: &'static [u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_flag.load(Ordering::Acquire) {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                if stop_flag.load(Ordering::Acquire) {
                    break;
                }
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    let mut tagged = false;
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if !tagged {
                                    if stream.write_all(tag).is_err() {
                                        break;
                                    }
                                    tagged = true;
                                }
                                if stream.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        Self {
            addr,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Spawns a tiny mock authenticated SOCKS5 server (TCP CONNECT) that forwards
/// everything to `backend` while counting handled connections.
struct MockSocksUpstream {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockSocksUpstream {
    fn start(username: &str, password: &str, backend: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let user = username.to_owned();
        let pass = password.to_owned();
        let hits_clone = Arc::clone(&hits);
        let stop_clone = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_clone.load(Ordering::Acquire) {
                let Ok((mut client, _)) = listener.accept() else {
                    break;
                };
                if stop_clone.load(Ordering::Acquire) {
                    break;
                }
                let user = user.clone();
                let pass = pass.clone();
                let hits = Arc::clone(&hits_clone);
                thread::spawn(move || {
                    let mut head = [0u8; 2];
                    if client.read_exact(&mut head).is_err() || head[0] != 5 {
                        return;
                    }
                    let mut methods = vec![0u8; usize::from(head[1])];
                    if client.read_exact(&mut methods).is_err() || !methods.contains(&0x02) {
                        let _ = client.write_all(&[5, 0xff]);
                        return;
                    }
                    let _ = client.write_all(&[5, 0x02]);
                    let mut auth = [0u8; 2];
                    if client.read_exact(&mut auth).is_err() || auth[0] != 1 {
                        return;
                    }
                    let mut got_user = vec![0u8; usize::from(auth[1])];
                    if client.read_exact(&mut got_user).is_err() {
                        return;
                    }
                    let mut plen = [0u8; 1];
                    if client.read_exact(&mut plen).is_err() {
                        return;
                    }
                    let mut got_pass = vec![0u8; usize::from(plen[0])];
                    if client.read_exact(&mut got_pass).is_err() {
                        return;
                    }
                    if got_user != user.as_bytes() || got_pass != pass.as_bytes() {
                        let _ = client.write_all(&[1, 1]);
                        return;
                    }
                    let _ = client.write_all(&[1, 0]);
                    let mut req = [0u8; 4];
                    if client.read_exact(&mut req).is_err() || req[1] != 1 {
                        return;
                    }
                    match req[3] {
                        1 => {
                            let mut skip = [0u8; 6];
                            if client.read_exact(&mut skip).is_err() {
                                return;
                            }
                        }
                        3 => {
                            let mut len = [0u8; 1];
                            if client.read_exact(&mut len).is_err() {
                                return;
                            }
                            let mut skip = vec![0u8; usize::from(len[0]) + 2];
                            if client.read_exact(&mut skip).is_err() {
                                return;
                            }
                        }
                        4 => {
                            let mut skip = [0u8; 18];
                            if client.read_exact(&mut skip).is_err() {
                                return;
                            }
                        }
                        _ => return,
                    }
                    let Ok(mut upstream) = TcpStream::connect(backend) else {
                        let _ = client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
                        return;
                    };
                    hits.fetch_add(1, Ordering::AcqRel);
                    let _ = client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]);
                    let mut client_r = client.try_clone().unwrap();
                    let mut up_w = upstream.try_clone().unwrap();
                    let t = thread::spawn(move || {
                        let _ = io::copy(&mut client_r, &mut up_w);
                        let _ = up_w.shutdown(Shutdown::Write);
                    });
                    let _ = io::copy(&mut upstream, &mut client);
                    let _ = client.shutdown(Shutdown::Write);
                    let _ = t.join();
                });
            }
        });
        Self {
            addr,
            hits,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for MockSocksUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[test]
fn mixed_proxy_routes_http_connect_and_socks5_across_direct_block_proxy_and_exits() {
    let direct_echo = EchoServer::start(b"DIRECT:");
    let proxy_echo = EchoServer::start(b"PROXY:");
    let exit_echo = EchoServer::start(b"EXIT:");

    let proxy_socks = MockSocksUpstream::start("main", "secret-main", proxy_echo.addr);
    let exit_socks = MockSocksUpstream::start("exit0", "secret-exit", exit_echo.addr);
    let exit_id = ExitId::new("nl");

    let mut exits = HashMap::new();
    exits.insert(
        exit_id.clone(),
        (
            "exit-0".to_owned(),
            Arc::new(Socks5Dialer::new(
                exit_socks.addr,
                Some(Credentials {
                    username: "exit0".into(),
                    password: "secret-exit".into(),
                }),
            )) as Arc<dyn Dialer>,
        ),
    );
    let outbounds = Arc::new(Outbounds {
        direct: Arc::new(DirectDialer::new(Arc::new(LoopbackResolver))),
        proxy: Some(Arc::new(Socks5Dialer::new(
            proxy_socks.addr,
            Some(Credentials {
                username: "main".into(),
                password: "secret-main".into(),
            }),
        ))),
        exits,
    });

    let exit_for_policy = exit_id.clone();
    let policy = Arc::new(move |query: &Query<'_>| match query.domain {
        Some("direct.example.com") => Verdict::Direct,
        Some("blocked.example.com") => Verdict::Block,
        Some("exit.example.com") => Verdict::Exit(exit_for_policy.clone()),
        _ => Verdict::Proxy,
    });

    let table = ConnectionTable::new();
    let router = Arc::new(Router::new(
        policy,
        outbounds,
        table.clone(),
        RouterConfig::default(),
    ));
    let mut server =
        ProxyServer::bind(Arc::clone(&router), &["127.0.0.1:0".parse().unwrap()]).unwrap();
    let proxy_addr = server.local_addrs()[0];

    // 1. HTTP CONNECT -> direct
    let mut stream = TcpStream::connect(proxy_addr).unwrap();
    write!(
        stream,
        "CONNECT direct.example.com:{} HTTP/1.1\r\nHost: direct.example.com\r\n\r\n",
        direct_echo.addr.port()
    )
    .unwrap();
    let mut head = [0u8; 39];
    stream.read_exact(&mut head).unwrap();
    assert!(head.starts_with(b"HTTP/1.1 200"));
    stream.write_all(b"ping").unwrap();
    let mut reply = [0u8; 11];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"DIRECT:ping");
    drop(stream);

    // 2. HTTP CONNECT -> block returns 403
    let mut stream = TcpStream::connect(proxy_addr).unwrap();
    stream
        .write_all(b"CONNECT blocked.example.com:443 HTTP/1.1\r\n\r\n")
        .unwrap();
    let mut status = String::new();
    stream.read_to_string(&mut status).unwrap();
    assert!(status.starts_with("HTTP/1.1 403"));

    // 3. SOCKS5 -> main proxy upstream
    let socks_client = Socks5Dialer::new(proxy_addr, None);
    let mut stream = socks_client
        .connect(
            &Target::domain("proxied.example.com", 443),
            Duration::from_secs(3),
        )
        .unwrap();
    stream.write_all(b"hello").unwrap();
    let mut reply = [0u8; 11];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"PROXY:hello");
    drop(stream);

    // 4. SOCKS5 -> exit upstream
    let mut stream = socks_client
        .connect(
            &Target::domain("exit.example.com", 443),
            Duration::from_secs(3),
        )
        .unwrap();
    stream.write_all(b"world").unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"EXIT:world");
    drop(stream);

    // 5. SOCKS5 -> block returns PermissionDenied (code 0x02)
    let err = socks_client
        .connect(
            &Target::domain("blocked.example.com", 443),
            Duration::from_secs(3),
        )
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

    assert_eq!(proxy_socks.hits.load(Ordering::Acquire), 1);
    assert_eq!(exit_socks.hits.load(Ordering::Acquire), 1);

    // Totals recorded every forwarded byte.
    let totals = table.totals();
    assert!(totals.up >= 14);
    assert!(totals.down >= 32);

    server.shutdown();
}

#[test]
fn plain_http_proxy_request_strips_proxy_headers_and_forwards_body() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_addr = listener.local_addr().unwrap();
    let server_thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut received = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).unwrap();
            received.extend_from_slice(&buf[..n]);
            if received.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let text = String::from_utf8(received).unwrap();
        assert!(text.starts_with("GET /hello?a=1 HTTP/1.1\r\n"));
        assert!(!text.to_lowercase().contains("proxy-authorization"));
        assert!(text.contains("Connection: close\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .unwrap();
    });

    let outbounds = Arc::new(Outbounds {
        direct: Arc::new(DirectDialer::new(Arc::new(LoopbackResolver))),
        proxy: None,
        exits: HashMap::new(),
    });
    let router = Arc::new(Router::new(
        Arc::new(|_: &Query<'_>| Verdict::Direct),
        outbounds,
        ConnectionTable::new(),
        RouterConfig::default(),
    ));
    let mut proxy = ProxyServer::bind(router, &["127.0.0.1:0".parse().unwrap()]).unwrap();
    let mut client = TcpStream::connect(proxy.local_addrs()[0]).unwrap();
    write!(
        client,
        "GET http://example.com:{}/hello?a=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic abc\r\n\r\n",
        origin_addr.port()
    )
    .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(response.ends_with("\r\n\r\nok"));
    server_thread.join().unwrap();
    proxy.shutdown();
}

#[test]
fn sniffing_routes_ip_connection_by_first_bytes_and_replays_prefix() {
    struct PrefixSniffer;

    impl Sniffing for PrefixSniffer {
        fn sniff_tcp(&self, stream: &mut TcpStream) -> io::Result<TcpSniff> {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf)?;
            let domain = (&buf == b"SNI!").then(|| "sniffed.example.com".to_owned());
            Ok(TcpSniff {
                domain,
                buffered: buf.to_vec(),
            })
        }

        fn sniff_udp(&self, _datagram: &[u8]) -> Option<String> {
            None
        }
    }

    let direct_echo = EchoServer::start(b"DIRECT:");
    let proxy_echo = EchoServer::start(b"PROXY:");
    let proxy_socks = MockSocksUpstream::start("u", "p", proxy_echo.addr);

    let outbounds = Arc::new(Outbounds {
        direct: Arc::new(DirectDialer::new(Arc::new(LoopbackResolver))),
        proxy: Some(Arc::new(Socks5Dialer::new(
            proxy_socks.addr,
            Some(Credentials {
                username: "u".into(),
                password: "p".into(),
            }),
        ))),
        exits: HashMap::new(),
    });
    let table = ConnectionTable::new();
    let router = Arc::new(
        Router::new(
            Arc::new(|query: &Query<'_>| match query.domain {
                Some("sniffed.example.com") => Verdict::Proxy,
                _ => Verdict::Direct,
            }),
            outbounds,
            table.clone(),
            RouterConfig::default(),
        )
        .with_sniffing(Arc::new(PrefixSniffer)),
    );
    let mut proxy = ProxyServer::bind(router, &["127.0.0.1:0".parse().unwrap()]).unwrap();
    let socks_client = Socks5Dialer::new(proxy.local_addrs()[0], None);

    // Connect by IP literal so early reply + sniffing triggers.
    let mut stream = socks_client
        .connect(&Target::socket(direct_echo.addr), Duration::from_secs(3))
        .unwrap();
    stream.write_all(b"SNI!rest").unwrap();
    let mut reply = [0u8; 14];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"PROXY:SNI!rest");
    drop(stream);

    // Wait briefly for registration drop and check closed record captured the sniffed host.
    thread::sleep(Duration::from_millis(50));
    let closed = table.closed();
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].connection.host, "sniffed.example.com");
    assert_eq!(closed[0].connection.ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(closed[0].connection.route, EngineRoute::Proxy);

    proxy.shutdown();
}

#[test]
fn close_connection_actively_terminates_an_open_tcp_flow() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let sink_addr = listener.local_addr().unwrap();
    let _sink = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 64];
        while stream.read(&mut buf).unwrap_or(0) > 0 {}
    });

    let outbounds = Arc::new(Outbounds {
        direct: Arc::new(DirectDialer::new(Arc::new(LoopbackResolver))),
        proxy: None,
        exits: HashMap::new(),
    });
    let table = ConnectionTable::new();
    let router = Arc::new(Router::new(
        Arc::new(|_: &Query<'_>| Verdict::Direct),
        outbounds,
        table.clone(),
        RouterConfig::default(),
    ));
    let mut proxy = ProxyServer::bind(router, &["127.0.0.1:0".parse().unwrap()]).unwrap();
    let socks_client = Socks5Dialer::new(proxy.local_addrs()[0], None);
    let mut stream = socks_client
        .connect(&Target::socket(sink_addr), Duration::from_secs(3))
        .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    // Poll briefly until the active connection is visible.
    let mut id = None;
    for _ in 0..40 {
        if let Some(conn) = table.active().into_iter().next() {
            id = Some(conn.id);
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let id = id.expect("active connection registered");
    assert!(table.close_connection(&id));

    let mut buf = [0u8; 16];
    let read = stream.read(&mut buf).unwrap_or(0);
    assert_eq!(read, 0);

    proxy.shutdown();
}

#[test]
fn socks5_udp_associate_relays_direct_and_drops_blocked() {
    let udp_echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_addr = udp_echo.local_addr().unwrap();
    udp_echo
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let echo_thread = thread::spawn(move || {
        let mut buf = [0u8; 1024];
        while !stop_flag.load(Ordering::Acquire) {
            if let Ok((n, from)) = udp_echo.recv_from(&mut buf) {
                let mut reply = b"UDP:".to_vec();
                reply.extend_from_slice(&buf[..n]);
                let _ = udp_echo.send_to(&reply, from);
            }
        }
    });

    let outbounds = Arc::new(Outbounds {
        direct: Arc::new(DirectDialer::new(Arc::new(LoopbackResolver))),
        proxy: None,
        exits: HashMap::new(),
    });
    let table = ConnectionTable::new();
    let router = Arc::new(Router::new(
        Arc::new(|query: &Query<'_>| match query.domain {
            Some("blocked.example.com") => Verdict::Block,
            _ => Verdict::Direct,
        }),
        outbounds,
        table.clone(),
        RouterConfig {
            udp_idle: Duration::from_secs(5),
            ..RouterConfig::default()
        },
    ));
    let mut proxy = ProxyServer::bind(router, &["127.0.0.1:0".parse().unwrap()]).unwrap();
    let socks_client = Socks5Dialer::new(proxy.local_addrs()[0], None);
    let udp_path = socks_client.udp(Duration::from_secs(3)).unwrap();
    udp_path
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    // Allowed UDP flow
    udp_path
        .send_to(b"hello", &Target::socket(echo_addr))
        .unwrap();
    let mut reply = [0u8; 64];
    let (n, origin) = udp_path.recv_from(&mut reply).unwrap();
    assert_eq!(&reply[..n], b"UDP:hello");
    assert_eq!(origin, Some(echo_addr));

    // Blocked UDP flow is silently dropped.
    udp_path
        .send_to(
            b"nope",
            &Target::domain("blocked.example.com", echo_addr.port()),
        )
        .unwrap();
    udp_path
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    assert!(udp_path.recv_from(&mut reply).is_err());

    let totals = table.totals();
    assert_eq!(totals.up, 5);
    assert_eq!(totals.down, 9);

    let active = table.active();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].network, ConnectionNetwork::Udp);

    drop(udp_path);
    stop.store(true, Ordering::Release);
    proxy.shutdown();
    let _ = echo_thread.join();
}

#[test]
fn entry_server_authenticates_routes_by_account_bypasses_rules_and_hides_connections() {
    let proxy_echo = EchoServer::start(b"MAIN:");
    let exit_echo = EchoServer::start(b"EXIT:");
    let proxy_socks = MockSocksUpstream::start("m", "mp", proxy_echo.addr);
    let exit_socks = MockSocksUpstream::start("e", "ep", exit_echo.addr);
    let exit_id = ExitId::new("de");

    let mut exits = HashMap::new();
    exits.insert(
        exit_id.clone(),
        (
            "exit-0".to_owned(),
            Arc::new(Socks5Dialer::new(
                exit_socks.addr,
                Some(Credentials {
                    username: "e".into(),
                    password: "ep".into(),
                }),
            )) as Arc<dyn Dialer>,
        ),
    );
    let outbounds = Arc::new(Outbounds {
        direct: Arc::new(DirectDialer::new(Arc::new(LoopbackResolver))),
        proxy: Some(Arc::new(Socks5Dialer::new(
            proxy_socks.addr,
            Some(Credentials {
                username: "m".into(),
                password: "mp".into(),
            }),
        ))),
        exits,
    });
    let table = ConnectionTable::new();
    // User policy blocks everything — entry server must bypass it!
    let router = Arc::new(Router::new(
        Arc::new(|_: &Query<'_>| Verdict::Block),
        outbounds,
        table.clone(),
        RouterConfig::default(),
    ));

    let delay_inbound = DelayInbound::local([
        PROXY_TAG.to_owned(),
        SUBSCRIPTION_PROXY_USER.to_owned(),
        "exit-0".to_owned(),
    ])
    .unwrap();
    let accounts =
        EntryAccount::from_delay_inbound(&delay_inbound, &[("exit-0".to_owned(), exit_id)]);
    let mut entry =
        EntryServer::bind(router, "127.0.0.1:0".parse().unwrap(), accounts.clone()).unwrap();
    let entry_addr = entry.local_addr();

    // Unauthenticated client is refused.
    let unauth = Socks5Dialer::new(entry_addr, None);
    assert!(
        unauth
            .connect(&Target::domain("example.com", 443), Duration::from_secs(2))
            .is_err()
    );

    // Wrong password is refused.
    let wrong = Socks5Dialer::new(
        entry_addr,
        Some(Credentials {
            username: PROXY_TAG.to_owned(),
            password: "wrong".to_owned(),
        }),
    );
    assert!(
        wrong
            .connect(&Target::domain("example.com", 443), Duration::from_secs(2))
            .is_err()
    );

    // Subscription user goes through main proxy.
    let sub_account = accounts
        .iter()
        .find(|a| a.username == SUBSCRIPTION_PROXY_USER)
        .unwrap();
    let sub_client = Socks5Dialer::new(
        entry_addr,
        Some(Credentials {
            username: sub_account.username.clone(),
            password: sub_account.password.clone(),
        }),
    );
    let mut s = sub_client
        .connect(&Target::domain("example.com", 443), Duration::from_secs(2))
        .unwrap();
    s.write_all(b"sub").unwrap();
    let mut reply = [0u8; 8];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"MAIN:sub");
    drop(s);

    // Exit account goes through exit-0.
    let exit_account = accounts.iter().find(|a| a.username == "exit-0").unwrap();
    let exit_client = Socks5Dialer::new(
        entry_addr,
        Some(Credentials {
            username: exit_account.username.clone(),
            password: exit_account.password.clone(),
        }),
    );
    let mut s = exit_client
        .connect(&Target::domain("example.com", 443), Duration::from_secs(2))
        .unwrap();
    s.write_all(b"probe").unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"EXIT:probe");
    drop(s);

    // Entry server refuses UDP ASSOCIATE.
    assert!(exit_client.udp(Duration::from_secs(2)).is_err());

    // Internal connections never leak into the user's connection table.
    assert_eq!(table.active_count(), 0);
    assert!(table.closed().is_empty());

    entry.shutdown();
}

#[test]
fn udp_header_write_and_parse_support_ipv6() {
    let mut frame = vec![0, 0, 0];
    write_address(
        &mut frame,
        &Target::ip("2001:db8::42".parse().unwrap(), 443),
    )
    .unwrap();
    frame.extend_from_slice(b"quic");
    let (target, offset) = udp::parse_client_datagram(&frame).unwrap();
    assert_eq!(target, Target::ip("2001:db8::42".parse().unwrap(), 443));
    assert_eq!(&frame[offset..], b"quic");
}

#[test]
fn socks5_normalizes_trailing_dots_and_ip_literals_in_domain_type() {
    struct PrefixSniffer;
    impl Sniffing for PrefixSniffer {
        fn sniff_tcp(&self, stream: &mut TcpStream) -> io::Result<TcpSniff> {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf)?;
            let domain = (&buf == b"SNI!").then(|| "sniffed.example.com".to_owned());
            Ok(TcpSniff {
                domain,
                buffered: buf.to_vec(),
            })
        }

        fn sniff_udp(&self, _datagram: &[u8]) -> Option<String> {
            None
        }
    }

    let direct_echo = EchoServer::start(b"DIRECT:");
    let proxy_echo = EchoServer::start(b"PROXY:");
    let proxy_socks = MockSocksUpstream::start("u", "p", proxy_echo.addr);

    let outbounds = Arc::new(Outbounds {
        direct: Arc::new(DirectDialer::new(Arc::new(LoopbackResolver))),
        proxy: Some(Arc::new(Socks5Dialer::new(
            proxy_socks.addr,
            Some(Credentials {
                username: "u".into(),
                password: "p".into(),
            }),
        ))),
        exits: HashMap::new(),
    });
    let router = Arc::new(
        Router::new(
            Arc::new(|query: &Query<'_>| match query.domain {
                Some("blocked.example.com") => Verdict::Block,
                Some("sniffed.example.com") => Verdict::Proxy,
                _ => Verdict::Direct,
            }),
            outbounds,
            ConnectionTable::new(),
            RouterConfig::default(),
        )
        .with_sniffing(Arc::new(PrefixSniffer)),
    );
    let mut proxy = ProxyServer::bind(router, &["127.0.0.1:0".parse().unwrap()]).unwrap();
    let socks_client = Socks5Dialer::new(proxy.local_addrs()[0], None);

    // Trailing dot in ATYP=0x03 must still match the Block rule.
    let err = socks_client
        .connect(
            &Target::domain("blocked.example.com.", 443),
            Duration::from_secs(2),
        )
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

    // An IPv4 literal sent as ATYP=0x03 normalizes to Host::Ip so early sniffing runs.
    let mut stream = socks_client
        .connect(
            &Target::domain("127.0.0.1", direct_echo.addr.port()),
            Duration::from_secs(2),
        )
        .unwrap();
    stream.write_all(b"SNI!hi").unwrap();
    let mut reply = [0u8; 12];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"PROXY:SNI!hi");
    drop(stream);

    proxy.shutdown();
}

#[test]
fn plain_http_to_ip_literal_routes_by_host_header() {
    let proxy_echo = EchoServer::start(b"");
    let proxy_socks = MockSocksUpstream::start("u", "p", proxy_echo.addr);
    let outbounds = Arc::new(Outbounds {
        direct: Arc::new(DirectDialer::new(Arc::new(LoopbackResolver))),
        proxy: Some(Arc::new(Socks5Dialer::new(
            proxy_socks.addr,
            Some(Credentials {
                username: "u".into(),
                password: "p".into(),
            }),
        ))),
        exits: HashMap::new(),
    });
    let router = Arc::new(Router::new(
        Arc::new(|query: &Query<'_>| match query.domain {
            Some("blocked-host.example.com") => Verdict::Block,
            Some("proxy-host.example.com") => Verdict::Proxy,
            _ => Verdict::Direct,
        }),
        outbounds,
        ConnectionTable::new(),
        RouterConfig::default(),
    ));
    let mut proxy = ProxyServer::bind(router, &["127.0.0.1:0".parse().unwrap()]).unwrap();

    // Plain HTTP request to an IP literal with a blocked Host header -> 403.
    let mut client = TcpStream::connect(proxy.local_addrs()[0]).unwrap();
    client
        .write_all(b"GET http://192.0.2.1/test HTTP/1.1\r\nHost: blocked-host.example.com\r\n\r\n")
        .unwrap();
    let mut status = String::new();
    client.read_to_string(&mut status).unwrap();
    assert!(status.starts_with("HTTP/1.1 403"));

    // Plain HTTP request to an IP literal with a proxied Host header -> routed to proxy upstream.
    let mut client = TcpStream::connect(proxy.local_addrs()[0]).unwrap();
    client
        .write_all(b"GET http://192.0.2.1/test HTTP/1.1\r\nHost: proxy-host.example.com\r\n\r\n")
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut echoed = String::new();
    client.read_to_string(&mut echoed).unwrap();
    assert!(echoed.starts_with("GET /test HTTP/1.1\r\n"));
    assert_eq!(proxy_socks.hits.load(Ordering::Acquire), 1);

    proxy.shutdown();
}
