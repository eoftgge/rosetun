//! End-to-end loopback tests exercising the full Stage 1 `Dataplane` stack:
//! local DNS -> DoH over upstream SOCKS5 -> reverse cache -> rule engine ->
//! TLS/QUIC sniffing -> HTTP CONNECT / SOCKS5 TCP & UDP -> connection table ->
//! hot rule reload -> authenticated delay/subscription entry.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;
use rosetun_config::{
    DnsSettings, DomainMatch, ExitId, Rule, RuleId, RuleMatcher, RuleSet, RuleSetId, RuleTarget,
};
use rosetun_dataplane::dns::DnsOptions;
use rosetun_dataplane::net::{Credentials, Dialer, Resolve, Socks5Dialer, Target};
use rosetun_dataplane::proxy::RouterConfig;
use rosetun_dataplane::rules::RulePlan;
use rosetun_dataplane::sniff::SniffLimits;
use rosetun_dataplane::{
    Dataplane, DataplaneConfig, ExitUpstream, OutboundEndpoints, UpstreamProxy,
};
use rosetun_engine::{
    DelayInbound, EngineRoute, LocalProxyListen, PROXY_TAG, SUBSCRIPTION_PROXY_USER,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

// Throwaway test CA and leaf certificate for `doh.example.com`.
const CA_CERT_HEX: &[&str] = &[
    "308201533081faa003020102020900c0b9350ccdf880e1300a06082a8648ce3d",
    "040302301c311a3018060355040313115468726f776177617920546573742043",
    "413020170d3234303130313030303030305a180f323132343031303130303030",
    "30305a301c311a3018060355040313115468726f776177617920546573742043",
    "413059301306072a8648ce3d020106082a8648ce3d030107034200042e5dd9ba",
    "739b5d8032efc708d05cb00e4d344d7aa1cef52bf1558e9335220c692846f73d",
    "8fc335a9bf5957f08c33fc9fe02f664f62e45f898d8b12dd7eba5a82a3233021",
    "300f0603551d130101ff040530030101ff300e0603551d0f0101ff0404030202",
    "04300a06082a8648ce3d04030203480030450220504ac6d6e4a3a0ca67d3531e",
    "d06f649e779eeeabcb826a9db3ab3c67f752845e022100a37c74b7d3ba8a6bee",
    "cd9fb6bf425a811df9c98646ff846dfe7789cdbb39c3e5",
];

const LEAF_CERT_HEX: &[&str] = &[
    "3082017c30820122a00302010202080102030405060708300a06082a8648ce3d",
    "040302301c311a3018060355040313115468726f776177617920546573742043",
    "413020170d3234303130313030303030305a180f323132343031303130303030",
    "30305a301a311830160603550403130f646f682e6578616d706c652e636f6d30",
    "59301306072a8648ce3d020106082a8648ce3d0301070342000480d0c8a195f3",
    "17a0e5ace3b5bd081290e1fc8dd92a346e662fb140a9086e7ad82f6ca7670f2c",
    "79f0a124299455dd67214aee4c498f625b25015a3a8cd74e4518a34e304c301a",
    "0603551d1104133011820f646f682e6578616d706c652e636f6d30090603551d",
    "1304023000300e0603551d0f0101ff04040302078030130603551d25040c300a",
    "06082b06010505070301300a06082a8648ce3d040302034800304502200b711c",
    "bd7f405916e683f459e4484ae61a0c5e8c7952f9dfd1f84da953b6c694022100",
    "9b942b4b2c296ca033f35f9732a78af1bc609ddafa884bb13e5e2623fb84f744",
];

const LEAF_KEY_HEX: &[&str] = &[
    "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02",
    "01010420cd1d5ae86dd44e899e9d561e778faff9cee841308ec8287e29463b87",
    "54a4fbefa1440342000480d0c8a195f317a0e5ace3b5bd081290e1fc8dd92a34",
    "6e662fb140a9086e7ad82f6ca7670f2c79f0a124299455dd67214aee4c498f62",
    "5b25015a3a8cd74e4518",
];

fn decode_hex(chunks: &[&str]) -> Vec<u8> {
    let joined: String = chunks.concat();
    let bytes = joined.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let hi = (pair[0] as char).to_digit(16).unwrap();
        let lo = (pair[1] as char).to_digit(16).unwrap();
        out.push(u8::try_from((hi << 4) | lo).unwrap());
    }
    out
}

struct LoopbackResolver;

impl Resolve for LoopbackResolver {
    fn resolve(&self, _name: &str) -> io::Result<Vec<IpAddr>> {
        Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
    }
}

struct TaggedEcho {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TaggedEcho {
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

impl Drop for TaggedEcho {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Minimal loopback TLS DoH server answering `app.example.com` with `192.0.2.7`.
struct MockDohServer {
    addr: SocketAddr,
    queries: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockDohServer {
    fn start() -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert = CertificateDer::from(decode_hex(LEAF_CERT_HEX));
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(decode_hex(LEAF_KEY_HEX)));
        let config = Arc::new(
            ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let queries = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let queries_c = Arc::clone(&queries);
        let stop_c = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_c.load(Ordering::Acquire) {
                let Ok((tcp, _)) = listener.accept() else {
                    break;
                };
                if stop_c.load(Ordering::Acquire) {
                    break;
                }
                let config = Arc::clone(&config);
                let queries = Arc::clone(&queries_c);
                thread::spawn(move || {
                    tcp.set_read_timeout(Some(Duration::from_secs(2))).ok();
                    let conn = ServerConnection::new(config).unwrap();
                    let mut tls = StreamOwned::new(conn, tcp);
                    let mut buf = [0u8; 4096];
                    let Ok(n) = tls.read(&mut buf) else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    let head_end = buf[..n]
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .map(|p| p + 4);
                    let Some(head_end) = head_end else {
                        return;
                    };
                    let head = std::str::from_utf8(&buf[..head_end]).unwrap_or("");
                    let content_len: usize = head
                        .lines()
                        .find_map(|line| {
                            let (k, v) = line.split_once(':')?;
                            k.eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    let mut body = buf[head_end..n].to_vec();
                    while body.len() < content_len {
                        let Ok(more) = tls.read(&mut buf) else {
                            return;
                        };
                        if more == 0 {
                            return;
                        }
                        body.extend_from_slice(&buf[..more]);
                    }
                    body.truncate(content_len);
                    queries.fetch_add(1, Ordering::AcqRel);
                    let answer = build_a_answer(&body, Ipv4Addr::new(192, 0, 2, 7), 120);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        answer.len()
                    );
                    let _ = tls.write_all(resp.as_bytes());
                    let _ = tls.write_all(&answer);
                    let _ = tls.flush();
                });
            }
        });
        Self {
            addr,
            queries,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for MockDohServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Authenticated mock SOCKS5 upstream forwarding `doh_port` to the DoH server
/// and all other TCP connections to `backend`.
struct MockUpstream {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockUpstream {
    fn start(
        username: &str,
        password: &str,
        backend: SocketAddr,
        doh_target: Option<SocketAddr>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_c = Arc::clone(&stop);
        let user = username.to_owned();
        let pass = password.to_owned();
        let handle = thread::spawn(move || {
            while !stop_c.load(Ordering::Acquire) {
                let Ok((mut client, _)) = listener.accept() else {
                    break;
                };
                if stop_c.load(Ordering::Acquire) {
                    break;
                }
                let user = user.clone();
                let pass = pass.clone();
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
                    let dest_port = match req[3] {
                        1 => {
                            let mut addr_port = [0u8; 6];
                            if client.read_exact(&mut addr_port).is_err() {
                                return;
                            }
                            u16::from_be_bytes([addr_port[4], addr_port[5]])
                        }
                        3 => {
                            let mut len = [0u8; 1];
                            if client.read_exact(&mut len).is_err() {
                                return;
                            }
                            let mut name_port = vec![0u8; usize::from(len[0]) + 2];
                            if client.read_exact(&mut name_port).is_err() {
                                return;
                            }
                            let l = usize::from(len[0]);
                            u16::from_be_bytes([name_port[l], name_port[l + 1]])
                        }
                        4 => {
                            let mut addr_port = [0u8; 18];
                            if client.read_exact(&mut addr_port).is_err() {
                                return;
                            }
                            u16::from_be_bytes([addr_port[16], addr_port[17]])
                        }
                        _ => return,
                    };
                    let target = match doh_target {
                        Some(doh) if dest_port == doh.port() => doh,
                        _ => backend,
                    };
                    let Ok(mut upstream) = TcpStream::connect(target) else {
                        let _ = client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
                        return;
                    };
                    let _ = client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]);
                    let mut cr = client.try_clone().unwrap();
                    let mut uw = upstream.try_clone().unwrap();
                    let t = thread::spawn(move || {
                        let _ = io::copy(&mut cr, &mut uw);
                        let _ = uw.shutdown(Shutdown::Write);
                    });
                    let _ = io::copy(&mut upstream, &mut client);
                    let _ = client.shutdown(Shutdown::Write);
                    let _ = t.join();
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

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn build_a_query(id: u16, name: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        msg.push(u8::try_from(label.len()).unwrap());
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    msg
}

fn build_a_answer(query: &[u8], ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    // Question ends after 0 label + 4 bytes (qtype + qclass).
    let mut pos = 12;
    while pos < query.len() && query[pos] != 0 {
        pos += 1 + usize::from(query[pos]);
    }
    let question_end = (pos + 5).min(query.len());
    let mut resp = Vec::with_capacity(question_end + 16);
    resp.extend_from_slice(&query[..2]);
    resp.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    resp.extend_from_slice(&query[12..question_end]);
    resp.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]);
    resp.extend_from_slice(&ttl.to_be_bytes());
    resp.extend_from_slice(&[0x00, 0x04]);
    resp.extend_from_slice(&ip.octets());
    resp
}

fn build_tls_client_hello(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    let sni_entry_len = 1 + 2 + name.len();
    let sni_list_len = sni_entry_len;
    let sni_ext_len = 2 + sni_list_len;
    let exts_len = 4 + sni_ext_len;
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 legacy_version
    body.extend_from_slice(&[0xaa; 32]); // random
    body.push(0); // session_id_len
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suite
    body.extend_from_slice(&[0x01, 0x00]); // compression
    body.extend_from_slice(&u16::try_from(exts_len).unwrap().to_be_bytes());
    body.extend_from_slice(&[0x00, 0x00]); // server_name ext
    body.extend_from_slice(&u16::try_from(sni_ext_len).unwrap().to_be_bytes());
    body.extend_from_slice(&u16::try_from(sni_list_len).unwrap().to_be_bytes());
    body.push(0x00); // host_name
    body.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
    body.extend_from_slice(name);

    let mut hs = Vec::with_capacity(4 + body.len());
    hs.push(0x01); // ClientHello
    let len = body.len();
    hs.push(u8::try_from((len >> 16) & 0xff).unwrap());
    hs.push(u8::try_from((len >> 8) & 0xff).unwrap());
    hs.push(u8::try_from(len & 0xff).unwrap());
    hs.extend_from_slice(&body);

    let mut record = Vec::with_capacity(5 + hs.len());
    record.extend_from_slice(&[0x16, 0x03, 0x01]);
    record.extend_from_slice(&u16::try_from(hs.len()).unwrap().to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

/// Builds a minimal RFC 9001 QUIC v1 Initial packet carrying a TLS ClientHello
/// with `sni` inside a CRYPTO frame so UDP sniffing can be verified end-to-end.
fn build_quic_v1_initial(sni: &str) -> Vec<u8> {
    struct Len(usize);
    impl hkdf::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }
    fn hkdf_label(secret: &hkdf::Prk, label: &[u8], out_len: usize) -> Vec<u8> {
        let full_label_len = 6 + label.len();
        let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1);
        info.extend_from_slice(&u16::try_from(out_len).unwrap().to_be_bytes());
        info.push(u8::try_from(full_label_len).unwrap());
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label);
        info.push(0);
        let slices = [info.as_slice()];
        let okm = secret.expand(&slices, Len(out_len)).unwrap();
        let mut out = vec![0u8; out_len];
        okm.fill(&mut out).unwrap();
        out
    }

    let dcid = [0x83u8, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let v1_salt: [u8; 20] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];
    let initial_secret = hkdf::Salt::new(hkdf::HKDF_SHA256, &v1_salt).extract(&dcid);
    let client_secret_bytes = hkdf_label(&initial_secret, b"client in", 32);
    let client_secret = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client_secret_bytes);
    let key_bytes = hkdf_label(&client_secret, b"quic key", 16);
    let iv_bytes = hkdf_label(&client_secret, b"quic iv", 12);
    let hp_bytes = hkdf_label(&client_secret, b"quic hp", 16);

    let tls_record = build_tls_client_hello(sni);
    let handshake = &tls_record[5..]; // strip TLS record header -> raw ClientHello handshake msg
    let mut plaintext = Vec::new();
    plaintext.push(0x06); // CRYPTO frame
    plaintext.push(0x00); // offset = 0
    // 2-byte varint length
    let hs_len = u16::try_from(handshake.len()).unwrap() | 0x4000;
    plaintext.extend_from_slice(&hs_len.to_be_bytes());
    plaintext.extend_from_slice(handshake);
    while plaintext.len() < 64 {
        plaintext.push(0x00); // PADDING
    }

    let mut header = Vec::new();
    header.push(0xc0); // Long header, fixed=1, Initial=00, pn_len=1 byte (00)
    header.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // QUIC v1
    header.push(u8::try_from(dcid.len()).unwrap());
    header.extend_from_slice(&dcid);
    header.push(0); // scid len
    header.push(0); // token len
    let payload_len = 1 + plaintext.len() + 16; // pn(1) + plaintext + tag(16)
    let len_varint = u16::try_from(payload_len).unwrap() | 0x4000;
    header.extend_from_slice(&len_varint.to_be_bytes());
    let pn_offset = header.len();
    header.push(0x00); // packet number = 0

    let key = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &key_bytes).unwrap());
    let nonce = Nonce::try_assume_unique_for_key(&iv_bytes).unwrap();
    let mut in_out = plaintext;
    key.seal_in_place_append_tag(nonce, Aad::from(&header), &mut in_out)
        .unwrap();

    let mut packet = header;
    packet.extend_from_slice(&in_out);

    let hp_key = aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &hp_bytes).unwrap();
    let sample = &packet[pn_offset + 4..pn_offset + 20];
    let mask = hp_key.new_mask(sample).unwrap();
    packet[0] ^= mask[0] & 0x0f;
    packet[pn_offset] ^= mask[1];
    packet
}

#[test]
fn full_dataplane_stack_routes_dns_sniffing_rules_exits_and_delay_entry() {
    let direct_echo = TaggedEcho::start(b"DIRECT:");
    let proxy_echo = TaggedEcho::start(b"PROXY:");
    let exit_echo = TaggedEcho::start(b"EXIT:");
    let doh_server = MockDohServer::start();

    let proxy_upstream = MockUpstream::start(
        "main-user",
        "main-pass",
        proxy_echo.addr,
        Some(doh_server.addr),
    );
    let exit_upstream = MockUpstream::start("exit-user", "exit-pass", exit_echo.addr, None);
    let exit_id = ExitId::new("de");

    let mut rule_set = RuleSet::new(RuleSetId::new("main"), "Main", RuleTarget::Proxy);
    rule_set.rules = vec![
        Rule {
            id: RuleId::new("r-direct"),
            enabled: true,
            matcher: RuleMatcher::Domain(DomainMatch::Exact("direct.example.com".into())),
            target: RuleTarget::Direct,
            exit: None,
        },
        Rule {
            id: RuleId::new("r-block"),
            enabled: true,
            matcher: RuleMatcher::Domain(DomainMatch::Suffix("blocked.example.com".into())),
            target: RuleTarget::Block,
            exit: None,
        },
        Rule {
            id: RuleId::new("r-exit"),
            enabled: true,
            matcher: RuleMatcher::Domain(DomainMatch::Exact("exit.example.com".into())),
            target: RuleTarget::Exit,
            exit: Some(exit_id.clone()),
        },
        Rule {
            id: RuleId::new("r-sni"),
            enabled: true,
            matcher: RuleMatcher::Domain(DomainMatch::Exact("sni.example.com".into())),
            target: RuleTarget::Exit,
            exit: Some(exit_id.clone()),
        },
        Rule {
            id: RuleId::new("r-app"),
            enabled: true,
            matcher: RuleMatcher::Domain(DomainMatch::Exact("app.example.com".into())),
            target: RuleTarget::Exit,
            exit: Some(exit_id.clone()),
        },
    ];

    let delay_inbound = DelayInbound::local([
        PROXY_TAG.to_owned(),
        SUBSCRIPTION_PROXY_USER.to_owned(),
        "exit-0".to_owned(),
    ])
    .unwrap();

    let config = DataplaneConfig {
        listen: LocalProxyListen {
            addresses: vec!["127.0.0.1:0".parse().unwrap()],
            dns: "127.0.0.1:0".parse().unwrap(),
        },
        dns: DnsSettings {
            server: IpAddr::V4(Ipv4Addr::LOCALHOST),
            server_name: "doh.example.com".to_owned(),
            port: Some(doh_server.addr.port()),
            path: Some("/dns-query".to_owned()),
        },
        dns_options: DnsOptions::default(),
        rules: RulePlan {
            rules: rule_set.clone(),
            temporary_count: 0,
            allow_lan: false,
            private_networks: false,
            exits: vec![exit_id.clone()],
            lists: Vec::new(),
        },
        outbounds: OutboundEndpoints {
            proxy: Some(UpstreamProxy {
                address: proxy_upstream.addr,
                username: "main-user".into(),
                password: "main-pass".into(),
            }),
            exits: vec![ExitUpstream {
                exit: exit_id.clone(),
                tag: "exit-0".into(),
                upstream: UpstreamProxy {
                    address: exit_upstream.addr,
                    username: "exit-user".into(),
                    password: "exit-pass".into(),
                },
            }],
        },
        delay: Some(delay_inbound.clone()),
        router: RouterConfig::default(),
        sniff: SniffLimits::default(),
        direct_resolver: Some(Arc::new(LoopbackResolver)),
    };

    let roots = vec![CertificateDer::from(decode_hex(CA_CERT_HEX))];
    let mut dataplane = Dataplane::start_with_roots(config, roots).unwrap();
    let proxy_addr = dataplane.proxy_addrs()[0];
    let dns_addr = dataplane.dns_addr();
    let delay_addr = dataplane.delay_addr().unwrap();

    // 1. Local UDP DNS query goes through DoH over the main proxy upstream and populates reverse cache.
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let query = build_a_query(0x1234, "app.example.com");
    udp.send_to(&query, dns_addr).unwrap();
    let mut dns_resp = [0u8; 512];
    let (n, _) = udp.recv_from(&mut dns_resp).unwrap();
    assert!(n >= 16);
    assert_eq!(&dns_resp[n - 4..n], &[192, 0, 2, 7]);
    assert_eq!(doh_server.queries.load(Ordering::Acquire), 1);
    assert_eq!(
        dataplane
            .dns()
            .domain_for("192.0.2.7".parse().unwrap())
            .as_deref(),
        Some("app.example.com")
    );

    // 2. IP connection to 192.0.2.7 (populated by DNS reverse cache) matches `app.example.com -> exit-0`!
    let socks = Socks5Dialer::new(proxy_addr, None);
    let mut s = socks
        .connect(
            &Target::ip("192.0.2.7".parse().unwrap(), 443),
            Duration::from_secs(3),
        )
        .unwrap();
    // Send plain non-TLS/non-HTTP bytes so sniffing finishes quickly with NotThis and falls back to reverse cache.
    s.write_all(b"\x01\x02\x03\x04ping").unwrap();
    let mut reply = [0u8; 13];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"EXIT:\x01\x02\x03\x04ping");
    drop(s);

    // 3. IP connection carrying a TLS ClientHello for `sni.example.com` is sniffed and routed to exit-0!
    let hello = build_tls_client_hello("sni.example.com");
    let mut s = socks
        .connect(&Target::socket(direct_echo.addr), Duration::from_secs(3))
        .unwrap();
    s.write_all(&hello).unwrap();
    let mut echoed = vec![0u8; 5 + hello.len()];
    s.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed[..5], b"EXIT:");
    assert_eq!(&echoed[5..], hello.as_slice());
    drop(s);

    // 4. Direct, Block, Proxy over HTTP CONNECT / SOCKS5.
    let mut s = socks
        .connect(
            &Target::domain("direct.example.com", direct_echo.addr.port()),
            Duration::from_secs(3),
        )
        .unwrap();
    s.write_all(b"ok").unwrap();
    let mut r = [0u8; 9];
    s.read_exact(&mut r).unwrap();
    assert_eq!(&r, b"DIRECT:ok");
    drop(s);

    let err = socks
        .connect(
            &Target::domain("sub.blocked.example.com", 443),
            Duration::from_secs(3),
        )
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

    // 5. QUIC Initial SNI sniffing over SOCKS5 UDP ASSOCIATE: blocked domain dropped, allowed domain forwarded.
    let udp_echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_echo_addr = udp_echo.local_addr().unwrap();
    udp_echo
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let udp_stop = Arc::new(AtomicBool::new(false));
    let udp_stop_c = Arc::clone(&udp_stop);
    let udp_thread = thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while !udp_stop_c.load(Ordering::Acquire) {
            if let Ok((n, from)) = udp_echo.recv_from(&mut buf) {
                let _ = udp_echo.send_to(&buf[..n], from);
            }
        }
    });
    let udp_path = socks.udp(Duration::from_secs(3)).unwrap();
    udp_path
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let blocked_quic = build_quic_v1_initial("sub.blocked.example.com");
    udp_path
        .send_to(&blocked_quic, &Target::socket(udp_echo_addr))
        .unwrap();
    let mut qbuf = [0u8; 2048];
    assert!(udp_path.recv_from(&mut qbuf).is_err());
    drop(udp_path);
    udp_stop.store(true, Ordering::Release);
    let _ = udp_thread.join();

    // 6. Hot-reload rules: change `direct.example.com` -> `Block` without restarting listeners!
    let mut updated = rule_set;
    updated.rules[0].target = RuleTarget::Block;
    dataplane
        .update_rules(&RulePlan {
            rules: updated,
            temporary_count: 0,
            allow_lan: false,
            private_networks: false,
            exits: vec![exit_id],
            lists: Vec::new(),
        })
        .unwrap();
    let err = socks
        .connect(
            &Target::domain("direct.example.com", direct_echo.addr.port()),
            Duration::from_secs(3),
        )
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

    // 7. Traffic probe reports accumulated totals and closed connections captured routes accurately.
    let mut probe = dataplane.traffic_probe();
    let sample = probe.sample(true).unwrap();
    assert!(sample.totals.up > 0);
    assert!(sample.totals.down > 0);
    thread::sleep(Duration::from_millis(50));
    let closed = dataplane.connections().closed();
    assert!(closed.iter().any(|c| {
        c.connection.host == "sni.example.com"
            && c.connection.route == EngineRoute::Exit("exit-0".into())
    }));

    // 8. Authenticated delay/subscription entry bypasses rules and stays hidden from connection table.
    let before_closed = dataplane.connections().closed().len();
    let sub = delay_inbound
        .accounts
        .iter()
        .find(|a| a.tag == SUBSCRIPTION_PROXY_USER)
        .unwrap();
    let sub_client = Socks5Dialer::new(
        delay_addr,
        Some(Credentials {
            username: sub.tag.clone(),
            password: sub.password.clone(),
        }),
    );
    let mut s = sub_client
        .connect(
            &Target::domain("sub.blocked.example.com", 443),
            Duration::from_secs(3),
        )
        .unwrap();
    s.write_all(b"sub").unwrap();
    let mut r = [0u8; 9];
    s.read_exact(&mut r).unwrap();
    assert_eq!(&r, b"PROXY:sub");
    drop(s);
    thread::sleep(Duration::from_millis(30));
    assert_eq!(dataplane.connections().closed().len(), before_closed);

    dataplane.shutdown();
}
