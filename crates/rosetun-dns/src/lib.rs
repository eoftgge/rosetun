//! A small stub resolver that sends its own queries instead of asking the
//! system resolver. Under Lockdown the system resolver cannot reach the
//! network: on Windows every lookup goes through the Dnscache service, and
//! permitting that service would let every program's lookups out. Rosetun's
//! own processes are permitted, so they ask the same servers themselves.

#![deny(unsafe_code)]

mod exchange;
mod hosts;
mod probe;
mod servers;
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;
pub mod wire;

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use exchange::Outcome;
pub use probe::{AskError, Reply, Transport, ask};

/// Each round asks every server in turn, waiting this long for each.
const ROUNDS: [Duration; 2] = [Duration::from_millis(1500), Duration::from_secs(3)];
/// CNAME chains a server leaves unfinished are followed this many times.
const MAX_ALIAS_QUERIES: usize = 8;
/// As many addresses as an HTTP client tries.
const MAX_ADDRESSES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveError {
    InvalidName,
    NotFound,
    NoServers,
    NoAnswer,
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidName => "not a valid host name",
            Self::NotFound => "the name does not exist",
            Self::NoServers => "the network adapter has no DNS server",
            Self::NoAnswer => "no DNS server answered",
        })
    }
}

impl std::error::Error for ResolveError {}

/// The addresses of `host`, IPv4 first, from an IP literal, the hosts file
/// or the DNS servers of the default network adapter, within `timeout`.
pub fn resolve(host: &str, timeout: Duration) -> Result<Vec<IpAddr>, ResolveError> {
    let deadline = Instant::now() + timeout;
    let name = match local(host) {
        Local::Addresses(addresses) => return Ok(addresses),
        Local::Name(name) => name,
    };
    let found = hosts::lookup(&name);
    if !found.is_empty() {
        return Ok(found);
    }
    let servers = servers::system();
    if servers.is_empty() {
        return Err(ResolveError::NoServers);
    }
    resolve_with(&name, &servers, &ROUNDS, deadline)
}

enum Local {
    Addresses(Vec<IpAddr>),
    Name(String),
}

fn local(host: &str) -> Local {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(address) = host.parse::<IpAddr>() {
        return Local::Addresses(vec![address]);
    }
    let name = host.trim_end_matches('.').to_ascii_lowercase();
    if name == "localhost" {
        return Local::Addresses(vec![Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()]);
    }
    Local::Name(name)
}

fn resolve_with(
    name: &str,
    servers: &[SocketAddr],
    rounds: &[Duration],
    deadline: Instant,
) -> Result<Vec<IpAddr>, ResolveError> {
    let mut name = name.to_owned();
    for _ in 0..MAX_ALIAS_QUERIES {
        let labels = wire::labels(&name).ok_or(ResolveError::InvalidName)?;
        match ask_servers(&name, &labels, servers, rounds, deadline) {
            Outcome::Addresses(mut addresses) => {
                addresses.truncate(MAX_ADDRESSES);
                return Ok(addresses);
            }
            Outcome::Alias(target) => name = target,
            Outcome::NoData | Outcome::NotFound => return Err(ResolveError::NotFound),
            Outcome::Failed => return Err(ResolveError::NoAnswer),
        }
    }
    Err(ResolveError::NotFound)
}

/// The first answer that settles the name; a server that fails or stays
/// silent passes the question to the next one.
fn ask_servers(
    name: &str,
    labels: &[&[u8]],
    servers: &[SocketAddr],
    rounds: &[Duration],
    deadline: Instant,
) -> Outcome {
    for wait in rounds {
        for server in servers {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Outcome::Failed;
            }
            match exchange::ask(*server, name, labels, (*wait).min(remaining)) {
                Outcome::Failed => {}
                settled => return settled,
            }
        }
    }
    Outcome::Failed
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::wire::test_support::{a, aaaa, cname, reply};
    use crate::wire::{TYPE_A, TYPE_AAAA};

    type Records = Vec<(&'static str, u16, Vec<u8>)>;

    /// What a fake server answers: flags and records per (name, type);
    /// `None` stays silent.
    type Zone = fn(&str, u16) -> Option<(u16, Records)>;

    fn question_of(packet: &[u8]) -> (String, u16) {
        let mut offset = 12;
        let mut labels = Vec::new();
        while packet[offset] != 0 {
            let length = usize::from(packet[offset]);
            labels.push(
                String::from_utf8_lossy(&packet[offset + 1..offset + 1 + length]).into_owned(),
            );
            offset += 1 + length;
        }
        let kind = u16::from_be_bytes([packet[offset + 1], packet[offset + 2]]);
        (labels.join("."), kind)
    }

    /// A UDP server on loopback, with a TCP listener on the same port for
    /// truncated replies. With `truncate`, UDP replies carry only the TC bit.
    fn serve(zone: Zone, truncate: bool) -> SocketAddr {
        let (udp, tcp) = loop {
            let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
            if let Ok(udp) = UdpSocket::bind(tcp.local_addr().unwrap()) {
                break (udp, tcp);
            }
        };
        let address = udp.local_addr().unwrap();
        thread::spawn(move || {
            let mut buffer = [0u8; 512];
            while let Ok((length, peer)) = udp.recv_from(&mut buffer) {
                let packet = &buffer[..length];
                let (name, kind) = question_of(packet);
                if let Some((flags, records)) = zone(&name, kind) {
                    let reply = if truncate {
                        reply(packet, flags | 0x0200, &[])
                    } else {
                        reply(packet, flags, &records)
                    };
                    let _ = udp.send_to(&reply, peer);
                }
            }
        });
        thread::spawn(move || {
            for stream in tcp.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut length = [0u8; 2];
                if stream.read_exact(&mut length).is_err() {
                    continue;
                }
                let mut packet = vec![0u8; usize::from(u16::from_be_bytes(length))];
                if stream.read_exact(&mut packet).is_err() {
                    continue;
                }
                let (name, kind) = question_of(&packet);
                if let Some((flags, records)) = zone(&name, kind) {
                    let reply = reply(&packet, flags, &records);
                    let mut message = u16::try_from(reply.len()).unwrap().to_be_bytes().to_vec();
                    message.extend_from_slice(&reply);
                    let _ = stream.write_all(&message);
                }
            }
        });
        address
    }

    /// A port that receives and never answers.
    fn silent() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        thread::spawn(move || {
            let mut buffer = [0u8; 512];
            while socket.recv_from(&mut buffer).is_ok() {}
        });
        address
    }

    const V6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];

    fn zone(name: &str, kind: u16) -> Option<(u16, Records)> {
        match (name, kind) {
            ("node.example.com", TYPE_A) => {
                Some((0x8180, vec![a("node.example.com", [192, 0, 2, 7])]))
            }
            ("node.example.com", TYPE_AAAA) => Some((0x8180, vec![aaaa("node.example.com", V6)])),
            ("sub.example.com", _) => {
                Some((0x8180, vec![cname("sub.example.com", "cdn.example.net")]))
            }
            ("cdn.example.net", TYPE_A) => {
                Some((0x8180, vec![a("cdn.example.net", [198, 51, 100, 4])]))
            }
            ("cdn.example.net", _) => Some((0x8180, Vec::new())),
            ("empty.example.com", _) => Some((0x8180, Vec::new())),
            ("refused.example.com", _) => Some((0x8185, Vec::new())),
            _ => Some((0x8183, Vec::new())),
        }
    }

    const FAST: [Duration; 2] = [Duration::from_millis(300), Duration::from_millis(300)];

    fn lookup(name: &str, servers: &[SocketAddr]) -> Result<Vec<IpAddr>, ResolveError> {
        resolve_with(
            name,
            servers,
            &FAST,
            Instant::now() + Duration::from_secs(5),
        )
    }

    #[test]
    fn a_and_aaaa_come_back_ipv4_first() {
        let server = serve(zone, false);
        assert_eq!(
            lookup("node.example.com", &[server]),
            Ok(vec![IpAddr::from([192, 0, 2, 7]), IpAddr::from(V6)])
        );
    }

    #[test]
    fn an_unfinished_cname_chain_is_asked_again() {
        let server = serve(zone, false);
        assert_eq!(
            lookup("sub.example.com", &[server]),
            Ok(vec![IpAddr::from([198, 51, 100, 4])])
        );
    }

    #[test]
    fn missing_names_and_names_without_addresses_are_not_found() {
        let server = serve(zone, false);
        assert_eq!(
            lookup("missing.example.com", &[server]),
            Err(ResolveError::NotFound)
        );
        assert_eq!(
            lookup("empty.example.com", &[server]),
            Err(ResolveError::NotFound)
        );
        assert_eq!(
            lookup("bad name.example.com", &[server]),
            Err(ResolveError::InvalidName)
        );
    }

    #[test]
    fn a_truncated_reply_is_repeated_over_tcp() {
        let server = serve(zone, true);
        assert_eq!(
            lookup("node.example.com", &[server]),
            Ok(vec![IpAddr::from([192, 0, 2, 7]), IpAddr::from(V6)])
        );
    }

    #[test]
    fn silent_and_refusing_servers_pass_to_the_next() {
        let refusing = serve(|_, _| Some((0x8185, Vec::new())), false);
        let server = serve(zone, false);
        assert_eq!(
            lookup("node.example.com", &[silent(), refusing, server]),
            Ok(vec![IpAddr::from([192, 0, 2, 7]), IpAddr::from(V6)])
        );
        assert_eq!(
            lookup("node.example.com", &[silent(), refusing]),
            Err(ResolveError::NoAnswer)
        );
    }

    #[test]
    fn the_deadline_bounds_the_whole_lookup() {
        let started = Instant::now();
        let result = resolve_with(
            "node.example.com",
            &[silent(), silent()],
            &ROUNDS,
            Instant::now() + Duration::from_millis(400),
        );
        assert_eq!(result, Err(ResolveError::NoAnswer));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn literals_and_localhost_need_no_server() {
        let addresses = |host| match local(host) {
            Local::Addresses(addresses) => Some(addresses),
            Local::Name(_) => None,
        };
        assert_eq!(
            addresses("192.0.2.1"),
            Some(vec![IpAddr::from([192, 0, 2, 1])])
        );
        assert_eq!(
            addresses("[2001:db8::7]"),
            Some(vec!["2001:db8::7".parse().unwrap()])
        );
        assert_eq!(
            addresses("LocalHost."),
            Some(vec![Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()])
        );
        assert!(
            matches!(local("Node.Example.com."), Local::Name(name) if name == "node.example.com")
        );
    }
}
