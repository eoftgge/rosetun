//! Outbound dialing shared by the router and the DNS client: a destination,
//! name resolution, a direct dialer and a SOCKS5 client dialer.
//!
//! A destination is the user's browsing history, so no type here prints one.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

const SOCKS_VERSION: u8 = 5;
const METHOD_NONE: u8 = 0x00;
const METHOD_PASSWORD: u8 = 0x02;
const METHOD_REFUSED: u8 = 0xff;
const COMMAND_CONNECT: u8 = 0x01;
const COMMAND_UDP_ASSOCIATE: u8 = 0x03;
const ADDRESS_V4: u8 = 0x01;
const ADDRESS_DOMAIN: u8 = 0x03;
const ADDRESS_V6: u8 = 0x04;

/// Where a flow goes: a name the peer asked for, or an address.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Host {
    Domain(String),
    Ip(IpAddr),
}

impl fmt::Debug for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Domain(_) => "Host::Domain",
            Self::Ip(_) => "Host::Ip",
        })
    }
}

/// A destination host and port. `Debug` shows nothing but the kind.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}

impl Target {
    pub fn domain(name: impl Into<String>, port: u16) -> Self {
        Self {
            host: Host::Domain(name.into()),
            port,
        }
    }

    pub fn ip(address: IpAddr, port: u16) -> Self {
        Self {
            host: Host::Ip(address),
            port,
        }
    }

    pub fn socket(address: SocketAddr) -> Self {
        Self::ip(address.ip(), address.port())
    }

    /// The destination as a `host:port` text for protocols that carry it.
    /// Never log the result.
    pub fn authority(&self) -> String {
        match &self.host {
            Host::Domain(name) => format!("{name}:{}", self.port),
            Host::Ip(IpAddr::V4(ip)) => format!("{ip}:{}", self.port),
            Host::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{}", self.port),
        }
    }
}

impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Target")
            .field("domain", &matches!(self.host, Host::Domain(_)))
            .finish_non_exhaustive()
    }
}

/// Normalizes a host string from SOCKS5 `ATYP=0x03` or HTTP authorities:
/// parses IP literals into [`Host::Ip`], strips trailing dots, lowercases,
/// and rejects empty or syntactically invalid hosts.
pub(crate) fn normalize_host(raw: &str) -> Option<Host> {
    if raw.is_empty() || raw.len() > 255 {
        return None;
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(Host::Ip(ip));
    }
    if let Some(inner) = raw.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return inner
            .parse::<Ipv6Addr>()
            .ok()
            .map(|v6| Host::Ip(IpAddr::V6(v6)));
    }
    if raw.bytes().any(|byte| {
        byte.is_ascii_whitespace() || byte.is_ascii_control() || matches!(byte, b'/' | b':')
    }) {
        return None;
    }
    let trimmed = raw.trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return None;
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(Host::Ip(ip));
    }
    Some(Host::Domain(trimmed.to_lowercase()))
}

/// Name resolution as the router and the direct dialer use it.
pub trait Resolve: Send + Sync {
    /// The addresses of `name`, in the order they should be tried.
    fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>>;
}

/// The operating system's resolver.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        let addresses: Vec<IpAddr> = (name, 0)
            .to_socket_addrs()?
            .map(|address| address.ip())
            .collect();
        if addresses.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "name not resolved"));
        }
        Ok(addresses)
    }
}

/// Opens an outbound TCP connection. Every implementation hands back a
/// connected [`TcpStream`], so the connection table can shut it down.
pub trait Dialer: Send + Sync + fmt::Debug {
    fn connect(&self, target: &Target, timeout: Duration) -> io::Result<TcpStream>;

    /// A UDP socket for datagrams to `target`s, relayed as the dialer
    /// relays TCP. The returned [`UdpPath`] sends and receives complete
    /// datagrams with their remote address.
    fn udp(&self, timeout: Duration) -> io::Result<UdpPath>;

    /// Opens a UDP path tailored to `target`'s address family when known.
    fn udp_for(&self, target: &Target, timeout: Duration) -> io::Result<UdpPath> {
        let _ = target;
        self.udp(timeout)
    }
}

/// A way to exchange UDP datagrams with remote peers through one outbound.
pub struct UdpPath {
    v4: Option<UdpSocket>,
    v6: Option<UdpSocket>,
    preferred: Arc<AtomicU8>,
    relay: Option<SocketAddr>,
    resolver: Option<Arc<dyn Resolve>>,
    /// Keeps the SOCKS5 association alive for as long as the path lives.
    _association: Option<TcpStream>,
}

impl fmt::Debug for UdpPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpPath")
            .field("relayed", &self.relay.is_some())
            .finish_non_exhaustive()
    }
}

impl UdpPath {
    pub(crate) fn set_nonblocking(&self, enabled: bool) -> io::Result<()> {
        for socket in self.v4.iter().chain(&self.v6) {
            socket.set_nonblocking(enabled)?;
        }
        Ok(())
    }

    pub(crate) fn recv_sockets(&self) -> (Option<&UdpSocket>, Option<&UdpSocket>) {
        match self.relay {
            Some(relay) => {
                if relay.is_ipv4() {
                    (self.v4.as_ref(), None)
                } else {
                    (None, self.v6.as_ref())
                }
            }
            None => (self.v4.as_ref(), self.v6.as_ref()),
        }
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        if let Some(socket) = &self.v4 {
            socket.set_read_timeout(timeout)?;
        }
        if let Some(socket) = &self.v6 {
            socket.set_read_timeout(timeout)?;
        }
        Ok(())
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            v4: match &self.v4 {
                Some(socket) => Some(socket.try_clone()?),
                None => None,
            },
            v6: match &self.v6 {
                Some(socket) => Some(socket.try_clone()?),
                None => None,
            },
            preferred: Arc::clone(&self.preferred),
            relay: self.relay,
            resolver: self.resolver.as_ref().map(Arc::clone),
            _association: match &self._association {
                Some(stream) => Some(stream.try_clone()?),
                None => None,
            },
        })
    }

    fn socket_for_family(&self, is_v4: bool) -> io::Result<&UdpSocket> {
        let socket = if is_v4 {
            self.v4.as_ref()
        } else {
            self.v6.as_ref()
        };
        socket.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "address family is not available on this UDP path",
            )
        })
    }

    /// Sends one datagram to `target`. A direct path resolves names with its
    /// configured resolver; a relayed path carries names as they are.
    pub fn send_to(&self, payload: &[u8], target: &Target) -> io::Result<()> {
        match self.relay {
            Some(relay) => {
                let mut frame = Vec::with_capacity(payload.len() + 24);
                frame.extend_from_slice(&[0, 0, 0]);
                write_address(&mut frame, target)?;
                frame.extend_from_slice(payload);
                self.socket_for_family(relay.is_ipv4())?
                    .send_to(&frame, relay)?;
            }
            None => {
                let ip = match &target.host {
                    Host::Ip(ip) => *ip,
                    Host::Domain(name) => {
                        let resolver = self.resolver.as_ref().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "a direct datagram needs an address",
                            )
                        })?;
                        let addresses = resolver.resolve(name)?;
                        addresses
                            .into_iter()
                            .find(|address| {
                                (address.is_ipv4() && self.v4.is_some())
                                    || (address.is_ipv6() && self.v6.is_some())
                            })
                            .ok_or_else(|| {
                                io::Error::new(io::ErrorKind::NotFound, "name not resolved")
                            })?
                    }
                };
                let is_v4 = ip.is_ipv4();
                let socket = self.socket_for_family(is_v4)?;
                self.preferred
                    .store(if is_v4 { 4 } else { 6 }, Ordering::Release);
                socket.send_to(payload, SocketAddr::new(ip, target.port))?;
            }
        }
        Ok(())
    }

    /// Receives one datagram; returns its length in `buffer` and the sender
    /// address when the path knows it (relayed paths report the origin the
    /// relay names, domain origins as `None`).
    pub fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
        let mut scratch = Vec::new();
        self.recv_from_into(buffer, &mut scratch)
    }

    /// Like [`Self::recv_from`], reusing `scratch` for the SOCKS5 UDP header
    /// envelope on relayed paths so polling does not allocate on every call.
    pub(crate) fn recv_from_into(
        &self,
        buffer: &mut [u8],
        scratch: &mut Vec<u8>,
    ) -> io::Result<(usize, Option<SocketAddr>)> {
        match self.relay {
            Some(relay) => {
                let socket = self.socket_for_family(relay.is_ipv4())?;
                let needed = buffer.len() + 262;
                if scratch.len() < needed {
                    scratch.resize(needed, 0);
                }
                let frame = &mut scratch[..needed];
                loop {
                    let (length, from) = socket.recv_from(frame)?;
                    if from != relay {
                        continue;
                    }
                    let Some((origin, header)) = parse_udp_header(&frame[..length]) else {
                        continue;
                    };
                    let payload = &frame[header..length];
                    let count = payload.len().min(buffer.len());
                    buffer[..count].copy_from_slice(&payload[..count]);
                    return Ok((count, origin));
                }
            }
            None => {
                let socket = match self.preferred.load(Ordering::Acquire) {
                    6 => self.v6.as_ref().or(self.v4.as_ref()),
                    4 => self.v4.as_ref().or(self.v6.as_ref()),
                    _ => self.v4.as_ref().or(self.v6.as_ref()),
                }
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "UDP path has no bound socket")
                })?;
                let (length, from) = socket.recv_from(buffer)?;
                Ok((length, Some(from)))
            }
        }
    }
}

/// Dials from this computer's own network, resolving names with `resolver`.
pub struct DirectDialer {
    resolver: Arc<dyn Resolve>,
    binding: Option<crate::tun::PhysicalEgress>,
}

impl fmt::Debug for DirectDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectDialer").finish_non_exhaustive()
    }
}

impl DirectDialer {
    pub fn new(resolver: Arc<dyn Resolve>) -> Self {
        Self {
            resolver,
            binding: None,
        }
    }

    /// Uses only the requested physical egress. A failed socket option fails
    /// the call instead of falling back into the captured default route.
    pub fn on_physical_network(
        resolver: Arc<dyn Resolve>,
        binding: crate::tun::PhysicalEgress,
    ) -> Self {
        Self {
            resolver,
            binding: Some(binding),
        }
    }

    fn tcp(&self, address: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        match self.binding {
            Some(binding) => binding.connect(address, timeout),
            None => TcpStream::connect_timeout(&address, timeout),
        }
    }

    fn bind_udp(&self, address: SocketAddr) -> io::Result<UdpSocket> {
        match self.binding {
            Some(binding) => binding.bind_udp(address),
            None => UdpSocket::bind(address),
        }
    }
}

impl Default for DirectDialer {
    fn default() -> Self {
        Self::new(Arc::new(SystemResolver))
    }
}

impl Dialer for DirectDialer {
    fn connect(&self, target: &Target, timeout: Duration) -> io::Result<TcpStream> {
        let addresses = match &target.host {
            Host::Ip(ip) => vec![*ip],
            Host::Domain(name) => self.resolver.resolve(name)?,
        };
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no address to connect to");
        for ip in addresses {
            match self.tcp(SocketAddr::new(ip, target.port), timeout) {
                Ok(stream) => {
                    stream.set_nodelay(true).ok();
                    return Ok(stream);
                }
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    fn udp(&self, _timeout: Duration) -> io::Result<UdpPath> {
        let v4 = self.bind_udp(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        let v6 = self.bind_udp(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)));
        let (v4, v6) = match (v4, v6) {
            (Ok(s4), Ok(s6)) => (Some(s4), Some(s6)),
            (Ok(s4), Err(_)) => (Some(s4), None),
            (Err(_), Ok(s6)) => (None, Some(s6)),
            (Err(err), Err(_)) => return Err(err),
        };
        Ok(UdpPath {
            v4,
            v6,
            preferred: Arc::new(AtomicU8::new(0)),
            relay: None,
            resolver: Some(Arc::clone(&self.resolver)),
            _association: None,
        })
    }

    fn udp_for(&self, target: &Target, _timeout: Duration) -> io::Result<UdpPath> {
        let wants_v6 = match &target.host {
            Host::Ip(ip) => ip.is_ipv6(),
            Host::Domain(name) => self
                .resolver
                .resolve(name)
                .ok()
                .and_then(|addrs| addrs.into_iter().next())
                .is_some_and(|ip| ip.is_ipv6()),
        };
        let (v4, v6, preferred) = if wants_v6 {
            (
                None,
                Some(self.bind_udp(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))?),
                6,
            )
        } else {
            (
                Some(self.bind_udp(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?),
                None,
                4,
            )
        };
        Ok(UdpPath {
            v4,
            v6,
            preferred: Arc::new(AtomicU8::new(preferred)),
            relay: None,
            resolver: Some(Arc::clone(&self.resolver)),
            _association: None,
        })
    }
}

/// A SOCKS5 account.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Dials through a SOCKS5 server, an engine's authenticated loopback entry
/// as a rule. Names go to the server as they are (SOCKS5h).
#[derive(Clone, PartialEq, Eq)]
pub struct Socks5Dialer {
    upstream: SocketAddr,
    credentials: Option<Credentials>,
}

impl fmt::Debug for Socks5Dialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5Dialer")
            .field("authenticated", &self.credentials.is_some())
            .finish_non_exhaustive()
    }
}

impl Socks5Dialer {
    pub fn new(upstream: SocketAddr, credentials: Option<Credentials>) -> Self {
        Self {
            upstream,
            credentials,
        }
    }

    fn open(&self, timeout: Duration) -> io::Result<TcpStream> {
        let mut stream = TcpStream::connect_timeout(&self.upstream, timeout)?;
        stream.set_nodelay(true).ok();
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        negotiate(&mut stream, self.credentials.as_ref())?;
        Ok(stream)
    }
}

impl Dialer for Socks5Dialer {
    fn connect(&self, target: &Target, timeout: Duration) -> io::Result<TcpStream> {
        let mut stream = self.open(timeout)?;
        let mut request = vec![SOCKS_VERSION, COMMAND_CONNECT, 0];
        write_address(&mut request, target)?;
        stream.write_all(&request)?;
        read_reply(&mut stream)?;
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(None)?;
        Ok(stream)
    }

    fn udp(&self, timeout: Duration) -> io::Result<UdpPath> {
        let mut stream = self.open(timeout)?;
        let mut request = vec![SOCKS_VERSION, COMMAND_UDP_ASSOCIATE, 0];
        write_address(
            &mut request,
            &Target::ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        )?;
        stream.write_all(&request)?;
        let bound = read_reply(&mut stream)?;
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(None)?;
        // A server that binds the wildcard is reached on the address we dialed.
        let relay = SocketAddr::new(
            if bound.ip().is_unspecified() {
                self.upstream.ip()
            } else {
                bound.ip()
            },
            bound.port(),
        );
        let (v4, v6, preferred) = if relay.is_ipv4() {
            (
                Some(UdpSocket::bind(SocketAddr::from((
                    Ipv4Addr::UNSPECIFIED,
                    0,
                )))?),
                None,
                4,
            )
        } else {
            (
                None,
                Some(UdpSocket::bind(SocketAddr::from((
                    Ipv6Addr::UNSPECIFIED,
                    0,
                )))?),
                6,
            )
        };
        Ok(UdpPath {
            v4,
            v6,
            preferred: Arc::new(AtomicU8::new(preferred)),
            relay: Some(relay),
            resolver: None,
            _association: Some(stream),
        })
    }
}

/// The method exchange and, when the server asks for it, the user/password
/// sub-negotiation of RFC 1929.
fn negotiate(stream: &mut TcpStream, credentials: Option<&Credentials>) -> io::Result<()> {
    let greeting: &[u8] = if credentials.is_some() {
        &[SOCKS_VERSION, 1, METHOD_PASSWORD]
    } else {
        &[SOCKS_VERSION, 1, METHOD_NONE]
    };
    stream.write_all(greeting)?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice)?;
    if choice[0] != SOCKS_VERSION || choice[1] == METHOD_REFUSED {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy refused the methods offered",
        ));
    }
    match (choice[1], credentials) {
        (METHOD_NONE, None) => Ok(()),
        (METHOD_PASSWORD, Some(account)) => {
            let user = account.username.as_bytes();
            let pass = account.password.as_bytes();
            let (Ok(user_len), Ok(pass_len)) = (u8::try_from(user.len()), u8::try_from(pass.len()))
            else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "credentials too long",
                ));
            };
            let mut request = Vec::with_capacity(3 + user.len() + pass.len());
            request.extend_from_slice(&[1, user_len]);
            request.extend_from_slice(user);
            request.push(pass_len);
            request.extend_from_slice(pass);
            stream.write_all(&request)?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status)?;
            if status[1] == 0 {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "proxy rejected the credentials",
                ))
            }
        }
        _ => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy chose an unexpected method",
        )),
    }
}

/// Reads a SOCKS5 reply; the bound address on success.
fn read_reply(stream: &mut TcpStream) -> io::Result<SocketAddr> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != SOCKS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a SOCKS5 reply",
        ));
    }
    let address = read_address(stream, head[3])?;
    if head[1] != 0 {
        let kind = match head[1] {
            2 => io::ErrorKind::PermissionDenied,
            3 | 4 => io::ErrorKind::HostUnreachable,
            5 => io::ErrorKind::ConnectionRefused,
            6 => io::ErrorKind::TimedOut,
            _ => io::ErrorKind::Other,
        };
        return Err(io::Error::new(
            kind,
            "proxy could not reach the destination",
        ));
    }
    Ok(address)
}

/// Reads the address that follows ATYP; a domain is reported as unspecified,
/// which only a bound address could carry and no server sends.
fn read_address(stream: &mut impl Read, atyp: u8) -> io::Result<SocketAddr> {
    let ip = match atyp {
        ADDRESS_V4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets)?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        ADDRESS_V6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets)?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        ADDRESS_DOMAIN => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length)?;
            let mut name = vec![0u8; usize::from(length[0])];
            stream.read_exact(&mut name)?;
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown SOCKS5 address type",
            ));
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port)?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(port)))
}

/// ATYP, address and port of `target` in SOCKS5 wire form.
pub(crate) fn write_address(out: &mut Vec<u8>, target: &Target) -> io::Result<()> {
    match &target.host {
        Host::Ip(IpAddr::V4(ip)) => {
            out.push(ADDRESS_V4);
            out.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            out.push(ADDRESS_V6);
            out.extend_from_slice(&ip.octets());
        }
        Host::Domain(name) => {
            let length = u8::try_from(name.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "domain name too long"))?;
            out.push(ADDRESS_DOMAIN);
            out.push(length);
            out.extend_from_slice(name.as_bytes());
        }
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(())
}

/// The origin and header length of a SOCKS5 UDP datagram; `None` when the
/// frame is malformed or fragmented (fragments are not reassembled).
/// A domain origin yields `Some((None, header))`.
pub(crate) fn parse_udp_header(frame: &[u8]) -> Option<(Option<SocketAddr>, usize)> {
    if frame.len() < 4 || frame[0] != 0 || frame[1] != 0 || frame[2] != 0 {
        return None;
    }
    match frame[3] {
        ADDRESS_V4 => {
            let octets: [u8; 4] = frame.get(4..8)?.try_into().ok()?;
            let port = u16::from_be_bytes(frame.get(8..10)?.try_into().ok()?);
            Some((
                Some(SocketAddr::new(Ipv4Addr::from(octets).into(), port)),
                10,
            ))
        }
        ADDRESS_V6 => {
            let octets: [u8; 16] = frame.get(4..20)?.try_into().ok()?;
            let port = u16::from_be_bytes(frame.get(20..22)?.try_into().ok()?);
            Some((
                Some(SocketAddr::new(Ipv6Addr::from(octets).into(), port)),
                22,
            ))
        }
        ADDRESS_DOMAIN => {
            let length = usize::from(*frame.get(4)?);
            let end = 5 + length + 2;
            frame.get(..end)?;
            Some((None, end))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_of_a_target_hides_the_destination() {
        let text = format!("{:?}", Target::domain("example.com", 443));
        assert!(!text.contains("example"));
        assert!(!text.contains("443"));
        let ip = format!("{:?}", Target::ip("192.0.2.1".parse().unwrap(), 80));
        assert!(!ip.contains("192"));
    }

    #[test]
    fn credentials_never_show_in_debug() {
        let dialer = Socks5Dialer::new(
            "127.0.0.1:1080".parse().unwrap(),
            Some(Credentials {
                username: "user-secret".into(),
                password: "pass-secret".into(),
            }),
        );
        let text = format!("{dialer:?}");
        assert!(!text.contains("secret"));
        assert!(!text.contains("1080"));
    }

    #[test]
    fn udp_headers_round_trip() {
        let mut frame = vec![0, 0, 0];
        write_address(&mut frame, &Target::ip("2001:db8::1".parse().unwrap(), 53)).unwrap();
        frame.extend_from_slice(b"payload");
        let (origin, header) = parse_udp_header(&frame).unwrap();
        assert_eq!(origin, Some("[2001:db8::1]:53".parse().unwrap()));
        assert_eq!(&frame[header..], b"payload");
        assert!(parse_udp_header(&[0, 0, 1, 1, 0, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn authority_brackets_ipv6() {
        assert_eq!(
            Target::ip("2001:db8::1".parse().unwrap(), 443).authority(),
            "[2001:db8::1]:443"
        );
        assert_eq!(
            Target::domain("example.com", 80).authority(),
            "example.com:80"
        );
    }

    #[test]
    fn normalize_host_strips_trailing_dots_and_parses_ip_literals() {
        assert_eq!(
            normalize_host("Blocked.Example.COM.."),
            Some(Host::Domain("blocked.example.com".into()))
        );
        assert_eq!(
            normalize_host("192.0.2.1"),
            Some(Host::Ip("192.0.2.1".parse().unwrap()))
        );
        assert_eq!(
            normalize_host("2001:db8::1"),
            Some(Host::Ip("2001:db8::1".parse().unwrap()))
        );
        assert_eq!(
            normalize_host("[2001:db8::1]"),
            Some(Host::Ip("2001:db8::1".parse().unwrap()))
        );
        assert!(normalize_host("").is_none());
        assert!(normalize_host(".").is_none());
        assert!(normalize_host("...").is_none());
        assert!(normalize_host("bad host").is_none());
        assert!(normalize_host("bad/host").is_none());
    }

    #[test]
    fn authenticated_socks5_dialer_rejects_unauthenticated_method_reply() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut req = [0u8; 3];
            stream.read_exact(&mut req).unwrap();
            assert_eq!(req, [5, 1, 2]);
            // Server tries to downgrade to METHOD_NONE.
            stream.write_all(&[5, 0]).unwrap();
        });
        let dialer = Socks5Dialer::new(
            addr,
            Some(Credentials {
                username: "u".into(),
                password: "p".into(),
            }),
        );
        let err = dialer
            .connect(&Target::domain("example.com", 443), Duration::from_secs(2))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        server.join().unwrap();
    }

    #[test]
    fn direct_udp_supports_ipv6_destinations_when_ipv6_loopback_is_available() {
        let dialer = DirectDialer::default();
        let v6_target = Target::ip("2001:db8::1".parse().unwrap(), 53);
        let v4_target = Target::ip("192.0.2.1".parse().unwrap(), 53);

        let v4_path = dialer.udp_for(&v4_target, Duration::from_secs(2)).unwrap();
        assert!(v4_path.v4.is_some());
        assert!(v4_path.v6.is_none());

        let Ok(v6_path) = dialer.udp_for(&v6_target, Duration::from_secs(2)) else {
            return;
        };
        assert!(v6_path.v6.is_some());
        assert!(v6_path.v4.is_none());

        let dual_path = dialer.udp(Duration::from_secs(2)).unwrap();
        assert!(dual_path.v4.is_some());
        assert!(dual_path.v6.is_some());

        // Also run a real [::1] UDP echo round-trip when the host's firewall permits IPv6 loopback.
        let Ok(probe_rx) = UdpSocket::bind("[::1]:0") else {
            return;
        };
        let Ok(probe_tx) = UdpSocket::bind("[::1]:0") else {
            return;
        };
        probe_rx
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let _ = probe_tx.send_to(b"ok", probe_rx.local_addr().unwrap());
        let mut probe_buf = [0u8; 4];
        if probe_rx.recv_from(&mut probe_buf).is_err() {
            return;
        }

        let echo = UdpSocket::bind("[::1]:0").unwrap();
        let echo_addr = echo.local_addr().unwrap();
        echo.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            let (n, peer) = echo.recv_from(&mut buf).unwrap();
            echo.send_to(&buf[..n], peer).unwrap();
        });
        let path = dialer
            .udp_for(&Target::socket(echo_addr), Duration::from_secs(2))
            .unwrap();
        path.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        path.send_to(b"v6ping", &Target::socket(echo_addr)).unwrap();
        let mut reply = [0u8; 64];
        let (n, origin) = path.recv_from(&mut reply).unwrap();
        assert_eq!(&reply[..n], b"v6ping");
        assert_eq!(origin, Some(echo_addr));
        handle.join().unwrap();
    }
}
