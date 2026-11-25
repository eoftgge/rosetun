//! Linux socket ownership from INET_DIAG and procfs.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rosetun_config::ConnectionNetwork;

use super::{ProcessLookup, TcpFlow};

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const HEADER_BYTES: usize = 16;
const DIAG_BYTES: usize = 72;
const CACHE_LIMIT: usize = 512;
const TTL: Duration = Duration::from_millis(300);
const LOOKUP_BUDGET: Duration = Duration::from_millis(150);
const MAX_SCAN: usize = 32_768;

type Images = HashMap<(TcpFlow, bool), (Instant, Option<String>)>;

#[derive(Default)]
pub struct LinuxProcessLookup {
    images: Mutex<Images>,
}

impl fmt::Debug for LinuxProcessLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxProcessLookup").finish_non_exhaustive()
    }
}

impl ProcessLookup for LinuxProcessLookup {
    fn image(&self, flow: &TcpFlow, network: ConnectionNetwork) -> Option<String> {
        let udp = network == ConnectionNetwork::Udp;
        let key = (*flow, udp);
        let now = Instant::now();
        if let Some((at, path)) = self.images.lock().ok()?.get(&key)
            && now.saturating_duration_since(*at) < TTL
        {
            return path.clone();
        }
        let deadline = now + LOOKUP_BUDGET;
        let path =
            socket_inode(flow, udp, deadline).and_then(|inode| process_image(inode, deadline));
        let mut images = self.images.lock().ok()?;
        images.retain(|_, (when, _)| now.saturating_duration_since(*when) < TTL);
        if images.len() < CACHE_LIMIT {
            images.insert(key, (now, path.clone()));
        }
        path
    }
}

#[derive(Default)]
struct Owner {
    score: u8,
    inode: u32,
    ambiguous: bool,
}

impl Owner {
    fn record(&mut self, score: u8, inode: u32) {
        if inode != 0 && score > self.score {
            *self = Self {
                inode,
                score,
                ambiguous: false,
            };
        } else if inode != 0 && score == self.score && self.inode != inode {
            self.ambiguous = true;
        }
    }

    fn answer(&self) -> Option<u32> {
        (self.inode != 0 && !self.ambiguous).then_some(self.inode)
    }
}

fn socket_inode(flow: &TcpFlow, udp: bool, deadline: Instant) -> Option<u32> {
    let socket = diag_socket().ok()?;
    let query = request(flow, udp);
    let kernel = kernel_address();
    // SAFETY: Both the address and message are live initialized values.
    // sendto borrows the still-owned fd and retains none of the pointers.
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            query.as_ptr().cast(),
            query.len(),
            0,
            (&raw const kernel).cast(),
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent != query.len() as isize {
        return None;
    }
    let mut buffer = vec![0u8; 64 * 1024];
    let mut owner = Owner::default();
    while Instant::now() < deadline {
        let packet = receive(&socket, &mut buffer).ok()?;
        if parse_replies(packet, flow, udp, &mut owner)? || !udp {
            return owner.answer();
        }
    }
    None
}

fn diag_socket() -> io::Result<OwnedFd> {
    // SAFETY: On success the syscall transfers sole ownership of a new fd.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_SOCK_DIAG,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is the just-opened fd, and OwnedFd closes it.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 100_000,
    };
    // SAFETY: The fd and timeval remain valid and the kernel copies exactly
    // the supplied timeval during the call.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeout).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

fn kernel_address() -> libc::sockaddr_nl {
    // SAFETY: Zeroing the sockaddr creates a kernel PID and zero groups.
    // The ABI includes padding that must stay initialized.
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    address
}

fn receive<'a>(socket: &OwnedFd, buffer: &'a mut [u8]) -> io::Result<&'a [u8]> {
    let mut sender = kernel_address();
    let mut address_len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    // SAFETY: recvfrom writes to the indicated bounded buffer and sockaddr
    // while the fd remains borrowed. MSG_TRUNC allows detecting a too-large packet.
    let bytes = unsafe {
        libc::recvfrom(
            socket.as_raw_fd(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            libc::MSG_TRUNC,
            (&raw mut sender).cast(),
            &mut address_len,
        )
    };
    let written = usize::try_from(bytes).map_err(|_| io::Error::last_os_error())?;
    if sender.nl_pid != 0 || written == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown diagnostic sender",
        ));
    }
    buffer
        .get(..written)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated diagnostic reply"))
}

fn request(flow: &TcpFlow, udp: bool) -> [u8; 72] {
    let mut packet = [0u8; 72];
    packet[..4].copy_from_slice(&72u32.to_ne_bytes());
    packet[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    let flags = NLM_F_REQUEST | if udp { NLM_F_DUMP } else { 0 };
    packet[6..8].copy_from_slice(&flags.to_ne_bytes());
    packet[8..12].copy_from_slice(&1u32.to_ne_bytes());
    packet[16] = if flow.source.is_ipv4() {
        libc::AF_INET as u8
    } else {
        libc::AF_INET6 as u8
    };
    packet[17] = if udp {
        libc::IPPROTO_UDP as u8
    } else {
        libc::IPPROTO_TCP as u8
    };
    packet[20..24].fill(0xff);
    if !udp {
        packet[24..26].copy_from_slice(&flow.source.port().to_be_bytes());
        packet[26..28].copy_from_slice(&flow.destination.port().to_be_bytes());
        put_ip(&mut packet[28..44], flow.source.ip());
        put_ip(&mut packet[44..60], flow.destination.ip());
    }
    packet[64..72].fill(0xff);
    packet
}

fn put_ip(out: &mut [u8], ip: IpAddr) {
    match ip {
        IpAddr::V4(ip) => out[..4].copy_from_slice(&ip.octets()),
        IpAddr::V6(ip) => out.copy_from_slice(&ip.octets()),
    }
}

fn read_ip(family: u8, data: &[u8]) -> Option<IpAddr> {
    match i32::from(family) {
        libc::AF_INET => Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]).into()),
        libc::AF_INET6 => Some(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?).into()),
        _ => None,
    }
}

fn parse_replies(mut data: &[u8], flow: &TcpFlow, udp: bool, owner: &mut Owner) -> Option<bool> {
    while data.len() >= HEADER_BYTES {
        let size = u32::from_ne_bytes(data[..4].try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(data[4..6].try_into().ok()?);
        let flags = u16::from_ne_bytes(data[6..8].try_into().ok()?);
        let sequence = u32::from_ne_bytes(data[8..12].try_into().ok()?);
        if size < HEADER_BYTES || flags & NLM_F_DUMP_INTR != 0 || sequence != 1 {
            return None;
        }
        let row = data.get(HEADER_BYTES..size)?;
        match kind {
            NLMSG_DONE => return Some(true),
            NLMSG_ERROR => return None,
            SOCK_DIAG_BY_FAMILY if row.len() >= DIAG_BYTES => {
                let local = SocketAddr::new(
                    read_ip(row[0], &row[8..24])?,
                    u16::from_be_bytes(row[4..6].try_into().ok()?),
                );
                let remote = SocketAddr::new(
                    read_ip(row[0], &row[24..40])?,
                    u16::from_be_bytes(row[6..8].try_into().ok()?),
                );
                let score = specificity(flow, udp, local, remote);
                if score > 0 {
                    owner.record(score, u32::from_ne_bytes(row[68..72].try_into().ok()?));
                }
            }
            _ => {}
        }
        data = data.get(size.next_multiple_of(4)..)?;
    }
    data.is_empty().then_some(false)
}

fn specificity(flow: &TcpFlow, udp: bool, local: SocketAddr, remote: SocketAddr) -> u8 {
    if remote == flow.destination && local == flow.source {
        return 3;
    }
    if !udp
        || !remote.ip().is_unspecified()
        || remote.port() != 0
        || local.port() != flow.source.port()
    {
        return 0;
    }
    if local == flow.source {
        2
    } else {
        u8::from(local.ip().is_unspecified())
    }
}

fn process_image(inode: u32, deadline: Instant) -> Option<String> {
    let expected = format!("socket:[{inode}]");
    let mut scanned = 0;
    let mut owner = None;
    for process in fs::read_dir("/proc").ok()?.flatten() {
        if !process
            .file_name()
            .as_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        let path = process.path();
        let Ok(sockets) = fs::read_dir(path.join("fd")) else {
            continue;
        };
        for descriptor in sockets.flatten() {
            scanned += 1;
            if scanned > MAX_SCAN || Instant::now() >= deadline {
                return None;
            }
            if fs::read_link(descriptor.path())
                .is_ok_and(|link| link.as_os_str() == expected.as_str())
            {
                let image = fs::read_link(path.join("exe"))
                    .ok()?
                    .into_os_string()
                    .into_string()
                    .ok()?;
                if owner.as_ref().is_some_and(|previous| previous != &image) {
                    return None;
                }
                owner = Some(image);
                break;
            }
        }
    }
    owner
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_connected_udp_owner_beats_wildcard_and_multiple_equal_owners_are_unknown() {
        let flow = TcpFlow {
            source: "192.0.2.1:51300".parse().unwrap(),
            destination: "198.51.100.2:443".parse().unwrap(),
        };
        assert_eq!(
            specificity(
                &flow,
                true,
                "0.0.0.0:51300".parse().unwrap(),
                "0.0.0.0:0".parse().unwrap()
            ),
            1
        );
        assert_eq!(specificity(&flow, true, flow.source, flow.destination), 3);
        let mut owners = Owner::default();
        owners.record(1, 17);
        owners.record(3, 18);
        assert_eq!(owners.answer(), Some(18));
        owners.record(3, 19);
        assert_eq!(owners.answer(), None);
    }

    #[test]
    fn inet_diag_matches_the_current_process_on_a_connected_socket() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let connection = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        let flow = TcpFlow {
            source: connection.local_addr().unwrap(),
            destination: connection.peer_addr().unwrap(),
        };
        let image = LinuxProcessLookup::default().image(&flow, ConnectionNetwork::Tcp);
        assert_eq!(image.as_deref(), std::env::current_exe().unwrap().to_str());
    }
}
