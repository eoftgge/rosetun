use std::ffi::CStr;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const HEADER: usize = 16;
const ROUTE: usize = 12;
const SEQUENCE: u32 = 1;

pub(super) fn route_interface(address: IpAddr) -> io::Result<String> {
    // SAFETY: socket creates a new descriptor, owned below on success; NETLINK_ROUTE
    // receives only a route query and does not send IP packets.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is a newly created descriptor and ownership is transferred once.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: sockaddr_nl has a valid all-zero representation before setting its family.
    let mut kernel: libc::sockaddr_nl = unsafe { zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;
    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 100_000,
    };
    // SAFETY: the input buffer is an initialized timeval of the supplied size.
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeout).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the send deadline uses the same initialized timeval buffer.
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            (&raw const timeout).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let query = query(address);
    // SAFETY: query and kernel remain alive and readable for the synchronous send.
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
        return Err(io::Error::last_os_error());
    }
    let mut bytes = [0u8; 8192];
    let mut peer = kernel;
    let mut peer_size = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    // SAFETY: bytes, peer and peer_size are writable buffers with the stated lengths.
    let received = unsafe {
        libc::recvfrom(
            socket.as_raw_fd(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
            libc::MSG_TRUNC,
            (&raw mut peer).cast(),
            &mut peer_size,
        )
    };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    if peer.nl_pid != 0 || received as usize > bytes.len() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let index = interface_index(&bytes[..received as usize])?;
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: name has IF_NAMESIZE writable bytes; the API NUL terminates on success.
    if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: if_indextoname succeeded and wrote a NUL-terminated string into name.
    unsafe { CStr::from_ptr(name.as_ptr()) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| io::ErrorKind::InvalidData.into())
}

fn query(address: IpAddr) -> Vec<u8> {
    let (family, address) = match address {
        IpAddr::V4(address) => (libc::AF_INET, address.octets().to_vec()),
        IpAddr::V6(address) => (libc::AF_INET6, address.octets().to_vec()),
    };
    let length = HEADER + ROUTE + 4 + address.len();
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&(length as u32).to_ne_bytes());
    bytes[4..6].copy_from_slice(&libc::RTM_GETROUTE.to_ne_bytes());
    bytes[6..8].copy_from_slice(&(libc::NLM_F_REQUEST as u16).to_ne_bytes());
    bytes[8..12].copy_from_slice(&SEQUENCE.to_ne_bytes());
    bytes[HEADER] = family as u8;
    bytes[HEADER + 1] = (address.len() * 8) as u8;
    bytes[HEADER + ROUTE..HEADER + ROUTE + 2]
        .copy_from_slice(&((4 + address.len()) as u16).to_ne_bytes());
    bytes[HEADER + ROUTE + 2..HEADER + ROUTE + 4].copy_from_slice(&libc::RTA_DST.to_ne_bytes());
    bytes[HEADER + ROUTE + 4..].copy_from_slice(&address);
    bytes
}

fn interface_index(bytes: &[u8]) -> io::Result<u32> {
    let invalid = || io::Error::from(io::ErrorKind::InvalidData);
    if bytes.len() < HEADER + 4 {
        return Err(invalid());
    }
    let length = u32::from_ne_bytes(bytes[..4].try_into().map_err(|_| invalid())?) as usize;
    if length > bytes.len() || length < HEADER + 4 || bytes[8..12] != SEQUENCE.to_ne_bytes() {
        return Err(invalid());
    }
    let kind = u16::from_ne_bytes([bytes[4], bytes[5]]);
    if kind == libc::NLMSG_ERROR as u16 {
        let code = i32::from_ne_bytes(
            bytes[HEADER..HEADER + 4]
                .try_into()
                .map_err(|_| invalid())?,
        );
        return Err(if code < 0 {
            io::Error::from_raw_os_error(code.saturating_neg())
        } else {
            invalid()
        });
    }
    if kind != libc::RTM_NEWROUTE || length < HEADER + ROUTE {
        return Err(invalid());
    }
    if bytes[HEADER + 7] != libc::RTN_UNICAST {
        return Err(io::ErrorKind::NotFound.into());
    }
    let mut offset = HEADER + ROUTE;
    while offset + 4 <= length {
        let size = u16::from_ne_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        let kind = u16::from_ne_bytes([bytes[offset + 2], bytes[offset + 3]]);
        if size < 4 || offset + size > length {
            return Err(invalid());
        }
        if kind == libc::RTA_OIF && size == 8 {
            let index = u32::from_ne_bytes(
                bytes[offset + 4..offset + 8]
                    .try_into()
                    .map_err(|_| invalid())?,
            );
            return if index == 0 {
                Err(invalid())
            } else {
                Ok(index)
            };
        }
        offset += (size + 3) & !3;
    }
    Err(io::ErrorKind::NotFound.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_or_foreign_route_messages_never_report_an_interface() {
        for length in 0..36 {
            assert!(interface_index(&vec![0; length]).is_err());
        }
        let mut response = query("192.0.2.1".parse().unwrap());
        response[4..6].copy_from_slice(&libc::RTM_NEWROUTE.to_ne_bytes());
        response[HEADER + 7] = libc::RTN_UNICAST;
        response[30..32].copy_from_slice(&libc::RTA_OIF.to_ne_bytes());
        response[32..36].copy_from_slice(&7u32.to_ne_bytes());
        assert_eq!(interface_index(&response).unwrap(), 7);
        response[8..12].copy_from_slice(&2u32.to_ne_bytes());
        assert!(interface_index(&response).is_err());
        response[8..12].copy_from_slice(&SEQUENCE.to_ne_bytes());
        response[28..30].copy_from_slice(&3u16.to_ne_bytes());
        assert!(interface_index(&response).is_err());
    }
}
