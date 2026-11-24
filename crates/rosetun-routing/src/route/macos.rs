//! Read-only route lookup on macOS via `PF_ROUTE` `RTM_GET`.
//!
//! No packets are sent to the destination and root privileges are not required.

use std::io;
use std::mem::size_of;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr;
use std::sync::atomic::{AtomicI32, Ordering};

use crate::platform::macos::rtmsg::{interface_name, roundup};

const MAX_READ_MESSAGES: usize = 64;
static NEXT_SEQ: AtomicI32 = AtomicI32::new(1);

fn next_sequence() -> i32 {
    loop {
        let current = NEXT_SEQ.fetch_add(1, Ordering::Relaxed);
        if current > 0 {
            return current;
        }
        let _ = NEXT_SEQ.compare_exchange(
            current.wrapping_add(1),
            1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }
}

fn build_rtm_get(address: IpAddr, pid: libc::pid_t, seq: i32) -> Vec<u8> {
    let header_len = size_of::<libc::rt_msghdr>();
    let dst_bytes = match address {
        IpAddr::V4(v4) => {
            let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sin.sin_len = size_of::<libc::sockaddr_in>() as u8;
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_addr.s_addr = u32::from(v4).to_be();
            // SAFETY: `sin` is initialized POD; reading its bytes produces the
            // exact Darwin wire representation.
            unsafe {
                std::slice::from_raw_parts(
                    (&raw const sin).cast::<u8>(),
                    size_of::<libc::sockaddr_in>(),
                )
            }
            .to_vec()
        }
        IpAddr::V6(v6) => {
            let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            sin6.sin6_len = size_of::<libc::sockaddr_in6>() as u8;
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_addr.s6_addr = v6.octets();
            // SAFETY: `sin6` is initialized POD.
            unsafe {
                std::slice::from_raw_parts(
                    (&raw const sin6).cast::<u8>(),
                    size_of::<libc::sockaddr_in6>(),
                )
            }
            .to_vec()
        }
    };

    let mut ifp: libc::sockaddr_dl = unsafe { std::mem::zeroed() };
    ifp.sdl_len = size_of::<libc::sockaddr_dl>() as u8;
    ifp.sdl_family = libc::AF_LINK as libc::sa_family_t;
    // SAFETY: `ifp` is initialized POD.
    let ifp_bytes = unsafe {
        std::slice::from_raw_parts(
            (&raw const ifp).cast::<u8>(),
            size_of::<libc::sockaddr_dl>(),
        )
    };

    let dst_padded = roundup(dst_bytes.len());
    let ifp_padded = roundup(ifp_bytes.len());
    let total_len = header_len + dst_padded + ifp_padded;

    let mut header: libc::rt_msghdr = unsafe { std::mem::zeroed() };
    header.rtm_msglen = total_len as u16;
    header.rtm_version = libc::RTM_VERSION as u8;
    header.rtm_type = libc::RTM_GET as u8;
    header.rtm_addrs = libc::RTA_DST | libc::RTA_IFP;
    header.rtm_pid = pid;
    header.rtm_seq = seq;

    let mut message = vec![0u8; total_len];
    // SAFETY: `header` is initialized POD and `total_len >= header_len`.
    let header_bytes =
        unsafe { std::slice::from_raw_parts((&raw const header).cast::<u8>(), header_len) };
    message[..header_len].copy_from_slice(header_bytes);
    message[header_len..header_len + dst_bytes.len()].copy_from_slice(&dst_bytes);
    let ifp_offset = header_len + dst_padded;
    message[ifp_offset..ifp_offset + ifp_bytes.len()].copy_from_slice(ifp_bytes);
    message
}

fn open_route_socket() -> io::Result<OwnedFd> {
    // SAFETY: Standard Darwin PF_ROUTE socket creation.
    let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a newly created valid descriptor owned exclusively here.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };

    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        // SAFETY: `socket` is open and `timeout` points to a valid `timeval`.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&raw const timeout).cast(),
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(socket)
}

pub(super) fn route_interface(address: IpAddr) -> io::Result<String> {
    let socket = open_route_socket()?;
    // SAFETY: `getpid` is always safe.
    let pid = unsafe { libc::getpid() };
    let seq = next_sequence();
    let request = build_rtm_get(address, pid, seq);

    // SAFETY: `socket` is open and `request` is valid for `request.len()` bytes.
    let written =
        unsafe { libc::write(socket.as_raw_fd(), request.as_ptr().cast(), request.len()) };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }
    if (written as usize) != request.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short write on PF_ROUTE socket",
        ));
    }

    let mut buffer = [0u8; 2048];
    for _ in 0..MAX_READ_MESSAGES {
        // SAFETY: `socket` is open and `buffer` is writable for `buffer.len()` bytes.
        let read =
            unsafe { libc::read(socket.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        let length = read as usize;
        if length < size_of::<libc::rt_msghdr>() {
            continue;
        }
        // SAFETY: `length >= size_of::<rt_msghdr>()`; `read_unaligned` is safe.
        let reply: libc::rt_msghdr = unsafe { ptr::read_unaligned(buffer.as_ptr().cast()) };
        if i32::from(reply.rtm_version) != libc::RTM_VERSION
            || i32::from(reply.rtm_type) != libc::RTM_GET
            || reply.rtm_pid != pid
            || reply.rtm_seq != seq
        {
            continue;
        }
        if reply.rtm_errno != 0 {
            return Err(io::Error::from_raw_os_error(reply.rtm_errno));
        }
        return interface_name(reply.rtm_index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "route reply carried no interface index",
            )
        });
    }

    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "no matching RTM_GET reply received",
    ))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn builds_four_byte_aligned_rtm_get_for_ipv4_and_ipv6() {
        let v4 = build_rtm_get(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 42, 7);
        assert_eq!(v4.len() % 4, 0);
        let v6 = build_rtm_get(
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
            42,
            8,
        );
        assert_eq!(v6.len() % 4, 0);
        assert_eq!(v6.len() - v4.len(), 12);
    }

    #[test]
    fn loopback_route_resolves_to_lo0() {
        let iface = route_interface(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .expect("RTM_GET for 127.0.0.1 on macOS");
        assert_eq!(iface, "lo0");
    }
}
