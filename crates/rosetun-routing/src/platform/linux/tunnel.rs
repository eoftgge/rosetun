//! Whether the engine's TUN exists, is up and carries the configured IPv4
//! address. A name alone could belong to a stale interface.

use std::ffi::CStr;
use std::net::Ipv4Addr;
use std::path::Path;

use crate::RoutingError;
use crate::nftables::InterfaceName;

const IFF_UP: u32 = 0x1;

pub(super) fn check(name: &InterfaceName, ipv4: Ipv4Addr) -> Result<(), RoutingError> {
    let not_ready = |reason: &str| RoutingError::TunnelNotReady {
        name: name.as_str().to_owned(),
        reason: reason.to_owned(),
    };
    let flags_path = Path::new("/sys/class/net")
        .join(name.as_str())
        .join("flags");
    let Ok(flags) = std::fs::read_to_string(&flags_path) else {
        return Err(not_ready("the interface does not exist yet"));
    };
    let up = parse_flags(&flags).is_some_and(|flags| flags & IFF_UP != 0);
    if !up {
        return Err(not_ready("the interface is not up"));
    }
    if !interface_ipv4(name.as_str())?.contains(&ipv4) {
        return Err(not_ready(
            "the interface does not carry the configured address",
        ));
    }
    Ok(())
}

/// `/sys/class/net/<name>/flags` holds the flags in hexadecimal, `0x1091`.
pub(super) fn parse_flags(text: &str) -> Option<u32> {
    let digits = text.trim().strip_prefix("0x")?;
    u32::from_str_radix(digits, 16).ok()
}

fn interface_ipv4(name: &str) -> Result<Vec<Ipv4Addr>, RoutingError> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a pointer to a list it allocates into
    // `list`; on success the list is ours until freeifaddrs below.
    if unsafe { libc::getifaddrs(&raw mut list) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut found = Vec::new();
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: `entry` is a node of the list getifaddrs returned, which
        // stays valid until freeifaddrs; we only read it.
        let current = unsafe { &*entry };
        entry = current.ifa_next;
        if current.ifa_name.is_null() || current.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: ifa_name is a NUL-terminated string owned by the list.
        let entry_name = unsafe { CStr::from_ptr(current.ifa_name) };
        if entry_name.to_bytes() != name.as_bytes() {
            continue;
        }
        // SAFETY: ifa_addr points to a sockaddr owned by the list; its
        // family says which concrete type it is.
        let family = unsafe { (*current.ifa_addr).sa_family };
        if i32::from(family) != libc::AF_INET {
            continue;
        }
        // SAFETY: an AF_INET address is a sockaddr_in; read_unaligned copes
        // with any alignment the C library used.
        let address =
            unsafe { std::ptr::read_unaligned(current.ifa_addr.cast::<libc::sockaddr_in>()) };
        found.push(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)));
    }
    // SAFETY: `list` came from a successful getifaddrs and is freed once;
    // no reference into it outlives this point.
    unsafe { libc::freeifaddrs(list) };
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_flags_are_read_as_hexadecimal() {
        assert_eq!(parse_flags("0x1091\n"), Some(0x1091));
        assert_eq!(parse_flags("0x1090"), Some(0x1090));
        assert_eq!(parse_flags("4241"), None);
        assert_eq!(parse_flags(""), None);
    }

    #[test]
    fn loopback_carries_its_address() {
        assert!(interface_ipv4("lo").unwrap().contains(&Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn a_missing_interface_is_not_ready() {
        let name = InterfaceName::new("rosetun-none").unwrap();
        assert!(
            check(&name, Ipv4Addr::new(192, 0, 2, 1))
                .unwrap_err()
                .is_tunnel_not_ready()
        );
    }

    #[test]
    fn loopback_without_the_wanted_address_is_not_ready() {
        let name = InterfaceName::new("lo").unwrap();
        assert!(check(&name, Ipv4Addr::LOCALHOST).is_ok());
        assert!(
            check(&name, Ipv4Addr::new(192, 0, 2, 1))
                .unwrap_err()
                .is_tunnel_not_ready()
        );
    }
}
