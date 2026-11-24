//! Active interface and address enumeration on macOS via `getifaddrs`.

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

/// Raw interface snapshot collected from `getifaddrs`.
#[derive(Debug, Clone)]
pub(super) struct RawInterface {
    pub(super) index: u32,
    pub(super) name: String,
    pub(super) up: bool,
    pub(super) point_to_point: bool,
    pub(super) loopback: bool,
    pub(super) sdl_type: Option<u8>,
    pub(super) addresses: Vec<(IpAddr, u8)>,
}

struct IfAddrs(*mut libc::ifaddrs);

impl IfAddrs {
    fn read() -> io::Result<Self> {
        let mut head = ptr::null_mut();
        // SAFETY: `getifaddrs` initializes `head` on success; `Drop` frees it.
        if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(head))
    }
}

impl Drop for IfAddrs {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was returned by `getifaddrs` and is freed once.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
}

fn ipv4_from_sockaddr(sa: *const libc::sockaddr) -> Option<Ipv4Addr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: Caller verified `sa` is non-null; reading `sa_family` checks the
    // variant before copying `sockaddr_in` unaligned.
    let family = i32::from(unsafe { (*sa).sa_family });
    if family != libc::AF_INET {
        return None;
    }
    // SAFETY: `sa_family == AF_INET` guarantees a `sockaddr_in` layout.
    let sin: libc::sockaddr_in = unsafe { ptr::read_unaligned(sa.cast()) };
    Some(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)))
}

fn ipv6_from_sockaddr(sa: *const libc::sockaddr) -> Option<Ipv6Addr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: Caller verified `sa` is non-null.
    let family = i32::from(unsafe { (*sa).sa_family });
    if family != libc::AF_INET6 {
        return None;
    }
    // SAFETY: `sa_family == AF_INET6` guarantees a `sockaddr_in6` layout.
    let sin6: libc::sockaddr_in6 = unsafe { ptr::read_unaligned(sa.cast()) };
    let mut octets = sin6.sin6_addr.s6_addr;
    // Darwin KAME embeds the scope id in octets[2..4] for link-local unicast
    // (`fe80::/10`) and link-local multicast (`ff02::/16`) addresses.
    if (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80)
        || (octets[0] == 0xff && (octets[1] & 0x0f) == 0x02)
    {
        octets[2] = 0;
        octets[3] = 0;
    }
    Some(Ipv6Addr::from(octets))
}

fn prefix_len_v4(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let ones = bits.leading_ones();
    let expected = if ones == 0 {
        0
    } else {
        u32::MAX << (32 - ones)
    };
    (bits == expected).then_some(ones as u8)
}

fn prefix_len_v6(mask: Ipv6Addr) -> Option<u8> {
    let bits = u128::from(mask);
    let ones = bits.leading_ones();
    let expected = if ones == 0 {
        0
    } else {
        u128::MAX << (128 - ones)
    };
    (bits == expected).then_some(ones as u8)
}

pub(super) fn read_interfaces() -> io::Result<Vec<RawInterface>> {
    let list = IfAddrs::read()?;
    let mut by_name: BTreeMap<String, RawInterface> = BTreeMap::new();
    let mut cursor = list.0;

    while !cursor.is_null() {
        // SAFETY: `cursor` walks the null-terminated linked list returned by
        // `getifaddrs` while `list` remains alive.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_name.is_null() {
            continue;
        }
        // SAFETY: `ifa_name` is a NUL-terminated interface name owned by `list`.
        let Ok(name) = unsafe { CStr::from_ptr(entry.ifa_name) }.to_str() else {
            continue;
        };
        let flags = entry.ifa_flags as i32;
        let up = (flags & libc::IFF_UP) != 0 && (flags & libc::IFF_RUNNING) != 0;
        let loopback = (flags & libc::IFF_LOOPBACK) != 0;
        let point_to_point = (flags & libc::IFF_POINTOPOINT) != 0;

        let iface = by_name
            .entry(name.to_owned())
            .or_insert_with(|| RawInterface {
                index: 0,
                name: name.to_owned(),
                up,
                point_to_point,
                loopback,
                sdl_type: None,
                addresses: Vec::new(),
            });
        iface.up = iface.up || up;
        iface.loopback = iface.loopback || loopback;
        iface.point_to_point = iface.point_to_point || point_to_point;

        if entry.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: `ifa_addr` was checked non-null above.
        let family = i32::from(unsafe { (*entry.ifa_addr).sa_family });
        if family == libc::AF_LINK {
            // SAFETY: `AF_LINK` entries hold a `sockaddr_dl`.
            let sdl: libc::sockaddr_dl = unsafe { ptr::read_unaligned(entry.ifa_addr.cast()) };
            if sdl.sdl_index != 0 {
                iface.index = u32::from(sdl.sdl_index);
            }
            iface.sdl_type = Some(sdl.sdl_type);
        } else if family == libc::AF_INET {
            if let (Some(addr), Some(mask)) = (
                ipv4_from_sockaddr(entry.ifa_addr),
                ipv4_from_sockaddr(entry.ifa_netmask),
            ) && let Some(length) = prefix_len_v4(mask)
            {
                let pair = (IpAddr::V4(addr), length);
                if !iface.addresses.contains(&pair) {
                    iface.addresses.push(pair);
                }
            }
        } else if family == libc::AF_INET6
            && let (Some(addr), Some(mask)) = (
                ipv6_from_sockaddr(entry.ifa_addr),
                ipv6_from_sockaddr(entry.ifa_netmask),
            )
            && let Some(length) = prefix_len_v6(mask)
        {
            let pair = (IpAddr::V6(addr), length);
            if !iface.addresses.contains(&pair) {
                iface.addresses.push(pair);
            }
        }
    }

    Ok(by_name.into_values().collect())
}

/// Private addresses of active physical interfaces, for shared local proxy
/// bindings.
pub(in crate::platform) fn private_addresses() -> Vec<IpAddr> {
    let Ok(interfaces) = read_interfaces() else {
        return Vec::new();
    };
    let mut addresses = Vec::new();
    for iface in interfaces {
        if !iface.up || iface.loopback || iface.point_to_point {
            continue;
        }
        if !super::segment::is_hardware_interface(&iface) {
            continue;
        }
        for (addr, _) in iface.addresses {
            if rosetun_config::is_private_address(addr) && !addresses.contains(&addr) {
                addresses.push(addr);
            }
        }
    }
    addresses.sort_unstable();
    addresses
}

/// Finds an active `utun*` interface holding `ipv4`, as a fallback when the
/// kernel-assigned interface name was not parsed from engine startup logs.
pub(in crate::platform) fn tunnel_interface_by_ipv4(ipv4: Ipv4Addr) -> io::Result<Option<String>> {
    let target = IpAddr::V4(ipv4);
    for iface in read_interfaces()? {
        if iface.up
            && iface.name.starts_with("utun")
            && iface.addresses.iter().any(|(addr, _)| *addr == target)
        {
            return Ok(Some(iface.name));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_lengths_reject_non_contiguous_masks() {
        assert_eq!(prefix_len_v4(Ipv4Addr::new(255, 255, 255, 0)), Some(24));
        assert_eq!(prefix_len_v4(Ipv4Addr::new(255, 255, 255, 252)), Some(30));
        assert_eq!(prefix_len_v4(Ipv4Addr::UNSPECIFIED), Some(0));
        assert_eq!(prefix_len_v4(Ipv4Addr::new(255, 0, 255, 0)), None);

        assert_eq!(
            prefix_len_v6("ffff:ffff:ffff:ffff::".parse().unwrap()),
            Some(64)
        );
        assert_eq!(prefix_len_v6(Ipv6Addr::UNSPECIFIED), Some(0));
        assert_eq!(prefix_len_v6("ffff:0:ffff::".parse().unwrap()), None);
    }

    #[test]
    fn reads_loopback_interface_on_macos() {
        let interfaces = read_interfaces().expect("getifaddrs on macOS");
        assert!(
            interfaces.iter().any(|iface| {
                iface.name == "lo0"
                    && iface.loopback
                    && iface
                        .addresses
                        .iter()
                        .any(|(addr, _)| *addr == IpAddr::V4(Ipv4Addr::LOCALHOST))
            }),
            "expected lo0 with 127.0.0.1"
        );
    }
}
