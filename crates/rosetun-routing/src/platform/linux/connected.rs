//! The private addresses of this computer's physical interfaces: where a shared
//! local proxy listens on Linux. Without Lockdown no chain of ours looks at
//! inbound traffic, so where it listens is what limits who reaches it, and a
//! public address must never be among them.

use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

pub(super) const SYS_NET: &str = "/sys/class/net";

/// A physical interface has a device behind it. Tunnels, bridges, veth pairs and
/// other software interfaces do not, and what is behind them is no local network.
fn is_physical(sys_net: &Path, name: &str) -> bool {
    sys_net.join(name).join("device").exists()
}

/// An address others on the same network can reach this computer at, and that
/// the outside cannot. Link-local ones need a scope no proxy client would give.
fn can_be_opened(address: IpAddr) -> bool {
    rosetun_config::is_private_address(address)
        && !address.is_loopback()
        && match address {
            IpAddr::V4(address) => !address.is_link_local(),
            IpAddr::V6(address) => !address.is_unicast_link_local(),
        }
}

fn openable(interfaces: Vec<(String, IpAddr)>, sys_net: &Path) -> Vec<IpAddr> {
    let mut addresses: Vec<IpAddr> = interfaces
        .into_iter()
        .filter(|(name, address)| can_be_opened(*address) && is_physical(sys_net, name))
        .map(|(_, address)| address)
        .collect();
    addresses.sort_unstable();
    addresses.dedup();
    addresses
}

/// An address of an interface that is up, with the length of its network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Found {
    pub(super) name: String,
    pub(super) address: IpAddr,
    pub(super) length: u8,
}

/// The number of leading one bits of a netmask; `None` for a mask with
/// holes, which no interface has.
fn mask_length(mask: IpAddr) -> Option<u8> {
    let (bits, width) = match mask {
        IpAddr::V4(mask) => (u128::from(mask.to_bits()) << 96, 32),
        IpAddr::V6(mask) => (mask.to_bits(), 128),
    };
    let ones = bits.leading_ones();
    let rest = bits.checked_shl(ones).unwrap_or(0);
    (rest == 0 && ones <= width)
        .then(|| u8::try_from(ones).ok())
        .flatten()
}

/// Reads one `sockaddr` of the list `getifaddrs` returned.
///
/// # Safety
/// `address` is null or points to a `sockaddr` that stays valid for the call.
unsafe fn socket_address(address: *const libc::sockaddr) -> Option<IpAddr> {
    if address.is_null() {
        return None;
    }
    // SAFETY: the caller promises a valid sockaddr; sa_family says which of the
    // two layouts below it really has.
    unsafe {
        match i32::from((*address).sa_family) {
            libc::AF_INET => {
                let v4 = address.cast::<libc::sockaddr_in>();
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    (*v4).sin_addr.s_addr,
                ))))
            }
            libc::AF_INET6 => {
                let v6 = address.cast::<libc::sockaddr_in6>();
                Some(IpAddr::V6(Ipv6Addr::from((*v6).sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }
}

/// The addresses of the interfaces that are up, each with its network's length.
pub(super) fn interfaces_up() -> io::Result<Vec<Found>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a pointer to a list it allocates into `list`; on
    // success the list is ours until freeifaddrs below.
    if unsafe { libc::getifaddrs(&raw mut list) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut found = Vec::new();
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: `entry` is a node of the list getifaddrs returned, which stays
        // valid until freeifaddrs; we only read it.
        let current = unsafe { &*entry };
        entry = current.ifa_next;
        if current.ifa_name.is_null()
            || current.ifa_addr.is_null()
            || current.ifa_flags & libc::IFF_UP as u32 == 0
        {
            continue;
        }
        // SAFETY: ifa_addr is non-null and owned by the list.
        let Some(address) = (unsafe { socket_address(current.ifa_addr) }) else {
            continue;
        };
        // SAFETY: ifa_netmask is null or a sockaddr owned by the list.
        let mask = unsafe { socket_address(current.ifa_netmask) };
        let full = if address.is_ipv4() { 32 } else { 128 };
        let length = mask.and_then(mask_length).unwrap_or(full);
        // SAFETY: ifa_name is a NUL-terminated string owned by the list.
        let name = unsafe { CStr::from_ptr(current.ifa_name) };
        found.push(Found {
            name: name.to_string_lossy().into_owned(),
            address,
            length,
        });
    }
    // SAFETY: `list` came from getifaddrs and nothing refers to it any more:
    // the name was copied and the addresses are values.
    unsafe { libc::freeifaddrs(list) };
    Ok(found)
}

/// The addresses of the interfaces that are up.
fn interface_addresses() -> io::Result<Vec<(String, IpAddr)>> {
    Ok(interfaces_up()?
        .into_iter()
        .map(|found| (found.name, found.address))
        .collect())
}

/// A failure opens nothing: the proxy stays on loopback, and the log says why.
pub(in crate::platform) fn private_addresses() -> Vec<IpAddr> {
    match interface_addresses() {
        Ok(interfaces) => openable(interfaces, Path::new(SYS_NET)),
        Err(error) => {
            tracing::warn!(%error, "could not read the interfaces' addresses");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn fake_sys(test: &str, physical: &[&str], software: &[&str]) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("rosetun-connected-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for name in physical {
            std::fs::create_dir_all(root.join(name).join("device")).unwrap();
        }
        for name in software {
            std::fs::create_dir_all(root.join(name)).unwrap();
        }
        root
    }

    fn entry(name: &str, address: &str) -> (String, IpAddr) {
        (name.to_owned(), address.parse().unwrap())
    }

    #[test]
    fn only_private_addresses_of_physical_interfaces_open() {
        let root = fake_sys(
            "private",
            &["eth0", "wlan0"],
            &["lo", "rosetun0", "docker0", "veth1"],
        );
        let addresses = openable(
            vec![
                entry("eth0", "192.168.1.5"),
                entry("wlan0", "10.0.0.7"),
                entry("eth0", "fd00:1::5"),
                entry("lo", "127.0.0.1"),
                entry("rosetun0", "172.19.0.1"),
                entry("docker0", "172.17.0.1"),
                entry("veth1", "10.1.0.1"),
                entry("gone0", "10.2.0.1"),
            ],
            &root,
        );
        let expected: Vec<IpAddr> = ["10.0.0.7", "192.168.1.5", "fd00:1::5"]
            .map(|address| address.parse().unwrap())
            .to_vec();
        assert_eq!(addresses, expected);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_public_or_link_local_address_never_opens() {
        let root = fake_sys("public", &["eth0"], &[]);
        let addresses = openable(
            vec![
                entry("eth0", "198.51.100.5"),
                entry("eth0", "203.0.113.9"),
                entry("eth0", "2001:db8::5"),
                entry("eth0", "169.254.3.4"),
                entry("eth0", "fe80::5"),
            ],
            &root,
        );
        assert!(addresses.is_empty(), "{addresses:?}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn this_machines_interfaces_can_be_read() {
        assert!(interface_addresses().is_ok());
    }

    #[test]
    fn a_netmask_is_its_prefix_length_and_a_mask_with_holes_is_none() {
        let length = |text: &str| mask_length(text.parse().unwrap());
        assert_eq!(length("255.255.255.0"), Some(24));
        assert_eq!(length("255.255.0.0"), Some(16));
        assert_eq!(length("255.255.255.255"), Some(32));
        assert_eq!(length("0.0.0.0"), Some(0));
        assert_eq!(length("ffff:ffff:ffff:ffff::"), Some(64));
        assert_eq!(length("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), Some(128));
        assert_eq!(length("255.0.255.0"), None);
        assert_eq!(length("::ffff"), None);
    }
}
