//! Local-network and private-address predicates matching `rosetun-core` and
//! sing-box `ip_is_private`.

use std::net::IpAddr;

use rosetun_config::{LINK_LOCAL_V4, LINK_LOCAL_V6};

/// Whether `ip` belongs to the link-local networks sent direct when
/// `allow_lan` is enabled.
pub fn is_link_local(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    LINK_LOCAL_V4
        .iter()
        .chain(&LINK_LOCAL_V6)
        .any(|network| network.contains(ip))
}

/// Whether `ip` is non-public according to sing-box's `ip_is_private`
/// (`network.IsPublicAddr` negated).
pub fn is_private(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_link_local()
                || ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            ip.is_unique_local()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unicast_link_local()
                || ip.is_unspecified()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn link_local_covers_unicast_link_multicast_ssdp_and_limited_broadcast() {
        for addr in [
            "169.254.0.1",
            "169.254.255.254",
            "224.0.0.251",
            "224.0.0.252",
            "239.255.255.250",
            "255.255.255.255",
            "fe80::1",
            "ff02::fb",
            "::ffff:169.254.1.2",
        ] {
            assert!(is_link_local(ip(addr)), "{addr}");
        }

        for addr in [
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "224.0.1.1",
            "2001:db8::1",
            "::1",
            "fc00::1",
            "ff05::1",
        ] {
            assert!(!is_link_local(ip(addr)), "{addr}");
        }
    }

    #[test]
    fn private_matches_non_public_v4_v6_and_v4_mapped_addresses() {
        for addr in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "0.0.0.0",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
        ] {
            assert!(is_private(ip(addr)), "{addr}");
        }

        for addr in [
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "2001:db8::1",
            "::ffff:192.0.2.1",
        ] {
            assert!(!is_private(ip(addr)), "{addr}");
        }
    }
}
