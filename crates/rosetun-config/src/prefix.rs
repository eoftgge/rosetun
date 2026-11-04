use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An IPv4 or IPv6 network: an address with its host bits cleared and a
/// prefix length. Runtime only, never stored in the settings file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IpPrefix {
    address: IpAddr,
    length: u8,
}

/// Link-local networks that belong to whatever segment a computer is on:
/// link-local unicast, link-local multicast (mDNS 224.0.0.251, LLMNR
/// 224.0.0.252), SSDP and the limited broadcast. Not all of 224.0.0.0/4:
/// the rest is routed multicast, which leaves the segment.
pub const LINK_LOCAL_V4: [IpPrefix; 4] = [
    IpPrefix::v4([169, 254, 0, 0], 16),
    IpPrefix::v4([224, 0, 0, 0], 24),
    IpPrefix::v4([239, 255, 255, 250], 32),
    IpPrefix::v4([255, 255, 255, 255], 32),
];

/// The IPv6 counterpart of `LINK_LOCAL_V4`: link-local unicast and
/// link-local scope multicast (ff02::/16, which holds mDNS and SSDP).
pub const LINK_LOCAL_V6: [IpPrefix; 2] = [
    IpPrefix::v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
    IpPrefix::v6([0xff02, 0, 0, 0, 0, 0, 0, 0], 16),
];

impl IpPrefix {
    /// The network of `address` with `length` bits; `None` when the length
    /// is longer than the family allows.
    pub const fn new(address: IpAddr, length: u8) -> Option<Self> {
        let address = match address {
            IpAddr::V4(address) => {
                if length > 32 {
                    return None;
                }
                IpAddr::V4(Ipv4Addr::from_bits(address.to_bits() & mask_v4(length)))
            }
            IpAddr::V6(address) => {
                if length > 128 {
                    return None;
                }
                IpAddr::V6(Ipv6Addr::from_bits(address.to_bits() & mask_v6(length)))
            }
        };
        Some(Self { address, length })
    }

    const fn v4(octets: [u8; 4], length: u8) -> Self {
        let [a, b, c, d] = octets;
        match Self::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), length) {
            Some(prefix) => prefix,
            None => panic!("a valid IPv4 prefix"),
        }
    }

    const fn v6(segments: [u16; 8], length: u8) -> Self {
        let [a, b, c, d, e, f, g, h] = segments;
        match Self::new(IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h)), length) {
            Some(prefix) => prefix,
            None => panic!("a valid IPv6 prefix"),
        }
    }

    /// The network address, host bits cleared.
    pub fn address(self) -> IpAddr {
        self.address
    }

    pub fn length(self) -> u8 {
        self.length
    }

    pub fn is_ipv4(self) -> bool {
        self.address.is_ipv4()
    }

    pub fn contains(self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                address.to_bits() & mask_v4(self.length) == network.to_bits()
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                address.to_bits() & mask_v6(self.length) == network.to_bits()
            }
            _ => false,
        }
    }

    /// Whether the two networks share any address.
    pub fn overlaps(self, other: Self) -> bool {
        if self.length <= other.length {
            self.contains(other.address)
        } else {
            other.contains(self.address)
        }
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.length)
    }
}

const fn mask_v4(length: u8) -> u32 {
    match u32::MAX.checked_shl(32 - length as u32) {
        Some(mask) => mask,
        None => 0,
    }
}

const fn mask_v6(length: u8) -> u128 {
    match u128::MAX.checked_shl(128 - length as u32) {
        Some(mask) => mask,
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(text: &str, length: u8) -> IpPrefix {
        IpPrefix::new(text.parse().unwrap(), length).unwrap()
    }

    #[test]
    fn a_prefix_clears_host_bits_and_rejects_impossible_lengths() {
        assert_eq!(v4("192.0.2.77", 24).to_string(), "192.0.2.0/24");
        assert_eq!(v4("192.0.2.77", 0).to_string(), "0.0.0.0/0");
        assert_eq!(v4("192.0.2.77", 32).to_string(), "192.0.2.77/32");
        assert!(IpPrefix::new("192.0.2.1".parse().unwrap(), 33).is_none());
        let v6 = IpPrefix::new("2001:db8::1".parse().unwrap(), 64).unwrap();
        assert_eq!(v6.to_string(), "2001:db8::/64");
        assert!(IpPrefix::new("2001:db8::1".parse().unwrap(), 129).is_none());
    }

    #[test]
    fn containment_and_overlap_respect_the_family() {
        let net = v4("198.51.100.0", 24);
        assert!(net.contains("198.51.100.200".parse().unwrap()));
        assert!(!net.contains("198.51.101.1".parse().unwrap()));
        assert!(!net.contains("2001:db8::1".parse().unwrap()));
        assert!(net.overlaps(v4("198.51.0.0", 16)));
        assert!(v4("198.51.0.0", 16).overlaps(net));
        assert!(net.overlaps(v4("198.51.100.4", 30)));
        assert!(!net.overlaps(v4("192.0.2.0", 24)));
    }
}
