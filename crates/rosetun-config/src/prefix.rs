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

/// Networks that say nothing about where a computer is on the internet:
/// private, carrier-grade NAT and link-local ones, of both families.
const PRIVATE: [IpPrefix; 7] = [
    IpPrefix::v4([10, 0, 0, 0], 8),
    IpPrefix::v4([100, 64, 0, 0], 10),
    IpPrefix::v4([169, 254, 0, 0], 16),
    IpPrefix::v4([172, 16, 0, 0], 12),
    IpPrefix::v4([192, 168, 0, 0], 16),
    IpPrefix::v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
    IpPrefix::v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
];

/// Whether the address is in one of the private networks.
pub fn is_private_address(address: IpAddr) -> bool {
    let address = address.to_canonical();
    PRIVATE.iter().any(|network| network.contains(address))
}

impl IpPrefix {
    /// Whether the whole network lies inside the private ones.
    pub fn is_private(self) -> bool {
        PRIVATE
            .iter()
            .any(|network| network.length <= self.length && network.contains(self.address))
    }

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

    /// The network without these addresses, as inclusive ranges in address
    /// order. Addresses outside it change nothing; with every address left
    /// out the list is empty.
    pub fn ranges_without(self, left_out: &[IpAddr]) -> Vec<(IpAddr, IpAddr)> {
        let first = bits(self.address);
        let last = first
            | match self.address {
                IpAddr::V4(_) => u128::from(!mask_v4(self.length)),
                IpAddr::V6(_) => !mask_v6(self.length),
            };
        let mut inside: Vec<u128> = left_out
            .iter()
            .filter(|address| self.contains(**address))
            .map(|address| bits(*address))
            .collect();
        inside.sort_unstable();
        inside.dedup();

        let mut ranges = Vec::with_capacity(inside.len() + 1);
        // `None` once the walk has passed the last address of the family.
        let mut next = Some(first);
        for address in inside {
            if let Some(start) = next.filter(|start| *start < address) {
                ranges.push((start, address - 1));
            }
            next = address.checked_add(1);
        }
        if let Some(start) = next.filter(|start| *start <= last) {
            ranges.push((start, last));
        }
        ranges
            .into_iter()
            .map(|(low, high)| (self.address_at(low), self.address_at(high)))
            .collect()
    }

    /// The network without these addresses, as the fewest prefixes.
    pub fn without(self, left_out: &[IpAddr]) -> Vec<Self> {
        let width = match self.address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let mut prefixes = Vec::new();
        for (low, high) in self.ranges_without(left_out) {
            let (mut low, high) = (bits(low), bits(high));
            loop {
                // The largest block that starts at `low` and ends by `high`.
                let span = (high - low).checked_add(1).map_or(128, u128::ilog2);
                let block = low.trailing_zeros().min(span).min(width);
                let length = u8::try_from(width - block).expect("at most 128 bits");
                prefixes.push(
                    Self::new(self.address_at(low), length).expect("a length within the family"),
                );
                let Some(after) = 1_u128
                    .checked_shl(block)
                    .and_then(|size| low.checked_add(size))
                    .filter(|after| *after <= high)
                else {
                    break;
                };
                low = after;
            }
        }
        prefixes
    }

    fn address_at(self, value: u128) -> IpAddr {
        match self.address {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from_bits(
                u32::try_from(value).expect("an IPv4 address is 32 bits"),
            )),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from_bits(value)),
        }
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.length)
    }
}

fn bits(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(address) => u128::from(address.to_bits()),
        IpAddr::V6(address) => address.to_bits(),
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

    #[test]
    fn only_a_network_wholly_inside_the_private_ones_is_private() {
        for private in [
            v4("10.1.0.0", 16),
            v4("172.16.0.0", 12),
            v4("192.168.1.0", 24),
            v4("100.64.0.0", 24),
            v4("169.254.0.0", 16),
            IpPrefix::new("fd00:1::".parse().unwrap(), 64).unwrap(),
            IpPrefix::new("fe80::".parse().unwrap(), 64).unwrap(),
        ] {
            assert!(private.is_private(), "{private}");
        }
        for public in [
            v4("192.0.2.0", 24),
            v4("172.0.0.0", 8),
            v4("8.0.0.0", 8),
            v4("0.0.0.0", 0),
            IpPrefix::new("2001:db8::".parse().unwrap(), 64).unwrap(),
        ] {
            assert!(!public.is_private(), "{public}");
        }
    }

    #[test]
    fn a_mapped_address_is_private_as_its_ipv4_address_is() {
        assert!(is_private_address("192.168.1.1".parse().unwrap()));
        assert!(is_private_address("::ffff:192.168.1.1".parse().unwrap()));
        assert!(is_private_address("fd00::1".parse().unwrap()));
        assert!(!is_private_address("203.0.113.5".parse().unwrap()));
        assert!(!is_private_address("::ffff:203.0.113.5".parse().unwrap()));
        assert!(!is_private_address("2001:db8::1".parse().unwrap()));
    }

    fn addresses(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|text| text.parse().unwrap()).collect()
    }

    fn ranges(prefix: IpPrefix, left_out: &[&str]) -> Vec<String> {
        prefix
            .ranges_without(&addresses(left_out))
            .into_iter()
            .map(|(low, high)| format!("{low}-{high}"))
            .collect()
    }

    fn prefixes(prefix: IpPrefix, left_out: &[&str]) -> Vec<String> {
        prefix
            .without(&addresses(left_out))
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// Every address of a small network, walked one by one.
    fn covered(list: &[String]) -> Vec<u32> {
        let mut all = Vec::new();
        for text in list {
            let (address, length) = text.split_once('/').unwrap();
            let prefix = v4(address, length.parse().unwrap());
            let IpAddr::V4(start) = prefix.address() else {
                panic!("IPv4 only");
            };
            all.extend((0..1_u32 << (32 - prefix.length())).map(|step| start.to_bits() + step));
        }
        all.sort_unstable();
        all
    }

    #[test]
    fn an_address_outside_the_network_changes_nothing() {
        let net = v4("192.0.2.0", 24);
        assert_eq!(ranges(net, &[]), ["192.0.2.0-192.0.2.255"]);
        assert_eq!(ranges(net, &["198.51.100.1"]), ["192.0.2.0-192.0.2.255"]);
        assert_eq!(ranges(net, &["2001:db8::1"]), ["192.0.2.0-192.0.2.255"]);
        assert_eq!(prefixes(net, &["198.51.100.1"]), ["192.0.2.0/24"]);
    }

    #[test]
    fn leaving_out_an_address_in_the_middle_splits_the_network() {
        let net = v4("192.0.2.0", 24);
        assert_eq!(
            ranges(net, &["192.0.2.10"]),
            ["192.0.2.0-192.0.2.9", "192.0.2.11-192.0.2.255"]
        );
        assert_eq!(
            prefixes(net, &["192.0.2.10"]),
            [
                "192.0.2.0/29",
                "192.0.2.8/31",
                "192.0.2.11/32",
                "192.0.2.12/30",
                "192.0.2.16/28",
                "192.0.2.32/27",
                "192.0.2.64/26",
                "192.0.2.128/25",
            ]
        );
    }

    #[test]
    fn leaving_out_the_first_or_the_last_address_leaves_one_range() {
        let net = v4("192.0.2.0", 24);
        assert_eq!(ranges(net, &["192.0.2.0"]), ["192.0.2.1-192.0.2.255"]);
        assert_eq!(ranges(net, &["192.0.2.255"]), ["192.0.2.0-192.0.2.254"]);
        assert_eq!(
            prefixes(net, &["192.0.2.255"]).last().unwrap(),
            "192.0.2.254/32"
        );
    }

    #[test]
    fn several_addresses_repeated_or_side_by_side_leave_no_empty_range() {
        let net = v4("192.0.2.0", 24);
        assert_eq!(
            ranges(
                net,
                &["192.0.2.11", "192.0.2.10", "192.0.2.11", "192.0.2.200"]
            ),
            [
                "192.0.2.0-192.0.2.9",
                "192.0.2.12-192.0.2.199",
                "192.0.2.201-192.0.2.255"
            ]
        );
    }

    #[test]
    fn a_network_of_only_left_out_addresses_has_nothing_left() {
        let net = v4("192.0.2.0", 31);
        assert_eq!(ranges(net, &["192.0.2.0"]), ["192.0.2.1-192.0.2.1"]);
        assert!(ranges(net, &["192.0.2.0", "192.0.2.1"]).is_empty());
        assert!(prefixes(net, &["192.0.2.0", "192.0.2.1"]).is_empty());
    }

    #[test]
    fn the_prefixes_cover_exactly_the_network_without_the_addresses() {
        let net = v4("192.0.2.0", 26);
        let left_out = ["192.0.2.0", "192.0.2.7", "192.0.2.8", "192.0.2.63"];
        let start = u32::from_be_bytes([192, 0, 2, 0]);
        let expected: Vec<u32> = (start..start + 64)
            .filter(|value| {
                !addresses(&left_out).contains(&IpAddr::V4(Ipv4Addr::from_bits(*value)))
            })
            .collect();
        assert_eq!(covered(&prefixes(net, &left_out)), expected);
    }

    #[test]
    fn ipv6_networks_split_too_up_to_the_end_of_the_address_space() {
        let net = IpPrefix::new("2001:db8:1::".parse().unwrap(), 64).unwrap();
        assert_eq!(
            ranges(net, &["2001:db8:1::5"]),
            [
                "2001:db8:1::-2001:db8:1::4",
                "2001:db8:1::6-2001:db8:1:0:ffff:ffff:ffff:ffff"
            ]
        );
        // One prefix per bit of the host part.
        assert_eq!(prefixes(net, &["2001:db8:1::5"]).len(), 64);

        let top = IpPrefix::new("ffff:ffff:ffff:ffff::".parse().unwrap(), 64).unwrap();
        let last = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
        assert_eq!(
            ranges(top, &[last]),
            ["ffff:ffff:ffff:ffff::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"]
        );
        assert_eq!(prefixes(top, &[]), ["ffff:ffff:ffff:ffff::/64"]);
    }

    #[test]
    fn the_whole_address_space_is_one_prefix_without_any_address_left_out() {
        let all = IpPrefix::new("::".parse().unwrap(), 0).unwrap();
        assert_eq!(prefixes(all, &[]), ["::/0"]);
        assert_eq!(prefixes(v4("0.0.0.0", 0), &[]), ["0.0.0.0/0"]);
    }
}
