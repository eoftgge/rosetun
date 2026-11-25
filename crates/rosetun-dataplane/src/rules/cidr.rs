//! Compressed binary radix (Patricia) trie for IPv4 and IPv6 CIDR matching.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rosetun_config::IpPrefix;

/// Parses a CIDR string (`192.0.2.5/24`, host bits masked) or bare IP address
/// (`192.0.2.5` as `/32`, `2001:db8::1` as `/128`) into a canonical [`IpPrefix`].
pub fn parse_cidr(text: &str) -> Option<IpPrefix> {
    let text = text.trim();
    let (addr, prefix_len) = match text.split_once('/') {
        Some((ip, len)) => (ip.parse::<IpAddr>().ok()?, len.parse::<u8>().ok()?),
        None => {
            let ip = text.parse::<IpAddr>().ok()?;
            (ip, if ip.is_ipv4() { 32 } else { 128 })
        }
    };
    IpPrefix::new(addr, prefix_len)
}

/// Compressed binary radix tree for IPv4 and IPv6 prefixes.
///
/// Queries convert IPv4-mapped IPv6 addresses via [`IpAddr::to_canonical`] so
/// an IPv4 prefix matches `::ffff:a.b.c.d`, while still checking native IPv6
/// supernets (such as `::/0` or `::ffff:0:0/96`) when the queried address is
/// IPv6.
#[derive(Clone, Default)]
pub struct CidrTree {
    v4: RadixTrie<u32>,
    v6: RadixTrie<u128>,
}

impl fmt::Debug for CidrTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CidrTree")
            .field("v4_prefixes", &self.v4.prefix_count)
            .field("v6_prefixes", &self.v6.prefix_count)
            .finish()
    }
}

impl CidrTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn insert(&mut self, prefix: IpPrefix) {
        match prefix.address() {
            IpAddr::V4(addr) => self.v4.insert(addr.to_bits(), prefix.length()),
            IpAddr::V6(addr) => self.v6.insert(addr.to_bits(), prefix.length()),
        }
    }

    /// Inserts every address in the inclusive range `[from, to]` as a minimal
    /// cover of CIDR prefixes. Ignores mismatched families or inverted bounds.
    pub(crate) fn insert_range(&mut self, from: IpAddr, to: IpAddr) {
        match (from, to) {
            (IpAddr::V4(from), IpAddr::V4(to)) => {
                insert_bits_range(&mut self.v4, from.to_bits(), to.to_bits());
            }
            (IpAddr::V6(from), IpAddr::V6(to)) => {
                insert_bits_range(&mut self.v6, from.to_bits(), to.to_bits());
            }
            _ => {}
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(v4) => {
                self.v4.contains(v4.to_bits())
                    || matches!(ip, IpAddr::V6(v6) if self.v6.contains(v6.to_bits()))
            }
            IpAddr::V6(v6) => self.v6.contains(v6.to_bits()),
        }
    }
}

trait Bits: Copy + Eq + Ord {
    const BITS: u8;
    const ZERO: Self;

    fn mask(prefix_len: u8) -> Self;
    fn bit_at(self, pos: u8) -> usize;
    fn common_prefix_len(a: Self, a_len: u8, b: Self, b_len: u8) -> u8;
    fn bit_and(self, rhs: Self) -> Self;
    fn trailing_zeros_u8(self) -> u8;
    fn leading_zeros_u8(self) -> u8;
    fn wrapping_sub(self, rhs: Self) -> Self;
    fn checked_add_one(self) -> Option<Self>;
    fn shl_one(shift: u8) -> Self;
    fn checked_add(self, rhs: Self) -> Option<Self>;
}

impl Bits for u32 {
    const BITS: u8 = 32;
    const ZERO: Self = 0;

    fn mask(prefix_len: u8) -> Self {
        if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(prefix_len))
        }
    }

    fn bit_at(self, pos: u8) -> usize {
        ((self >> (31 - u32::from(pos))) & 1) as usize
    }

    fn common_prefix_len(a: Self, a_len: u8, b: Self, b_len: u8) -> u8 {
        let min_len = a_len.min(b_len);
        let diff = (a ^ b) & Self::mask(min_len);
        if diff == 0 {
            min_len
        } else {
            diff.leading_zeros() as u8
        }
    }

    fn bit_and(self, rhs: Self) -> Self {
        self & rhs
    }

    fn trailing_zeros_u8(self) -> u8 {
        self.trailing_zeros() as u8
    }

    fn leading_zeros_u8(self) -> u8 {
        self.leading_zeros() as u8
    }

    fn wrapping_sub(self, rhs: Self) -> Self {
        self.wrapping_sub(rhs)
    }

    fn checked_add_one(self) -> Option<Self> {
        self.checked_add(1)
    }

    fn shl_one(shift: u8) -> Self {
        1_u32 << u32::from(shift)
    }

    fn checked_add(self, rhs: Self) -> Option<Self> {
        u32::checked_add(self, rhs)
    }
}

impl Bits for u128 {
    const BITS: u8 = 128;
    const ZERO: Self = 0;

    fn mask(prefix_len: u8) -> Self {
        if prefix_len == 0 {
            0
        } else {
            u128::MAX << (128 - u32::from(prefix_len))
        }
    }

    fn bit_at(self, pos: u8) -> usize {
        ((self >> (127 - u32::from(pos))) & 1) as usize
    }

    fn common_prefix_len(a: Self, a_len: u8, b: Self, b_len: u8) -> u8 {
        let min_len = a_len.min(b_len);
        let diff = (a ^ b) & Self::mask(min_len);
        if diff == 0 {
            min_len
        } else {
            diff.leading_zeros() as u8
        }
    }

    fn bit_and(self, rhs: Self) -> Self {
        self & rhs
    }

    fn trailing_zeros_u8(self) -> u8 {
        self.trailing_zeros() as u8
    }

    fn leading_zeros_u8(self) -> u8 {
        self.leading_zeros() as u8
    }

    fn wrapping_sub(self, rhs: Self) -> Self {
        self.wrapping_sub(rhs)
    }

    fn checked_add_one(self) -> Option<Self> {
        self.checked_add(1)
    }

    fn shl_one(shift: u8) -> Self {
        1_u128 << u32::from(shift)
    }

    fn checked_add(self, rhs: Self) -> Option<Self> {
        u128::checked_add(self, rhs)
    }
}

#[derive(Clone)]
struct Node<K> {
    prefix: K,
    prefix_len: u8,
    terminal: bool,
    children: [Option<usize>; 2],
}

#[derive(Clone)]
struct RadixTrie<K> {
    nodes: Vec<Node<K>>,
    root: Option<usize>,
    prefix_count: usize,
}

impl<K> Default for RadixTrie<K> {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            root: None,
            prefix_count: 0,
        }
    }
}

impl<K: Bits> RadixTrie<K> {
    fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    fn insert(&mut self, raw: K, len: u8) {
        let len = len.min(K::BITS);
        let key = raw.bit_and(K::mask(len));
        let Some(mut cur) = self.root else {
            self.nodes.push(Node {
                prefix: key,
                prefix_len: len,
                terminal: true,
                children: [None, None],
            });
            self.root = Some(0);
            self.prefix_count = 1;
            return;
        };

        loop {
            let node_prefix = self.nodes[cur].prefix;
            let node_len = self.nodes[cur].prefix_len;
            let common = K::common_prefix_len(node_prefix, node_len, key, len);

            if common < node_len {
                let old_node = self.nodes[cur].clone();
                let old_child_idx = self.nodes.len();
                self.nodes.push(old_node);

                let mut split = Node {
                    prefix: key.bit_and(K::mask(common)),
                    prefix_len: common,
                    terminal: common == len,
                    children: [None, None],
                };
                split.children[node_prefix.bit_at(common)] = Some(old_child_idx);

                if common < len {
                    let new_leaf_idx = self.nodes.len();
                    self.nodes.push(Node {
                        prefix: key,
                        prefix_len: len,
                        terminal: true,
                        children: [None, None],
                    });
                    split.children[key.bit_at(common)] = Some(new_leaf_idx);
                }
                self.nodes[cur] = split;
                self.prefix_count += 1;
                return;
            }

            if common == len {
                if !self.nodes[cur].terminal {
                    self.nodes[cur].terminal = true;
                    self.prefix_count += 1;
                }
                return;
            }

            let bit = key.bit_at(node_len);
            if let Some(child) = self.nodes[cur].children[bit] {
                cur = child;
            } else {
                let new_leaf_idx = self.nodes.len();
                self.nodes.push(Node {
                    prefix: key,
                    prefix_len: len,
                    terminal: true,
                    children: [None, None],
                });
                self.nodes[cur].children[bit] = Some(new_leaf_idx);
                self.prefix_count += 1;
                return;
            }
        }
    }

    fn contains(&self, addr: K) -> bool {
        let Some(mut cur) = self.root else {
            return false;
        };
        loop {
            let node = &self.nodes[cur];
            if addr.bit_and(K::mask(node.prefix_len)) != node.prefix {
                return false;
            }
            if node.terminal {
                return true;
            }
            if node.prefix_len == K::BITS {
                return false;
            }
            let Some(next) = node.children[addr.bit_at(node.prefix_len)] else {
                return false;
            };
            cur = next;
        }
    }
}

fn insert_bits_range<K: Bits>(trie: &mut RadixTrie<K>, from: K, to: K) {
    if from > to {
        return;
    }
    let mut cur = from;
    loop {
        let max_align = if cur == K::ZERO {
            K::BITS
        } else {
            cur.trailing_zeros_u8()
        };
        let remaining = to.wrapping_sub(cur);
        let max_span = match remaining.checked_add_one() {
            None => K::BITS,
            Some(count) => K::BITS - 1 - count.leading_zeros_u8(),
        };
        let host_bits = max_align.min(max_span);
        trie.insert(cur, K::BITS - host_bits);
        if host_bits == K::BITS {
            break;
        }
        let Some(next) = cur.checked_add(K::shl_one(host_bits)) else {
            break;
        };
        if next > to {
            break;
        }
        cur = next;
    }
}

/// Converts a 4- or 16-byte big-endian slice into an [`IpAddr`].
pub(crate) fn ip_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes {
        [a, b, c, d] => Some(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
        bytes if bytes.len() == 16 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(bytes);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
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
    fn parse_cidr_masks_host_bits_and_accepts_bare_addresses() {
        let v4 = parse_cidr("192.0.2.5/24").unwrap();
        assert_eq!(v4.address(), ip("192.0.2.0"));
        assert_eq!(v4.length(), 24);

        let bare_v4 = parse_cidr("198.51.100.7").unwrap();
        assert_eq!(bare_v4.address(), ip("198.51.100.7"));
        assert_eq!(bare_v4.length(), 32);

        let v6 = parse_cidr("2001:db8:abcd::42/32").unwrap();
        assert_eq!(v6.address(), ip("2001:db8::"));
        assert_eq!(v6.length(), 32);

        let bare_v6 = parse_cidr("2001:db8::9").unwrap();
        assert_eq!(bare_v6.address(), ip("2001:db8::9"));
        assert_eq!(bare_v6.length(), 128);

        assert!(parse_cidr("192.0.2.0/33").is_none());
        assert!(parse_cidr("2001:db8::/129").is_none());
        assert!(parse_cidr("not-an-ip").is_none());
    }

    #[test]
    fn cidr_tree_matches_ipv4_ipv6_nesting_and_edge_lengths() {
        let mut tree = CidrTree::new();
        assert!(tree.is_empty());
        assert!(!tree.contains(ip("192.0.2.1")));

        // Insert subnet before supernet and supernet before subnet.
        tree.insert(parse_cidr("192.0.2.128/25").unwrap());
        tree.insert(parse_cidr("192.0.2.0/24").unwrap());
        tree.insert(parse_cidr("198.51.100.0/24").unwrap());
        tree.insert(parse_cidr("198.51.100.42/32").unwrap());
        tree.insert(parse_cidr("203.0.113.1/32").unwrap());
        tree.insert(parse_cidr("203.0.113.2/32").unwrap());
        tree.insert(parse_cidr("2001:db8:1::/48").unwrap());
        tree.insert(parse_cidr("2001:db8:2::7/128").unwrap());

        assert!(tree.contains(ip("192.0.2.0")));
        assert!(tree.contains(ip("192.0.2.129")));
        assert!(tree.contains(ip("192.0.2.255")));
        assert!(!tree.contains(ip("192.0.3.0")));

        assert!(tree.contains(ip("198.51.100.42")));
        assert!(tree.contains(ip("198.51.100.99")));

        assert!(!tree.contains(ip("203.0.113.0")));
        assert!(tree.contains(ip("203.0.113.1")));
        assert!(tree.contains(ip("203.0.113.2")));
        assert!(!tree.contains(ip("203.0.113.3")));

        assert!(tree.contains(ip("2001:db8:1::abcd")));
        assert!(!tree.contains(ip("2001:db8:2::6")));
        assert!(tree.contains(ip("2001:db8:2::7")));
        assert!(!tree.contains(ip("2001:db8:2::8")));
    }

    #[test]
    fn cidr_tree_handles_slash_zero_and_v4_mapped_addresses() {
        let mut v4_only = CidrTree::new();
        v4_only.insert(parse_cidr("192.0.2.0/24").unwrap());
        assert!(v4_only.contains(ip("::ffff:192.0.2.9")));
        assert!(!v4_only.contains(ip("::ffff:198.51.100.9")));

        let mut all_v4 = CidrTree::new();
        all_v4.insert(parse_cidr("0.0.0.0/0").unwrap());
        assert!(all_v4.contains(ip("192.0.2.1")));
        assert!(all_v4.contains(ip("::ffff:203.0.113.5")));
        assert!(!all_v4.contains(ip("2001:db8::1")));

        let mut all_v6 = CidrTree::new();
        all_v6.insert(parse_cidr("::/0").unwrap());
        assert!(all_v6.contains(ip("2001:db8::1")));
        assert!(all_v6.contains(ip("::ffff:192.0.2.1")));
        assert!(!all_v6.contains(ip("192.0.2.1")));
    }

    #[test]
    fn cidr_tree_range_insertion_covers_exact_inclusive_bounds() {
        let mut tree = CidrTree::new();
        tree.insert_range(ip("192.0.2.3"), ip("192.0.2.10"));
        for last in 0_u8..=20 {
            let addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, last));
            assert_eq!(tree.contains(addr), (3..=10).contains(&last), "{addr}");
        }

        let mut full = CidrTree::new();
        full.insert_range(ip("0.0.0.0"), ip("255.255.255.255"));
        assert!(full.contains(ip("0.0.0.0")));
        assert!(full.contains(ip("198.51.100.42")));
        assert!(full.contains(ip("255.255.255.255")));

        let mut v6 = CidrTree::new();
        v6.insert_range(ip("2001:db8::1"), ip("2001:db8::5"));
        assert!(!v6.contains(ip("2001:db8::")));
        assert!(v6.contains(ip("2001:db8::1")));
        assert!(v6.contains(ip("2001:db8::5")));
        assert!(!v6.contains(ip("2001:db8::6")));
    }

    #[test]
    fn cidr_tree_debug_redacts_prefixes() {
        let mut tree = CidrTree::new();
        tree.insert(parse_cidr("192.0.2.0/24").unwrap());
        let debug = format!("{tree:?}");
        assert!(!debug.contains("192.0.2"));
    }
}
