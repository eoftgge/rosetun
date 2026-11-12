//! "Local network": the networks the computer's physical adapters are
//! connected to, which stay outside the tunnel and are the only ones the
//! kill switch opens, each on its own adapter.

use std::fmt;
use std::net::IpAddr;

use rosetun_config::IpPrefix;

/// The shortest IPv4 network taken as a whole. A /16 is the largest private
/// block a home or office uses; a shorter connected network is a provider's
/// or a flat corporate one, where "the devices next to me" would be
/// thousands of strangers.
pub const MIN_IPV4_LENGTH: u8 = 16;
/// The IPv6 counterpart: a link is a /64; anything shorter than a site's
/// /48 is not one segment.
pub const MIN_IPV6_LENGTH: u8 = 48;
/// How many VPN servers one connected network may hold and still stay open
/// without their addresses. A session has a main node and a few exits, rarely
/// on one network. This bounds the address conditions of a WFP filter, which
/// keeps Lockdown's one fixed key per connected network, and the prefixes
/// sing-box gets.
pub const MAX_SERVERS_PER_NETWORK: usize = 8;

/// An adapter as the routing layer identifies it, opaque outside the crate.
/// On Windows the value is the interface LUID, on Linux the interface index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InterfaceId(pub(crate) u64);

/// One connected network and the adapter it is connected through.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SegmentNetwork {
    pub prefix: IpPrefix,
    pub(crate) interface: InterfaceId,
}

/// A public network tells where the computer is, and plans reach the log.
impl fmt::Debug for SegmentNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("SegmentNetwork");
        if self.prefix.is_private() {
            debug.field("prefix", &self.prefix);
        } else {
            debug.field("prefix", &format_args!("public"));
        }
        debug.field("interface", &self.interface).finish()
    }
}

/// The computer's own segment: connected networks of the physical adapters
/// and the adapters themselves, which carry link-local traffic. The addresses
/// of VPN servers inside those networks are not part of it: only the engine
/// goes there, by its own permit.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct LanSegment {
    networks: Vec<SegmentNetwork>,
    interfaces: Vec<InterfaceId>,
    /// The physical adapters' names, which nftables matches (`iifname` and
    /// `oifname`): a name outlives an interface that is made again, an index
    /// does not.
    names: Vec<(InterfaceId, String)>,
    left_out: Vec<IpAddr>,
}

/// Node addresses stay out of logs, and plans and scans are logged whole.
impl fmt::Debug for LanSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LanSegment")
            .field("networks", &self.networks)
            .field("interfaces", &self.interfaces)
            .field("left_out", &self.left_out.len())
            .finish()
    }
}

impl LanSegment {
    #[cfg(windows)]
    pub(crate) fn from_parts(
        mut networks: Vec<SegmentNetwork>,
        mut interfaces: Vec<InterfaceId>,
    ) -> Self {
        networks.sort_by_key(|network| (network.prefix, network.interface));
        networks.dedup();
        interfaces.sort_unstable();
        interfaces.dedup();
        Self {
            networks,
            interfaces,
            names: Vec::new(),
            left_out: Vec::new(),
        }
    }

    /// This segment without these addresses, as `select` leaves out servers,
    /// for tests of code that only passes segments along.
    #[doc(hidden)]
    pub fn leaving_out(mut self, addresses: &[IpAddr]) -> Self {
        self.left_out.extend(addresses.iter().filter(|address| {
            self.networks
                .iter()
                .any(|network| network.prefix.contains(**address))
        }));
        self.left_out.sort_unstable();
        self.left_out.dedup();
        self
    }

    /// A segment of these networks on one adapter, for tests of code that
    /// only passes segments along.
    #[doc(hidden)]
    pub fn for_tests(prefixes: &[IpPrefix]) -> Self {
        Self {
            networks: prefixes
                .iter()
                .map(|&prefix| SegmentNetwork {
                    prefix,
                    interface: InterfaceId(1),
                })
                .collect(),
            interfaces: vec![InterfaceId(1)],
            names: Vec::new(),
            left_out: Vec::new(),
        }
    }

    /// A segment of these networks on the interface of this name, for tests
    /// of code that renders rules from it.
    #[doc(hidden)]
    pub fn named_for_tests(interface: &str, prefixes: &[IpPrefix]) -> Self {
        let mut segment = Self::for_tests(prefixes);
        segment.names = vec![(InterfaceId(1), interface.to_owned())];
        segment
    }

    pub fn networks(&self) -> &[SegmentNetwork] {
        &self.networks
    }

    /// The connected networks whole, which say less about a server than
    /// `route_networks` does: this is the list for logs.
    pub fn prefixes(&self) -> Vec<IpPrefix> {
        self.networks.iter().map(|network| network.prefix).collect()
    }

    /// The VPN servers' addresses left out of the networks, in order.
    pub fn left_out(&self) -> &[IpAddr] {
        &self.left_out
    }

    /// The segment as routes: each connected network without the addresses
    /// left out. Traffic to one of those stays in the tunnel, as to any
    /// address outside.
    pub fn route_networks(&self) -> Vec<IpPrefix> {
        let mut prefixes: Vec<IpPrefix> = self
            .networks
            .iter()
            .flat_map(|network| network.prefix.without(&self.left_out))
            .collect();
        // The same network on two adapters is one route.
        prefixes.sort_unstable();
        prefixes.dedup();
        prefixes
    }

    /// The physical adapters that are up, in a stable order.
    #[cfg_attr(
        not(any(windows, target_os = "linux", test)),
        expect(dead_code, reason = "only WFP and nftables use it")
    )]
    pub(crate) fn interfaces(&self) -> &[InterfaceId] {
        &self.interfaces
    }

    /// The name of one of the segment's adapters, where the platform gave one.
    #[cfg_attr(
        not(target_os = "linux"),
        expect(dead_code, reason = "only nftables matches by name")
    )]
    pub(crate) fn interface_name(&self, interface: InterfaceId) -> Option<&str> {
        self.names
            .iter()
            .find(|(id, _)| *id == interface)
            .map(|(_, name)| name.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.networks.is_empty() && self.interfaces.is_empty()
    }
}

/// What "Local network" opens.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LanAccess {
    pub segment: LanSegment,
    /// "Private networks behind the router": every private range, on any
    /// adapter, as before the segment existed.
    pub private_networks: bool,
    /// The tunnel carries IPv6, so IPv6 link-local multicast can work at all.
    pub ipv6_multicast: bool,
    /// The session's VPN servers, in the form `canonical_servers` gives, left
    /// out of the private ranges and the link-local networks as `LanSegment`
    /// leaves them out of the connected ones.
    pub servers: Vec<IpAddr>,
}

/// Servers as WFP and the networks compare them: IPv4 given as IPv4.
pub fn canonical_servers(servers: &[IpAddr]) -> Vec<IpAddr> {
    let mut servers: Vec<IpAddr> = servers.iter().map(IpAddr::to_canonical).collect();
    servers.sort_unstable();
    servers.dedup();
    servers
}

/// Why a connected network is not part of the segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Shorter than `MIN_IPV4_LENGTH` or `MIN_IPV6_LENGTH`.
    TooWide,
    /// It holds the tunnel's own addresses.
    OverlapsTunnel,
    /// It holds more than `MAX_SERVERS_PER_NETWORK` VPN servers, or nothing
    /// else.
    TooManyServers,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SegmentScan {
    pub segment: LanSegment,
    pub skipped: Vec<(IpPrefix, SkipReason)>,
}

/// What the segment must stay clear of.
#[derive(Debug, Clone, Copy)]
pub struct SegmentQuery<'a> {
    /// The tunnel adapter's alias, never part of the segment.
    pub tunnel_alias: &'a str,
    /// The tunnel's own networks, such as 172.19.0.0/30.
    pub tunnel_networks: &'a [IpPrefix],
    /// Addresses of the VPN servers of the session, which the networks stay
    /// open without.
    pub servers: &'a [IpAddr],
}

/// An adapter as the platform reports it.
#[cfg(any(windows, target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Adapter {
    pub(crate) interface: InterfaceId,
    pub(crate) alias: String,
    pub(crate) description: String,
    /// IANA ifType: 6 Ethernet, 71 Wi-Fi, 24 loopback, 53 and 131 tunnels.
    /// Linux maps what it knows onto these.
    pub(crate) if_type: u32,
    pub(crate) up: bool,
    /// Windows' `HardwareInterface` flag, on Linux a device behind the
    /// interface: a NIC, not a driver's software adapter.
    pub(crate) hardware: bool,
    pub(crate) has_gateway: bool,
    /// Usable unicast addresses with their on-link prefix lengths.
    pub(crate) addresses: Vec<(IpAddr, u8)>,
}

#[cfg(any(windows, target_os = "linux", test))]
pub(crate) const ETHERNET: u32 = 6;
#[cfg(any(windows, target_os = "linux", test))]
pub(crate) const WIFI: u32 = 71;
/// Software adapters of other VPNs that present themselves as Ethernet.
#[cfg(any(windows, target_os = "linux", test))]
const TUNNEL_MARKERS: [&str; 6] = ["tap", "vpn", "wintun", "wireguard", "tunnel", "openvpn"];

/// Whether the adapter leads to a real network next to the computer.
///
/// A NIC (Ethernet or Wi-Fi with the hardware flag) does. A software
/// Ethernet adapter does only when it holds a default gateway and is not a
/// VPN's: that is the host side of a Hyper-V external switch, which carries
/// the real network once the NIC is bound to the switch. Hyper-V's Default
/// Switch and WSL's vEthernet have no gateway, so they stay out; so do
/// host-only VM adapters. Tunnels (53, 131) and loopback (24) are not
/// Ethernet or Wi-Fi at all.
#[cfg(any(windows, target_os = "linux", test))]
pub(crate) fn is_physical(adapter: &Adapter, tunnel_alias: &str) -> bool {
    if !adapter.up
        || adapter.alias.eq_ignore_ascii_case(tunnel_alias)
        || !matches!(adapter.if_type, ETHERNET | WIFI)
    {
        return false;
    }
    if adapter.hardware {
        return true;
    }
    let name = format!("{} {}", adapter.alias, adapter.description).to_ascii_lowercase();
    adapter.has_gateway && !TUNNEL_MARKERS.iter().any(|marker| name.contains(marker))
}

/// The segment of these adapters.
#[cfg(any(windows, target_os = "linux", test))]
pub(crate) fn select(adapters: &[Adapter], query: &SegmentQuery<'_>) -> SegmentScan {
    let mut scan = SegmentScan::default();
    let mut interfaces = Vec::new();
    for adapter in adapters
        .iter()
        .filter(|adapter| is_physical(adapter, query.tunnel_alias))
    {
        interfaces.push(adapter.interface);
        for &(address, length) in &adapter.addresses {
            let Some(prefix) = IpPrefix::new(address, length) else {
                continue;
            };
            if !counts(address, length) {
                continue;
            }
            let wide = match address {
                IpAddr::V4(_) => length < MIN_IPV4_LENGTH,
                IpAddr::V6(_) => length < MIN_IPV6_LENGTH,
            };
            let reason = if wide {
                Some(SkipReason::TooWide)
            } else if query
                .tunnel_networks
                .iter()
                .any(|tunnel| tunnel.overlaps(prefix))
            {
                Some(SkipReason::OverlapsTunnel)
            } else {
                let mut servers: Vec<IpAddr> = query
                    .servers
                    .iter()
                    .map(IpAddr::to_canonical)
                    .filter(|server| prefix.contains(*server))
                    .collect();
                servers.sort_unstable();
                servers.dedup();
                if servers.len() > MAX_SERVERS_PER_NETWORK
                    || prefix.ranges_without(&servers).is_empty()
                {
                    Some(SkipReason::TooManyServers)
                } else {
                    scan.segment.left_out.extend(servers);
                    None
                }
            };
            match reason {
                Some(reason) => {
                    if !scan.skipped.contains(&(prefix, reason)) {
                        scan.skipped.push((prefix, reason));
                    }
                }
                None => {
                    let network = SegmentNetwork {
                        prefix,
                        interface: adapter.interface,
                    };
                    if !scan.segment.networks.contains(&network) {
                        scan.segment.networks.push(network);
                    }
                }
            }
        }
    }
    interfaces.sort_unstable();
    interfaces.dedup();
    scan.segment.interfaces = interfaces;
    scan.segment.names = adapters
        .iter()
        .filter(|adapter| scan.segment.interfaces.contains(&adapter.interface))
        .map(|adapter| (adapter.interface, adapter.alias.clone()))
        .collect();
    scan.segment
        .networks
        .sort_by_key(|network| (network.prefix, network.interface));
    scan.segment.left_out.sort_unstable();
    scan.segment.left_out.dedup();
    scan
}

/// Host routes and link-local addresses add nothing: a /32 has no
/// neighbours, and link-local networks are opened on every physical adapter
/// anyway.
#[cfg(any(windows, target_os = "linux", test))]
fn counts(address: IpAddr, length: u8) -> bool {
    match address {
        IpAddr::V4(address) => length < 32 && !address.is_link_local() && !address.is_loopback(),
        IpAddr::V6(address) => {
            length < 128 && !address.is_unicast_link_local() && !address.is_loopback()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(id: u64, alias: &str, if_type: u32, hardware: bool) -> Adapter {
        Adapter {
            interface: InterfaceId(id),
            alias: alias.to_owned(),
            description: String::new(),
            if_type,
            up: true,
            hardware,
            has_gateway: false,
            addresses: Vec::new(),
        }
    }

    fn with(mut adapter: Adapter, addresses: &[(&str, u8)]) -> Adapter {
        adapter.addresses = addresses
            .iter()
            .map(|(address, length)| (address.parse().unwrap(), *length))
            .collect();
        adapter
    }

    fn prefix(text: &str, length: u8) -> IpPrefix {
        IpPrefix::new(text.parse().unwrap(), length).unwrap()
    }

    const QUERY: SegmentQuery<'static> = SegmentQuery {
        tunnel_alias: "rosetun0",
        tunnel_networks: &[],
        servers: &[],
    };

    #[test]
    fn nics_count_and_tunnels_loopback_and_down_adapters_do_not() {
        assert!(is_physical(&adapter(1, "Ethernet", 6, true), "rosetun0"));
        assert!(is_physical(&adapter(2, "Wi-Fi", 71, true), "rosetun0"));
        assert!(!is_physical(&adapter(3, "rosetun0", 53, false), "rosetun0"));
        assert!(!is_physical(&adapter(4, "ROSETUN0", 6, true), "rosetun0"));
        assert!(!is_physical(
            &adapter(5, "WireGuard", 53, false),
            "rosetun0"
        ));
        assert!(!is_physical(&adapter(6, "Teredo", 131, false), "rosetun0"));
        assert!(!is_physical(&adapter(7, "Loopback", 24, false), "rosetun0"));
        let mut down = adapter(8, "Ethernet 2", 6, true);
        down.up = false;
        assert!(!is_physical(&down, "rosetun0"));
    }

    #[test]
    fn a_software_ethernet_adapter_counts_only_with_a_gateway_and_not_as_a_vpn() {
        let mut default_switch = adapter(1, "vEthernet (Default Switch)", 6, false);
        default_switch.description = "Hyper-V Virtual Ethernet Adapter".into();
        assert!(!is_physical(&default_switch, "rosetun0"));

        let mut external = default_switch.clone();
        external.alias = "vEthernet (External)".into();
        external.has_gateway = true;
        assert!(is_physical(&external, "rosetun0"));

        let mut tap = adapter(2, "Ethernet 3", 6, false);
        tap.description = "TAP-Windows Adapter V9".into();
        tap.has_gateway = true;
        assert!(!is_physical(&tap, "rosetun0"));
    }

    #[test]
    fn the_segment_is_each_connected_network_with_its_adapter() {
        let adapters = [
            with(
                adapter(10, "Ethernet", 6, true),
                &[
                    ("192.0.2.15", 24),
                    ("2001:db8:1::15", 64),
                    ("fe80::1", 64),
                    ("169.254.3.4", 16),
                ],
            ),
            with(adapter(20, "Wi-Fi", 71, true), &[("198.51.100.20", 24)]),
            with(adapter(30, "rosetun0", 53, false), &[("172.19.0.1", 30)]),
            with(
                adapter(40, "vEthernet (WSL)", 6, false),
                &[("203.0.113.1", 28)],
            ),
        ];
        let scan = select(&adapters, &QUERY);
        assert!(scan.skipped.is_empty());
        assert_eq!(
            scan.segment.networks(),
            [
                SegmentNetwork {
                    prefix: prefix("192.0.2.0", 24),
                    interface: InterfaceId(10),
                },
                SegmentNetwork {
                    prefix: prefix("198.51.100.0", 24),
                    interface: InterfaceId(20),
                },
                SegmentNetwork {
                    prefix: prefix("2001:db8:1::", 64),
                    interface: InterfaceId(10),
                },
            ]
        );
        assert_eq!(
            scan.segment.interfaces(),
            [InterfaceId(10), InterfaceId(20)]
        );
    }

    #[test]
    fn wide_networks_and_ones_holding_the_tunnel_are_left_out() {
        let adapters = [with(
            adapter(1, "Ethernet", 6, true),
            &[
                ("10.1.2.3", 8),
                ("2001:db8::5", 32),
                ("172.19.0.9", 24),
                ("192.0.2.9", 16),
            ],
        )];
        let tunnel = [prefix("172.19.0.0", 30)];
        let scan = select(
            &adapters,
            &SegmentQuery {
                tunnel_alias: "rosetun0",
                tunnel_networks: &tunnel,
                servers: &[],
            },
        );
        assert_eq!(scan.segment.prefixes(), [prefix("192.0.0.0", 16)]);
        assert_eq!(
            scan.skipped,
            [
                (prefix("10.0.0.0", 8), SkipReason::TooWide),
                (prefix("2001:db8::", 32), SkipReason::TooWide),
                (prefix("172.19.0.0", 24), SkipReason::OverlapsTunnel),
            ]
        );
    }

    fn scan_with_servers(addresses: &[(&str, u8)], servers: &[IpAddr]) -> SegmentScan {
        let adapters = [with(adapter(1, "Ethernet", 6, true), addresses)];
        select(
            &adapters,
            &SegmentQuery {
                tunnel_alias: "rosetun0",
                tunnel_networks: &[prefix("172.19.0.0", 30)],
                servers,
            },
        )
    }

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|text| text.parse().unwrap()).collect()
    }

    #[test]
    fn a_network_holding_a_server_stays_open_without_that_address() {
        let servers = ips(&["198.51.100.200", "203.0.113.5", "2001:db8:1::7"]);
        let scan = scan_with_servers(
            &[
                ("198.51.100.9", 24),
                ("2001:db8:1::9", 64),
                ("192.0.2.9", 24),
            ],
            &servers,
        );
        assert!(scan.skipped.is_empty());
        assert_eq!(
            scan.segment.prefixes(),
            [
                prefix("192.0.2.0", 24),
                prefix("198.51.100.0", 24),
                prefix("2001:db8:1::", 64),
            ]
        );
        // The server outside every network is nobody's concern here.
        assert_eq!(
            scan.segment.left_out(),
            ips(&["198.51.100.200", "2001:db8:1::7"])
        );
        let routes = scan.segment.route_networks();
        assert!(routes.contains(&prefix("192.0.2.0", 24)));
        assert!(routes.contains(&prefix("198.51.100.0", 25)));
        assert!(routes.contains(&prefix("198.51.100.201", 32)));
        for server in scan.segment.left_out() {
            assert!(routes.iter().all(|route| !route.contains(*server)));
        }
    }

    #[test]
    fn a_server_given_as_a_mapped_address_counts_as_ipv4() {
        let scan = scan_with_servers(&[("198.51.100.9", 24)], &ips(&["::ffff:198.51.100.200"]));
        assert_eq!(scan.segment.left_out(), ips(&["198.51.100.200"]));
    }

    #[test]
    fn a_network_holding_the_tunnel_stays_closed_whatever_servers_it_holds() {
        let scan = scan_with_servers(&[("172.19.0.9", 24)], &ips(&["172.19.0.200"]));
        assert!(scan.segment.networks().is_empty());
        assert!(scan.segment.left_out().is_empty());
        assert_eq!(
            scan.skipped,
            [(prefix("172.19.0.0", 24), SkipReason::OverlapsTunnel)]
        );
    }

    #[test]
    fn a_network_with_more_servers_than_the_limit_stays_closed() {
        let servers: Vec<IpAddr> = (1..=u8::try_from(MAX_SERVERS_PER_NETWORK + 1).unwrap())
            .map(|host| IpAddr::from([198, 51, 100, host]))
            .collect();
        let at_limit = scan_with_servers(
            &[("198.51.100.200", 24)],
            &servers[..MAX_SERVERS_PER_NETWORK],
        );
        assert!(at_limit.skipped.is_empty());
        assert_eq!(at_limit.segment.left_out().len(), MAX_SERVERS_PER_NETWORK);

        let past_limit = scan_with_servers(&[("198.51.100.200", 24)], &servers);
        assert!(past_limit.segment.networks().is_empty());
        assert!(past_limit.segment.left_out().is_empty());
        assert_eq!(
            past_limit.skipped,
            [(prefix("198.51.100.0", 24), SkipReason::TooManyServers)]
        );
    }

    #[test]
    fn a_network_of_only_servers_stays_closed() {
        let scan = scan_with_servers(
            &[("198.51.100.0", 31)],
            &ips(&["198.51.100.0", "198.51.100.1"]),
        );
        assert!(scan.segment.networks().is_empty());
        assert_eq!(
            scan.skipped,
            [(prefix("198.51.100.0", 31), SkipReason::TooManyServers)]
        );
    }

    #[test]
    fn the_debug_form_of_a_segment_does_not_name_a_server() {
        let scan = scan_with_servers(&[("198.51.100.9", 24)], &ips(&["198.51.100.200"]));
        assert!(!format!("{scan:?}").contains("198.51.100.200"));
    }

    #[test]
    fn the_debug_form_of_a_segment_names_private_networks_only() {
        let scan = scan_with_servers(&[("198.51.100.9", 24), ("192.168.1.9", 24)], &[]);
        let text = format!("{:?}", scan.segment);
        assert!(text.contains("192.168.1.0"), "{text}");
        assert!(text.contains("prefix: public"), "{text}");
        assert!(!text.contains("198.51.100"), "{text}");
    }

    #[test]
    fn another_server_address_makes_another_segment() {
        let one = scan_with_servers(&[("198.51.100.9", 24)], &ips(&["198.51.100.200"]));
        let other = scan_with_servers(&[("198.51.100.9", 24)], &ips(&["198.51.100.201"]));
        assert_ne!(one.segment, other.segment);
    }

    #[test]
    fn an_adapter_with_only_link_local_addresses_still_carries_link_local_traffic() {
        let adapters = [with(
            adapter(7, "Ethernet", 6, true),
            &[("169.254.9.9", 16), ("fe80::9", 64)],
        )];
        let scan = select(&adapters, &QUERY);
        assert!(scan.segment.networks().is_empty());
        assert_eq!(scan.segment.interfaces(), [InterfaceId(7)]);
        assert!(!scan.segment.is_empty());
    }
}
