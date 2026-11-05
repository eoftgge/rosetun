//! Takes Windows' own multicast and limited-broadcast routes off the tunnel
//! while "Local network" is on.
//!
//! Windows gives every adapter on-link routes for these destinations, and the
//! tunnel's interface metric of 0 wins, so a program that does not choose an
//! adapter sends its discovery into the tunnel. Without the tunnel's rows
//! Windows picks a real adapter, where the WFP filters decide as for any other
//! traffic. The rows belong to the adapter: they go with it, and the next
//! adapter gets them again, so nothing here has to put them back.
//!
//! The engine's configuration keeps multicast out of the tunnel's wide routes,
//! so that none is left on the tunnel to cover it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows_sys::Win32::{
    Foundation::ERROR_NOT_FOUND,
    NetworkManagement::IpHelper::{DeleteIpForwardEntry2, MIB_IPFORWARD_ROW2},
    Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, MIB_IPPROTO_LOCAL, NL_ROUTE_PROTOCOL, SOCKADDR_INET,
    },
};

use super::{physical::ForwardTable, tunnel};
use crate::{DiscoveryRoutes, TunnelInterface};

const IPV4_ROUTES: [(IpAddr, u8); 2] = [
    (IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)), 4),
    (IpAddr::V4(Ipv4Addr::BROADCAST), 32),
];
const IPV6_ROUTE: (IpAddr, u8) = (IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0)), 8);

/// The fields of a route row that decide whether it goes.
#[derive(Debug, Clone, Copy)]
struct Route {
    interface: u64,
    address: IpAddr,
    length: u8,
    protocol: NL_ROUTE_PROTOCOL,
}

/// An engine's route to the same prefix has another protocol and stays.
fn is_discovery_route(route: &Route, tunnel: u64, ipv6: bool) -> bool {
    let destination = (route.address, route.length);
    route.interface == tunnel
        && route.protocol == MIB_IPPROTO_LOCAL
        && (IPV4_ROUTES.contains(&destination) || (ipv6 && destination == IPV6_ROUTE))
}

fn record(sweep: &mut DiscoveryRoutes, status: u32) {
    match status {
        0 => sweep.removed += 1,
        // Gone since the table was read, which is what was wanted.
        ERROR_NOT_FOUND => {}
        code => {
            sweep.failure.get_or_insert(code);
        }
    }
}

fn address(prefix: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: si_family overlays the family field of both union members, and
    // the member read matches the family it names.
    unsafe {
        match prefix.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                prefix.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
            ))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(prefix.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

fn route(row: &MIB_IPFORWARD_ROW2) -> Option<Route> {
    Some(Route {
        // SAFETY: Value is the plain 64-bit view of the LUID union.
        interface: unsafe { row.InterfaceLuid.Value },
        address: address(&row.DestinationPrefix.Prefix)?,
        length: row.DestinationPrefix.PrefixLength,
        protocol: row.Protocol,
    })
}

/// Removes what is there; a repeat finds nothing and does nothing. A tunnel
/// that does not pass validation, such as a stale adapter with the same
/// alias, is left alone: the next read may find it ready.
pub(super) fn release(tunnel: &TunnelInterface, ipv6: bool) -> DiscoveryRoutes {
    let mut sweep = DiscoveryRoutes::default();
    let Ok(luid) = tunnel::resolve_luid(tunnel) else {
        return sweep;
    };
    let table = match ForwardTable::get(if ipv6 { AF_UNSPEC } else { AF_INET }) {
        Ok(table) => table,
        Err(status) => {
            record(&mut sweep, status);
            return sweep;
        }
    };
    for row in table.routes() {
        if route(row).is_some_and(|route| is_discovery_route(&route, luid.value(), ipv6)) {
            // SAFETY: the row comes from the table, which outlives this
            // synchronous call. The call copies what it needs from the row.
            record(&mut sweep, unsafe { DeleteIpForwardEntry2(row) });
        }
    }
    sweep
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::Networking::WinSock::MIB_IPPROTO_NETMGMT;

    use super::*;

    const TUNNEL: u64 = 7;

    fn system_route(interface: u64, address: &str, length: u8) -> Route {
        Route {
            interface,
            address: address.parse().unwrap(),
            length,
            protocol: MIB_IPPROTO_LOCAL,
        }
    }

    /// A mock table: the tunnel's and another adapter's system routes, and
    /// the tunnel's other routes.
    fn table() -> Vec<Route> {
        let mut table = Vec::new();
        for interface in [TUNNEL, 9] {
            for (address, length) in [
                ("224.0.0.0", 4),
                ("255.255.255.255", 32),
                ("ff00::", 8),
                ("172.19.0.1", 32),
                ("172.19.0.3", 32),
                ("239.0.0.0", 8),
                ("224.0.0.0", 24),
                ("255.255.255.254", 32),
                ("ff02::", 16),
                ("0.0.0.0", 0),
                ("::", 0),
            ] {
                table.push(system_route(interface, address, length));
            }
        }
        table.push(Route {
            protocol: MIB_IPPROTO_NETMGMT,
            ..system_route(TUNNEL, "224.0.0.0", 4)
        });
        table.push(Route {
            protocol: MIB_IPPROTO_NETMGMT,
            ..system_route(TUNNEL, "255.255.255.255", 32)
        });
        table
    }

    fn chosen(table: &[Route], ipv6: bool) -> Vec<(u64, String, u8)> {
        table
            .iter()
            .filter(|route| is_discovery_route(route, TUNNEL, ipv6))
            .map(|route| (route.interface, route.address.to_string(), route.length))
            .collect()
    }

    #[test]
    fn only_the_tunnels_system_routes_to_the_two_ipv4_prefixes_are_chosen() {
        assert_eq!(
            chosen(&table(), false),
            [
                (TUNNEL, "224.0.0.0".to_owned(), 4),
                (TUNNEL, "255.255.255.255".to_owned(), 32),
            ]
        );
    }

    #[test]
    fn a_tunnel_that_carries_ipv6_also_gives_up_ff00() {
        assert_eq!(
            chosen(&table(), true),
            [
                (TUNNEL, "224.0.0.0".to_owned(), 4),
                (TUNNEL, "255.255.255.255".to_owned(), 32),
                (TUNNEL, "ff00::".to_owned(), 8),
            ]
        );
    }

    #[test]
    fn a_table_after_the_sweep_gives_nothing_more_to_remove() {
        let mut table = table();
        table.retain(|route| !is_discovery_route(route, TUNNEL, true));
        assert!(chosen(&table, true).is_empty());
    }

    #[test]
    fn a_route_that_is_already_gone_is_not_a_failure() {
        let mut sweep = DiscoveryRoutes::default();
        record(&mut sweep, 0);
        record(&mut sweep, ERROR_NOT_FOUND);
        assert_eq!(
            sweep,
            DiscoveryRoutes {
                removed: 1,
                failure: None
            }
        );
    }

    #[test]
    fn the_first_failure_is_kept_and_the_rest_of_the_sweep_counts() {
        let mut sweep = DiscoveryRoutes::default();
        record(&mut sweep, 5);
        record(&mut sweep, 0);
        record(&mut sweep, 87);
        assert_eq!(
            sweep,
            DiscoveryRoutes {
                removed: 1,
                failure: Some(5)
            }
        );
    }

    #[test]
    fn a_row_gives_its_address_in_network_order() {
        let mut row = MIB_IPFORWARD_ROW2::default();
        row.DestinationPrefix.Prefix.si_family = AF_INET;
        row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes([224, 0, 0, 0]);
        row.DestinationPrefix.PrefixLength = 4;
        row.Protocol = MIB_IPPROTO_LOCAL;
        row.InterfaceLuid.Value = TUNNEL;
        let read = route(&row).expect("IPv4 row");
        assert!(is_discovery_route(&read, TUNNEL, false));

        let mut row = MIB_IPFORWARD_ROW2::default();
        row.DestinationPrefix.Prefix.si_family = AF_INET6;
        row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte =
            Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0).octets();
        row.DestinationPrefix.PrefixLength = 8;
        row.Protocol = MIB_IPPROTO_LOCAL;
        row.InterfaceLuid.Value = TUNNEL;
        let read = route(&row).expect("IPv6 row");
        assert!(is_discovery_route(&read, TUNNEL, true));
        assert!(!is_discovery_route(&read, TUNNEL, false));
    }
}
