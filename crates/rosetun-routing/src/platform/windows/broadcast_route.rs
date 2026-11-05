//! Takes Windows' own limited-broadcast route off the tunnel while "Local
//! network" is on.
//!
//! Windows gives every adapter an on-link route to 255.255.255.255, and the
//! tunnel's interface metric of 0 wins, so a program that does not choose an
//! adapter sends its broadcast into the tunnel. Without the tunnel's row
//! Windows picks a real adapter, where the WFP filters decide as for any other
//! traffic. The row belongs to the adapter: it goes with it, and the next
//! adapter gets it again, so nothing here has to put it back.
//!
//! Multicast's 224.0.0.0/4 stays. Measured, a socket without a chosen adapter
//! took the tunnel's address seconds after a connect with that route deleted,
//! and kept it with longer routes on the physical adapter too, and with no route
//! on the tunnel covering multicast at all. Deleting it only let multicast leave
//! outside the tunnel for those seconds.

use std::net::Ipv4Addr;

use windows_sys::Win32::{
    Foundation::ERROR_NOT_FOUND,
    NetworkManagement::IpHelper::{DeleteIpForwardEntry2, MIB_IPFORWARD_ROW2},
    Networking::WinSock::{AF_INET, MIB_IPPROTO_LOCAL, NL_ROUTE_PROTOCOL, SOCKADDR_INET},
};

use super::{physical::ForwardTable, tunnel};
use crate::{RouteRelease, TunnelInterface};

/// The fields of a route row that decide whether it goes.
#[derive(Debug, Clone, Copy)]
struct Route {
    interface: u64,
    address: Ipv4Addr,
    length: u8,
    protocol: NL_ROUTE_PROTOCOL,
}

/// An engine's route to the same prefix has another protocol and stays.
fn is_broadcast_route(route: &Route, tunnel: u64) -> bool {
    route.interface == tunnel
        && route.protocol == MIB_IPPROTO_LOCAL
        && route.address == Ipv4Addr::BROADCAST
        && route.length == 32
}

fn record(release: &mut RouteRelease, status: u32) {
    match status {
        0 => release.removed += 1,
        // Gone since the table was read, which is what was wanted.
        ERROR_NOT_FOUND => {}
        code => {
            release.failure.get_or_insert(code);
        }
    }
}

fn address(prefix: &SOCKADDR_INET) -> Option<Ipv4Addr> {
    // SAFETY: si_family overlays the family field of both union members, and
    // Ipv4 is read only when the family names it.
    unsafe {
        (prefix.si_family == AF_INET)
            .then(|| Ipv4Addr::from(prefix.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()))
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
pub(super) fn release(tunnel: &TunnelInterface) -> RouteRelease {
    let mut release = RouteRelease::default();
    let Ok(luid) = tunnel::resolve_luid(tunnel) else {
        return release;
    };
    let table = match ForwardTable::get() {
        Ok(table) => table,
        Err(status) => {
            record(&mut release, status);
            return release;
        }
    };
    for row in table.routes() {
        if route(row).is_some_and(|route| is_broadcast_route(&route, luid.value())) {
            // SAFETY: the row comes from the table, which outlives this
            // synchronous call. The call copies what it needs from the row.
            record(&mut release, unsafe { DeleteIpForwardEntry2(row) });
        }
    }
    release
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

    /// A mock table: the tunnel's and another adapter's system routes, and an
    /// engine's route to the same prefix.
    fn table() -> Vec<Route> {
        let mut table = Vec::new();
        for interface in [TUNNEL, 9] {
            for (address, length) in [
                ("224.0.0.0", 4),
                ("255.255.255.255", 32),
                ("172.19.0.1", 32),
                ("172.19.0.3", 32),
                ("239.255.255.250", 32),
                ("255.255.255.254", 32),
                ("255.255.255.255", 31),
                ("0.0.0.0", 0),
            ] {
                table.push(system_route(interface, address, length));
            }
        }
        table.push(Route {
            protocol: MIB_IPPROTO_NETMGMT,
            ..system_route(TUNNEL, "255.255.255.255", 32)
        });
        table
    }

    fn chosen(table: &[Route]) -> Vec<(u64, Ipv4Addr, u8)> {
        table
            .iter()
            .filter(|route| is_broadcast_route(route, TUNNEL))
            .map(|route| (route.interface, route.address, route.length))
            .collect()
    }

    #[test]
    fn only_the_tunnels_system_route_to_the_limited_broadcast_is_chosen() {
        assert_eq!(chosen(&table()), [(TUNNEL, Ipv4Addr::BROADCAST, 32)]);
    }

    #[test]
    fn a_table_after_the_release_gives_nothing_more_to_remove() {
        let mut table = table();
        table.retain(|route| !is_broadcast_route(route, TUNNEL));
        assert!(chosen(&table).is_empty());
    }

    #[test]
    fn a_route_that_is_already_gone_is_not_a_failure() {
        let mut release = RouteRelease::default();
        record(&mut release, 0);
        record(&mut release, ERROR_NOT_FOUND);
        assert_eq!(
            release,
            RouteRelease {
                removed: 1,
                failure: None
            }
        );
    }

    #[test]
    fn the_first_failure_is_kept_and_the_rest_counts() {
        let mut release = RouteRelease::default();
        record(&mut release, 5);
        record(&mut release, 0);
        record(&mut release, 87);
        assert_eq!(
            release,
            RouteRelease {
                removed: 1,
                failure: Some(5)
            }
        );
    }

    #[test]
    fn a_row_gives_its_address_in_network_order() {
        let mut row = MIB_IPFORWARD_ROW2::default();
        row.DestinationPrefix.Prefix.si_family = AF_INET;
        row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr =
            u32::from_ne_bytes([255, 255, 255, 255]);
        row.DestinationPrefix.PrefixLength = 32;
        row.Protocol = MIB_IPPROTO_LOCAL;
        row.InterfaceLuid.Value = TUNNEL;
        assert!(is_broadcast_route(&route(&row).expect("IPv4 row"), TUNNEL));

        row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes([224, 0, 0, 0]);
        row.DestinationPrefix.PrefixLength = 4;
        assert!(!is_broadcast_route(&route(&row).expect("IPv4 row"), TUNNEL));
    }
}
