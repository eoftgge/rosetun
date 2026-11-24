//! Connected LAN segment adapters on macOS.

use std::io;

use crate::lan::{Adapter, ETHERNET, InterfaceId};

use super::connected::{self, RawInterface};
use super::physical;

/// IANA `IFT_ETHER` (`<net/if_types.h>`).
const IFT_ETHER: u8 = 0x06;
/// IANA `IFT_LOOP` (`<net/if_types.h>`).
const IFT_LOOP: u8 = 0x18;

/// macOS virtual / Apple-internal Ethernet-typed interfaces that are never a
/// user's physical LAN NIC.
const VIRTUAL_PREFIXES: [&str; 12] = [
    "anpi", "ap", "awdl", "bridge", "feth", "gif", "iptap", "llw", "pktap", "stf", "utun", "vm",
];

pub(super) fn is_hardware_interface(iface: &RawInterface) -> bool {
    if iface.loopback || iface.point_to_point || iface.sdl_type != Some(IFT_ETHER) {
        return false;
    }
    if VIRTUAL_PREFIXES
        .iter()
        .any(|prefix| iface.name.starts_with(prefix))
    {
        return false;
    }
    iface.name.starts_with("en")
        && iface
            .name
            .strip_prefix("en")
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

fn to_adapter(iface: RawInterface, default_route_interfaces: &[String]) -> Adapter {
    let if_type = match iface.sdl_type {
        Some(IFT_ETHER) => ETHERNET,
        Some(IFT_LOOP) => u32::from(IFT_LOOP),
        Some(other) => u32::from(other),
        None => 0,
    };
    let hardware = is_hardware_interface(&iface);
    let has_gateway = default_route_interfaces
        .iter()
        .any(|name| name == &iface.name);
    Adapter {
        interface: InterfaceId(u64::from(iface.index)),
        alias: iface.name.clone(),
        description: iface.name,
        if_type,
        up: iface.up,
        hardware,
        has_gateway,
        addresses: iface.addresses,
    }
}

pub(in crate::platform) fn adapters(tunnel_alias: &str) -> io::Result<Vec<Adapter>> {
    let interfaces = connected::read_interfaces()?;
    let gateways = physical::interfaces_with_default_route(tunnel_alias);
    Ok(interfaces
        .into_iter()
        .filter(|iface| iface.index != 0)
        .map(|iface| to_adapter(iface, &gateways))
        .collect())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::lan::{SegmentQuery, select};

    use super::*;

    fn raw(
        index: u32,
        name: &str,
        sdl_type: u8,
        point_to_point: bool,
        addresses: Vec<(IpAddr, u8)>,
    ) -> RawInterface {
        RawInterface {
            index,
            name: name.to_owned(),
            up: true,
            point_to_point,
            loopback: name == "lo0",
            sdl_type: Some(sdl_type),
            addresses,
        }
    }

    #[test]
    fn selects_en0_lan_and_excludes_virtual_and_utun_interfaces() {
        let gateways = vec!["en0".to_owned()];
        let adapters = vec![
            to_adapter(
                raw(
                    4,
                    "en0",
                    IFT_ETHER,
                    false,
                    vec![
                        (IpAddr::V4(Ipv4Addr::new(192, 168, 1, 25)), 24),
                        (
                            IpAddr::V6("fd12:3456:789a::5".parse::<Ipv6Addr>().unwrap()),
                            64,
                        ),
                    ],
                ),
                &gateways,
            ),
            to_adapter(
                raw(
                    9,
                    "bridge100",
                    IFT_ETHER,
                    false,
                    vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 64, 1)), 24)],
                ),
                &gateways,
            ),
            to_adapter(
                raw(
                    10,
                    "awdl0",
                    IFT_ETHER,
                    false,
                    vec![(IpAddr::V4(Ipv4Addr::new(169, 254, 10, 2)), 16)],
                ),
                &gateways,
            ),
            to_adapter(
                raw(
                    15,
                    "utun6",
                    0,
                    true,
                    vec![(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 30)],
                ),
                &gateways,
            ),
        ];

        let query = SegmentQuery {
            tunnel_alias: "utun6",
            tunnel_networks: &[],
            servers: &[],
        };
        let scan = select(&adapters, &query);
        assert_eq!(scan.segment.interfaces(), &[InterfaceId(4)]);
        assert_eq!(scan.segment.prefixes().len(), 2);
    }
}
