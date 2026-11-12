use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows_sys::Win32::{
    NetworkManagement::{
        IpHelper::{
            GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
            GAA_FLAG_SKIP_MULTICAST, GetIfEntry2, IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2,
        },
        Ndis::IfOperStatusUp,
    },
    Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, IpDadStateDeprecated, IpDadStatePreferred, SOCKADDR_IN,
        SOCKADDR_IN6,
    },
};

use super::tunnel::find_adapter;
use crate::lan::{Adapter, InterfaceId};

/// Every adapter Windows reports, with what `lan::select` needs.
pub(super) fn adapters() -> std::io::Result<Vec<Adapter>> {
    let mut adapters = Vec::new();
    let flags = GAA_FLAG_INCLUDE_GATEWAYS
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;
    find_adapter::<()>(AF_UNSPEC as u32, flags, |adapter| {
        adapters.push(read(adapter));
        None
    })?;
    Ok(adapters)
}

fn read(adapter: &IP_ADAPTER_ADDRESSES_LH) -> Adapter {
    // SAFETY: Value is the plain 64-bit view of the LUID union.
    let luid = unsafe { adapter.Luid.Value };
    Adapter {
        interface: InterfaceId(luid),
        alias: wide_string(adapter.FriendlyName),
        description: wide_string(adapter.Description),
        if_type: adapter.IfType,
        up: adapter.OperStatus == IfOperStatusUp,
        hardware: hardware_interface(adapter),
        has_gateway: !adapter.FirstGatewayAddress.is_null(),
        addresses: unicast_addresses(adapter),
    }
}

/// `MIB_IF_ROW2.InterfaceAndOperStatusFlags.HardwareInterface`, the first
/// bit of the bit field; false when the row cannot be read.
fn hardware_interface(adapter: &IP_ADAPTER_ADDRESSES_LH) -> bool {
    let mut row = MIB_IF_ROW2 {
        InterfaceLuid: adapter.Luid,
        ..MIB_IF_ROW2::default()
    };
    // SAFETY: the call fills our stack row, keyed by the LUID set above.
    let status = unsafe { GetIfEntry2(&mut row) };
    status == 0 && row.InterfaceAndOperStatusFlags._bitfield & 1 != 0
}

fn unicast_addresses(adapter: &IP_ADAPTER_ADDRESSES_LH) -> Vec<(IpAddr, u8)> {
    let mut addresses = Vec::new();
    let mut unicast = adapter.FirstUnicastAddress;
    while !unicast.is_null() {
        // SAFETY: every node points into the GetAdaptersAddresses buffer the
        // caller keeps alive while visiting this adapter.
        let current = unsafe { &*unicast };
        unicast = current.Next;
        // A tentative or duplicate address is not usable yet.
        if current.DadState != IpDadStatePreferred && current.DadState != IpDadStateDeprecated {
            continue;
        }
        let socket = current.Address.lpSockaddr;
        if socket.is_null() {
            continue;
        }
        // SAFETY: lpSockaddr points to a SOCKADDR of the family it names,
        // inside the same buffer.
        let address = unsafe {
            match (*socket).sa_family {
                AF_INET => {
                    let raw = (*socket.cast::<SOCKADDR_IN>()).sin_addr.S_un.S_addr;
                    IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes()))
                }
                AF_INET6 => {
                    let raw = (*socket.cast::<SOCKADDR_IN6>()).sin6_addr.u.Byte;
                    IpAddr::V6(Ipv6Addr::from(raw))
                }
                _ => continue,
            }
        };
        addresses.push((address, current.OnLinkPrefixLength));
    }
    addresses
}

pub(super) fn wide_string(value: *const u16) -> String {
    if value.is_null() {
        return String::new();
    }
    let mut length = 0;
    // SAFETY: Windows terminates these strings with NUL inside the buffer.
    while unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: length counts the u16 values before the NUL found above.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, length) })
}
