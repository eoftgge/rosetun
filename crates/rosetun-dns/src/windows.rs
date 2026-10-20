use std::mem::{MaybeUninit, size_of};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::ptr;

use windows_sys::Win32::{
    Foundation::ERROR_BUFFER_OVERFLOW,
    NetworkManagement::{
        IpHelper::{
            GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_FRIENDLY_NAME,
            GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses,
            IP_ADAPTER_ADDRESSES_LH,
        },
        Ndis::IfOperStatusUp,
    },
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6},
};

use crate::servers::DNS_PORT;

const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
/// Wintun, WireGuard and other virtual tunnels report this type.
const IF_TYPE_PROP_VIRTUAL: u32 = 53;
const IF_TYPE_TUNNEL: u32 = 131;

const FLAGS: u32 = GAA_FLAG_INCLUDE_GATEWAYS
    | GAA_FLAG_SKIP_UNICAST
    | GAA_FLAG_SKIP_ANYCAST
    | GAA_FLAG_SKIP_MULTICAST
    | GAA_FLAG_SKIP_FRIENDLY_NAME;

/// `(metric, servers)` of every adapter that is up, is not a tunnel or the
/// loopback, and has a gateway, which is where a default route comes from.
/// The metric is the interface metric of the family the gateway belongs to.
pub(crate) fn adapter_servers() -> Vec<(u32, Vec<SocketAddr>)> {
    let mut bytes = 15_000_u32;
    for _ in 0..4 {
        let count = (bytes as usize).div_ceil(size_of::<IP_ADAPTER_ADDRESSES_LH>());
        let mut buffer = Vec::<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>::new();
        buffer.resize_with(count, MaybeUninit::uninit);
        // SAFETY: Vec owns at least `bytes` writable, correctly aligned bytes;
        // Windows initializes the linked ABI records synchronously. Its pointers
        // are used only after a successful result and while the Vec stays alive.
        let status = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                FLAGS,
                ptr::null(),
                buffer.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if status == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        // ERROR_NO_DATA and real failures alike leave no server to ask,
        // which the caller reports.
        if status != 0 {
            return Vec::new();
        }

        let mut found = Vec::new();
        let mut current = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !current.is_null() {
            // SAFETY: `current` is the head or a `Next` link written by the
            // successful call above, pointing into `buffer`, which is alive.
            let adapter = unsafe { &*current };
            if let Some(entry) = usable_adapter(adapter) {
                found.push(entry);
            }
            current = adapter.Next;
        }
        return found;
    }
    Vec::new()
}

fn usable_adapter(adapter: &IP_ADAPTER_ADDRESSES_LH) -> Option<(u32, Vec<SocketAddr>)> {
    if adapter.OperStatus != IfOperStatusUp
        || matches!(
            adapter.IfType,
            IF_TYPE_SOFTWARE_LOOPBACK | IF_TYPE_PROP_VIRTUAL | IF_TYPE_TUNNEL
        )
    {
        return None;
    }
    let (mut ipv4_gateway, mut ipv6_gateway) = (false, false);
    let mut gateway = adapter.FirstGatewayAddress;
    while !gateway.is_null() {
        // SAFETY: a `FirstGatewayAddress`/`Next` link of the live buffer.
        let entry = unsafe { &*gateway };
        match family(entry.Address.lpSockaddr) {
            Some(AF_INET) => ipv4_gateway = true,
            Some(AF_INET6) => ipv6_gateway = true,
            _ => {}
        }
        gateway = entry.Next;
    }
    let metric = if ipv4_gateway {
        adapter.Ipv4Metric
    } else if ipv6_gateway {
        adapter.Ipv6Metric
    } else {
        return None;
    };

    let mut servers = Vec::new();
    let mut server = adapter.FirstDnsServerAddress;
    while !server.is_null() {
        // SAFETY: a `FirstDnsServerAddress`/`Next` link of the live buffer.
        let entry = unsafe { &*server };
        if let Some(address) = socket_address(entry.Address.lpSockaddr) {
            servers.push(address);
        }
        server = entry.Next;
    }
    (!servers.is_empty()).then_some((metric, servers))
}

fn family(address: *const SOCKADDR) -> Option<u16> {
    // SAFETY: a non-null `lpSockaddr` of the live buffer starts with the
    // family field shared by every SOCKADDR variant.
    (!address.is_null()).then(|| unsafe { (*address).sa_family })
}

fn socket_address(address: *const SOCKADDR) -> Option<SocketAddr> {
    match family(address)? {
        AF_INET => {
            // SAFETY: the family says the buffer holds a SOCKADDR_IN; S_addr
            // is in network order, so its in-memory bytes are the octets.
            let octets = unsafe {
                (*address.cast::<SOCKADDR_IN>())
                    .sin_addr
                    .S_un
                    .S_addr
                    .to_ne_bytes()
            };
            Some(SocketAddr::new(Ipv4Addr::from(octets).into(), DNS_PORT))
        }
        AF_INET6 => {
            // SAFETY: the family says the buffer holds a SOCKADDR_IN6; the
            // byte view of the address union is always initialized.
            let (octets, scope) = unsafe {
                let address = &*address.cast::<SOCKADDR_IN6>();
                (address.sin6_addr.u.Byte, address.Anonymous.sin6_scope_id)
            };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                DNS_PORT,
                0,
                scope,
            )))
        }
        _ => None,
    }
}
