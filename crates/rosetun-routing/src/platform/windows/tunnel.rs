use std::{
    mem::{MaybeUninit, size_of},
    net::Ipv4Addr,
    ptr,
};

use windows_sys::Win32::{
    Foundation::ERROR_BUFFER_OVERFLOW,
    NetworkManagement::{
        IpHelper::{
            ConvertInterfaceAliasToLuid, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
        },
        Ndis::{IfOperStatusUp, NET_LUID_LH},
    },
    Networking::WinSock::{AF_INET, SOCKADDR_IN},
};

use crate::{RoutingError, TunnelInterface};

/// Windows-specific identity accepted by
/// `FWPM_CONDITION_IP_LOCAL_INTERFACE`.
///
/// A LUID remains stable while an adapter exists, unlike an interface index.
/// It intentionally does not cross the `rosetun-routing` public boundary.
#[derive(Clone, Copy)]
pub(super) struct TunnelLuid(pub(super) NET_LUID_LH);

impl std::fmt::Debug for TunnelLuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe { f.debug_tuple("TunnelLuid").field(&self.0.Value).finish() }
    }
}

impl PartialEq for TunnelLuid {
    fn eq(&self, other: &Self) -> bool {
        unsafe { self.0.Value == other.0.Value }
    }
}

impl Eq for TunnelLuid {}

pub(super) fn resolve_luid(tunnel: &TunnelInterface) -> Result<TunnelLuid, RoutingError> {
    let alias = wide(&tunnel.alias);
    let mut luid = NET_LUID_LH::default();

    let status = unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) };
    if status != 0 {
        return Err(not_ready(
            tunnel,
            format!("adapter alias could not be resolved to a LUID (Windows error {status})"),
        ));
    }

    validate_adapter(tunnel, luid)?;
    Ok(TunnelLuid(luid))
}

fn validate_adapter(tunnel: &TunnelInterface, luid: NET_LUID_LH) -> Result<(), RoutingError> {
    let mut buffer_size = 0_u32;
    let status = unsafe {
        GetAdaptersAddresses(
            AF_INET as u32,
            0,
            ptr::null(),
            ptr::null_mut(),
            &mut buffer_size,
        )
    };
    if status != ERROR_BUFFER_OVERFLOW {
        return Err(not_ready(
            tunnel,
            format!("could not enumerate adapters (Windows error {status})"),
        ));
    }

    let entries = (buffer_size as usize).div_ceil(size_of::<IP_ADAPTER_ADDRESSES_LH>());
    let mut buffer = Vec::<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>::with_capacity(entries);
    unsafe {
        buffer.set_len(entries);
    }

    let status = unsafe {
        GetAdaptersAddresses(
            AF_INET as u32,
            0,
            ptr::null(),
            buffer.as_mut_ptr().cast(),
            &mut buffer_size,
        )
    };
    if status != 0 {
        return Err(not_ready(
            tunnel,
            format!("could not enumerate adapters (Windows error {status})"),
        ));
    }

    let mut adapter = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !adapter.is_null() {
        let current = unsafe { &*adapter };

        if unsafe { current.Luid.Value == luid.Value } {
            if current.OperStatus != IfOperStatusUp {
                return Err(not_ready(tunnel, "adapter is not operationally up"));
            }

            if !has_ipv4_address(current, tunnel.ipv4) {
                return Err(not_ready(
                    tunnel,
                    format!("expected IPv4 address {} is not assigned", tunnel.ipv4),
                ));
            }

            return Ok(());
        }

        adapter = current.Next;
    }

    Err(not_ready(tunnel, "adapter is no longer present"))
}

fn has_ipv4_address(adapter: &IP_ADAPTER_ADDRESSES_LH, expected: Ipv4Addr) -> bool {
    let mut unicast = adapter.FirstUnicastAddress;

    while !unicast.is_null() {
        let current = unsafe { &*unicast };
        let socket = &current.Address;

        if !socket.lpSockaddr.is_null()
            && unsafe { (*socket.lpSockaddr).sa_family == AF_INET }
        {
            let address = unsafe {
                (*socket.lpSockaddr.cast::<SOCKADDR_IN>())
                    .sin_addr
                    .S_un
                    .S_addr
                    .to_ne_bytes()
            };

            if address == expected.octets() {
                return true;
            }
        }

        unicast = current.Next;
    }

    false
}

fn not_ready(tunnel: &TunnelInterface, reason: impl Into<String>) -> RoutingError {
    RoutingError::TunnelNotReady {
        name: tunnel.alias.clone(),
        reason: reason.into(),
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
