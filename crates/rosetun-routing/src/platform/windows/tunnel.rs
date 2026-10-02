use std::{
    mem::{MaybeUninit, size_of},
    net::Ipv4Addr,
    ptr,
};

use windows_sys::Win32::{
    Foundation::{
        ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER,
        ERROR_NOT_FOUND,
    },
    NetworkManagement::{
        IpHelper::{
            ConvertInterfaceAliasToLuid, GAA_FLAG_INCLUDE_ALL_INTERFACES,
            GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
        },
        Ndis::{IfOperStatusUp, NET_LUID_LH},
    },
    Networking::WinSock::{AF_INET, AF_UNSPEC, SOCKADDR_IN},
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

impl TunnelLuid {
    pub(super) fn value(self) -> u64 {
        unsafe { self.0.Value }
    }
}

pub(super) fn alias_exists(alias: &str) -> Result<bool, RoutingError> {
    if alias.is_empty() || alias.contains('\0') {
        return Err(RoutingError::Tun {
            name: alias.to_owned(),
            reason: "adapter alias must be non-empty and contain no NUL characters".to_owned(),
        });
    }

    let alias_wide = wide(alias);
    let mut luid = NET_LUID_LH::default();
    let status = unsafe {
        ConvertInterfaceAliasToLuid(alias_wide.as_ptr(), &mut luid)
    };

    let resolved_luid = if status == 0 {
        Some(unsafe { luid.Value })
    } else {
        None
    };
    tracing::debug!(
        alias,
        windows_status = status,
        luid = ?resolved_luid,
        "checked tunnel alias before engine startup"
    );

    if let Some(value) = resolved_luid {
        diagnose_adapter_presence(alias, value);
    }

    match status {
        0 => Ok(true),
        ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND | ERROR_INVALID_PARAMETER => Ok(false),
        code => Err(RoutingError::Tun {
            name: alias.to_owned(),
            reason: format!(
                "could not check whether the adapter exists (Windows error {code})"
            ),
        }),
    }
}

fn diagnose_adapter_presence(alias: &str, expected_luid: u64) {
    let mut buffer_size = 0_u32;

    let status = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_INCLUDE_ALL_INTERFACES,
            ptr::null(),
            ptr::null_mut(),
            &mut buffer_size,
        )
    };

    tracing::debug!(
        alias,
        windows_status = status,
        buffer_size,
        "adapter diagnostic: queried buffer size"
    );

    if status != ERROR_BUFFER_OVERFLOW {
        tracing::debug!(
            alias,
            windows_status = status,
            "adapter diagnostic: enumeration unavailable"
        );
        return;
    }

    // The interface list can grow between the size query and enumeration.
    for attempt in 1..=3 {
        let entries =
            (buffer_size as usize).div_ceil(size_of::<IP_ADAPTER_ADDRESSES_LH>());
        let mut buffer = Vec::<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>::new();
        buffer.resize_with(entries, MaybeUninit::uninit);

        let status = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_INCLUDE_ALL_INTERFACES,
                ptr::null(),
                buffer.as_mut_ptr().cast(),
                &mut buffer_size,
            )
        };

        tracing::debug!(
            alias,
            attempt,
            windows_status = status,
            buffer_size,
            "adapter diagnostic: enumeration result"
        );

        if status == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if status != 0 {
            return;
        }

        let mut adapter = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let mut count = 0_usize;
        let mut found = false;

        while !adapter.is_null() {
            // Only inspect the linked list after a successful API call.
            // The backing buffer remains alive throughout traversal.
            let current = unsafe { &*adapter };
            let value = unsafe { current.Luid.Value };
            let matches_alias_luid = value == expected_luid;

            tracing::debug!(
                alias,
                adapter_luid = value,
                if_index = unsafe { current.Anonymous1.Anonymous.IfIndex },
                oper_status = current.OperStatus,
                matches_alias_luid,
                "adapter diagnostic: enumerated interface"
            );

            count += 1;
            found |= matches_alias_luid;
            adapter = current.Next;
        }

        tracing::debug!(
            alias,
            expected_luid,
            adapter_count = count,
            found,
            "adapter diagnostic: presence summary"
        );
        return;
    }

    tracing::debug!(
        alias,
        "adapter diagnostic: enumeration kept growing; presence is unknown"
    );
}

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

        if !socket.lpSockaddr.is_null() && unsafe { (*socket.lpSockaddr).sa_family == AF_INET } {
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
