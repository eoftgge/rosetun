use std::{
    mem::{MaybeUninit, size_of},
    net::Ipv4Addr,
    ptr,
};

use crate::{RoutingError, TunnelInterface};
use windows_sys::Win32::{
    Foundation::ERROR_BUFFER_OVERFLOW,
    NetworkManagement::{
        IpHelper::{ConvertInterfaceAliasToLuid, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH},
        Ndis::{IfOperStatusUp, NET_LUID_LH},
    },
    Networking::WinSock::{AF_INET, AF_UNSPEC, SOCKADDR_IN},
};

pub(super) fn adapter_present(alias: &str) -> std::io::Result<bool> {
    if alias.contains('\0') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "adapter alias contains NUL",
        ));
    }
    let alias = wide(alias);
    let mut luid = NET_LUID_LH::default();
    // SAFETY: alias is NUL-terminated and luid is writable for the synchronous call.
    let status = unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) };
    match status {
        // SAFETY: Value is the plain 64-bit view of the LUID union.
        0 => Ok(find_adapter(AF_UNSPEC as u32, |adapter| unsafe {
            (adapter.Luid.Value == luid.Value).then_some(())
        })?
            .is_some()),
        windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER => Ok(false),
        _ => Err(std::io::Error::from_raw_os_error(status as i32)),
    }
}

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

/// Visits the adapters Windows reports as present, until `visit` returns `Some`.
/// The alias of a removed adapter still resolves to a LUID, but such an
/// adapter is not in this list.
fn find_adapter<T>(
    family: u32,
    mut visit: impl FnMut(&IP_ADAPTER_ADDRESSES_LH) -> Option<T>,
) -> std::io::Result<Option<T>> {
    let mut buffer_size = 16 * 1024_u32;
    // The list can grow between the size query and the read, so retry a few times.
    for _ in 0..3 {
        let entries = (buffer_size as usize).div_ceil(size_of::<IP_ADAPTER_ADDRESSES_LH>());
        let mut buffer = Vec::<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>::with_capacity(entries);
        // SAFETY: MaybeUninit needs no initialisation; Windows fills the buffer
        // and it is only read after a successful call.
        unsafe { buffer.set_len(entries) };
        // SAFETY: the buffer holds buffer_size bytes, aligned for the struct, and
        // stays alive while the returned linked list is walked below.
        let status = unsafe {
            GetAdaptersAddresses(
                family,
                0,
                ptr::null(),
                buffer.as_mut_ptr().cast(),
                &mut buffer_size,
            )
        };
        match status {
            0 => {
                let mut adapter = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
                while !adapter.is_null() {
                    // SAFETY: every node points into the buffer filled above.
                    let current = unsafe { &*adapter };
                    if let Some(found) = visit(current) {
                        return Ok(Some(found));
                    }
                    adapter = current.Next;
                }
                return Ok(None);
            }
            ERROR_BUFFER_OVERFLOW => continue,
            windows_sys::Win32::Foundation::ERROR_NO_DATA => return Ok(None),
            _ => return Err(std::io::Error::from_raw_os_error(status as i32)),
        }
    }
    Err(std::io::Error::other("adapter list kept changing size"))
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
