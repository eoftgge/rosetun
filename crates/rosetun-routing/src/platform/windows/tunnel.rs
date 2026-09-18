use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

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
        return Err(RoutingError::TunnelNotReady {
            name: tunnel.alias.clone(),
            reason: format!("adapter alias could not be resolved to a LUID (Windows error {status})"),
        });
    }

    Ok(TunnelLuid(luid))
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
