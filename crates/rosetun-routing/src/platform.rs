#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

#[cfg(not(any(windows, target_os = "linux")))]
use crate::{ProtectionCapabilities, RoutingBackend, RoutingError, RoutingGuard, RoutingPlan};

/// The platform's backend. On Linux it offers no protection: only the
/// service, through `backend_with_cgroups`, knows its engines' cgroup.
pub fn backend() -> Box<dyn crate::RoutingBackend> {
    #[cfg(windows)]
    {
        Box::new(windows::WfpBackend::new())
    }

    #[cfg(target_os = "linux")]
    {
        backend_with_cgroups(Err(linux::NOT_THE_SERVICE.to_owned()))
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Box::new(Stub {
            name: PLATFORM_NAME,
        })
    }
}

/// The nftables backend for the engines in these leaves, or without
/// protection for the reason given.
#[cfg(target_os = "linux")]
pub fn backend_with_cgroups(
    leaves: Result<crate::cgroup::Leaves, String>,
) -> Box<dyn crate::RoutingBackend> {
    Box::new(linux::NftBackend::new(leaves))
}

#[cfg(target_os = "linux")]
pub(super) fn restore_at_boot() -> Result<crate::BootRestore, crate::RoutingError> {
    linux::restore_at_boot()
}

#[cfg(target_os = "linux")]
pub(super) fn reset_firewall() -> Result<crate::FirewallReset, crate::RoutingError> {
    linux::reset_firewall()
}

/// Whether Windows still has the adapter with this alias.
pub fn tunnel_adapter_present(alias: &str) -> std::io::Result<bool> {
    #[cfg(windows)]
    {
        windows::tunnel_adapter_present(alias)
    }
    #[cfg(not(windows))]
    {
        let _ = alias;
        Ok(false)
    }
}

pub(super) fn lan_segment(
    query: &crate::lan::SegmentQuery<'_>,
) -> std::io::Result<crate::lan::SegmentScan> {
    #[cfg(windows)]
    {
        Ok(crate::lan::select(&windows::adapters()?, query))
    }
    #[cfg(not(windows))]
    {
        let _ = query;
        Ok(crate::lan::SegmentScan::default())
    }
}

pub(super) fn release_discovery_routes(
    tunnel: &crate::TunnelInterface,
    ipv6: bool,
) -> crate::DiscoveryRoutes {
    #[cfg(windows)]
    {
        windows::release_discovery_routes(tunnel, ipv6)
    }
    #[cfg(not(windows))]
    {
        let _ = (tunnel, ipv6);
        crate::DiscoveryRoutes::default()
    }
}

pub(super) fn physical_default_interface(exclude_alias: &str) -> Option<String> {
    #[cfg(windows)]
    {
        windows::physical_default_interface(exclude_alias)
    }
    #[cfg(target_os = "linux")]
    {
        linux::physical_default_interface(exclude_alias)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = exclude_alias;
        None
    }
}

pub(super) fn lockdown_status() -> Result<crate::LockdownStatus, crate::RoutingError> {
    #[cfg(windows)]
    {
        windows::lockdown::status()
    }
    #[cfg(not(windows))]
    {
        Err(crate::RoutingError::Unsupported)
    }
}

pub(super) fn lockdown_enable(
    lan: Option<&crate::lan::LanAccess>,
    apps: &crate::LockdownApps,
) -> Result<crate::LockdownStatus, crate::RoutingError> {
    #[cfg(windows)]
    {
        windows::lockdown::enable(lan, apps)
    }
    #[cfg(not(windows))]
    {
        let _ = (lan, apps);
        Err(crate::RoutingError::Unsupported)
    }
}

pub(super) fn lockdown_disable() -> Result<bool, crate::RoutingError> {
    #[cfg(windows)]
    {
        windows::lockdown::disable()
    }
    #[cfg(not(windows))]
    {
        Err(crate::RoutingError::Unsupported)
    }
}

pub(super) fn session_filters()
-> Result<Vec<crate::upgrade_hold::SessionFilter>, crate::RoutingError> {
    #[cfg(windows)]
    {
        windows::lockdown::session_filters()
    }
    #[cfg(not(windows))]
    {
        Err(crate::RoutingError::Unsupported)
    }
}

pub(super) fn hold_place(
    lan: Option<&crate::lan::LanAccess>,
    apps: &crate::LockdownApps,
) -> Result<crate::LockdownStatus, crate::RoutingError> {
    #[cfg(windows)]
    {
        windows::lockdown::hold(lan, apps)
    }
    #[cfg(not(windows))]
    {
        let _ = (lan, apps);
        Err(crate::RoutingError::Unsupported)
    }
}

pub(super) fn hold_end() -> Result<(), crate::RoutingError> {
    #[cfg(windows)]
    {
        windows::lockdown::end_hold()
    }
    #[cfg(not(windows))]
    {
        Err(crate::RoutingError::Unsupported)
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
const PLATFORM_NAME: &str = "unsupported";

#[cfg(not(any(windows, target_os = "linux")))]
#[derive(Debug)]
struct Stub {
    name: &'static str,
}

#[cfg(not(any(windows, target_os = "linux")))]
impl RoutingBackend for Stub {
    fn name(&self) -> &'static str {
        self.name
    }

    fn capabilities(&self) -> ProtectionCapabilities {
        ProtectionCapabilities::default()
    }

    fn preflight(&self) -> Result<(), RoutingError> {
        Err(RoutingError::Unsupported)
    }

    fn begin_protection(
        &mut self,
        _plan: &RoutingPlan,
        _engine_binaries: &[&std::path::Path],
    ) -> Result<RoutingGuard, RoutingError> {
        Err(RoutingError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use crate::ProtectionCapabilities;

    #[cfg(windows)]
    #[test]
    fn the_windows_backend_has_the_kill_switch_and_lockdown() {
        assert_eq!(
            super::backend().capabilities(),
            ProtectionCapabilities {
                kill_switch: true,
                lockdown: true,
            }
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn a_platform_without_routing_or_outside_the_service_has_no_protection() {
        assert_eq!(
            super::backend().capabilities(),
            ProtectionCapabilities::default()
        );
    }
}
