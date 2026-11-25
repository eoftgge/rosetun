#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
pub(crate) mod macos;
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

/// What Windows reports about an adapter, for the service log. It carries no
/// address and no identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelAdapterState {
    pub oper_status: &'static str,
    pub description: String,
}

/// The adapter with this alias as Windows reports it, `None` when there is
/// none. Read-only.
pub fn tunnel_adapter_state(alias: &str) -> std::io::Result<Option<TunnelAdapterState>> {
    #[cfg(windows)]
    {
        windows::tunnel_adapter_state(alias)
    }
    #[cfg(not(windows))]
    {
        let _ = alias;
        Ok(None)
    }
}

/// Finds an active `utun*` interface carrying `ipv4` on macOS.
pub fn tunnel_interface_by_ipv4(ipv4: std::net::Ipv4Addr) -> std::io::Result<Option<String>> {
    #[cfg(target_os = "macos")]
    {
        macos::tunnel_interface_by_ipv4(ipv4)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = ipv4;
        Ok(None)
    }
}

pub(super) fn ruleset_json() -> Result<String, crate::RoutingError> {
    #[cfg(target_os = "linux")]
    {
        linux::ruleset_json()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(crate::RoutingError::Unsupported)
    }
}

pub(super) fn lan_segment(
    query: &crate::lan::SegmentQuery<'_>,
) -> std::io::Result<crate::lan::SegmentScan> {
    #[cfg(windows)]
    {
        Ok(crate::lan::select(&windows::adapters()?, query))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(crate::lan::select(
            &linux::segment::adapters(query.tunnel_alias)?,
            query,
        ))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(crate::lan::select(
            &macos::segment::adapters(query.tunnel_alias)?,
            query,
        ))
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = query;
        Ok(crate::lan::SegmentScan::default())
    }
}

pub(super) fn release_broadcast_route(tunnel: &crate::TunnelInterface) -> crate::RouteRelease {
    #[cfg(windows)]
    {
        windows::release_broadcast_route(tunnel)
    }
    #[cfg(not(windows))]
    {
        let _ = tunnel;
        crate::RouteRelease::default()
    }
}

pub(super) fn shared_proxy_addresses() -> Vec<std::net::IpAddr> {
    #[cfg(target_os = "linux")]
    {
        linux::connected::private_addresses()
    }
    #[cfg(target_os = "macos")]
    {
        macos::connected::private_addresses()
    }
    #[cfg(windows)]
    {
        let adapters = windows::adapters().unwrap_or_default();
        let scan = crate::lan::select(
            &adapters,
            &crate::lan::SegmentQuery {
                tunnel_alias: "",
                tunnel_networks: &[],
                servers: &[],
            },
        );
        let mut addresses: Vec<_> = adapters
            .iter()
            .flat_map(|adapter| {
                let segment = &scan.segment;
                adapter.addresses.iter().filter_map(move |(address, _)| {
                    segment
                        .networks()
                        .iter()
                        .any(|network| {
                            network.interface == adapter.interface
                                && network.prefix.contains(*address)
                        })
                        .then_some(*address)
                })
            })
            .collect();
        addresses.sort_unstable();
        addresses.dedup();
        addresses
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
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
    #[cfg(target_os = "macos")]
    {
        macos::physical_default_interface(exclude_alias)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
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
