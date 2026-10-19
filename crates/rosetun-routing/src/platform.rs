#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
use crate::{RoutingBackend, RoutingError, RoutingGuard, RoutingPlan};

pub fn backend() -> Box<dyn crate::RoutingBackend> {
    #[cfg(windows)]
    {
        Box::new(windows::WfpBackend::new())
    }

    #[cfg(not(windows))]
    {
        Box::new(Stub {
            name: PLATFORM_NAME,
        })
    }
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

pub(super) fn physical_default_interface(exclude_alias: &str) -> Option<String> {
    #[cfg(windows)]
    {
        windows::physical_default_interface(exclude_alias)
    }
    #[cfg(not(windows))]
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
    allow_lan: bool,
    apps: &crate::LockdownApps,
) -> Result<crate::LockdownStatus, crate::RoutingError> {
    #[cfg(windows)]
    {
        windows::lockdown::enable(allow_lan, apps)
    }
    #[cfg(not(windows))]
    {
        let _ = (allow_lan, apps);
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

#[cfg(target_os = "linux")]
const PLATFORM_NAME: &str = "linux-netlink";
#[cfg(target_os = "macos")]
const PLATFORM_NAME: &str = "macos-pf";
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
const PLATFORM_NAME: &str = "unsupported";

#[cfg(not(windows))]
#[derive(Debug)]
struct Stub {
    name: &'static str,
}

#[cfg(not(windows))]
impl RoutingBackend for Stub {
    fn name(&self) -> &'static str {
        self.name
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
