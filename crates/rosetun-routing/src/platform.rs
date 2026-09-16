use crate::{RoutingBackend, RoutingError, RoutingGuard, RoutingPlan};

pub fn backend() -> Box<dyn RoutingBackend> {
    Box::new(Stub {
        name: PLATFORM_NAME,
    })
}

#[cfg(target_os = "linux")]
const PLATFORM_NAME: &str = "linux-netlink";
#[cfg(target_os = "windows")]
const PLATFORM_NAME: &str = "windows-wfp";
#[cfg(target_os = "macos")]
const PLATFORM_NAME: &str = "macos-pf";
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
const PLATFORM_NAME: &str = "unsupported";

#[derive(Debug)]
struct Stub {
    name: &'static str,
}

impl RoutingBackend for Stub {
    fn name(&self) -> &'static str {
        self.name
    }

    fn preflight(&self) -> Result<(), RoutingError> {
        Err(RoutingError::Unsupported)
    }

    fn apply(&mut self, _plan: &RoutingPlan) -> Result<RoutingGuard, RoutingError> {
        Err(RoutingError::Unsupported)
    }
}
