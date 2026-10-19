mod filters;
pub(super) mod lockdown;
mod physical;
mod policy;
mod session;
mod tunnel;

pub(super) fn tunnel_adapter_present(alias: &str) -> std::io::Result<bool> {
    tunnel::adapter_present(alias)
}

use session::Engine;

pub(super) fn physical_default_interface(exclude_alias: &str) -> Option<String> {
    physical::physical_default_interface(exclude_alias)
}

use crate::platform::windows::session::WfpProtectionSession;
use crate::{
    LockdownApps, LockdownStatus, RoutingBackend, RoutingError, RoutingGuard, RoutingPlan,
};

#[derive(Debug, Default)]
pub(super) struct WfpBackend;

impl WfpBackend {
    pub(super) fn new() -> Self {
        Self
    }
}

impl RoutingBackend for WfpBackend {
    fn name(&self) -> &'static str {
        "windows-wfp"
    }

    fn preflight(&self) -> Result<(), RoutingError> {
        let session = Engine::dynamic()?;
        let transaction = session.transaction()?;
        session.add_provider_and_sublayer()?;
        transaction.commit()
    }

    fn begin_protection(
        &mut self,
        plan: &RoutingPlan,
        engine_binaries: &[&std::path::Path],
    ) -> Result<RoutingGuard, RoutingError> {
        Ok(RoutingGuard::from_session(WfpProtectionSession::begin(
            plan,
            engine_binaries,
        )?))
    }

    fn lockdown_status(&self) -> Result<LockdownStatus, RoutingError> {
        lockdown::status()
    }

    fn enable_lockdown(
        &self,
        allow_lan: bool,
        apps: &LockdownApps,
    ) -> Result<LockdownStatus, RoutingError> {
        lockdown::enable(allow_lan, apps)
    }

    fn disable_lockdown(&self) -> Result<bool, RoutingError> {
        lockdown::disable()
    }

    fn permit_in_lockdown(
        &mut self,
        binaries: &[&std::path::Path],
    ) -> Result<RoutingGuard, RoutingError> {
        lockdown::permit_programs(binaries)
    }
}
