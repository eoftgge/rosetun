mod filters;
mod policy;
mod session;
mod tunnel;

use session::DynamicSession;

use crate::{RoutingBackend, RoutingError, RoutingGuard, RoutingPlan};
use crate::platform::windows::session::WfpProtectionSession;

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
        let session = DynamicSession::open()?;
        let transaction = session.transaction()?;
        session.add_provider_and_sublayer()?;
        transaction.commit()
    }

    fn begin_protection(
        &mut self,
        plan: &RoutingPlan,
        engine_binary: &std::path::Path,
    ) -> Result<RoutingGuard, RoutingError> {
        Ok(RoutingGuard::from_session(WfpProtectionSession::begin(
            plan,
            engine_binary,
        )?))
    }
}
