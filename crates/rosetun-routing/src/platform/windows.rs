use crate::{RoutingBackend, RoutingError, RoutingGuard, RoutingPlan};

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
        Err(RoutingError::Unsupported)
    }

    fn apply(&mut self, _plan: &RoutingPlan) -> Result<RoutingGuard, RoutingError> {
        Err(RoutingError::Unsupported)
    }
}