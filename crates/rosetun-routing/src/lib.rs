use std::net::IpAddr;

use rosetun_config::TunSettings;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingPlan {
    pub tun: TunSettings,
    pub bypass: Vec<IpAddr>,
    pub dns: Vec<IpAddr>,
    pub default_route: bool,
    pub kill_switch: bool,
}

pub trait RoutingBackend: std::fmt::Debug + Send {
    fn name(&self) -> &'static str;
    fn preflight(&self) -> Result<(), RoutingError>;
    fn apply(&mut self, plan: &RoutingPlan) -> Result<RoutingGuard, RoutingError>;
}

pub struct RoutingGuard {
    revert: Option<Box<dyn FnOnce() -> Result<(), RoutingError> + Send>>,
}

impl std::fmt::Debug for RoutingGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutingGuard")
            .field("armed", &self.revert.is_some())
            .finish()
    }
}

impl RoutingGuard {
    pub fn new(revert: impl FnOnce() -> Result<(), RoutingError> + Send + 'static) -> Self {
        Self {
            revert: Some(Box::new(revert)),
        }
    }
    pub fn noop() -> Self {
        Self::new(|| Ok(()))
    }

    pub fn revert(mut self) -> Result<(), RoutingError> {
        match self.revert.take() {
            Some(revert) => revert(),
            None => Ok(()),
        }
    }
}

impl Drop for RoutingGuard {
    fn drop(&mut self) {
        if let Some(revert) = self.revert.take()
            && let Err(error) = revert()
        {
            tracing::error!(%error, "failed to roll back routes");
        }
    }
}

mod platform;
pub mod errors;

pub use platform::backend;
use crate::errors::RoutingError;
