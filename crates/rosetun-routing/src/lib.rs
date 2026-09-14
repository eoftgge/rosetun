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

#[derive(Debug, thiserror::Error)]
pub enum RoutingError {
    #[error("not enough rights: {0}")]
    NotPrivileged(String),
    #[error("the system does not have the required: {0}")]
    MissingDependency(String),
    #[error("failed to bring up interface {name}: {reason}")]
    Tun { name: String, reason: String },
    #[error("failed to change routes: {0}")]
    Route(String),
    #[error("failed to configure dns: {0}")]
    Dns(String),
    #[error("routing for this platform is not yet implemented")]
    Unsupported,
    #[error("input/output error: {0}")]
    Io(#[from] std::io::Error),
}

mod platform;

pub use platform::backend;