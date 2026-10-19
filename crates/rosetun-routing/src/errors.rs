#[derive(Debug, thiserror::Error)]
pub enum RoutingError {
    #[error("insufficient privileges: {0}")]
    NotPrivileged(String),
    #[error("missing system dependency: {0}")]
    MissingDependency(String),
    #[error("failed to bring up interface {name}: {reason}")]
    Tun { name: String, reason: String },
    #[error("tunnel interface {name} is not ready: {reason}")]
    TunnelNotReady { name: String, reason: String },
    #[error("failed to change routes: {0}")]
    Route(String),
    #[error("failed to configure dns: {0}")]
    Dns(String),
    #[error("Windows Filtering Platform error {code}: {context}")]
    Wfp { code: u32, context: &'static str },
    #[error("routing for this platform is not yet implemented")]
    Unsupported,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// `FWP_E_IN_USE`: an object is still referenced, as the Lockdown sublayer is
/// by a running session's filters.
const FWP_E_IN_USE: u32 = 0x8032_000A;

impl RoutingError {
    pub fn is_tunnel_not_ready(&self) -> bool {
        matches!(self, Self::TunnelNotReady { .. })
    }

    pub fn is_in_use(&self) -> bool {
        matches!(self, Self::Wfp { code, .. } if *code == FWP_E_IN_USE)
    }
}

#[cfg(test)]
mod tests {
    use super::RoutingError;

    #[test]
    fn only_tunnel_not_ready_is_retryable() {
        assert!(
            RoutingError::TunnelNotReady {
                name: "rosetun0".to_owned(),
                reason: "adapter is still being created".to_owned(),
            }
            .is_tunnel_not_ready()
        );

        assert!(
            !RoutingError::Tun {
                name: "rosetun0".to_owned(),
                reason: "invalid configured address".to_owned(),
            }
            .is_tunnel_not_ready()
        );
        assert!(!RoutingError::Unsupported.is_tunnel_not_ready());
    }
}
