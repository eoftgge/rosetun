use std::net::IpAddr;

pub mod errors;
pub mod platform;

pub use errors::RoutingError;
pub use platform::backend;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingPlan {
    /// VPN server addresses that must remain reachable while protection is active.
    pub bypass: Vec<IpAddr>,
    /// Whether the platform protection layer must prevent direct internet access.
    pub kill_switch: bool,
}

pub trait RoutingBackend: std::fmt::Debug + Send {
    fn name(&self) -> &'static str;
    fn preflight(&self) -> Result<(), RoutingError>;

    /// Installs bootstrap protection before the engine starts. The returned
    /// guard owns the platform protection session until disconnect.
    fn begin_protection(
        &mut self,
        plan: &RoutingPlan,
        engine_binary: &std::path::Path,
    ) -> Result<RoutingGuard, RoutingError>;
}

/// An engine-owned tunnel interface that has passed engine readiness checks.
///
/// Platform routing discovers the concrete OS identity itself. On Windows this
/// means resolving `alias` to an interface LUID and validating `ipv4` before
/// adding `FWPM_CONDITION_IP_LOCAL_INTERFACE` filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelInterface {
    pub alias: String,
    pub ipv4: std::net::Ipv4Addr,
}

impl TryFrom<&rosetun_config::TunSettings> for TunnelInterface {
    type Error = RoutingError;

    fn try_from(settings: &rosetun_config::TunSettings) -> Result<Self, Self::Error> {
        let (address, _) = settings.ipv4.split_once('/').ok_or_else(|| {
            RoutingError::Tun {
                name: settings.name.clone(),
                reason: "the IPv4 address must use CIDR notation".to_owned(),
            }
        })?;
        let ipv4 = address.parse().map_err(|error| RoutingError::Tun {
            name: settings.name.clone(),
            reason: format!("invalid IPv4 address: {error}"),
        })?;

        Ok(Self {
            alias: settings.name.clone(),
            ipv4,
        })
    }
}

trait ProtectionSession: std::fmt::Debug + Send {
    fn authorize_tunnel(&mut self, tunnel: &TunnelInterface) -> Result<(), RoutingError>;
    fn teardown(&mut self) -> Result<(), RoutingError>;
}

pub struct RoutingGuard {
    session: Option<Box<dyn ProtectionSession>>,
}

impl std::fmt::Debug for RoutingGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutingGuard")
            .field("armed", &self.session.is_some())
            .finish()
    }
}

impl RoutingGuard {
    pub fn new(revert: impl FnOnce() -> Result<(), RoutingError> + Send + 'static) -> Self {
        Self {
            session: Some(Box::new(ClosureSession {
                revert: Some(Box::new(revert)),
            })),
        }
    }

    pub fn noop() -> Self {
        Self::new(|| Ok(()))
    }

    pub(crate) fn from_session(session: impl ProtectionSession + 'static) -> Self {
        Self {
            session: Some(Box::new(session)),
        }
    }

    /// Adds phase-2 authorization after the engine has created its TUN adapter.
    pub fn authorize_tunnel(&mut self, tunnel: &TunnelInterface) -> Result<(), RoutingError> {
        match self.session.as_mut() {
            Some(session) => session.authorize_tunnel(tunnel),
            None => Ok(()),
        }
    }

    pub fn revert(mut self) -> Result<(), RoutingError> {
        match self.session.take() {
            Some(mut session) => session.teardown(),
            None => Ok(()),
        }
    }
}

impl Drop for RoutingGuard {
    fn drop(&mut self) {
        if let Some(mut session) = self.session.take()
            && let Err(error) = session.teardown()
        {
            tracing::error!(%error, "failed to tear down routing protection");
        }
    }
}

struct ClosureSession {
    revert: Option<Box<dyn FnOnce() -> Result<(), RoutingError> + Send>>,
}

impl std::fmt::Debug for ClosureSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClosureSession")
            .field("armed", &self.revert.is_some())
            .finish()
    }
}

impl ProtectionSession for ClosureSession {
    fn authorize_tunnel(&mut self, _tunnel: &TunnelInterface) -> Result<(), RoutingError> {
        Err(RoutingError::Unsupported)
    }

    fn teardown(&mut self) -> Result<(), RoutingError> {
        match self.revert.take() {
            Some(revert) => revert(),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rosetun_config::TunSettings;

    use super::{RoutingError, TunnelInterface};

    #[test]
    fn tunnel_interface_uses_alias_and_address_from_cidr() {
        let settings = TunSettings {
            name: "rosetun0".to_owned(),
            ipv4: "172.19.0.1/30".to_owned(),
            ..Default::default()
        };

        let tunnel = TunnelInterface::try_from(&settings).expect("valid tunnel settings");

        assert_eq!(tunnel.alias, "rosetun0");
        assert_eq!(tunnel.ipv4, Ipv4Addr::new(172, 19, 0, 1));
    }

    #[test]
    fn tunnel_interface_rejects_an_address_without_prefix() {
        let settings = TunSettings {
            name: "rosetun0".to_owned(),
            ipv4: "172.19.0.1".to_owned(),
            ..Default::default()
        };

        assert!(matches!(
            TunnelInterface::try_from(&settings),
            Err(RoutingError::Tun { .. })
        ));
    }

    #[test]
    fn tunnel_interface_rejects_invalid_ipv4() {
        let settings = TunSettings {
            name: "rosetun0".to_owned(),
            ipv4: "not-an-address/30".to_owned(),
            ..Default::default()
        };

        assert!(matches!(
            TunnelInterface::try_from(&settings),
            Err(RoutingError::Tun { .. })
        ));
    }
}