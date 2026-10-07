pub mod errors;
pub mod platform;

pub use errors::RoutingError;
pub use platform::backend;

pub type PrepareClosure =
    Box<dyn FnMut(&RoutingPlan, &std::path::Path) -> Result<(), RoutingError> + Send>;
pub type AuthorizeClosure = Box<dyn FnMut(&TunnelInterface) -> Result<(), RoutingError> + Send>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionScope {
    /// Kill switch: outside the tunnel only the engine, loopback and DHCP pass.
    AllTraffic,
    /// DNS lock: only port 53 is confined to the tunnel; other traffic is untouched.
    DnsOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingPlan {
    pub scope: ProtectionScope,
    /// Allows non-engine applications to reach private destinations; ignored for DNS-only protection.
    pub allow_lan: bool,
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
        let (address, _) = settings
            .ipv4
            .split_once('/')
            .ok_or_else(|| RoutingError::Tun {
                name: settings.name.clone(),
                reason: "the IPv4 address must use CIDR notation".to_owned(),
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

pub(crate) trait ProtectionSession: std::fmt::Debug + Send {
    /// Removes stale tunnel authorization and updates bootstrap protection
    /// atomically, without closing the existing protection session.
    fn prepare_reconnect(
        &mut self,
        plan: &RoutingPlan,
        engine_binary: &std::path::Path,
    ) -> Result<(), RoutingError>;
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
        Self::new_with_authorizer(|_| Ok(()), revert)
    }

    /// Creates a guard whose phase-2 authorization is implemented by closures.
    ///
    /// This is intended for routing backends that do not need a dedicated
    /// platform session type but still need to authorize a discovered tunnel.
    pub fn new_with_authorizer(
        authorize: impl FnMut(&TunnelInterface) -> Result<(), RoutingError> + Send + 'static,
        revert: impl FnOnce() -> Result<(), RoutingError> + Send + 'static,
    ) -> Self {
        Self::new_with_reconnector(|_, _| Err(RoutingError::Unsupported), authorize, revert)
    }

    /// Creates a guard with explicit protected-reconnect support.
    pub fn new_with_reconnector(
        prepare: impl FnMut(&RoutingPlan, &std::path::Path) -> Result<(), RoutingError> + Send + 'static,
        authorize: impl FnMut(&TunnelInterface) -> Result<(), RoutingError> + Send + 'static,
        revert: impl FnOnce() -> Result<(), RoutingError> + Send + 'static,
    ) -> Self {
        Self {
            session: Some(Box::new(ClosureSession {
                prepare: Box::new(prepare),
                authorize: Box::new(authorize),
                revert: Some(Box::new(revert)),
            })),
        }
    }

    pub fn noop() -> Self {
        Self::new_with_reconnector(|_, _| Ok(()), |_| Ok(()), || Ok(()))
    }

    pub(crate) fn from_session(session: impl ProtectionSession + 'static) -> Self {
        Self {
            session: Some(Box::new(session)),
        }
    }

    pub fn prepare_reconnect(
        &mut self,
        plan: &RoutingPlan,
        engine_binary: &std::path::Path,
    ) -> Result<(), RoutingError> {
        self.session
            .as_mut()
            .ok_or_else(|| RoutingError::Route("routing protection is not active".to_owned()))?
            .prepare_reconnect(plan, engine_binary)
    }

    /// Adds phase-2 authorization after the engine has created its TUN adapter.
    pub fn authorize_tunnel(&mut self, tunnel: &TunnelInterface) -> Result<(), RoutingError> {
        match self.session.as_mut() {
            Some(session) => session.authorize_tunnel(tunnel),
            None => Err(RoutingError::Route(
                "routing protection is not active".to_owned(),
            )),
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
    prepare: PrepareClosure,
    authorize: AuthorizeClosure,
    revert: Option<Box<dyn FnOnce() -> Result<(), RoutingError> + Send>>,
}

impl std::fmt::Debug for ClosureSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClosureSession")
            .field("armed", &self.revert.is_some())
            .finish_non_exhaustive()
    }
}

impl ProtectionSession for ClosureSession {
    fn prepare_reconnect(
        &mut self,
        plan: &RoutingPlan,
        engine_binary: &std::path::Path,
    ) -> Result<(), RoutingError> {
        (self.prepare)(plan, engine_binary)
    }

    fn authorize_tunnel(&mut self, tunnel: &TunnelInterface) -> Result<(), RoutingError> {
        (self.authorize)(tunnel)
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
