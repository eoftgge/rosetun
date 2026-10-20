pub mod errors;
pub mod platform;

pub use errors::RoutingError;
pub use platform::backend;
pub use platform::tunnel_adapter_present;

/// Lockdown: persistent WFP objects that keep the machine blocked outside the
/// tunnel while disconnected, after a service crash and across reboots. The
/// objects themselves are the only record of whether it is on.
pub mod lockdown {
    use crate::{LockdownApps, LockdownStatus, RoutingError};

    /// Reads which Lockdown objects exist.
    pub fn status() -> Result<LockdownStatus, RoutingError> {
        crate::platform::lockdown_status()
    }

    /// Adds what is missing and removes what no longer applies, in one
    /// transaction, then flushes the change to disk.
    pub fn enable(allow_lan: bool, apps: &LockdownApps) -> Result<LockdownStatus, RoutingError> {
        crate::platform::lockdown_enable(allow_lan, apps)
    }

    /// Removes every Lockdown object by its fixed key, in one transaction,
    /// then flushes. Absent objects are not an error; returns whether anything
    /// was removed. Fails with `FWP_E_IN_USE` while a running session still
    /// has filters in the Lockdown sublayer.
    pub fn disable() -> Result<bool, RoutingError> {
        crate::platform::lockdown_disable()
    }
}

/// Choose the physical default route: a probe engine without its own TUN would
/// otherwise follow the connected session's default route back into that tunnel.
pub fn physical_default_interface(exclude_alias: &str) -> Option<String> {
    platform::physical_default_interface(exclude_alias)
}

pub type PrepareClosure =
    Box<dyn FnMut(&RoutingPlan, &[&std::path::Path]) -> Result<(), RoutingError> + Send>;
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
    /// Puts the session's filters into the Lockdown sublayer instead of the
    /// Rosetun one, above Lockdown's own block.
    pub lockdown: bool,
}

/// What exists of Lockdown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LockdownStatus {
    /// The Lockdown provider exists.
    pub enabled: bool,
    /// Provider, sublayer and every filter of the base set are present, and
    /// with `allow_lan` every LAN filter too. Application permits are not
    /// counted: a missing program has none.
    pub complete: bool,
    pub allow_lan: bool,
    /// The weight BFE stored for the sublayer, which may differ from the one
    /// requested.
    pub sublayer_weight: Option<u16>,
}

/// Programs Lockdown permits by application ID so a subscription can be
/// updated without the tunnel. `None` (a program that is not installed) adds
/// no permit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LockdownApps {
    pub gui: Option<std::path::PathBuf>,
    pub cli: Option<std::path::PathBuf>,
}

pub trait RoutingBackend: std::fmt::Debug + Send {
    fn name(&self) -> &'static str;
    fn preflight(&self) -> Result<(), RoutingError>;

    /// Installs bootstrap protection before the engine starts. The returned
    /// guard owns the platform protection session until disconnect.
    fn begin_protection(
        &mut self,
        plan: &RoutingPlan,
        engine_binaries: &[&std::path::Path],
    ) -> Result<RoutingGuard, RoutingError>;

    fn lockdown_status(&self) -> Result<LockdownStatus, RoutingError> {
        Ok(LockdownStatus::default())
    }

    fn enable_lockdown(
        &self,
        _allow_lan: bool,
        _apps: &LockdownApps,
    ) -> Result<LockdownStatus, RoutingError> {
        Err(RoutingError::Unsupported)
    }

    fn disable_lockdown(&self) -> Result<bool, RoutingError> {
        Err(RoutingError::Unsupported)
    }

    /// Permits these programs in the Lockdown sublayer for as long as the
    /// guard lives, for server checks while no session is running.
    fn permit_in_lockdown(
        &mut self,
        _binaries: &[&std::path::Path],
    ) -> Result<RoutingGuard, RoutingError> {
        Err(RoutingError::Unsupported)
    }
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
        engine_binaries: &[&std::path::Path],
    ) -> Result<(), RoutingError>;
    fn authorize_tunnel(&mut self, tunnel: &TunnelInterface) -> Result<(), RoutingError>;
    fn permit_probe_binary(&mut self, binary: &std::path::Path) -> Result<(), RoutingError>;
    fn remove_probe_binary(&mut self, binary: &std::path::Path) -> Result<(), RoutingError>;
    /// Moves every filter of the session into the Lockdown sublayer or back,
    /// in one transaction, so there is no moment without them.
    fn set_lockdown(&mut self, lockdown: bool) -> Result<(), RoutingError>;
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
        prepare: impl FnMut(&RoutingPlan, &[&std::path::Path]) -> Result<(), RoutingError>
        + Send
        + 'static,
        authorize: impl FnMut(&TunnelInterface) -> Result<(), RoutingError> + Send + 'static,
        revert: impl FnOnce() -> Result<(), RoutingError> + Send + 'static,
    ) -> Self {
        Self {
            session: Some(Box::new(ClosureSession {
                prepare: Box::new(prepare),
                authorize: Box::new(authorize),
                lockdown: Box::new(|_| Ok(())),
                revert: Some(Box::new(revert)),
            })),
        }
    }

    /// A guard whose moves between the Rosetun and Lockdown sublayers are
    /// implemented by a closure; everything else succeeds and does nothing.
    pub fn new_with_lockdown(
        lockdown: impl FnMut(bool) -> Result<(), RoutingError> + Send + 'static,
    ) -> Self {
        Self {
            session: Some(Box::new(ClosureSession {
                prepare: Box::new(|_, _| Ok(())),
                authorize: Box::new(|_| Ok(())),
                lockdown: Box::new(lockdown),
                revert: Some(Box::new(|| Ok(()))),
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
        engine_binaries: &[&std::path::Path],
    ) -> Result<(), RoutingError> {
        self.session
            .as_mut()
            .ok_or_else(|| RoutingError::Route("routing protection is not active".to_owned()))?
            .prepare_reconnect(plan, engine_binaries)
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

    pub fn permit_probe_binary(&mut self, binary: &std::path::Path) -> Result<(), RoutingError> {
        self.session
            .as_mut()
            .ok_or_else(|| RoutingError::Route("routing protection is not active".to_owned()))?
            .permit_probe_binary(binary)
    }

    pub fn remove_probe_binary(&mut self, binary: &std::path::Path) -> Result<(), RoutingError> {
        match self.session.as_mut() {
            Some(session) => session.remove_probe_binary(binary),
            None => Ok(()),
        }
    }

    pub fn set_lockdown(&mut self, lockdown: bool) -> Result<(), RoutingError> {
        self.session
            .as_mut()
            .ok_or_else(|| RoutingError::Route("routing protection is not active".to_owned()))?
            .set_lockdown(lockdown)
    }

    pub fn revert(mut self) -> Result<(), RoutingError> {
        self.revert_in_place()
    }

    pub fn revert_in_place(&mut self) -> Result<(), RoutingError> {
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
    lockdown: Box<dyn FnMut(bool) -> Result<(), RoutingError> + Send>,
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
        engine_binaries: &[&std::path::Path],
    ) -> Result<(), RoutingError> {
        (self.prepare)(plan, engine_binaries)
    }

    fn authorize_tunnel(&mut self, tunnel: &TunnelInterface) -> Result<(), RoutingError> {
        (self.authorize)(tunnel)
    }

    fn permit_probe_binary(&mut self, _binary: &std::path::Path) -> Result<(), RoutingError> {
        Ok(())
    }

    fn remove_probe_binary(&mut self, _binary: &std::path::Path) -> Result<(), RoutingError> {
        Ok(())
    }

    fn set_lockdown(&mut self, lockdown: bool) -> Result<(), RoutingError> {
        (self.lockdown)(lockdown)
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
