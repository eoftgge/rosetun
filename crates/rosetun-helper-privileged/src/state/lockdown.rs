//! Lockdown in the service. The persistent WFP objects are the only record of
//! whether it is on; the service reads them at start and is the only writer
//! while it runs, so it keeps a copy instead of asking BFE on every request.
//!
//! The installer's upgrade hold is the same objects with a marker
//! (`rosetun_routing::upgrade_hold`). The service treats it as Lockdown, so a
//! connect goes above its block, and lifts it like turning Lockdown off: once
//! a session is connected, on a disconnect, or on `OpenNetwork`. It has no
//! timer: until then the network stays closed.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, TryLockError};

use rosetun_config::ConnectionMode;
use rosetun_ipc::{ErrorCode, HelperError};
use rosetun_routing::{
    LockdownApps, ProtectionScope, RoutingBackend, RoutingError, RoutingGuard, RoutingPlan,
    TunnelInterface,
};

use super::{Acquired, Caller, Guard, Helper, SESSION_WAIT, Session, SessionHolder, StartMode};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct LockdownState {
    pub(super) enabled: bool,
    pub(super) allow_lan: bool,
    /// Private networks behind the router are open too; only with `allow_lan`.
    pub(super) private_networks: bool,
    /// The objects are an upgrade's hold, not the user's Lockdown.
    pub(super) upgrade_hold: bool,
}

pub(super) type SharedLockdown = Arc<Mutex<LockdownState>>;

pub(super) fn read(shared: &SharedLockdown) -> LockdownState {
    *shared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write(shared: &SharedLockdown, state: LockdownState) {
    *shared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = state;
    shared.clear_poison();
}

/// Lockdown forces the kill switch: under its block a session without its
/// own permits in the Lockdown sublayer has no tunnel at all.
pub(super) fn protection_scope(
    mode: StartMode,
    kill_switch: bool,
    tunnel_dns: bool,
    lockdown: bool,
    local_proxy: bool,
) -> Option<ProtectionScope> {
    if kill_switch || lockdown {
        return Some(ProtectionScope::AllTraffic);
    }
    // The engine resolves names itself, so there is no system DNS to confine:
    // a program that goes around the proxy goes around all of it, and that
    // is what this mode without the kill switch says it does.
    if local_proxy {
        return None;
    }
    match mode {
        StartMode::Fresh => tunnel_dns.then_some(ProtectionScope::DnsOnly),
        // The guard stays; only the kill switch may widen it.
        StartMode::ProtectedReconnect => Some(ProtectionScope::DnsOnly),
    }
}

/// The GUI and the CLI next to the service, so a subscription can be updated
/// while locked, and the service for its own name lookups. A program that is
/// not installed gets no permit.
#[cfg_attr(test, expect(dead_code, reason = "tests permit fixed paths"))]
pub(super) fn lockdown_apps() -> LockdownApps {
    let exe = std::env::current_exe().ok();
    let dir = exe
        .as_ref()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    let find = |name: &str| -> Option<PathBuf> {
        let path = dir.as_ref()?.join(name);
        path.is_file()
            .then(|| std::fs::canonicalize(&path).ok())
            .flatten()
    };
    // On Linux only whether they are installed counts: Lockdown permits
    // the scopes they run in, not the files.
    let suffix = std::env::consts::EXE_SUFFIX;
    LockdownApps {
        gui: find(&format!("rosetun-gui{suffix}")),
        cli: find(&format!("rosetun{suffix}")),
        service: exe.and_then(|exe| std::fs::canonicalize(exe).ok()),
    }
}

/// Programs under fixed documentation paths, since the test binary has no
/// GUI or CLI next to it.
#[cfg(test)]
pub(super) fn test_apps() -> LockdownApps {
    LockdownApps {
        gui: Some(PathBuf::from(r"C:\Rosetun\rosetun-gui.exe")),
        cli: Some(PathBuf::from(r"C:\Rosetun\rosetun.exe")),
        service: Some(PathBuf::from(r"C:\Rosetun\rosetun-helper-privileged.exe")),
    }
}

fn routing_failed(error: RoutingError) -> HelperError {
    HelperError::new(ErrorCode::RoutingFailed, error.to_string())
}

impl Helper {
    pub(crate) fn set_lockdown_as(
        &self,
        caller: &Caller,
        enabled: bool,
        allow_lan: bool,
        private_networks: bool,
    ) -> Result<(), HelperError> {
        // Lockdown is machine-wide and outlives the session, so the session
        // owner alone may not turn it off. An administrator passes any
        // owner check as well.
        if !caller.administrator {
            return Err(HelperError::new(
                ErrorCode::AccessDenied,
                "only an administrator can change Lockdown",
            ));
        }
        // Turning it off still works: on Linux it lifts the hold after a crash.
        if enabled && !self.protection.lockdown {
            return Err(HelperError::new(
                ErrorCode::ProtectionUnavailable,
                "Lockdown is not available on this system",
            ));
        }
        let mut session = self.session_for(SessionHolder::Lockdown)?;
        if self.with_status(|status| status.state.is_transitional()) {
            return Err(HelperError::new(
                ErrorCode::Busy,
                "another tunnel operation is in progress",
            ));
        }
        // A server check may hold its own permits in the Lockdown sublayer,
        // which would make removing it fail with FWP_E_IN_USE.
        let _probe = match self.probe.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => {
                return Err(HelperError::new(
                    ErrorCode::Busy,
                    "a server check is in progress",
                ));
            }
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
        };
        if enabled {
            session.enable_lockdown(allow_lan, private_networks)?;
            session.adopt_upgrade_hold()
        } else {
            session.disable_lockdown()
        }
    }

    /// Lifts the upgrade hold for the session's owner or an administrator;
    /// with no session, for any local account, as a disconnect would.
    pub(crate) fn open_network_as(&self, caller: &Caller) -> Result<(), HelperError> {
        self.check_owner(caller)?;
        let mut session = self.session_for(SessionHolder::Lockdown)?;
        self.check_owner(caller)?;
        if !read(&session.lockdown).upgrade_hold {
            return Ok(());
        }
        if self.with_status(|status| status.state.is_transitional()) {
            return Err(HelperError::new(
                ErrorCode::Busy,
                "another tunnel operation is in progress",
            ));
        }
        let _probe = match self.probe.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => {
                return Err(HelperError::new(
                    ErrorCode::Busy,
                    "a server check is in progress",
                ));
            }
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
        };
        session.release_upgrade_hold("opened by the user")
    }

    /// At service start: Lockdown is on if its provider exists. Repairs a
    /// partial set by adding what is missing; on any doubt the objects stay
    /// as they are, which keeps the machine closed rather than open.
    pub fn restore_lockdown(&self) {
        let session = self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let status = match session.routing.lockdown_status() {
            Ok(status) => status,
            Err(error) => {
                tracing::error!(%error, "could not read Lockdown; its objects, if any, stay");
                return;
            }
        };
        if !status.enabled {
            tracing::info!("Lockdown is off");
            return;
        }
        write(
            &session.lockdown,
            LockdownState {
                enabled: true,
                allow_lan: status.allow_lan,
                private_networks: status.private_networks,
                upgrade_hold: status.upgrade_hold,
            },
        );
        if status.upgrade_hold {
            tracing::info!("the upgrade hold keeps the network closed until a connect");
        }
        // No session yet: the GUI and the CLI get their permits back too.
        let lan = session.lockdown_lan(status.allow_lan, status.private_networks);
        match session
            .routing
            .enable_lockdown(lan.as_ref(), &(session.lockdown_apps)())
        {
            Ok(repaired) => tracing::info!(
                allow_lan = status.allow_lan,
                complete_before = status.complete,
                complete = repaired.complete,
                sublayer_weight = %format_weight(repaired.sublayer_weight),
                "Lockdown is on"
            ),
            Err(error) => tracing::error!(
                %error,
                complete = status.complete,
                sublayer_weight = %format_weight(status.sublayer_weight),
                "Lockdown is on but could not be repaired"
            ),
        }
    }

    /// A client connected (Linux): the GUI or the CLI may have just made
    /// the scope Lockdown permits it by, so Lockdown's permits follow the
    /// scopes before the client's first request outside. Never waits: a
    /// busy session runs a change of its own, and a session withdraws
    /// those permits anyway.
    pub(crate) fn refresh_lockdown_programs(&self) {
        if !read(&self.lockdown).enabled {
            return;
        }
        let Some(Acquired::Locked(session)) = self.try_session(SessionHolder::Lockdown) else {
            return;
        };
        if session.programs_withdrawn {
            return;
        }
        if let Err(error) = session.routing.refresh_lockdown_programs() {
            tracing::warn!(%error, "could not update Lockdown's permits for Rosetun's programs");
        }
    }

    /// For a server check while no session runs: a short permit for the
    /// check's engine in the Lockdown sublayer. With a session, its own
    /// permits already cover the engine.
    pub(super) fn lockdown_probe_routing(
        &self,
        engine: &Path,
    ) -> Result<Option<Arc<Mutex<RoutingGuard>>>, HelperError> {
        let mut session = match self.acquire_session(SessionHolder::Probe, SESSION_WAIT) {
            Some(Acquired::Locked(session)) => session,
            None => {
                return Err(self.session_busy(
                    SessionHolder::Probe,
                    "tunnel changes are in progress during server checks",
                ));
            }
            Some(Acquired::Poisoned(_)) => {
                return Err(HelperError::new(
                    ErrorCode::Internal,
                    "helper state is unavailable during server checks",
                ));
            }
        };
        if !read(&session.lockdown).enabled || session.guard.is_some() {
            return Ok(None);
        }
        let guard = session
            .routing
            .permit_in_lockdown(&[engine])
            .map_err(routing_failed)?;
        Ok(Some(Arc::new(Mutex::new(guard))))
    }
}

fn format_weight(weight: Option<u16>) -> String {
    weight.map_or_else(|| "none".to_owned(), |weight| format!("{weight:#06x}"))
}

impl Session {
    /// Persistent objects first, then the session's filters move above
    /// Lockdown's block. In between the tunnel is blocked, never open.
    fn enable_lockdown(
        &mut self,
        allow_lan: bool,
        private_networks: bool,
    ) -> Result<(), HelperError> {
        // During a session the GUI and the CLI get no permits: the session's
        // filters land in the Lockdown sublayer, above its block but below
        // them.
        if self.guard.is_some() || self.request.is_some() {
            self.programs_withdrawn = true;
        }
        let lan = self.lockdown_lan(allow_lan, private_networks);
        let status = self
            .routing
            .enable_lockdown(lan.as_ref(), &self.lockdown_programs())
            .map_err(routing_failed)?;
        write(
            &self.lockdown,
            LockdownState {
                enabled: true,
                allow_lan,
                private_networks,
                ..read(&self.lockdown)
            },
        );
        tracing::info!(
            allow_lan,
            private_networks,
            complete = status.complete,
            sublayer_weight = %format_weight(status.sublayer_weight),
            "Lockdown turned on"
        );
        self.cover_with_lockdown()
    }

    fn cover_with_lockdown(&mut self) -> Result<(), HelperError> {
        let request = self.request.clone();
        let Some(guard) = self.guard.as_mut() else {
            let Some(request) = request else {
                return Ok(());
            };
            // A session without protection gets the kill switch it now needs.
            let (plan, tunnel) = all_traffic(&request, &self.lan)?;
            let binaries = self
                .protected_binaries
                .iter()
                .map(PathBuf::as_path)
                .collect::<Vec<_>>();
            let mut routing = self
                .routing
                .begin_protection(&plan, &binaries)
                .map_err(routing_failed)?;
            if let Some(tunnel) = tunnel.as_ref() {
                routing.authorize_tunnel(tunnel).map_err(routing_failed)?;
            }
            self.guard = Some(Guard {
                routing: Arc::new(Mutex::new(routing)),
                scope: ProtectionScope::AllTraffic,
            });
            tracing::info!("Lockdown is on: the kill switch is forced on for this session");
            return Ok(());
        };
        let mut routing = guard
            .routing
            .lock()
            .map_err(|_| HelperError::new(ErrorCode::RoutingFailed, "routing guard is poisoned"))?;
        match (guard.scope, request) {
            (ProtectionScope::DnsOnly, Some(request)) => {
                let (plan, tunnel) = all_traffic(&request, &self.lan)?;
                let binaries = self
                    .protected_binaries
                    .iter()
                    .map(PathBuf::as_path)
                    .collect::<Vec<_>>();
                routing
                    .prepare_reconnect(&plan, &binaries)
                    .map_err(routing_failed)?;
                if let Some(tunnel) = tunnel.as_ref() {
                    routing.authorize_tunnel(tunnel).map_err(routing_failed)?;
                }
                guard.scope = ProtectionScope::AllTraffic;
                tracing::info!("Lockdown is on: the kill switch is forced on for this session");
            }
            _ => routing.set_lockdown(true).map_err(routing_failed)?,
        }
        Ok(())
    }

    /// The session's filters move back to the Rosetun sublayer first, so
    /// removing the Lockdown sublayer does not fail with FWP_E_IN_USE.
    fn disable_lockdown(&mut self) -> Result<(), HelperError> {
        if let Some(guard) = self.guard.as_ref() {
            guard
                .routing
                .lock()
                .map_err(|_| {
                    HelperError::new(ErrorCode::RoutingFailed, "routing guard is poisoned")
                })?
                .set_lockdown(false)
                .map_err(routing_failed)?;
        }
        let removed = match self.routing.disable_lockdown() {
            Ok(removed) => removed,
            Err(error) => {
                // The persistent block stays; without its permits back above
                // it the session would be "connected" with no network.
                if let Some(guard) = self.guard.as_ref()
                    && let Err(restore) = guard
                        .routing
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .set_lockdown(true)
                {
                    tracing::error!(
                        error = %restore,
                        "could not move the session back above the Lockdown block"
                    );
                }
                return Err(routing_failed(error));
            }
        };
        write(&self.lockdown, LockdownState::default());
        self.programs_withdrawn = false;
        tracing::info!(removed, "Lockdown turned off");
        self.release_forced_kill_switch();
        Ok(())
    }

    /// Lockdown turned on by an administrator during the hold stays when the
    /// hold would end: only the marker goes.
    fn adopt_upgrade_hold(&mut self) -> Result<(), HelperError> {
        let state = read(&self.lockdown);
        if !state.upgrade_hold {
            return Ok(());
        }
        self.routing.end_upgrade_hold().map_err(routing_failed)?;
        write(
            &self.lockdown,
            LockdownState {
                upgrade_hold: false,
                ..state
            },
        );
        tracing::info!("the upgrade hold is now the user's Lockdown");
        Ok(())
    }

    /// Lifts the upgrade hold as turning Lockdown off does: a session's
    /// filters move back to the Rosetun sublayer before the block goes, so
    /// a connected tunnel is never open, and a kill switch Lockdown forced
    /// on a session that does not want one is released.
    pub(super) fn release_upgrade_hold(&mut self, reason: &'static str) -> Result<(), HelperError> {
        if !read(&self.lockdown).upgrade_hold {
            return Ok(());
        }
        self.disable_lockdown()?;
        tracing::info!(reason, "upgrade hold lifted");
        Ok(())
    }

    /// The programs Lockdown permits now: without the GUI and the CLI while
    /// the session's filters keep their permits away.
    pub(super) fn lockdown_programs(&self) -> LockdownApps {
        let apps = (self.lockdown_apps)();
        if self.programs_withdrawn {
            LockdownApps {
                gui: None,
                cli: None,
                ..apps
            }
        } else {
            apps
        }
    }

    /// Once the session's filters are gone, the GUI and the CLI get their
    /// Lockdown permits back. A failure leaves them blocked until the next
    /// disconnect or service start, which is closed rather than open.
    pub(super) fn restore_lockdown_programs(&mut self) {
        if !self.programs_withdrawn {
            return;
        }
        let state = read(&self.lockdown);
        if !state.enabled {
            self.programs_withdrawn = false;
            return;
        }
        let lan = self.lockdown_lan(state.allow_lan, state.private_networks);
        match self
            .routing
            .enable_lockdown(lan.as_ref(), &(self.lockdown_apps)())
        {
            Ok(_) => {
                self.programs_withdrawn = false;
                tracing::info!("Lockdown permits for Rosetun's programs restored");
            }
            Err(error) => tracing::error!(
                %error,
                "could not restore Lockdown permits for Rosetun's programs"
            ),
        }
    }

    /// Lockdown forced the kill switch on a session whose settings have it
    /// off; give it the protection it would have had, or a protected
    /// reconnect would refuse to narrow it.
    fn release_forced_kill_switch(&mut self) {
        let Some(request) = self.request.as_ref() else {
            return;
        };
        let settings = &request.settings;
        if settings.kill_switch
            || !self
                .guard
                .as_ref()
                .is_some_and(|guard| guard.scope == ProtectionScope::AllTraffic)
        {
            return;
        }
        let tunnel_dns = settings.connection_mode == ConnectionMode::Tun
            && self
                .engines
                .get(settings.engine)
                .is_some_and(|backend| backend.tunnel_dns_server(&settings.tun).is_some());
        if !tunnel_dns {
            if let Some(guard) = self.guard.take()
                && let Err(error) = guard
                    .routing
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .revert_in_place()
            {
                tracing::error!(%error, "failed to remove the forced kill switch");
            }
            tracing::info!("kill switch released with Lockdown");
            return;
        }
        let plan = RoutingPlan {
            scope: ProtectionScope::DnsOnly,
            allow_lan: settings.allow_lan,
            lan: Default::default(),
            lockdown: false,
        };
        let tunnel = match TunnelInterface::try_from(&settings.tun) {
            Ok(tunnel) => tunnel,
            Err(error) => {
                tracing::warn!(%error, "the kill switch stays on until the next connect");
                return;
            }
        };
        let binaries = self
            .protected_binaries
            .iter()
            .map(PathBuf::as_path)
            .collect::<Vec<_>>();
        let guard = self.guard.as_mut().expect("checked above");
        let result = guard
            .routing
            .lock()
            .map_err(|_| RoutingError::Route("routing guard is poisoned".to_owned()))
            .and_then(|mut routing| {
                routing.prepare_reconnect(&plan, &binaries)?;
                routing.authorize_tunnel(&tunnel)
            });
        match result {
            Ok(()) => {
                guard.scope = ProtectionScope::DnsOnly;
                tracing::info!("kill switch released with Lockdown; the DNS lock stays");
            }
            Err(error) => {
                tracing::warn!(%error, "the kill switch stays on until the next connect");
            }
        }
    }
}

/// Updates the persistent LAN permits to what an administrator's connect
/// asks for. Anyone else's connect leaves Lockdown as it is; the session's
/// own LAN rules still follow the request.
pub(super) fn sync_lan(
    routing: &dyn RoutingBackend,
    shared: &SharedLockdown,
    apps: &LockdownApps,
    caller: &Caller,
    lan: Option<&rosetun_routing::lan::LanAccess>,
) -> Result<(), HelperError> {
    let allow_lan = lan.is_some();
    let private_networks = lan.is_some_and(|lan| lan.private_networks);
    let state = read(shared);
    if !state.enabled
        || (state.allow_lan == allow_lan && state.private_networks == private_networks)
    {
        return Ok(());
    }
    if !caller.administrator {
        tracing::info!(
            allow_lan = state.allow_lan,
            "Lockdown LAN access stays: only an administrator changes it"
        );
        return Ok(());
    }
    routing.enable_lockdown(lan, apps).map_err(routing_failed)?;
    write(
        shared,
        LockdownState {
            enabled: true,
            allow_lan,
            private_networks,
            ..state
        },
    );
    tracing::info!(
        allow_lan,
        private_networks,
        "Lockdown LAN access follows the connect request"
    );
    Ok(())
}

/// The plan of a kill switch forced on a running session, and the adapter to
/// authorize, which the proxy mode does not have.
fn all_traffic(
    request: &rosetun_ipc::ConnectRequest,
    lan: &rosetun_routing::lan::LanAccess,
) -> Result<(RoutingPlan, Option<TunnelInterface>), HelperError> {
    let tunnel = match request.settings.connection_mode {
        ConnectionMode::Tun => {
            Some(TunnelInterface::try_from(&request.settings.tun).map_err(routing_failed)?)
        }
        ConnectionMode::SystemProxy => None,
    };
    Ok((
        RoutingPlan {
            scope: ProtectionScope::AllTraffic,
            allow_lan: request.settings.allow_lan,
            lan: lan.clone(),
            lockdown: true,
        },
        tunnel,
    ))
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use rosetun_engine::EngineRegistry;
    use rosetun_ipc::ErrorCode;
    use rosetun_ipc::transport::AccountIdentity;
    use rosetun_routing::{
        LockdownApps, LockdownStatus, ProtectionCapabilities, ProtectionScope, RoutingBackend,
        RoutingError, RoutingGuard, RoutingPlan,
    };

    use super::protection_scope;
    use crate::log_gate::VerboseGate;
    use crate::state::{Caller, Guard, Helper, SessionHolder, StartMode};

    #[test]
    fn lockdown_forces_the_all_traffic_policy() {
        for mode in [StartMode::Fresh, StartMode::ProtectedReconnect] {
            for tunnel_dns in [false, true] {
                assert_eq!(
                    protection_scope(mode, false, tunnel_dns, true, false),
                    Some(ProtectionScope::AllTraffic)
                );
                assert_eq!(
                    protection_scope(mode, true, tunnel_dns, false, false),
                    Some(ProtectionScope::AllTraffic)
                );
            }
        }
        assert_eq!(
            protection_scope(StartMode::Fresh, false, true, false, false),
            Some(ProtectionScope::DnsOnly)
        );
        assert_eq!(
            protection_scope(StartMode::Fresh, false, false, false, false),
            None
        );
        assert_eq!(
            protection_scope(StartMode::ProtectedReconnect, false, false, false, false),
            Some(ProtectionScope::DnsOnly)
        );
    }

    #[derive(Debug, Default)]
    struct Calls {
        enabled: Mutex<Vec<bool>>,
        /// The addresses each write of the set left out of the segment.
        left_out: Mutex<Vec<Vec<std::net::IpAddr>>>,
        apps: Mutex<Vec<LockdownApps>>,
        disabled: AtomicUsize,
        hold_ended: AtomicUsize,
        installed: Mutex<Option<LockdownStatus>>,
        fail_disable: std::sync::atomic::AtomicBool,
        /// A system without Lockdown and without a kill switch, as Linux
        /// outside its service.
        unprotected: std::sync::atomic::AtomicBool,
        released_on_stop: AtomicUsize,
        kept_on_stop: AtomicUsize,
    }

    impl Calls {
        /// What the installer leaves: Lockdown's set with the hold's marker.
        fn held() -> Arc<Self> {
            let calls = Arc::new(Self::default());
            *calls.installed.lock().unwrap() = Some(LockdownStatus {
                enabled: true,
                complete: true,
                allow_lan: false,
                private_networks: false,
                sublayer_weight: Some(0xD000),
                upgrade_hold: true,
            });
            calls
        }

        fn disabled(&self) -> usize {
            self.disabled.load(Ordering::Acquire)
        }
    }

    #[derive(Debug)]
    struct LockdownRouting(Arc<Calls>);

    impl RoutingBackend for LockdownRouting {
        fn name(&self) -> &'static str {
            "test-lockdown"
        }

        fn capabilities(&self) -> ProtectionCapabilities {
            let protected = !self.0.unprotected.load(Ordering::Acquire);
            ProtectionCapabilities {
                kill_switch: protected,
                lockdown: protected,
            }
        }

        fn unavailable_reason(&self) -> Option<String> {
            self.0
                .unprotected
                .load(Ordering::Acquire)
                .then(|| "no cgroup of its own".to_owned())
        }

        fn preflight(&self) -> Result<(), RoutingError> {
            Ok(())
        }

        fn begin_protection(
            &mut self,
            _plan: &RoutingPlan,
            _engine_binaries: &[&Path],
        ) -> Result<RoutingGuard, RoutingError> {
            Ok(RoutingGuard::noop())
        }

        fn keep_protection_on_stop(&self) {
            self.0.kept_on_stop.fetch_add(1, Ordering::AcqRel);
        }

        fn release_on_stop(&self) -> Result<(), RoutingError> {
            self.0.released_on_stop.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn lockdown_status(&self) -> Result<LockdownStatus, RoutingError> {
            Ok(self.0.installed.lock().unwrap().unwrap_or_default())
        }

        fn enable_lockdown(
            &self,
            lan: Option<&rosetun_routing::lan::LanAccess>,
            apps: &LockdownApps,
        ) -> Result<LockdownStatus, RoutingError> {
            let allow_lan = lan.is_some();
            self.0.enabled.lock().unwrap().push(allow_lan);
            self.0.left_out.lock().unwrap().push(
                lan.map(|lan| lan.segment.left_out().to_vec())
                    .unwrap_or_default(),
            );
            self.0.apps.lock().unwrap().push(apps.clone());
            let held = self
                .0
                .installed
                .lock()
                .unwrap()
                .is_some_and(|status| status.upgrade_hold);
            let status = LockdownStatus {
                enabled: true,
                complete: true,
                allow_lan,
                private_networks: false,
                sublayer_weight: Some(0xD000),
                upgrade_hold: held,
            };
            *self.0.installed.lock().unwrap() = Some(status);
            Ok(status)
        }

        fn disable_lockdown(&self) -> Result<bool, RoutingError> {
            self.0.disabled.fetch_add(1, Ordering::AcqRel);
            if self.0.fail_disable.load(Ordering::Acquire) {
                return Err(RoutingError::Wfp {
                    code: 0x8032_000A,
                    context: "removing the Lockdown sublayer",
                });
            }
            Ok(self.0.installed.lock().unwrap().take().is_some())
        }

        fn end_upgrade_hold(&self) -> Result<(), RoutingError> {
            self.0.hold_ended.fetch_add(1, Ordering::AcqRel);
            if let Some(status) = self.0.installed.lock().unwrap().as_mut() {
                status.upgrade_hold = false;
            }
            Ok(())
        }
    }

    fn held_helper(calls: &Arc<Calls>) -> Helper {
        let helper = lockdown_helper(calls);
        helper.restore_lockdown();
        helper
    }

    fn lockdown_helper(calls: &Arc<Calls>) -> Helper {
        Helper::new(
            EngineRegistry::new(),
            Box::new(LockdownRouting(Arc::clone(calls))),
            VerboseGate::default(),
        )
    }

    #[test]
    fn set_lockdown_writes_the_objects_and_reports_them_in_status() {
        let calls = Arc::new(Calls::default());
        let helper = lockdown_helper(&calls);
        let caller = Caller::fake(b"admin", true);
        assert!(!helper.status().lockdown);

        helper.set_lockdown_as(&caller, true, true, false).unwrap();
        assert!(helper.status().lockdown);
        helper.set_lockdown_as(&caller, true, false, false).unwrap();
        assert_eq!(*calls.enabled.lock().unwrap(), [true, false]);

        helper
            .set_lockdown_as(&caller, false, false, false)
            .unwrap();
        assert!(!helper.status().lockdown);
        assert_eq!(calls.disabled.load(Ordering::Acquire), 1);
    }

    #[test]
    fn lockdown_is_refused_where_the_system_has_none_but_can_still_be_lifted() {
        let calls = Arc::new(Calls::default());
        calls.unprotected.store(true, Ordering::Release);
        let helper = lockdown_helper(&calls);
        let caller = Caller::fake(b"admin", true);
        let error = helper
            .set_lockdown_as(&caller, true, false, false)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtectionUnavailable);
        assert!(calls.enabled.lock().unwrap().is_empty());
        helper
            .set_lockdown_as(&caller, false, false, false)
            .unwrap();
        assert_eq!(calls.disabled(), 1);
    }

    #[test]
    fn the_reason_for_a_missing_kill_switch_is_kept_for_the_refusal() {
        let calls = Arc::new(Calls::default());
        calls.unprotected.store(true, Ordering::Release);
        let helper = lockdown_helper(&calls);
        assert_eq!(
            helper.protection_unavailable.as_deref(),
            Some("no cgroup of its own")
        );
        let protected = lockdown_helper(&Arc::new(Calls::default()));
        assert_eq!(protected.protection_unavailable, None);
    }

    #[test]
    fn a_normal_stop_releases_what_only_a_crash_may_leave() {
        let calls = Calls::held();
        let helper = held_helper(&calls);
        assert!(helper.status().upgrade_hold);
        helper.shutdown();
        assert_eq!(calls.released_on_stop.load(Ordering::Acquire), 1);
    }

    #[test]
    fn a_stop_for_an_upgrade_keeps_protection_only_with_the_marker() {
        let folder =
            std::env::temp_dir().join(format!("rosetun-upgrade-marker-{}", std::process::id()));
        std::fs::create_dir_all(&folder).unwrap();
        let marker = folder.join("upgrading");
        let _ = std::fs::remove_file(&marker);

        let without = Calls::held();
        held_helper(&without)
            .with_upgrade_marker(marker.clone())
            .shutdown();
        assert_eq!(without.kept_on_stop.load(Ordering::Acquire), 0);

        std::fs::write(&marker, b"").unwrap();
        let with = Calls::held();
        held_helper(&with)
            .with_upgrade_marker(marker.clone())
            .shutdown();
        assert_eq!(with.kept_on_stop.load(Ordering::Acquire), 1);

        std::fs::remove_dir_all(folder).unwrap();
    }

    #[test]
    fn service_start_repairs_an_installed_lockdown_with_its_lan_setting() {
        let calls = Arc::new(Calls::default());
        *calls.installed.lock().unwrap() = Some(LockdownStatus {
            enabled: true,
            complete: false,
            allow_lan: true,
            private_networks: false,
            sublayer_weight: None,
            upgrade_hold: false,
        });
        let helper = lockdown_helper(&calls);
        helper.restore_lockdown();
        assert!(helper.status().lockdown);
        assert_eq!(*calls.enabled.lock().unwrap(), [true]);

        let calls = Arc::new(Calls::default());
        let helper = lockdown_helper(&calls);
        helper.restore_lockdown();
        assert!(!helper.status().lockdown);
        assert!(calls.enabled.lock().unwrap().is_empty());
    }

    #[test]
    fn failed_removal_moves_the_session_back_above_the_block() {
        let calls = Arc::new(Calls::default());
        let helper = lockdown_helper(&calls);
        let caller = Caller::fake(b"admin", true);
        helper.set_lockdown_as(&caller, true, false, false).unwrap();
        let moves = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&moves);
        helper.session.lock().unwrap().guard = Some(Guard {
            routing: Arc::new(Mutex::new(RoutingGuard::new_with_lockdown(
                move |lockdown| {
                    recorded.lock().unwrap().push(lockdown);
                    Ok(())
                },
            ))),
            scope: ProtectionScope::AllTraffic,
        });
        calls.fail_disable.store(true, Ordering::Release);

        let error = helper
            .set_lockdown_as(&caller, false, false, false)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::RoutingFailed);
        assert_eq!(*moves.lock().unwrap(), [false, true]);
        assert!(helper.status().lockdown);
    }

    #[test]
    fn lockdown_turned_on_during_a_session_permits_the_programs_only_after_it() {
        let calls = Arc::new(Calls::default());
        let helper = lockdown_helper(&calls);
        let caller = Caller::fake(b"admin", true);
        helper.session.lock().unwrap().guard = Some(Guard {
            routing: Arc::new(Mutex::new(RoutingGuard::new_with_lockdown(|_| Ok(())))),
            scope: ProtectionScope::AllTraffic,
        });

        helper.set_lockdown_as(&caller, true, false, false).unwrap();
        let during = calls.apps.lock().unwrap()[0].clone();
        assert_eq!((during.gui, during.cli), (None, None));
        assert!(during.service.is_some());

        helper.session.lock().unwrap().teardown();
        let after = calls.apps.lock().unwrap()[1].clone();
        assert_eq!(after, super::test_apps());
        assert!(!helper.session.lock().unwrap().programs_withdrawn);

        // Without Lockdown nothing comes back.
        helper.session.lock().unwrap().programs_withdrawn = true;
        helper
            .set_lockdown_as(&caller, false, false, false)
            .unwrap();
        helper.session.lock().unwrap().teardown();
        assert_eq!(calls.apps.lock().unwrap().len(), 2);
    }

    fn segment_around_servers(
        query: &rosetun_routing::lan::SegmentQuery<'_>,
    ) -> std::io::Result<rosetun_routing::lan::SegmentScan> {
        let prefix = rosetun_config::IpPrefix::new("192.0.2.0".parse().unwrap(), 24).unwrap();
        Ok(rosetun_routing::lan::SegmentScan {
            segment: rosetun_routing::lan::LanSegment::for_tests(&[prefix])
                .leaving_out(query.servers),
            skipped: Vec::new(),
        })
    }

    #[test]
    fn lockdowns_segment_leaves_out_the_sessions_servers_until_the_session_ends() {
        let calls = Arc::new(Calls::default());
        let helper = lockdown_helper(&calls).with_lan_scan(segment_around_servers);
        helper
            .set_lockdown_as(&Caller::fake(b"admin", true), true, true, false)
            .unwrap();
        let writes = || calls.left_out.lock().unwrap().clone();
        assert_eq!(writes(), [Vec::<std::net::IpAddr>::new()]);
        let (one, other) = ("192.0.2.10".parse().unwrap(), "192.0.2.20".parse().unwrap());

        let mut session = helper.session.lock().unwrap();
        session.follow_servers_in_lockdown(&[one]).unwrap();
        assert_eq!(writes().last().unwrap(), &[one]);
        session.follow_servers_in_lockdown(&[one]).unwrap();
        assert_eq!(writes().len(), 2, "the same server rewrites nothing");
        session.follow_servers_in_lockdown(&[other]).unwrap();
        assert_eq!(writes().last().unwrap(), &[other]);
        assert_eq!(writes().len(), 3);

        // A connect that failed before the session's filters: nothing was withdrawn.
        session.teardown();
        assert!(writes().last().unwrap().is_empty());
        assert_eq!(writes().len(), 4);

        // A session that ran: its end restores the programs and the whole segment.
        session.follow_servers_in_lockdown(&[one]).unwrap();
        session.programs_withdrawn = true;
        session.teardown();
        assert!(writes().last().unwrap().is_empty());
        assert!(session.lan_servers.is_empty());
        assert!(!session.programs_withdrawn);
    }

    #[test]
    fn a_server_behind_the_router_rewrites_lockdown_and_a_public_one_does_not() {
        let calls = Arc::new(Calls::default());
        let helper = lockdown_helper(&calls).with_lan_scan(segment_around_servers);
        helper
            .set_lockdown_as(&Caller::fake(b"admin", true), true, true, true)
            .unwrap();
        let writes = || calls.enabled.lock().unwrap().len();
        assert_eq!(writes(), 1);

        let mut session = helper.session.lock().unwrap();
        session
            .follow_servers_in_lockdown(&["203.0.113.5".parse().unwrap()])
            .unwrap();
        assert_eq!(writes(), 1);
        // Outside the segment, inside "Private networks behind the router".
        session
            .follow_servers_in_lockdown(&["10.1.2.3".parse().unwrap()])
            .unwrap();
        assert_eq!(writes(), 2);
        session
            .follow_servers_in_lockdown(&["10.1.2.3".parse().unwrap()])
            .unwrap();
        assert_eq!(writes(), 2);
    }

    #[test]
    fn without_lockdown_a_sessions_servers_write_nothing() {
        let calls = Arc::new(Calls::default());
        let helper = lockdown_helper(&calls).with_lan_scan(segment_around_servers);
        let server = "192.0.2.10".parse().unwrap();
        let mut session = helper.session.lock().unwrap();
        session.follow_servers_in_lockdown(&[server]).unwrap();
        assert_eq!(session.lan_servers, [server]);
        assert!(calls.left_out.lock().unwrap().is_empty());
    }

    #[test]
    fn set_lockdown_is_refused_during_another_operation() {
        let calls = Arc::new(Calls::default());
        let helper = lockdown_helper(&calls);
        let _session = helper.session.lock().unwrap();
        let error = helper
            .set_lockdown_as(&Caller::fake(b"admin", true), true, false, false)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Busy);
        assert!(calls.enabled.lock().unwrap().is_empty());
    }

    #[test]
    fn a_server_check_waits_for_the_session_before_asking_for_a_permit() {
        let calls = Arc::new(Calls::default());
        let helper = Arc::new(lockdown_helper(&calls));
        let worker = {
            let helper = Arc::clone(&helper);
            let (held_tx, held_rx) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                let _session = helper
                    .try_session(SessionHolder::Supervisor)
                    .expect("session is free");
                held_tx.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(100));
            });
            held_rx.recv().unwrap();
            worker
        };

        let permit = helper.lockdown_probe_routing(Path::new("engine.exe"));

        assert!(matches!(permit, Ok(None)), "Lockdown is off, no permit");
        worker.join().unwrap();

        let _held = helper
            .try_session(SessionHolder::Connect)
            .expect("session is free");
        let error = helper
            .lockdown_probe_routing(Path::new("engine.exe"))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Busy);
    }

    #[test]
    fn only_an_administrator_changes_lockdown() {
        let calls = Arc::new(Calls::default());
        let helper = lockdown_helper(&calls);
        let user = Caller::fake(b"user", false);
        let admin = Caller::fake(b"admin", true);

        let error = helper
            .set_lockdown_as(&user, true, false, false)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::AccessDenied);
        assert!(!helper.status().lockdown);
        assert!(calls.enabled.lock().unwrap().is_empty());

        helper.set_lockdown_as(&admin, true, false, false).unwrap();
        let error = helper
            .set_lockdown_as(&user, false, false, false)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::AccessDenied);
        assert!(helper.status().lockdown);
        assert_eq!(calls.disabled.load(Ordering::Acquire), 0);
    }

    #[test]
    fn a_connect_changes_lockdown_lan_access_only_for_an_administrator() {
        let calls = Arc::new(Calls::default());
        let routing = LockdownRouting(Arc::clone(&calls));
        let shared = super::SharedLockdown::default();
        super::write(
            &shared,
            super::LockdownState {
                enabled: true,
                allow_lan: false,
                private_networks: false,
                upgrade_hold: false,
            },
        );
        let apps = super::test_apps();

        super::sync_lan(
            &routing,
            &shared,
            &apps,
            &Caller::fake(b"user", false),
            Some(&rosetun_routing::lan::LanAccess::default()),
        )
        .unwrap();
        assert!(calls.enabled.lock().unwrap().is_empty());
        assert!(!super::read(&shared).allow_lan);

        super::sync_lan(
            &routing,
            &shared,
            &apps,
            &Caller::fake(b"admin", true),
            Some(&rosetun_routing::lan::LanAccess::default()),
        )
        .unwrap();
        assert_eq!(*calls.enabled.lock().unwrap(), [true]);
        assert!(super::read(&shared).allow_lan);
    }

    #[test]
    fn service_start_keeps_the_upgrade_hold_apart_from_lockdown() {
        let calls = Calls::held();
        let helper = held_helper(&calls);

        let status = helper.status();
        assert!(status.upgrade_hold);
        assert!(!status.lockdown);
        assert_eq!(calls.apps.lock().unwrap().clone(), [super::test_apps()]);
        assert_eq!(calls.disabled(), 0);
        assert_eq!(calls.hold_ended.load(Ordering::Acquire), 0);
    }

    #[test]
    fn open_network_lifts_the_hold_for_any_account_while_nothing_runs() {
        let calls = Calls::held();
        let helper = held_helper(&calls);

        helper
            .open_network_as(&Caller::fake(b"user", false))
            .unwrap();

        assert_eq!(calls.disabled(), 1);
        let status = helper.status();
        assert!(!status.upgrade_hold);
        assert!(!status.lockdown);
        helper
            .open_network_as(&Caller::fake(b"user", false))
            .unwrap();
        assert_eq!(calls.disabled(), 1, "nothing left to lift");
    }

    #[test]
    fn open_network_belongs_to_the_session_owner_or_an_administrator() {
        let calls = Calls::held();
        let helper = held_helper(&calls);
        *helper.owner.lock().unwrap() = Some(AccountIdentity::WindowsSid(b"owner".to_vec()));

        let error = helper
            .open_network_as(&Caller::fake(b"other", false))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::AccessDenied);
        assert_eq!(calls.disabled(), 0);
        assert!(helper.status().upgrade_hold);

        helper
            .open_network_as(&Caller::fake(b"owner", false))
            .unwrap();
        assert_eq!(calls.disabled(), 1);

        let calls = Calls::held();
        let helper = held_helper(&calls);
        *helper.owner.lock().unwrap() = Some(AccountIdentity::WindowsSid(b"owner".to_vec()));
        helper
            .open_network_as(&Caller::fake(b"admin", true))
            .unwrap();
        assert_eq!(calls.disabled(), 1);
    }

    #[test]
    fn the_hold_actions_leave_the_users_lockdown_alone() {
        let calls = Arc::new(Calls::default());
        let helper = lockdown_helper(&calls);
        let admin = Caller::fake(b"admin", true);
        helper.set_lockdown_as(&admin, true, false, false).unwrap();

        helper.open_network_as(&admin).unwrap();
        helper.disconnect_as(&admin).unwrap();

        assert_eq!(calls.disabled(), 0);
        assert_eq!(calls.hold_ended.load(Ordering::Acquire), 0);
        let status = helper.status();
        assert!(status.lockdown);
        assert!(!status.upgrade_hold);
    }

    #[test]
    fn lockdown_turned_on_during_the_hold_stays_when_the_hold_would_end() {
        let calls = Calls::held();
        let helper = held_helper(&calls);
        let admin = Caller::fake(b"admin", true);

        helper.set_lockdown_as(&admin, true, true, false).unwrap();
        assert_eq!(calls.hold_ended.load(Ordering::Acquire), 1);
        let status = helper.status();
        assert!(status.lockdown);
        assert!(!status.upgrade_hold);

        helper.disconnect_as(&admin).unwrap();
        helper.open_network_as(&admin).unwrap();
        assert_eq!(calls.disabled(), 0);
        assert!(helper.status().lockdown);
    }

    #[test]
    fn turning_lockdown_off_during_the_hold_ends_both() {
        let calls = Calls::held();
        let helper = held_helper(&calls);

        helper
            .set_lockdown_as(&Caller::fake(b"admin", true), false, false, false)
            .unwrap();

        assert_eq!(calls.disabled(), 1);
        let status = helper.status();
        assert!(!status.lockdown);
        assert!(!status.upgrade_hold);
    }

    #[test]
    fn a_hold_removed_by_reset_firewall_is_gone_at_the_next_start() {
        let calls = Calls::held();
        // `--reset-firewall` removes Lockdown's objects, the marker with them,
        // while the service is stopped; it starts again afterwards.
        calls.installed.lock().unwrap().take();
        let helper = held_helper(&calls);

        let status = helper.status();
        assert!(!status.upgrade_hold);
        assert!(!status.lockdown);
        assert!(calls.enabled.lock().unwrap().is_empty());
    }
}
