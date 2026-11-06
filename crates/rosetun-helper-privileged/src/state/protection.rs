//! The routing protection a session holds: what installs it, changes its scope
//! and takes it off. `ProtectionRuntime::release` is the only place in the
//! service that takes it off.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rosetun_config::{
    ConnectionMode, InstalledProtection, ProtectionShortfallCode, ProtectionState,
    RequestedProtection, Settings,
};
use rosetun_ipc::{ConnectRequest, ErrorCode, HelperError};
use rosetun_routing::lan::LanAccess;
use rosetun_routing::{
    ProtectionScope, RoutingBackend, RoutingError, RoutingGuard, RoutingPlan, TunnelInterface,
};

use super::lockdown::LockdownState;
use super::{StartMode, local_proxy};

/// Routing protection that outlives one engine process.
struct Guard {
    routing: Arc<Mutex<RoutingGuard>>,
    scope: ProtectionScope,
}

/// What the status says about the session's protection. `Helper::status`
/// reads it without the session mutex, as it does Lockdown's state.
#[derive(Debug, Clone, Default)]
pub(super) struct ProtectionReport {
    scope: Option<ProtectionScope>,
    requested: RequestedProtection,
    shortfall: Option<ProtectionShortfallCode>,
    connection_mode: Option<ConnectionMode>,
}

pub(super) type SharedReport = Arc<Mutex<ProtectionReport>>;

impl ProtectionReport {
    pub(super) fn state(&self, lockdown: LockdownState) -> ProtectionState {
        let installed = match (lockdown.enabled, lockdown.upgrade_hold) {
            (true, true) if lockdown.hold_after_crash => InstalledProtection::HoldAfterCrash,
            (true, true) => InstalledProtection::HoldAfterUpgrade,
            (true, false) => InstalledProtection::Lockdown,
            (false, _) => match self.scope {
                None => InstalledProtection::None,
                Some(ProtectionScope::DnsOnly) => InstalledProtection::DnsLock,
                Some(ProtectionScope::SharedProxy) => InstalledProtection::SharedProxyPort,
                Some(ProtectionScope::AllTraffic) => InstalledProtection::KillSwitch,
            },
        };
        ProtectionState {
            installed,
            requested: self.requested,
            shortfall: self.shortfall.map(Into::into),
            connection_mode: self.connection_mode,
            survives_service_crash: survives_service_crash(installed),
        }
    }
}

/// A kill switch's table outlives the service on Linux. On Windows its filters
/// belong to the service's dynamic firewall session and go with it, on purpose:
/// a crash does not leave the computer offline. Lockdown and the holds are
/// persistent on both.
fn survives_service_crash(installed: InstalledProtection) -> bool {
    match installed {
        InstalledProtection::None
        | InstalledProtection::DnsLock
        | InstalledProtection::SharedProxyPort => false,
        InstalledProtection::KillSwitch => cfg!(target_os = "linux"),
        InstalledProtection::Lockdown
        | InstalledProtection::HoldAfterUpgrade
        | InstalledProtection::HoldAfterCrash => true,
    }
}

/// What these settings ask for. The proxy mode has no DNS to lock: without a
/// kill switch it asks for nothing.
fn requested_by(settings: &Settings) -> RequestedProtection {
    if settings.kill_switch {
        RequestedProtection::KillSwitch
    } else if settings.connection_mode == ConnectionMode::Tun {
        RequestedProtection::DnsLock
    } else {
        RequestedProtection::None
    }
}

/// A DNS lock that could not go in, by what the firewall answered.
pub(super) fn shortfall_of(error: &RoutingError) -> ProtectionShortfallCode {
    if error.is_unavailable() {
        ProtectionShortfallCode::FirewallUnavailable
    } else {
        ProtectionShortfallCode::FirewallRefused
    }
}

pub(super) struct ProtectionRuntime {
    report: SharedReport,
    guard: Option<Guard>,
    /// Lockdown's GUI and CLI permits are removed because the session's
    /// filters sit in its sublayer; a teardown puts them back.
    programs_withdrawn: bool,
    /// The engine binaries the current protection permits, for changing its
    /// scope when Lockdown is turned on or off.
    binaries: Vec<PathBuf>,
}

impl ProtectionRuntime {
    pub(super) fn new(report: SharedReport) -> Self {
        Self {
            report,
            guard: None,
            programs_withdrawn: false,
            binaries: Vec::new(),
        }
    }

    fn change_report(&self, change: impl FnOnce(&mut ProtectionReport)) {
        change(
            &mut self
                .report
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        self.report.clear_poison();
    }

    fn report_scope(&self) {
        let scope = self.scope();
        self.change_report(|report| report.scope = scope);
    }

    /// A start with these settings: earlier failures no longer count.
    pub(super) fn begin_attempt(&self, settings: &Settings) {
        self.change_report(|report| {
            report.requested = requested_by(settings);
            report.shortfall = None;
            report.connection_mode = Some(settings.connection_mode);
        });
    }

    /// Requested protection did not go in, and the session goes on without it.
    pub(super) fn record_shortfall(&self, code: ProtectionShortfallCode) {
        self.change_report(|report| report.shortfall = Some(code));
    }

    /// The session is over: nothing is asked for any more.
    pub(super) fn session_over(&self) {
        let scope = self.scope();
        self.change_report(|report| {
            *report = ProtectionReport {
                scope,
                ..ProtectionReport::default()
            };
        });
    }

    pub(super) fn is_active(&self) -> bool {
        self.guard.is_some()
    }

    pub(super) fn scope(&self) -> Option<ProtectionScope> {
        self.guard.as_ref().map(|guard| guard.scope)
    }

    /// Only the kill switch keeps blocking after a failure. The DNS lock goes
    /// with the session.
    pub(super) fn keeps_protection(&self) -> bool {
        self.scope() == Some(ProtectionScope::AllTraffic)
    }

    /// A restart under this protection cannot use system DNS, so any guard
    /// makes it a protected reconnect.
    pub(super) fn restart_mode(&self) -> StartMode {
        if self.is_active() {
            StartMode::ProtectedReconnect
        } else {
            StartMode::Fresh
        }
    }

    /// For a short permit of a server check's engine, which never reverts.
    pub(super) fn routing(&self) -> Option<Arc<Mutex<RoutingGuard>>> {
        self.guard.as_ref().map(|guard| Arc::clone(&guard.routing))
    }

    pub(super) fn programs_withdrawn(&self) -> bool {
        self.programs_withdrawn
    }

    pub(super) fn withdraw_programs(&mut self) {
        self.programs_withdrawn = true;
    }

    pub(super) fn programs_restored(&mut self) {
        self.programs_withdrawn = false;
    }

    pub(super) fn permit_binaries(&mut self, binaries: &[&Path]) {
        self.binaries = binaries.iter().map(|path| path.to_path_buf()).collect();
    }

    fn binaries(&self) -> Vec<&Path> {
        self.binaries.iter().map(PathBuf::as_path).collect()
    }

    /// Takes the protection off. `failure` is what the log says if that fails.
    pub(super) fn release(&mut self, failure: &'static str) {
        if let Some(guard) = self.guard.take()
            && let Err(error) = guard
                .routing
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .revert_in_place()
        {
            tracing::error!(%error, "{failure}");
        }
        self.report_scope();
    }

    /// A fresh start: outbound protection goes up before the engine spawns.
    pub(super) fn install(
        &mut self,
        backend: &mut dyn RoutingBackend,
        plan: &RoutingPlan,
    ) -> Result<(), RoutingError> {
        backend.preflight()?;
        let routing = backend.begin_protection(plan, &self.binaries())?;
        self.guard = Some(Guard {
            routing: Arc::new(Mutex::new(routing)),
            scope: plan.scope,
        });
        // The same transaction removed Lockdown's GUI and CLI permits.
        self.programs_withdrawn |= plan.lockdown;
        self.report_scope();
        Ok(())
    }

    /// A protected reconnect: the standing guard takes the new plan.
    pub(super) fn prepare_reconnect(&mut self, plan: &RoutingPlan) -> Result<(), HelperError> {
        let binaries = self
            .binaries
            .iter()
            .map(PathBuf::as_path)
            .collect::<Vec<_>>();
        let guard = self
            .guard
            .as_mut()
            .expect("protected reconnect validated the guard");
        guard
            .routing
            .lock()
            .map_err(|_| poisoned())?
            .prepare_reconnect(plan, &binaries)
            .map_err(routing_failed)?;
        guard.scope = plan.scope;
        self.programs_withdrawn |= plan.lockdown;
        self.report_scope();
        Ok(())
    }

    /// Phase two: the tunnel's identity exists only now.
    pub(super) fn authorize_tunnel(&self, tunnel: &TunnelInterface) -> Result<(), RoutingError> {
        let guard = self
            .guard
            .as_ref()
            .ok_or_else(|| RoutingError::Route("routing protection is not active".to_owned()))?;
        guard
            .routing
            .lock()
            .map_err(|_| RoutingError::Route("routing guard is poisoned".to_owned()))?
            .authorize_tunnel(tunnel)
    }

    /// Turning Lockdown on: a session's filters move above its block, and a
    /// session without a kill switch gets the one it now needs.
    pub(super) fn cover_with_lockdown(
        &mut self,
        backend: &mut dyn RoutingBackend,
        request: Option<&ConnectRequest>,
        lan: &LanAccess,
        state: &LockdownState,
    ) -> Result<(), HelperError> {
        let binaries = self
            .binaries
            .iter()
            .map(PathBuf::as_path)
            .collect::<Vec<_>>();
        let Some(guard) = self.guard.as_mut() else {
            let Some(request) = request else {
                return Ok(());
            };
            let (plan, tunnel) = all_traffic(request, lan, state)?;
            let mut routing = backend
                .begin_protection(&plan, &binaries)
                .map_err(routing_failed)?;
            if let Some(tunnel) = tunnel.as_ref() {
                routing.authorize_tunnel(tunnel).map_err(routing_failed)?;
            }
            self.guard = Some(Guard {
                routing: Arc::new(Mutex::new(routing)),
                scope: ProtectionScope::AllTraffic,
            });
            self.report_scope();
            tracing::info!("Lockdown is on: the kill switch is forced on for this session");
            return Ok(());
        };
        let mut routing = guard.routing.lock().map_err(|_| poisoned())?;
        match (guard.scope, request) {
            (ProtectionScope::DnsOnly | ProtectionScope::SharedProxy, Some(request)) => {
                let (plan, tunnel) = all_traffic(request, lan, state)?;
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
        drop(routing);
        self.report_scope();
        Ok(())
    }

    /// The session's filters move back to the Rosetun sublayer first, so
    /// removing the Lockdown sublayer does not fail with FWP_E_IN_USE.
    pub(super) fn leave_lockdown(&self) -> Result<(), HelperError> {
        if let Some(guard) = self.guard.as_ref() {
            guard
                .routing
                .lock()
                .map_err(|_| poisoned())?
                .set_lockdown(false)
                .map_err(routing_failed)?;
        }
        Ok(())
    }

    /// The persistent block stays; without its permits back above it the
    /// session would be "connected" with no network.
    pub(super) fn return_to_lockdown(&self) {
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
    }

    /// Lockdown forced the kill switch on a session whose settings have it
    /// off; give it the protection it would have had, or a protected
    /// reconnect would refuse to narrow it.
    pub(super) fn release_forced_kill_switch(
        &mut self,
        settings: &Settings,
        tunnel_dns: bool,
        lan: &LanAccess,
    ) {
        if settings.kill_switch || !self.keeps_protection() {
            return;
        }
        let tunnel = settings.connection_mode == ConnectionMode::Tun;
        let shared_proxy = local_proxy::shared_port(settings, &LockdownState::default());
        let scope = protection_scope(
            StartMode::Fresh,
            false,
            tunnel && tunnel_dns,
            false,
            !tunnel,
            shared_proxy.is_some(),
        );
        let Some(scope) = scope else {
            self.release("failed to remove the forced kill switch");
            tracing::info!("kill switch released with Lockdown");
            return;
        };
        let plan = RoutingPlan {
            scope,
            allow_lan: settings.allow_lan,
            lan: if shared_proxy.is_some() {
                lan.clone()
            } else {
                Default::default()
            },
            lockdown: false,
            shared_proxy,
        };
        let adapter = if tunnel {
            match TunnelInterface::try_from(&settings.tun) {
                Ok(adapter) => Some(adapter),
                Err(error) => {
                    tracing::warn!(%error, "the kill switch stays on until the next connect");
                    return;
                }
            }
        } else {
            None
        };
        let binaries = self
            .binaries
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
                match adapter.as_ref() {
                    Some(adapter) => routing.authorize_tunnel(adapter),
                    None => Ok(()),
                }
            });
        match result {
            Ok(()) => {
                guard.scope = scope;
                self.report_scope();
                tracing::info!(?scope, "kill switch released with Lockdown");
            }
            Err(error) => {
                tracing::warn!(%error, "the kill switch stays on until the next connect");
            }
        }
    }

    #[cfg(test)]
    pub(super) fn install_for_test(&mut self, routing: RoutingGuard, scope: ProtectionScope) {
        self.guard = Some(Guard {
            routing: Arc::new(Mutex::new(routing)),
            scope,
        });
        self.report_scope();
    }
}

/// Lockdown forces the kill switch: under its block a session without its
/// own permits in the Lockdown sublayer has no tunnel at all.
pub(super) fn protection_scope(
    mode: StartMode,
    kill_switch: bool,
    tunnel_dns: bool,
    lockdown: bool,
    local_proxy: bool,
    shared_proxy: bool,
) -> Option<ProtectionScope> {
    if kill_switch || lockdown {
        return Some(ProtectionScope::AllTraffic);
    }
    // The engine resolves names itself, so there is no system DNS to confine:
    // a program that goes around the proxy goes around all of it, and that
    // is what this mode without the kill switch says it does. Only Windows
    // limits a shared port this way; Linux listens on its private addresses
    // alone, and has no filter to keep up without a kill switch.
    if local_proxy {
        return (shared_proxy && cfg!(windows)).then_some(ProtectionScope::SharedProxy);
    }
    match mode {
        StartMode::Fresh => tunnel_dns.then_some(ProtectionScope::DnsOnly),
        // The guard stays; only the kill switch may widen it.
        StartMode::ProtectedReconnect => Some(ProtectionScope::DnsOnly),
    }
}

/// The plan of a kill switch forced on a running session, and the adapter to
/// authorize, which the proxy mode does not have.
fn all_traffic(
    request: &ConnectRequest,
    lan: &LanAccess,
    state: &LockdownState,
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
            shared_proxy: local_proxy::shared_port(&request.settings, state),
        },
        tunnel,
    ))
}

fn routing_failed(error: RoutingError) -> HelperError {
    HelperError::new(ErrorCode::RoutingFailed, error.to_string())
}

fn poisoned() -> HelperError {
    HelperError::new(ErrorCode::RoutingFailed, "routing guard is poisoned")
}
