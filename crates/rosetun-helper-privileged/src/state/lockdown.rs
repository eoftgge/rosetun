//! Lockdown in the service. The persistent WFP objects are the only record of
//! whether it is on; the service reads them at start and is the only writer
//! while it runs, so it keeps a copy instead of asking BFE on every request.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, TryLockError};

use rosetun_ipc::{ErrorCode, HelperError};
use rosetun_routing::{
    LockdownApps, ProtectionScope, RoutingBackend, RoutingError, RoutingGuard, RoutingPlan,
    TunnelInterface,
};

use super::{Caller, Guard, Helper, Session, StartMode};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct LockdownState {
    pub(super) enabled: bool,
    pub(super) allow_lan: bool,
}

pub(super) type SharedLockdown = Arc<Mutex<LockdownState>>;

pub(super) fn read(shared: &SharedLockdown) -> LockdownState {
    *shared.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn write(shared: &SharedLockdown, state: LockdownState) {
    *shared.lock().unwrap_or_else(|poison| poison.into_inner()) = state;
    shared.clear_poison();
}

/// Lockdown forces the kill switch: under its block a session without its
/// own permits in the Lockdown sublayer has no tunnel at all.
pub(super) fn protection_scope(
    mode: StartMode,
    kill_switch: bool,
    tunnel_dns: bool,
    lockdown: bool,
) -> Option<ProtectionScope> {
    if kill_switch || lockdown {
        return Some(ProtectionScope::AllTraffic);
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
    LockdownApps {
        gui: find("rosetun-gui.exe"),
        cli: find("rosetun.exe"),
        service: exe.and_then(|exe| std::fs::canonicalize(exe).ok()),
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
    ) -> Result<(), HelperError> {
        self.check_owner(caller)?;
        let mut session = self.session()?;
        self.check_owner(caller)?;
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
            session.enable_lockdown(allow_lan)
        } else {
            session.disable_lockdown()
        }
    }

    /// At service start: Lockdown is on if its provider exists. Repairs a
    /// partial set by adding what is missing; on any doubt the objects stay
    /// as they are, which keeps the machine closed rather than open.
    pub fn restore_lockdown(&self) {
        let session = self
            .session
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
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
            },
        );
        match session
            .routing
            .enable_lockdown(status.allow_lan, &lockdown_apps())
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

    /// For a server check while no session runs: a short permit for the
    /// check's engine in the Lockdown sublayer. With a session, its own
    /// permits already cover the engine.
    pub(super) fn lockdown_probe_routing(
        &self,
        engine: &Path,
    ) -> Result<Option<Arc<Mutex<RoutingGuard>>>, HelperError> {
        let mut session = match self.session.try_lock() {
            Ok(session) => session,
            Err(TryLockError::WouldBlock) => {
                return Err(HelperError::new(
                    ErrorCode::Busy,
                    "tunnel changes are in progress during server checks",
                ));
            }
            Err(TryLockError::Poisoned(_)) => {
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
    fn enable_lockdown(&mut self, allow_lan: bool) -> Result<(), HelperError> {
        let status = self
            .routing
            .enable_lockdown(allow_lan, &lockdown_apps())
            .map_err(routing_failed)?;
        write(
            &self.lockdown,
            LockdownState {
                enabled: true,
                allow_lan,
            },
        );
        tracing::info!(
            allow_lan,
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
            let (plan, tunnel) = all_traffic(&request)?;
            let binaries = self
                .protected_binaries
                .iter()
                .map(PathBuf::as_path)
                .collect::<Vec<_>>();
            let mut routing = self
                .routing
                .begin_protection(&plan, &binaries)
                .map_err(routing_failed)?;
            routing.authorize_tunnel(&tunnel).map_err(routing_failed)?;
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
                let (plan, tunnel) = all_traffic(&request)?;
                let binaries = self
                    .protected_binaries
                    .iter()
                    .map(PathBuf::as_path)
                    .collect::<Vec<_>>();
                routing
                    .prepare_reconnect(&plan, &binaries)
                    .map_err(routing_failed)?;
                routing.authorize_tunnel(&tunnel).map_err(routing_failed)?;
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
                        .unwrap_or_else(|poison| poison.into_inner())
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
        tracing::info!(removed, "Lockdown turned off");
        self.release_forced_kill_switch();
        Ok(())
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
        let tunnel_dns = self
            .engines
            .get(settings.engine)
            .is_some_and(|backend| backend.tunnel_dns_server(&settings.tun).is_some());
        if !tunnel_dns {
            if let Some(guard) = self.guard.take()
                && let Err(error) = guard
                    .routing
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
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

/// Updates the persistent LAN permits to what a connect asks for.
pub(super) fn sync_lan(
    routing: &dyn RoutingBackend,
    shared: &SharedLockdown,
    allow_lan: bool,
) -> Result<(), HelperError> {
    let state = read(shared);
    if !state.enabled || state.allow_lan == allow_lan {
        return Ok(());
    }
    routing
        .enable_lockdown(allow_lan, &lockdown_apps())
        .map_err(routing_failed)?;
    write(
        shared,
        LockdownState {
            enabled: true,
            allow_lan,
        },
    );
    tracing::info!(allow_lan, "Lockdown LAN access follows the connect request");
    Ok(())
}

fn all_traffic(
    request: &rosetun_ipc::ConnectRequest,
) -> Result<(RoutingPlan, TunnelInterface), HelperError> {
    let tunnel = TunnelInterface::try_from(&request.settings.tun).map_err(routing_failed)?;
    Ok((
        RoutingPlan {
            scope: ProtectionScope::AllTraffic,
            allow_lan: request.settings.allow_lan,
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
    use rosetun_routing::{
        LockdownApps, LockdownStatus, ProtectionScope, RoutingBackend, RoutingError, RoutingGuard,
        RoutingPlan,
    };

    use super::protection_scope;
    use crate::log_gate::VerboseGate;
    use crate::state::{Caller, Guard, Helper, StartMode};

    #[test]
    fn lockdown_forces_the_all_traffic_policy() {
        for mode in [StartMode::Fresh, StartMode::ProtectedReconnect] {
            for tunnel_dns in [false, true] {
                assert_eq!(
                    protection_scope(mode, false, tunnel_dns, true),
                    Some(ProtectionScope::AllTraffic)
                );
                assert_eq!(
                    protection_scope(mode, true, tunnel_dns, false),
                    Some(ProtectionScope::AllTraffic)
                );
            }
        }
        assert_eq!(
            protection_scope(StartMode::Fresh, false, true, false),
            Some(ProtectionScope::DnsOnly)
        );
        assert_eq!(
            protection_scope(StartMode::Fresh, false, false, false),
            None
        );
        assert_eq!(
            protection_scope(StartMode::ProtectedReconnect, false, false, false),
            Some(ProtectionScope::DnsOnly)
        );
    }

    #[derive(Debug, Default)]
    struct Calls {
        enabled: Mutex<Vec<bool>>,
        disabled: AtomicUsize,
        installed: Mutex<Option<LockdownStatus>>,
        fail_disable: std::sync::atomic::AtomicBool,
    }

    #[derive(Debug)]
    struct LockdownRouting(Arc<Calls>);

    impl RoutingBackend for LockdownRouting {
        fn name(&self) -> &'static str {
            "test-lockdown"
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

        fn lockdown_status(&self) -> Result<LockdownStatus, RoutingError> {
            Ok(self.0.installed.lock().unwrap().unwrap_or_default())
        }

        fn enable_lockdown(
            &self,
            allow_lan: bool,
            _apps: &LockdownApps,
        ) -> Result<LockdownStatus, RoutingError> {
            self.0.enabled.lock().unwrap().push(allow_lan);
            let status = LockdownStatus {
                enabled: true,
                complete: true,
                allow_lan,
                sublayer_weight: Some(0xD000),
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
        let caller = Caller::fake(b"user", false);
        assert!(!helper.status().lockdown);

        helper.set_lockdown_as(&caller, true, true).unwrap();
        assert!(helper.status().lockdown);
        helper.set_lockdown_as(&caller, true, false).unwrap();
        assert_eq!(*calls.enabled.lock().unwrap(), [true, false]);

        helper.set_lockdown_as(&caller, false, false).unwrap();
        assert!(!helper.status().lockdown);
        assert_eq!(calls.disabled.load(Ordering::Acquire), 1);
    }

    #[test]
    fn service_start_repairs_an_installed_lockdown_with_its_lan_setting() {
        let calls = Arc::new(Calls::default());
        *calls.installed.lock().unwrap() = Some(LockdownStatus {
            enabled: true,
            complete: false,
            allow_lan: true,
            sublayer_weight: None,
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
        let caller = Caller::fake(b"user", false);
        helper.set_lockdown_as(&caller, true, false).unwrap();
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

        let error = helper.set_lockdown_as(&caller, false, false).unwrap_err();
        assert_eq!(error.code, ErrorCode::RoutingFailed);
        assert_eq!(*moves.lock().unwrap(), [false, true]);
        assert!(helper.status().lockdown);
    }

    #[test]
    fn set_lockdown_is_refused_during_another_operation() {
        let calls = Arc::new(Calls::default());
        let helper = lockdown_helper(&calls);
        let _session = helper.session.lock().unwrap();
        let error = helper
            .set_lockdown_as(&Caller::fake(b"user", false), true, false)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Busy);
        assert!(calls.enabled.lock().unwrap().is_empty());
    }
}
