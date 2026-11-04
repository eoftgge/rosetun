//! Kill switch and DNS lock on nftables (Linux).
//!
//! Engines are told apart by cgroup: the helper starts them in the `engines`
//! leaf of its systemd unit (`crate::cgroup`), and the table permits that
//! leaf. Without the unit's leaves there is no protection at all, because
//! any other cgroup (a terminal session's) would open the network to
//! everything in it.
//!
//! Unlike a dynamic WFP session the table outlives the helper. A crash
//! therefore leaves the network closed, and the next start finds the table
//! with no session: the hold after a crash. The service reports it as the
//! upgrade hold (`LockdownStatus::upgrade_hold`) and lifts it the same way,
//! on a connect, on `OpenNetwork` or on a normal stop. Lockdown itself is
//! not offered on Linux.

mod nft;
mod physical;
mod tunnel;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::cgroup::{self, Leaves};
use crate::nftables::{self, InterfaceName, Rules};
use crate::{
    LockdownApps, LockdownStatus, ProtectionCapabilities, ProtectionScope, ProtectionSession,
    RoutingBackend, RoutingError, RoutingGuard, RoutingPlan, TunnelInterface,
};

use self::nft::{Nft, SystemNft};

pub(super) use self::physical::physical_default_interface;

/// Why there is no protection when the helper does not run as the unit.
pub(super) const NOT_THE_SERVICE: &str =
    "the helper does not run as rosetun-helper.service, so its engines have no cgroup of their own";

#[derive(Debug, Default)]
struct Shared {
    /// A session's table is in place.
    session: bool,
    /// The table was found at start with no session: a crash left it.
    hold: bool,
}

#[derive(Debug)]
pub(super) struct NftBackend {
    nft: Arc<dyn Nft>,
    leaves: Result<Leaves, String>,
    mount: PathBuf,
    shared: Arc<Mutex<Shared>>,
}

impl NftBackend {
    pub(super) fn new(leaves: Result<Leaves, String>) -> Self {
        Self::with(Arc::new(SystemNft), leaves, PathBuf::from(cgroup::MOUNT))
    }

    fn with(nft: Arc<dyn Nft>, leaves: Result<Leaves, String>, mount: PathBuf) -> Self {
        Self {
            nft,
            leaves,
            mount,
            shared: Arc::default(),
        }
    }

    fn shared(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn leaves(&self) -> Result<&Leaves, RoutingError> {
        self.leaves
            .as_ref()
            .map_err(|reason| RoutingError::Unavailable(reason.clone()))
    }

    fn hold_status(hold: bool) -> LockdownStatus {
        LockdownStatus {
            enabled: hold,
            complete: hold,
            allow_lan: false,
            sublayer_weight: None,
            upgrade_hold: hold,
        }
    }
}

/// The hold: the kill switch's first phase without "Local network", plus
/// DNS for the helper so a connect can resolve its server.
fn hold_rules(leaves: &Leaves) -> String {
    nftables::replace(&Rules {
        scope: ProtectionScope::AllTraffic,
        allow_lan: false,
        engines: &leaves.engines,
        helper_dns: Some(&leaves.helper),
        tunnel: None,
    })
}

/// Every condition the rules rely on, with the reason for the first that
/// fails: the unit's leaves, cgroup v2 at the mount point, the engines' leaf
/// in place, and an nft binary only root can change.
fn preflight(
    nft: &dyn Nft,
    leaves: &Result<Leaves, String>,
    mount: &Path,
) -> Result<(), RoutingError> {
    let leaves = leaves
        .as_ref()
        .map_err(|reason| RoutingError::Unavailable(reason.clone()))?;
    if !mount.join("cgroup.controllers").is_file() {
        return Err(RoutingError::Unavailable(format!(
            "cgroup v2 is not mounted at {}",
            mount.display()
        )));
    }
    if !leaves.engines.under(mount).is_dir() {
        return Err(RoutingError::Unavailable(
            "the engines' cgroup does not exist".to_owned(),
        ));
    }
    nft.check().map_err(RoutingError::Unavailable)
}

impl RoutingBackend for NftBackend {
    fn name(&self) -> &'static str {
        "linux-nftables"
    }

    fn capabilities(&self) -> ProtectionCapabilities {
        ProtectionCapabilities {
            kill_switch: self.preflight().is_ok(),
            lockdown: false,
        }
    }

    fn unavailable_reason(&self) -> Option<String> {
        self.preflight().err().map(|error| error.to_string())
    }

    fn preflight(&self) -> Result<(), RoutingError> {
        preflight(self.nft.as_ref(), &self.leaves, &self.mount)
    }

    /// The engine binaries are not needed: the engines' cgroup identifies
    /// them, whatever file they run from.
    fn begin_protection(
        &mut self,
        plan: &RoutingPlan,
        _engine_binaries: &[&Path],
    ) -> Result<RoutingGuard, RoutingError> {
        self.preflight()?;
        let leaves = self.leaves()?.clone();
        let mut shared = self.shared();
        if shared.session {
            return Err(RoutingError::Route(
                "routing protection is already active".to_owned(),
            ));
        }
        // Replaces the hold's table, if there is one, in the same
        // transaction: there is no moment without rules.
        self.nft.apply(&nftables::replace(&Rules {
            scope: plan.scope,
            allow_lan: plan.allow_lan,
            engines: &leaves.engines,
            helper_dns: None,
            tunnel: None,
        }))?;
        shared.session = true;
        drop(shared);
        Ok(RoutingGuard::from_session(NftSession {
            nft: Arc::clone(&self.nft),
            shared: Arc::clone(&self.shared),
            leaves,
            scope: plan.scope,
            allow_lan: plan.allow_lan,
            tunnel: None,
            armed: true,
        }))
    }

    /// Finds a table no session of this process made: a crash left it.
    fn lockdown_status(&self) -> Result<LockdownStatus, RoutingError> {
        let mut shared = self.shared();
        if !shared.session && !shared.hold {
            if self.nft.check().is_err() {
                return Ok(LockdownStatus::default());
            }
            if previous_exit(self.nft.table_exists()?) == PreviousExit::Crashed {
                tracing::warn!("a table left by a crashed helper keeps the network closed");
                shared.hold = true;
            }
        }
        Ok(Self::hold_status(shared.hold))
    }

    /// Only for the hold: puts the hold's own rules in place of whatever the
    /// crashed session left, so the engines' and the helper's permits match
    /// the cgroups of this start. Lockdown cannot be turned on here.
    fn enable_lockdown(
        &self,
        _allow_lan: bool,
        _apps: &LockdownApps,
    ) -> Result<LockdownStatus, RoutingError> {
        let shared = self.shared();
        if !shared.hold {
            return Err(RoutingError::Unsupported);
        }
        if !shared.session {
            self.nft.apply(&hold_rules(self.leaves()?))?;
        }
        Ok(Self::hold_status(true))
    }

    /// Lifts the hold. With a session in place its own table stays.
    fn disable_lockdown(&self) -> Result<bool, RoutingError> {
        let mut shared = self.shared();
        if !shared.hold {
            return Ok(false);
        }
        if !shared.session {
            self.nft.apply(&nftables::remove())?;
        }
        shared.hold = false;
        Ok(true)
    }

    /// Server checks during the hold: the engines' leaf is permitted
    /// already.
    fn permit_in_lockdown(&mut self, _binaries: &[&Path]) -> Result<RoutingGuard, RoutingError> {
        if self.shared().hold {
            Ok(RoutingGuard::noop())
        } else {
            Err(RoutingError::Unsupported)
        }
    }

    fn release_on_stop(&self) -> Result<(), RoutingError> {
        self.disable_lockdown().map(drop)
    }
}

#[derive(Debug)]
struct NftSession {
    nft: Arc<dyn Nft>,
    shared: Arc<Mutex<Shared>>,
    leaves: Leaves,
    scope: ProtectionScope,
    allow_lan: bool,
    tunnel: Option<InterfaceName>,
    armed: bool,
}

impl NftSession {
    fn rules(
        &self,
        scope: ProtectionScope,
        allow_lan: bool,
        tunnel: Option<&InterfaceName>,
    ) -> String {
        nftables::replace(&Rules {
            scope,
            allow_lan,
            engines: &self.leaves.engines,
            helper_dns: None,
            tunnel,
        })
    }

    fn require_armed(&self) -> Result<(), RoutingError> {
        if self.armed {
            Ok(())
        } else {
            Err(RoutingError::Route(
                "routing protection is not active".to_owned(),
            ))
        }
    }
}

impl ProtectionSession for NftSession {
    /// One transaction from the old rules to the new phase 1: the stale
    /// tunnel permit goes and the new plan comes at the same moment.
    fn prepare_reconnect(
        &mut self,
        plan: &RoutingPlan,
        _engine_binaries: &[&Path],
    ) -> Result<(), RoutingError> {
        self.require_armed()?;
        self.nft
            .apply(&self.rules(plan.scope, plan.allow_lan, None))?;
        self.scope = plan.scope;
        self.allow_lan = plan.allow_lan;
        self.tunnel = None;
        Ok(())
    }

    fn authorize_tunnel(&mut self, tunnel: &TunnelInterface) -> Result<(), RoutingError> {
        self.require_armed()?;
        let name = InterfaceName::new(&tunnel.alias)?;
        tunnel::check(&name, tunnel.ipv4)?;
        if self.tunnel.as_ref() == Some(&name) {
            return Ok(());
        }
        self.nft
            .apply(&self.rules(self.scope, self.allow_lan, Some(&name)))?;
        self.tunnel = Some(name);
        Ok(())
    }

    fn permit_probe_binary(&mut self, _binary: &Path) -> Result<(), RoutingError> {
        Ok(())
    }

    fn remove_probe_binary(&mut self, _binary: &Path) -> Result<(), RoutingError> {
        Ok(())
    }

    /// There is no separate Lockdown layer on Linux.
    fn set_lockdown(&mut self, _lockdown: bool) -> Result<(), RoutingError> {
        Ok(())
    }

    /// Removes the table, or puts the hold back while one is in force. On
    /// an error the old rules stay: closed, not open.
    fn teardown(&mut self) -> Result<(), RoutingError> {
        if !self.armed {
            return Ok(());
        }
        self.armed = false;
        let mut shared = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        shared.session = false;
        let script = if shared.hold {
            hold_rules(&self.leaves)
        } else {
            nftables::remove()
        };
        self.nft.apply(&script)
    }
}

/// What a start found: a table with no session in this process means the
/// previous one did not tear down, which only a crash (or a kill) skips.
/// A normal stop removes the table before the process exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PreviousExit {
    Clean,
    Crashed,
}

pub(super) fn previous_exit(table_present: bool) -> PreviousExit {
    if table_present {
        PreviousExit::Crashed
    } else {
        PreviousExit::Clean
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::cgroup::CgroupPath;

    #[derive(Debug, Default)]
    struct FakeNft {
        unusable: Option<String>,
        table: Mutex<bool>,
        applied: Mutex<Vec<String>>,
        fail_next: Mutex<bool>,
    }

    impl FakeNft {
        fn applied(&self) -> Vec<String> {
            self.applied.lock().unwrap().clone()
        }
    }

    impl Nft for FakeNft {
        fn check(&self) -> Result<(), String> {
            self.unusable.clone().map_or(Ok(()), Err)
        }

        fn apply(&self, script: &str) -> Result<(), RoutingError> {
            if std::mem::take(&mut *self.fail_next.lock().unwrap()) {
                return Err(RoutingError::Route("nft failed".to_owned()));
            }
            self.applied.lock().unwrap().push(script.to_owned());
            *self.table.lock().unwrap() = script.contains("table inet rosetun {");
            Ok(())
        }

        fn table_exists(&self) -> Result<bool, RoutingError> {
            Ok(*self.table.lock().unwrap())
        }
    }

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Mount(PathBuf);

    impl Mount {
        /// A cgroup v2 mount with the unit's leaves, or without the leaves.
        fn new(with_leaves: bool) -> Self {
            let path = std::env::temp_dir().join(format!(
                "rosetun-cgroup-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join("cgroup.controllers"), "cpu memory pids\n").unwrap();
            if with_leaves {
                std::fs::create_dir_all(leaves().engines.under(&path)).unwrap();
                std::fs::create_dir_all(leaves().helper.under(&path)).unwrap();
            }
            Self(path)
        }
    }

    impl Drop for Mount {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn leaves() -> Leaves {
        Leaves::of(&CgroupPath::parse("/system.slice/rosetun-helper.service").unwrap()).unwrap()
    }

    fn backend(nft: &Arc<FakeNft>, mount: &Mount) -> NftBackend {
        NftBackend::with(
            Arc::clone(nft) as Arc<dyn Nft>,
            Ok(leaves()),
            mount.0.clone(),
        )
    }

    fn plan(scope: ProtectionScope) -> RoutingPlan {
        RoutingPlan {
            scope,
            allow_lan: false,
            lockdown: false,
        }
    }

    #[test]
    fn protection_is_offered_only_when_every_condition_holds() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let ready = backend(&nft, &mount);
        assert!(ready.capabilities().kill_switch);
        assert!(!ready.capabilities().lockdown);
        assert_eq!(ready.unavailable_reason(), None);

        let outside = NftBackend::with(
            Arc::clone(&nft) as Arc<dyn Nft>,
            Err(NOT_THE_SERVICE.to_owned()),
            mount.0.clone(),
        );
        assert!(!outside.capabilities().kill_switch);
        assert!(
            outside
                .unavailable_reason()
                .unwrap()
                .contains("rosetun-helper.service")
        );

        let bare = Mount::new(false);
        let no_leaves = backend(&nft, &bare);
        assert!(
            no_leaves
                .unavailable_reason()
                .unwrap()
                .contains("engines' cgroup")
        );

        let no_v2 = Mount::new(true);
        std::fs::remove_file(no_v2.0.join("cgroup.controllers")).unwrap();
        assert!(
            backend(&nft, &no_v2)
                .unavailable_reason()
                .unwrap()
                .contains("cgroup v2")
        );

        let foreign = Arc::new(FakeNft {
            unusable: Some("/usr/sbin/nft is not a regular file owned by root alone".to_owned()),
            ..FakeNft::default()
        });
        assert!(!backend(&foreign, &mount).capabilities().kill_switch);
    }

    #[test]
    fn without_the_units_leaves_nothing_is_installed() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let mut outside = NftBackend::with(
            Arc::clone(&nft) as Arc<dyn Nft>,
            Err(NOT_THE_SERVICE.to_owned()),
            mount.0.clone(),
        );
        assert!(matches!(
            outside.begin_protection(&plan(ProtectionScope::AllTraffic), &[]),
            Err(RoutingError::Unavailable(_))
        ));
        assert!(nft.applied().is_empty());
    }

    #[test]
    fn a_session_installs_phase_one_and_removes_the_table_on_teardown() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let mut backend = backend(&nft, &mount);
        let guard = backend
            .begin_protection(&plan(ProtectionScope::AllTraffic), &[])
            .unwrap();
        assert!(nft.applied()[0].contains("policy drop;"));
        assert!(
            backend
                .begin_protection(&plan(ProtectionScope::AllTraffic), &[])
                .is_err()
        );
        guard.revert().unwrap();
        assert_eq!(nft.applied().last().unwrap(), &nftables::remove());
        assert!(!*nft.table.lock().unwrap());
    }

    #[test]
    fn a_reconnect_changes_the_rules_in_one_transaction() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let mut backend = backend(&nft, &mount);
        let mut guard = backend
            .begin_protection(&plan(ProtectionScope::DnsOnly), &[])
            .unwrap();
        let before = nft.applied().len();
        guard
            .prepare_reconnect(&plan(ProtectionScope::AllTraffic), &[])
            .unwrap();
        let applied = nft.applied();
        assert_eq!(applied.len(), before + 1, "exactly one transaction");
        let script = applied.last().unwrap();
        // Replace in place: never a bare removal, which would open the network.
        assert!(script.starts_with(&nftables::remove()));
        assert!(script.contains("policy drop;"));
        assert!(!script.contains("oif \"rosetun"));
        assert!(*nft.table.lock().unwrap());
    }

    #[test]
    fn a_failed_reconnect_keeps_the_rules_it_had() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let mut backend = backend(&nft, &mount);
        let mut guard = backend
            .begin_protection(&plan(ProtectionScope::AllTraffic), &[])
            .unwrap();
        *nft.fail_next.lock().unwrap() = true;
        assert!(
            guard
                .prepare_reconnect(&plan(ProtectionScope::DnsOnly), &[])
                .is_err()
        );
        assert!(nft.applied().last().unwrap().contains("policy drop;"));
    }

    #[test]
    fn a_tunnel_that_is_not_there_is_not_authorized() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let mut backend = backend(&nft, &mount);
        let mut guard = backend
            .begin_protection(&plan(ProtectionScope::AllTraffic), &[])
            .unwrap();
        let before = nft.applied().len();
        let missing = TunnelInterface {
            alias: "rosetun-none".to_owned(),
            ipv4: Ipv4Addr::new(192, 0, 2, 1),
        };
        assert!(
            guard
                .authorize_tunnel(&missing)
                .unwrap_err()
                .is_tunnel_not_ready()
        );
        let unsafe_name = TunnelInterface {
            alias: "tun\"0".to_owned(),
            ipv4: Ipv4Addr::new(192, 0, 2, 1),
        };
        assert!(matches!(
            guard.authorize_tunnel(&unsafe_name),
            Err(RoutingError::Tun { .. })
        ));
        assert_eq!(nft.applied().len(), before);
    }

    #[test]
    fn an_existing_interface_is_authorized_once() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let mut backend = backend(&nft, &mount);
        let mut guard = backend
            .begin_protection(&plan(ProtectionScope::AllTraffic), &[])
            .unwrap();
        // Loopback stands in for the TUN: it exists, is up and has its address.
        let lo = TunnelInterface {
            alias: "lo".to_owned(),
            ipv4: Ipv4Addr::LOCALHOST,
        };
        guard.authorize_tunnel(&lo).unwrap();
        let count = nft.applied().len();
        assert!(
            nft.applied()
                .last()
                .unwrap()
                .contains("\t\toif \"lo\" accept\n\t\toif \"lo\" accept")
        );
        guard.authorize_tunnel(&lo).unwrap();
        assert_eq!(nft.applied().len(), count);
    }

    #[test]
    fn a_table_found_at_start_is_the_hold_after_a_crash() {
        let nft = Arc::new(FakeNft::default());
        *nft.table.lock().unwrap() = true;
        let mount = Mount::new(true);
        let backend = backend(&nft, &mount);
        assert_eq!(previous_exit(true), PreviousExit::Crashed);
        assert_eq!(previous_exit(false), PreviousExit::Clean);
        let status = backend.lockdown_status().unwrap();
        assert!(status.enabled && status.upgrade_hold);
        // The service "repairs" it: the hold's own rules replace the leftovers.
        backend
            .enable_lockdown(false, &LockdownApps::default())
            .unwrap();
        let script = nft.applied().last().unwrap().clone();
        assert_eq!(script, hold_rules(&leaves()));
        assert!(script.contains("/helper\" meta l4proto { tcp, udp } th dport 53 accept"));
    }

    #[test]
    fn a_clean_start_has_no_hold_and_refuses_lockdown() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let mut backend = backend(&nft, &mount);
        assert!(!backend.lockdown_status().unwrap().enabled);
        assert!(matches!(
            backend.enable_lockdown(false, &LockdownApps::default()),
            Err(RoutingError::Unsupported)
        ));
        assert!(!backend.disable_lockdown().unwrap());
        assert!(backend.permit_in_lockdown(&[]).is_err());
        backend.release_on_stop().unwrap();
        assert!(nft.applied().is_empty());
    }

    #[test]
    fn opening_the_network_removes_the_hold() {
        let nft = Arc::new(FakeNft::default());
        *nft.table.lock().unwrap() = true;
        let mount = Mount::new(true);
        let backend = backend(&nft, &mount);
        backend.lockdown_status().unwrap();
        assert!(backend.disable_lockdown().unwrap());
        assert_eq!(nft.applied().last().unwrap(), &nftables::remove());
        assert!(!backend.lockdown_status().unwrap().enabled);
    }

    #[test]
    fn a_normal_stop_removes_the_hold() {
        let nft = Arc::new(FakeNft::default());
        *nft.table.lock().unwrap() = true;
        let mount = Mount::new(true);
        let backend = backend(&nft, &mount);
        backend.lockdown_status().unwrap();
        backend.release_on_stop().unwrap();
        assert!(!*nft.table.lock().unwrap());
    }

    #[test]
    fn a_failed_connect_during_the_hold_puts_the_hold_back() {
        let nft = Arc::new(FakeNft::default());
        *nft.table.lock().unwrap() = true;
        let mount = Mount::new(true);
        let mut backend = backend(&nft, &mount);
        backend.lockdown_status().unwrap();
        let guard = backend
            .begin_protection(&plan(ProtectionScope::AllTraffic), &[])
            .unwrap();
        guard.revert().unwrap();
        assert_eq!(nft.applied().last().unwrap(), &hold_rules(&leaves()));
        assert!(*nft.table.lock().unwrap());
    }

    #[test]
    fn a_connect_lifts_the_hold_without_removing_its_own_table() {
        let nft = Arc::new(FakeNft::default());
        *nft.table.lock().unwrap() = true;
        let mount = Mount::new(true);
        let mut backend = backend(&nft, &mount);
        backend.lockdown_status().unwrap();
        let guard = backend
            .begin_protection(&plan(ProtectionScope::AllTraffic), &[])
            .unwrap();
        let count = nft.applied().len();
        // Connected: the service lifts the hold; the session's table stays.
        assert!(backend.disable_lockdown().unwrap());
        assert_eq!(nft.applied().len(), count);
        assert!(backend.permit_in_lockdown(&[]).is_err());
        // A later disconnect removes the table for good.
        guard.revert().unwrap();
        assert_eq!(nft.applied().last().unwrap(), &nftables::remove());
    }

    #[test]
    fn teardown_runs_once() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let mut backend = backend(&nft, &mount);
        let mut guard = backend
            .begin_protection(&plan(ProtectionScope::AllTraffic), &[])
            .unwrap();
        guard.revert_in_place().unwrap();
        let count = nft.applied().len();
        guard.revert_in_place().unwrap();
        drop(guard);
        assert_eq!(nft.applied().len(), count);
    }
}
