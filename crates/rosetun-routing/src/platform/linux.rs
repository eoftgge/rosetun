//! Kill switch, DNS lock and Lockdown on nftables (Linux).
//!
//! Engines are told apart by cgroup: the helper starts them in the `engines`
//! leaf of its systemd unit (`crate::cgroup`), and the table permits that
//! leaf. Without the unit's leaves there is no protection at all, because
//! any other cgroup (a terminal session's) would open the network to
//! everything in it.
//!
//! One table holds everything, written whole from `Shared` on every change
//! in one transaction: the session's rules, the hold after a crash, and
//! Lockdown. nftables turns a cgroup path into the cgroup's ID when a rule
//! is loaded, so a rule names the cgroup that existed at that moment. When
//! systemd makes the unit's cgroup again (a restart after a crash), the old
//! table's permits name cgroups that are gone and match nothing: the
//! network stays closed until the new helper writes the table again with
//! its own leaves, which it does at start (the hold's or Lockdown's rules).
//!
//! Unlike a dynamic WFP session the table outlives the helper, and the next
//! start finds it with no session. Without Lockdown, a kill switch's table
//! becomes the hold after a crash: the network stays closed, the service
//! reports it as the upgrade hold (`LockdownStatus::upgrade_hold`) and
//! lifts it the same way, on a connect, on `OpenNetwork` or on a normal
//! stop. A DNS lock's table is removed: the user never asked for a closed
//! network. A table that is neither is held, as closed is the safe guess.
//!
//! Lockdown is recorded in a root-only file (`state`), since the table is
//! gone after a reboot. `rosetun-lockdown.service` writes Lockdown's set at
//! boot from it, before any network, without cgroups (the service's leaves
//! do not exist yet); the service adds the engines', its own and the
//! programs' permits at start. A normal stop leaves Lockdown's table.

pub(super) mod connected;
mod nft;
mod physical;
mod programs;
pub(super) mod segment;
mod state;
mod tunnel;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::cgroup::{self, CgroupPath, Leaves};
use crate::lan::LanAccess;
use crate::nftables::{self, InterfaceName, LeftBehind, Lockdown, Rules};
use crate::{
    BootRestore, FirewallReset, LockdownApps, LockdownStatus, ProtectionCapabilities,
    ProtectionCheck, ProtectionScope, ProtectionSession, RoutingBackend, RoutingError,
    RoutingGuard, RoutingPlan, TunnelInterface,
};

use self::nft::{Nft, SystemNft};
use self::programs::{CLI_SCOPE, GUI_SCOPE, Membership, Program};
use self::state::{Saved, Stored};

pub(super) use self::nft::ruleset_json;
pub(super) use self::physical::physical_default_interface;

/// Why there is no protection when the helper does not run as the unit.
pub(super) const NOT_THE_SERVICE: &str =
    "the helper does not run as rosetun-helper.service, so its engines have no cgroup of their own";
/// The unit that writes Lockdown's set at boot.
const LOCKDOWN_UNIT: &str = "rosetun-lockdown.service";
/// Where `systemctl enable` puts the unit's link (`WantedBy=sysinit.target`),
/// for an administrator and for a package.
const UNIT_WANTS: [&str; 2] = [
    "/etc/systemd/system/sysinit.target.wants",
    "/usr/lib/systemd/system/sysinit.target.wants",
];

/// Lockdown as the service runs it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LockdownRules {
    allow_lan: bool,
    private_networks: bool,
    /// The GUI's and the CLI's scopes are permitted while no session runs.
    gui: bool,
    cli: bool,
}

impl LockdownRules {
    fn saved(self) -> Saved {
        Saved {
            allow_lan: self.allow_lan,
            private_networks: self.private_networks,
        }
    }
}

#[derive(Debug, Clone)]
struct SessionRules {
    scope: ProtectionScope,
    allow_lan: bool,
    /// What "Local network" opens for the session; only with `allow_lan`.
    lan: LanAccess,
    tunnel: Option<InterfaceName>,
}

impl SessionRules {
    fn of(plan: &RoutingPlan, tunnel: Option<InterfaceName>) -> Self {
        Self {
            scope: plan.scope,
            allow_lan: plan.allow_lan,
            lan: plan.lan.clone(),
            tunnel,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Shared {
    session: Option<SessionRules>,
    /// The table was found at start with no session and no Lockdown: a
    /// crash left it. Never together with `lockdown`.
    hold: bool,
    lockdown: Option<LockdownRules>,
    /// What Lockdown's own "Local network" opens, as the service last wrote
    /// it; only with `LockdownRules::allow_lan`. Empty after a reboot, until
    /// the service has read the networks.
    lockdown_lan: LanAccess,
    /// During the hold: the Lockdown an administrator turned on, which the
    /// hold becomes when it ends that way (`end_upgrade_hold`).
    requested: Option<LockdownRules>,
    requested_lan: LanAccess,
    /// The record was read; from then on the service is its only writer.
    loaded: bool,
    /// The programs' scopes found by the last scan.
    programs: Vec<Program>,
    /// The service stops for an upgrade: the table stays as it is.
    frozen: bool,
    /// The previous service left word that it stopped for an upgrade.
    stopped_for_upgrade: bool,
    /// The table as `nft` listed it right after this service wrote it. Read
    /// back rather than compared with the script: `nft` prints rules in its
    /// own words. The text itself, not a hash: it is a few kilobytes, and an
    /// equal text is the proof a hash would only stand for.
    written: Option<String>,
}

impl Shared {
    /// This service's state calls for a table.
    fn expects_table(&self) -> bool {
        self.session.is_some() || self.lockdown.is_some() || self.hold
    }
}

/// Where the backend looks; fixed outside tests.
#[derive(Debug, Clone)]
struct Paths {
    mount: PathBuf,
    record: PathBuf,
    upgrade_stop: PathBuf,
    wants: Vec<PathBuf>,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            mount: PathBuf::from(cgroup::MOUNT),
            record: PathBuf::from(state::STATE_FILE),
            upgrade_stop: PathBuf::from(state::UPGRADE_STOP_FILE),
            wants: UNIT_WANTS.iter().map(PathBuf::from).collect(),
        }
    }
}

/// What the backend and its sessions share: the state and the means to
/// write the table for it.
#[derive(Clone)]
struct Table {
    nft: Arc<dyn Nft>,
    shared: Arc<Mutex<Shared>>,
    leaves: Option<Leaves>,
    paths: Paths,
    member: Arc<Membership>,
}

impl std::fmt::Debug for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Table")
            .field("leaves", &self.leaves)
            .field("paths", &self.paths)
            .finish_non_exhaustive()
    }
}

impl Table {
    fn lock(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Changes the state and writes the table for it in one transaction.
    /// On an error both stay as they were: the old rules, closed.
    fn change(
        &self,
        shared: &mut Shared,
        change: impl FnOnce(&mut Shared),
    ) -> Result<(), RoutingError> {
        if shared.frozen {
            return Ok(());
        }
        let mut next = shared.clone();
        change(&mut next);
        self.scan_programs(&mut next);
        if let Err(error) = self.nft.apply(&render(&next, self.leaves.as_ref())) {
            // A scope may have gone between the scan and the load, which
            // fails the whole transaction: once more with a fresh scan.
            if next.programs.is_empty() {
                return Err(error);
            }
            next.programs = self.scan();
            self.nft.apply(&render(&next, self.leaves.as_ref()))?;
        }
        next.written = self.read_back(&next);
        *shared = next;
        Ok(())
    }

    fn read_back(&self, shared: &Shared) -> Option<String> {
        if !shared.expects_table() {
            return None;
        }
        match self.nft.list_table() {
            Ok(listing) => listing.as_deref().map(nftables::normalized),
            // The next check finds no match and writes the table again.
            Err(error) => {
                tracing::warn!(%error, "could not read back the table just written");
                None
            }
        }
    }

    /// Scans the scopes only when Lockdown would permit them now.
    fn scan_programs(&self, next: &mut Shared) {
        if programs_permitted(next).is_some() {
            next.programs = self.scan();
        }
    }

    fn scan(&self) -> Vec<Program> {
        programs::scan(&self.paths.mount, &[GUI_SCOPE, CLI_SCOPE], &*self.member)
    }

    fn write_record(&self, saved: Saved) -> Result<(), RoutingError> {
        state::write(&self.paths.record, saved).map_err(|error| {
            RoutingError::Route(format!("cannot write the Lockdown record: {error}"))
        })
    }

    fn remove_record(&self) -> Result<bool, RoutingError> {
        state::remove(&self.paths.record).map_err(|error| {
            RoutingError::Route(format!("cannot remove the Lockdown record: {error}"))
        })
    }

    /// Puts the record back as it was before a change that failed: the
    /// record must say what the kernel has.
    fn restore_record(&self, before: Option<LockdownRules>) {
        let result = match before {
            Some(lockdown) => state::write(&self.paths.record, lockdown.saved()),
            None => state::remove(&self.paths.record).map(drop),
        };
        if let Err(error) = result {
            tracing::error!(%error, "could not put the Lockdown record back");
        }
    }
}

/// Lockdown's rules when the programs' scopes count: Lockdown is on, no
/// session runs, and the GUI or the CLI is permitted.
fn programs_permitted(shared: &Shared) -> Option<LockdownRules> {
    shared
        .lockdown
        .filter(|lockdown| shared.session.is_none() && (lockdown.gui || lockdown.cli))
}

/// The table for `shared`. `leaves` is `None` only outside the unit, where
/// no session can run: Lockdown then gets its set without cgroups, as at
/// boot.
fn render(shared: &Shared, leaves: Option<&Leaves>) -> String {
    let programs: Vec<CgroupPath> = programs_permitted(shared)
        .map(|lockdown| {
            shared
                .programs
                .iter()
                .filter(|program| match program.path.last() {
                    Some(GUI_SCOPE) => lockdown.gui,
                    Some(CLI_SCOPE) => lockdown.cli,
                    _ => false,
                })
                .map(|program| program.path.clone())
                .collect()
        })
        .unwrap_or_default();
    let session = shared.session.as_ref();
    let lockdown = shared.lockdown.map(|lockdown| Lockdown {
        lan: lockdown.allow_lan,
        session: session.is_some(),
        helper: leaves.map(|leaves| &leaves.helper),
        programs: &programs,
    });
    if lockdown.is_none() && session.is_none() {
        return if shared.hold {
            hold_rules(leaves)
        } else {
            nftables::remove()
        };
    }
    let lan = lan_access(shared);
    nftables::replace(&Rules {
        scope: session.map_or(ProtectionScope::AllTraffic, |session| session.scope),
        allow_lan: session.is_some_and(|session| session.allow_lan),
        lan: Some(&lan),
        engines: leaves.map(|leaves| &leaves.engines),
        hold: None,
        tunnel: session.and_then(|session| session.tunnel.as_ref()),
        lockdown,
    })
}

/// What "Local network" opens now. The session's own access, which knows its
/// servers, when it has one; otherwise Lockdown's. Lockdown's "Private
/// networks behind the router" holds whatever the session asked for.
fn lan_access(shared: &Shared) -> LanAccess {
    let lockdown = shared.lockdown.filter(|lockdown| lockdown.allow_lan);
    let mut access = match shared.session.as_ref().filter(|session| session.allow_lan) {
        Some(session) => session.lan.clone(),
        None => shared.lockdown_lan.clone(),
    };
    if let Some(lockdown) = lockdown {
        access.private_networks |= lockdown.private_networks;
    }
    access
}

/// The hold: the kill switch's first phase without "Local network" and with
/// nothing forwarded, plus DNS for the helper so a connect can resolve its
/// server.
fn hold_rules(leaves: Option<&Leaves>) -> String {
    nftables::replace(&Rules {
        scope: ProtectionScope::AllTraffic,
        allow_lan: false,
        lan: None,
        engines: leaves.map(|leaves| &leaves.engines),
        hold: leaves.map(|leaves| &leaves.helper),
        tunnel: None,
        lockdown: None,
    })
}

/// Lockdown's set at boot: no cgroup exists yet that a rule could name, and
/// no network either, so no segment to open. With "Private networks behind
/// the router" the private ranges are open, as the user chose; the segment
/// and the link-local networks follow once the service has read them, which
/// it does within seconds of starting.
fn boot_rules(saved: Saved) -> String {
    let lan = LanAccess {
        private_networks: saved.private_networks,
        ..LanAccess::default()
    };
    nftables::replace(&Rules {
        scope: ProtectionScope::AllTraffic,
        allow_lan: false,
        lan: Some(&lan),
        engines: None,
        hold: None,
        tunnel: None,
        lockdown: Some(Lockdown {
            lan: saved.allow_lan,
            session: false,
            helper: None,
            programs: &[],
        }),
    })
}

#[derive(Debug)]
pub(super) struct NftBackend {
    table: Table,
    leaves: Result<Leaves, String>,
}

impl NftBackend {
    pub(super) fn new(leaves: Result<Leaves, String>) -> Self {
        Self::with(
            Arc::new(SystemNft),
            leaves,
            Paths::default(),
            Arc::new(programs::in_rosetun_group),
        )
    }

    fn with(
        nft: Arc<dyn Nft>,
        leaves: Result<Leaves, String>,
        paths: Paths,
        member: Arc<Membership>,
    ) -> Self {
        Self {
            table: Table {
                nft,
                shared: Arc::default(),
                leaves: leaves.as_ref().ok().cloned(),
                paths,
                member,
            },
            leaves,
        }
    }

    fn shared(&self) -> MutexGuard<'_, Shared> {
        self.table.lock()
    }

    fn hold_status(hold: bool, after_crash: bool) -> LockdownStatus {
        LockdownStatus {
            hold_after_crash: hold && after_crash,
            enabled: hold,
            complete: hold,
            allow_lan: false,
            private_networks: false,
            sublayer_weight: None,
            upgrade_hold: hold,
        }
    }

    /// Lockdown survives a reboot only through the boot unit, so it is
    /// offered only while the unit is enabled: a link to it in a
    /// `sysinit.target.wants` folder that leads to a file.
    fn lockdown_unit_enabled(&self) -> bool {
        self.table
            .paths
            .wants
            .iter()
            .any(|folder| folder.join(LOCKDOWN_UNIT).is_file())
    }

    /// Reads the record once, at the first status the service asks for.
    fn load(&self, shared: &mut Shared) {
        if shared.loaded {
            return;
        }
        shared.loaded = true;
        shared.stopped_for_upgrade = state::take_upgrade_stop(&self.table.paths.upgrade_stop);
        let stored = state::read(&self.table.paths.record);
        if let Stored::Corrupt(reason) = &stored {
            tracing::error!(
                reason,
                "the Lockdown record cannot be trusted; Lockdown stays on without the local network"
            );
        }
        shared.lockdown = stored.lockdown().map(|saved| LockdownRules {
            allow_lan: saved.allow_lan,
            private_networks: saved.private_networks,
            gui: false,
            cli: false,
        });
    }

    /// Finds a table no session of this process made, with no Lockdown: a
    /// crash (or a kill) skipped its teardown, as a normal stop removes it
    /// before the process exits. A DNS lock's table goes; any other becomes
    /// the hold.
    fn find_left_behind(&self, shared: &mut Shared) -> Result<(), RoutingError> {
        let nft = &self.table.nft;
        if nft.check().is_err() {
            return Ok(());
        }
        if let Some(listing) = nft.list_table()? {
            match nftables::left_behind(&listing) {
                LeftBehind::DnsLock => {
                    nft.apply(&nftables::remove())?;
                    tracing::warn!(
                        "removed the DNS lock a crashed helper left; the network is open"
                    );
                }
                LeftBehind::KillSwitch => {
                    tracing::warn!("a table left by a crashed helper keeps the network closed");
                    shared.hold = true;
                }
                LeftBehind::Unknown => {
                    tracing::warn!(
                        "a table left by a crashed helper is not recognised; it keeps the network closed"
                    );
                    shared.hold = true;
                }
            }
        }
        Ok(())
    }
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
        let kill_switch = self.preflight().is_ok();
        ProtectionCapabilities {
            kill_switch,
            lockdown: kill_switch && self.lockdown_unit_enabled(),
        }
    }

    fn unavailable_reason(&self) -> Option<String> {
        self.preflight().err().map(|error| error.to_string())
    }

    fn preflight(&self) -> Result<(), RoutingError> {
        preflight(
            self.table.nft.as_ref(),
            &self.leaves,
            &self.table.paths.mount,
        )
    }

    /// The engine binaries are not needed: the engines' cgroup identifies
    /// them, whatever file they run from.
    fn begin_protection(
        &mut self,
        plan: &RoutingPlan,
        _engine_binaries: &[&Path],
    ) -> Result<RoutingGuard, RoutingError> {
        self.preflight()?;
        let table = self.table.clone();
        let mut shared = table.lock();
        if shared.session.is_some() {
            return Err(RoutingError::Route(
                "routing protection is already active".to_owned(),
            ));
        }
        // Replaces the hold's or Lockdown's table, if there is one, in the
        // same transaction: there is no moment without rules. Under
        // Lockdown the programs' permits go with it, as on Windows.
        table.change(&mut shared, |next| {
            next.session = Some(SessionRules::of(plan, None));
            if plan.lockdown
                && let Some(lockdown) = next.lockdown.as_mut()
            {
                lockdown.gui = false;
                lockdown.cli = false;
            }
        })?;
        drop(shared);
        Ok(RoutingGuard::from_session(NftSession {
            table,
            armed: true,
        }))
    }

    /// `Table::change` writes the whole table from the state in one
    /// transaction, so whatever happened to it, one write puts it right. A
    /// table of this name while none is expected is not this service's, and
    /// another table never counts.
    fn verify_protection(&self) -> Result<ProtectionCheck, RoutingError> {
        let mut shared = self.shared();
        if shared.frozen || !shared.loaded || !shared.expects_table() {
            return Ok(ProtectionCheck::Intact);
        }
        let listing = self.table.nft.list_table()?;
        let listing = listing.as_deref().map(nftables::normalized);
        if listing.is_some() && listing == shared.written {
            return Ok(ProtectionCheck::Intact);
        }
        let missing = listing.is_none();
        self.table.change(&mut shared, |_| {})?;
        tracing::warn!(
            missing,
            "another program changed the table; it is back in place"
        );
        Ok(ProtectionCheck::Restored)
    }

    /// Lockdown when its record says so; otherwise a table left by a crash
    /// is looked for.
    fn lockdown_status(&self) -> Result<LockdownStatus, RoutingError> {
        let mut shared = self.shared();
        self.load(&mut shared);
        if shared.lockdown.is_none() && shared.session.is_none() && !shared.hold {
            self.find_left_behind(&mut shared)?;
        }
        Ok(match shared.lockdown {
            Some(lockdown) => LockdownStatus {
                enabled: true,
                complete: matches!(self.table.nft.list_table(), Ok(Some(_))),
                allow_lan: lockdown.allow_lan,
                private_networks: lockdown.private_networks,
                sublayer_weight: None,
                upgrade_hold: false,
                hold_after_crash: false,
            },
            None => Self::hold_status(shared.hold, !shared.stopped_for_upgrade),
        })
    }

    /// Writes the record, then the table: Lockdown with the engines', the
    /// helper's and (without a session) the programs' permits of this
    /// start. During the hold it only puts the hold's own rules in place of
    /// whatever the crashed session left, and keeps what was asked for
    /// until the hold ends.
    fn enable_lockdown(
        &self,
        lan: Option<&crate::lan::LanAccess>,
        apps: &LockdownApps,
    ) -> Result<LockdownStatus, RoutingError> {
        let wanted = LockdownRules {
            allow_lan: lan.is_some(),
            private_networks: lan.is_some_and(|lan| lan.private_networks),
            gui: apps.gui.is_some(),
            cli: apps.cli.is_some(),
        };
        let mut shared = self.shared();
        let wanted_lan = lan.cloned().unwrap_or_default();
        if shared.hold && shared.lockdown.is_none() {
            shared.requested = Some(wanted);
            shared.requested_lan = wanted_lan;
            if shared.session.is_none() {
                self.table
                    .nft
                    .apply(&hold_rules(self.table.leaves.as_ref()))?;
                shared.written = self.table.read_back(&shared);
            }
            return Ok(Self::hold_status(true, !shared.stopped_for_upgrade));
        }
        self.preflight()?;
        let before = shared.lockdown;
        // Always, so a record found corrupt at start is replaced.
        self.table.write_record(wanted.saved())?;
        if let Err(error) = self.table.change(&mut shared, |next| {
            next.lockdown = Some(wanted);
            next.lockdown_lan = wanted_lan;
            next.requested = None;
            next.requested_lan = LanAccess::default();
        }) {
            self.table.restore_record(before);
            return Err(error);
        }
        Ok(LockdownStatus {
            enabled: true,
            complete: true,
            allow_lan: wanted.allow_lan,
            private_networks: wanted.private_networks,
            sublayer_weight: None,
            upgrade_hold: false,
            hold_after_crash: false,
        })
    }

    /// Lockdown: the record goes first, then its rules (a session keeps
    /// its own). Without Lockdown it lifts the hold.
    fn disable_lockdown(&self) -> Result<bool, RoutingError> {
        let mut shared = self.shared();
        if let Some(before) = shared.lockdown {
            self.table.remove_record()?;
            if let Err(error) = self.table.change(&mut shared, |next| {
                next.lockdown = None;
                next.lockdown_lan = LanAccess::default();
                next.hold = false;
                next.requested = None;
                next.requested_lan = LanAccess::default();
            }) {
                self.table.restore_record(Some(before));
                return Err(error);
            }
            return Ok(true);
        }
        if !shared.hold {
            return Ok(false);
        }
        if shared.session.is_none() {
            self.table.nft.apply(&nftables::remove())?;
        }
        shared.hold = false;
        shared.requested = None;
        shared.requested_lan = LanAccess::default();
        Ok(true)
    }

    /// The hold becomes the Lockdown an administrator turned on during it.
    fn end_upgrade_hold(&self) -> Result<(), RoutingError> {
        let mut shared = self.shared();
        if !shared.hold {
            return Ok(());
        }
        let wanted = shared.requested.unwrap_or_default();
        let wanted_lan = shared.requested_lan.clone();
        self.table.write_record(wanted.saved())?;
        if let Err(error) = self.table.change(&mut shared, |next| {
            next.hold = false;
            next.lockdown = Some(wanted);
            next.lockdown_lan = wanted_lan;
            next.requested = None;
            next.requested_lan = LanAccess::default();
        }) {
            self.table.restore_record(None);
            return Err(error);
        }
        Ok(())
    }

    /// Server checks under Lockdown or during the hold: the engines' leaf
    /// is permitted already.
    fn permit_in_lockdown(&mut self, _binaries: &[&Path]) -> Result<RoutingGuard, RoutingError> {
        let shared = self.shared();
        if shared.hold || shared.lockdown.is_some() {
            Ok(RoutingGuard::noop())
        } else {
            Err(RoutingError::Unsupported)
        }
    }

    /// The scopes the GUI and the CLI run in come and go; a client asks for
    /// this when it connects, so a program that has just made its scope
    /// finds it permitted.
    fn refresh_lockdown_programs(&self) -> Result<(), RoutingError> {
        let mut shared = self.shared();
        if programs_permitted(&shared).is_none() {
            return Ok(());
        }
        let found = self.table.scan();
        if found == shared.programs {
            return Ok(());
        }
        self.table.change(&mut shared, |_| {})
    }

    fn keep_protection_on_stop(&self) {
        self.shared().frozen = true;
        // The marker in /run goes with the unit, so the next service would
        // take this hold for a crash's.
        state::leave_upgrade_stop(&self.table.paths.upgrade_stop);
    }

    /// Lifts the hold. Lockdown stays: a stopped service leaves the network
    /// closed.
    fn release_on_stop(&self) -> Result<(), RoutingError> {
        let shared = self.shared();
        if shared.lockdown.is_some() || shared.frozen {
            return Ok(());
        }
        drop(shared);
        self.disable_lockdown().map(drop)
    }
}

#[derive(Debug)]
struct NftSession {
    table: Table,
    armed: bool,
}

impl NftSession {
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
        let mut shared = self.table.lock();
        self.table.change(&mut shared, |next| {
            next.session = Some(SessionRules::of(plan, None));
        })
    }

    fn authorize_tunnel(&mut self, tunnel: &TunnelInterface) -> Result<(), RoutingError> {
        self.require_armed()?;
        let name = InterfaceName::new(&tunnel.alias)?;
        tunnel::check(&name, tunnel.ipv4)?;
        let mut shared = self.table.lock();
        let Some(session) = shared.session.as_ref() else {
            return Err(RoutingError::Route(
                "routing protection is not active".to_owned(),
            ));
        };
        if session.tunnel.as_ref() == Some(&name) {
            return Ok(());
        }
        self.table.change(&mut shared, |next| {
            if let Some(session) = next.session.as_mut() {
                session.tunnel = Some(name);
            }
        })
    }

    fn permit_probe_binary(&mut self, _binary: &Path) -> Result<(), RoutingError> {
        Ok(())
    }

    fn remove_probe_binary(&mut self, _binary: &Path) -> Result<(), RoutingError> {
        Ok(())
    }

    /// Lockdown is part of the one table: turning it on or off writes the
    /// session's rules with it or without it already.
    fn set_lockdown(&mut self, _lockdown: bool) -> Result<(), RoutingError> {
        Ok(())
    }

    /// Writes the table without the session: Lockdown's rules, the hold
    /// while one is in force, or none. On an error the old rules stay,
    /// closed, and the next change writes the table again.
    fn teardown(&mut self) -> Result<(), RoutingError> {
        if !self.armed {
            return Ok(());
        }
        self.armed = false;
        let mut shared = self.table.lock();
        let result = self.table.change(&mut shared, |next| next.session = None);
        shared.session = None;
        result
    }
}

/// `rosetun-lockdown.service`: Lockdown's set from the record, before any
/// network and without the service. A table already there is left alone:
/// at boot there is none, so it is the service's.
pub(super) fn restore_at_boot() -> Result<BootRestore, RoutingError> {
    restore_from(&SystemNft, Path::new(state::STATE_FILE))
}

/// Without a record nothing runs, not even `nft`: Lockdown is off.
fn restore_from(nft: &dyn Nft, record: &Path) -> Result<BootRestore, RoutingError> {
    let stored = state::read(record);
    let Some(saved) = stored.lockdown() else {
        return Ok(BootRestore::Off);
    };
    nft.check().map_err(RoutingError::Unavailable)?;
    if nft.list_table()?.is_some() {
        return Ok(BootRestore::AlreadyInPlace);
    }
    nft.apply(&boot_rules(saved))?;
    Ok(match stored {
        Stored::Corrupt(reason) => BootRestore::Corrupt { reason },
        _ => BootRestore::On {
            allow_lan: saved.allow_lan,
        },
    })
}

/// `reset-firewall`: the table goes first, which opens the network, then
/// the record, so Lockdown does not come back at the next boot.
pub(super) fn reset_firewall() -> Result<FirewallReset, RoutingError> {
    let nft = SystemNft;
    nft.check().map_err(RoutingError::Unavailable)?;
    let table = nft.list_table()?.is_some();
    nft.apply(&nftables::remove())?;
    let record = state::remove(Path::new(state::STATE_FILE)).map_err(|error| {
        RoutingError::Route(format!("cannot remove the Lockdown record: {error}"))
    })?;
    Ok(FirewallReset { table, record })
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
        /// The table as `nft list table` prints it.
        table: Mutex<Option<String>>,
        applied: Mutex<Vec<String>>,
        fail_next: Mutex<bool>,
    }

    impl FakeNft {
        /// What a crashed session of `scope` left.
        fn left(scope: ProtectionScope) -> Arc<Self> {
            let nft = Arc::new(Self::default());
            let script = nftables::replace(&Rules {
                lan: None,
                scope,
                allow_lan: false,
                engines: Some(&leaves().engines),
                hold: None,
                tunnel: None,
                lockdown: None,
            });
            *nft.table.lock().unwrap() = Some(script[nftables::remove().len()..].to_owned());
            nft
        }

        fn applied(&self) -> Vec<String> {
            self.applied.lock().unwrap().clone()
        }

        fn has_table(&self) -> bool {
            self.table.lock().unwrap().is_some()
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
            *self.table.lock().unwrap() = script
                .find("table inet rosetun {")
                .map(|start| script[start..].to_owned());
            Ok(())
        }

        fn list_table(&self) -> Result<Option<String>, RoutingError> {
            Ok(self.table.lock().unwrap().clone())
        }
    }

    static NEXT: AtomicU64 = AtomicU64::new(0);

    /// A folder standing in for the system: `cgroup` is the cgroup v2
    /// mount, `lib` the service's state folder, `wants` the boot target's
    /// links.
    struct Mount(PathBuf);

    impl Mount {
        /// A cgroup v2 mount with the unit's leaves, or without the leaves.
        fn new(with_leaves: bool) -> Self {
            let mount = Self(std::env::temp_dir().join(format!(
                "rosetun-cgroup-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )));
            std::fs::create_dir_all(mount.cgroup()).unwrap();
            std::fs::create_dir_all(mount.0.join("lib")).unwrap();
            std::fs::create_dir_all(mount.0.join("wants")).unwrap();
            std::fs::write(
                mount.cgroup().join("cgroup.controllers"),
                "cpu memory pids\n",
            )
            .unwrap();
            if with_leaves {
                std::fs::create_dir_all(leaves().engines.under(&mount.cgroup())).unwrap();
                std::fs::create_dir_all(leaves().helper.under(&mount.cgroup())).unwrap();
            }
            mount
        }

        fn cgroup(&self) -> PathBuf {
            self.0.join("cgroup")
        }

        fn record(&self) -> PathBuf {
            self.0.join("lib").join("lockdown")
        }

        fn paths(&self) -> Paths {
            Paths {
                mount: self.cgroup(),
                record: self.record(),
                upgrade_stop: self.0.join("upgrade-stop"),
                wants: vec![self.0.join("wants")],
            }
        }

        /// What `systemctl enable rosetun-lockdown` leaves.
        fn enable_unit(&self) {
            std::fs::write(self.0.join("wants").join(LOCKDOWN_UNIT), "[Unit]\n").unwrap();
        }

        /// A scope as `systemd-run --user --scope --unit=…` makes it.
        fn scope(&self, uid: u32, scope: &str) -> PathBuf {
            let path = self.cgroup().join(format!(
                "user.slice/user-{uid}.slice/user@{uid}.service/app.slice/{scope}"
            ));
            std::fs::create_dir_all(&path).unwrap();
            path
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
            mount.paths(),
            Arc::new(|uid| uid == 1000),
        )
    }

    fn plan(scope: ProtectionScope) -> RoutingPlan {
        RoutingPlan {
            scope,
            allow_lan: false,
            lan: Default::default(),
            lockdown: false,
            shared_proxy: None,
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
            mount.paths(),
            Arc::new(|_| true),
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
        std::fs::remove_file(no_v2.cgroup().join("cgroup.controllers")).unwrap();
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
            mount.paths(),
            Arc::new(|_| true),
        );
        for scope in [ProtectionScope::AllTraffic, ProtectionScope::DnsOnly] {
            assert!(matches!(
                outside.begin_protection(&plan(scope), &[]),
                Err(RoutingError::Unavailable(_))
            ));
        }
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
        assert!(!nft.has_table());
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
        assert!(nft.has_table());
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
    fn a_kill_switch_table_found_at_start_is_the_hold_after_a_crash() {
        let nft = FakeNft::left(ProtectionScope::AllTraffic);
        let mount = Mount::new(true);
        let backend = backend(&nft, &mount);
        let status = backend.lockdown_status().unwrap();
        assert!(status.enabled && status.upgrade_hold);
        // The service "repairs" it: the hold's own rules replace the leftovers.
        backend
            .enable_lockdown(None, &LockdownApps::default())
            .unwrap();
        let script = nft.applied().last().unwrap().clone();
        assert_eq!(script, hold_rules(Some(&leaves())));
        assert!(script.contains("/helper\" meta l4proto { tcp, udp } th dport 53 accept"));
    }

    #[test]
    fn a_dns_lock_found_at_start_is_removed_and_the_network_stays_open() {
        let nft = FakeNft::left(ProtectionScope::DnsOnly);
        let mount = Mount::new(true);
        let backend = backend(&nft, &mount);
        let status = backend.lockdown_status().unwrap();
        assert!(!status.enabled && !status.upgrade_hold);
        assert_eq!(nft.applied(), [nftables::remove()]);
        assert!(!nft.has_table());
        // Asked again, there is nothing left to find.
        assert!(!backend.lockdown_status().unwrap().enabled);
        assert_eq!(nft.applied().len(), 1);
    }

    #[test]
    fn an_unrecognised_table_found_at_start_is_held() {
        let nft = Arc::new(FakeNft::default());
        *nft.table.lock().unwrap() = Some(
            "table inet rosetun {\n\tchain output {\n\t\ttype filter hook output priority 0; policy accept;\n\t}\n}\n"
                .to_owned(),
        );
        let mount = Mount::new(true);
        let backend = backend(&nft, &mount);
        let status = backend.lockdown_status().unwrap();
        assert!(status.enabled && status.upgrade_hold);
        assert!(nft.applied().is_empty());
        assert!(nft.has_table());
    }

    #[test]
    fn a_clean_start_has_no_hold_and_nothing_to_lift() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let mut backend = backend(&nft, &mount);
        assert!(!backend.lockdown_status().unwrap().enabled);
        assert!(!backend.disable_lockdown().unwrap());
        assert!(backend.permit_in_lockdown(&[]).is_err());
        backend.release_on_stop().unwrap();
        assert!(nft.applied().is_empty());
    }

    fn apps(gui: bool, cli: bool) -> LockdownApps {
        LockdownApps {
            gui: gui.then(|| PathBuf::from("/usr/lib/rosetun/rosetun-gui")),
            cli: cli.then(|| PathBuf::from("/usr/lib/rosetun/rosetun")),
            service: None,
        }
    }

    fn lan() -> crate::lan::LanAccess {
        crate::lan::LanAccess::default()
    }

    const GUI_PERMIT: &str = "\"user.slice/user-1000.slice/user@1000.service/app.slice/rosetun-gui.scope\" meta l4proto tcp accept";

    #[test]
    fn lockdown_is_offered_only_with_the_boot_unit_enabled() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let backend = backend(&nft, &mount);
        assert!(!backend.capabilities().lockdown);
        mount.enable_unit();
        assert_eq!(
            backend.capabilities(),
            ProtectionCapabilities {
                kill_switch: true,
                lockdown: true,
            }
        );
        let bare = Mount::new(false);
        bare.enable_unit();
        assert!(!super::tests::backend(&nft, &bare).capabilities().lockdown);
    }

    #[test]
    fn lockdown_writes_its_record_and_its_rules_and_survives_a_normal_stop() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let backend = backend(&nft, &mount);
        let status = backend
            .enable_lockdown(Some(&lan()), &LockdownApps::default())
            .unwrap();
        assert!(status.enabled && status.allow_lan && !status.upgrade_hold);
        assert_eq!(
            state::read(&mount.record()),
            Stored::Saved(Saved {
                allow_lan: true,
                private_networks: false
            })
        );
        let script = nft.applied().last().unwrap().clone();
        assert!(script.contains("hook input"));
        assert!(script.contains("/helper\" meta l4proto { tcp, udp } th dport 53 accept"));
        assert!(script.contains("/engines\" accept"));
        assert!(!script.contains("ct direction reply"));
        backend.release_on_stop().unwrap();
        assert!(nft.has_table());
        assert!(mount.record().exists());
    }

    #[test]
    fn turning_lockdown_off_removes_the_record_and_the_table() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let backend = backend(&nft, &mount);
        backend
            .enable_lockdown(None, &LockdownApps::default())
            .unwrap();
        assert!(backend.disable_lockdown().unwrap());
        assert!(!mount.record().exists());
        assert!(!nft.has_table());
        assert!(!backend.disable_lockdown().unwrap());
    }

    #[test]
    fn a_failed_table_write_leaves_neither_record_nor_rules() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let backend = backend(&nft, &mount);
        *nft.fail_next.lock().unwrap() = true;
        assert!(
            backend
                .enable_lockdown(None, &LockdownApps::default())
                .is_err()
        );
        assert!(!mount.record().exists());
        assert!(!backend.lockdown_status().unwrap().enabled);
    }

    #[test]
    fn a_failed_removal_keeps_the_record_with_the_rules() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let backend = backend(&nft, &mount);
        backend
            .enable_lockdown(Some(&lan()), &LockdownApps::default())
            .unwrap();
        *nft.fail_next.lock().unwrap() = true;
        assert!(backend.disable_lockdown().is_err());
        assert!(matches!(state::read(&mount.record()), Stored::Saved(saved) if saved.allow_lan));
        assert!(backend.lockdown_status().unwrap().enabled);
    }

    #[test]
    fn the_record_found_at_start_is_lockdown_not_the_hold() {
        // A crash under Lockdown left a session's table behind.
        let nft = FakeNft::left(ProtectionScope::AllTraffic);
        let mount = Mount::new(true);
        state::write(
            &mount.record(),
            Saved {
                allow_lan: true,
                private_networks: true,
            },
        )
        .unwrap();
        let backend = backend(&nft, &mount);
        let status = backend.lockdown_status().unwrap();
        assert!(status.enabled && !status.upgrade_hold);
        assert!(status.allow_lan && status.private_networks);
        assert!(nft.applied().is_empty());
        // The service writes Lockdown's rules for the leaves of this start.
        backend
            .enable_lockdown(Some(&lan()), &apps(true, true))
            .unwrap();
        assert!(nft.applied().last().unwrap().contains("hook input"));
    }

    #[test]
    fn a_corrupt_record_at_start_is_lockdown_without_the_local_network() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        state::write(&mount.record(), Saved::default()).unwrap();
        std::fs::write(mount.record(), "rosetun lockdown 9\n").unwrap();
        let backend = backend(&nft, &mount);
        let status = backend.lockdown_status().unwrap();
        assert!(status.enabled && !status.allow_lan && !status.upgrade_hold);
        // Turning it on again repairs the record.
        backend
            .enable_lockdown(None, &LockdownApps::default())
            .unwrap();
        assert_eq!(
            state::read(&mount.record()),
            Stored::Saved(Saved::default())
        );
    }

    #[test]
    fn the_programs_scopes_are_permitted_only_without_a_session() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        mount.scope(1000, GUI_SCOPE);
        // Not in group rosetun.
        mount.scope(1001, GUI_SCOPE);
        let mut backend = backend(&nft, &mount);
        backend.enable_lockdown(None, &apps(true, false)).unwrap();
        let script = nft.applied().last().unwrap().clone();
        assert!(script.contains(GUI_PERMIT), "{script}");
        assert!(!script.contains("user-1001"));

        let mut locked = plan(ProtectionScope::AllTraffic);
        locked.lockdown = true;
        let guard = backend.begin_protection(&locked, &[]).unwrap();
        let session = nft.applied().last().unwrap().clone();
        assert!(!session.contains("rosetun-gui.scope"));
        assert!(session.contains("hook input"));
        // Teardown keeps them away until the service gives them back.
        guard.revert().unwrap();
        assert!(!nft.applied().last().unwrap().contains("rosetun-gui.scope"));
        assert!(nft.applied().last().unwrap().contains("hook input"));
        backend.enable_lockdown(None, &apps(true, false)).unwrap();
        assert!(nft.applied().last().unwrap().contains(GUI_PERMIT));
    }

    #[test]
    fn a_scope_that_appears_or_is_made_again_is_permitted_on_refresh() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let backend = backend(&nft, &mount);
        backend.enable_lockdown(None, &apps(true, true)).unwrap();
        assert!(!nft.applied().last().unwrap().contains("scope"));
        let count = nft.applied().len();
        backend.refresh_lockdown_programs().unwrap();
        assert_eq!(nft.applied().len(), count, "nothing changed");

        let scope = mount.scope(1000, GUI_SCOPE);
        backend.refresh_lockdown_programs().unwrap();
        assert!(nft.applied().last().unwrap().contains(GUI_PERMIT));
        let count = nft.applied().len();

        let keep = mount.0.join("old-scope");
        std::fs::rename(&scope, &keep).unwrap();
        std::fs::create_dir(&scope).unwrap();
        backend.refresh_lockdown_programs().unwrap();
        assert_eq!(nft.applied().len(), count + 1, "a new cgroup ID");
    }

    #[test]
    fn a_lockdown_turned_on_during_the_hold_becomes_the_users_when_it_ends() {
        let nft = FakeNft::left(ProtectionScope::AllTraffic);
        let mount = Mount::new(true);
        let backend = backend(&nft, &mount);
        assert!(backend.lockdown_status().unwrap().upgrade_hold);
        let status = backend
            .enable_lockdown(Some(&lan()), &LockdownApps::default())
            .unwrap();
        assert!(status.upgrade_hold);
        assert!(!mount.record().exists());
        assert_eq!(nft.applied().last().unwrap(), &hold_rules(Some(&leaves())));
        backend.end_upgrade_hold().unwrap();
        let status = backend.lockdown_status().unwrap();
        assert!(status.enabled && status.allow_lan && !status.upgrade_hold);
        assert!(matches!(state::read(&mount.record()), Stored::Saved(saved) if saved.allow_lan));
        assert!(nft.applied().last().unwrap().contains("hook input"));
    }

    #[test]
    fn server_checks_need_no_permit_of_their_own_under_lockdown() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let mut backend = backend(&nft, &mount);
        backend
            .enable_lockdown(None, &LockdownApps::default())
            .unwrap();
        let count = nft.applied().len();
        drop(backend.permit_in_lockdown(&[]).unwrap());
        assert_eq!(nft.applied().len(), count);
    }

    #[test]
    fn at_boot_without_a_record_nothing_is_written() {
        let mount = Mount::new(false);
        let nft = FakeNft {
            unusable: Some("no nft".to_owned()),
            ..FakeNft::default()
        };
        assert_eq!(
            restore_from(&nft, &mount.record()).unwrap(),
            BootRestore::Off
        );
        assert!(nft.applied().is_empty());
    }

    #[test]
    fn at_boot_the_record_closes_the_network_before_the_service_starts() {
        let mount = Mount::new(false);
        let saved = Saved {
            allow_lan: true,
            private_networks: false,
        };
        state::write(&mount.record(), saved).unwrap();
        let nft = FakeNft::default();
        assert_eq!(
            restore_from(&nft, &mount.record()).unwrap(),
            BootRestore::On { allow_lan: true }
        );
        assert_eq!(nft.applied(), [boot_rules(saved)]);
        // Started again with the service's table in place: it stays.
        assert_eq!(
            restore_from(&nft, &mount.record()).unwrap(),
            BootRestore::AlreadyInPlace
        );
        assert_eq!(nft.applied().len(), 1);
    }

    #[test]
    fn at_boot_a_corrupt_record_closes_the_network_without_the_local_network() {
        let mount = Mount::new(false);
        state::write(&mount.record(), Saved::default()).unwrap();
        std::fs::write(mount.record(), "allow_lan=yes\n").unwrap();
        let nft = FakeNft::default();
        assert!(matches!(
            restore_from(&nft, &mount.record()),
            Ok(BootRestore::Corrupt { .. })
        ));
        assert_eq!(nft.applied(), [boot_rules(Saved::default())]);
    }

    #[test]
    fn at_boot_a_record_without_nft_is_an_error_not_an_open_network_silently() {
        let mount = Mount::new(false);
        state::write(&mount.record(), Saved::default()).unwrap();
        let nft = FakeNft {
            unusable: Some("no nft".to_owned()),
            ..FakeNft::default()
        };
        assert!(matches!(
            restore_from(&nft, &mount.record()),
            Err(RoutingError::Unavailable(_))
        ));
    }

    #[test]
    fn the_boot_set_names_no_cgroup() {
        let text = boot_rules(Saved {
            allow_lan: true,
            private_networks: true,
        });
        assert!(!text.contains("cgroupv2"));
        assert!(text.contains("ip saddr { 10.0.0.0/8"));
        // Without that option no network is known yet, so none is opened.
        let own = boot_rules(Saved {
            allow_lan: true,
            private_networks: false,
        });
        assert!(!own.contains("ip saddr {"));
        assert!(!own.contains("iifname"));
    }

    #[test]
    fn opening_the_network_removes_the_hold() {
        let nft = FakeNft::left(ProtectionScope::AllTraffic);
        let mount = Mount::new(true);
        let backend = backend(&nft, &mount);
        backend.lockdown_status().unwrap();
        assert!(backend.disable_lockdown().unwrap());
        assert_eq!(nft.applied().last().unwrap(), &nftables::remove());
        assert!(!backend.lockdown_status().unwrap().enabled);
    }

    #[test]
    fn a_table_found_at_start_is_a_crash_unless_the_last_stop_was_for_an_upgrade() {
        let nft = FakeNft::left(ProtectionScope::AllTraffic);
        let mount = Mount::new(true);
        backend(&nft, &mount).keep_protection_on_stop();

        let after_upgrade = backend(&nft, &mount).lockdown_status().unwrap();
        assert!(after_upgrade.upgrade_hold);
        assert!(!after_upgrade.hold_after_crash);

        // The word is used up: the next start without it is a crash.
        let after_crash = backend(&nft, &mount).lockdown_status().unwrap();
        assert!(after_crash.upgrade_hold);
        assert!(after_crash.hold_after_crash);
    }

    fn connected_backend(nft: &Arc<FakeNft>, mount: &Mount) -> (NftBackend, RoutingGuard) {
        let mut backend = backend(nft, mount);
        backend.lockdown_status().unwrap();
        let guard = backend
            .begin_protection(&plan(ProtectionScope::AllTraffic), &[])
            .unwrap();
        (backend, guard)
    }

    #[test]
    fn a_table_as_it_was_written_is_left_alone() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let (backend, _guard) = connected_backend(&nft, &mount);
        let writes = nft.applied().len();
        assert_eq!(
            backend.verify_protection().unwrap(),
            ProtectionCheck::Intact
        );
        assert_eq!(nft.applied().len(), writes);
    }

    #[test]
    fn a_flushed_table_is_put_back_in_one_transaction() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let (backend, _guard) = connected_backend(&nft, &mount);
        let written = nft.applied().last().unwrap().clone();
        *nft.table.lock().unwrap() = None;

        assert_eq!(
            backend.verify_protection().unwrap(),
            ProtectionCheck::Restored
        );
        assert_eq!(nft.applied().last().unwrap(), &written);
        assert!(nft.has_table());
        assert_eq!(
            backend.verify_protection().unwrap(),
            ProtectionCheck::Intact
        );
    }

    #[test]
    fn a_changed_rule_is_put_back() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let (backend, _guard) = connected_backend(&nft, &mount);
        let writes = nft.applied().len();
        let changed = nft
            .table
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .replace("policy drop", "policy accept");
        *nft.table.lock().unwrap() = Some(changed);

        assert_eq!(
            backend.verify_protection().unwrap(),
            ProtectionCheck::Restored
        );
        assert_eq!(nft.applied().len(), writes + 1);
        assert!(
            nft.table
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .contains("policy drop")
        );
    }

    #[test]
    fn only_a_change_of_layout_is_no_change() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let (backend, _guard) = connected_backend(&nft, &mount);
        let writes = nft.applied().len();
        let spaced = nft
            .table
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .replace('\n', "\n\n  ");
        *nft.table.lock().unwrap() = Some(spaced);

        assert_eq!(
            backend.verify_protection().unwrap(),
            ProtectionCheck::Intact
        );
        assert_eq!(nft.applied().len(), writes);
    }

    #[test]
    fn lockdown_without_a_session_is_put_back_too() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        mount.enable_unit();
        let backend = backend(&nft, &mount);
        backend.lockdown_status().unwrap();
        backend
            .enable_lockdown(None, &LockdownApps::default())
            .unwrap();
        *nft.table.lock().unwrap() = None;

        assert_eq!(
            backend.verify_protection().unwrap(),
            ProtectionCheck::Restored
        );
        assert!(nft.has_table());
    }

    #[test]
    fn the_holds_own_rules_are_not_taken_for_another_programs_change() {
        let nft = FakeNft::left(ProtectionScope::AllTraffic);
        let mount = Mount::new(true);
        let backend = backend(&nft, &mount);
        assert!(backend.lockdown_status().unwrap().upgrade_hold);
        // What the service does at start, and what the next check then looks at.
        backend
            .enable_lockdown(None, &LockdownApps::default())
            .unwrap();
        let writes = nft.applied().len();

        assert_eq!(
            backend.verify_protection().unwrap(),
            ProtectionCheck::Intact
        );
        assert_eq!(nft.applied().len(), writes);
    }

    #[test]
    fn the_hold_is_put_back_too() {
        let nft = FakeNft::left(ProtectionScope::AllTraffic);
        let mount = Mount::new(true);
        let backend = backend(&nft, &mount);
        assert!(backend.lockdown_status().unwrap().upgrade_hold);
        *nft.table.lock().unwrap() = None;

        assert_eq!(
            backend.verify_protection().unwrap(),
            ProtectionCheck::Restored
        );
        assert_eq!(nft.applied().last().unwrap(), &hold_rules(Some(&leaves())));
    }

    #[test]
    fn nothing_is_checked_when_no_table_is_expected() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let backend = backend(&nft, &mount);
        backend.lockdown_status().unwrap();
        // A table of this name is not this service's without a state that calls for one.
        *nft.table.lock().unwrap() = Some("table inet rosetun {\n}\n".to_owned());

        assert_eq!(
            backend.verify_protection().unwrap(),
            ProtectionCheck::Intact
        );
        assert!(nft.applied().is_empty());
    }

    #[test]
    fn a_stop_for_an_upgrade_is_not_restored_over() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let (backend, _guard) = connected_backend(&nft, &mount);
        backend.keep_protection_on_stop();
        let writes = nft.applied().len();
        *nft.table.lock().unwrap() = None;

        assert_eq!(
            backend.verify_protection().unwrap(),
            ProtectionCheck::Intact
        );
        assert_eq!(nft.applied().len(), writes);
    }

    #[test]
    fn a_failed_write_keeps_saying_so_and_tries_again() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let (backend, _guard) = connected_backend(&nft, &mount);
        *nft.table.lock().unwrap() = None;
        *nft.fail_next.lock().unwrap() = true;

        assert!(backend.verify_protection().is_err());
        assert_eq!(
            backend.verify_protection().unwrap(),
            ProtectionCheck::Restored
        );
    }

    #[test]
    fn a_normal_stop_removes_the_hold() {
        let nft = FakeNft::left(ProtectionScope::AllTraffic);
        let mount = Mount::new(true);
        let backend = backend(&nft, &mount);
        backend.lockdown_status().unwrap();
        backend.release_on_stop().unwrap();
        assert!(!nft.has_table());
    }

    #[test]
    fn a_stop_for_an_upgrade_leaves_a_kill_switch_for_the_new_version_as_the_hold() {
        let nft = Arc::new(FakeNft::default());
        let mount = Mount::new(true);
        let mut old = backend(&nft, &mount);
        let mut guard = old
            .begin_protection(&plan(ProtectionScope::AllTraffic), &[])
            .unwrap();
        let written = nft.applied().len();

        old.keep_protection_on_stop();
        guard.revert_in_place().unwrap();
        old.release_on_stop().unwrap();
        assert_eq!(nft.applied().len(), written, "not one rule changes");
        assert!(nft.has_table());

        let new = backend(&nft, &mount);
        assert!(new.lockdown_status().unwrap().upgrade_hold);
        assert!(nft.has_table());
    }

    #[test]
    fn a_stop_for_an_upgrade_keeps_the_hold_a_normal_stop_would_lift() {
        let nft = FakeNft::left(ProtectionScope::AllTraffic);
        let mount = Mount::new(true);
        let backend = backend(&nft, &mount);
        backend.lockdown_status().unwrap();
        backend.keep_protection_on_stop();
        backend.release_on_stop().unwrap();
        assert!(nft.has_table());
    }

    #[test]
    fn a_failed_connect_during_the_hold_puts_the_hold_back() {
        let nft = FakeNft::left(ProtectionScope::AllTraffic);
        let mount = Mount::new(true);
        let mut backend = backend(&nft, &mount);
        backend.lockdown_status().unwrap();
        let guard = backend
            .begin_protection(&plan(ProtectionScope::AllTraffic), &[])
            .unwrap();
        guard.revert().unwrap();
        assert_eq!(nft.applied().last().unwrap(), &hold_rules(Some(&leaves())));
        assert!(nft.has_table());
    }

    #[test]
    fn a_connect_lifts_the_hold_without_removing_its_own_table() {
        let nft = FakeNft::left(ProtectionScope::AllTraffic);
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
