//! `--hold-for-upgrade <install dir>`: run by the installer from its new
//! helper, before it stops the running copy. Talks to nothing but WFP, since
//! the old service may speak another protocol.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rosetun_routing::upgrade_hold::{self, HoldDecision};
use rosetun_routing::{LockdownApps, RoutingError};

/// Exit codes of `--hold-for-upgrade`; the installer reads them.
pub(crate) mod hold_exit {
    /// The kill switch was on: the hold is in place now.
    pub(crate) const PLACED: u8 = 0;
    /// A hold from an earlier upgrade that did not finish is kept.
    pub(crate) const KEPT: u8 = 1;
    /// No kill switch: nothing to hold.
    pub(crate) const NO_KILL_SWITCH: u8 = 3;
    /// Lockdown already holds the network.
    pub(crate) const LOCKDOWN_ON: u8 = 4;
    /// WFP could not be read or written; the upgrade may open the network.
    pub(crate) const FAILED: u8 = 5;
}

pub(crate) fn hold_for_upgrade(install_dir: &Path) -> ExitCode {
    let code = match decide().and_then(|decision| act(decision, install_dir)) {
        Ok(code) => code,
        Err(error) => {
            println!("could not hold the network for the upgrade: {error}");
            hold_exit::FAILED
        }
    };
    ExitCode::from(code)
}

fn decide() -> Result<HoldDecision, RoutingError> {
    let lockdown = rosetun_routing::lockdown::status()?;
    let kill_switch = if lockdown.enabled {
        None
    } else {
        upgrade_hold::running_kill_switch()?
    };
    Ok(upgrade_hold::decide(&lockdown, kill_switch))
}

/// The segment the hold keeps open: the computer's own, as a session with
/// the default tunnel would see it. Private networks behind the router stay
/// closed; the hold lasts an upgrade.
fn hold_lan() -> rosetun_routing::lan::LanAccess {
    let tun = rosetun_config::TunSettings::default();
    let tunnel = tun
        .ipv4
        .split_once('/')
        .and_then(|(address, length)| {
            rosetun_config::IpPrefix::new(address.parse().ok()?, length.parse().ok()?)
        })
        .into_iter()
        .collect::<Vec<_>>();
    let query = rosetun_routing::lan::SegmentQuery {
        tunnel_alias: &tun.name,
        tunnel_networks: &tunnel,
        servers: &[],
    };
    let segment = match rosetun_routing::lan_segment(&query) {
        Ok(scan) => scan.segment,
        Err(error) => {
            eprintln!("could not read the local networks, they stay closed: {error}");
            rosetun_routing::lan::LanSegment::default()
        }
    };
    rosetun_routing::lan::LanAccess {
        segment,
        private_networks: false,
        ipv6_multicast: false,
        servers: Vec::new(),
    }
}

fn act(decision: HoldDecision, install_dir: &Path) -> Result<u8, RoutingError> {
    Ok(match decision {
        HoldDecision::Place { allow_lan } => {
            let lan = allow_lan.then(hold_lan);
            let status = upgrade_hold::place(lan.as_ref(), &installed_apps(install_dir))?;
            println!(
                "upgrade hold placed: local network {}, complete {}",
                if allow_lan { "on" } else { "off" },
                status.complete
            );
            hold_exit::PLACED
        }
        HoldDecision::AlreadyHeld => {
            println!("upgrade hold from an earlier upgrade kept");
            hold_exit::KEPT
        }
        HoldDecision::LockdownOn => {
            println!("Lockdown is on and holds the network during the upgrade");
            hold_exit::LOCKDOWN_ON
        }
        HoldDecision::NoKillSwitch => {
            println!("no kill switch is on; the network is not held");
            hold_exit::NO_KILL_SWITCH
        }
    })
}

/// Lockdown's programs as the installed service will permit them: the GUI,
/// the CLI and the service in the install folder. This helper runs from the
/// installer's temporary folder, so `lockdown_apps` would find itself there.
fn installed_apps(install_dir: &Path) -> LockdownApps {
    let find = |name: &str| -> Option<PathBuf> {
        let path = install_dir.join(name);
        path.is_file()
            .then(|| std::fs::canonicalize(&path).ok())
            .flatten()
    };
    LockdownApps {
        gui: find("rosetun-gui.exe"),
        cli: find("rosetun.exe"),
        service: find("rosetun-helper-privileged.exe"),
    }
}
