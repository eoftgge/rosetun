//! Lockdown outside the service (Linux): `--restore-lockdown`, which
//! `rosetun-lockdown.service` runs at boot before any network, and
//! `--reset-firewall`, the way out when the service cannot be reached.

use std::process::{Command, ExitCode, Stdio};

use rosetun_routing::{BootRestore, RoutingError};

const SYSTEMCTL: &str = "/usr/bin/systemctl";
const SERVICE_UNIT: &str = "rosetun-helper.service";

/// Exit codes of `--restore-lockdown`.
pub(crate) mod restore_exit {
    /// Lockdown's set could not be written: the network is not closed.
    pub(crate) const FAILED: u8 = 1;
    /// The record was corrupt; Lockdown's set is up without the local
    /// network, closed. The unit shows as failed so it gets looked at.
    pub(crate) const CORRUPT: u8 = 4;
    pub(crate) const NOT_ROOT: u8 = 3;
}

/// Exit codes of `--reset-firewall`, the same numbers as on Windows.
pub(crate) mod reset_exit {
    pub(crate) const NOT_ROOT: u8 = 3;
    pub(crate) const SERVICE_DID_NOT_STOP: u8 = 4;
    pub(crate) const RULES_REMAIN: u8 = 5;
    pub(crate) const SERVICE_DID_NOT_START: u8 = 6;
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

pub(crate) fn restore_at_boot() -> ExitCode {
    if !is_root() {
        eprintln!("restoring Lockdown needs root");
        return ExitCode::from(restore_exit::NOT_ROOT);
    }
    exit_for_restore(&rosetun_routing::lockdown::restore_at_boot())
}

fn exit_for_restore(result: &Result<BootRestore, RoutingError>) -> ExitCode {
    match result {
        Ok(BootRestore::Off) => {
            println!("Lockdown is off");
            ExitCode::SUCCESS
        }
        Ok(BootRestore::On { allow_lan }) => {
            println!("Lockdown is on (local network: {})", on_off(*allow_lan));
            ExitCode::SUCCESS
        }
        Ok(BootRestore::AlreadyInPlace) => {
            println!("Rosetun's table is already in place; it stays");
            ExitCode::SUCCESS
        }
        Ok(BootRestore::Corrupt { reason }) => {
            eprintln!(
                "the Lockdown record cannot be trusted ({reason}); Lockdown is on without the local network"
            );
            ExitCode::from(restore_exit::CORRUPT)
        }
        Err(error) => {
            eprintln!("cannot restore Lockdown: {error}");
            ExitCode::from(restore_exit::FAILED)
        }
    }
}

fn on_off(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

/// Stops a running service first, so it cannot write Lockdown's table
/// again from what it still holds, removes the table and the record, and
/// starts the service again if it was running: it then finds no Lockdown.
pub(crate) fn reset_firewall() -> ExitCode {
    if !is_root() {
        eprintln!("removing Lockdown needs root");
        return ExitCode::from(reset_exit::NOT_ROOT);
    }
    let was_running = systemctl(&["is-active", "--quiet", SERVICE_UNIT]).unwrap_or(false);
    if was_running {
        match systemctl(&["stop", SERVICE_UNIT]) {
            Ok(true) => println!("Rosetun service stopped"),
            Ok(false) | Err(_) => {
                eprintln!("cannot stop the Rosetun service");
                return ExitCode::from(reset_exit::SERVICE_DID_NOT_STOP);
            }
        }
    }
    let code = match rosetun_routing::lockdown::reset_firewall() {
        Ok(reset) if reset.table || reset.record => {
            println!("Lockdown removed");
            ExitCode::SUCCESS
        }
        Ok(_) => {
            println!("Lockdown was not on; nothing to remove");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("cannot remove Lockdown: {error}");
            ExitCode::from(reset_exit::RULES_REMAIN)
        }
    };
    if was_running && !matches!(systemctl(&["start", SERVICE_UNIT]), Ok(true)) {
        eprintln!("cannot start the Rosetun service again");
        if code == ExitCode::SUCCESS {
            return ExitCode::from(reset_exit::SERVICE_DID_NOT_START);
        }
    }
    code
}

/// Whether `systemctl` succeeded; an error when it cannot run at all.
fn systemctl(arguments: &[&str]) -> std::io::Result<bool> {
    Command::new(SYSTEMCTL)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .status()
        .map(|status| status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_corrupt_record_fails_the_unit_but_only_after_closing_the_network() {
        assert_eq!(
            exit_for_restore(&Ok(BootRestore::Corrupt {
                reason: "x".to_owned()
            })),
            ExitCode::from(restore_exit::CORRUPT)
        );
        for done in [
            BootRestore::Off,
            BootRestore::On { allow_lan: true },
            BootRestore::AlreadyInPlace,
        ] {
            assert_eq!(exit_for_restore(&Ok(done)), ExitCode::SUCCESS);
        }
        assert_eq!(
            exit_for_restore(&Err(RoutingError::Unavailable("no nft".to_owned()))),
            ExitCode::from(restore_exit::FAILED)
        );
    }
}
