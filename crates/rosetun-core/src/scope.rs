//! The user scope the GUI and the CLI run in on Linux. Lockdown permits
//! the scopes `app.slice/rosetun-gui.scope` and `rosetun-cli.scope` of
//! accounts in group `rosetun`, so a subscription can be updated without
//! a tunnel; nftables cannot tell a program by its file.
//!
//! The program runs itself again through `systemd-run --user --scope`,
//! which asks the user's service manager for the scope and then becomes
//! the program, in the same process. The parent waits for it and exits
//! with its code. `systemd-run` can fail before our program runs (no user
//! bus, say), which its exit code alone does not tell; so the program,
//! once inside, creates a marker file the parent named, in the user's
//! private runtime folder. Without the marker the parent goes on itself,
//! outside the scope.

use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const MARKER_ENV: &str = "ROSETUN_SCOPE_MARKER";
const MARKER_PREFIX: &str = "rosetun-scope-";
const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const CGROUP_MOUNT: &str = "/sys/fs/cgroup";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeProgram {
    Gui,
    Cli,
}

impl ScopeProgram {
    fn unit(self) -> &'static str {
        match self {
            Self::Gui => "rosetun-gui",
            Self::Cli => "rosetun-cli",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    Inside,
    /// Outside its scope, and why: under Lockdown it then has no network
    /// without a session.
    Outside(String),
}

/// Runs this program again in its scope and exits with that run's code
/// once it ends. Returns only when this process is the one to go on:
/// inside the scope already, or outside it with the reason.
pub fn enter_scope(program: ScopeProgram) -> Scope {
    let unit = program.unit();
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let marker = std::env::var_os(MARKER_ENV).map(PathBuf::from);
    if in_scope(&cgroup, unit) {
        if let Some(marker) = marker.filter(|path| valid_marker(path)) {
            let _ = std::fs::File::create_new(marker);
        }
        return Scope::Inside;
    }
    if marker.is_some() {
        // A run that systemd-run started, yet outside the scope: never
        // again, or it would start itself without end.
        return Scope::Outside("systemd-run started Rosetun outside its scope".to_owned());
    }
    let runtime = match prerequisites(unit) {
        Ok(runtime) => runtime,
        Err(reason) => return Scope::Outside(reason),
    };
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => return Scope::Outside(format!("cannot find this program: {error}")),
    };
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let marker = runtime.join(format!("{MARKER_PREFIX}{}-{nanos}", std::process::id()));
    let status = Command::new(SYSTEMD_RUN)
        .args([
            "--user",
            "--scope",
            "--quiet",
            "--collect",
            "--slice=app.slice",
            &format!("--unit={unit}"),
            "--",
        ])
        .arg(&exe)
        .args(std::env::args_os().skip(1).collect::<Vec<OsString>>())
        .env(MARKER_ENV, &marker)
        .status();
    let started = std::fs::remove_file(&marker).is_ok();
    match status {
        Ok(status) if started => std::process::exit(status.code().unwrap_or(1)),
        Ok(status) => Scope::Outside(format!("systemd-run could not make the scope ({status})")),
        Err(error) => Scope::Outside(format!("cannot run systemd-run: {error}")),
    }
}

/// Whether `/proc/self/cgroup` puts this process in the unit's scope of a
/// user's `app.slice`.
fn in_scope(cgroup: &str, unit: &str) -> bool {
    let wanted = format!("/app.slice/{unit}.scope");
    let mut lines = cgroup.lines().filter(|line| !line.is_empty());
    match (lines.next(), lines.next()) {
        (Some(line), None) => line
            .strip_prefix("0::/user.slice/")
            .is_some_and(|path| path.ends_with(&wanted)),
        _ => false,
    }
}

/// Only a marker this design names: in a private runtime folder, with our
/// prefix.
fn valid_marker(path: &Path) -> bool {
    path.is_absolute()
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(MARKER_PREFIX))
        && std::env::var_os("XDG_RUNTIME_DIR")
            .is_some_and(|runtime| path.parent() == Some(Path::new(&runtime)))
}

/// What `systemd-run --user --scope` needs, or why it cannot work: not
/// root (which needs no scope), the user's service manager and its
/// runtime folder, the program itself, and no other run in the scope.
fn prerequisites(unit: &str) -> Result<PathBuf, String> {
    let uid = std::fs::metadata("/proc/self")
        .map_err(|error| format!("cannot read this process's account: {error}"))?
        .uid();
    if uid == 0 {
        return Err("root needs no scope".to_owned());
    }
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute() && path.is_dir())
        .ok_or_else(|| "the session has no runtime folder (XDG_RUNTIME_DIR)".to_owned())?;
    let manager = Path::new(CGROUP_MOUNT).join(format!(
        "user.slice/user-{uid}.slice/user@{uid}.service"
    ));
    if !manager.is_dir() {
        return Err("the user's systemd service manager is not running".to_owned());
    }
    if !Path::new(SYSTEMD_RUN).is_file() {
        return Err(format!("{SYSTEMD_RUN} is missing"));
    }
    if manager.join(format!("app.slice/{unit}.scope")).exists() {
        return Err(format!("another Rosetun program runs in {unit}.scope"));
    }
    Ok(runtime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_units_own_scope_in_a_users_app_slice_counts() {
        let gui = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/rosetun-gui.scope\n";
        assert!(in_scope(gui, "rosetun-gui"));
        assert!(!in_scope(gui, "rosetun-cli"));
        for other in [
            "0::/user.slice/user-1000.slice/session-2.scope\n",
            "0::/system.slice/rosetun-gui.scope\n",
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-rosetun-gui.scope\n",
            "12:pids:/user.slice\n0::/user.slice/user-1000.slice/user@1000.service/app.slice/rosetun-gui.scope\n",
            "",
        ] {
            assert!(!in_scope(other, "rosetun-gui"), "{other}");
        }
    }

    #[test]
    fn units_have_fixed_names() {
        assert_eq!(ScopeProgram::Gui.unit(), "rosetun-gui");
        assert_eq!(ScopeProgram::Cli.unit(), "rosetun-cli");
    }
}
