//! Privileged package installation on Linux (`pkexec` + `dpkg`) and macOS
//! (`osascript` + `installer`), re-verifying SHA-256 on a root-owned copy
//! before invoking the system package manager.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::{Command, Stdio};

#[cfg(target_os = "linux")]
const INSTALLED_LINUX_GUI: &str = "/usr/lib/rosetun/rosetun-gui";
#[cfg(target_os = "linux")]
const REPLACED_LINUX_GUI: &str = "/usr/lib/rosetun/rosetun-gui (deleted)";
#[cfg(target_os = "linux")]
const DPKG_LIST_PATH: &str = "/var/lib/dpkg/info/rosetun.list";
#[cfg(target_os = "linux")]
const LINUX_INSTALL_SCRIPT: &str = concat!(
    "set -eu\n",
    "umask 077\n",
    "tmp=$(/usr/bin/mktemp /tmp/rosetun-update.XXXXXXXXXX.deb)\n",
    "trap '/bin/rm -f -- \"$tmp\"' EXIT INT TERM\n",
    "/bin/cp -- \"$1\" \"$tmp\"\n",
    "printf '%s  %s\\n' \"$2\" \"$tmp\" | /usr/bin/sha256sum -c - >/dev/null\n",
    "DEBIAN_FRONTEND=noninteractive /usr/bin/dpkg -i -- \"$tmp\"\n",
);

#[cfg(target_os = "macos")]
const INSTALLED_MACOS_APP: &str = "/Applications/Rosetun.app";

fn is_valid_sha256_hex(hex: &str) -> bool {
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(any(target_os = "macos", test))]
fn posix_single_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

#[cfg(any(target_os = "macos", test))]
fn applescript_string_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[cfg(any(target_os = "macos", test))]
fn build_macos_osascript(package_path: &str, expected_sha256: &str) -> Option<String> {
    if package_path.is_empty()
        || package_path.chars().any(char::is_control)
        || !is_valid_sha256_hex(expected_sha256)
    {
        return None;
    }
    let quoted_path = posix_single_quote(package_path);
    let shell_script = format!(
        "set -eu; umask 077; dir=$(/usr/bin/mktemp -d /private/tmp/rosetun-update.XXXXXXXXXX); \
         trap '/bin/rm -rf -- \"$dir\"' EXIT INT TERM; \
         pkg=\"$dir/rosetun.pkg\"; \
         /bin/cp -- {quoted_path} \"$pkg\"; \
         printf '%s  %s\\n' '{expected_sha256}' \"$pkg\" | /usr/bin/shasum -a 256 -c - >/dev/null; \
         /usr/sbin/installer -pkg \"$pkg\" -target / >/dev/null"
    );
    Some(format!(
        "do shell script {} with administrator privileges",
        applescript_string_literal(&shell_script)
    ))
}

#[cfg(any(target_os = "linux", test))]
fn classify_pkexec_code(code: Option<i32>) -> Option<u32> {
    match code {
        Some(0) => Some(0),
        Some(126 | 127) => None,
        Some(other) => Some(u32::try_from(other).unwrap_or(1)),
        None => Some(1),
    }
}

#[cfg(any(target_os = "macos", test))]
fn classify_osascript_result(code: Option<i32>, stderr: &str) -> Option<u32> {
    match code {
        Some(0) => Some(0),
        _ if stderr.contains("(-128)") => None,
        Some(other) => Some(u32::try_from(other).unwrap_or(1)),
        None => Some(1),
    }
}

/// Whether this Linux process is the `.deb`-installed GUI on `amd64` with
/// Polkit and `dpkg` available for an in-app package upgrade.
#[cfg(target_os = "linux")]
pub fn can_install_updates() -> bool {
    if !cfg!(target_arch = "x86_64") {
        return false;
    }
    let installed_exe = std::fs::read_link("/proc/self/exe").is_ok_and(|exe| {
        let text = exe.as_os_str();
        text == INSTALLED_LINUX_GUI || text == REPLACED_LINUX_GUI
    });
    installed_exe
        && Path::new(DPKG_LIST_PATH).is_file()
        && Path::new("/usr/bin/dpkg").is_file()
        && Path::new("/usr/bin/pkexec").is_file()
        && Path::new("/usr/bin/sha256sum").is_file()
}

/// Copies `path` to a root-owned temporary `.deb`, verifies `expected_sha256`
/// as `root`, and installs it with `dpkg -i`.
///
/// Returns `Ok(Some(0))` when installed, `Ok(None)` when Polkit authentication
/// was cancelled/declined, and `Ok(Some(code))` when installation failed.
#[cfg(target_os = "linux")]
pub fn install_verified_update(path: &Path, expected_sha256: &str) -> io::Result<Option<u32>> {
    if !is_valid_sha256_hex(expected_sha256) || !path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid update package or digest",
        ));
    }
    let status = Command::new("/usr/bin/pkexec")
        .args(["/bin/sh", "-c", LINUX_INSTALL_SCRIPT, "rosetun-update"])
        .arg(path)
        .arg(expected_sha256)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    Ok(classify_pkexec_code(status.code()))
}

/// Whether this macOS process runs alongside an installed `/Applications/Rosetun.app`
/// on Apple Silicon with `/usr/sbin/installer` and `osascript` available.
#[cfg(target_os = "macos")]
pub fn can_install_updates() -> bool {
    cfg!(target_arch = "aarch64")
        && Path::new(INSTALLED_MACOS_APP).exists()
        && Path::new("/usr/sbin/installer").is_file()
        && Path::new("/usr/bin/osascript").is_file()
        && Path::new("/usr/bin/shasum").is_file()
}

/// Copies `path` to a root-owned temporary `.pkg`, verifies `expected_sha256`
/// as `root`, and installs it with `/usr/sbin/installer -target /`.
///
/// Returns `Ok(Some(0))` when installed, `Ok(None)` when the user cancelled
/// the administrator prompt, and `Ok(Some(code))` when installation failed.
#[cfg(target_os = "macos")]
pub fn install_verified_update(path: &Path, expected_sha256: &str) -> io::Result<Option<u32>> {
    if !path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "update package does not exist",
        ));
    }
    let path_str = path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "update package path is not valid UTF-8",
        )
    })?;
    let script = build_macos_osascript(path_str, expected_sha256).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid update package path or digest",
        )
    })?;
    let output = Command::new("/usr/bin/osascript")
        .args(["-e", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    Ok(classify_osascript_result(output.status.code(), &stderr))
}

/// Launches a fresh instance of `/Applications/Rosetun.app` after an in-place
/// `.pkg` upgrade so the running old GUI can exit cleanly.
#[cfg(target_os = "macos")]
pub fn relaunch_installed_app() -> io::Result<()> {
    Command::new("/usr/bin/open")
        .args(["-n", INSTALLED_MACOS_APP])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_lowercase_sha256_hex_strictly() {
        let valid = "0123456789abcdef".repeat(4);
        assert!(is_valid_sha256_hex(&valid));
        assert!(!is_valid_sha256_hex(&valid.to_uppercase()));
        assert!(!is_valid_sha256_hex("0123"));
        assert!(!is_valid_sha256_hex(&format!("{}g", &valid[..63])));
    }

    #[test]
    fn quotes_paths_with_spaces_quotes_and_shell_metacharacters() {
        let digest = "ab".repeat(32);
        let tricky = "/Users/o'connor/Library/Caches/$HOME `uname`/rosetun-0.8.0.pkg";
        assert_eq!(
            posix_single_quote(tricky),
            "'/Users/o'\\''connor/Library/Caches/$HOME `uname`/rosetun-0.8.0.pkg'"
        );
        let script = build_macos_osascript(tricky, &digest).expect("valid script");
        assert!(script.starts_with("do shell script \""));
        assert!(script.ends_with("\" with administrator privileges"));
        assert!(
            script
                .contains("'/Users/o'\\\\''connor/Library/Caches/$HOME `uname`/rosetun-0.8.0.pkg'")
        );
        assert_eq!(build_macos_osascript("bad\npath.pkg", &digest), None);
        assert_eq!(build_macos_osascript("bad\0path.pkg", &digest), None);
        assert_eq!(build_macos_osascript("/tmp/ok.pkg", "not-a-hash"), None);
    }

    #[test]
    fn classifies_cancelled_auth_dialogs_separately_from_installer_errors() {
        assert_eq!(classify_pkexec_code(Some(0)), Some(0));
        assert_eq!(classify_pkexec_code(Some(126)), None);
        assert_eq!(classify_pkexec_code(Some(127)), None);
        assert_eq!(classify_pkexec_code(Some(2)), Some(2));

        assert_eq!(classify_osascript_result(Some(0), ""), Some(0));
        assert_eq!(
            classify_osascript_result(Some(1), "36:98: execution error: User canceled. (-128)\n"),
            None
        );
        assert_eq!(
            classify_osascript_result(Some(1), "installer: Error - package invalid\n"),
            Some(1)
        );
    }
}
