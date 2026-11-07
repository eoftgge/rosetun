//! Runs `/usr/bin/nft` or `/usr/sbin/nft`. The helper is root, so it runs
//! only a binary that only root can change: the file and every folder above it owned by root
//! and writable by nobody else, checked before every run. No `PATH` lookup,
//! no environment, no interactive input.

use std::fmt::Debug;
use std::fs::Metadata;
use std::io::Write as _;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use crate::RoutingError;
use crate::nftables;

const NFT_PATHS: [&str; 2] = ["/usr/bin/nft", "/usr/sbin/nft"];
const ROOT: u32 = 0;
const WRITABLE_BY_OTHERS: u32 = 0o022;
const MAX_ERROR_CHARS: usize = 300;

pub(super) trait Nft: Debug + Send + Sync {
    /// Why nft cannot be used, if it cannot.
    fn check(&self) -> Result<(), String>;
    /// Runs one script as one transaction.
    fn apply(&self, script: &str) -> Result<(), RoutingError>;
    /// Rosetun's table as `nft list table` prints it, if there is one.
    fn list_table(&self) -> Result<Option<String>, RoutingError>;
}

#[derive(Debug)]
pub(super) struct SystemNft;

impl Nft for SystemNft {
    fn check(&self) -> Result<(), String> {
        select_below(Path::new("/"), ROOT).map(drop)
    }

    fn apply(&self, script: &str) -> Result<(), RoutingError> {
        run(&["-f", "-"], script).map(drop)
    }

    fn list_table(&self) -> Result<Option<String>, RoutingError> {
        // Listing a missing table fails like any other error, so look first.
        if !nftables::lists_table(&run(&["list", "tables", "inet"], "")?) {
            return Ok(None);
        }
        run(&["list", "table", "inet", nftables::TABLE], "").map(Some)
    }
}

fn run(arguments: &[&str], input: &str) -> Result<String, RoutingError> {
    let mut child = prepare_command(Path::new("/"), ROOT, arguments)?.spawn()?;
    // The script is a few kilobytes, far below a pipe's buffer, and nft
    // reads all of it before it writes anything.
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let first = stderr
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("no message");
        return Err(RoutingError::Route(format!(
            "nft failed ({}): {}",
            output.status,
            first.chars().take(MAX_ERROR_CHARS).collect::<String>()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn prepare_command(top: &Path, owner: u32, arguments: &[&str]) -> Result<Command, RoutingError> {
    let binary = select_below(top, owner).map_err(RoutingError::Unavailable)?;
    let mut command = Command::new(binary);
    command
        .args(arguments)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    Ok(command)
}

fn select_below(top: &Path, owner: u32) -> Result<PathBuf, String> {
    let mut reasons = Vec::new();
    for candidate in NFT_PATHS {
        // Only the trust anchor changes in tests; candidates and checks are shared.
        let binary = top.join(candidate.trim_start_matches('/'));
        match verify_below(top, &binary, owner) {
            Ok(()) => return Ok(binary),
            Err(reason) => reasons.push(reason),
        }
    }
    Err(format!("no trusted nft executable: {}", reasons.join("; ")))
}

fn trusted(metadata: &Metadata, owner: u32) -> bool {
    metadata.uid() == owner && metadata.mode() & WRITABLE_BY_OTHERS == 0
}

/// Checks `top` and every folder below it on the way to `binary`, then the
/// file, without following a symbolic link. Production starts at `/` with
/// root as the owner; tests start at a folder of their own.
pub(super) fn verify_below(top: &Path, binary: &Path, owner: u32) -> Result<(), String> {
    let candidate = binary.display();
    let rest = binary
        .strip_prefix(top)
        .map_err(|_| format!("{candidate} is not below {}", top.display()))?;
    let components: Vec<_> = rest.components().collect();
    let Some((Component::Normal(_), folders)) = components.split_last() else {
        return Err(format!("{candidate} does not name a file"));
    };
    let unsafe_folder = || format!("a folder above {candidate} is not owned by root alone or is missing");
    let mut path = top.to_path_buf();
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| unsafe_folder())?;
    if !metadata.is_dir() || !trusted(&metadata, owner) {
        return Err(unsafe_folder());
    }
    for folder in folders {
        let Component::Normal(name) = folder else {
            return Err(format!("{candidate} is not canonical"));
        };
        path.push(name);
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| unsafe_folder())?;
        if !metadata.is_dir() || !trusted(&metadata, owner) {
            return Err(unsafe_folder());
        }
    }
    let metadata = std::fs::symlink_metadata(binary)
        .map_err(|_| format!("{candidate} is missing or inaccessible; install nftables"))?;
    if !metadata.is_file() || !trusted(&metadata, owner) {
        return Err(format!(
            "{candidate} is not a regular file owned by root alone"
        ));
    }
    if metadata.mode() & 0o111 == 0 {
        return Err(format!("{candidate} is not executable"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "rosetun-nft-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(0o755)).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn me() -> u32 {
        // SAFETY: getuid has no preconditions and cannot fail.
        unsafe { libc::getuid() }
    }

    fn layout() -> (TempDir, PathBuf) {
        let top = TempDir::new();
        let sbin = top.0.join("usr/sbin");
        fs::create_dir_all(&sbin).unwrap();
        for dir in [top.0.join("usr"), sbin.clone()] {
            fs::set_permissions(&dir, Permissions::from_mode(0o755)).unwrap();
        }
        let nft = sbin.join("nft");
        fs::write(&nft, b"").unwrap();
        fs::set_permissions(&nft, Permissions::from_mode(0o755)).unwrap();
        (top, nft)
    }

    fn add_bin(top: &TempDir) -> PathBuf {
        let bin = top.0.join("usr/bin");
        fs::create_dir(&bin).unwrap();
        fs::set_permissions(&bin, Permissions::from_mode(0o755)).unwrap();
        let nft = bin.join("nft");
        fs::write(&nft, b"").unwrap();
        fs::set_permissions(&nft, Permissions::from_mode(0o755)).unwrap();
        nft
    }

    #[test]
    fn arch_uses_the_direct_bin_path_without_following_sbin() {
        let (top, sbin_nft) = layout();
        fs::remove_file(&sbin_nft).unwrap();
        fs::remove_dir(sbin_nft.parent().unwrap()).unwrap();
        let bin_nft = add_bin(&top);
        symlink("bin", top.0.join("usr/sbin")).unwrap();
        assert!(verify_below(&top.0, &sbin_nft, me()).is_err());
        assert_eq!(select_below(&top.0, me()).unwrap(), bin_nft);
    }

    #[test]
    fn a_missing_bin_candidate_falls_back_to_sbin() {
        let (top, nft) = layout();
        assert_eq!(select_below(&top.0, me()).unwrap(), nft);
    }

    #[test]
    fn bin_has_priority_when_both_candidates_are_trusted() {
        let (top, _) = layout();
        let bin_nft = add_bin(&top);
        assert_eq!(select_below(&top.0, me()).unwrap(), bin_nft);
    }

    #[test]
    fn an_unsafe_first_candidate_does_not_prevent_a_verified_fallback() {
        let (top, sbin_nft) = layout();
        let bin_nft = add_bin(&top);
        for mode in [0o777, 0o644] {
            fs::set_permissions(&bin_nft, Permissions::from_mode(mode)).unwrap();
            assert_eq!(select_below(&top.0, me()).unwrap(), sbin_nft);
        }
        fs::remove_file(&bin_nft).unwrap();
        symlink(&sbin_nft, &bin_nft).unwrap();
        assert_eq!(select_below(&top.0, me()).unwrap(), sbin_nft);
    }

    #[test]
    fn missing_or_unsafe_candidates_report_both_actual_paths() {
        let (top, sbin_nft) = layout();
        let bin_nft = add_bin(&top);
        for mode in [0o777, 0o644] {
            for nft in [&bin_nft, &sbin_nft] {
                fs::set_permissions(nft, Permissions::from_mode(mode)).unwrap();
            }
            let reason = select_below(&top.0, me()).unwrap_err();
            assert!(reason.contains(bin_nft.to_str().unwrap()), "{reason}");
            assert!(reason.contains(sbin_nft.to_str().unwrap()), "{reason}");
            assert!(matches!(
                prepare_command(&top.0, me(), &["-f", "-"]),
                Err(RoutingError::Unavailable(_))
            ));
        }
        fs::remove_file(&bin_nft).unwrap();
        fs::remove_file(&sbin_nft).unwrap();
        assert!(select_below(&top.0, me()).is_err());
    }

    #[test]
    fn a_linked_parent_or_a_directory_in_place_of_a_binary_is_refused() {
        let (top, nft) = layout();
        let original = top.0.join("usr/original");
        fs::rename(nft.parent().unwrap(), &original).unwrap();
        symlink("original", nft.parent().unwrap()).unwrap();
        assert!(select_below(&top.0, me()).is_err());
        fs::remove_file(nft.parent().unwrap()).unwrap();
        fs::rename(&original, nft.parent().unwrap()).unwrap();
        fs::remove_file(&nft).unwrap();
        fs::create_dir(&nft).unwrap();
        assert!(select_below(&top.0, me()).is_err());
    }

    #[test]
    fn command_preparation_uses_the_verified_candidate_and_rechecks_permissions() {
        let (top, sbin_nft) = layout();
        let bin_nft = add_bin(&top);
        let command = prepare_command(&top.0, me(), &["-f", "-"]).unwrap();
        assert_eq!(command.get_program(), bin_nft.as_os_str());
        assert_eq!(command.get_args().collect::<Vec<_>>(), ["-f", "-"]);
        fs::set_permissions(&bin_nft, Permissions::from_mode(0o777)).unwrap();
        let command = prepare_command(&top.0, me(), &["list", "tables", "inet"]).unwrap();
        assert_eq!(command.get_program(), sbin_nft.as_os_str());
        fs::set_permissions(&sbin_nft, Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            prepare_command(&top.0, me(), &[]),
            Err(RoutingError::Unavailable(_))
        ));
    }

    #[test]
    fn a_binary_only_its_owner_can_change_passes() {
        let (top, nft) = layout();
        assert_eq!(verify_below(&top.0, &nft, me()), Ok(()));
    }

    #[test]
    fn a_binary_of_another_owner_is_refused() {
        let (top, nft) = layout();
        assert!(!trusted(&fs::symlink_metadata(&nft).unwrap(), me() + 1));
        assert!(verify_below(&top.0, &nft, me() + 1).is_err());
    }

    #[test]
    fn a_writable_binary_or_folder_is_refused() {
        let (top, nft) = layout();
        fs::set_permissions(&nft, Permissions::from_mode(0o775)).unwrap();
        assert!(verify_below(&top.0, &nft, me()).is_err());
        fs::set_permissions(&nft, Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(nft.parent().unwrap(), Permissions::from_mode(0o757)).unwrap();
        assert!(verify_below(&top.0, &nft, me()).is_err());
    }

    #[test]
    fn a_missing_binary_or_a_link_is_refused() {
        let (top, nft) = layout();
        let link = nft.with_file_name("nft-link");
        symlink(&nft, &link).unwrap();
        assert!(verify_below(&top.0, &link, me()).is_err());
        fs::remove_file(&nft).unwrap();
        let missing = verify_below(&top.0, &nft, me()).unwrap_err();
        assert!(missing.contains("install nftables"), "{missing}");
    }
}
