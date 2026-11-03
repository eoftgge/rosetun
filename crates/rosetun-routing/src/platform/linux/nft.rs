//! Runs `/usr/sbin/nft`. The helper is root, so it runs only a binary that
//! only root can change: the file and every folder above it owned by root
//! and writable by nobody else, checked before every run. No `PATH` lookup,
//! no environment, no interactive input.

use std::fmt::Debug;
use std::fs::Metadata;
use std::io::Write as _;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::process::{Command, Stdio};

use crate::RoutingError;
use crate::nftables;

pub(super) const NFT_PATH: &str = "/usr/sbin/nft";
const ROOT: u32 = 0;
const WRITABLE_BY_OTHERS: u32 = 0o022;
const MAX_ERROR_CHARS: usize = 300;

pub(super) trait Nft: Debug + Send + Sync {
    /// Why nft cannot be used, if it cannot.
    fn check(&self) -> Result<(), String>;
    /// Runs one script as one transaction.
    fn apply(&self, script: &str) -> Result<(), RoutingError>;
    fn table_exists(&self) -> Result<bool, RoutingError>;
}

#[derive(Debug)]
pub(super) struct SystemNft;

impl Nft for SystemNft {
    fn check(&self) -> Result<(), String> {
        verify_below(Path::new("/"), Path::new(NFT_PATH), ROOT)
    }

    fn apply(&self, script: &str) -> Result<(), RoutingError> {
        run(&["-f", "-"], script).map(drop)
    }

    fn table_exists(&self) -> Result<bool, RoutingError> {
        run(&["list", "tables", "inet"], "").map(|listing| nftables::lists_table(&listing))
    }
}

fn run(arguments: &[&str], input: &str) -> Result<String, RoutingError> {
    SystemNft.check().map_err(RoutingError::Unavailable)?;
    let mut child = Command::new(NFT_PATH)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
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

fn trusted(metadata: &Metadata, owner: u32) -> bool {
    metadata.uid() == owner && metadata.mode() & WRITABLE_BY_OTHERS == 0
}

/// Checks `top` and every folder below it on the way to `binary`, then the
/// file, without following a symbolic link. Production starts at `/` with
/// root as the owner; tests start at a folder of their own.
pub(super) fn verify_below(top: &Path, binary: &Path, owner: u32) -> Result<(), String> {
    let rest = binary
        .strip_prefix(top)
        .map_err(|_| format!("{NFT_PATH} is not below {}", top.display()))?;
    let components: Vec<_> = rest.components().collect();
    let Some((Component::Normal(_), folders)) = components.split_last() else {
        return Err("the nft path does not name a file".to_owned());
    };
    let unsafe_folder = || format!("a folder above {NFT_PATH} is not owned by root alone");
    let mut path = top.to_path_buf();
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| unsafe_folder())?;
    if !metadata.is_dir() || !trusted(&metadata, owner) {
        return Err(unsafe_folder());
    }
    for folder in folders {
        let Component::Normal(name) = folder else {
            return Err("the nft path is not canonical".to_owned());
        };
        path.push(name);
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| unsafe_folder())?;
        if !metadata.is_dir() || !trusted(&metadata, owner) {
            return Err(unsafe_folder());
        }
    }
    let metadata = std::fs::symlink_metadata(binary)
        .map_err(|_| format!("{NFT_PATH} is missing; install nftables"))?;
    if !metadata.is_file() || !trusted(&metadata, owner) {
        return Err(format!(
            "{NFT_PATH} is not a regular file owned by root alone"
        ));
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

    #[test]
    fn a_binary_only_its_owner_can_change_passes() {
        let (top, nft) = layout();
        assert_eq!(verify_below(&top.0, &nft, me()), Ok(()));
    }

    #[test]
    fn a_binary_of_another_owner_is_refused() {
        let (top, nft) = layout();
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
