//! Linux: the helper runs engines as root, so it runs only files that only
//! root can change: the file and every folder above it are owned by root and
//! writable by nobody else. Without that, whoever can write one of them
//! chooses what runs as root. There is no fallback to another file.
//!
//! The walk follows a canonical path, so it meets no symbolic link, and once
//! it passes only root can change any part of the chain: checking by path
//! is enough here, unlike for the objects the helper creates itself.

use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use crate::errors::EngineError;

const ROOT: u32 = 0;
const WRITABLE_BY_OTHERS: u32 = 0o022;

/// Fails with `BinaryUnavailable` unless `binary`, an absolute canonical
/// path, and every folder from `/` down to it belong to root alone.
pub fn verify(binary: &Path) -> Result<(), EngineError> {
    verify_below(Path::new("/"), binary, ROOT)
}

fn trusted_directory(metadata: &Metadata, owner: u32) -> bool {
    metadata.is_dir() && metadata.uid() == owner && metadata.mode() & WRITABLE_BY_OTHERS == 0
}

fn trusted_file(metadata: &Metadata, owner: u32) -> bool {
    metadata.is_file() && metadata.uid() == owner && metadata.mode() & WRITABLE_BY_OTHERS == 0
}

fn unavailable(reason: &str) -> EngineError {
    EngineError::BinaryUnavailable(reason.to_owned())
}

/// Checks `top` and every folder below it on the way to `binary`, then the
/// file. Production starts at `/` with root as the owner; tests start at a
/// folder of their own with their own user.
fn verify_below(top: &Path, binary: &Path, owner: u32) -> Result<(), EngineError> {
    let rest = binary
        .strip_prefix(top)
        .map_err(|_| unavailable("the engine path is not absolute"))?;
    let components: Vec<_> = rest.components().collect();
    let Some((Component::Normal(_), folders)) = components.split_last() else {
        return Err(unavailable("the engine path does not name a file"));
    };
    let unsafe_folder = || unavailable("a folder above the engine is not owned by root alone");
    let mut path = top.to_path_buf();
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| unsafe_folder())?;
    if !trusted_directory(&metadata, owner) {
        return Err(unsafe_folder());
    }
    for folder in folders {
        let Component::Normal(name) = folder else {
            return Err(unavailable("the engine path is not canonical"));
        };
        path.push(name);
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| unsafe_folder())?;
        if !trusted_directory(&metadata, owner) {
            return Err(unsafe_folder());
        }
    }
    let metadata = std::fs::symlink_metadata(binary)
        .map_err(|_| unavailable("the engine file cannot be read"))?;
    if !trusted_file(&metadata, owner) {
        return Err(unavailable(
            "the engine file is not a regular file owned by root alone",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, DirBuilder, Permissions};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    /// A private folder with `bin/engine` inside, all owned by the test user.
    struct Fixture {
        top: PathBuf,
        owner: u32,
    }

    impl Fixture {
        fn new() -> Self {
            let top = std::env::temp_dir().join(format!(
                "rosetun-installed-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            DirBuilder::new().mode(0o755).create(&top).unwrap();
            DirBuilder::new()
                .mode(0o755)
                .create(top.join("bin"))
                .unwrap();
            fs::write(top.join("bin/engine"), b"#!/bin/sh\n").unwrap();
            fs::set_permissions(top.join("bin/engine"), Permissions::from_mode(0o755)).unwrap();
            let owner = fs::metadata(&top).unwrap().uid();
            Self { top, owner }
        }

        fn engine(&self) -> PathBuf {
            self.top.join("bin/engine")
        }

        fn chmod(&self, relative: &str, mode: u32) {
            fs::set_permissions(self.top.join(relative), Permissions::from_mode(mode)).unwrap();
        }

        fn verify(&self, binary: &Path) -> Result<(), String> {
            verify_below(&self.top, binary, self.owner).map_err(|error| error.to_string())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.top);
        }
    }

    #[test]
    fn a_file_only_its_owner_can_change_is_accepted() {
        let fixture = Fixture::new();
        assert_eq!(fixture.verify(&fixture.engine()), Ok(()));
        fixture.chmod("bin/engine", 0o700);
        fixture.chmod("bin", 0o711);
        assert_eq!(fixture.verify(&fixture.engine()), Ok(()));
    }

    #[test]
    fn another_owner_is_refused_for_the_file_and_for_folders() {
        let fixture = Fixture::new();
        let stranger = fixture.owner.wrapping_add(1);
        let error = verify_below(&fixture.top, &fixture.engine(), stranger)
            .unwrap_err()
            .to_string();
        assert!(error.contains("folder"), "{error}");
        assert!(matches!(
            verify_below(&fixture.top, &fixture.engine(), stranger),
            Err(EngineError::BinaryUnavailable(_))
        ));
    }

    #[test]
    fn a_file_writable_by_its_group_or_others_is_refused() {
        let fixture = Fixture::new();
        for mode in [0o775, 0o757, 0o777] {
            fixture.chmod("bin/engine", mode);
            let error = fixture.verify(&fixture.engine()).unwrap_err();
            assert!(error.contains("engine file"), "{mode:o}: {error}");
        }
    }

    #[test]
    fn a_folder_writable_by_its_group_or_others_is_refused() {
        for (folder, mode) in [("bin", 0o775), ("bin", 0o757), ("bin", 0o1777), ("", 0o775)] {
            let fixture = Fixture::new();
            fixture.chmod(folder, mode);
            let error = fixture.verify(&fixture.engine()).unwrap_err();
            assert!(error.contains("folder"), "{folder} {mode:o}: {error}");
        }
    }

    #[test]
    fn links_folders_and_missing_files_are_refused() {
        let fixture = Fixture::new();
        symlink(fixture.engine(), fixture.top.join("bin/link")).unwrap();
        assert!(fixture.verify(&fixture.top.join("bin/link")).is_err());
        symlink(fixture.top.join("bin"), fixture.top.join("bin-link")).unwrap();
        assert!(
            fixture
                .verify(&fixture.top.join("bin-link/engine"))
                .is_err()
        );
        assert!(fixture.verify(&fixture.top.join("bin")).is_err());
        assert!(fixture.verify(&fixture.top.join("bin/missing")).is_err());
    }

    #[test]
    fn paths_outside_the_top_or_not_canonical_are_refused() {
        let fixture = Fixture::new();
        assert!(fixture.verify(Path::new("relative/engine")).is_err());
        assert!(
            fixture
                .verify(&fixture.top.join("bin/../bin/engine"))
                .is_err()
        );
        assert!(fixture.verify(&fixture.top).is_err());
    }

    #[test]
    fn the_reason_names_no_path() {
        let fixture = Fixture::new();
        fixture.chmod("bin/engine", 0o777);
        let error = fixture.verify(&fixture.engine()).unwrap_err();
        assert!(!error.contains(fixture.top.to_str().unwrap()), "{error}");
        assert!(!error.contains("/tmp"), "{error}");
    }
}
