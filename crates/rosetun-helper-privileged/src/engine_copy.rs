//! sing-box runs from a copy in `data\engines` that only SYSTEM and
//! Administrators can open. With `strict_route`, sing-tun adds a hard WFP
//! permit for its own executable by app ID alone, with no account
//! condition, that our blocks cannot override; while a session is up, a
//! standard account starting the installed `sing-box.exe` would get it.
//! A hard link would not help: the DACL belongs to the file, not the name.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::data_dir;

const DIR: &str = "engines";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    len: u64,
    sha256: [u8; 32],
}

/// Copies `source` into `data_dir\engines` when the copy is missing or
/// differs and returns the copy's path. An error means the engine must not
/// start: running `source` itself would bring the permit back.
pub(crate) fn prepare(source: &Path, data_dir: &Path) -> io::Result<PathBuf> {
    let dir = data_dir.join(DIR);
    data_dir::secure_private_dir(&dir)
        .map_err(|error| context(error, "cannot secure the engine folder"))?;
    refresh(source, &dir, data_dir::secure_private_file, |from, to| {
        fs::copy(from, to).map(drop)
    })
}

fn refresh(
    source: &Path,
    dir: &Path,
    secure: impl Fn(&Path) -> io::Result<()>,
    copy: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> io::Result<PathBuf> {
    let name = source
        .file_name()
        .ok_or_else(|| io::Error::other("engine source has no file name"))?;
    let target = dir.join(name);
    let wanted = fingerprint(source)
        .map_err(|error| context(error, "cannot read the installed engine"))?
        .ok_or_else(|| io::Error::other("the installed engine is missing"))?;
    let current = match fingerprint_if_len(&target, Some(wanted.len)) {
        Ok(current) => current,
        Err(error) => {
            tracing::warn!(%error, "cannot read the engine copy; replacing it");
            None
        }
    };
    if !needs_copy(&wanted, current.as_ref()) {
        // The installer resets data ACLs on upgrade; protect the copy again.
        if let Err(error) = secure(&target) {
            tracing::warn!(%error, "cannot reapply the engine copy's ACL");
        }
        return Ok(target);
    }

    let mut temp = target.clone().into_os_string();
    temp.push(".tmp");
    let temp = PathBuf::from(temp);
    let result = copy_verified(source, &temp, &wanted, &secure, copy).and_then(|()| {
        fs::rename(&temp, &target).map_err(|error| {
            if target.exists() {
                // A running engine keeps its image, and Windows refuses to
                // replace it; the old copy differs, so it must not run.
                context(
                    error,
                    "the engine copy is in use by a running engine and differs from the installed one",
                )
            } else {
                context(error, "cannot move the engine copy into place")
            }
        })
    });
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result?;
    tracing::info!(copy = %target.display(), "engine copy updated");
    Ok(target)
}

fn copy_verified(
    source: &Path,
    temp: &Path,
    wanted: &Fingerprint,
    secure: impl Fn(&Path) -> io::Result<()>,
    copy: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> io::Result<()> {
    copy(source, temp).map_err(|error| context(error, "cannot copy the engine"))?;
    secure(temp).map_err(|error| context(error, "cannot protect the engine copy"))?;
    let copied = fingerprint(temp)
        .map_err(|error| context(error, "cannot read the engine copy"))?
        .ok_or_else(|| io::Error::other("the engine copy disappeared"))?;
    if &copied != wanted {
        return Err(io::Error::other(
            "the engine copy does not match the installed engine",
        ));
    }
    Ok(())
}

fn needs_copy(source: &Fingerprint, copy: Option<&Fingerprint>) -> bool {
    copy != Some(source)
}

fn fingerprint(path: &Path) -> io::Result<Option<Fingerprint>> {
    fingerprint_if_len(path, None)
}

/// Skips hashing a file whose length already differs from `len`.
fn fingerprint_if_len(path: &Path, len: Option<u64>) -> io::Result<Option<Fingerprint>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let actual = file.metadata()?.len();
    if len.is_some_and(|len| len != actual) {
        // The length alone already tells the files apart.
        return Ok(Some(Fingerprint {
            len: actual,
            sha256: [0; 32],
        }));
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 1 << 16];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(Some(Fingerprint {
        len: actual,
        sha256: hasher.finalize().into(),
    }))
}

fn context(error: io::Error, what: &str) -> io::Error {
    io::Error::new(error.kind(), format!("{what}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "rosetun-engine-copy-{name}-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir_all(dir.join("app")).unwrap();
        fs::create_dir_all(dir.join(DIR)).unwrap();
        dir
    }

    fn no_acl(_: &Path) -> io::Result<()> {
        Ok(())
    }

    fn plain_copy(from: &Path, to: &Path) -> io::Result<()> {
        fs::copy(from, to).map(drop)
    }

    fn print(bytes: &[u8]) -> Fingerprint {
        Fingerprint {
            len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
        }
    }

    #[test]
    fn an_identical_copy_is_kept() {
        assert!(!needs_copy(&print(b"engine"), Some(&print(b"engine"))));
    }

    #[test]
    fn a_different_copy_is_replaced() {
        assert!(needs_copy(&print(b"engine"), Some(&print(b"other!"))));
        assert!(needs_copy(&print(b"engine"), Some(&print(b"older engine"))));
    }

    #[test]
    fn a_missing_copy_is_made() {
        assert!(needs_copy(&print(b"engine"), None));
    }

    #[test]
    fn a_copy_of_a_different_length_is_not_hashed() {
        let dir = temp_dir("length");
        let path = dir.join(DIR).join("sing-box.exe");
        fs::write(&path, b"old").unwrap();
        let copy = fingerprint_if_len(&path, Some(6)).unwrap().unwrap();
        assert_eq!(copy.len, 3);
        assert!(needs_copy(&print(b"engine"), Some(&copy)));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_stale_copy_is_replaced_with_the_installed_engine() {
        let dir = temp_dir("stale");
        let source = dir.join("app").join("sing-box.exe");
        fs::write(&source, b"new engine").unwrap();
        fs::write(dir.join(DIR).join("sing-box.exe"), b"old engine").unwrap();
        let copy = refresh(&source, &dir.join(DIR), no_acl, plain_copy).unwrap();
        assert_eq!(copy, dir.join(DIR).join("sing-box.exe"));
        assert_eq!(fs::read(&copy).unwrap(), b"new engine");
        assert!(!dir.join(DIR).join("sing-box.exe.tmp").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_copy_that_does_not_match_the_source_is_removed_and_fails() {
        let dir = temp_dir("mismatch");
        let source = dir.join("app").join("sing-box.exe");
        fs::write(&source, b"new engine").unwrap();
        let result = refresh(&source, &dir.join(DIR), no_acl, |_, to| {
            fs::write(to, b"bad engine")
        });
        assert!(result.is_err());
        assert!(!dir.join(DIR).join("sing-box.exe").exists());
        assert!(!dir.join(DIR).join("sing-box.exe.tmp").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_failed_copy_is_an_error_and_leaves_no_runnable_copy() {
        let dir = temp_dir("failed");
        let source = dir.join("app").join("sing-box.exe");
        fs::write(&source, b"new engine").unwrap();
        let result = refresh(&source, &dir.join(DIR), no_acl, |_, _| {
            Err(io::Error::from(io::ErrorKind::StorageFull))
        });
        assert!(result.is_err());
        assert!(!dir.join(DIR).join("sing-box.exe").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_copy_that_cannot_be_protected_fails() {
        let dir = temp_dir("acl");
        let source = dir.join("app").join("sing-box.exe");
        fs::write(&source, b"new engine").unwrap();
        let result = refresh(
            &source,
            &dir.join(DIR),
            |_| Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            plain_copy,
        );
        assert!(result.is_err());
        assert!(!dir.join(DIR).join("sing-box.exe").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_missing_installed_engine_fails() {
        let dir = temp_dir("missing");
        let result = refresh(
            &dir.join("app").join("sing-box.exe"),
            &dir.join(DIR),
            no_acl,
            plain_copy,
        );
        assert!(result.is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
