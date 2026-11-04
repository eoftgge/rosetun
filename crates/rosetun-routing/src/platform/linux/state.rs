//! Lockdown's record on disk (Linux). The nftables table lives in the kernel
//! and is gone after a reboot; this file is what says Lockdown is on, read
//! by the boot unit before any network comes up and by the service at start.
//!
//! The format is strict and versioned, three lines:
//!
//! ```text
//! rosetun lockdown 1
//! allow_lan=no
//! private_networks=no
//! ```
//!
//! Anything else is corrupt, and a corrupt record keeps the network closed:
//! it is read as Lockdown without "Local network". Only a missing file means
//! Lockdown is off.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// Where the service and the boot unit keep the record: the service's
/// state directory, root only.
pub(crate) const STATE_FILE: &str = "/var/lib/rosetun/lockdown";

const HEADER: &str = "rosetun lockdown 1";
/// Far more than the three lines take; a bigger file is not ours.
const MAX_BYTES: u64 = 256;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Saved {
    pub(crate) allow_lan: bool,
    /// Only with `allow_lan`.
    pub(crate) private_networks: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Stored {
    Missing,
    Saved(Saved),
    /// There is a record, but it cannot be trusted or read: Lockdown is on,
    /// without "Local network".
    Corrupt(String),
}

impl Stored {
    /// What the network gets: `None` only without a record.
    pub(crate) fn lockdown(&self) -> Option<Saved> {
        match self {
            Self::Missing => None,
            Self::Saved(saved) => Some(*saved),
            Self::Corrupt(_) => Some(Saved::default()),
        }
    }
}

pub(crate) fn render(saved: Saved) -> String {
    let word = |value: bool| if value { "yes" } else { "no" };
    format!(
        "{HEADER}\nallow_lan={}\nprivate_networks={}\n",
        word(saved.allow_lan),
        word(saved.allow_lan && saved.private_networks)
    )
}

pub(crate) fn parse(text: &str) -> Result<Saved, String> {
    let body = text
        .strip_suffix('\n')
        .ok_or_else(|| "the record does not end with a newline".to_owned())?;
    let lines: Vec<&str> = body.split('\n').collect();
    let [header, allow_lan, private_networks] = lines.as_slice() else {
        return Err(format!("the record has {} lines, not 3", lines.len()));
    };
    if *header != HEADER {
        return Err("the record has an unknown header or version".to_owned());
    }
    let value = |line: &str, key: &str| -> Result<bool, String> {
        match line
            .strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
        {
            Some("yes") => Ok(true),
            Some("no") => Ok(false),
            _ => Err(format!("the record has no valid {key} line")),
        }
    };
    let saved = Saved {
        allow_lan: value(allow_lan, "allow_lan")?,
        private_networks: value(private_networks, "private_networks")?,
    };
    if saved.private_networks && !saved.allow_lan {
        return Err("private networks are on without the local network".to_owned());
    }
    Ok(saved)
}

/// Reads the record. It must be a regular file (not a link), owned by the
/// account reading it (root, for the service and the boot unit), and
/// writable or readable by nobody else.
pub(crate) fn read(path: &Path) -> Stored {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Stored::Missing,
        Err(error) => return Stored::Corrupt(format!("cannot open the record: {error}")),
    };
    match read_trusted(&file) {
        Ok(text) => parse(&text).map_or_else(Stored::Corrupt, Stored::Saved),
        Err(reason) => Stored::Corrupt(reason),
    }
}

fn read_trusted(file: &File) -> Result<String, String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect the record: {error}"))?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let owner = unsafe { libc::geteuid() };
    if !metadata.is_file() || metadata.uid() != owner || metadata.mode() & 0o077 != 0 {
        return Err("the record has an unsafe type, owner or mode".to_owned());
    }
    if metadata.len() > MAX_BYTES {
        return Err("the record is too large".to_owned());
    }
    let mut text = String::new();
    file.take(MAX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|error| format!("cannot read the record: {error}"))?;
    Ok(text)
}

/// Replaces the record atomically: a private temporary file beside it,
/// flushed, renamed over it, and the folder flushed, so a power cut leaves
/// the old record or the new one.
pub(crate) fn write(path: &Path, saved: Saved) -> io::Result<()> {
    let folder = folder(path)?;
    let temporary = path.with_extension("new");
    // A temporary file left by a power cut in the middle of a write.
    match std::fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(render(saved).as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result?;
    File::open(folder)?.sync_all()
}

/// Removes the record; returns whether there was one.
pub(crate) fn remove(path: &Path) -> io::Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    }
    File::open(folder(path)?)?.sync_all()?;
    Ok(true)
}

fn folder(path: &Path) -> io::Result<&Path> {
    path.parent()
        .ok_or_else(|| io::Error::other("the Lockdown record has no folder"))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Folder(PathBuf);

    impl Folder {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "rosetun-lockdown-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn record(&self) -> PathBuf {
            self.0.join("lockdown")
        }
    }

    impl Drop for Folder {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn every_record_reads_back_as_written() {
        for (allow_lan, private_networks) in [(false, false), (true, false), (true, true)] {
            let saved = Saved {
                allow_lan,
                private_networks,
            };
            assert_eq!(parse(&render(saved)), Ok(saved));
        }
        assert_eq!(
            render(Saved {
                allow_lan: false,
                private_networks: true
            }),
            "rosetun lockdown 1\nallow_lan=no\nprivate_networks=no\n"
        );
    }

    #[test]
    fn anything_but_the_exact_format_is_corrupt() {
        let good = "rosetun lockdown 1\nallow_lan=yes\nprivate_networks=no\n";
        assert!(parse(good).is_ok());
        for (what, text) in [
            ("empty", String::new()),
            ("no final newline", good.trim_end().to_owned()),
            ("another version", good.replace(" 1\n", " 2\n")),
            ("CRLF", good.replace('\n', "\r\n")),
            ("a value in capitals", good.replace("=yes", "=YES")),
            ("a space", good.replace("allow_lan=", "allow_lan =")),
            ("a missing line", good.replace("private_networks=no\n", "")),
            ("an extra line", format!("{good}extra=no\n")),
            (
                "swapped lines",
                "rosetun lockdown 1\nprivate_networks=no\nallow_lan=yes\n".to_owned(),
            ),
            (
                "private networks alone",
                good.replace("allow_lan=yes", "allow_lan=no")
                    .replace("private_networks=no", "private_networks=yes"),
            ),
            ("a blank line", good.replace("\nallow", "\n\nallow")),
        ] {
            assert!(parse(&text).is_err(), "{what}");
        }
    }

    #[test]
    fn a_corrupt_record_closes_the_network_without_the_local_network() {
        assert_eq!(Stored::Missing.lockdown(), None);
        assert_eq!(
            Stored::Corrupt("x".to_owned()).lockdown(),
            Some(Saved::default())
        );
    }

    #[test]
    fn a_written_record_is_private_and_reads_back() {
        let folder = Folder::new();
        let path = folder.record();
        assert_eq!(read(&path), Stored::Missing);
        let saved = Saved {
            allow_lan: true,
            private_networks: true,
        };
        write(&path, saved).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(read(&path), Stored::Saved(saved));
        write(&path, Saved::default()).unwrap();
        assert_eq!(read(&path), Stored::Saved(Saved::default()));
        assert!(!path.with_extension("new").exists());
        assert!(remove(&path).unwrap());
        assert!(!remove(&path).unwrap());
        assert_eq!(read(&path), Stored::Missing);
    }

    #[test]
    fn a_leftover_temporary_file_does_not_stop_a_write() {
        let folder = Folder::new();
        let path = folder.record();
        std::fs::write(path.with_extension("new"), "half").unwrap();
        write(&path, Saved::default()).unwrap();
        assert_eq!(read(&path), Stored::Saved(Saved::default()));
    }

    #[test]
    fn a_record_others_could_write_or_a_link_is_corrupt() {
        let folder = Folder::new();
        let path = folder.record();
        write(&path, Saved::default()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(read(&path), Stored::Corrupt(_)));

        let target = folder.0.join("target");
        std::fs::write(&target, render(Saved::default())).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(matches!(read(&path), Stored::Corrupt(_)));

        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(matches!(read(&path), Stored::Corrupt(_)));
    }

    #[test]
    fn a_record_of_garbage_is_corrupt() {
        let folder = Folder::new();
        let path = folder.record();
        std::fs::write(&path, vec![b'x'; 1000]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(read(&path), Stored::Corrupt(_)));
    }
}
