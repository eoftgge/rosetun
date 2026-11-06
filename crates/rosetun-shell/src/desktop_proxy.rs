//! The desktop's proxy settings: pointing them at the local proxy, and putting
//! back what the user had.
//!
//! The settings belong to the user's session, so the GUI changes them, not the
//! service. What was there before is written to a file first, so that a crash
//! or a power cut loses nothing: the next start finds the file and restores it.
//! Settings that are no longer ours were changed by someone else on purpose,
//! and stay as they are.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

/// Addresses that never go through the proxy, in the desktop's own words: this
/// computer and the private networks, as other clients set it.
pub(crate) const LOOPBACK_V4: &str = "127.0.0.1";

/// What a desktop keeps of its proxy settings, as read before the change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SavedSettings {
    #[cfg(windows)]
    WinInet(crate::wininet::Saved),
    /// Stands in for a real backend's settings in tests.
    #[cfg(test)]
    Fake(String),
}

/// One desktop's proxy settings.
pub(crate) trait Backend: Send {
    fn read(&self) -> io::Result<SavedSettings>;
    /// Points the settings at the local proxy on `port`.
    fn apply(&self, port: u16) -> io::Result<()>;
    fn write_back(&self, saved: &SavedSettings) -> io::Result<()>;
    /// Whether the settings point at the local proxy on `port` now.
    fn holds_ours(&self, port: u16) -> io::Result<bool>;
}

/// The record of a change, kept until it is undone.
#[derive(Debug, Serialize, Deserialize)]
struct Record {
    port: u16,
    saved: SavedSettings,
}

/// How `DesktopProxy::set` left things.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxySet {
    /// The desktop's settings point at the proxy.
    Applied,
    /// This desktop has no settings Rosetun can change: the user sets them.
    Manual,
}

/// How `DesktopProxy::restore` left things.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyRestore {
    /// No change of ours was waiting.
    Nothing,
    Restored,
    /// The settings were changed by someone else since, and stay.
    LeftAsTheyAre,
}

/// The desktop's proxy settings and the record of Rosetun's change to them.
pub struct DesktopProxy {
    backend: Option<Box<dyn Backend>>,
    record: PathBuf,
}

impl std::fmt::Debug for DesktopProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DesktopProxy")
            .field("automatic", &self.backend.is_some())
            .finish_non_exhaustive()
    }
}

impl DesktopProxy {
    /// `record` lives next to the configuration.
    pub fn new(record: PathBuf) -> Self {
        Self {
            backend: default_backend(),
            record,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_backend(backend: Box<dyn Backend>, record: PathBuf) -> Self {
        Self {
            backend: Some(backend),
            record,
        }
    }

    /// Whether Rosetun can change this desktop's settings.
    pub fn automatic(&self) -> bool {
        self.backend.is_some()
    }

    /// Points the desktop at the local proxy. The record goes first: a crash
    /// between the two leaves it to restore settings that did not change yet,
    /// which is harmless, while the other order could lose them.
    pub fn set(&self, port: u16) -> io::Result<ProxySet> {
        let Some(backend) = self.backend.as_ref() else {
            return Ok(ProxySet::Manual);
        };
        let saved = match self.read_record() {
            // Still ours from an earlier set, so the record holds the user's
            // settings and the current ones are only ours.
            Some(record) if backend.holds_ours(record.port)? => record.saved,
            // The user changed them since: these are the ones to come back to.
            _ => backend.read()?,
        };
        self.write_record(&Record {
            port,
            saved: saved.clone(),
        })?;
        if let Err(error) = backend.apply(port) {
            // Nothing of ours is in place, unless a part of it went through.
            if let Err(restore) = backend.write_back(&saved) {
                tracing::warn!(error = %restore, "could not undo a failed proxy change");
            }
            self.remove_record();
            return Err(error);
        }
        tracing::info!("the desktop's proxy points at the local proxy");
        Ok(ProxySet::Applied)
    }

    /// Puts the user's settings back if the current ones are still ours, and
    /// forgets the change either way. Safe to repeat. A record that cannot be
    /// read is dropped: nothing in it can be trusted to write back.
    pub fn restore(&self) -> io::Result<ProxyRestore> {
        let Some(backend) = self.backend.as_ref() else {
            return Ok(ProxyRestore::Nothing);
        };
        let Some(record) = self.read_record() else {
            self.remove_record();
            return Ok(ProxyRestore::Nothing);
        };
        if !backend.holds_ours(record.port)? {
            self.remove_record();
            tracing::info!("the desktop's proxy changed outside Rosetun and stays as it is");
            return Ok(ProxyRestore::LeftAsTheyAre);
        }
        backend.write_back(&record.saved)?;
        self.remove_record();
        tracing::info!("the desktop's proxy is back as it was");
        Ok(ProxyRestore::Restored)
    }

    fn read_record(&self) -> Option<Record> {
        let bytes = match std::fs::read(&self.record) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "could not read the desktop proxy record");
                return None;
            }
        };
        // Serde's message could quote the settings, which are the user's.
        serde_json::from_slice(&bytes)
            .inspect_err(|_| tracing::warn!("the desktop proxy record is damaged"))
            .ok()
    }

    fn write_record(&self, record: &Record) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(record).map_err(io::Error::other)?;
        write_atomically(&self.record, &bytes)
    }

    fn remove_record(&self) {
        if let Err(error) = std::fs::remove_file(&self.record)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(kind = ?error.kind(), "could not remove the desktop proxy record");
        }
    }
}

/// Replaces `path` in one step, with data flushed first: the file is either the
/// old one or the whole new one, whenever the power goes.
pub(crate) fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "a path without a file name"))?;
    let mut temporary = name.to_owned();
    temporary.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let temporary = path.with_file_name(temporary);
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(windows)]
fn default_backend() -> Option<Box<dyn Backend>> {
    Some(Box::new(crate::wininet::WinInet))
}

#[cfg(not(windows))]
fn default_backend() -> Option<Box<dyn Backend>> {
    None
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// A desktop whose settings are a string; `ours:<port>` is the local proxy.
    #[derive(Clone, Default)]
    struct FakeDesktop {
        current: Arc<Mutex<String>>,
        fail_apply: Arc<Mutex<bool>>,
    }

    impl Backend for FakeDesktop {
        fn read(&self) -> io::Result<SavedSettings> {
            Ok(SavedSettings::Fake(self.current.lock().unwrap().clone()))
        }

        fn apply(&self, port: u16) -> io::Result<()> {
            if *self.fail_apply.lock().unwrap() {
                *self.current.lock().unwrap() = "half-written".to_owned();
                return Err(io::Error::other("refused"));
            }
            *self.current.lock().unwrap() = format!("ours:{port}");
            Ok(())
        }

        fn write_back(&self, saved: &SavedSettings) -> io::Result<()> {
            let SavedSettings::Fake(value) = saved else {
                unreachable!("only fake settings in these tests");
            };
            value.clone_into(&mut self.current.lock().unwrap());
            Ok(())
        }

        fn holds_ours(&self, port: u16) -> io::Result<bool> {
            Ok(*self.current.lock().unwrap() == format!("ours:{port}"))
        }
    }

    struct Fixture {
        desktop: FakeDesktop,
        directory: PathBuf,
        record: PathBuf,
    }

    impl Fixture {
        fn new(name: &str, settings: &str) -> Self {
            let directory = std::env::temp_dir().join(format!(
                "rosetun-desktop-proxy-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&directory);
            std::fs::create_dir_all(&directory).unwrap();
            let desktop = FakeDesktop::default();
            settings.clone_into(&mut desktop.current.lock().unwrap());
            Self {
                desktop,
                record: directory.join("desktop-proxy.json"),
                directory,
            }
        }

        fn proxy(&self) -> DesktopProxy {
            DesktopProxy::with_backend(Box::new(self.desktop.clone()), self.record.clone())
        }

        fn current(&self) -> String {
            self.desktop.current.lock().unwrap().clone()
        }

        fn change_by_hand(&self, value: &str) {
            value.clone_into(&mut self.desktop.current.lock().unwrap());
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn the_settings_come_back_as_they_were() {
        let fixture = Fixture::new("back", "pac:http://proxy.example.com/wpad.dat");
        let proxy = fixture.proxy();
        assert_eq!(proxy.set(10808).unwrap(), ProxySet::Applied);
        assert_eq!(fixture.current(), "ours:10808");
        assert!(fixture.record.exists());

        assert_eq!(proxy.restore().unwrap(), ProxyRestore::Restored);
        assert_eq!(fixture.current(), "pac:http://proxy.example.com/wpad.dat");
        assert!(!fixture.record.exists());
    }

    #[test]
    fn a_setting_changed_since_stays_and_the_record_goes() {
        let fixture = Fixture::new("foreign", "direct");
        let proxy = fixture.proxy();
        proxy.set(10808).unwrap();
        fixture.change_by_hand("manual:proxy.example.com:3128");

        assert_eq!(proxy.restore().unwrap(), ProxyRestore::LeftAsTheyAre);
        assert_eq!(fixture.current(), "manual:proxy.example.com:3128");
        assert!(!fixture.record.exists());
    }

    #[test]
    fn a_new_start_restores_what_a_crash_left() {
        let fixture = Fixture::new("crash", "direct");
        fixture.proxy().set(10808).unwrap();
        // The process is gone; only the file and the desktop remember.
        assert_eq!(fixture.proxy().restore().unwrap(), ProxyRestore::Restored);
        assert_eq!(fixture.current(), "direct");
    }

    #[test]
    fn a_second_set_keeps_the_users_settings_not_our_own() {
        let fixture = Fixture::new("twice", "direct");
        let proxy = fixture.proxy();
        proxy.set(10808).unwrap();
        proxy.set(10808).unwrap();
        proxy.set(20808).unwrap();
        assert_eq!(fixture.current(), "ours:20808");
        proxy.restore().unwrap();
        assert_eq!(fixture.current(), "direct");
    }

    #[test]
    fn a_set_after_a_change_by_hand_comes_back_to_that_change() {
        let fixture = Fixture::new("rehand", "direct");
        let proxy = fixture.proxy();
        proxy.set(10808).unwrap();
        fixture.change_by_hand("manual:proxy.example.com:3128");
        proxy.set(10808).unwrap();
        proxy.restore().unwrap();
        assert_eq!(fixture.current(), "manual:proxy.example.com:3128");
    }

    #[test]
    fn restoring_with_nothing_to_restore_changes_nothing() {
        let fixture = Fixture::new("nothing", "direct");
        let proxy = fixture.proxy();
        assert_eq!(proxy.restore().unwrap(), ProxyRestore::Nothing);
        assert_eq!(proxy.restore().unwrap(), ProxyRestore::Nothing);
        assert_eq!(fixture.current(), "direct");
    }

    #[test]
    fn a_failed_change_undoes_itself_and_leaves_no_record() {
        let fixture = Fixture::new("failed", "direct");
        *fixture.desktop.fail_apply.lock().unwrap() = true;
        let proxy = fixture.proxy();
        assert!(proxy.set(10808).is_err());
        assert_eq!(fixture.current(), "direct");
        assert!(!fixture.record.exists());
    }

    #[test]
    fn a_damaged_record_is_dropped_and_nothing_is_written_back() {
        let fixture = Fixture::new("damaged", "direct");
        let proxy = fixture.proxy();
        proxy.set(10808).unwrap();
        std::fs::write(&fixture.record, b"not json").unwrap();
        assert_eq!(proxy.restore().unwrap(), ProxyRestore::Nothing);
        assert_eq!(fixture.current(), "ours:10808");
        assert!(!fixture.record.exists());
    }

    #[test]
    fn a_desktop_without_automatic_settings_changes_nothing() {
        let fixture = Fixture::new("manual", "direct");
        let proxy = DesktopProxy {
            backend: None,
            record: fixture.record.clone(),
        };
        assert!(!proxy.automatic());
        assert_eq!(proxy.set(10808).unwrap(), ProxySet::Manual);
        assert_eq!(proxy.restore().unwrap(), ProxyRestore::Nothing);
        assert!(!fixture.record.exists());
    }

    #[test]
    fn writing_replaces_the_whole_file_and_leaves_no_temporary() {
        let fixture = Fixture::new("atomic", "direct");
        let path = fixture.directory.join("file");
        write_atomically(&path, b"first").unwrap();
        write_atomically(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        let names: Vec<_> = std::fs::read_dir(&fixture.directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["file"]);
    }
}
