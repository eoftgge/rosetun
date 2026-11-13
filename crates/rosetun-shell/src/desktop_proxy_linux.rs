//! The desktop's proxy settings on Linux: KDE Plasma's `kioslaverc` and GNOME's
//! `org.gnome.system.proxy`. Anywhere else the user points programs at the proxy.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zbus::blocking::Connection;

use crate::desktop_proxy::{Backend, LOOPBACK_V4, SavedSettings, write_atomically};

const KDE_GROUP: &str = "Proxy Settings";
/// `ProxyType=1` in KIO: the addresses below, by hand.
const KDE_MANUAL: &str = "1";
/// Every key Rosetun writes, and so every key it has to put back.
const KDE_KEYS: [&str; 6] = [
    "ProxyType",
    "httpProxy",
    "httpsProxy",
    "ftpProxy",
    "socksProxy",
    "NoProxyFor",
];
const NO_PROXY: &str = "localhost,127.0.0.0/8,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16";
/// The signal KIO's scheduler listens to (`kio/src/core/scheduler.cpp`), which
/// makes running KDE programs read the settings again. Programs that read the
/// file by themselves, as Chromium does, watch it instead.
const KIO_PATH: &str = "/KIO/Scheduler";
const KIO_INTERFACE: &str = "org.kde.KIO.Scheduler";
const KIO_SIGNAL: &str = "reparseSlaveConfiguration";

/// Absolute, so nothing on `PATH` decides what runs. dconf's writer takes
/// changes over D-Bus, but it has no reading side: the current values and the
/// schema's defaults are in a database file only GSettings reads, and restoring
/// needs them. This tool comes with every GNOME desktop.
const GSETTINGS: &str = "/usr/bin/gsettings";
const GNOME_SCHEMA: &str = "org.gnome.system.proxy";
const GNOME_TIMEOUT: Duration = Duration::from_secs(5);
const GNOME_IGNORE: &str =
    "['localhost', '127.0.0.0/8', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']";
/// `(schema, key)` of everything Rosetun writes.
const GNOME_KEYS: [(&str, &str); 8] = [
    (GNOME_SCHEMA, "mode"),
    (GNOME_SCHEMA, "ignore-hosts"),
    ("org.gnome.system.proxy.http", "host"),
    ("org.gnome.system.proxy.http", "port"),
    ("org.gnome.system.proxy.https", "host"),
    ("org.gnome.system.proxy.https", "port"),
    ("org.gnome.system.proxy.socks", "host"),
    ("org.gnome.system.proxy.socks", "port"),
];

/// The desktop as `XDG_CURRENT_DESKTOP` names it, a colon-separated list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Desktop {
    Kde,
    Gnome,
    Unknown,
}

pub(crate) fn desktop_from(current: Option<&str>) -> Desktop {
    let names = current.unwrap_or_default();
    if names
        .split(':')
        .any(|name| name.eq_ignore_ascii_case("KDE"))
    {
        Desktop::Kde
    } else if names
        .split(':')
        .any(|name| name.eq_ignore_ascii_case("GNOME"))
    {
        Desktop::Gnome
    } else {
        Desktop::Unknown
    }
}

/// `None` on a desktop whose settings Rosetun does not know.
pub(crate) fn backend() -> Option<Box<dyn Backend>> {
    let current = std::env::var("XDG_CURRENT_DESKTOP").ok();
    match desktop_from(current.as_deref()) {
        Desktop::Kde => Some(Box::new(Kde {
            file: kioslaverc_path()?,
        })),
        Desktop::Gnome if Path::new(GSETTINGS).exists() => Some(Box::new(Gnome {
            runner: SystemGsettings,
        })),
        Desktop::Gnome | Desktop::Unknown => None,
    }
}

pub(crate) fn kioslaverc_path() -> Option<PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(config.join("kioslaverc"))
}

/// What the KDE settings held for each of `KDE_KEYS`; `None` is a missing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SavedKde(Vec<(String, Option<String>)>);

/// KIO's own format: the scheme, the host, a space and the port.
fn kde_entries(port: u16) -> [(&'static str, String); 6] {
    let http = format!("http://{LOOPBACK_V4} {port}");
    [
        ("ProxyType", KDE_MANUAL.to_owned()),
        ("httpProxy", http.clone()),
        ("httpsProxy", http.clone()),
        ("ftpProxy", http),
        ("socksProxy", format!("socks://{LOOPBACK_V4} {port}")),
        ("NoProxyFor", NO_PROXY.to_owned()),
    ]
}

/// The value of `key` in `[group]`; KConfig's localized and `[$e]` forms of a key
/// are other keys, and stay as they are.
pub(crate) fn ini_get(text: &str, group: &str, key: &str) -> Option<String> {
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(name) = group_name(line) {
            inside = name == group;
        } else if inside
            && let Some((name, value)) = line.split_once('=')
            && name.trim() == key
        {
            return Some(value.trim().to_owned());
        }
    }
    None
}

fn group_name(line: &str) -> Option<&str> {
    line.strip_prefix('[')?.strip_suffix(']')
}

/// `text` with `changes` made in `[group]`: everything else, other programs' keys
/// and comments included, stays as it was. `None` removes a key.
fn ini_set(text: &str, group: &str, changes: &[(&str, Option<&str>)]) -> String {
    let mut output = String::with_capacity(text.len() + 128);
    let mut inside = false;
    let mut seen = false;
    let mut written = vec![false; changes.len()];
    let flush = |output: &mut String, written: &mut [bool]| {
        for (index, (key, value)) in changes.iter().enumerate() {
            if let (false, Some(value)) = (written[index], value) {
                output.push_str(key);
                output.push('=');
                output.push_str(value);
                output.push('\n');
            }
            written[index] = true;
        }
    };
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(name) = group_name(trimmed) {
            if inside {
                flush(&mut output, &mut written);
            }
            inside = name == group;
            seen |= inside;
        } else if inside
            && let Some((name, _)) = trimmed.split_once('=')
            && let Some(index) = changes.iter().position(|(key, _)| *key == name.trim())
        {
            if let (false, Some(value)) = (written[index], changes[index].1) {
                output.push_str(changes[index].0);
                output.push('=');
                output.push_str(value);
                output.push('\n');
            }
            written[index] = true;
            continue;
        }
        output.push_str(line);
        output.push('\n');
    }
    if inside {
        flush(&mut output, &mut written);
    }
    if !seen && changes.iter().any(|(_, value)| value.is_some()) {
        if !output.is_empty() && !output.ends_with("\n\n") {
            output.push('\n');
        }
        output.push('[');
        output.push_str(group);
        output.push_str("]\n");
        flush(&mut output, &mut written);
    }
    output
}

/// KDE Plasma's settings file.
pub(crate) struct Kde {
    file: PathBuf,
}

impl Kde {
    fn text(&self) -> io::Result<String> {
        match std::fs::read_to_string(&self.file) {
            Ok(text) => Ok(text),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
            Err(error) => Err(error),
        }
    }

    fn change(&self, changes: &[(&str, Option<&str>)]) -> io::Result<()> {
        let updated = ini_set(&self.text()?, KDE_GROUP, changes);
        write_atomically(&self.file, updated.as_bytes())?;
        announce_to_kde();
        Ok(())
    }
}

/// A failure only logs: the file is written, and programs read it when they next
/// start or look.
fn announce_to_kde() {
    let result = Connection::session().and_then(|connection| {
        connection.emit_signal(
            None::<&str>,
            KIO_PATH,
            KIO_INTERFACE,
            KIO_SIGNAL,
            &(String::new(),),
        )
    });
    if let Err(error) = result {
        tracing::warn!(%error, "could not tell KDE programs that the proxy changed");
    }
}

impl Backend for Kde {
    fn read(&self) -> io::Result<SavedSettings> {
        let text = self.text()?;
        let saved = KDE_KEYS
            .iter()
            .map(|key| ((*key).to_owned(), ini_get(&text, KDE_GROUP, key)))
            .collect();
        Ok(SavedSettings::Kde(SavedKde(saved)))
    }

    fn apply(&self, port: u16) -> io::Result<()> {
        let entries = kde_entries(port);
        let changes: Vec<(&str, Option<&str>)> = entries
            .iter()
            .map(|(key, value)| (*key, Some(value.as_str())))
            .collect();
        self.change(&changes)
    }

    fn write_back(&self, saved: &SavedSettings) -> io::Result<()> {
        let SavedSettings::Kde(SavedKde(values)) = saved else {
            return Err(io::Error::other("settings of another desktop"));
        };
        let changes: Vec<(&str, Option<&str>)> = values
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_deref()))
            .collect();
        self.change(&changes)
    }

    fn holds_ours(&self, port: u16) -> io::Result<bool> {
        let text = self.text()?;
        Ok(kde_entries(port)
            .iter()
            .take(2)
            .all(|(key, value)| ini_get(&text, KDE_GROUP, key).as_deref() == Some(value)))
    }
}

/// What GNOME's settings held, in the order of `GNOME_KEYS`, as GSettings prints
/// them, which is also how it takes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SavedGnome(Vec<String>);

/// Runs `gsettings`; a seam for tests.
pub(crate) trait Gsettings: Send {
    fn get(&self, schema: &str, key: &str) -> io::Result<String>;
    fn set(&self, schema: &str, key: &str, value: &str) -> io::Result<()>;
}

pub(crate) struct SystemGsettings;

impl SystemGsettings {
    fn run(arguments: &[&str]) -> io::Result<String> {
        let mut child = Command::new(GSETTINGS)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let deadline = std::time::Instant::now() + GNOME_TIMEOUT;
        loop {
            if child.try_wait()?.is_some() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(io::Error::other("gsettings refused the request"));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }
}

impl Gsettings for SystemGsettings {
    fn get(&self, schema: &str, key: &str) -> io::Result<String> {
        Self::run(&["get", schema, key])
    }

    fn set(&self, schema: &str, key: &str, value: &str) -> io::Result<()> {
        Self::run(&["set", schema, key, value]).map(drop)
    }
}

/// `org.gnome.system.proxy`.
pub(crate) struct Gnome<G> {
    runner: G,
}

fn gnome_values(port: u16) -> [String; 8] {
    let host = format!("'{LOOPBACK_V4}'");
    let port = port.to_string();
    [
        "'manual'".to_owned(),
        GNOME_IGNORE.to_owned(),
        host.clone(),
        port.clone(),
        host.clone(),
        port.clone(),
        host,
        port,
    ]
}

impl<G: Gsettings> Backend for Gnome<G> {
    fn read(&self) -> io::Result<SavedSettings> {
        let values = GNOME_KEYS
            .iter()
            .map(|(schema, key)| self.runner.get(schema, key))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(SavedSettings::Gnome(SavedGnome(values)))
    }

    /// The mode last: until then nobody is using what is being written.
    fn apply(&self, port: u16) -> io::Result<()> {
        let values = gnome_values(port);
        for ((schema, key), value) in GNOME_KEYS.iter().zip(&values).rev() {
            self.runner.set(schema, key, value)?;
        }
        // Without a running dconf service `gsettings set` succeeds into a store that
        // dies with the command; reading back is the only way to tell.
        if self.holds_ours(port)? {
            Ok(())
        } else {
            Err(io::Error::other(
                "the desktop did not keep the proxy settings",
            ))
        }
    }

    /// The mode first, for the same reason.
    fn write_back(&self, saved: &SavedSettings) -> io::Result<()> {
        let SavedSettings::Gnome(SavedGnome(values)) = saved else {
            return Err(io::Error::other("settings of another desktop"));
        };
        for ((schema, key), value) in GNOME_KEYS.iter().zip(values) {
            self.runner.set(schema, key, value)?;
        }
        Ok(())
    }

    fn holds_ours(&self, port: u16) -> io::Result<bool> {
        let values = gnome_values(port);
        for index in [0, 2, 3] {
            let (schema, key) = GNOME_KEYS[index];
            if self.runner.get(schema, key)? != values[index] {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::desktop_proxy::{DesktopProxy, ProxyRestore, ProxySet};

    const SAMPLE: &str = "\
# A comment of the user's
[Cookie Policy]
Enabled=true

[Proxy Settings]
Proxy Config Script=http://proxy.example.com/wpad.dat
ProxyType=2
httpProxy=http://proxy.example.com 3128
NoProxyFor[$e]=$HOME
AuthMode=0

[UserAgent]
SendLanguageSettings=false
";

    fn scratch(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "rosetun-desktop-proxy-linux-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn the_desktop_is_read_from_its_list_of_names() {
        assert_eq!(desktop_from(Some("KDE")), Desktop::Kde);
        assert_eq!(desktop_from(Some("ubuntu:GNOME")), Desktop::Gnome);
        assert_eq!(desktop_from(Some("gnome-classic:GNOME")), Desktop::Gnome);
        assert_eq!(desktop_from(Some("XFCE")), Desktop::Unknown);
        assert_eq!(desktop_from(Some("")), Desktop::Unknown);
        assert_eq!(desktop_from(None), Desktop::Unknown);
    }

    #[test]
    fn writing_keeps_every_other_key_comment_and_group() {
        let updated = ini_set(
            SAMPLE,
            KDE_GROUP,
            &[
                ("ProxyType", Some("1")),
                ("socksProxy", Some("socks://127.0.0.1 10808")),
            ],
        );
        assert_eq!(
            ini_get(&updated, KDE_GROUP, "ProxyType").as_deref(),
            Some("1")
        );
        assert_eq!(
            ini_get(&updated, KDE_GROUP, "socksProxy").as_deref(),
            Some("socks://127.0.0.1 10808")
        );
        for kept in [
            "# A comment of the user's",
            "[Cookie Policy]",
            "Enabled=true",
            "Proxy Config Script=http://proxy.example.com/wpad.dat",
            "httpProxy=http://proxy.example.com 3128",
            "NoProxyFor[$e]=$HOME",
            "AuthMode=0",
            "[UserAgent]",
            "SendLanguageSettings=false",
        ] {
            assert!(updated.contains(kept), "{kept} is gone:\n{updated}");
        }
        assert_eq!(updated.matches("[Proxy Settings]").count(), 1);
        // The new key stays in its own group.
        let group_end = updated.find("[UserAgent]").unwrap();
        assert!(updated.find("socksProxy").unwrap() < group_end);
    }

    #[test]
    fn a_missing_file_or_group_gets_the_group() {
        let updated = ini_set("", KDE_GROUP, &[("ProxyType", Some("1"))]);
        assert_eq!(updated, "[Proxy Settings]\nProxyType=1\n");
        let updated = ini_set("[Other]\nA=1\n", KDE_GROUP, &[("ProxyType", Some("1"))]);
        assert_eq!(updated, "[Other]\nA=1\n\n[Proxy Settings]\nProxyType=1\n");
        assert_eq!(ini_set("", KDE_GROUP, &[("ProxyType", None)]), "");
    }

    #[test]
    fn a_key_elsewhere_or_with_another_form_is_not_this_key() {
        let text = "[Other]\nProxyType=9\n[Proxy Settings]\nNoProxyFor[$e]=$HOME\n";
        assert_eq!(ini_get(text, KDE_GROUP, "ProxyType"), None);
        assert_eq!(ini_get(text, KDE_GROUP, "NoProxyFor"), None);
        let updated = ini_set(text, KDE_GROUP, &[("ProxyType", None)]);
        assert!(updated.contains("[Other]\nProxyType=9\n"));
    }

    #[test]
    fn kde_values_follow_kios_format() {
        let entries = kde_entries(10808);
        let value = |key: &str| {
            entries
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(value("ProxyType"), Some("1"));
        assert_eq!(value("httpProxy"), Some("http://127.0.0.1 10808"));
        assert_eq!(value("httpsProxy"), Some("http://127.0.0.1 10808"));
        assert_eq!(value("socksProxy"), Some("socks://127.0.0.1 10808"));
        assert!(value("NoProxyFor").unwrap().contains("192.168.0.0/16"));
    }

    #[test]
    fn kde_settings_come_back_and_other_keys_never_move() {
        let root = scratch("kde-back");
        let file = root.join("kioslaverc");
        std::fs::write(&file, SAMPLE).unwrap();
        let proxy = DesktopProxy::with_backend(
            Box::new(Kde { file: file.clone() }),
            root.join("record.json"),
        );

        assert_eq!(proxy.set(10808).unwrap(), ProxySet::Applied);
        let during = std::fs::read_to_string(&file).unwrap();
        assert_eq!(
            ini_get(&during, KDE_GROUP, "ProxyType").as_deref(),
            Some("1")
        );
        assert!(during.contains("SendLanguageSettings=false"));

        assert_eq!(proxy.restore().unwrap(), ProxyRestore::Restored);
        let after = std::fs::read_to_string(&file).unwrap();
        assert_eq!(
            ini_get(&after, KDE_GROUP, "ProxyType").as_deref(),
            Some("2")
        );
        assert_eq!(
            ini_get(&after, KDE_GROUP, "httpProxy").as_deref(),
            Some("http://proxy.example.com 3128")
        );
        for key in ["httpsProxy", "ftpProxy", "socksProxy", "NoProxyFor"] {
            assert_eq!(ini_get(&after, KDE_GROUP, key), None, "{key}");
        }
        assert!(after.contains("Proxy Config Script=http://proxy.example.com/wpad.dat"));
        assert!(after.contains("NoProxyFor[$e]=$HOME"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn kde_settings_changed_since_stay() {
        let root = scratch("kde-foreign");
        let file = root.join("kioslaverc");
        let proxy = DesktopProxy::with_backend(
            Box::new(Kde { file: file.clone() }),
            root.join("record.json"),
        );
        proxy.set(10808).unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        let changed = ini_set(
            &text,
            KDE_GROUP,
            &[("httpProxy", Some("http://proxy.example.com 3128"))],
        );
        std::fs::write(&file, &changed).unwrap();

        assert_eq!(proxy.restore().unwrap(), ProxyRestore::LeftAsTheyAre);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), changed);
        assert!(!root.join("record.json").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_new_start_restores_kde_settings_after_a_crash() {
        let root = scratch("kde-crash");
        let file = root.join("kioslaverc");
        std::fs::write(&file, SAMPLE).unwrap();
        let record = root.join("record.json");
        DesktopProxy::with_backend(Box::new(Kde { file: file.clone() }), record.clone())
            .set(10808)
            .unwrap();
        let again = DesktopProxy::with_backend(Box::new(Kde { file: file.clone() }), record);
        assert_eq!(again.restore().unwrap(), ProxyRestore::Restored);
        let after = std::fs::read_to_string(&file).unwrap();
        assert_eq!(
            ini_get(&after, KDE_GROUP, "ProxyType").as_deref(),
            Some("2")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[derive(Clone, Default)]
    struct FakeGsettings {
        values: Arc<Mutex<HashMap<(String, String), String>>>,
        order: Arc<Mutex<Vec<String>>>,
    }

    impl Gsettings for FakeGsettings {
        fn get(&self, schema: &str, key: &str) -> io::Result<String> {
            Ok(self
                .values
                .lock()
                .unwrap()
                .get(&(schema.to_owned(), key.to_owned()))
                .cloned()
                .unwrap_or_else(|| "''".to_owned()))
        }

        fn set(&self, schema: &str, key: &str, value: &str) -> io::Result<()> {
            self.order.lock().unwrap().push(format!("{schema} {key}"));
            self.values
                .lock()
                .unwrap()
                .insert((schema.to_owned(), key.to_owned()), value.to_owned());
            Ok(())
        }
    }

    #[test]
    fn gnome_settings_turn_on_last_off_first_and_come_back() {
        let root = scratch("gnome");
        let runner = FakeGsettings::default();
        runner.set(GNOME_SCHEMA, "mode", "'auto'").unwrap();
        runner
            .set(GNOME_SCHEMA, "ignore-hosts", "['intranet.example.com']")
            .unwrap();
        runner.order.lock().unwrap().clear();
        let proxy = DesktopProxy::with_backend(
            Box::new(Gnome {
                runner: runner.clone(),
            }),
            root.join("record.json"),
        );

        assert_eq!(proxy.set(10808).unwrap(), ProxySet::Applied);
        assert_eq!(runner.get(GNOME_SCHEMA, "mode").unwrap(), "'manual'");
        assert_eq!(
            runner.get("org.gnome.system.proxy.socks", "port").unwrap(),
            "10808"
        );
        assert_eq!(
            runner.order.lock().unwrap().last().unwrap(),
            "org.gnome.system.proxy mode"
        );

        runner.order.lock().unwrap().clear();
        assert_eq!(proxy.restore().unwrap(), ProxyRestore::Restored);
        assert_eq!(runner.get(GNOME_SCHEMA, "mode").unwrap(), "'auto'");
        assert_eq!(
            runner.get(GNOME_SCHEMA, "ignore-hosts").unwrap(),
            "['intranet.example.com']"
        );
        assert_eq!(
            runner.order.lock().unwrap().first().unwrap(),
            "org.gnome.system.proxy mode"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_new_start_restores_gnome_settings_after_a_crash() {
        let root = scratch("gnome-crash");
        let runner = FakeGsettings::default();
        runner.set(GNOME_SCHEMA, "mode", "'auto'").unwrap();
        let record = root.join("record.json");
        DesktopProxy::with_backend(
            Box::new(Gnome {
                runner: runner.clone(),
            }),
            record.clone(),
        )
        .set(10808)
        .unwrap();
        // The process is gone; a new one finds the record and nothing else.
        let again = DesktopProxy::with_backend(
            Box::new(Gnome {
                runner: runner.clone(),
            }),
            record.clone(),
        );
        assert_eq!(again.restore().unwrap(), ProxyRestore::Restored);
        assert_eq!(runner.get(GNOME_SCHEMA, "mode").unwrap(), "'auto'");
        assert!(!record.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn setting_gnome_twice_still_comes_back_to_the_users_own() {
        let root = scratch("gnome-twice");
        let runner = FakeGsettings::default();
        runner.set(GNOME_SCHEMA, "mode", "'auto'").unwrap();
        let proxy = DesktopProxy::with_backend(
            Box::new(Gnome {
                runner: runner.clone(),
            }),
            root.join("record.json"),
        );
        proxy.set(10808).unwrap();
        proxy.set(10809).unwrap();
        assert_eq!(proxy.restore().unwrap(), ProxyRestore::Restored);
        assert_eq!(runner.get(GNOME_SCHEMA, "mode").unwrap(), "'auto'");
        std::fs::remove_dir_all(root).unwrap();
    }

    /// Writes that the desktop forgets, as `gsettings` does without a dconf service.
    struct Forgetful(FakeGsettings);

    impl Gsettings for Forgetful {
        fn get(&self, schema: &str, key: &str) -> io::Result<String> {
            self.0.get(schema, key)
        }

        fn set(&self, _: &str, _: &str, _: &str) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn gnome_settings_that_the_desktop_does_not_keep_are_an_error_with_nothing_left_behind() {
        let root = scratch("gnome-forgetful");
        let record = root.join("record.json");
        let proxy = DesktopProxy::with_backend(
            Box::new(Gnome {
                runner: Forgetful(FakeGsettings::default()),
            }),
            record.clone(),
        );
        assert!(proxy.set(10808).is_err());
        assert!(!record.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A tool that stops answering after a few calls.
    struct Breaking {
        inner: FakeGsettings,
        calls: Mutex<usize>,
        allowed: usize,
    }

    impl Gsettings for Breaking {
        fn get(&self, schema: &str, key: &str) -> io::Result<String> {
            self.inner.get(schema, key)
        }

        fn set(&self, schema: &str, key: &str, value: &str) -> io::Result<()> {
            let mut calls = self.calls.lock().unwrap();
            *calls += 1;
            if *calls > self.allowed {
                return Err(io::Error::other("gsettings refused the request"));
            }
            self.inner.set(schema, key, value)
        }
    }

    #[test]
    fn a_failure_half_way_through_gnome_puts_the_users_settings_back() {
        let root = scratch("gnome-half");
        let inner = FakeGsettings::default();
        inner.set(GNOME_SCHEMA, "mode", "'auto'").unwrap();
        let record = root.join("record.json");
        let proxy = DesktopProxy::with_backend(
            Box::new(Gnome {
                runner: Breaking {
                    inner: inner.clone(),
                    calls: Mutex::new(0),
                    // The first writes go in, then the tool stops, undo included.
                    allowed: 3,
                },
            }),
            record.clone(),
        );
        assert!(proxy.set(10808).is_err());
        // Mode is written last, so the half-written change never took effect.
        assert_eq!(inner.get(GNOME_SCHEMA, "mode").unwrap(), "'auto'");
        assert!(!record.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn gnome_settings_changed_since_stay() {
        let root = scratch("gnome-foreign");
        let runner = FakeGsettings::default();
        let proxy = DesktopProxy::with_backend(
            Box::new(Gnome {
                runner: runner.clone(),
            }),
            root.join("record.json"),
        );
        proxy.set(10808).unwrap();
        runner.set(GNOME_SCHEMA, "mode", "'none'").unwrap();
        assert_eq!(proxy.restore().unwrap(), ProxyRestore::LeftAsTheyAre);
        assert_eq!(runner.get(GNOME_SCHEMA, "mode").unwrap(), "'none'");
        std::fs::remove_dir_all(root).unwrap();
    }
}
