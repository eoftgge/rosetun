//! What the system check can see on a Linux desktop without any rights: a proxy set in
//! the desktop (KDE's `kioslaverc`, GNOME's `org.gnome.system.proxy`) or in the session's
//! environment, and a program holding a netfilter queue (what Zapret's `nfqws` does).
//! Whatever else is in the firewall is the service's to read; see the helper.

use std::io;
use std::path::Path;

use crate::desktop_proxy_linux::{
    Desktop, Gsettings, SystemGsettings, desktop_from, ini_get, kioslaverc_path,
};

/// Kernel's list of bound user-space queues, one line per queue, readable by anyone.
const NFQUEUE: &str = "/proc/net/netfilter/nfnetlink_queue";
const KDE_GROUP: &str = "Proxy Settings";
const GNOME_SCHEMA: &str = "org.gnome.system.proxy";
/// The variables programs read, in the order they look at them.
const ENVIRONMENT: [&str; 6] = [
    "https_proxy",
    "HTTPS_PROXY",
    "http_proxy",
    "HTTP_PROXY",
    "all_proxy",
    "ALL_PROXY",
];

/// `(enabled, server, auto_config)` as the Windows check reads them: `enabled` is
/// `Some(1)` for a proxy set by hand.
pub fn proxy_settings() -> io::Result<(Option<u32>, Option<String>, Option<String>)> {
    let current = std::env::var("XDG_CURRENT_DESKTOP").ok();
    let from_desktop = match desktop_from(current.as_deref()) {
        Desktop::Kde => kioslaverc_path()
            .and_then(|path| std::fs::read_to_string(path).ok())
            .map(|text| kde_proxy(&text)),
        Desktop::Gnome => gnome_proxy(&SystemGsettings).ok(),
        Desktop::Unknown => None,
    };
    match from_desktop {
        Some(found) if found != (None, None, None) => Ok(found),
        _ => Ok(environment_proxy(|name| std::env::var(name).ok())),
    }
}

/// KIO: `ProxyType` 1 is by hand, 2 is a script, 3 and 4 find one by themselves.
fn kde_proxy(text: &str) -> (Option<u32>, Option<String>, Option<String>) {
    let get = |key| ini_get(text, KDE_GROUP, key).filter(|value| !value.is_empty());
    match get("ProxyType").as_deref() {
        Some("1") => {
            let server = ["httpsProxy", "httpProxy", "socksProxy"]
                .into_iter()
                .find_map(get)
                .map(|value| kio_address(&value));
            (Some(1), server, None)
        }
        Some("2") => (
            None,
            None,
            get("Proxy Config Script").map(|url| strip_user(&url)),
        ),
        Some("3" | "4") => (None, None, Some("automatic".to_owned())),
        _ => (None, None, None),
    }
}

/// KIO writes `scheme://host port`; the address everyone else writes is `host:port`.
fn kio_address(value: &str) -> String {
    let value = strip_user(value);
    let without_scheme = value
        .split_once("://")
        .map_or(value.as_str(), |(_, rest)| rest);
    without_scheme.replacen(' ', ":", 1)
}

fn gnome_proxy(
    gsettings: &dyn Gsettings,
) -> io::Result<(Option<u32>, Option<String>, Option<String>)> {
    let quoted = |value: String| value.trim().trim_matches('\'').to_owned();
    let mode = quoted(gsettings.get(GNOME_SCHEMA, "mode")?);
    match mode.as_str() {
        "manual" => {
            for schema in [
                "org.gnome.system.proxy.https",
                "org.gnome.system.proxy.http",
                "org.gnome.system.proxy.socks",
            ] {
                let host = quoted(gsettings.get(schema, "host")?);
                if !host.is_empty() {
                    let port = gsettings.get(schema, "port")?;
                    return Ok((Some(1), Some(format!("{host}:{}", port.trim())), None));
                }
            }
            Ok((Some(1), None, None))
        }
        "auto" => {
            let url = quoted(gsettings.get(GNOME_SCHEMA, "autoconfig-url")?);
            let url = if url.is_empty() {
                "automatic".to_owned()
            } else {
                strip_user(&url)
            };
            Ok((None, None, Some(url)))
        }
        _ => Ok((None, None, None)),
    }
}

/// The session's own variables: they reach only programs started from it, but those
/// are the ones the user runs.
fn environment_proxy(
    variable: impl Fn(&str) -> Option<String>,
) -> (Option<u32>, Option<String>, Option<String>) {
    let server = ENVIRONMENT
        .into_iter()
        .filter_map(variable)
        .map(|value| value.trim().to_owned())
        .find(|value| !value.is_empty())
        .map(|value| strip_user(&value));
    (server.as_ref().map(|_| 1), server, None)
}

/// Drops `user:password@` from an address: credentials are not for a screen or a report.
fn strip_user(address: &str) -> String {
    match address.split_once("://") {
        Some((scheme, rest)) => format!("{scheme}://{}", after_user(rest)),
        None => after_user(address).to_owned(),
    }
}

fn after_user(rest: &str) -> &str {
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
        Some(at) => &rest[at + 1..],
        None => rest,
    }
}

/// Whether a program has a netfilter queue open: Zapret's `nfqws` and the like read every
/// packet a rule sends there. No file means the kernel module is not loaded.
pub fn packet_queue_bound() -> io::Result<bool> {
    queue_bound_in(Path::new(NFQUEUE))
}

fn queue_bound_in(path: &Path) -> io::Result<bool> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text.lines().any(|line| !line.trim().is_empty())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn a_kde_proxy_by_hand_is_read_as_an_address() {
        let text = "[Proxy Settings]\nProxyType=1\nhttpProxy=http://proxy.example.com 3128\n";
        assert_eq!(
            kde_proxy(text),
            (Some(1), Some("proxy.example.com:3128".to_owned()), None)
        );
    }

    #[test]
    fn a_kde_script_or_detection_is_an_automatic_proxy() {
        let script = "[Proxy Settings]\nProxyType=2\nProxy Config Script=http://proxy.example.com/wpad.dat\n";
        assert_eq!(
            kde_proxy(script),
            (
                None,
                None,
                Some("http://proxy.example.com/wpad.dat".to_owned())
            )
        );
        assert_eq!(
            kde_proxy("[Proxy Settings]\nProxyType=3\n"),
            (None, None, Some("automatic".to_owned()))
        );
        assert_eq!(
            kde_proxy("[Proxy Settings]\nProxyType=0\n"),
            (None, None, None)
        );
        assert_eq!(kde_proxy(""), (None, None, None));
    }

    struct Fake(HashMap<(&'static str, &'static str), &'static str>);

    impl Gsettings for Fake {
        fn get(&self, schema: &str, key: &str) -> io::Result<String> {
            self.0
                .iter()
                .find(|((s, k), _)| *s == schema && *k == key)
                .map(|(_, value)| (*value).to_owned())
                .ok_or_else(|| io::Error::other("no such key"))
        }

        fn set(&self, _: &str, _: &str, _: &str) -> io::Result<()> {
            Err(io::Error::other("read only"))
        }
    }

    #[test]
    fn a_gnome_proxy_by_hand_names_the_first_host_that_is_set() {
        let fake = Fake(HashMap::from([
            ((GNOME_SCHEMA, "mode"), "'manual'"),
            (("org.gnome.system.proxy.https", "host"), "''"),
            (("org.gnome.system.proxy.https", "port"), "0"),
            (
                ("org.gnome.system.proxy.http", "host"),
                "'proxy.example.com'",
            ),
            (("org.gnome.system.proxy.http", "port"), "3128"),
            (("org.gnome.system.proxy.socks", "host"), "''"),
            (("org.gnome.system.proxy.socks", "port"), "0"),
        ]));
        assert_eq!(
            gnome_proxy(&fake).unwrap(),
            (Some(1), Some("proxy.example.com:3128".to_owned()), None)
        );
    }

    #[test]
    fn a_gnome_script_is_automatic_and_none_is_nothing() {
        let auto = Fake(HashMap::from([
            ((GNOME_SCHEMA, "mode"), "'auto'"),
            (
                (GNOME_SCHEMA, "autoconfig-url"),
                "'http://proxy.example.com/wpad.dat'",
            ),
        ]));
        assert_eq!(
            gnome_proxy(&auto).unwrap(),
            (
                None,
                None,
                Some("http://proxy.example.com/wpad.dat".to_owned())
            )
        );
        let none = Fake(HashMap::from([((GNOME_SCHEMA, "mode"), "'none'")]));
        assert_eq!(gnome_proxy(&none).unwrap(), (None, None, None));
    }

    #[test]
    fn the_session_environment_is_read_without_credentials() {
        let variables = HashMap::from([(
            "http_proxy",
            "http://user:secret@proxy.example.com:3128/".to_owned(),
        )]);
        let found = environment_proxy(|name| variables.get(name).cloned());
        assert_eq!(
            found,
            (
                Some(1),
                Some("http://proxy.example.com:3128/".to_owned()),
                None
            )
        );
        assert_eq!(environment_proxy(|_| None), (None, None, None));
        assert_eq!(
            environment_proxy(|_| Some("  ".to_owned())),
            (None, None, None)
        );
    }

    #[test]
    fn a_missing_queue_file_is_no_queue_and_a_listed_queue_is_one() {
        let dir = std::env::temp_dir().join(format!("rosetun-nfq-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("nfnetlink_queue");
        assert!(!queue_bound_in(&file).unwrap());
        std::fs::write(&file, "").unwrap();
        assert!(!queue_bound_in(&file).unwrap());
        std::fs::write(&file, "  200  4242     0 2 65535     0     0        1  1\n").unwrap();
        assert!(queue_bound_in(&file).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
