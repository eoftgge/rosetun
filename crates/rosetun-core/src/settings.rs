use std::net::IpAddr;

use rosetun_config::{DnsSettings, LanguageSetting, Settings};
use url::Host;

use crate::{Store, StoreError};

pub const INTERFACE_SCALES: [u16; 6] = [80, 90, 100, 110, 125, 150];

#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("unsupported interface scale")]
    UnsupportedScale,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsInputError {
    #[error("enter the resolver's IP address, such as 8.8.8.8")]
    InvalidServer,
    #[error("enter the resolver's TLS name, such as dns.google")]
    InvalidServerName,
    #[error("the port must be a number from 1 to 65535")]
    InvalidPort,
    #[error("the path must start with /")]
    InvalidPath,
}

pub fn parse_dns_input(
    server: &str,
    server_name: &str,
    port: &str,
    path: &str,
) -> Result<DnsSettings, DnsInputError> {
    let server = server
        .trim()
        .parse::<IpAddr>()
        .map_err(|_| DnsInputError::InvalidServer)?;
    let server_name = match Host::parse(server_name.trim()) {
        Ok(Host::Domain(name)) => name,
        _ => return Err(DnsInputError::InvalidServerName),
    };
    let port = match port.trim() {
        "" => None,
        value => Some(
            value
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or(DnsInputError::InvalidPort)?,
        ),
    };
    let path = match path.trim() {
        "" => None,
        value if value.starts_with('/') && !value.chars().any(char::is_whitespace) => {
            Some(value.to_owned())
        }
        _ => return Err(DnsInputError::InvalidPath),
    };
    Ok(DnsSettings {
        server,
        server_name,
        port,
        path,
    })
}

pub fn set_interface_scale(store: &Store, percent: u16) -> Result<(), SettingsError> {
    store.modify(|config| {
        if !INTERFACE_SCALES.contains(&percent) {
            return Err(SettingsError::UnsupportedScale);
        }
        config.interface.scale_percent = percent;
        Ok(())
    })
}

pub fn set_close_to_tray(store: &Store, enabled: bool) -> Result<(), SettingsError> {
    store.modify(|config| {
        config.interface.close_to_tray = enabled;
        Ok(())
    })
}

pub fn set_connect_on_start(store: &Store, enabled: bool) -> Result<(), SettingsError> {
    store.modify(|config| {
        config.interface.connect_on_start = enabled;
        Ok(())
    })
}

pub fn set_auto_update_subscriptions(store: &Store, enabled: bool) -> Result<(), SettingsError> {
    store.modify(|config| {
        config.interface.auto_update_subscriptions = enabled;
        Ok(())
    })
}

pub fn set_auto_reconnect(store: &Store, enabled: bool) -> Result<(), SettingsError> {
    store.modify(|config| {
        config.settings.auto_reconnect = enabled;
        Ok(())
    })
}

pub fn set_language(store: &Store, language: LanguageSetting) -> Result<(), SettingsError> {
    store.modify(|config| {
        config.interface.language = language;
        Ok(())
    })
}

pub fn set_dns(store: &Store, dns: DnsSettings) -> Result<(), SettingsError> {
    store.modify(|config| {
        config.settings.dns = dns;
        Ok(())
    })
}

/// Turns the verbose log on for a day from `now_unix`, or off.
pub fn set_verbose_log(store: &Store, on: bool, now_unix: u64) -> Result<(), SettingsError> {
    store.modify(|config| {
        config.settings.verbose_log_until =
            on.then_some(now_unix.saturating_add(Settings::VERBOSE_LOG_SECONDS));
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use rosetun_config::{AppConfig, DnsSettings, LogLevel};

    use super::*;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    struct TestFile(PathBuf);

    impl TestFile {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "rosetun-settings-{}-{}.json",
                std::process::id(),
                NEXT_PATH.fetch_add(1, Ordering::Relaxed)
            )))
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[test]
    fn default_and_custom_dns_input() {
        let default = DnsSettings::default();
        assert_eq!(
            parse_dns_input(" 8.8.8.8 ", " dns.google ", "", "").unwrap(),
            default
        );
        let custom =
            parse_dns_input("1.1.1.1", " Cloudflare-DNS.com ", " 8443 ", " /dns-query ").unwrap();
        assert_eq!(custom.server.to_string(), "1.1.1.1");
        assert_eq!(custom.server_name, "cloudflare-dns.com");
        assert_eq!(custom.port, Some(8443));
        assert_eq!(custom.path.as_deref(), Some("/dns-query"));
        assert_eq!(
            parse_dns_input("2001:4860:4860::8888", "dns.google", "", "")
                .unwrap()
                .server
                .to_string(),
            "2001:4860:4860::8888"
        );
    }

    #[test]
    fn invalid_dns_fields_report_their_error() {
        assert_eq!(
            parse_dns_input("dns.google", "dns.google", "", ""),
            Err(DnsInputError::InvalidServer)
        );
        for name in ["1.1.1.1", "not a domain"] {
            assert_eq!(
                parse_dns_input("1.1.1.1", name, "", ""),
                Err(DnsInputError::InvalidServerName)
            );
        }
        for port in ["0", "70000", "abc"] {
            assert_eq!(
                parse_dns_input("1.1.1.1", "dns.google", port, ""),
                Err(DnsInputError::InvalidPort)
            );
        }
        for path in ["dns-query", "/a b"] {
            assert_eq!(
                parse_dns_input("1.1.1.1", "dns.google", "", path),
                Err(DnsInputError::InvalidPath)
            );
        }
    }

    #[test]
    fn setting_operations_change_only_the_selected_field() {
        let file = TestFile::new();
        let store = Store::at(&file.0);
        let mut expected = AppConfig::default();
        expected.settings.kill_switch = true;
        expected.settings.dns.path = Some("/original".to_owned());
        expected.settings.log_level = LogLevel::Trace;
        store
            .modify::<_, StoreError>(|config| {
                *config = expected.clone();
                Ok(())
            })
            .unwrap();

        set_interface_scale(&store, 125).unwrap();
        expected.interface.scale_percent = 125;
        assert_eq!(store.load().unwrap(), expected);

        set_close_to_tray(&store, false).unwrap();
        expected.interface.close_to_tray = false;
        assert_eq!(store.load().unwrap(), expected);

        set_connect_on_start(&store, true).unwrap();
        expected.interface.connect_on_start = true;
        assert_eq!(store.load().unwrap(), expected);

        set_auto_update_subscriptions(&store, false).unwrap();
        expected.interface.auto_update_subscriptions = false;
        assert_eq!(store.load().unwrap(), expected);

        set_auto_reconnect(&store, false).unwrap();
        expected.settings.auto_reconnect = false;
        assert_eq!(store.load().unwrap(), expected);

        set_language(&store, LanguageSetting::Russian).unwrap();
        expected.interface.language = LanguageSetting::Russian;
        assert_eq!(store.load().unwrap(), expected);

        let dns = parse_dns_input("1.1.1.1", "cloudflare-dns.com", "443", "/dns-query").unwrap();
        set_dns(&store, dns.clone()).unwrap();
        expected.settings.dns = dns;
        assert_eq!(store.load().unwrap(), expected);

        set_verbose_log(&store, true, 100).unwrap();
        expected.settings.verbose_log_until = Some(100 + Settings::VERBOSE_LOG_SECONDS);
        assert_eq!(store.load().unwrap(), expected);

        set_verbose_log(&store, false, 101).unwrap();
        expected.settings.verbose_log_until = None;
        assert_eq!(store.load().unwrap(), expected);
    }

    #[test]
    fn unsupported_scale_preserves_existing_file_bytes() {
        let file = TestFile::new();
        let store = Store::at(&file.0);
        fs::write(&file.0, b"{\"settings\": {\"kill_switch\": true}}\n").unwrap();
        let before = fs::read(&file.0).unwrap();
        assert!(matches!(
            set_interface_scale(&store, 95),
            Err(SettingsError::UnsupportedScale)
        ));
        assert_eq!(fs::read(&file.0).unwrap(), before);
    }
}
