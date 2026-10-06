use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineKind {
    #[default]
    SingBox,
    Xray,
}

impl EngineKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingBox => "sing-box",
            Self::Xray => "xray",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunSettings {
    pub name: String,
    pub mtu: u16,
    pub ipv4: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    #[serde(default = "crate::default_true")]
    pub auto_route: bool,
}

impl Default for TunSettings {
    fn default() -> Self {
        Self {
            name: "rosetun0".to_owned(),
            mtu: 1500,
            ipv4: "172.19.0.1/30".to_owned(),
            ipv6: None,
            auto_route: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsSettings {
    // A hostname would require DNS through the tunnel being built, creating a
    // resolver cycle; the helper cannot resolve new names under the kill switch.
    pub server: IpAddr,
    pub server_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            server: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            server_name: "dns.google".to_owned(),
            port: None,
            path: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub engine: EngineKind,
    #[serde(default)]
    pub kill_switch: bool,
    /// The helper restarts the engine by itself after it exits or after a resume from sleep.
    #[serde(default = "crate::default_true")]
    pub auto_reconnect: bool,
    #[serde(default)]
    pub allow_lan: bool,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default)]
    pub tun: TunSettings,
    #[serde(default)]
    pub dns: DnsSettings,
    /// Sets only the depth of an enabled verbose log: trace or debug.
    #[serde(default)]
    pub log_level: LogLevel,
    /// The verbose log is on until this Unix time, in seconds. `None` or a past time means off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verbose_log_until: Option<u64>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            engine: EngineKind::default(),
            kill_switch: false,
            auto_reconnect: true,
            allow_lan: false,
            autostart: false,
            tun: TunSettings::default(),
            dns: DnsSettings::default(),
            log_level: LogLevel::default(),
            verbose_log_until: None,
        }
    }
}

impl Settings {
    /// How long the verbose log stays on after it is turned on.
    pub const VERBOSE_LOG_SECONDS: u64 = 24 * 60 * 60;

    pub fn verbose_log_active(&self, now_unix: u64) -> bool {
        self.verbose_log_until.is_some_and(|until| now_unix < until)
    }
}

#[cfg(test)]
mod settings_tests {
    use super::{DnsSettings, Settings};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn old_settings_without_allow_lan_remain_valid() {
        let settings: Settings =
            serde_json::from_str(r#"{"kill_switch":true}"#).expect("old settings");
        assert!(settings.kill_switch);
        assert!(!settings.allow_lan);
        assert!(!Settings::default().allow_lan);
    }

    #[test]
    fn old_settings_enable_auto_reconnect_by_default() {
        let settings: Settings = serde_json::from_str(r#"{"kill_switch":true}"#)
            .expect("settings without auto reconnect");
        assert!(settings.auto_reconnect);
        assert!(Settings::default().auto_reconnect);
        let disabled: Settings = serde_json::from_str(r#"{"auto_reconnect":false}"#)
            .expect("settings with auto reconnect disabled");
        assert!(!disabled.auto_reconnect);
    }

    #[test]
    fn verbose_log_expires_at_its_deadline() {
        let mut settings = Settings::default();
        assert!(!settings.verbose_log_active(0));
        settings.verbose_log_until = Some(100);
        assert!(settings.verbose_log_active(99));
        assert!(!settings.verbose_log_active(100));
        assert!(!settings.verbose_log_active(101));
    }

    #[test]
    fn verbose_log_remains_off_in_old_settings() {
        let settings: Settings = serde_json::from_str(r#"{"log_level":"trace"}"#)
            .expect("old settings without verbose log");
        assert_eq!(settings.verbose_log_until, None);
        assert!(!settings.verbose_log_active(0));
        let encoded = serde_json::to_value(&settings).expect("serialized settings");
        assert!(encoded.get("verbose_log_until").is_none());

        let settings: Settings = serde_json::from_str(r#"{"verbose_log_until":123}"#)
            .expect("settings with verbose log deadline");
        assert_eq!(settings.verbose_log_until, Some(123));
    }

    #[test]
    fn dns_defaults_preserve_the_public_resolver() {
        let dns = DnsSettings::default();
        assert_eq!(dns.server, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(dns.server_name, "dns.google");
        assert_eq!(dns.port, None);
        assert_eq!(dns.path, None);
        assert_eq!(Settings::default().dns, dns);
    }

    #[test]
    fn dns_settings_round_trip_with_all_fields() {
        let input = serde_json::json!({
            "dns": {
                "server": "77.88.8.8",
                "server_name": "common.dot.dns.yandex.net",
                "port": 8443,
                "path": "/custom-dns-query"
            }
        });
        let settings: Settings = serde_json::from_value(input.clone()).expect("DNS settings");

        assert_eq!(settings.dns.server, IpAddr::V4(Ipv4Addr::new(77, 88, 8, 8)));
        assert_eq!(settings.dns.server_name, "common.dot.dns.yandex.net");
        assert_eq!(settings.dns.port, Some(8443));
        assert_eq!(settings.dns.path.as_deref(), Some("/custom-dns-query"));

        let encoded = serde_json::to_value(&settings).expect("serialized settings");
        assert_eq!(encoded["dns"], input["dns"]);
        let decoded: Settings = serde_json::from_value(encoded).expect("round-trip settings");
        assert_eq!(decoded, settings);
    }

    #[test]
    fn old_settings_without_dns_remain_valid() {
        let settings: Settings =
            serde_json::from_str(r#"{"kill_switch":true}"#).expect("old settings");
        assert!(settings.kill_switch);
        assert_eq!(settings.dns, DnsSettings::default());
    }

    #[test]
    fn omitted_dns_port_and_path_remain_absent() {
        let settings: Settings = serde_json::from_str(
            r#"{"dns":{"server":"77.88.8.8","server_name":"common.dot.dns.yandex.net"}}"#,
        )
        .expect("DNS settings without optional fields");

        assert_eq!(settings.dns.port, None);
        assert_eq!(settings.dns.path, None);

        let encoded = serde_json::to_value(&settings).expect("serialized settings");
        assert!(encoded["dns"].get("port").is_none());
        assert!(encoded["dns"].get("path").is_none());
    }

    #[test]
    fn dns_server_hostname_is_rejected() {
        let result = serde_json::from_str::<Settings>(
            r#"{"dns":{"server":"dns.google","server_name":"dns.google"}}"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn unknown_settings_fields_remain_valid() {
        let settings: Settings =
            serde_json::from_str(r#"{"kill_switch":true,"future_setting":true}"#)
                .expect("settings with an unknown field");
        assert!(settings.kill_switch);
        assert_eq!(settings.dns, DnsSettings::default());
    }
}
