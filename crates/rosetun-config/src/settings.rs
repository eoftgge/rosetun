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

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub engine: EngineKind,
    #[serde(default)]
    pub kill_switch: bool,
    #[serde(default)]
    pub allow_lan: bool,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default)]
    pub tun: TunSettings,
    #[serde(default)]
    pub log_level: LogLevel,
}

#[cfg(test)]
mod settings_tests {
    use super::Settings;

    #[test]
    fn old_settings_without_allow_lan_remain_valid() {
        let settings: Settings =
            serde_json::from_str(r#"{"kill_switch":true}"#).expect("old settings");
        assert!(settings.kill_switch);
        assert!(!settings.allow_lan);
        assert!(!Settings::default().allow_lan);
    }
}
