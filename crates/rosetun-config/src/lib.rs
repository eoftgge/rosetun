#![forbid(unsafe_code)]

mod ids;
mod list;
mod node;
mod rule;
mod runtime;
mod settings;
mod subscription;
mod uploaded_list;

pub use ids::{ListId, NodeId, RuleId, RuleSetId, SubscriptionId};
pub use list::{List, ListCategoryError, ListFormat, ListSource};
pub use node::{
    Hysteria2Params, Node, Outbound, RealityParams, ShadowsocksParams, StreamSettings, TlsMode,
    TlsParams, Transport, TrojanParams, VlessParams, VmessParams,
};
pub use rule::{DomainMatch, ProcessMatch, Rule, RuleMatcher, RuleSet, RuleTarget, RuleTemplate};
pub use runtime::{ConnectStage, ConnectionState, FailureKind, Status, Traffic};
pub use settings::{DnsSettings, EngineKind, LogLevel, Settings, TunSettings};
pub use subscription::{Selection, Subscription, SubscriptionInfo};
pub use uploaded_list::{ListRef, UploadedListFormat, list_tag};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Bump for every serialized format change, including defaulted fields older releases drop on save.
/// Add a Value migration and a new fixture; never edit fixtures of released formats.
pub const CONFIG_VERSION: u32 = 3;

pub fn is_sensitive_log_target(target: &str) -> bool {
    ["ureq", "ureq_proto", "rustls", "rustls_platform_verifier"]
        .iter()
        .any(|prefix| {
            target == *prefix
                || target
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.starts_with("::"))
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LanguageSetting {
    #[default]
    System,
    English,
    Russian,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceSettings {
    /// Window scale in percent; see `rosetun_core::INTERFACE_SCALES`.
    #[serde(default = "default_scale_percent")]
    pub scale_percent: u16,
    /// The close button hides the window to the tray instead of quitting.
    #[serde(default = "default_close_to_tray")]
    pub close_to_tray: bool,
    /// The client connects once at start when the tunnel is disconnected.
    #[serde(default)]
    pub connect_on_start: bool,
    /// Subscriptions are refreshed in the background when they get old.
    #[serde(default = "default_true")]
    pub auto_update_subscriptions: bool,
    #[serde(default = "default_true")]
    pub check_updates: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_update_check: Option<u64>,
    #[serde(default)]
    pub language: LanguageSetting,
    #[serde(default)]
    pub reduce_motion: bool,
}

fn default_scale_percent() -> u16 {
    100
}

fn default_close_to_tray() -> bool {
    true
}

impl Default for InterfaceSettings {
    fn default() -> Self {
        Self {
            scale_percent: default_scale_percent(),
            close_to_tray: default_close_to_tray(),
            connect_on_start: false,
            auto_update_subscriptions: true,
            check_updates: true,
            skipped_version: None,
            last_update_check: None,
            language: LanguageSetting::System,
            reduce_motion: false,
        }
    }
}

pub(crate) fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default = "default_config_version")]
    pub version: u32,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub interface: InterfaceSettings,
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
    #[serde(default)]
    pub lists: Vec<List>,
    #[serde(default)]
    pub rule_sets: Vec<RuleSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<Selection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_rule_set: Option<RuleSetId>,
}

fn default_config_version() -> u32 {
    1
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            settings: Settings::default(),
            interface: InterfaceSettings::default(),
            subscriptions: Vec::new(),
            lists: Vec::new(),
            rule_sets: Vec::new(),
            active: None,
            active_rule_set: None,
        }
    }
}

impl AppConfig {
    pub fn active_node(&self) -> Option<(&Subscription, &Node)> {
        let selection = self.active.as_ref()?;
        let subscription = self
            .subscriptions
            .iter()
            .find(|item| item.id == selection.subscription)?;
        let node = subscription.node(&selection.node)?;
        Some((subscription, node))
    }

    pub fn active_rules(&self) -> Option<&RuleSet> {
        let id = self.active_rule_set.as_ref()?;
        self.rule_sets.iter().find(|set| &set.id == id)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(
        "configuration version {found} is not supported (expected to be no higher than {expected})"
    )]
    UnsupportedVersion { found: u32, expected: u32 },
    #[error("selected node {node} is not in subscription {subscription}")]
    DanglingSelection {
        subscription: SubscriptionId,
        node: NodeId,
    },
    #[error("selected rule set {0} does not exist")]
    DanglingRuleSet(RuleSetId),
    #[error("a list ID is not safe for a file name or is duplicated")]
    InvalidListId,
    #[error("list metadata or categories are invalid")]
    InvalidListMetadata,
    #[error("a rule refers to a missing list")]
    MissingList,
    #[error("a rule has an invalid list category")]
    InvalidListCategory,
}

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("invalid JSON at line {}, column {}", .0.line(), .0.column())]
    Json(#[source] serde_json::Error),
    #[error("unexpected value in the configuration")]
    UnexpectedValue,
    #[error(transparent)]
    Config(#[from] ConfigError),
}

pub fn from_json(bytes: &[u8]) -> Result<(AppConfig, Option<u32>), FormatError> {
    let mut value: Value = serde_json::from_slice(bytes).map_err(FormatError::Json)?;
    let config = value.as_object_mut().ok_or(FormatError::UnexpectedValue)?;
    let original_version = match config.get("version") {
        None => 1,
        Some(version) => version
            .as_u64()
            .and_then(|version| u32::try_from(version).ok())
            .filter(|version| *version > 0)
            .ok_or(FormatError::UnexpectedValue)?,
    };
    if original_version > CONFIG_VERSION {
        return Err(ConfigError::UnsupportedVersion {
            found: original_version,
            expected: CONFIG_VERSION,
        }
        .into());
    }

    let mut version = original_version;
    while version < CONFIG_VERSION {
        match version {
            1 => migrate_1_to_2(config),
            2 => migrate_2_to_3(config),
            _ => return Err(FormatError::UnexpectedValue),
        }
        version += 1;
        config.insert("version".to_owned(), Value::from(version));
    }

    let config: AppConfig =
        serde_json::from_value(value).map_err(|_| FormatError::UnexpectedValue)?;
    config.validate()?;
    Ok((
        config,
        (original_version < CONFIG_VERSION).then_some(original_version),
    ))
}

fn migrate_1_to_2(_config: &mut Map<String, Value>) {
    // New fields are supplied by serde defaults; updating the version prevents older writers from dropping them.
}

fn migrate_2_to_3(config: &mut Map<String, Value>) {
    config.insert("lists".to_owned(), Value::Array(Vec::new()));
}

impl AppConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version > CONFIG_VERSION {
            return Err(ConfigError::UnsupportedVersion {
                found: self.version,
                expected: CONFIG_VERSION,
            });
        }
        if let Some(selection) = &self.active
            && self.active_node().is_none()
        {
            return Err(ConfigError::DanglingSelection {
                subscription: selection.subscription.clone(),
                node: selection.node.clone(),
            });
        }
        if let Some(id) = &self.active_rule_set
            && self.active_rules().is_none()
        {
            return Err(ConfigError::DanglingRuleSet(id.clone()));
        }
        let mut ids = std::collections::HashSet::new();
        for list in &self.lists {
            let id = list.id.as_str();
            if id.is_empty()
                || id.len() > 20
                || !id.bytes().all(|byte| byte.is_ascii_digit())
                || !ids.insert(id)
            {
                return Err(ConfigError::InvalidListId);
            }
            if matches!(&list.source, ListSource::File { original_name } if original_name.is_empty() || original_name == "." || original_name == ".." || original_name.contains(['/', '\\']))
                || list.size.is_some() != list.sha256.is_some()
                || list.sha256.as_ref().is_some_and(|digest| {
                    digest.len() != 64
                        || !digest
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
                || list.format.has_categories() == list.categories.is_empty()
            {
                return Err(ConfigError::InvalidListMetadata);
            }
            let mut categories = std::collections::HashSet::new();
            for category in &list.categories {
                if category.is_empty()
                    || !category.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'-' | b'_' | b'.' | b'!')
                    })
                    || !categories.insert(category)
                {
                    return Err(ConfigError::InvalidListMetadata);
                }
            }
        }
        for rule in self.rule_sets.iter().flat_map(|set| &set.rules) {
            if let RuleMatcher::List { list, category } = &rule.matcher {
                let entry = self
                    .lists
                    .iter()
                    .find(|entry| &entry.id == list)
                    .ok_or(ConfigError::MissingList)?;
                entry
                    .validate_category(category.as_deref())
                    .map_err(|_| ConfigError::InvalidListCategory)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, InterfaceSettings, LanguageSetting, is_sensitive_log_target};

    #[test]
    fn sensitive_log_targets_match_only_exact_names_and_submodules() {
        for target in ["ureq", "ureq_proto", "rustls", "rustls_platform_verifier"] {
            assert!(is_sensitive_log_target(target));
            assert!(is_sensitive_log_target(&format!("{target}::run")));
            assert!(is_sensitive_log_target(&format!("{target}::run::request")));
            assert!(!is_sensitive_log_target(&format!("{target}x")));
            assert!(!is_sensitive_log_target(&format!("{target}_other")));
        }

        for target in ["", "rosetun", "other::ureq", "ureqx::run"] {
            assert!(!is_sensitive_log_target(target));
        }
    }

    #[test]
    fn old_configuration_without_interface_uses_default_scale() {
        let config: AppConfig =
            serde_json::from_str(r#"{"version":1,"settings":{}}"#).expect("old configuration");
        assert_eq!(config.interface, InterfaceSettings::default());
        assert_eq!(config.interface.scale_percent, 100);

        let interface: InterfaceSettings =
            serde_json::from_str("{}").expect("interface without scale");
        assert_eq!(interface.scale_percent, 100);
        assert!(interface.close_to_tray);
        assert!(!interface.connect_on_start);
        assert!(!config.interface.connect_on_start);
        assert!(interface.auto_update_subscriptions);
        assert!(config.interface.auto_update_subscriptions);
        assert!(interface.check_updates);
        assert!(config.interface.check_updates);
        assert_eq!(interface.skipped_version, None);
        assert_eq!(config.interface.skipped_version, None);
        assert_eq!(interface.last_update_check, None);
        assert_eq!(config.interface.last_update_check, None);
        let saved = serde_json::to_value(&interface).unwrap();
        assert!(saved.get("skipped_version").is_none());
        assert!(saved.get("last_update_check").is_none());
    }

    #[test]
    fn old_interface_without_language_defaults_to_system() {
        let config: AppConfig =
            serde_json::from_str(r#"{"interface":{"scale_percent":125,"close_to_tray":false}}"#)
                .expect("configuration without language setting");
        assert_eq!(config.interface.language, LanguageSetting::System);
        assert_eq!(config.interface.scale_percent, 125);
        assert!(!config.interface.close_to_tray);
    }

    #[test]
    fn old_interface_with_only_scale_defaults_to_close_to_tray() {
        let config: AppConfig = serde_json::from_str(r#"{"interface":{"scale_percent":125}}"#)
            .expect("configuration without close-to-tray setting");
        assert_eq!(config.interface.scale_percent, 125);
        assert!(config.interface.close_to_tray);
    }
}
