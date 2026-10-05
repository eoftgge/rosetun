#![forbid(unsafe_code)]

mod ids;
mod node;
mod rule;
mod runtime;
mod settings;
mod subscription;

pub use ids::{NodeId, RuleId, RuleSetId, SubscriptionId};
pub use node::{
    Node, Outbound, RealityParams, ShadowsocksParams, StreamSettings, TlsMode, TlsParams,
    Transport, TrojanParams, VlessParams, VmessParams,
};
pub use rule::{DomainMatch, ProcessMatch, Rule, RuleMatcher, RuleSet, RuleTarget};
pub use runtime::{ConnectionState, Status, Traffic};
pub use settings::{DnsSettings, EngineKind, LogLevel, Settings, TunSettings};
pub use subscription::{Selection, Subscription, SubscriptionInfo};

use serde::{Deserialize, Serialize};

pub const CONFIG_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceSettings {
    /// Window scale in percent; see `rosetun_core::INTERFACE_SCALES`.
    #[serde(default = "default_scale_percent")]
    pub scale_percent: u16,
}

fn default_scale_percent() -> u16 {
    100
}

impl Default for InterfaceSettings {
    fn default() -> Self {
        Self {
            scale_percent: default_scale_percent(),
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
    pub rule_sets: Vec<RuleSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<Selection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_rule_set: Option<RuleSetId>,
}

fn default_config_version() -> u32 {
    CONFIG_VERSION
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            settings: Settings::default(),
            interface: InterfaceSettings::default(),
            subscriptions: Vec::new(),
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, InterfaceSettings};

    #[test]
    fn old_configuration_without_interface_uses_default_scale() {
        let config: AppConfig =
            serde_json::from_str(r#"{"version":1,"settings":{}}"#).expect("old configuration");
        assert_eq!(config.interface, InterfaceSettings::default());
        assert_eq!(config.interface.scale_percent, 100);

        let interface: InterfaceSettings =
            serde_json::from_str("{}").expect("interface without scale");
        assert_eq!(interface.scale_percent, 100);
    }
}
