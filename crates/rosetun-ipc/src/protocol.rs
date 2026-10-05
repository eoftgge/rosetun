use rosetun_config::{
    AppConfig, LogLevel, Node, RuleSet, RuleSetId, RuleTarget, Selection, Settings, Status, Traffic,
};
use serde::{Deserialize, Serialize};
use std::fmt::Formatter;

pub const PROTOCOL_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    Hello {
        client: String,
        protocol_version: u32,
    },
    Status,
    Connect(Box<ConnectRequest>),
    Disconnect,
    ApplyRules {
        rule_set: RuleSet,
    },
    Subscribe,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConnectRequestError {
    #[error("select an existing node with rosetun select <subscription-id> <node-id>")]
    NodeNotSelected,
    #[error("select a node with rosetun select <subscription-id> <node-id>")]
    SelectionMissing,
    #[error("the selected rule set does not exist")]
    RuleSetNotFound,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub selection: Selection,
    pub node: Node,
    pub rule_set: RuleSet,
    pub settings: Settings,
}

impl std::fmt::Debug for ConnectRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectRequest")
            .field("selection", &self.selection)
            .field("node_id", &self.node.id)
            .field("engine", &self.settings.engine)
            .field("kill_switch", &self.settings.kill_switch)
            .field("tun_alias", &self.settings.tun.name)
            .field("auto_route", &self.settings.tun.auto_route)
            .field("rule_set_id", &self.rule_set.id)
            .field("rule_count", &self.rule_set.rules.len())
            .finish_non_exhaustive()
    }
}

impl ConnectRequest {
    pub fn from_config(config: &AppConfig) -> Result<Self, ConnectRequestError> {
        let (_, node) = config
            .active_node()
            .ok_or(ConnectRequestError::NodeNotSelected)?;
        let selection = config
            .active
            .as_ref()
            .ok_or(ConnectRequestError::SelectionMissing)?;

        let rule_set = match &config.active_rule_set {
            Some(_) => config
                .active_rules()
                .cloned()
                .ok_or(ConnectRequestError::RuleSetNotFound)?,
            None => RuleSet::new(RuleSetId::new("default"), "Default", RuleTarget::Proxy),
        };

        Ok(Self {
            selection: selection.clone(),
            node: node.clone(),
            rule_set,
            settings: config.settings.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Hello {
        helper_version: String,
        protocol_version: u32,
    },
    Status(Status),
    Ok,
    Error(HelperError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    State(rosetun_config::ConnectionState),
    Traffic(Traffic),
    Log {
        level: LogLevel,
        target: String,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frame {
    Request { id: u64, body: Request },
    Response { id: u64, body: Response },
    Event(Event),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperError {
    pub code: ErrorCode,
    pub message: String,
}

impl HelperError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for HelperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for HelperError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    ProtocolMismatch,
    HandshakeRequired,
    NotPrivileged,
    EngineFailed,
    RoutingFailed,
    Busy,
    InvalidState,
    UnsupportedRules,
    NotImplemented,
    Internal,
}

#[cfg(test)]
mod tests {
    use rosetun_config::{
        AppConfig, Node, NodeId, Outbound, Rule, RuleId, RuleMatcher, RuleSet, RuleSetId,
        RuleTarget, Selection, StreamSettings, Subscription, SubscriptionId, TrojanParams,
    };

    use super::{ConnectRequest, ConnectRequestError};

    fn selected_config() -> AppConfig {
        let subscription_id = SubscriptionId::new("subscription");
        let node_id = NodeId::new("node");
        let rule_set_id = RuleSetId::new("rules");
        let node = Node {
            id: node_id.clone(),
            name: "Test node".to_owned(),
            server: "example.com".to_owned(),
            port: 443,
            outbound: Outbound::Trojan(TrojanParams {
                password: "test-secret".to_owned(),
            }),
            stream: StreamSettings::default(),
            raw: None,
        };

        let mut rule_set = RuleSet::new(rule_set_id.clone(), "Test rules", RuleTarget::Proxy);
        rule_set.rules.push(Rule {
            id: RuleId::new("block"),
            enabled: true,
            matcher: RuleMatcher::IpCidr("192.0.2.0/24".to_owned()),
            target: RuleTarget::Block,
        });

        AppConfig {
            subscriptions: vec![Subscription {
                id: subscription_id.clone(),
                name: "Test subscription".to_owned(),
                url: "https://example.com/subscription".to_owned(),
                nodes: vec![node],
                auto_update: false,
                updated_at_unix: None,
                user_agent: None,
                send_hwid: true,
                info: None,
                update_interval_hours: None,
                support_url: None,
                web_page_url: None,
                announce: None,
                notices: Vec::new(),
            }],
            rule_sets: vec![rule_set],
            active: Some(Selection {
                subscription: subscription_id,
                node: node_id,
            }),
            active_rule_set: Some(rule_set_id),
            ..AppConfig::default()
        }
    }

    fn dangling_node_config() -> AppConfig {
        AppConfig {
            active: Some(Selection {
                subscription: SubscriptionId::new("missing"),
                node: NodeId::new("missing"),
            }),
            ..AppConfig::default()
        }
    }

    #[test]
    fn request_contains_selected_node_rules_and_settings() {
        let config = selected_config();

        let request = ConnectRequest::from_config(&config).unwrap();

        assert_eq!(Some(&request.selection), config.active.as_ref());
        assert_eq!(&request.node, config.active_node().unwrap().1);
        assert_eq!(&request.rule_set, config.active_rules().unwrap());
        assert_eq!(request.settings, config.settings);
    }

    #[test]
    fn request_requires_an_existing_selected_node() {
        for config in [AppConfig::default(), dangling_node_config()] {
            let error = ConnectRequest::from_config(&config).unwrap_err();

            assert_eq!(error, ConnectRequestError::NodeNotSelected);
            assert!(error.to_string().contains("rosetun select"));
        }
    }

    #[test]
    fn request_uses_default_proxy_rules_when_no_rule_set_is_selected() {
        let config = AppConfig {
            active_rule_set: None,
            ..selected_config()
        };

        let request = ConnectRequest::from_config(&config).unwrap();

        assert_eq!(
            request.rule_set,
            RuleSet::new(RuleSetId::new("default"), "Default", RuleTarget::Proxy)
        );
    }

    #[test]
    fn request_does_not_replace_a_dangling_rule_set_with_defaults() {
        let config = AppConfig {
            active_rule_set: Some(RuleSetId::new("missing")),
            ..selected_config()
        };

        assert_eq!(
            ConnectRequest::from_config(&config),
            Err(ConnectRequestError::RuleSetNotFound)
        );
    }

    #[test]
    fn request_debug_does_not_expose_credentials_or_subscription_url() {
        let config = selected_config();
        let request = ConnectRequest::from_config(&config).unwrap();
        let debug = format!("{request:?}");

        assert!(!debug.contains("test-secret"));
        assert!(!debug.contains(&config.subscriptions[0].url));
    }
}
