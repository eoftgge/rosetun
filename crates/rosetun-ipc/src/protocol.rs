use rosetun_config::{
    AppConfig, LogLevel, Node, NodeId, Rule, RuleSet, RuleSetId, RuleTarget, Selection, Settings,
    Status, Traffic,
};
use serde::{Deserialize, Serialize};
use std::fmt::Formatter;

pub const PROTOCOL_VERSION: u32 = 7;
pub const MAX_PROBE_NODES: usize = 256;
pub const MAX_TEMPORARY_RULES: usize = 256;
pub const MAX_LIST_CHUNK_BYTES: usize = 1024 * 1024;
pub const MAX_LIST_PAYLOAD_BYTES: u64 = 16 * 1024 * 1024;

pub use rosetun_config::{ListRef, UploadedListFormat as ListFormat};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    Hello {
        client: String,
        protocol_version: u32,
    },
    Status,
    TemporaryRules,
    ListStatus {
        hashes: Vec<String>,
    },
    PutListChunk {
        sha256: String,
        format: ListFormat,
        total_size: u64,
        offset: u64,
        data: String,
    },
    Connect(Box<ConnectRequest>),
    ProbeNodes(Box<ProbeRequest>),
    TunnelDelay,
    Disconnect,
    Apply(Box<ConnectRequest>),
    Subscribe,
    Shutdown,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hello {
                protocol_version, ..
            } => f
                .debug_struct("Hello")
                .field("protocol_version", protocol_version)
                .finish_non_exhaustive(),
            Self::ListStatus { hashes } => f
                .debug_struct("ListStatus")
                .field("hash_count", &hashes.len())
                .finish(),
            Self::PutListChunk {
                sha256,
                format,
                total_size,
                offset,
                data,
            } => f
                .debug_struct("PutListChunk")
                .field("sha256_prefix", &sha256.get(..12).unwrap_or("<invalid>"))
                .field("format", format)
                .field("total_size", total_size)
                .field("offset", offset)
                .field("encoded_len", &data.len())
                .finish(),
            Self::Connect(request) => f.debug_tuple("Connect").field(request).finish(),
            Self::Apply(request) => f.debug_tuple("Apply").field(request).finish(),
            Self::ProbeNodes(request) => f.debug_tuple("ProbeNodes").field(request).finish(),
            Self::Status => f.write_str("Status"),
            Self::TemporaryRules => f.write_str("TemporaryRules"),
            Self::TunnelDelay => f.write_str("TunnelDelay"),
            Self::Disconnect => f.write_str("Disconnect"),
            Self::Subscribe => f.write_str("Subscribe"),
            Self::Shutdown => f.write_str("Shutdown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConnectRequestError {
    #[error("the selected node does not exist")]
    NodeNotFound,
    #[error("no node is selected")]
    SelectionMissing,
    #[error("the selected rule set does not exist")]
    RuleSetNotFound,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub selection: Selection,
    pub node: Node,
    pub rule_set: RuleSet,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub temporary_rules: Vec<Rule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lists: Vec<ListRef>,
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
            .field("temporary_rule_count", &self.temporary_rules.len())
            .field("list_count", &self.lists.len())
            .finish_non_exhaustive()
    }
}

impl ConnectRequest {
    pub fn from_config(config: &AppConfig) -> Result<Self, ConnectRequestError> {
        let selection = config
            .active
            .as_ref()
            .ok_or(ConnectRequestError::SelectionMissing)?;
        let (_, node) = config
            .active_node()
            .ok_or(ConnectRequestError::NodeNotFound)?;

        let rule_set = match &config.active_rule_set {
            Some(_) => config
                .active_rules()
                .map(RuleSet::with_templates_expanded)
                .ok_or(ConnectRequestError::RuleSetNotFound)?,
            None => RuleSet::new(RuleSetId::new("default"), "Default", RuleTarget::Proxy),
        };

        Ok(Self {
            selection: selection.clone(),
            node: node.clone(),
            rule_set,
            temporary_rules: Vec::new(),
            lists: Vec::new(),
            settings: config.settings.clone(),
        })
    }

    pub fn effective_rule_set(&self) -> RuleSet {
        let mut rules = self.rule_set.clone();
        rules
            .rules
            .splice(0..0, self.temporary_rules.iter().cloned());
        rules
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRequest {
    pub nodes: Vec<Node>,
    pub settings: Settings,
}

impl std::fmt::Debug for ProbeRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeRequest")
            .field("node_count", &self.nodes.len())
            .field("engine", &self.settings.engine)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub node: NodeId,
    pub outcome: ProbeOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// The request through the node answered after this many milliseconds.
    Works { millis: u32 },
    /// The request through the node failed or timed out.
    Fails,
    /// The node's name could not be resolved.
    Unresolved,
    /// The engine cannot express this node.
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Hello {
        helper_version: String,
        protocol_version: u32,
    },
    Status(Status),
    TemporaryRules(Vec<Rule>),
    ListStatus {
        missing: Vec<String>,
    },
    Probe(Vec<ProbeResult>),
    Delay(ProbeOutcome),
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
    ServerUnreachable,
    ServerRejected,
    ServerClosed,
    DnsTimeout,
    Cancelled,
    EngineNotReady,
    RoutingFailed,
    Busy,
    InvalidState,
    UnsupportedRules,
    ListMissing,
    NotImplemented,
    Internal,
}

#[cfg(test)]
mod tests {
    #[test]
    fn classified_errors_round_trip() {
        for code in [
            super::ErrorCode::ServerUnreachable,
            super::ErrorCode::ServerRejected,
            super::ErrorCode::ServerClosed,
            super::ErrorCode::DnsTimeout,
        ] {
            let value = serde_json::to_string(&code).unwrap();
            assert_eq!(
                serde_json::from_str::<super::ErrorCode>(&value).unwrap(),
                code
            );
        }
        assert_eq!(super::PROTOCOL_VERSION, 7);
    }
    use rosetun_config::{
        AppConfig, Node, NodeId, Outbound, Rule, RuleId, RuleMatcher, RuleSet, RuleSetId,
        RuleTarget, RuleTemplate, Selection, StreamSettings, Subscription, SubscriptionId,
        TrojanParams,
    };

    use super::{ConnectRequest, ConnectRequestError, ListFormat, ListRef, ProbeRequest, Request};

    #[test]
    fn list_requests_round_trip_without_exposing_chunks_in_debug() {
        let hash = "a".repeat(64);
        let status = Request::ListStatus {
            hashes: vec![hash.clone()],
        };
        let chunk = Request::PutListChunk {
            sha256: hash.clone(),
            format: ListFormat::Source,
            total_size: 6,
            offset: 0,
            data: "c2VjcmV0".into(),
        };
        for request in [status, chunk] {
            let encoded = serde_json::to_string(&request).unwrap();
            assert_eq!(serde_json::from_str::<Request>(&encoded).unwrap(), request);
            let debug = format!("{request:?}");
            assert!(!debug.contains("c2VjcmV0"));
            assert!(!debug.contains(&hash) || matches!(request, Request::PutListChunk { .. }));
        }
        assert_eq!(
            serde_json::to_string(&super::ErrorCode::ListMissing).unwrap(),
            "\"list_missing\""
        );
    }

    #[test]
    fn list_references_are_optional_and_debug_is_redacted() {
        let mut request = ConnectRequest::from_config(&selected_config()).unwrap();
        let old = serde_json::to_value(&request).unwrap();
        assert!(old.get("lists").is_none());
        let decoded: ConnectRequest = serde_json::from_value(old).unwrap();
        assert!(decoded.lists.is_empty());

        request.lists.push(ListRef {
            tag: "list-test".into(),
            sha256: "b".repeat(64),
            format: ListFormat::Binary,
        });
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["lists"][0]["format"], "binary");
        assert_eq!(
            serde_json::from_value::<ConnectRequest>(json).unwrap(),
            request
        );
        assert!(!format!("{request:?}").contains("list-test"));
        assert!(!format!("{:?}", request.lists[0]).contains("list-test"));
    }

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
        assert!(request.temporary_rules.is_empty());
    }

    #[test]
    fn request_requires_an_existing_selected_node() {
        let cases = [
            (
                AppConfig::default(),
                ConnectRequestError::SelectionMissing,
                "no node is selected",
            ),
            (
                dangling_node_config(),
                ConnectRequestError::NodeNotFound,
                "the selected node does not exist",
            ),
        ];

        for (config, expected, message) in cases {
            let error = ConnectRequest::from_config(&config).unwrap_err();

            assert_eq!(error, expected);
            assert_eq!(error.to_string(), message);
        }
    }

    #[test]
    fn request_expands_templates_in_place_before_sending_to_helper() {
        let mut config = selected_config();
        let template = Rule {
            id: RuleId::new("template"),
            enabled: false,
            matcher: RuleMatcher::Template(RuleTemplate::Torrents),
            target: RuleTarget::Block,
        };
        config.rule_sets[0].rules.insert(0, template.clone());
        let request = ConnectRequest::from_config(&config).unwrap();
        assert_eq!(request.rule_set.rules.len(), 8);
        for (rule, matcher) in request.rule_set.rules[..7]
            .iter()
            .zip(RuleTemplate::Torrents.matchers())
        {
            assert_eq!(rule.id, template.id);
            assert!(!rule.enabled);
            assert_eq!(rule.target, template.target);
            assert_eq!(rule.matcher, matcher);
        }
        assert_eq!(request.rule_set.rules[7], config.rule_sets[0].rules[1]);
        assert!(
            request
                .rule_set
                .rules
                .iter()
                .all(|rule| !matches!(rule.matcher, RuleMatcher::Template(_)))
        );
        assert_eq!(config.rule_sets[0].rules[0], template);
    }

    #[test]
    fn request_expands_enabled_templates_for_routing() {
        let mut config = selected_config();
        config.rule_sets[0].rules[0].matcher = RuleMatcher::Template(RuleTemplate::Youtube);
        config.rule_sets[0].rules[0].target = RuleTarget::Proxy;
        let request = ConnectRequest::from_config(&config).unwrap();
        assert_eq!(request.rule_set.rules.len(), 7);
        assert_eq!(
            request.rule_set.rules[0].matcher,
            RuleTemplate::Youtube.matchers()[0]
        );
        assert!(request.rule_set.rules.iter().all(|rule| rule.enabled));
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
    fn temporary_rules_precede_base_rules_without_changing_them() {
        let mut request = ConnectRequest::from_config(&selected_config()).unwrap();
        request.temporary_rules = vec![
            Rule {
                id: RuleId::new("first"),
                enabled: true,
                matcher: RuleMatcher::IpCidr("198.51.100.0/24".into()),
                target: RuleTarget::Direct,
            },
            Rule {
                id: RuleId::new("second"),
                enabled: false,
                matcher: RuleMatcher::IpCidr("203.0.113.0/24".into()),
                target: RuleTarget::Block,
            },
        ];
        let base = request.rule_set.clone();

        let effective = request.effective_rule_set();
        assert_eq!(effective.rules[..2], request.temporary_rules);
        assert_eq!(effective.rules[2..], base.rules);
        assert_eq!(effective.id, base.id);
        assert_eq!(effective.default_target, base.default_target);
        assert_eq!(request.rule_set, base);
    }

    #[test]
    fn request_debug_does_not_expose_credentials_or_rule_values() {
        let config = selected_config();
        let mut request = ConnectRequest::from_config(&config).unwrap();
        request.temporary_rules.push(Rule {
            id: RuleId::new("temporary"),
            enabled: true,
            matcher: RuleMatcher::Domain(rosetun_config::DomainMatch::Exact(
                "private.example.com".into(),
            )),
            target: RuleTarget::Direct,
        });
        for debug in [
            format!("{request:?}"),
            format!("{:?}", Request::Apply(Box::new(request))),
        ] {
            assert!(debug.contains("temporary_rule_count: 1"));
            assert!(!debug.contains("private.example.com"));
            assert!(!debug.contains("test-secret"));
            assert!(!debug.contains(&config.subscriptions[0].url));
        }
    }

    #[test]
    fn probe_debug_only_contains_count_and_engine() {
        let config = selected_config();
        let mut node = config.subscriptions[0].nodes[0].clone();
        node.id = NodeId::new("secret-node-uuid");
        let request = ProbeRequest {
            nodes: vec![node.clone()],
            settings: config.settings,
        };
        let debug = format!("{:?}", Request::ProbeNodes(Box::new(request)));

        assert!(debug.contains("node_count: 1"));
        assert!(debug.contains("engine:"));
        assert!(!debug.contains("test-secret"));
        assert!(!debug.contains("example.com"));
        assert!(!debug.contains(node.id.as_str()));
    }
}
