use rosetun_config::{
    AppConfig, ExitId, LogLevel, Node, NodeId, Rule, RuleSet, RuleSetId, RuleTarget, Selection,
    Settings, Status, Traffic, resolve_exits,
};
use serde::{Deserialize, Serialize};
use std::fmt::Formatter;
use std::time::Duration;

pub const PROTOCOL_VERSION: u32 = 12;
pub const MAX_PROBE_NODES: usize = 256;
pub const MAX_TEMPORARY_RULES: usize = 256;
pub const MAX_EXTRA_NODES: usize = 16;
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
    SessionExits,
    DiagnosticLog,
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
    /// Turns Lockdown on (or updates its LAN permits) or off (protocol 12).
    SetLockdown {
        enabled: bool,
        allow_lan: bool,
    },
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
            Self::SessionExits => f.write_str("SessionExits"),
            Self::DiagnosticLog => f.write_str("DiagnosticLog"),
            Self::TunnelDelay => f.write_str("TunnelDelay"),
            Self::Disconnect => f.write_str("Disconnect"),
            Self::SetLockdown { enabled, allow_lan } => f
                .debug_struct("SetLockdown")
                .field("enabled", enabled)
                .field("allow_lan", allow_lan)
                .finish(),
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
pub struct ExtraNode {
    pub exit: ExitId,
    pub selection: Selection,
    pub node: Node,
}

impl std::fmt::Debug for ExtraNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtraNode")
            .field("exit", &self.exit)
            .field("selection", &self.selection)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ExitContext<'a> {
    pub delays: &'a [(Selection, Duration)],
    pub selected: &'a [(ExitId, Selection)],
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub selection: Selection,
    pub node: Node,
    pub rule_set: RuleSet,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_nodes: Vec<ExtraNode>,
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
            .field("extra_node_count", &self.extra_nodes.len())
            .field("temporary_rule_count", &self.temporary_rules.len())
            .field("list_count", &self.lists.len())
            .finish_non_exhaustive()
    }
}

impl ConnectRequest {
    pub fn from_config(config: &AppConfig) -> Result<Self, ConnectRequestError> {
        Self::from_config_with_exits(config, ExitContext::default())
    }

    pub fn from_config_with_exits(
        config: &AppConfig,
        exits: ExitContext<'_>,
    ) -> Result<Self, ConnectRequestError> {
        let (request, blocked) = Self::build(config, Vec::new(), exits)?;
        warn_blocked_exits(blocked);
        Ok(request)
    }

    fn build(
        config: &AppConfig,
        temporary_rules: Vec<Rule>,
        exits: ExitContext<'_>,
    ) -> Result<(Self, usize), ConnectRequestError> {
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
        let mut request = Self {
            selection: selection.clone(),
            node: node.clone(),
            rule_set,
            extra_nodes: Vec::new(),
            temporary_rules,
            lists: Vec::new(),
            settings: config.settings.clone(),
        };
        let referenced = |id: &ExitId| {
            request
                .rule_set
                .enabled()
                .chain(request.temporary_rules.iter().filter(|rule| rule.enabled))
                .any(|rule| rule.target == RuleTarget::Exit && rule.exit.as_ref() == Some(id))
        };
        let used: Vec<_> = config
            .exits
            .iter()
            .filter(|exit| referenced(&exit.id))
            .cloned()
            .collect();
        let resolved = resolve_exits(&used, &config.subscriptions, exits.delays, exits.selected);
        let mut blocked = 0;
        for rule in request
            .rule_set
            .rules
            .iter_mut()
            .chain(&mut request.temporary_rules)
            .filter(|rule| rule.enabled && rule.target == RuleTarget::Exit)
        {
            let Some((id, Some(selected))) = rule
                .exit
                .as_ref()
                .and_then(|id| resolved.iter().find(|(exit, _)| exit == id))
            else {
                rule.target = RuleTarget::Block;
                rule.exit = None;
                blocked += 1;
                continue;
            };
            if selected == selection {
                rule.target = RuleTarget::Proxy;
                rule.exit = None;
            } else if !request.extra_nodes.iter().any(|extra| extra.exit == *id) {
                if let Some(node) = config
                    .subscriptions
                    .iter()
                    .find(|sub| sub.id == selected.subscription)
                    .and_then(|sub| sub.node(&selected.node))
                {
                    request.extra_nodes.push(ExtraNode {
                        exit: id.clone(),
                        selection: selected.clone(),
                        node: node.clone(),
                    });
                } else {
                    rule.target = RuleTarget::Block;
                    rule.exit = None;
                    blocked += 1;
                }
            }
        }
        Ok((request, blocked))
    }

    pub fn for_apply(
        config: &AppConfig,
        running: Option<&Settings>,
        temporary_rules: Vec<Rule>,
    ) -> Result<Self, ConnectRequestError> {
        Self::for_apply_with_exits(config, running, temporary_rules, ExitContext::default())
    }

    pub fn for_apply_with_exits(
        config: &AppConfig,
        running: Option<&Settings>,
        temporary_rules: Vec<Rule>,
        exits: ExitContext<'_>,
    ) -> Result<Self, ConnectRequestError> {
        let (mut request, blocked) = Self::build(config, temporary_rules, exits)?;
        if let Some(running) = running {
            request.settings.engine = running.engine;
            request.settings.xray = running.xray;
            request.settings.tun = running.tun.clone();
            request.settings.kill_switch = running.kill_switch;
            request.settings.allow_lan = running.allow_lan;
        }
        warn_blocked_exits(blocked);
        Ok(request)
    }

    pub fn effective_rule_set(&self) -> RuleSet {
        let mut rules = self.rule_set.clone();
        rules
            .rules
            .splice(0..0, self.temporary_rules.iter().cloned());
        rules
    }
}

fn warn_blocked_exits(count: usize) {
    if count > 0 {
        tracing::warn!(
            count,
            "exit rules blocked because their exits could not be resolved"
        );
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

/// How an exit of the running session answered a delay check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitOutcome {
    Probed(ProbeOutcome),
    /// The exit's server had no address, so its rules block instead.
    NoAddress,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitDelay {
    pub exit: ExitId,
    pub outcome: ExitOutcome,
}

/// Delay through the main node and through each exit of the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelDelays {
    pub proxy: ProbeOutcome,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exits: Vec<ExitDelay>,
}

/// The node an exit of the running session goes through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionExit {
    pub exit: ExitId,
    pub selection: Selection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Hello {
        helper_version: String,
        protocol_version: u32,
        #[serde(default)]
        sing_box_version: Option<String>,
        #[serde(default)]
        xray_version: Option<String>,
    },
    Status(Status),
    TemporaryRules(Vec<Rule>),
    SessionExits(Vec<SessionExit>),
    DiagnosticLog {
        text: String,
    },
    ListStatus {
        missing: Vec<String>,
    },
    Probe(Vec<ProbeResult>),
    Delay(TunnelDelays),
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
    AccessDenied,
    EngineFailed,
    XrayStartFailed,
    XrayStopped,
    NoNetwork,
    ServerUnreachable,
    ServerRejected,
    ServerClosed,
    DnsTimeout,
    Cancelled,
    EngineNotReady,
    RoutingFailed,
    Busy,
    InvalidState,
    InvalidRequest,
    UnsupportedRules,
    ListMissing,
    NotImplemented,
    Internal,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    #[test]
    fn classified_errors_round_trip() {
        for code in [
            super::ErrorCode::AccessDenied,
            super::ErrorCode::XrayStartFailed,
            super::ErrorCode::XrayStopped,
            super::ErrorCode::NoNetwork,
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
        assert_eq!(
            serde_json::to_string(&super::ErrorCode::AccessDenied).unwrap(),
            "\"access_denied\""
        );
        assert_eq!(super::PROTOCOL_VERSION, 12);
        let lockdown = super::Request::SetLockdown {
            enabled: true,
            allow_lan: false,
        };
        let encoded = serde_json::to_string(&lockdown).unwrap();
        assert_eq!(
            encoded,
            r#"{"set_lockdown":{"enabled":true,"allow_lan":false}}"#
        );
        assert_eq!(
            serde_json::from_str::<super::Request>(&encoded).unwrap(),
            lockdown
        );
    }
    use rosetun_config::{
        AppConfig, CountryCode, EngineKind, Exit, ExitId, ExitTarget, Node, NodeId, Outbound, Rule,
        RuleId, RuleMatcher, RuleSet, RuleSetId, RuleTarget, RuleTemplate, Selection,
        StreamSettings, Subscription, SubscriptionId, TrojanParams,
    };

    use super::{
        ConnectRequest, ConnectRequestError, ExitContext, ListFormat, ListRef, ProbeRequest,
        Request,
    };

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
        assert!(old.get("extra_nodes").is_none());
        let decoded: ConnectRequest = serde_json::from_value(old).unwrap();
        assert!(decoded.lists.is_empty());
        assert!(decoded.extra_nodes.is_empty());

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
            exit: None,
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
    fn unresolved_exit_rules_are_blocked_in_requests() {
        let mut config = selected_config();
        let exit_id = ExitId::new("1");
        config.exits.push(Exit {
            id: exit_id.clone(),
            name: "Example exit".into(),
            target: ExitTarget::Country(CountryCode::parse("GB").unwrap()),
        });
        config.rule_sets[0].rules.push(Rule {
            id: RuleId::new("exit"),
            enabled: true,
            matcher: RuleMatcher::Template(RuleTemplate::Youtube),
            target: RuleTarget::Exit,
            exit: Some(exit_id.clone()),
        });
        assert!(config.validate().is_ok());

        let request = ConnectRequest::from_config(&config).unwrap();
        let exit_rules: Vec<_> = request
            .rule_set
            .rules
            .iter()
            .filter(|rule| rule.id.as_str() == "exit")
            .collect();
        assert_eq!(exit_rules.len(), RuleTemplate::Youtube.matchers().len());
        assert!(
            exit_rules
                .iter()
                .all(|rule| rule.target == RuleTarget::Block && rule.exit.is_none())
        );
        assert_eq!(request.rule_set.rules[0].target, RuleTarget::Block);
        assert_eq!(config.rule_sets[0].rules[1].target, RuleTarget::Exit);

        let temporary = Rule {
            id: RuleId::new("temporary"),
            enabled: true,
            matcher: RuleMatcher::IpCidr("198.51.100.0/24".into()),
            target: RuleTarget::Exit,
            exit: Some(exit_id),
        };
        let applied = ConnectRequest::for_apply(&config, None, vec![temporary]).unwrap();
        assert_eq!(applied.temporary_rules[0].target, RuleTarget::Block);
        assert!(applied.temporary_rules[0].exit.is_none());
        assert!(applied.extra_nodes.is_empty());
    }

    #[test]
    fn exit_rules_share_one_extra_node_and_disabled_rules_add_none() {
        let mut config = selected_config();
        let exit = ExitId::new("gb");
        let mut other = config.subscriptions[0].nodes[0].clone();
        other.id = NodeId::new("gb-node");
        other.name = "GB example node".into();
        other.server = "192.0.2.10".into();
        config.subscriptions[0].nodes.push(other.clone());
        config.exits.push(Exit {
            id: exit.clone(),
            name: "GB exit".into(),
            target: ExitTarget::Country(CountryCode::parse("GB").unwrap()),
        });
        let rule = Rule {
            id: RuleId::new("exit"),
            enabled: true,
            matcher: RuleMatcher::IpCidr("198.51.100.0/24".into()),
            target: RuleTarget::Exit,
            exit: Some(exit.clone()),
        };
        config.rule_sets[0].rules.push(rule.clone());
        config.rule_sets[0].rules.push(Rule {
            id: RuleId::new("disabled"),
            enabled: false,
            ..rule.clone()
        });
        let request = ConnectRequest::for_apply(&config, None, vec![rule.clone()]).unwrap();
        assert_eq!(request.rule_set.rules[1].target, RuleTarget::Exit);
        assert_eq!(request.temporary_rules[0].target, RuleTarget::Exit);
        assert_eq!(request.extra_nodes.len(), 1);
        assert_eq!(request.extra_nodes[0].exit, exit);
        assert_eq!(request.extra_nodes[0].node, other);
        assert_eq!(
            serde_json::from_str::<ConnectRequest>(&serde_json::to_string(&request).unwrap())
                .unwrap(),
            request
        );
        let debug = format!("{request:?}");
        assert!(debug.contains("extra_node_count: 1"));
        assert!(!debug.contains("192.0.2.10"));
        assert!(!debug.contains("test-secret"));

        config.rule_sets[0].rules[1].enabled = false;
        let request = ConnectRequest::from_config(&config).unwrap();
        assert!(request.extra_nodes.is_empty());
        assert_eq!(request.rule_set.rules[1].target, RuleTarget::Exit);
    }

    #[test]
    fn selected_country_node_stays_fixed_when_another_node_gets_faster() {
        let mut config = selected_config();
        let exit = ExitId::new("gb");
        config.exits.push(Exit {
            id: exit.clone(),
            name: "GB exit".into(),
            target: ExitTarget::Country(CountryCode::parse("GB").unwrap()),
        });
        config.rule_sets[0].rules.push(Rule {
            id: RuleId::new("country"),
            enabled: true,
            matcher: RuleMatcher::IpCidr("203.0.113.0/24".into()),
            target: RuleTarget::Exit,
            exit: Some(exit.clone()),
        });
        let mut first = config.subscriptions[0].nodes[0].clone();
        first.id = NodeId::new("gb-first");
        first.name = "GB first".into();
        let mut second = first.clone();
        second.id = NodeId::new("gb-second");
        second.name = "GB second".into();
        config.subscriptions[0].nodes.extend([first, second]);
        let first = Selection {
            subscription: config.subscriptions[0].id.clone(),
            node: NodeId::new("gb-first"),
        };
        let second = Selection {
            subscription: config.subscriptions[0].id.clone(),
            node: NodeId::new("gb-second"),
        };
        let delays = [
            (first.clone(), Duration::from_millis(80)),
            (second.clone(), Duration::from_millis(10)),
        ];
        let request = ConnectRequest::from_config_with_exits(
            &config,
            ExitContext {
                delays: &delays,
                selected: &[],
            },
        )
        .unwrap();
        assert_eq!(request.extra_nodes[0].selection, second);
        let pinned = [(exit, first.clone())];
        let request = ConnectRequest::from_config_with_exits(
            &config,
            ExitContext {
                delays: &delays,
                selected: &pinned,
            },
        )
        .unwrap();
        assert_eq!(request.extra_nodes[0].selection, first);
    }

    #[test]
    fn exit_on_main_node_becomes_proxy_in_base_and_temporary_rules() {
        let mut config = selected_config();
        let exit = ExitId::new("main");
        config.exits.push(Exit {
            id: exit.clone(),
            name: "Main exit".into(),
            target: ExitTarget::Node {
                selection: config.active.clone().unwrap(),
                fallback: None,
            },
        });
        let rule = Rule {
            id: RuleId::new("exit"),
            enabled: true,
            matcher: RuleMatcher::IpCidr("203.0.113.0/24".into()),
            target: RuleTarget::Exit,
            exit: Some(exit),
        };
        config.rule_sets[0].rules.push(rule.clone());
        let request = ConnectRequest::for_apply(&config, None, vec![rule]).unwrap();
        assert!(request.extra_nodes.is_empty());
        for rule in [&request.rule_set.rules[1], &request.temporary_rules[0]] {
            assert_eq!(rule.target, RuleTarget::Proxy);
            assert!(rule.exit.is_none());
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
    fn apply_request_uses_config_settings_without_running_session() {
        let mut config = selected_config();
        config.settings.kill_switch = true;
        config.settings.dns.server_name = "dns.example.com".to_owned();
        let temporary = Rule {
            id: RuleId::new("temporary"),
            enabled: true,
            matcher: RuleMatcher::IpCidr("198.51.100.0/24".to_owned()),
            target: RuleTarget::Direct,
            exit: None,
        };

        let request = ConnectRequest::for_apply(&config, None, vec![temporary.clone()]).unwrap();

        assert_eq!(request.settings, config.settings);
        assert_eq!(request.temporary_rules, vec![temporary]);
        assert!(request.lists.is_empty());
    }

    #[test]
    fn apply_request_keeps_running_protection_but_new_other_settings() {
        let mut config = selected_config();
        config.settings.dns.server_name = "dns.example.com".to_owned();
        config.settings.auto_reconnect = false;
        let mut running = config.settings.clone();
        running.engine = EngineKind::Xray;
        running.xray = rosetun_config::XrayUse::Off;
        running.tun.name = "old-tun".to_owned();
        running.kill_switch = true;
        running.allow_lan = true;
        running.dns.server_name = "old.example.com".to_owned();
        running.auto_reconnect = true;

        let request = ConnectRequest::for_apply(&config, Some(&running), Vec::new()).unwrap();

        assert_eq!(request.settings.engine, running.engine);
        assert_eq!(request.settings.xray, running.xray);
        assert_eq!(request.settings.tun, running.tun);
        assert_eq!(request.settings.kill_switch, running.kill_switch);
        assert_eq!(request.settings.allow_lan, running.allow_lan);
        assert_eq!(request.settings.dns, config.settings.dns);
        assert_eq!(
            request.settings.auto_reconnect,
            config.settings.auto_reconnect
        );
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
            exit: None,
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
                exit: None,
            },
            Rule {
                id: RuleId::new("second"),
                enabled: false,
                matcher: RuleMatcher::IpCidr("203.0.113.0/24".into()),
                target: RuleTarget::Block,
                exit: None,
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
            exit: None,
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

    #[test]
    fn exit_responses_debug_has_no_node_addresses() {
        use super::{ExitDelay, ExitOutcome, ProbeOutcome, Response, SessionExit, TunnelDelays};
        use rosetun_config::ExitId;

        let config = selected_config();
        let node = &config.subscriptions[0].nodes[0];
        let responses = [
            Response::SessionExits(vec![SessionExit {
                exit: ExitId::new("exit"),
                selection: config.active.clone().unwrap(),
            }]),
            Response::Delay(TunnelDelays {
                proxy: ProbeOutcome::Works { millis: 12 },
                exits: vec![ExitDelay {
                    exit: ExitId::new("exit"),
                    outcome: ExitOutcome::NoAddress,
                }],
            }),
        ];
        for response in responses {
            let debug = format!("{response:?}");
            assert!(debug.contains("exit"));
            assert!(!debug.contains(&node.server));
            assert!(!debug.contains("test-secret"));
        }
    }
}
