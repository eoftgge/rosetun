use serde::{Deserialize, Serialize};

use crate::{EngineKind, NodeId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectStage {
    WaitingForAdapter,
    StartingEngine,
    CheckingServer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    EngineNotReady,
    ServerUnreachable,
    ServerRejected,
    ServerClosed,
    DnsTimeout,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Failed {
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failure_kind: Option<FailureKind>,
    },
    FailedProtected {
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failure_kind: Option<FailureKind>,
    },
}

impl ConnectionState {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Connected | Self::FailedProtected { .. })
    }

    pub fn is_transitional(&self) -> bool {
        matches!(self, Self::Connecting | Self::Reconnecting)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Traffic {
    pub up_bps: u64,
    pub down_bps: u64,
    pub up_total: u64,
    pub down_total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Status {
    pub state: ConnectionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_stage: Option<ConnectStage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage_since_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<NodeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<EngineKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_unix: Option<u64>,
    #[serde(default)]
    pub traffic: Traffic,
}

#[cfg(test)]
mod failure_tests {
    use super::{ConnectionState, FailureKind, Status};

    #[test]
    fn failure_kind_is_optional_and_does_not_change_other_status_fields() {
        let old: Status = serde_json::from_str(
            r#"{"state":{"failed":{"reason":"engine did not start"}},"traffic":{"up_bps":0,"down_bps":0,"up_total":0,"down_total":0}}"#,
        )
        .unwrap();
        assert_eq!(
            old.state,
            ConnectionState::Failed {
                reason: "engine did not start".into(),
                failure_kind: None,
            }
        );
        let saved = serde_json::to_value(&old).unwrap();
        assert!(saved["state"]["failed"].get("failure_kind").is_none());

        let typed = Status {
            state: ConnectionState::FailedProtected {
                reason: "dial tcp 203.0.113.10:443: i/o timeout".into(),
                failure_kind: Some(FailureKind::ServerUnreachable),
            },
            ..Status::default()
        };
        let encoded = serde_json::to_value(&typed).unwrap();
        assert_eq!(
            encoded["state"]["failed_protected"]["failure_kind"],
            "server_unreachable"
        );
        assert_eq!(serde_json::from_value::<Status>(encoded).unwrap(), typed);
    }
}
