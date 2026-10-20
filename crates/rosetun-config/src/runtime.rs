use serde::{Deserialize, Serialize};

use crate::{EngineKind, ExitId, NodeId, XrayUse};

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
    XrayStartFailed,
    XrayStopped,
    NoNetwork,
    ServerUnreachable,
    ServerRejected,
    ServerClosed,
    DnsTimeout,
    ServerNameUnresolved,
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
    pub reconnect_failure_kind: Option<FailureKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_stage: Option<ConnectStage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage_since_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<NodeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<EngineKind>,
    #[serde(default)]
    pub xray: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xray_use: Option<XrayUse>,
    #[serde(default)]
    pub xray_stopped: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_unix: Option<u64>,
    #[serde(default)]
    pub traffic: Traffic,
    /// Lockdown's persistent block is installed (protocol 12).
    #[serde(default)]
    pub lockdown: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionNetwork {
    Tcp,
    Udp,
}

/// Where the engine sent a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionRoute {
    Proxy,
    Direct,
    Exit(ExitId),
    Other,
}

/// One connection of the running session (IPC only, never persisted or logged:
/// it is the user's browsing history).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveConnection {
    /// The engine's own id for the connection (a random UUID in sing-box, not
    /// an address), used to select and close it. Empty when the engine's id
    /// is too long to be closed.
    pub id: String,
    pub start_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_unix_ms: Option<u64>,
    /// Full path of the program, when the engine found it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    /// The sniffed or requested domain, otherwise the IP address.
    pub host: String,
    pub port: u16,
    pub network: ConnectionNetwork,
    pub route: ConnectionRoute,
    pub download: u64,
    pub upload: u64,
}

impl std::fmt::Debug for LiveConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveConnection")
            .field("closed", &self.end_unix_ms.is_some())
            .field("network", &self.network)
            .field("download", &self.download)
            .field("upload", &self.upload)
            .finish_non_exhaustive()
    }
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

    #[test]
    fn reconnect_reports_network_loss_without_changing_state_shape() {
        let status = Status {
            state: ConnectionState::Reconnecting,
            reconnect_failure_kind: Some(FailureKind::NoNetwork),
            ..Status::default()
        };
        let encoded = serde_json::to_value(&status).unwrap();
        assert_eq!(encoded["state"], "reconnecting");
        assert_eq!(encoded["reconnect_failure_kind"], "no_network");
        assert_eq!(serde_json::from_value::<Status>(encoded).unwrap(), status);
        assert!(
            serde_json::to_value(Status::default())
                .unwrap()
                .get("reconnect_failure_kind")
                .is_none()
        );
    }

    #[test]
    fn status_reports_the_actual_engine_chain() {
        let status = Status {
            xray: true,
            ..Status::default()
        };
        assert_eq!(serde_json::to_value(&status).unwrap()["xray"], true);
        assert!(
            !serde_json::from_str::<Status>(r#"{"state":"disconnected"}"#)
                .unwrap()
                .xray
        );
    }
}
