use serde::{Deserialize, Serialize};

use crate::{EngineKind, ExitId, Node, NodeId, Settings, XrayUse, fragments_tls, uses_xray};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectStage {
    WaitingForAdapter,
    /// The server name cannot be looked up yet: right after power-on the
    /// adapter is up before the network carries anything.
    WaitingForNetwork,
    /// Waiting for the engine's version check, which an antivirus can hold up
    /// for half a minute after a cold boot.
    CheckingEngine,
    StartingEngine,
    CheckingServer,
}

/// A stage this build does not know reads as none, so a newer service never
/// makes the whole status unreadable.
fn known_stage<'de, D>(deserializer: D) -> Result<Option<ConnectStage>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Stage {
        Known(ConnectStage),
        Unknown(serde::de::IgnoredAny),
    }
    Ok(match Option::<Stage>::deserialize(deserializer)? {
        Some(Stage::Known(stage)) => Some(stage),
        Some(Stage::Unknown(_)) | None => None,
    })
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

/// The protection the helper's routing backend implements, reported in
/// `Hello` (protocol 14). It says what exists, not whether it works right
/// now: a Windows service that cannot reach the firewall still has a kill
/// switch, and a connect that needs it fails with its own error. Nothing
/// is available by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProtectionCapabilities {
    #[serde(default)]
    pub kill_switch: bool,
    #[serde(default)]
    pub lockdown: bool,
}

impl ProtectionCapabilities {
    /// The kill switch a request asks for: the saved setting, where the
    /// helper can give it. The saved setting itself stays as the user left it.
    pub fn effective_kill_switch(self, saved: bool) -> bool {
        saved && self.kill_switch
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Status {
    pub state: ConnectionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect_failure_kind: Option<FailureKind>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "known_stage"
    )]
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
    /// The connection to the server is split into pieces in this session (protocol 15).
    #[serde(default)]
    pub fragmented: bool,
    /// Fragmentation was on in the settings this session started with. With `fragmented` off
    /// it means the server's protocol cannot have it.
    #[serde(default)]
    pub fragment_requested: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_unix: Option<u64>,
    #[serde(default)]
    pub traffic: Traffic,
    /// Lockdown's persistent block is installed (protocol 12).
    #[serde(default)]
    pub lockdown: bool,
}

impl Status {
    /// Records which engine chain carries the session that just came up.
    pub fn record_chain(&mut self, node: &Node, settings: &Settings) {
        self.xray = uses_xray(node, settings);
        self.xray_use = Some(settings.xray);
        self.xray_stopped = false;
        self.fragmented = fragments_tls(node, settings);
        self.fragment_requested = settings.tls_fragment.enabled;
    }
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
    /// The destination address when `host` is a name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
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
    use super::{ConnectStage, ConnectionState, FailureKind, ProtectionCapabilities, Status};

    #[test]
    fn an_unknown_connect_stage_reads_as_none_and_keeps_the_status() {
        let status: Status = serde_json::from_str(
            r#"{"state":"connecting","connect_stage":"a_later_stage","stage_since_unix":5}"#,
        )
        .unwrap();
        assert_eq!(status.state, ConnectionState::Connecting);
        assert_eq!(status.connect_stage, None);
        assert_eq!(status.stage_since_unix, Some(5));

        let checking = Status {
            connect_stage: Some(ConnectStage::CheckingEngine),
            ..Status::default()
        };
        let encoded = serde_json::to_value(&checking).unwrap();
        assert_eq!(encoded["connect_stage"], "checking_engine");
        assert_eq!(serde_json::from_value::<Status>(encoded).unwrap(), checking);
        assert_eq!(
            serde_json::from_str::<Status>(r#"{"state":"connecting","connect_stage":null}"#)
                .unwrap()
                .connect_stage,
            None
        );
    }

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

    #[test]
    fn old_status_reports_no_fragmentation() {
        let status: Status = serde_json::from_str(r#"{"state":"disconnected"}"#).unwrap();
        assert!(!status.fragmented && !status.fragment_requested);
    }

    #[test]
    fn protection_is_unavailable_unless_the_helper_says_otherwise() {
        let none = ProtectionCapabilities::default();
        assert!(!none.kill_switch && !none.lockdown);
        assert_eq!(
            serde_json::from_str::<ProtectionCapabilities>("{}").unwrap(),
            none
        );
        assert!(
            !serde_json::from_str::<ProtectionCapabilities>(r#"{"lockdown":true}"#)
                .unwrap()
                .kill_switch
        );
    }

    #[test]
    fn the_effective_kill_switch_needs_both_the_setting_and_the_capability() {
        let full = ProtectionCapabilities {
            kill_switch: true,
            lockdown: true,
        };
        let none = ProtectionCapabilities::default();
        assert!(full.effective_kill_switch(true));
        assert!(!full.effective_kill_switch(false));
        assert!(!none.effective_kill_switch(true));
        assert!(!none.effective_kill_switch(false));
    }
}
