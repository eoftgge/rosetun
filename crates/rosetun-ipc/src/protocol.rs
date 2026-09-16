use rosetun_config::{LogLevel, Node, RuleSet, Selection, Settings, Status, Traffic};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub selection: Selection,
    pub node: Node,
    pub rule_set: RuleSet,
    pub settings: Settings,
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
    NotImplemented,
    Internal,
}
