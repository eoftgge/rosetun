use std::path::Path;

use crate::{
    ConnectRequest, Connection, Frame, HelperError, ListFormat, PROTOCOL_VERSION, ProbeRequest,
    ProbeResult, Request, Response, SessionExit, TunnelDelays,
};
use rosetun_config::{LiveConnection, ProtectionCapabilities, Rule, Status};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("unable to contact helper: {0}")]
    Transport(String),
    #[error("helper answered with an error: {0}")]
    Helper(#[from] HelperError),
    #[error("unexpected response from helper")]
    Unexpected,
    #[error("helper closed the connection")]
    Closed,
    /// The socket's permissions refused this account.
    #[error(
        "no access to the Rosetun service: run sudo usermod -aG rosetun \"$USER\", then log out and log in again"
    )]
    SocketDenied,
}

fn connect_error(error: &std::io::Error) -> ClientError {
    // Only the system's own refusal: the transport's checks of who serves the
    // socket report PermissionDenied as well, and joining a group fixes none.
    #[cfg(target_os = "linux")]
    if error.raw_os_error() == Some(libc::EACCES) {
        return ClientError::SocketDenied;
    }
    ClientError::Transport(error.to_string())
}

#[derive(Debug)]
pub struct HelperClient {
    connection: Connection,
    next_id: u64,
    helper_version: String,
    sing_box_version: Option<String>,
    xray_version: Option<String>,
    protection: ProtectionCapabilities,
}

impl HelperClient {
    pub fn connect(endpoint: &Path, client_name: &str) -> Result<Self, ClientError> {
        let connection = crate::connect(endpoint).map_err(|error| connect_error(&error))?;
        let mut client = Self {
            connection,
            next_id: 1,
            helper_version: String::new(),
            sing_box_version: None,
            xray_version: None,
            protection: ProtectionCapabilities::default(),
        };
        match client.request(Request::Hello {
            client: client_name.to_owned(),
            protocol_version: PROTOCOL_VERSION,
        })? {
            Response::Hello {
                helper_version,
                sing_box_version,
                xray_version,
                protection,
                ..
            } => {
                client.helper_version = helper_version;
                client.sing_box_version = sing_box_version;
                client.xray_version = xray_version;
                client.protection = protection;
                Ok(client)
            }
            _ => Err(ClientError::Unexpected),
        }
    }

    pub fn helper_version(&self) -> &str {
        &self.helper_version
    }

    /// What the helper's routing can give, as it said in `Hello`.
    pub fn protection(&self) -> ProtectionCapabilities {
        self.protection
    }

    pub fn engine_versions(&self) -> (Option<&str>, Option<&str>) {
        (
            self.sing_box_version.as_deref(),
            self.xray_version.as_deref(),
        )
    }

    pub fn diagnostic_log(&mut self) -> Result<String, ClientError> {
        match self.request(Request::DiagnosticLog)? {
            Response::DiagnosticLog { text } => Ok(text),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub fn status(&mut self) -> Result<Status, ClientError> {
        match self.request(Request::Status)? {
            Response::Status(status) => Ok(status),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub fn temporary_rules(&mut self) -> Result<Vec<Rule>, ClientError> {
        match self.request(Request::TemporaryRules)? {
            Response::TemporaryRules(rules) => Ok(rules),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub fn session_exits(&mut self) -> Result<Vec<SessionExit>, ClientError> {
        match self.request(Request::SessionExits)? {
            Response::SessionExits(exits) => Ok(exits),
            _ => Err(ClientError::Unexpected),
        }
    }

    /// Active and recently closed connections of the session, newest first.
    pub fn connections(
        &mut self,
    ) -> Result<(Vec<LiveConnection>, Vec<LiveConnection>), ClientError> {
        match self.request(Request::Connections)? {
            Response::Connections { active, closed } => Ok((active, closed)),
            _ => Err(ClientError::Unexpected),
        }
    }

    /// Closes one active connection of the session by its id.
    pub fn close_connection(&mut self, id: &str) -> Result<(), ClientError> {
        self.expect_ok(Request::CloseConnection { id: id.to_owned() })
    }

    pub fn list_status(&mut self, hashes: Vec<String>) -> Result<Vec<String>, ClientError> {
        match self.request(Request::ListStatus { hashes })? {
            Response::ListStatus { missing } => Ok(missing),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub fn put_list_chunk(
        &mut self,
        sha256: &str,
        format: ListFormat,
        total_size: u64,
        offset: u64,
        data: String,
    ) -> Result<(), ClientError> {
        self.expect_ok(Request::PutListChunk {
            sha256: sha256.to_owned(),
            format,
            total_size,
            offset,
            data,
        })
    }

    pub fn connect_tunnel(&mut self, request: ConnectRequest) -> Result<(), ClientError> {
        self.expect_ok(Request::Connect(Box::new(request)))
    }

    pub fn apply_tunnel(&mut self, request: ConnectRequest) -> Result<(), ClientError> {
        self.expect_ok(Request::Apply(Box::new(request)))
    }

    pub fn probe_nodes(&mut self, request: ProbeRequest) -> Result<Vec<ProbeResult>, ClientError> {
        match self.request(Request::ProbeNodes(Box::new(request)))? {
            Response::Probe(results) => Ok(results),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub fn tunnel_delay(&mut self) -> Result<TunnelDelays, ClientError> {
        match self.request(Request::TunnelDelay)? {
            Response::Delay(delays) => Ok(delays),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub fn disconnect_tunnel(&mut self) -> Result<(), ClientError> {
        self.expect_ok(Request::Disconnect)
    }

    pub fn reconnect_tunnel(&mut self) -> Result<(), ClientError> {
        self.expect_ok(Request::Reconnect)
    }

    /// `private_networks` counts only with `allow_lan`.
    pub fn set_lockdown(
        &mut self,
        enabled: bool,
        allow_lan: bool,
        private_networks: bool,
    ) -> Result<(), ClientError> {
        self.expect_ok(Request::SetLockdown {
            enabled,
            allow_lan,
            private_networks: allow_lan && private_networks,
        })
    }

    /// Lifts the hold an upgrade left; `Ok` when there was none.
    pub fn open_network(&mut self) -> Result<(), ClientError> {
        self.expect_ok(Request::OpenNetwork)
    }

    pub fn shutdown(&mut self) -> Result<(), ClientError> {
        self.expect_ok(Request::Shutdown)
    }

    fn expect_ok(&mut self, request: Request) -> Result<(), ClientError> {
        match self.request(request)? {
            Response::Ok => Ok(()),
            _ => Err(ClientError::Unexpected),
        }
    }

    fn request(&mut self, body: Request) -> Result<Response, ClientError> {
        let id = self.next_id;
        self.next_id += 1;

        self.connection
            .write(&Frame::Request { id, body })
            .map_err(|error| ClientError::Transport(error.to_string()))?;

        loop {
            let frame = self
                .connection
                .read()
                .map_err(|error| ClientError::Transport(error.to_string()))?
                .ok_or(ClientError::Closed)?;
            match frame {
                Frame::Response { id: got, body } if got == id => {
                    return match body {
                        Response::Error(error) => Err(ClientError::Helper(error)),
                        other => Ok(other),
                    };
                }
                _ => continue,
            }
        }
    }
}
