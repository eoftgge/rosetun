use std::path::Path;

use rosetun_config::Status;
use rosetun_ipc::{
    ConnectRequest, Connection, Frame, HelperError, PROTOCOL_VERSION, Request, Response,
};

const CLIENT: &str = concat!("rosetun/", env!("CARGO_PKG_VERSION"));

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
}

#[derive(Debug)]
pub struct HelperClient {
    connection: Connection,
    next_id: u64,
    helper_version: String,
}

impl HelperClient {
    pub fn connect(endpoint: &Path) -> Result<Self, ClientError> {
        let connection = rosetun_ipc::connect(endpoint)
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        let mut client = Self {
            connection,
            next_id: 1,
            helper_version: String::new(),
        };
        match client.request(Request::Hello {
            client: CLIENT.to_owned(),
            protocol_version: PROTOCOL_VERSION,
        })? {
            Response::Hello { helper_version, .. } => {
                client.helper_version = helper_version;
                Ok(client)
            }
            _ => Err(ClientError::Unexpected),
        }
    }

    pub fn helper_version(&self) -> &str {
        &self.helper_version
    }

    pub fn status(&mut self) -> Result<Status, ClientError> {
        match self.request(Request::Status)? {
            Response::Status(status) => Ok(status),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub fn connect_tunnel(&mut self, request: ConnectRequest) -> Result<(), ClientError> {
        self.expect_ok(Request::Connect(Box::new(request)))
    }

    pub fn disconnect_tunnel(&mut self) -> Result<(), ClientError> {
        self.expect_ok(Request::Disconnect)
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
