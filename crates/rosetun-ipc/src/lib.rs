#![cfg_attr(not(windows), forbid(unsafe_code))]
#![cfg_attr(windows, deny(unsafe_code))]

mod client;
mod codec;
mod protocol;
pub mod transport;

pub use client::{ClientError, HelperClient};
pub use codec::{CodecError, MAX_FRAME_BYTES, read_frame, write_frame};
pub use protocol::{
    ConnectRequest, ConnectRequestError, ErrorCode, Event, Frame, HelperError, ListFormat, ListRef,
    MAX_LIST_CHUNK_BYTES, MAX_LIST_PAYLOAD_BYTES, MAX_PROBE_NODES, MAX_TEMPORARY_RULES,
    PROTOCOL_VERSION, ProbeOutcome, ProbeRequest, ProbeResult, Request, Response,
};
pub use transport::{Connection, Listener, connect, default_endpoint};

pub const SERVICE_NAME: &str = "Rosetun";
