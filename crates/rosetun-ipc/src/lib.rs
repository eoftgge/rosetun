#![forbid(unsafe_code)]

mod codec;
mod protocol;
pub mod transport;

pub use codec::{CodecError, MAX_FRAME_BYTES, read_frame, write_frame};
pub use protocol::{
    ConnectRequest, ErrorCode, Event, Frame, HelperError, PROTOCOL_VERSION, Request, Response,
};
pub use transport::{Connection, Listener, connect, default_endpoint};