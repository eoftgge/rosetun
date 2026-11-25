//! Rosetun's own data plane: rule engine, sniffer, DNS, connection table and
//! the local mixed proxy that routes each flow to `direct`, `block` or an
//! engine's authenticated loopback SOCKS5 entry.
//!
//! Everything runs on blocking worker threads; there is no async runtime.
//! No type here shows a destination, host, address, program path or
//! credential in `Debug` or in a log line.

#![forbid(unsafe_code)]

pub mod conntable;
pub mod dataplane;
pub mod dns;
pub mod net;
pub mod proxy;
pub mod rules;
pub mod sniff;

pub use dataplane::{
    Dataplane, DataplaneConfig, DataplaneError, ExitUpstream, OutboundEndpoints, UpstreamProxy,
    load_list_files,
};
