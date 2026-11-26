//! Rosetun's own data plane: rule engine, sniffer, DNS, connection table and
//! the local mixed proxy that routes each flow to `direct`, `block` or an
//! engine's authenticated loopback SOCKS5 entry.
//!
//! Everything runs on blocking worker threads; there is no async runtime.
//! No type here shows a destination, host, address, program path or
//! credential in `Debug` or in a log line.

#![deny(unsafe_code)]

pub mod conntable;
pub mod dataplane;
pub mod dns;
pub mod net;
#[expect(
    unsafe_code,
    reason = "polling requires registered sources to be deleted before drop, enforced by RAII wrappers"
)]
mod poller;
pub mod proxy;
pub mod rules;
pub mod sniff;
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "socket readiness without timing out Windows TCP I/O"
)]
mod socket_ready;
pub mod tun;

pub use dataplane::{
    Dataplane, DataplaneConfig, DataplaneError, ExitUpstream, NativeTunnel, OutboundEndpoints,
    UpstreamProxy, load_list_files,
};
