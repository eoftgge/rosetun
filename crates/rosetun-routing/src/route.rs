//! Read-only route lookups. No probe packet is sent to the destination.

use std::io;
use std::net::IpAddr;

/// The interface the OS selects for an ordinary, unmarked connection.
/// This says nothing about firewall acceptance or application-specific routes.
pub fn route_interface(address: IpAddr) -> io::Result<String> {
    platform::route_interface(address)
}

#[cfg(windows)]
#[path = "route/windows.rs"]
mod platform;
#[cfg(target_os = "linux")]
#[path = "route/linux.rs"]
mod platform;
#[cfg(not(any(windows, target_os = "linux")))]
mod platform {
    pub(super) fn route_interface(_: std::net::IpAddr) -> std::io::Result<String> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}
