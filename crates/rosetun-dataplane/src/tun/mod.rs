//! Packet translation and flow state for the native layer-3 tunnel.

mod device;
mod egress;
mod mixed;
mod nat;
mod packet;
#[cfg(target_os = "linux")]
#[expect(unsafe_code, reason = "Linux socket-diagnostic netlink syscalls")]
mod process_linux;
#[cfg(target_os = "macos")]
#[expect(unsafe_code, reason = "Darwin libproc socket and process path queries")]
mod process_macos;
#[cfg(windows)]
#[expect(unsafe_code, reason = "IP Helper and limited process image queries")]
mod process_windows;
mod routes;
#[cfg(target_os = "linux")]
mod routes_linux;
#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "Darwin sysctl routing dump and interface index queries"
)]
mod routes_macos;
mod runtime;

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub use device::NativeDevice;
#[cfg(windows)]
pub use device::PinnedWintun;
pub use device::{DeviceSettings, PacketDevice, TunnelAddress};
pub use egress::PhysicalEgress;
pub use mixed::{MixedTcp, RedirectError, TcpFlow, TcpRedirect, TcpStack};
pub use nat::{FullConeNat, MappingError, MappingKey};
pub use packet::{Packet, PacketError, Transport, udp_reply};
#[cfg(target_os = "linux")]
pub use process_linux::LinuxProcessLookup;
#[cfg(target_os = "macos")]
pub use process_macos::MacosProcessLookup;
#[cfg(windows)]
pub use process_windows::WindowsProcessLookup;
pub use routes::{CaptureRoutes, RouteBackend, RouteLease};
#[cfg(windows)]
pub use routes::{InterfaceRoutes, WindowsRoutes};
#[cfg(target_os = "linux")]
pub use routes_linux::LinuxRoutes;
#[cfg(target_os = "macos")]
pub use routes_macos::MacosRoutes;
pub use runtime::{ProcessLookup, TunnelPolicy, TunnelRuntime};
