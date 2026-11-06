//! The proxy mode: what the engine listens on, found free before it starts.

use std::io;
#[cfg(windows)]
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use rosetun_config::{ConnectionMode, Settings};
use rosetun_engine::LocalProxyListen;
use rosetun_ipc::{ErrorCode, HelperError};

use super::lockdown::LockdownState;
use super::sleep_cancellable;

/// The engine a restart replaces has exited, but Windows may hold its port for
/// a moment longer, and a busy port should not fail a restart for that.
const PORT_TRIES: u32 = 5;
const PORT_RETRY_DELAY: Duration = Duration::from_millis(200);

/// Why a port cannot be listened on.
#[derive(Debug, PartialEq, Eq)]
enum PortProblem {
    /// Another program holds it, or the system reserves it.
    Busy,
    /// The system has no such address, as IPv6 on a machine without it.
    NoAddress,
    Other,
}

impl PortProblem {
    fn of(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied => Self::Busy,
            io::ErrorKind::AddrNotAvailable => Self::NoAddress,
            // EAFNOSUPPORT, which std has no kind for, and Windows' WSAEAFNOSUPPORT.
            _ if matches!(error.raw_os_error(), Some(97 | 10047)) => Self::NoAddress,
            _ => Self::Other,
        }
    }
}

fn try_bind(address: SocketAddr) -> Result<(), PortProblem> {
    TcpListener::bind(address)
        .map(drop)
        .map_err(|error| PortProblem::of(&error))
}

/// What the local proxy listens on when `port` is free for it.
///
/// Shared on Windows it listens on `::` where the system has IPv6, which also
/// serves IPv4 clients, and filters let in only the computer's own networks.
#[cfg(windows)]
fn free_addresses(port: u16, share: bool, _: &[IpAddr]) -> Result<Vec<SocketAddr>, PortProblem> {
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    try_bind(loopback)?;
    if !share {
        return Ok(vec![loopback]);
    }
    let any_v4 = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    try_bind(any_v4)?;
    let any_v6 = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));
    match try_bind(any_v6) {
        Ok(()) => Ok(vec![any_v6]),
        Err(PortProblem::NoAddress) => Ok(vec![any_v4]),
        Err(problem) => Err(problem),
    }
}

/// Shared on Linux it listens on loopback and `connected`, the private addresses
/// of the physical interfaces: without Lockdown nothing else limits who gets in.
/// An address that went away meanwhile only costs that address.
#[cfg(not(windows))]
fn free_addresses(
    port: u16,
    share: bool,
    connected: &[IpAddr],
) -> Result<Vec<SocketAddr>, PortProblem> {
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    try_bind(loopback)?;
    let mut addresses = vec![loopback];
    if share {
        for address in connected {
            let address = SocketAddr::new(*address, port);
            match try_bind(address) {
                Ok(()) => addresses.push(address),
                Err(PortProblem::NoAddress) => {}
                Err(problem) => return Err(problem),
            }
        }
    }
    Ok(addresses)
}

/// A free loopback port for the engine's DNS. As with the control endpoint,
/// another process could take it before the engine does, and then the engine
/// fails to start, as any engine error.
fn free_dns_address() -> io::Result<SocketAddr> {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?.local_addr()
}

/// Whether other devices may reach a session's proxy now. Lockdown closes
/// inbound from everywhere but its own "Local network".
pub(super) fn sharing_allowed(lockdown: &LockdownState) -> bool {
    !lockdown.enabled || lockdown.allow_lan
}

/// The port to open to other devices: only in the proxy mode, with sharing on
/// and where Lockdown allows it.
pub(super) fn shared_port(settings: &Settings, lockdown: &LockdownState) -> Option<u16> {
    (settings.connection_mode == ConnectionMode::SystemProxy
        && settings.local_proxy.share_on_lan
        && sharing_allowed(lockdown))
    .then_some(settings.local_proxy.port)
}

/// `None` in the TUN mode. In the proxy mode the listener the engine gets, or
/// the error that names the taken port, before anything has started.
pub(super) fn listen_for(
    settings: &Settings,
    sharing_allowed: bool,
    connected: &[IpAddr],
    cancelled: &AtomicBool,
) -> Result<Option<LocalProxyListen>, HelperError> {
    if settings.connection_mode != ConnectionMode::SystemProxy {
        return Ok(None);
    }
    let port = settings.local_proxy.port;
    let mut tries = 0;
    let addresses = loop {
        tries += 1;
        match free_addresses(
            port,
            settings.local_proxy.share_on_lan && sharing_allowed,
            connected,
        ) {
            Ok(addresses) => break addresses,
            Err(PortProblem::Busy) if tries < PORT_TRIES => {
                sleep_cancellable(PORT_RETRY_DELAY, cancelled)?;
            }
            Err(PortProblem::Busy) => {
                tracing::warn!(port, "the local proxy port is held by another program");
                return Err(HelperError::local_proxy_port_busy(port));
            }
            Err(problem) => {
                return Err(HelperError::new(
                    ErrorCode::EngineFailed,
                    format!("cannot listen on the local proxy port {port}: {problem:?}"),
                ));
            }
        }
    };
    let dns = free_dns_address().map_err(|error| {
        HelperError::new(
            ErrorCode::EngineFailed,
            format!("cannot pick a port for the engine's DNS: {error}"),
        )
    })?;
    Ok(Some(LocalProxyListen { addresses, dns }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn free_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn proxy_settings(port: u16, share_on_lan: bool) -> Settings {
        let mut settings = Settings {
            connection_mode: ConnectionMode::SystemProxy,
            ..Settings::default()
        };
        settings.local_proxy.port = port;
        settings.local_proxy.share_on_lan = share_on_lan;
        settings
    }

    #[test]
    fn the_tunnel_mode_listens_on_nothing() {
        let cancelled = AtomicBool::new(false);
        assert_eq!(
            listen_for(&Settings::default(), true, &[], &cancelled).unwrap(),
            None
        );
    }

    #[test]
    fn an_unshared_proxy_listens_on_loopback_only() {
        let port = free_port();
        let listen = listen_for(
            &proxy_settings(port, false),
            true,
            &[],
            &AtomicBool::new(false),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            listen.addresses,
            [SocketAddr::from((Ipv4Addr::LOCALHOST, port))]
        );
        assert!(listen.dns.ip().is_loopback());
    }

    #[test]
    fn a_shared_proxy_listens_on_a_wildcard_address() {
        let port = free_port();
        let listen = listen_for(
            &proxy_settings(port, true),
            true,
            &[],
            &AtomicBool::new(false),
        )
        .unwrap()
        .unwrap();
        #[cfg(windows)]
        assert!(listen.addresses[0].ip().is_unspecified());
        // Linux takes its addresses from `connected`, which is empty here.
        #[cfg(not(windows))]
        assert_eq!(
            listen.addresses,
            [SocketAddr::from((Ipv4Addr::LOCALHOST, port))]
        );
        assert_eq!(listen.addresses[0].port(), port);
        assert!(listen.dns.ip().is_loopback());
    }

    #[test]
    fn lockdown_without_its_local_network_keeps_the_proxy_on_loopback() {
        let port = free_port();
        let listen = listen_for(
            &proxy_settings(port, true),
            false,
            &[],
            &AtomicBool::new(false),
        )
        .unwrap()
        .unwrap();
        assert!(
            listen
                .addresses
                .iter()
                .all(|address| address.ip().is_loopback())
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn a_shared_proxy_on_linux_listens_only_on_the_addresses_it_is_given() {
        let port = free_port();
        let connected: Vec<IpAddr> = vec!["127.0.0.2".parse().unwrap()];
        let listen = listen_for(
            &proxy_settings(port, true),
            true,
            &connected,
            &AtomicBool::new(false),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            listen.addresses,
            [
                SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                SocketAddr::new(connected[0], port),
            ]
        );
        let unshared = listen_for(
            &proxy_settings(port, false),
            true,
            &connected,
            &AtomicBool::new(false),
        )
        .unwrap()
        .unwrap();
        assert_eq!(unshared.addresses.len(), 1);
    }

    #[test]
    fn a_taken_port_is_an_error_that_names_it() {
        let holder = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = holder.local_addr().unwrap().port();
        let error = listen_for(
            &proxy_settings(port, false),
            true,
            &[],
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::LocalProxyPortBusy);
        assert_eq!(error.local_proxy_port(), Some(port));
    }

    #[test]
    fn a_port_reserved_by_the_system_counts_as_busy() {
        let denied = io::Error::from(io::ErrorKind::PermissionDenied);
        assert_eq!(PortProblem::of(&denied), PortProblem::Busy);
        let in_use = io::Error::from(io::ErrorKind::AddrInUse);
        assert_eq!(PortProblem::of(&in_use), PortProblem::Busy);
        let no_family = io::Error::from_raw_os_error(if cfg!(windows) { 10047 } else { 97 });
        assert_eq!(PortProblem::of(&no_family), PortProblem::NoAddress);
    }
}
