//! Listener addresses and port retries for the local proxy.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
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

/// `WSAEAFNOSUPPORT` on Windows, `EAFNOSUPPORT` on Linux (97) and macOS (47).
#[cfg(windows)]
const EAFNOSUPPORT: i32 = 10047;
#[cfg(target_os = "linux")]
const EAFNOSUPPORT: i32 = 97;
#[cfg(target_os = "macos")]
const EAFNOSUPPORT: i32 = 47;
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
const EAFNOSUPPORT: i32 = 97;

impl PortProblem {
    fn of(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied => Self::Busy,
            io::ErrorKind::AddrNotAvailable => Self::NoAddress,
            // EAFNOSUPPORT, which std has no kind for, and Windows' WSAEAFNOSUPPORT.
            _ if error.raw_os_error() == Some(EAFNOSUPPORT) => Self::NoAddress,
            _ => Self::Other,
        }
    }
}

fn try_bind(address: SocketAddr) -> Result<(), PortProblem> {
    TcpListener::bind(address)
        .map(drop)
        .map_err(|error| PortProblem::of(&error))
}

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

pub(super) fn application() -> Result<std::path::PathBuf, HelperError> {
    std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|_| {
            HelperError::new(
                ErrorCode::RoutingFailed,
                "cannot identify the proxy service",
            )
        })
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
    let dns = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    Ok(Some(LocalProxyListen { addresses, dns }))
}

pub(super) fn start(
    port: u16,
    cancelled: &AtomicBool,
    mut bind: impl FnMut() -> Result<rosetun_dataplane::Dataplane, rosetun_dataplane::DataplaneError>,
) -> Result<rosetun_dataplane::Dataplane, HelperError> {
    use rosetun_dataplane::{DataplaneError, proxy::ServerError};

    for attempt in 1.. {
        match bind() {
            Ok(dataplane) => return Ok(dataplane),
            Err(DataplaneError::Proxy(ServerError::Bind { source }))
                if PortProblem::of(&source) == PortProblem::Busy =>
            {
                if attempt == PORT_TRIES {
                    return Err(HelperError::local_proxy_port_busy(port));
                }
                sleep_cancellable(PORT_RETRY_DELAY, cancelled)?;
            }
            Err(error) => return Err(HelperError::new(ErrorCode::EngineFailed, error.to_string())),
        }
    }
    unreachable!("the last bind attempt returns its error")
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
    fn sharing_without_a_connected_address_keeps_only_loopback() {
        let port = free_port();
        let listen = listen_for(
            &proxy_settings(port, true),
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

    #[cfg(target_os = "linux")]
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
        let no_family = io::Error::from_raw_os_error(EAFNOSUPPORT);
        assert_eq!(PortProblem::of(&no_family), PortProblem::NoAddress);
    }
}
