//! Name lookups for HTTP and pings. Under Lockdown without a tunnel the
//! system resolver cannot get out (see `rosetun-dns`), so the client asks the
//! network's DNS servers itself; otherwise it uses the system resolver.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::time::Duration;

use rosetun_config::{ConnectionState, Status};
use ureq::Proxy;
use ureq::config::Config;
use ureq::http::Uri;
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

static DIRECT: AtomicBool = AtomicBool::new(false);
/// The port of the session's local proxy, 0 without one.
static LOCAL_PROXY: AtomicU16 = AtomicU16::new(0);

/// `ResolvedSocketAddrs` holds no more; pushing beyond it panics.
const MAX_ADDRESSES: usize = 16;
/// For a request without a timeout of its own.
const DIRECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Lockdown is per machine and only the service knows it: the GUI and the
/// CLI pass every status they read, or `None` when the service is
/// unreachable, which leaves the system resolver.
pub fn follow_service_status(status: Option<&Status>) {
    DIRECT.store(direct_for(status), Ordering::Relaxed);
    let port = status.and_then(Status::running_local_proxy).unwrap_or(0);
    LOCAL_PROXY.store(port, Ordering::Relaxed);
}

/// The proxy for an agent's requests: the session's local proxy if it has one,
/// otherwise what the environment says, as an agent does by default. There is
/// no adapter in the proxy mode to carry Rosetun's own requests, and with its
/// kill switch they could not go out by themselves.
pub(crate) fn agent_proxy() -> Option<Proxy> {
    local_proxy_url(LOCAL_PROXY.load(Ordering::Relaxed))
        .and_then(|url| Proxy::new(&url).ok())
        .or_else(Proxy::try_from_env)
}

fn local_proxy_url(port: u16) -> Option<String> {
    (port != 0).then(|| format!("http://127.0.0.1:{port}"))
}

fn direct_for(status: Option<&Status>) -> bool {
    status.is_some_and(|status| status.lockdown && status.state != ConnectionState::Connected)
}

fn direct() -> bool {
    DIRECT.load(Ordering::Relaxed)
}

/// An agent whose lookups follow `follow_service_status`, decided per request.
pub(crate) fn agent(config: Config) -> ureq::Agent {
    ureq::Agent::with_parts(config, DefaultConnector::default(), Lookup)
}

/// This computer's address on the network it reaches the outside through, for
/// other devices to find its proxy. A datagram socket picks it from the routes;
/// connecting one sends nothing.
pub fn lan_address() -> Option<IpAddr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    usable_lan_address(socket.local_addr().ok()?.ip())
}

fn usable_lan_address(address: IpAddr) -> Option<IpAddr> {
    // Linux listens only on private addresses, and a public one would not answer.
    let reachable = cfg!(windows) || rosetun_config::is_private_address(address);
    (reachable && !address.is_unspecified() && !address.is_loopback()).then_some(address)
}

/// The addresses of `host:port` for a TCP connection.
pub(crate) fn socket_addresses(host: &str, port: u16) -> Vec<SocketAddr> {
    if direct() {
        rosetun_dns::resolve(host, DIRECT_TIMEOUT)
            .map(|addresses| {
                addresses
                    .into_iter()
                    .map(|address| SocketAddr::new(address, port))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        (host, port)
            .to_socket_addrs()
            .map(Iterator::collect)
            .unwrap_or_default()
    }
}

#[derive(Debug)]
struct Lookup;

impl Resolver for Lookup {
    fn resolve(
        &self,
        uri: &Uri,
        config: &Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        if !direct() {
            return DefaultResolver::default().resolve(uri, config, timeout);
        }
        let host = uri.host().ok_or(ureq::Error::HostNotFound)?;
        let port = uri
            .port_u16()
            .or_else(|| match uri.scheme_str() {
                Some("https") => Some(443),
                Some("http") => Some(80),
                _ => None,
            })
            .ok_or(ureq::Error::HostNotFound)?;
        let wait = timeout.not_zero().map_or(DIRECT_TIMEOUT, |wait| *wait);
        let addresses = rosetun_dns::resolve(host, wait).map_err(|error| {
            tracing::debug!(%error, "direct name lookup failed");
            ureq::Error::HostNotFound
        })?;

        let mut resolved = self.empty();
        let family = config.ip_family();
        let wanted = family.keep_wanted(
            addresses
                .into_iter()
                .map(|address| SocketAddr::new(address, port)),
        );
        for address in wanted.take(MAX_ADDRESSES) {
            resolved.push(address);
        }
        if resolved.is_empty() {
            return Err(ureq::Error::HostNotFound);
        }
        Ok(resolved)
    }
}

#[cfg(test)]
mod tests {
    use rosetun_config::{ConnectionState, Status};

    use super::{direct_for, local_proxy_url, usable_lan_address};

    #[test]
    fn neither_loopback_nor_no_address_is_shown_to_other_devices() {
        let usable = |text: &str| usable_lan_address(text.parse().unwrap());
        assert_eq!(usable("0.0.0.0"), None);
        assert_eq!(usable("127.0.0.1"), None);
        assert_eq!(usable("192.168.1.5"), Some("192.168.1.5".parse().unwrap()));
    }

    #[test]
    fn requests_use_the_local_proxy_only_while_its_session_is_up() {
        let status = |state, port| Status {
            state,
            local_proxy_port: port,
            ..Status::default()
        };
        assert_eq!(
            status(ConnectionState::Connected, Some(10808)).running_local_proxy(),
            Some(10808)
        );
        assert_eq!(
            status(ConnectionState::Reconnecting, Some(10808)).running_local_proxy(),
            None
        );
        assert_eq!(
            status(ConnectionState::Disconnected, Some(10808)).running_local_proxy(),
            None
        );
        assert_eq!(
            status(ConnectionState::Connected, None).running_local_proxy(),
            None
        );
        assert_eq!(local_proxy_url(0), None);
        assert_eq!(
            local_proxy_url(10808).as_deref(),
            Some("http://127.0.0.1:10808")
        );
    }

    #[test]
    fn direct_lookups_only_under_lockdown_without_a_tunnel() {
        let status = |lockdown, state| Status {
            lockdown,
            state,
            ..Status::default()
        };
        assert!(!direct_for(None));
        assert!(!direct_for(Some(&status(
            false,
            ConnectionState::Disconnected
        ))));
        assert!(!direct_for(Some(&status(true, ConnectionState::Connected))));
        for state in [
            ConnectionState::Disconnected,
            ConnectionState::Connecting,
            ConnectionState::Reconnecting,
            ConnectionState::Failed {
                reason: String::new(),
                failure_kind: None,
            },
            ConnectionState::FailedProtected {
                reason: String::new(),
                failure_kind: None,
            },
        ] {
            assert!(direct_for(Some(&status(true, state))));
        }
    }
}
