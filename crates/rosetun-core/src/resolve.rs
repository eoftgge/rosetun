//! Name lookups for HTTP and pings. Under Lockdown without a tunnel the
//! system resolver cannot get out (see `rosetun-dns`), so the client asks the
//! network's DNS servers itself; otherwise it uses the system resolver.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rosetun_config::{ConnectionState, Status};
use ureq::config::Config;
use ureq::http::Uri;
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

static DIRECT: AtomicBool = AtomicBool::new(false);

/// `ResolvedSocketAddrs` holds no more; pushing beyond it panics.
const MAX_ADDRESSES: usize = 16;
/// For a request without a timeout of its own.
const DIRECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Lockdown is per machine and only the service knows it: the GUI and the
/// CLI pass every status they read, or `None` when the service is
/// unreachable, which leaves the system resolver.
pub fn follow_service_status(status: Option<&Status>) {
    DIRECT.store(direct_for(status), Ordering::Relaxed);
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

    use super::direct_for;

    #[test]
    fn direct_lookups_only_under_lockdown_without_a_tunnel() {
        let status = |lockdown, state| Status {
            lockdown,
            state,
            ..Status::default()
        };
        assert!(!direct_for(None));
        assert!(!direct_for(Some(&status(false, ConnectionState::Disconnected))));
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
