//! The local mixed proxy: one listener that speaks HTTP (CONNECT and plain
//! requests) and SOCKS5 (CONNECT and UDP ASSOCIATE), and routes every flow
//! to `direct`, `block`, the main engine or an exit's engine.
//!
//! Policy, name lookup and sniffing are traits so the router knows nothing
//! about the rule engine or the DNS service; `crate::Dataplane` wires them.
//! Authenticated internal entries (delay probes, subscription requests)
//! share the SOCKS5 server but pick the outbound by account and never reach
//! the rules.
//!
//! No type here shows a destination, address or credential in `Debug`.

mod entry;
mod http;
mod relay;
mod router;
mod server;
mod socks;
mod udp;

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rosetun_config::ConnectionNetwork;
use rosetun_config::ExitId;
use rosetun_engine::EngineRoute;

use crate::net::Dialer;

pub use entry::{EntryAccount, EntryServer, EntryTarget};
pub use router::{ConnectError, Router};
pub use server::{ProxyServer, ServerError};

/// Where a flow is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Direct,
    Block,
    /// The main engine's outbound.
    Proxy,
    /// The outbound of the exit.
    Exit(ExitId),
}

/// What the policy is asked about one flow.
#[derive(Clone, Copy)]
pub struct Query<'a> {
    /// The sniffed or requested domain, or the one the DNS service handed out
    /// for the destination address.
    pub domain: Option<&'a str>,
    pub ip: Option<IpAddr>,
    pub network: ConnectionNetwork,
}

impl fmt::Debug for Query<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Query")
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

/// Decides where a flow goes.
pub trait Policy: Send + Sync {
    fn decide(&self, query: &Query<'_>) -> Verdict;
}

impl<F> Policy for F
where
    F: Fn(&Query<'_>) -> Verdict + Send + Sync,
{
    fn decide(&self, query: &Query<'_>) -> Verdict {
        self(query)
    }
}

/// The name a destination address was last resolved from.
pub trait NameLookup: Send + Sync {
    fn domain_for(&self, ip: IpAddr) -> Option<String>;
}

/// What sniffing a client's first bytes found.
pub struct TcpSniff {
    pub domain: Option<String>,
    /// Every byte read; replayed to the outbound first.
    pub buffered: Vec<u8>,
}

impl fmt::Debug for TcpSniff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpSniff")
            .field("buffered", &self.buffered.len())
            .finish_non_exhaustive()
    }
}

/// Finds the site name in a flow's first bytes.
pub trait Sniffing: Send + Sync {
    /// Reads at most a bounded prefix of `stream` within a deadline.
    fn sniff_tcp(&self, stream: &mut TcpStream) -> io::Result<TcpSniff>;
    /// The site name in the first datagram of a UDP flow.
    fn sniff_udp(&self, datagram: &[u8]) -> Option<String>;
}

/// The outbounds a verdict can pick.
#[derive(Clone)]
pub struct Outbounds {
    pub direct: Arc<dyn Dialer>,
    /// The main engine; `None` makes a `Proxy` verdict a refusal.
    pub proxy: Option<Arc<dyn Dialer>>,
    /// Each exit with the outbound tag the connection list shows. An exit
    /// without an entry is refused.
    pub exits: HashMap<ExitId, (String, Arc<dyn Dialer>)>,
}

impl fmt::Debug for Outbounds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Outbounds")
            .field("proxy", &self.proxy.is_some())
            .field("exits", &self.exits.len())
            .finish_non_exhaustive()
    }
}

impl Outbounds {
    /// The dialer and the route a verdict names; `None` is a refusal.
    pub(crate) fn select(&self, verdict: &Verdict) -> Option<(Arc<dyn Dialer>, EngineRoute)> {
        match verdict {
            Verdict::Direct => Some((Arc::clone(&self.direct), EngineRoute::Direct)),
            Verdict::Block => None,
            Verdict::Proxy => self
                .proxy
                .as_ref()
                .map(|dialer| (Arc::clone(dialer), EngineRoute::Proxy)),
            Verdict::Exit(exit) => self
                .exits
                .get(exit)
                .map(|(tag, dialer)| (Arc::clone(dialer), EngineRoute::Exit(tag.clone()))),
        }
    }
}

/// Timeouts and limits of the router.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterConfig {
    /// Dialing an outbound.
    pub connect_timeout: Duration,
    /// A client's protocol handshake, from accept to the request.
    pub handshake_timeout: Duration,
    /// Handler threads running at once; further clients are closed.
    pub max_connections: usize,
    /// A UDP flow without a datagram this long ends.
    pub udp_idle: Duration,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            max_connections: 2048,
            udp_idle: Duration::from_secs(60),
        }
    }
}

#[cfg(test)]
mod tests;
