//! Deciding, dialing and relaying one TCP flow.

use std::fmt;
use std::io::{self, Write};
use std::net::TcpStream;
use std::sync::{Arc, PoisonError, RwLock};

use rosetun_config::ConnectionNetwork;

use super::relay::relay;
use super::{NameLookup, Outbounds, Policy, Query, RouterConfig, Sniffing, Verdict};
use crate::conntable::{ConnectionMeta, ConnectionTable};
use crate::net::{Host, Target};

/// Why a flow did not connect; the protocol handler turns it into its own
/// status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectError {
    /// The rules, or a missing outbound, refused the flow.
    Blocked,
    /// The outbound could not reach the destination.
    Unreachable(io::ErrorKind),
    /// The connection table is full.
    Busy,
}

/// How a protocol handler reports a flow's outcome to its client.
pub(crate) type Reply<'a> =
    dyn FnMut(&mut TcpStream, Result<(), ConnectError>) -> io::Result<()> + 'a;

/// Routes flows. Policy and outbounds can be replaced while it runs; a flow
/// in progress keeps the ones it started with.
pub struct Router {
    policy: RwLock<Arc<dyn Policy>>,
    outbounds: RwLock<Arc<Outbounds>>,
    names: Option<Arc<dyn NameLookup>>,
    sniffing: Option<Arc<dyn Sniffing>>,
    table: ConnectionTable,
    config: RouterConfig,
}

impl fmt::Debug for Router {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Router")
            .field("table", &self.table)
            .finish_non_exhaustive()
    }
}

impl Router {
    pub fn new(
        policy: Arc<dyn Policy>,
        outbounds: Arc<Outbounds>,
        table: ConnectionTable,
        config: RouterConfig,
    ) -> Self {
        Self {
            policy: RwLock::new(policy),
            outbounds: RwLock::new(outbounds),
            names: None,
            sniffing: None,
            table,
            config,
        }
    }

    #[must_use]
    pub fn with_names(mut self, names: Arc<dyn NameLookup>) -> Self {
        self.names = Some(names);
        self
    }

    #[must_use]
    pub fn with_sniffing(mut self, sniffing: Arc<dyn Sniffing>) -> Self {
        self.sniffing = Some(sniffing);
        self
    }

    pub fn set_policy(&self, policy: Arc<dyn Policy>) {
        *self.policy.write().unwrap_or_else(PoisonError::into_inner) = policy;
    }

    pub fn set_outbounds(&self, outbounds: Arc<Outbounds>) {
        *self
            .outbounds
            .write()
            .unwrap_or_else(PoisonError::into_inner) = outbounds;
    }

    pub fn table(&self) -> &ConnectionTable {
        &self.table
    }

    pub fn config(&self) -> &RouterConfig {
        &self.config
    }

    pub(crate) fn sniffing(&self) -> Option<&Arc<dyn Sniffing>> {
        self.sniffing.as_ref()
    }

    pub(crate) fn outbounds(&self) -> Arc<Outbounds> {
        Arc::clone(
            &self
                .outbounds
                .read()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    /// The verdict for a flow to `target`, with the domain the rules saw.
    pub(crate) fn decide(
        &self,
        target: &Target,
        sniffed: Option<&str>,
        network: ConnectionNetwork,
    ) -> (Verdict, Option<String>) {
        let (domain, ip) = match &target.host {
            Host::Domain(name) => (sniffed.map_or_else(|| name.clone(), str::to_owned), None),
            Host::Ip(ip) => (
                sniffed
                    .map(str::to_owned)
                    .or_else(|| self.names.as_ref().and_then(|names| names.domain_for(*ip)))
                    .unwrap_or_default(),
                Some(*ip),
            ),
        };
        let domain = (!domain.is_empty()).then_some(domain);
        let policy = Arc::clone(&self.policy.read().unwrap_or_else(PoisonError::into_inner));
        let verdict = policy.decide(&Query {
            domain: domain.as_deref(),
            ip,
            network,
        });
        (verdict, domain)
    }

    pub(crate) fn meta(
        target: &Target,
        domain: Option<&str>,
        route: rosetun_engine::EngineRoute,
        network: ConnectionNetwork,
    ) -> ConnectionMeta {
        let (host, ip) = match (&target.host, domain) {
            (Host::Domain(name), sniffed) => (sniffed.unwrap_or(name).to_owned(), None),
            (Host::Ip(ip), Some(domain)) => (domain.to_owned(), Some(*ip)),
            (Host::Ip(ip), None) => (ip.to_string(), None),
        };
        ConnectionMeta {
            process: None,
            host,
            ip,
            port: target.port,
            network,
            route,
        }
    }

    /// Runs one TCP flow of `client` to `target` to its end.
    ///
    /// `forced` skips sniffing and the policy (an internal entry). `preface`
    /// are bytes of the client's stream the handler already consumed.
    /// `reply` tells the client the outcome: before dialing's end for a
    /// named target, so errors carry a status, but before sniffing for an
    /// address, which needs the client to speak first. A refusal after that
    /// point can only close the connection.
    pub(crate) fn tcp_flow(
        &self,
        client: TcpStream,
        target: &Target,
        forced: Option<&Verdict>,
        hint_domain: Option<&str>,
        preface: &[u8],
        reply: &mut Reply<'_>,
    ) -> io::Result<()> {
        self.tcp_flow_in(
            &self.table,
            client,
            target,
            forced,
            hint_domain,
            preface,
            reply,
        )
    }

    /// Like [`Self::tcp_flow`], registering the connection in `table` instead
    /// of the router's own table. Internal entries use a private table so
    /// probe and subscription connections never show in the user's list while
    /// still shutting down cleanly on stop.
    #[expect(
        clippy::too_many_arguments,
        reason = "flow setup passes protocol callbacks and optional domain hint without allocating"
    )]
    pub(crate) fn tcp_flow_in(
        &self,
        table: &ConnectionTable,
        mut client: TcpStream,
        target: &Target,
        forced: Option<&Verdict>,
        hint_domain: Option<&str>,
        preface: &[u8],
        reply: &mut Reply<'_>,
    ) -> io::Result<()> {
        let early = forced.is_none()
            && preface.is_empty()
            && hint_domain.is_none()
            && matches!(target.host, Host::Ip(_))
            && self.sniffing.is_some();
        let mut buffered = Vec::new();
        let mut sniffed = None;
        if early && let Some(sniffing) = &self.sniffing {
            reply(&mut client, Ok(()))?;
            let result = sniffing.sniff_tcp(&mut client)?;
            sniffed = result.domain;
            buffered = result.buffered;
        }
        let (verdict, domain) = match forced {
            Some(verdict) => (verdict.clone(), None),
            None => self.decide(
                target,
                sniffed.as_deref().or(hint_domain),
                ConnectionNetwork::Tcp,
            ),
        };
        let Some((dialer, route)) = self.outbounds().select(&verdict) else {
            if !early {
                reply(&mut client, Err(ConnectError::Blocked))?;
            }
            return Ok(());
        };
        let upstream = match dialer.connect(target, self.config.connect_timeout) {
            Ok(stream) => stream,
            Err(error) => {
                if !early {
                    reply(&mut client, Err(ConnectError::Unreachable(error.kind())))?;
                }
                return Ok(());
            }
        };
        let Ok(registration) = table.register(Self::meta(
            target,
            domain.as_deref(),
            route,
            ConnectionNetwork::Tcp,
        )) else {
            if !early {
                reply(&mut client, Err(ConnectError::Busy))?;
            }
            return Ok(());
        };
        if !early {
            reply(&mut client, Ok(()))?;
        }
        let mut head = Vec::with_capacity(preface.len() + buffered.len());
        head.extend_from_slice(preface);
        head.extend_from_slice(&buffered);
        relay(&client, &upstream, &registration, &head);
        Ok(())
    }

    /// Writes `bytes` to the client; used by handlers for their replies.
    pub(crate) fn write_all(client: &mut TcpStream, bytes: &[u8]) -> io::Result<()> {
        client.write_all(bytes)?;
        client.flush()
    }
}
