//! Top-level facade tying the rule engine, sniffer, DNS service, connection
//! table and local mixed proxy into one lifecycle for `rosetun-helper-privileged`.
//!
//! All state stays in memory on blocking worker threads. `Debug` never prints
//! credentials, destinations or addresses.

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;

use rosetun_config::{DnsSettings, ExitId, ListRef, UploadedListFormat};
use rosetun_engine::{DelayInbound, LocalProxyListen, SocksProxy, TrafficProbe};
use rustls::pki_types::CertificateDer;

use crate::conntable::ConnectionTable;
use crate::dns::{DnsError, DnsOptions, DnsServer, DnsService};
use crate::net::{Credentials, Dialer, DirectDialer, Resolve, Socks5Dialer, SystemResolver};
use crate::proxy::{
    EntryAccount, EntryServer, NameLookup, Outbounds, Policy, ProxyServer, Query, Router,
    RouterConfig, ServerError, Sniffing, TcpSniff, Verdict,
};
use crate::rules::{Flow, ListContent, ListInput, Route, RuleEngine, RulePlan, RulesError};
use crate::sniff::{SniffLimits, sniff_quic_datagram, sniff_stream};

/// Upper bound on reading one staged list file from disk.
const MAX_LIST_FILE_BYTES: u64 = 128 * 1024 * 1024;

/// Authenticated loopback SOCKS5 upstream (an Xray or sing-box outbound worker).
#[derive(Clone, PartialEq, Eq)]
pub struct UpstreamProxy {
    pub address: SocketAddr,
    pub username: String,
    pub password: String,
}

impl fmt::Debug for UpstreamProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamProxy")
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl From<SocksProxy<'_>> for UpstreamProxy {
    fn from(proxy: SocksProxy<'_>) -> Self {
        Self {
            address: proxy.address,
            username: proxy.username.to_owned(),
            password: proxy.password.to_owned(),
        }
    }
}

impl UpstreamProxy {
    fn to_dialer(&self) -> Arc<dyn Dialer> {
        let credentials =
            (!self.username.is_empty() || !self.password.is_empty()).then(|| Credentials {
                username: self.username.clone(),
                password: self.password.clone(),
            });
        Arc::new(Socks5Dialer::new(self.address, credentials))
    }
}

/// One extra exit's outbound tag and upstream SOCKS5 worker.
#[derive(Clone, PartialEq, Eq)]
pub struct ExitUpstream {
    pub exit: ExitId,
    pub tag: String,
    pub upstream: UpstreamProxy,
}

impl fmt::Debug for ExitUpstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExitUpstream")
            .field("exit", &self.exit)
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

/// Outbound SOCKS5 endpoints the data plane routes to (beside `direct` and `block`).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct OutboundEndpoints {
    /// Main proxy worker; `None` makes `Proxy` decisions fail closed.
    pub proxy: Option<UpstreamProxy>,
    /// Extra exit workers keyed by [`ExitId`].
    pub exits: Vec<ExitUpstream>,
}

impl fmt::Debug for OutboundEndpoints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundEndpoints")
            .field("proxy", &self.proxy.is_some())
            .field("exits", &self.exits.len())
            .finish()
    }
}

/// Complete configuration to start one [`Dataplane`] session.
pub struct DataplaneConfig {
    pub listen: LocalProxyListen,
    pub dns: DnsSettings,
    pub dns_options: DnsOptions,
    pub rules: RulePlan,
    pub outbounds: OutboundEndpoints,
    pub delay: Option<DelayInbound>,
    pub router: RouterConfig,
    pub sniff: SniffLimits,
    /// Optional resolver for `direct` flows; defaults to the built-in [`DnsService`].
    pub direct_resolver: Option<Arc<dyn Resolve>>,
}

impl fmt::Debug for DataplaneConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataplaneConfig")
            .field("listeners", &self.listen.addresses.len())
            .field("has_delay_entry", &self.delay.is_some())
            .field("outbounds", &self.outbounds)
            .finish_non_exhaustive()
    }
}

/// Why starting or updating a [`Dataplane`] failed.
#[derive(Debug, thiserror::Error)]
pub enum DataplaneError {
    #[error("rule compilation failed: {0}")]
    Rules(#[from] RulesError),
    #[error("DNS service initialization failed: {0}")]
    Dns(#[from] DnsError),
    #[error("local proxy server failed: {0}")]
    Proxy(#[from] ServerError),
    #[error("DNS listener failed: {0}")]
    DnsListener(#[source] io::Error),
    #[error("internal entry listener failed: {0}")]
    EntryListener(#[source] io::Error),
    #[error("list file could not be read: {0}")]
    ListIo(#[source] io::Error),
    #[error("list file exceeds size limit")]
    ListTooLarge,
}

/// Loads staged `.srs` / `.json` list files (as stored by the helper's list
/// store) into [`ListInput`]s ready for [`RulePlan::lists`].
pub fn load_list_files(entries: &[(ListRef, &Path)]) -> Result<Vec<ListInput>, DataplaneError> {
    let mut loaded = Vec::with_capacity(entries.len());
    for (reference, path) in entries {
        let bytes = read_bounded_file(path, MAX_LIST_FILE_BYTES)?;
        let content = match reference.format {
            UploadedListFormat::Binary => ListContent::Srs(bytes),
            UploadedListFormat::Source => ListContent::Source(bytes),
        };
        loaded.push(ListInput {
            tag: reference.tag.clone(),
            content,
        });
    }
    Ok(loaded)
}

fn read_bounded_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, DataplaneError> {
    let file = File::open(path).map_err(DataplaneError::ListIo)?;
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(DataplaneError::ListIo)?;
    if bytes.len() as u64 > max_bytes {
        return Err(DataplaneError::ListTooLarge);
    }
    Ok(bytes)
}

struct RulePolicy {
    engine: RuleEngine,
    resolver: Arc<dyn Resolve>,
}

impl Policy for RulePolicy {
    fn decide(&self, query: &Query<'_>) -> Verdict {
        let flow = Flow {
            domain: query.domain,
            ip: query.ip,
            process: None,
        };
        match self.engine.decide(&flow, self.resolver.as_ref()).route {
            Route::Direct => Verdict::Direct,
            Route::Block => Verdict::Block,
            Route::Proxy => Verdict::Proxy,
            Route::Exit(exit) => Verdict::Exit(exit),
        }
    }
}

struct DnsNameLookup(Arc<DnsService>);

impl NameLookup for DnsNameLookup {
    fn domain_for(&self, ip: IpAddr) -> Option<String> {
        self.0.domain_for(ip)
    }
}

struct DefaultSniffer {
    limits: SniffLimits,
}

impl Sniffing for DefaultSniffer {
    fn sniff_tcp(&self, stream: &mut TcpStream) -> io::Result<TcpSniff> {
        let result = sniff_stream(stream, &self.limits)?;
        Ok(TcpSniff {
            domain: result.sniffed.and_then(|sniffed| sniffed.domain),
            buffered: result.buffered,
        })
    }

    fn sniff_udp(&self, datagram: &[u8]) -> Option<String> {
        sniff_quic_datagram(datagram).and_then(|sniffed| sniffed.domain)
    }
}

/// Running local-proxy data plane (Stage 1: mixed HTTP/SOCKS5 proxy, built-in
/// DoH DNS server, rule engine, sniffer, connection table, and optional
/// authenticated delay/subscription entry).
pub struct Dataplane {
    router: Arc<Router>,
    dns: Arc<DnsService>,
    direct_resolver: Arc<dyn Resolve>,
    dns_server: DnsServer,
    proxy_server: ProxyServer,
    entry_server: Option<EntryServer>,
    dns_addr: SocketAddr,
}

impl fmt::Debug for Dataplane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dataplane")
            .field("proxy_listeners", &self.proxy_server.local_addrs().len())
            .field("has_delay_entry", &self.entry_server.is_some())
            .field("active_connections", &self.router.table().active_count())
            .finish_non_exhaustive()
    }
}

impl Dataplane {
    /// Starts the data plane using `webpki-roots` for DoH TLS verification.
    pub fn start(config: DataplaneConfig) -> Result<Self, DataplaneError> {
        Self::start_inner(config, None)
    }

    /// Starts the data plane using custom root certificates for DoH TLS
    /// verification (primarily for loopback end-to-end tests).
    pub fn start_with_roots(
        config: DataplaneConfig,
        roots: Vec<CertificateDer<'static>>,
    ) -> Result<Self, DataplaneError> {
        Self::start_inner(config, Some(roots))
    }

    fn start_inner(
        config: DataplaneConfig,
        roots: Option<Vec<CertificateDer<'static>>>,
    ) -> Result<Self, DataplaneError> {
        let engine = RuleEngine::compile(&config.rules)?;

        // Route DoH through the main proxy when available; otherwise direct via
        // literal IP (the system resolver is never invoked for literal IPs).
        let doh_dialer: Arc<dyn Dialer> = config.outbounds.proxy.as_ref().map_or_else(
            || Arc::new(DirectDialer::new(Arc::new(SystemResolver))) as Arc<dyn Dialer>,
            UpstreamProxy::to_dialer,
        );

        let dns = Arc::new(match roots {
            Some(roots) => {
                DnsService::with_roots(&config.dns, doh_dialer, config.dns_options, roots)?
            }
            None => DnsService::new(&config.dns, doh_dialer, config.dns_options)?,
        });

        let direct_resolver: Arc<dyn Resolve> = config
            .direct_resolver
            .unwrap_or_else(|| Arc::clone(&dns) as Arc<dyn Resolve>);

        let outbounds = Arc::new(build_outbounds(
            &config.outbounds,
            Arc::clone(&direct_resolver),
        ));
        let exit_tags: Vec<(String, ExitId)> = config
            .outbounds
            .exits
            .iter()
            .map(|exit| (exit.tag.clone(), exit.exit.clone()))
            .collect();

        let policy: Arc<dyn Policy> = Arc::new(RulePolicy {
            engine,
            resolver: Arc::clone(&dns) as Arc<dyn Resolve>,
        });

        let table = ConnectionTable::new();
        let router = Arc::new(
            Router::new(policy, outbounds, table, config.router)
                .with_names(Arc::new(DnsNameLookup(Arc::clone(&dns))))
                .with_sniffing(Arc::new(DefaultSniffer {
                    limits: config.sniff,
                })),
        );

        let dns_server = DnsServer::bind(Arc::clone(&dns), &[config.listen.dns])
            .map_err(DataplaneError::DnsListener)?;
        let dns_addr = dns_server
            .local_addrs()
            .into_iter()
            .next()
            .unwrap_or(config.listen.dns);

        let proxy_server = ProxyServer::bind(Arc::clone(&router), &config.listen.addresses)?;

        let entry_server = match config.delay {
            Some(delay) => {
                let accounts = EntryAccount::from_delay_inbound(&delay, &exit_tags);
                Some(
                    EntryServer::bind(Arc::clone(&router), delay.address, accounts)
                        .map_err(DataplaneError::EntryListener)?,
                )
            }
            None => None,
        };

        Ok(Self {
            router,
            dns,
            direct_resolver,
            dns_server,
            proxy_server,
            entry_server,
            dns_addr,
        })
    }

    /// Actual bound addresses of the local mixed proxy.
    pub fn proxy_addrs(&self) -> &[SocketAddr] {
        self.proxy_server.local_addrs()
    }

    /// Actual bound loopback address of the built-in UDP/TCP DNS listener.
    pub fn dns_addr(&self) -> SocketAddr {
        self.dns_addr
    }

    /// Actual bound address of the authenticated delay/subscription SOCKS5 entry.
    pub fn delay_addr(&self) -> Option<SocketAddr> {
        self.entry_server.as_ref().map(EntryServer::local_addr)
    }

    pub fn connections(&self) -> &ConnectionTable {
        self.router.table()
    }

    /// Returns a [`TrafficProbe`] compatible with the helper's traffic monitor.
    pub fn traffic_probe(&self) -> Box<dyn TrafficProbe> {
        Box::new(self.router.table().probe())
    }

    /// Actively shuts down an active connection by id.
    pub fn close_connection(&self, id: &str) -> bool {
        self.router.table().close_connection(id)
    }

    pub fn dns(&self) -> &Arc<DnsService> {
        &self.dns
    }

    /// Compiles and swaps the rule engine in place without restarting listeners.
    pub fn update_rules(&self, plan: &RulePlan) -> Result<(), DataplaneError> {
        let engine = RuleEngine::compile(plan)?;
        self.router.set_policy(Arc::new(RulePolicy {
            engine,
            resolver: Arc::clone(&self.dns) as Arc<dyn Resolve>,
        }));
        Ok(())
    }

    /// Swaps the outbound SOCKS5 workers and DoH upstream dialer in place.
    pub fn update_outbounds(&self, endpoints: OutboundEndpoints) {
        let doh_dialer: Arc<dyn Dialer> = endpoints.proxy.as_ref().map_or_else(
            || Arc::new(DirectDialer::new(Arc::new(SystemResolver))) as Arc<dyn Dialer>,
            UpstreamProxy::to_dialer,
        );
        self.dns.set_dialer(doh_dialer);
        let outbounds = Arc::new(build_outbounds(
            &endpoints,
            Arc::clone(&self.direct_resolver),
        ));
        self.router.set_outbounds(outbounds);
    }

    /// Stops all listeners and closes active connections. Idempotent.
    pub fn shutdown(&mut self) {
        if let Some(entry) = &mut self.entry_server {
            entry.shutdown();
        }
        self.proxy_server.shutdown();
        self.dns_server.shutdown();
    }
}

impl Drop for Dataplane {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn build_outbounds(endpoints: &OutboundEndpoints, direct_resolver: Arc<dyn Resolve>) -> Outbounds {
    let mut exits = HashMap::with_capacity(endpoints.exits.len());
    for exit in &endpoints.exits {
        exits.insert(
            exit.exit.clone(),
            (exit.tag.clone(), exit.upstream.to_dialer()),
        );
    }
    Outbounds {
        direct: Arc::new(DirectDialer::new(direct_resolver)),
        proxy: endpoints.proxy.as_ref().map(UpstreamProxy::to_dialer),
        exits,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn read_bounded_file_reads_within_limit_and_rejects_oversized_files() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rosetun-dataplane-bound-{unique}.bin"));
        {
            let mut file = File::create(&path).unwrap();
            file.write_all(b"0123456789").unwrap();
        }
        assert_eq!(read_bounded_file(&path, 10).unwrap(), b"0123456789");
        assert!(matches!(
            read_bounded_file(&path, 9),
            Err(DataplaneError::ListTooLarge)
        ));
        let _ = std::fs::remove_file(&path);
    }
}
