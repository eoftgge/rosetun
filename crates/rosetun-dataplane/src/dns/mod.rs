//! Built-in DNS server, DNS-over-HTTPS client, forward/reverse caches, and
//! loop protection.
//!
//! ## Loop protection
//!
//! Routing DNS through the same data plane that consults DNS for domain rules
//! can cycle if the upstream resolver itself triggers a lookup. Four layers
//! prevent that:
//!
//! 1. **Literal-IP upstream dial:** [`DohClient`] always connects to the
//!    literal `DnsSettings::server` IP address and passes
//!    `DnsSettings::server_name` only as TLS SNI/verification identity.
//! 2. **Thread-local re-entrancy guard:** while a thread is inside an upstream
//!    DoH exchange, any re-entrant call to [`DnsService::exchange`] or
//!    [`DnsService::lookup`] on that thread fails immediately with
//!    [`DnsError::Loop`].
//! 3. **Local anchor for `server_name`:** queries for `DnsSettings::server_name`
//!    are answered locally with `DnsSettings::server` for `A`/`AAAA` (and
//!    empty `NOERROR` for other types) and are never forwarded upstream.
//! 4. **Bounded recursion and concurrency:** response parsing caps CNAME chain
//!    following, pointer jumps are bounded and strictly backward, and
//!    [`DnsOptions::max_in_flight`] bounds concurrent upstream exchanges
//!    (excess queries receive `SERVFAIL` immediately).

mod cache;
mod doh;
mod server;
#[cfg(test)]
mod testcerts;
mod wire;

use std::cell::Cell;
use std::fmt;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rosetun_config::DnsSettings;
use rustls::pki_types::CertificateDer;
use thiserror::Error;
use tracing::debug;

use self::cache::{Clock, TtlCache, system_clock};
use crate::net::{Dialer, Resolve};

pub use self::doh::DohClient;
pub use self::server::DnsServer;

thread_local! {
    static IN_DOH_EXCHANGE: Cell<bool> = const { Cell::new(false) };
}

/// Errors returned by [`DnsService`] and [`DohClient`].
///
/// Messages are lowercase and never contain domain names or IP addresses.
#[derive(Debug, Error)]
pub enum DnsError {
    #[error("invalid resolver server name")]
    InvalidServerName,
    #[error("invalid resolver path")]
    InvalidPath,
    #[error("invalid root certificate")]
    InvalidRootCertificate,
    #[error("could not build tls configuration")]
    TlsConfig,
    #[error("dns resolution loop detected")]
    Loop,
    #[error("could not connect to upstream resolver")]
    Dial(#[source] io::Error),
    #[error("upstream exchange failed")]
    Io(#[source] io::Error),
    #[error("upstream resolver returned http status {0}")]
    HttpStatus(u16),
    #[error("invalid http response from upstream resolver")]
    BadHttpResponse,
    #[error("upstream dns response exceeded size limit")]
    ResponseTooLarge,
    #[error("invalid dns response from upstream resolver")]
    BadResponse,
    #[error("invalid dns query")]
    InvalidQuery,
}

/// Tuning knobs for [`DnsService`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsOptions {
    pub cache_entries: usize,
    pub reverse_entries: usize,
    pub min_ttl: Duration,
    pub max_ttl: Duration,
    pub negative_ttl: Duration,
    pub timeout: Duration,
    pub max_in_flight: usize,
}

impl Default for DnsOptions {
    fn default() -> Self {
        Self {
            cache_entries: 4096,
            reverse_entries: 8192,
            min_ttl: Duration::from_secs(30),
            max_ttl: Duration::from_secs(3600),
            negative_ttl: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            max_in_flight: 64,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    name: String,
    qtype: u16,
    qclass: u16,
}

struct CachedResponse {
    wire: Vec<u8>,
    stored_at: Instant,
}

struct ExchangeGuard;

impl ExchangeGuard {
    fn enter() -> Result<Self, DnsError> {
        IN_DOH_EXCHANGE.with(|flag| {
            if flag.get() {
                Err(DnsError::Loop)
            } else {
                flag.set(true);
                Ok(Self)
            }
        })
    }
}

impl Drop for ExchangeGuard {
    fn drop(&mut self) {
        IN_DOH_EXCHANGE.with(|flag| flag.set(false));
    }
}

struct InFlightGuard<'a> {
    counter: &'a AtomicUsize,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Thread-safe DNS resolver backed by DoH with forward and reverse TTL caches.
pub struct DnsService {
    server_ip: IpAddr,
    server_name_lower: String,
    options: DnsOptions,
    doh: DohClient,
    cache: Mutex<TtlCache<CacheKey, CachedResponse>>,
    reverse: Mutex<TtlCache<IpAddr, String>>,
    in_flight: AtomicUsize,
    clock: Clock,
}

impl fmt::Debug for DnsService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsService")
            .field("cache_entries", &self.cache_len())
            .field("in_flight", &self.in_flight.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl DnsService {
    /// Creates a DNS service that verifies the upstream against the bundled
    /// Mozilla root certificates (`webpki-roots`).
    pub fn new(
        settings: &DnsSettings,
        dialer: Arc<dyn Dialer>,
        options: DnsOptions,
    ) -> Result<Self, DnsError> {
        let doh = DohClient::new(settings, dialer, options.timeout)?;
        Ok(Self::from_client(settings, doh, options, system_clock()))
    }

    /// Creates a DNS service trusting only `roots`, intended for tests or a
    /// private CA.
    pub fn with_roots(
        settings: &DnsSettings,
        dialer: Arc<dyn Dialer>,
        options: DnsOptions,
        roots: Vec<CertificateDer<'static>>,
    ) -> Result<Self, DnsError> {
        let doh = DohClient::with_roots(settings, dialer, options.timeout, roots)?;
        Ok(Self::from_client(settings, doh, options, system_clock()))
    }

    #[cfg(test)]
    pub(crate) fn with_roots_and_clock(
        settings: &DnsSettings,
        dialer: Arc<dyn Dialer>,
        options: DnsOptions,
        roots: Vec<CertificateDer<'static>>,
        clock: Clock,
    ) -> Result<Self, DnsError> {
        let doh = DohClient::with_roots(settings, dialer, options.timeout, roots)?;
        Ok(Self::from_client(settings, doh, options, clock))
    }

    fn from_client(
        settings: &DnsSettings,
        doh: DohClient,
        options: DnsOptions,
        clock: Clock,
    ) -> Self {
        let server_name_lower = normalize_domain(&settings.server_name);
        Self {
            server_ip: settings.server,
            server_name_lower,
            options,
            doh,
            cache: Mutex::new(TtlCache::new(options.cache_entries)),
            reverse: Mutex::new(TtlCache::new(options.reverse_entries)),
            in_flight: AtomicUsize::new(0),
            clock,
        }
    }

    /// Swaps the outbound [`Dialer`] at runtime without clearing caches.
    pub fn set_dialer(&self, dialer: Arc<dyn Dialer>) {
        self.doh.set_dialer(dialer);
    }

    /// Processes a single wire-format DNS query and returns the wire-format
    /// response carrying the same message ID.
    pub fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, DnsError> {
        if IN_DOH_EXCHANGE.with(Cell::get) {
            return Err(DnsError::Loop);
        }

        let parsed = match wire::parse_query(query) {
            Ok(parsed) => parsed,
            Err(wire::WireError::UnsupportedOpcode) => {
                return Ok(wire::error_response(query, wire::RCODE_NOTIMP));
            }
            Err(_) => {
                return Ok(wire::error_response(query, wire::RCODE_FORMERR));
            }
        };

        if matches!(parsed.question.qtype, wire::TYPE_AXFR | wire::TYPE_IXFR) {
            return Ok(wire::error_response(query, wire::RCODE_REFUSED));
        }

        // Loop-protection anchor: never forward queries for the resolver's own
        // TLS server name.
        if parsed.question.qclass == wire::CLASS_IN
            && parsed.question.name == self.server_name_lower
        {
            let answer_ip = match (parsed.question.qtype, self.server_ip) {
                (wire::TYPE_A, IpAddr::V4(_)) | (wire::TYPE_AAAA, IpAddr::V6(_)) => {
                    Some(self.server_ip)
                }
                _ => None,
            };
            let ttl = u32::try_from(self.options.min_ttl.as_secs()).unwrap_or(u32::MAX);
            return Ok(wire::local_answer(query, &parsed, answer_ip, ttl));
        }

        let key = CacheKey {
            name: parsed.question.name.clone(),
            qtype: parsed.question.qtype,
            qclass: parsed.question.qclass,
        };
        let now = (self.clock)();

        if let Some(cached) = self.lookup_cache(&key, now) {
            let mut reply = cached.wire;
            let elapsed = u32::try_from(now.saturating_duration_since(cached.stored_at).as_secs())
                .unwrap_or(u32::MAX);
            wire::set_id(&mut reply, parsed.id);
            wire::set_recursion_desired(&mut reply, parsed.recursion_desired);
            let _ = wire::rewrite_ttls(&mut reply, |ttl| ttl.saturating_sub(elapsed).max(1));
            return Ok(reply);
        }

        let Some(_slot) = self.try_acquire_in_flight() else {
            debug!("dns in-flight limit reached");
            return Ok(wire::error_response(query, wire::RCODE_SERVFAIL));
        };

        let response = {
            let _guard = ExchangeGuard::enter()?;
            self.doh.exchange(query)?
        };

        let answer = wire::parse_response(&response, &parsed.question.name)
            .map_err(|_| DnsError::BadResponse)?;
        let finish = (self.clock)();

        self.record_reverse(&parsed.question.name, &answer, finish);
        self.store_cache(key, &response, &answer, finish);

        Ok(response)
    }

    /// Returns the lower-case domain name (without trailing dot) last seen
    /// answering an `A` or `AAAA` query with `ip`, if still unexpired.
    pub fn domain_for(&self, ip: IpAddr) -> Option<String> {
        let now = (self.clock)();
        let mut reverse = self.reverse.lock().ok()?;
        reverse.get(&ip, now).cloned()
    }

    /// Resolves `name` to IPv4 and IPv6 addresses via [`Self::exchange`].
    pub fn lookup(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        if IN_DOH_EXCHANGE.with(Cell::get) {
            return Err(io::Error::other(DnsError::Loop));
        }
        let trimmed = normalize_domain(name);
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        let query_a = wire::build_query(1, &trimmed, wire::TYPE_A)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, DnsError::InvalidQuery))?;
        let query_aaaa = wire::build_query(2, &trimmed, wire::TYPE_AAAA)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, DnsError::InvalidQuery))?;

        let mut addresses = Vec::new();
        let mut first_error: Option<DnsError> = None;
        let mut succeeded = false;

        for query in [&query_a, &query_aaaa] {
            match self.exchange(query) {
                Ok(reply) => {
                    succeeded = true;
                    if let Ok(answer) = wire::parse_response(&reply, &trimmed)
                        && answer.rcode == wire::RCODE_NOERROR
                    {
                        for (ip, _) in answer.addresses {
                            if !addresses.contains(&ip) {
                                addresses.push(ip);
                            }
                        }
                    }
                }
                Err(DnsError::Loop) => return Err(io::Error::other(DnsError::Loop)),
                Err(err) => {
                    first_error.get_or_insert(err);
                }
            }
        }

        if !addresses.is_empty() {
            return Ok(addresses);
        }
        if !succeeded && let Some(err) = first_error {
            return Err(io::Error::other(err));
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "name not resolved"))
    }

    /// Number of entries currently held in the forward DNS cache.
    pub fn cache_len(&self) -> usize {
        self.cache.lock().map_or(0, |cache| cache.len())
    }

    /// Clears both the forward and reverse caches.
    pub fn flush(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
        if let Ok(mut reverse) = self.reverse.lock() {
            reverse.clear();
        }
    }

    fn lookup_cache(&self, key: &CacheKey, now: Instant) -> Option<CachedResponse> {
        let mut cache = self.cache.lock().ok()?;
        cache.get(key, now).map(|entry| CachedResponse {
            wire: entry.wire.clone(),
            stored_at: entry.stored_at,
        })
    }

    fn store_cache(&self, key: CacheKey, response: &[u8], answer: &wire::Answer, now: Instant) {
        if answer.truncated {
            return;
        }
        let ttl = match answer.rcode {
            wire::RCODE_NOERROR if answer.answer_count > 0 => {
                let raw = Duration::from_secs(u64::from(answer.answer_ttl.unwrap_or(0)));
                clamp_ttl(raw, self.options.min_ttl, self.options.max_ttl)
            }
            wire::RCODE_NXDOMAIN | wire::RCODE_NOERROR => match answer.negative_ttl {
                Some(soa_min) => {
                    Duration::from_secs(u64::from(soa_min)).min(self.options.negative_ttl)
                }
                None => self.options.negative_ttl,
            },
            _ => return,
        };
        if ttl.is_zero() {
            return;
        }
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(
                key,
                CachedResponse {
                    wire: response.to_vec(),
                    stored_at: now,
                },
                now + ttl,
            );
        }
    }

    fn record_reverse(&self, question_name: &str, answer: &wire::Answer, now: Instant) {
        if answer.truncated || answer.rcode != wire::RCODE_NOERROR || answer.addresses.is_empty() {
            return;
        }
        let Ok(mut reverse) = self.reverse.lock() else {
            return;
        };
        for &(ip, record_ttl) in &answer.addresses {
            let ttl = clamp_ttl(
                Duration::from_secs(u64::from(record_ttl)),
                self.options.min_ttl,
                self.options.max_ttl,
            );
            if !ttl.is_zero() {
                reverse.insert(ip, question_name.to_owned(), now + ttl);
            }
        }
    }

    fn try_acquire_in_flight(&self) -> Option<InFlightGuard<'_>> {
        let max = self.options.max_in_flight;
        let mut current = self.in_flight.load(Ordering::Acquire);
        loop {
            if current >= max {
                return None;
            }
            match self.in_flight.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(InFlightGuard {
                        counter: &self.in_flight,
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }
}

impl Resolve for DnsService {
    fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        self.lookup(name)
    }
}

fn normalize_domain(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn clamp_ttl(raw: Duration, min: Duration, max: Duration) -> Duration {
    let upper = max.max(min);
    raw.clamp(min, upper)
}

#[cfg(test)]
mod tests;
