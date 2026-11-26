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
pub(crate) mod testcerts;
mod wire;

use std::cell::Cell;
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use rosetun_config::DnsSettings;
use rustls::pki_types::CertificateDer;
use thiserror::Error;
use tracing::debug;

use self::cache::{Clock, TtlCache, system_clock};
use crate::net::{Dialer, Resolve};

pub use self::doh::DohClient;
pub use self::server::DnsServer;

/// Enforces the client's UDP payload limit (RFC 1035 / EDNS0) and `max_payload`
/// (e.g. tunnel MTU minus IP+UDP headers), returning a `TC=1` truncated reply
/// when `response` exceeds either bound.
pub(crate) fn truncate_udp_reply(query: &[u8], response: Vec<u8>, max_payload: usize) -> Vec<u8> {
    let limit = wire::udp_limit(query).min(max_payload);
    if response.len() > limit {
        wire::truncated_response(&response)
    } else {
        response
    }
}

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
    #[error("invalid resolver port")]
    InvalidPort,
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

#[derive(Clone)]
enum FlightOutcome {
    Wire(Vec<u8>),
    ServFail,
    Dial(io::ErrorKind),
    Io(io::ErrorKind),
    HttpStatus(u16),
    BadHttpResponse,
    ResponseTooLarge,
    BadResponse,
}

impl FlightOutcome {
    fn from_error(error: &DnsError) -> Self {
        match error {
            DnsError::Dial(err) => Self::Dial(err.kind()),
            DnsError::Io(err) => Self::Io(err.kind()),
            DnsError::HttpStatus(code) => Self::HttpStatus(*code),
            DnsError::BadHttpResponse => Self::BadHttpResponse,
            DnsError::ResponseTooLarge => Self::ResponseTooLarge,
            DnsError::BadResponse => Self::BadResponse,
            _ => Self::Io(io::ErrorKind::Other),
        }
    }

    fn into_result(self, query: &[u8], id: u16, rd: bool) -> Result<Vec<u8>, DnsError> {
        match self {
            Self::Wire(mut reply) => {
                wire::set_id(&mut reply, id);
                wire::set_recursion_desired(&mut reply, rd);
                Ok(reply)
            }
            Self::ServFail => Ok(wire::error_response(query, wire::RCODE_SERVFAIL)),
            Self::Dial(kind) => Err(DnsError::Dial(io::Error::from(kind))),
            Self::Io(kind) => Err(DnsError::Io(io::Error::from(kind))),
            Self::HttpStatus(code) => Err(DnsError::HttpStatus(code)),
            Self::BadHttpResponse => Err(DnsError::BadHttpResponse),
            Self::ResponseTooLarge => Err(DnsError::ResponseTooLarge),
            Self::BadResponse => Err(DnsError::BadResponse),
        }
    }
}

struct SharedFlight {
    outcome: Mutex<Option<FlightOutcome>>,
    ready: Condvar,
}

impl SharedFlight {
    fn new() -> Self {
        Self {
            outcome: Mutex::new(None),
            ready: Condvar::new(),
        }
    }

    fn finish(&self, result: FlightOutcome) {
        let mut slot = self.outcome.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(result);
            self.ready.notify_all();
        }
    }
}

struct FlightLeaderGuard<'a> {
    flights: &'a Mutex<HashMap<CacheKey, Arc<SharedFlight>>>,
    key: CacheKey,
    flight: Arc<SharedFlight>,
}

impl Drop for FlightLeaderGuard<'_> {
    fn drop(&mut self) {
        self.flights
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.key);
        self.flight.finish(FlightOutcome::Io(io::ErrorKind::Other));
    }
}

/// Thread-safe DNS resolver backed by DoH with forward and reverse TTL caches.
pub struct DnsService {
    resolver: std::sync::RwLock<Arc<DnsResolver>>,
}

struct DnsResolver {
    server_ip: IpAddr,
    server_name_lower: String,
    options: DnsOptions,
    doh: DohClient,
    cache: Mutex<TtlCache<CacheKey, CachedResponse>>,
    reverse: Mutex<TtlCache<IpAddr, String>>,
    flights: Mutex<HashMap<CacheKey, Arc<SharedFlight>>>,
    in_flight: AtomicUsize,
    clock: Clock,
}

impl fmt::Debug for DnsService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsService")
            .field("cache_entries", &self.cache_len())
            .finish_non_exhaustive()
    }
}

impl DnsService {
    /// Creates a DNS service that verifies the upstream against the system's trust store.
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
            resolver: std::sync::RwLock::new(Arc::new(DnsResolver {
                server_ip: settings.server,
                server_name_lower,
                options,
                doh,
                cache: Mutex::new(TtlCache::new(options.cache_entries)),
                reverse: Mutex::new(TtlCache::new(options.reverse_entries)),
                flights: Mutex::new(HashMap::new()),
                in_flight: AtomicUsize::new(0),
                clock,
            })),
        }
    }

    fn resolver(&self) -> Arc<DnsResolver> {
        Arc::clone(
            &self
                .resolver
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    pub(crate) fn replace(&self, next: Self) {
        *self
            .resolver
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = next
            .resolver
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }

    /// Swaps the outbound [`Dialer`] at runtime without clearing caches.
    pub fn set_dialer(&self, dialer: Arc<dyn Dialer>) {
        self.resolver().doh.set_dialer(dialer);
    }

    pub fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, DnsError> {
        self.resolver().exchange(query)
    }

    pub fn domain_for(&self, ip: IpAddr) -> Option<String> {
        self.resolver().domain_for(ip)
    }

    pub fn lookup(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        self.resolver().lookup(name)
    }

    pub fn cache_len(&self) -> usize {
        self.resolver().cache_len()
    }

    pub fn flush(&self) {
        self.resolver().flush();
    }
}

impl DnsResolver {
    /// Processes a single wire-format DNS query and returns the wire-format
    /// response carrying the same message ID.
    fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, DnsError> {
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

        let leader_guard = {
            let mut flights = self.flights.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(existing) = flights.get(&key).cloned() {
                drop(flights);
                let guard = existing
                    .outcome
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let (guard, _) = existing
                    .ready
                    .wait_timeout_while(guard, self.options.timeout, |out| out.is_none())
                    .unwrap_or_else(PoisonError::into_inner);
                let outcome = guard
                    .clone()
                    .unwrap_or(FlightOutcome::Io(io::ErrorKind::TimedOut));
                return outcome.into_result(query, parsed.id, parsed.recursion_desired);
            }
            // Re-check the cache under the flights lock so a follower arriving
            // right as the previous leader finished still hits the cache.
            if let Some(cached) = self.lookup_cache(&key, now) {
                let mut reply = cached.wire;
                let elapsed =
                    u32::try_from(now.saturating_duration_since(cached.stored_at).as_secs())
                        .unwrap_or(u32::MAX);
                wire::set_id(&mut reply, parsed.id);
                wire::set_recursion_desired(&mut reply, parsed.recursion_desired);
                let _ = wire::rewrite_ttls(&mut reply, |ttl| ttl.saturating_sub(elapsed).max(1));
                return Ok(reply);
            }
            let flight = Arc::new(SharedFlight::new());
            flights.insert(key.clone(), Arc::clone(&flight));
            FlightLeaderGuard {
                flights: &self.flights,
                key: key.clone(),
                flight,
            }
        };

        let Some(_slot) = self.try_acquire_in_flight() else {
            debug!("dns in-flight limit reached");
            leader_guard.flight.finish(FlightOutcome::ServFail);
            return Ok(wire::error_response(query, wire::RCODE_SERVFAIL));
        };

        let response = match ExchangeGuard::enter().and_then(|_guard| self.doh.exchange(query)) {
            Ok(response) => response,
            Err(error) => {
                leader_guard
                    .flight
                    .finish(FlightOutcome::from_error(&error));
                return Err(error);
            }
        };

        let Ok(answer) = wire::parse_response(&response, &parsed.question.name) else {
            leader_guard.flight.finish(FlightOutcome::BadResponse);
            return Err(DnsError::BadResponse);
        };
        let finish = (self.clock)();

        self.record_reverse(&parsed.question.name, &answer, finish);
        self.store_cache(key, &response, &answer, finish);
        leader_guard
            .flight
            .finish(FlightOutcome::Wire(response.clone()));

        Ok(response)
    }

    /// Returns the lower-case domain name (without trailing dot) last seen
    /// answering an `A` or `AAAA` query with `ip`, if still unexpired.
    fn domain_for(&self, ip: IpAddr) -> Option<String> {
        let now = (self.clock)();
        let mut reverse = self.reverse.lock().ok()?;
        reverse.get(&ip, now).cloned()
    }

    /// Resolves `name` to IPv4 and IPv6 addresses via [`Self::exchange`].
    fn lookup(&self, name: &str) -> io::Result<Vec<IpAddr>> {
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
    fn cache_len(&self) -> usize {
        self.cache.lock().map_or(0, |cache| cache.len())
    }

    /// Clears both the forward and reverse caches.
    fn flush(&self) {
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
