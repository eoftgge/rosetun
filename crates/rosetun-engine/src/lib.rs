//! Engine contract: what Rosetun requires from sing-box, xray, and everything that comes after.
//!
//! The crate lives on the helper side—the engine doesn't launch the application. So the tunnel
//! survives a GUI crash, and the privilege escalation remains at one point.
//!
//! Traits are synchronous. Monitoring a child process is blocking by its nature,
//! and the helper allocates a thread for it. If xray needs
//! gRPC statistics, the runtime is started within that backend and doesn't leak out.

#![forbid(unsafe_code)]

pub mod errors;

/// Tracing target for lines an engine writes to its own output. The helper's
/// default filter passes it at every level, because `Settings::log_level`
/// already decides how much the engine writes.
pub const ENGINE_OUTPUT_TARGET: &str = "engine_output";

use errors::EngineError;
use rosetun_config::{EngineKind, Node, RuleId, RuleSet, Settings};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::AtomicU64};
use std::time::Duration;

/// Fetched through each checked node. Cloudflare is already contacted for the
/// exit lookup, so the check adds no new party. sing-box 1.14.1 discards HTTP
/// URLs in its Clash delay API and substitutes its Google default instead.
pub const PROBE_URL: &str = "https://cp.cloudflare.com/generate_204";
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// A local-only control API that the engine serves for one session.
#[derive(Clone, PartialEq, Eq)]
pub struct ControlEndpoint {
    pub address: SocketAddr,
    pub secret: String,
}

impl ControlEndpoint {
    /// A free port on 127.0.0.1 and a random 256-bit secret.
    pub fn local() -> std::io::Result<Self> {
        // Another process may claim this port before the engine starts listening.
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        drop(listener);

        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|error| std::io::Error::other(error.to_string()))?;
        let hex = b"0123456789abcdef";
        let mut secret = String::with_capacity(64);
        for byte in bytes {
            secret.push(char::from(hex[usize::from(byte >> 4)]));
            secret.push(char::from(hex[usize::from(byte & 0x0f)]));
        }
        Ok(Self { address, secret })
    }
}

impl std::fmt::Debug for ControlEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlEndpoint")
            .field("address", &self.address)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Bytes the engine has carried since it started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrafficTotals {
    pub up: u64,
    pub down: u64,
}

pub trait TrafficProbe: Send + std::fmt::Debug {
    fn totals(&mut self) -> Result<TrafficTotals, EngineError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineIntegration {
    EngineManagedTun,
    /// The backend is a placeholder and cannot provide network integration.
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleCapabilities {
    pub domain_exact: bool,
    pub domain_suffix: bool,
    pub domain_keyword: bool,
    pub process_name: bool,
    pub process_path: bool,
    pub ip_cidr: bool,
    pub lists: bool,
}

impl RuleCapabilities {
    pub const NONE: Self = Self {
        domain_exact: false,
        domain_suffix: false,
        domain_keyword: false,
        process_name: false,
        process_path: false,
        ip_cidr: false,
        lists: false,
    };

    pub const ALL: Self = Self {
        domain_exact: true,
        domain_suffix: true,
        domain_keyword: true,
        process_name: true,
        process_path: true,
        ip_cidr: true,
        lists: true,
    };

    pub fn supports(self, matcher: &rosetun_config::RuleMatcher) -> bool {
        match matcher {
            rosetun_config::RuleMatcher::Domain(rosetun_config::DomainMatch::Exact(_)) => {
                self.domain_exact
            }
            rosetun_config::RuleMatcher::Domain(rosetun_config::DomainMatch::Suffix(_)) => {
                self.domain_suffix
            }
            rosetun_config::RuleMatcher::Domain(rosetun_config::DomainMatch::Keyword(_)) => {
                self.domain_keyword
            }
            rosetun_config::RuleMatcher::Process(rosetun_config::ProcessMatch::Name(_)) => {
                self.process_name
            }
            rosetun_config::RuleMatcher::Process(rosetun_config::ProcessMatch::Path(_)) => {
                self.process_path
            }
            rosetun_config::RuleMatcher::IpCidr(_) => self.ip_cidr,
            rosetun_config::RuleMatcher::List { .. } => self.lists,
            rosetun_config::RuleMatcher::Template(_) => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineCapabilities {
    pub rules: RuleCapabilities,
}

pub trait EngineBackend: Send + Sync + std::fmt::Debug {
    fn kind(&self) -> EngineKind;
    fn integration(&self) -> EngineIntegration;
    fn capabilities(&self) -> EngineCapabilities;
    fn tunnel_dns_server(&self, tun: &rosetun_config::TunSettings) -> Option<std::net::SocketAddr>;
    fn locate_binary(&self) -> Result<PathBuf, EngineError>;
    fn render(&self, request: &RenderRequest<'_>) -> Result<RenderedConfig, EngineError>;

    fn render_probe(
        &self,
        _request: &ProbeRenderRequest<'_>,
    ) -> Result<RenderedConfig, EngineError> {
        Err(EngineError::Unsupported("server checks".to_owned()))
    }

    /// Where `spawn` writes a probe config, so the helper can remove its secrets.
    fn probe_config_path(&self, _config: &RenderedConfig) -> Option<PathBuf> {
        None
    }

    fn url_test(
        &self,
        _control: &ControlEndpoint,
        _target: UrlTestTarget<'_>,
        _url: &str,
        _timeout: Duration,
    ) -> Result<Duration, EngineError> {
        Err(EngineError::Unsupported("URL tests".to_owned()))
    }

    /// Reads traffic from the control API that `render` enabled for `control`.
    fn traffic_probe(&self, _control: &ControlEndpoint) -> Option<Box<dyn TrafficProbe>> {
        None
    }

    fn spawn(
        &self,
        binary: &Path,
        config: &RenderedConfig,
    ) -> Result<Box<dyn EngineProcess>, EngineError>;

    /// Shared deadline for logging destinations; the helper can close the gate
    /// while the process is still draining its output during shutdown.
    fn spawn_with_log_gate(
        &self,
        binary: &Path,
        config: &RenderedConfig,
        verbose_until_unix: Arc<AtomicU64>,
    ) -> Result<Box<dyn EngineProcess>, EngineError> {
        let _ = verbose_until_unix;
        self.spawn(binary, config)
    }
}

#[derive(Clone, Copy)]
pub struct RenderRequest<'a> {
    pub node: &'a Node,
    pub rules: &'a RuleSet,
    pub lists: &'a [rosetun_config::ListRef],
    pub fallback_block_rules: &'a [rosetun_config::RuleId],
    pub settings: &'a Settings,
    pub control: Option<&'a ControlEndpoint>,
    pub verbose_log: bool,
}

impl std::fmt::Debug for RenderRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RenderRequest")
            .field("node_id", &self.node.id)
            .field("engine", &self.settings.engine)
            .field("kill_switch", &self.settings.kill_switch)
            .field("rule_set_id", &self.rules.id)
            .field("rule_count", &self.rules.rules.len())
            .field("list_count", &self.lists.len())
            .field("fallback_block_rule_count", &self.fallback_block_rules.len())
            .field("control", &self.control)
            .field("verbose_log", &self.verbose_log)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
pub struct ProbeRenderRequest<'a> {
    /// Nodes with their outbound tags. Server addresses are IP literals.
    pub nodes: &'a [(String, Node)],
    pub control: &'a ControlEndpoint,
    /// The physical interface to dial through; `None` lets the engine pick.
    pub interface: Option<&'a str>,
}

impl std::fmt::Debug for ProbeRenderRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeRenderRequest")
            .field("node_count", &self.nodes.len())
            .field("control", &self.control)
            .field("interface", &self.interface)
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum UrlTestTarget<'a> {
    /// The proxy outbound of a running session.
    Session,
    /// An outbound of a probe config, by tag.
    Probe(&'a str),
}

#[derive(Clone, PartialEq, Eq)]
pub struct RenderedConfig {
    pub file_name: String,
    pub body: Vec<u8>,
    /// Enabled rules that the backend cannot represent in its configuration.
    pub unsupported: Vec<RuleId>,
    /// Probe outbound tags whose nodes the backend cannot represent.
    pub unsupported_probes: Vec<String>,
}

impl std::fmt::Debug for RenderedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RenderedConfig")
            .field("file_name", &self.file_name)
            .field("body_len", &self.body.len())
            .field("unsupported", &self.unsupported)
            .field("unsupported_probes", &self.unsupported_probes)
            .finish()
    }
}

impl RenderedConfig {
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.body).ok()
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StartupHints {
    pub slow_tunnel_creation: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundFailure {
    Unreachable,
    Rejected,
    Closed,
}

/// Saturating monotonic diagnostic counters, scoped to one engine process.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OutboundFailures {
    pub unreachable: u64,
    pub rejected: u64,
    pub closed: u64,
}

impl OutboundFailures {
    pub fn delta(self, previous: Self) -> Self {
        Self {
            unreachable: self.unreachable.saturating_sub(previous.unreachable),
            rejected: self.rejected.saturating_sub(previous.rejected),
            closed: self.closed.saturating_sub(previous.closed),
        }
    }

    pub fn threshold(self, events: u64) -> Option<OutboundFailure> {
        if self.rejected >= events {
            Some(OutboundFailure::Rejected)
        } else if self.unreachable >= events {
            Some(OutboundFailure::Unreachable)
        } else if self.closed >= events {
            Some(OutboundFailure::Closed)
        } else {
            None
        }
    }
}

pub trait EngineProcess: Send + std::fmt::Debug {
    fn is_running(&mut self) -> Result<bool, EngineError>;

    /// Non-blocking startup readiness check.
    ///
    /// Backends without a separate startup handshake retain their existing
    /// behavior. The caller must check process liveness separately.
    fn is_ready(&mut self) -> Result<bool, EngineError> {
        Ok(true)
    }

    fn stop(&mut self) -> Result<(), EngineError>;

    /// Non-blocking, latched hints from startup diagnostics.
    fn startup_hints(&self) -> StartupHints {
        StartupHints::default()
    }

    fn outbound_failures(&self) -> OutboundFailures {
        OutboundFailures::default()
    }
}

#[derive(Debug, Default)]
pub struct EngineRegistry {
    backends: Vec<Box<dyn EngineBackend>>,
}

impl EngineRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, backend: Box<dyn EngineBackend>) -> &mut Self {
        self.backends.push(backend);
        self
    }

    pub fn get(&self, kind: EngineKind) -> Option<&dyn EngineBackend> {
        self.backends
            .iter()
            .find(|backend| backend.kind() == kind)
            .map(|backend| backend.as_ref())
    }

    pub fn kinds(&self) -> impl Iterator<Item = EngineKind> + '_ {
        self.backends.iter().map(|backend| backend.kind())
    }
}

#[cfg(test)]
mod tests {
    use super::{ControlEndpoint, RuleCapabilities};
    use rosetun_config::{ListId, RuleMatcher};

    #[test]
    fn list_rules_require_an_explicit_backend_capability() {
        let matcher = RuleMatcher::List {
            list: ListId::new("1"),
            category: None,
        };
        assert!(!RuleCapabilities::NONE.supports(&matcher));
        assert!(RuleCapabilities::ALL.supports(&matcher));
    }

    #[test]
    fn local_control_endpoint_uses_loopback_and_a_redacted_hex_secret() {
        let endpoint = ControlEndpoint::local().expect("local endpoint");
        assert!(endpoint.address.ip().is_loopback());
        assert_ne!(endpoint.address.port(), 0);
        assert_eq!(endpoint.secret.len(), 64);
        assert!(
            endpoint
                .secret
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        let debug = format!("{endpoint:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&endpoint.secret));
    }
}
