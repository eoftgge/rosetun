//! Session rule compiler and flow router.
//!
//! ## Evaluation order
//!
//! [`RuleEngine::decide`] matches a [`Flow`] in the exact order used by
//! `rosetun-core::explain` and sing-box:
//!
//! 1. **Link-local direct** (`allow_lan`): when `allow_lan` is enabled and
//!    `flow.ip` is already known and satisfies [`private::is_link_local`],
//!    routes [`Route::Direct`] with [`Reason::LocalNetwork`] before any user
//!    rule or DNS lookup.
//! 2. **Session rules in order**: temporary rules (`0..temporary_count`) come
//!    first, followed by the set's rules. Disabled rules, unexpanded
//!    [`RuleMatcher::Group`] matchers, [`RuleTarget::Exit`] rules whose exit
//!    is absent from `RulePlan::exits`, and list rules whose tag is absent
//!    from `RulePlan::lists` are skipped.
//! 3. **Private-network direct** (`allow_lan && private_networks`): when both
//!    flags are enabled and any destination address satisfies
//!    [`private::is_private`], routes [`Route::Direct`] with
//!    [`Reason::PrivateNetwork`].
//! 4. **Default target**: routes `RuleSet::default_target` with
//!    [`Reason::Default`] (an `Exit` default without an exit resolves to
//!    [`Route::Block`]).
//!
//! ## Lazy DNS resolution
//!
//! When `flow.ip` is `None` and `flow.domain` is `Some(name)`:
//!
//! - Domain-only and process-only rules run without invoking `resolver`. If
//!   an earlier rule decides the flow, `resolver.resolve` is never called.
//! - The first rule that needs an IP address (`RuleMatcher::IpCidr`, a list
//!   rule whose CIDR condition must be checked, or the post-rule
//!   `allow_lan && private_networks` check) calls `resolver.resolve(domain)`
//!   at most once per [`RuleEngine::decide`] call and caches the returned
//!   addresses (or an empty list on error) for the rest of the decision.
//! - CIDR and private-network checks match when any resolved address matches.
//!   A resolution failure yields no addresses, so IP rules do not match and
//!   resolution is not retried.
//!
//! ## Proxy-mode list items
//!
//! List rules (`.srs` or JSON source) that require attributes unavailable in
//! [`Flow`] — source IP/port, destination port, transport network, DNS query
//! type, Wi-Fi SSID/BSSID, OS network flags, interface addresses, or Android
//! package names — never match (even when `invert` is set).

mod cidr;
mod dat;
mod domain;
mod list;
pub mod private;
mod source;
mod srs;

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;

use rosetun_config::{
    DomainMatch, ExitId, ProcessMatch, RuleId, RuleMatcher, RuleSet, RuleTarget, list_tag,
};

use crate::net::Resolve;

pub use cidr::{CidrTree, parse_cidr};

use domain::has_suffix;
use list::CompiledList;

/// Inputs needed to compile a session's rule table.
#[derive(Clone)]
pub struct RulePlan {
    /// Session rules with groups already expanded and temporary rules first.
    pub rules: RuleSet,
    /// Number of leading entries in `rules.rules` that are temporary rules.
    pub temporary_count: usize,
    pub allow_lan: bool,
    pub lan_segment: Vec<rosetun_config::IpPrefix>,
    pub lan_servers: Vec<IpAddr>,
    pub private_networks: bool,
    /// Exits backed by a node; an exit rule whose exit is absent is skipped.
    pub exits: Vec<ExitId>,
    pub lists: Vec<ListInput>,
}

impl fmt::Debug for RulePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RulePlan")
            .field("rule_count", &self.rules.rules.len())
            .field("temporary_count", &self.temporary_count)
            .field("allow_lan", &self.allow_lan)
            .field("private_networks", &self.private_networks)
            .field("exit_count", &self.exits.len())
            .field("list_count", &self.lists.len())
            .finish()
    }
}

/// One compiled-list payload identified by its [`rosetun_config::list_tag`].
#[derive(Clone)]
pub struct ListInput {
    pub tag: String,
    pub content: ListContent,
}

impl fmt::Debug for ListInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListInput")
            .field("content", &self.content)
            .finish_non_exhaustive()
    }
}

/// Raw list payload formats accepted by [`RuleEngine::compile`].
#[derive(Clone)]
pub enum ListContent {
    /// sing-box binary rule-set (`.srs`).
    Srs(Vec<u8>),
    /// sing-box JSON rule-set source.
    Source(Vec<u8>),
    /// Xray `geosite.dat` or `geoip.dat` with `name`, `name@attr`, or `name@!attr`.
    Dat { bytes: Vec<u8>, category: String },
}

impl fmt::Debug for ListContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Srs(bytes) => f
                .debug_struct("ListContent::Srs")
                .field("bytes_len", &bytes.len())
                .finish(),
            Self::Source(bytes) => f
                .debug_struct("ListContent::Source")
                .field("bytes_len", &bytes.len())
                .finish(),
            Self::Dat { bytes, category } => f
                .debug_struct("ListContent::Dat")
                .field("bytes_len", &bytes.len())
                .field("has_category", &!category.is_empty())
                .finish(),
        }
    }
}

/// Attributes known about a flow being routed.
#[derive(Clone, Copy)]
pub struct Flow<'a> {
    /// Destination domain name in any letter case (lowercased internally).
    pub domain: Option<&'a str>,
    pub ip: Option<IpAddr>,
    /// Full executable path of the originating process, or `None` in proxy mode.
    pub process: Option<&'a str>,
}

impl fmt::Debug for Flow<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flow")
            .field("domain", &self.domain.is_some())
            .field("ip", &self.ip.is_some())
            .field("process", &self.process.is_some())
            .finish()
    }
}

/// Route chosen for a flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Proxy,
    Direct,
    Block,
    Exit(ExitId),
}

impl Route {
    fn of(target: RuleTarget, exit: Option<&ExitId>) -> Self {
        match (target, exit) {
            (RuleTarget::Proxy, _) => Self::Proxy,
            (RuleTarget::Direct, _) => Self::Direct,
            (RuleTarget::Exit, Some(exit)) => Self::Exit(exit.clone()),
            (RuleTarget::Block | RuleTarget::Exit, _) => Self::Block,
        }
    }
}

/// Routing decision and the reason that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub route: Route,
    pub reason: Reason,
}

/// Why [`RuleEngine::decide`] picked a [`Route`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    Rule { id: RuleId, temporary: bool },
    LocalNetwork,
    PrivateNetwork,
    Default,
}

/// Errors returned when compiling a [`RulePlan`]. Neither `Display` nor
/// `Debug` exposes domains, IP addresses, paths, or list contents.
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
pub enum RulesError {
    #[error("list exceeds the 128 MiB limit")]
    ListTooLarge,
    #[error("list exceeds the entry limit")]
    TooManyEntries,
    #[error("invalid sing-box binary rule-set")]
    InvalidSrs,
    #[error("unsupported sing-box binary rule-set version {0}")]
    UnsupportedSrsVersion(u8),
    #[error("invalid sing-box source rule-set")]
    InvalidSource,
    #[error("invalid xray dat list")]
    InvalidDat,
    #[error("unknown dat category")]
    UnknownCategory,
    #[error("unsupported list feature")]
    Unsupported,
    #[error("invalid ip cidr")]
    InvalidCidr,
    #[error("invalid regular expression")]
    InvalidRegex,
}

impl fmt::Debug for RulesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// Compiled rule table for a session.
pub struct RuleEngine {
    rules: Vec<CompiledRule>,
    lists: Vec<CompiledList>,
    allow_lan: bool,
    lan_segment: Vec<rosetun_config::IpPrefix>,
    lan_servers: Vec<IpAddr>,
    private_networks: bool,
    default_route: Route,
}

impl fmt::Debug for RuleEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleEngine")
            .field("rule_count", &self.rules.len())
            .field("list_count", &self.lists.len())
            .field("allow_lan", &self.allow_lan)
            .field("private_networks", &self.private_networks)
            .field("default_route", &self.default_route)
            .finish()
    }
}

struct CompiledRule {
    id: RuleId,
    temporary: bool,
    route: Route,
    matcher: CompiledMatcher,
}

enum CompiledMatcher {
    DomainExact(String),
    DomainSuffix(String),
    DomainKeyword(String),
    ProcessName(String),
    ProcessPath(String),
    IpCidr(CidrTree),
    List(usize),
}

impl RuleEngine {
    /// Compiles `plan` once for repeated lock-free flow evaluation.
    ///
    /// Fails closed if any supplied list or CIDR rule cannot be parsed.
    pub fn compile(plan: &RulePlan) -> Result<Self, RulesError> {
        let mut lists = Vec::with_capacity(plan.lists.len());
        let mut list_indices = HashMap::with_capacity(plan.lists.len());
        for input in &plan.lists {
            let compiled = match &input.content {
                ListContent::Srs(bytes) => srs::parse_srs(bytes)?,
                ListContent::Source(bytes) => source::parse_source(bytes)?,
                ListContent::Dat { bytes, category } => dat::parse_dat(bytes, category)?,
            };
            let idx = lists.len();
            lists.push(compiled);
            list_indices.insert(input.tag.as_str(), idx);
        }

        let available_exits: HashSet<&ExitId> = plan.exits.iter().collect();
        let mut compiled_rules = Vec::new();

        for (index, rule) in plan.rules.rules.iter().enumerate() {
            if !rule.enabled {
                continue;
            }
            if rule.target == RuleTarget::Exit
                && !rule
                    .exit
                    .as_ref()
                    .is_some_and(|exit| available_exits.contains(exit))
            {
                continue;
            }
            let matcher = match &rule.matcher {
                RuleMatcher::Group { .. } => continue,
                RuleMatcher::Domain(DomainMatch::Exact(domain)) => {
                    CompiledMatcher::DomainExact(domain.to_lowercase())
                }
                RuleMatcher::Domain(DomainMatch::Suffix(suffix)) => {
                    CompiledMatcher::DomainSuffix(suffix.to_lowercase())
                }
                RuleMatcher::Domain(DomainMatch::Keyword(keyword)) => {
                    CompiledMatcher::DomainKeyword(keyword.to_lowercase())
                }
                RuleMatcher::Process(ProcessMatch::Name(name)) => {
                    CompiledMatcher::ProcessName(if cfg!(windows) {
                        name.to_lowercase()
                    } else {
                        name.clone()
                    })
                }
                RuleMatcher::Process(ProcessMatch::Path(path)) => {
                    CompiledMatcher::ProcessPath(path.to_string_lossy().into_owned())
                }
                RuleMatcher::IpCidr(cidr) => {
                    let prefix = parse_cidr(cidr).ok_or(RulesError::InvalidCidr)?;
                    let mut tree = CidrTree::new();
                    tree.insert(prefix);
                    CompiledMatcher::IpCidr(tree)
                }
                RuleMatcher::List { list, category } => {
                    let tag = list_tag(list, category.as_deref());
                    let Some(&idx) = list_indices.get(tag.as_str()) else {
                        continue;
                    };
                    CompiledMatcher::List(idx)
                }
            };
            compiled_rules.push(CompiledRule {
                id: rule.id.clone(),
                temporary: index < plan.temporary_count,
                route: Route::of(rule.target, rule.exit.as_ref()),
                matcher,
            });
        }

        Ok(Self {
            rules: compiled_rules,
            lists,
            allow_lan: plan.allow_lan,
            lan_segment: plan.lan_segment.clone(),
            lan_servers: plan.lan_servers.clone(),
            private_networks: plan.private_networks,
            default_route: Route::of(plan.rules.default_target, None),
        })
    }

    /// Decides how to route `flow`, resolving `flow.domain` via `resolver` at
    /// most once if an IP-dependent rule or private-network check requires it.
    pub fn decide(&self, flow: &Flow<'_>, resolver: &dyn Resolve) -> Decision {
        if self.allow_lan
            && flow.ip.is_some_and(|ip| {
                !self.lan_servers.contains(&ip)
                    && (private::is_link_local(ip)
                        || self.lan_segment.iter().any(|prefix| prefix.contains(ip)))
            })
        {
            return Decision {
                route: Route::Direct,
                reason: Reason::LocalNetwork,
            };
        }

        let lowered_domain = flow.domain.map(|domain| {
            if domain.is_ascii() && !domain.bytes().any(|b| b.is_ascii_uppercase()) {
                Cow::Borrowed(domain)
            } else {
                Cow::Owned(domain.to_lowercase())
            }
        });
        let mut ctx = EvalCtx::new(lowered_domain.as_deref(), flow.ip, flow.process, resolver);

        for rule in &self.rules {
            if self.matches_rule(&rule.matcher, &mut ctx) {
                return Decision {
                    route: rule.route.clone(),
                    reason: Reason::Rule {
                        id: rule.id.clone(),
                        temporary: rule.temporary,
                    },
                };
            }
        }

        if self.allow_lan
            && self.private_networks
            && ctx
                .resolve_ips()
                .iter()
                .copied()
                .any(|ip| !self.lan_servers.contains(&ip) && private::is_private(ip))
        {
            return Decision {
                route: Route::Direct,
                reason: Reason::PrivateNetwork,
            };
        }

        Decision {
            route: self.default_route.clone(),
            reason: Reason::Default,
        }
    }

    fn matches_rule(&self, matcher: &CompiledMatcher, ctx: &mut EvalCtx<'_, '_>) -> bool {
        match matcher {
            CompiledMatcher::DomainExact(expected) => ctx.domain == Some(expected.as_str()),
            CompiledMatcher::DomainSuffix(suffix) => {
                ctx.domain.is_some_and(|domain| has_suffix(domain, suffix))
            }
            CompiledMatcher::DomainKeyword(keyword) => ctx
                .domain
                .is_some_and(|domain| domain.contains(keyword.as_str())),
            CompiledMatcher::ProcessName(name) => ctx
                .process
                .is_some_and(|path| ends_with_program(path, name)),
            CompiledMatcher::ProcessPath(path) => ctx.process == Some(path.as_str()),
            CompiledMatcher::IpCidr(tree) => ctx.resolve_ips().iter().any(|ip| tree.contains(*ip)),
            CompiledMatcher::List(idx) => self.lists[*idx].matches(ctx),
        }
    }
}

pub(crate) struct EvalCtx<'a, 'r> {
    pub(crate) domain: Option<&'a str>,
    pub(crate) process: Option<&'a str>,
    ip_state: IpState,
    resolver: &'r dyn Resolve,
}

enum IpState {
    Provided([IpAddr; 1]),
    Unresolved,
    Resolved(Vec<IpAddr>),
}

impl<'a, 'r> EvalCtx<'a, 'r> {
    pub(crate) fn new(
        domain: Option<&'a str>,
        ip: Option<IpAddr>,
        process: Option<&'a str>,
        resolver: &'r dyn Resolve,
    ) -> Self {
        let ip_state = match ip {
            Some(addr) => IpState::Provided([addr]),
            None => IpState::Unresolved,
        };
        Self {
            domain,
            process,
            ip_state,
            resolver,
        }
    }

    pub(crate) fn resolve_ips(&mut self) -> &[IpAddr] {
        if matches!(self.ip_state, IpState::Unresolved) {
            let resolved = self
                .domain
                .and_then(|name| self.resolver.resolve(name).ok())
                .unwrap_or_default();
            self.ip_state = IpState::Resolved(resolved);
        }
        match &self.ip_state {
            IpState::Provided(one) => one.as_slice(),
            IpState::Resolved(many) => many.as_slice(),
            IpState::Unresolved => &[],
        }
    }
}

/// Matches a rule by executable name against a full program path, matching
/// case-insensitively on Windows only as `rosetun-core::explain` does.
/// `name` is already lowercased at compile time on Windows.
fn ends_with_program(path: &str, name: &str) -> bool {
    if cfg!(windows) {
        if path.is_ascii() && name.is_ascii() {
            let Some(split) = path.len().checked_sub(name.len()) else {
                return false;
            };
            return (split == 0 || matches!(path.as_bytes()[split - 1], b'\\' | b'/'))
                && path[split..].eq_ignore_ascii_case(name);
        }
        let lower = path.to_lowercase();
        lower
            .strip_suffix(name)
            .is_some_and(|rest| rest.is_empty() || rest.ends_with(['\\', '/']))
    } else {
        path.strip_suffix(name)
            .is_some_and(|rest| rest.is_empty() || rest.ends_with(['\\', '/']))
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rosetun_config::{ListId, Rule, RuleSetId};

    use super::*;

    struct CountingResolver {
        calls: AtomicUsize,
        result: Result<Vec<IpAddr>, io::ErrorKind>,
    }

    impl CountingResolver {
        fn returning(addrs: &[&str]) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                result: Ok(addrs.iter().map(|s| s.parse().unwrap()).collect()),
            }
        }

        fn failing() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                result: Err(io::ErrorKind::NotFound),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Resolve for CountingResolver {
        fn resolve(&self, _name: &str) -> io::Result<Vec<IpAddr>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match &self.result {
                Ok(addrs) => Ok(addrs.clone()),
                Err(kind) => Err(io::Error::new(*kind, "resolution failed")),
            }
        }
    }

    fn make_rule(id: &str, matcher: RuleMatcher, target: RuleTarget) -> Rule {
        Rule {
            id: RuleId::new(id),
            enabled: true,
            matcher,
            target,
            exit: None,
        }
    }

    fn plan(rules: Vec<Rule>) -> RulePlan {
        let mut set = RuleSet::new(RuleSetId::new("set"), "Set", RuleTarget::Proxy);
        set.rules = rules;
        RulePlan {
            rules: set,
            temporary_count: 0,
            allow_lan: false,
            lan_segment: Vec::new(),
            lan_servers: Vec::new(),
            private_networks: false,
            exits: Vec::new(),
            lists: Vec::new(),
        }
    }

    #[test]
    fn lazy_resolve_is_skipped_when_an_earlier_domain_rule_decides() {
        let mut rule_plan = plan(vec![
            make_rule(
                "domain-first",
                RuleMatcher::Domain(DomainMatch::Exact("example.com".into())),
                RuleTarget::Block,
            ),
            make_rule(
                "cidr-later",
                RuleMatcher::IpCidr("192.0.2.0/24".into()),
                RuleTarget::Direct,
            ),
        ]);
        rule_plan.allow_lan = true;
        rule_plan.private_networks = true;
        let engine = RuleEngine::compile(&rule_plan).unwrap();

        let resolver = CountingResolver::returning(&["192.0.2.1"]);
        let decision = engine.decide(
            &Flow {
                domain: Some("EXAMPLE.COM"),
                ip: None,
                process: None,
            },
            &resolver,
        );
        assert_eq!(decision.route, Route::Block);
        assert_eq!(resolver.calls(), 0);
    }

    #[test]
    fn lazy_resolve_runs_at_most_once_across_multiple_ip_and_list_rules() {
        let list_id = ListId::new("cidrs");
        let mut rule_plan = plan(vec![
            make_rule(
                "cidr-1",
                RuleMatcher::IpCidr("192.0.2.0/24".into()),
                RuleTarget::Block,
            ),
            make_rule(
                "list-cidr",
                RuleMatcher::List {
                    list: list_id.clone(),
                    category: None,
                },
                RuleTarget::Direct,
            ),
            make_rule(
                "cidr-2",
                RuleMatcher::IpCidr("203.0.113.0/24".into()),
                RuleTarget::Block,
            ),
        ]);
        rule_plan.allow_lan = true;
        rule_plan.private_networks = true;
        rule_plan.lists.push(ListInput {
            tag: list_tag(&list_id, None),
            content: ListContent::Source(
                br#"{"version":3,"rules":[{"ip_cidr":["198.51.100.0/24"]}]}"#.to_vec(),
            ),
        });
        let engine = RuleEngine::compile(&rule_plan).unwrap();

        // Matches second rule via one resolution returning multiple addresses.
        let resolver = CountingResolver::returning(&["203.0.113.5", "198.51.100.9"]);
        let decision = engine.decide(
            &Flow {
                domain: Some("host.example.com"),
                ip: None,
                process: None,
            },
            &resolver,
        );
        assert_eq!(
            decision,
            Decision {
                route: Route::Direct,
                reason: Reason::Rule {
                    id: RuleId::new("list-cidr"),
                    temporary: false,
                },
            }
        );
        assert_eq!(resolver.calls(), 1);

        // Resolution failure is cached and does not retry across remaining IP rules or private check.
        let failing = CountingResolver::failing();
        let fallback = engine.decide(
            &Flow {
                domain: Some("missing.invalid"),
                ip: None,
                process: None,
            },
            &failing,
        );
        assert_eq!(
            fallback,
            Decision {
                route: Route::Proxy,
                reason: Reason::Default,
            }
        );
        assert_eq!(failing.calls(), 1);
    }

    #[test]
    fn lazy_resolve_supports_private_network_check_after_rules() {
        let mut rule_plan = plan(vec![make_rule(
            "unrelated",
            RuleMatcher::Domain(DomainMatch::Exact("other.example.com".into())),
            RuleTarget::Block,
        )]);
        rule_plan.allow_lan = true;
        rule_plan.private_networks = true;
        let engine = RuleEngine::compile(&rule_plan).unwrap();

        let resolver = CountingResolver::returning(&["192.168.1.10"]);
        let decision = engine.decide(
            &Flow {
                domain: Some("nas.example.invalid"),
                ip: None,
                process: None,
            },
            &resolver,
        );
        assert_eq!(
            decision,
            Decision {
                route: Route::Direct,
                reason: Reason::PrivateNetwork,
            }
        );
        assert_eq!(resolver.calls(), 1);
    }

    #[test]
    fn absent_exit_disabled_group_and_missing_list_rules_are_skipped() {
        let present = ExitId::new("present");
        let absent = ExitId::new("absent");
        let mut rule_plan = plan(vec![
            Rule {
                id: RuleId::new("disabled"),
                enabled: false,
                matcher: RuleMatcher::Domain(DomainMatch::Exact("example.com".into())),
                target: RuleTarget::Block,
                exit: None,
            },
            Rule {
                id: RuleId::new("absent-exit"),
                enabled: true,
                matcher: RuleMatcher::Domain(DomainMatch::Exact("example.com".into())),
                target: RuleTarget::Exit,
                exit: Some(absent),
            },
            make_rule(
                "missing-list",
                RuleMatcher::List {
                    list: ListId::new("left-out"),
                    category: None,
                },
                RuleTarget::Block,
            ),
            Rule {
                id: RuleId::new("present-exit"),
                enabled: true,
                matcher: RuleMatcher::Domain(DomainMatch::Exact("example.com".into())),
                target: RuleTarget::Exit,
                exit: Some(present.clone()),
            },
        ]);
        rule_plan.exits = vec![present.clone()];
        let engine = RuleEngine::compile(&rule_plan).unwrap();

        let resolver = CountingResolver::failing();
        let decision = engine.decide(
            &Flow {
                domain: Some("example.com"),
                ip: None,
                process: None,
            },
            &resolver,
        );
        assert_eq!(
            decision,
            Decision {
                route: Route::Exit(present),
                reason: Reason::Rule {
                    id: RuleId::new("present-exit"),
                    temporary: false,
                },
            }
        );
    }

    #[test]
    fn compile_fails_closed_on_unparseable_list_or_invalid_cidr() {
        let mut bad_list = plan(vec![]);
        bad_list.lists.push(ListInput {
            tag: "list-bad".into(),
            content: ListContent::Source(b"{not-json".to_vec()),
        });
        assert!(RuleEngine::compile(&bad_list).is_err());

        let bad_cidr = plan(vec![make_rule(
            "bad-cidr",
            RuleMatcher::IpCidr("not-a-cidr".into()),
            RuleTarget::Block,
        )]);
        assert_eq!(
            RuleEngine::compile(&bad_cidr).unwrap_err(),
            RulesError::InvalidCidr
        );
    }

    #[test]
    fn compile_and_decide_work_with_srs_and_dat_lists() {
        let srs_id = ListId::new("srs-list");
        let dat_id = ListId::new("dat-list");
        let srs_bytes = srs::test_encoder::encode_srs(
            3,
            &[srs::test_encoder::SrsRule::Default(
                srs::test_encoder::SrsDefaultRule {
                    domain_suffix: &["srs.example.com"],
                    ..Default::default()
                },
            )],
        );
        // Minimal GeoIP dat entry for category "doc" with 198.51.100.0/24.
        let cidr = [0x0a, 4, 198, 51, 100, 0, 0x10, 24];
        let mut entry = vec![0x0a, 3, b'D', b'O', b'C', 0x12, cidr.len() as u8];
        entry.extend_from_slice(&cidr);
        let mut dat_bytes = vec![0x0a, entry.len() as u8];
        dat_bytes.extend_from_slice(&entry);

        let mut rule_plan = plan(vec![
            make_rule(
                "via-srs",
                RuleMatcher::List {
                    list: srs_id.clone(),
                    category: None,
                },
                RuleTarget::Direct,
            ),
            make_rule(
                "via-dat",
                RuleMatcher::List {
                    list: dat_id.clone(),
                    category: Some("doc".into()),
                },
                RuleTarget::Block,
            ),
        ]);
        rule_plan.lists.push(ListInput {
            tag: list_tag(&srs_id, None),
            content: ListContent::Srs(srs_bytes),
        });
        rule_plan.lists.push(ListInput {
            tag: list_tag(&dat_id, Some("doc")),
            content: ListContent::Dat {
                bytes: dat_bytes,
                category: "doc".into(),
            },
        });

        let engine = RuleEngine::compile(&rule_plan).unwrap();
        let resolver = CountingResolver::returning(&["198.51.100.7"]);

        let srs_hit = engine.decide(
            &Flow {
                domain: Some("a.srs.example.com"),
                ip: None,
                process: None,
            },
            &resolver,
        );
        assert_eq!(srs_hit.route, Route::Direct);
        assert_eq!(resolver.calls(), 0);

        let dat_hit = engine.decide(
            &Flow {
                domain: Some("resolved.example.invalid"),
                ip: None,
                process: None,
            },
            &resolver,
        );
        assert_eq!(dat_hit.route, Route::Block);
        assert_eq!(resolver.calls(), 1);
    }

    #[test]
    fn debug_implementations_redact_domains_ips_paths_and_list_contents() {
        let mut rule_plan = plan(vec![make_rule(
            "secret-rule",
            RuleMatcher::Domain(DomainMatch::Exact("secret.example.com".into())),
            RuleTarget::Block,
        )]);
        rule_plan.lists.push(ListInput {
            tag: "list-tag".into(),
            content: ListContent::Source(
                br#"{"version":3,"rules":[{"domain":["hidden.example.org"]}]}"#.to_vec(),
            ),
        });
        let engine = RuleEngine::compile(&rule_plan).unwrap();
        let flow = Flow {
            domain: Some("visited.example.net"),
            ip: Some("192.0.2.77".parse().unwrap()),
            process: Some("/usr/bin/private-tool"),
        };

        let plan_dbg = format!("{rule_plan:?}");
        let engine_dbg = format!("{engine:?}");
        let flow_dbg = format!("{flow:?}");

        for secret in [
            "secret.example.com",
            "hidden.example.org",
            "visited.example.net",
            "192.0.2.77",
            "private-tool",
        ] {
            assert!(!plan_dbg.contains(secret), "plan leaked {secret}");
            assert!(!engine_dbg.contains(secret), "engine leaked {secret}");
            assert!(!flow_dbg.contains(secret), "flow leaked {secret}");
        }
    }
}
