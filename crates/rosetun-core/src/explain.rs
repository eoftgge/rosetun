//! Which rule of the running session routes a connection.
//!
//! The answer is worked out from the rules the engine received, in the order
//! the sing-box renderer emits them: the rules of
//! [`ConnectRequest::effective_rule_set`] (temporary rules first), the local
//! network when it is allowed, then the default. Conditions match as sing-box
//! 1.14 matches them. A connection is the user's browsing history: nothing
//! here logs or keeps one, and no `Debug` shows a destination.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;

use regex_automata::meta::Regex;
use rosetun_config::{
    ConnectionRoute, DomainMatch, ExitId, ListId, LiveConnection, ProcessMatch, RuleId,
    RuleMatcher, RuleTarget, RuleTemplate, list_tag,
};
use rosetun_ipc::ConnectRequest;
use serde_json::Value;

use crate::lists::{Chosen, choose_payload};
use crate::{ListPayload, PayloadFormat, Store, StoreError};

/// What is known about one connection.
#[derive(Clone, Copy)]
pub struct Destination<'a> {
    /// The site name, when the engine saw one.
    pub domain: Option<&'a str>,
    pub ip: Option<IpAddr>,
    /// The program's full path.
    pub process: Option<&'a str>,
}

impl fmt::Debug for Destination<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Destination")
            .field("domain", &self.domain.is_some())
            .field("ip", &self.ip.is_some())
            .field("process", &self.process.is_some())
            .finish()
    }
}

impl<'a> Destination<'a> {
    pub fn of(connection: &'a LiveConnection) -> Self {
        let process = connection.process.as_deref();
        match connection.host.parse::<IpAddr>() {
            Ok(ip) => Self {
                domain: None,
                ip: Some(ip),
                process,
            },
            Err(_) => Self {
                domain: Some(&connection.host),
                ip: connection.ip.as_deref().and_then(|ip| ip.parse().ok()),
                process,
            },
        }
    }
}

/// Where the rules send a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplainedRoute {
    Proxy,
    Direct,
    Block,
    Exit(ExitId),
}

impl ExplainedRoute {
    fn of(target: RuleTarget, exit: Option<&ExitId>) -> Self {
        match (target, exit) {
            (RuleTarget::Proxy, _) => Self::Proxy,
            (RuleTarget::Direct, _) => Self::Direct,
            (RuleTarget::Exit, Some(exit)) => Self::Exit(exit.clone()),
            (RuleTarget::Block | RuleTarget::Exit, _) => Self::Block,
        }
    }

    /// A blocked connection never reaches the engine's list.
    pub fn agrees_with(&self, route: &ConnectionRoute) -> bool {
        match (self, route) {
            (Self::Proxy, ConnectionRoute::Proxy) | (Self::Direct, ConnectionRoute::Direct) => true,
            (Self::Exit(explained), ConnectionRoute::Exit(taken)) => explained == taken,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// A rule the session received: one of its temporary rules or a rule of
    /// its set (by the set's rule id).
    Rule {
        id: RuleId,
        temporary: bool,
        source: RuleSource,
    },
    /// Local addresses go direct because the settings allow the local network.
    LocalNetwork,
    /// No rule matched.
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSource {
    /// The rule's own condition.
    Condition(RuleMatcher),
    /// One of the conditions a template rule stands for.
    Template {
        template: RuleTemplate,
        matcher: RuleMatcher,
    },
    List {
        list: ListId,
        category: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Explanation {
    Routed {
        reason: Reason,
        route: ExplainedRoute,
    },
    /// The rule's list cannot be read here (an uploaded `.srs`), so all that
    /// is known is that no rule before it matched.
    Unverifiable { rule: RuleId, temporary: bool },
}

/// The session's list contents, by the tag the engine got them under.
#[derive(Default)]
pub struct SessionLists {
    contents: HashMap<String, ListContent>,
}

impl fmt::Debug for SessionLists {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionLists")
            .field("lists", &self.contents.len())
            .finish()
    }
}

enum ListContent {
    Rules(Vec<SourceRule>),
    Unreadable,
    /// The list could not be prepared, so the engine never got the rule.
    LeftOut,
}

impl SessionLists {
    /// The payload the engine got for a list rule; `None` when the rule was
    /// left out of the request.
    pub fn insert(&mut self, list: &ListId, category: Option<&str>, payload: Option<&ListPayload>) {
        let content = match payload {
            None => ListContent::LeftOut,
            Some(payload) => match payload.format {
                PayloadFormat::Binary => ListContent::Unreadable,
                PayloadFormat::Source => {
                    parse_source(&payload.bytes).map_or(ListContent::Unreadable, ListContent::Rules)
                }
            },
        };
        self.contents.insert(list_tag(list, category), content);
    }

    fn contains(&self, list: &ListId, category: Option<&str>) -> bool {
        self.contents.contains_key(&list_tag(list, category))
    }
}

/// Reads the lists of the session's list rules as connecting prepares them.
/// A list that cannot be read is unreadable, not an error.
pub fn read_session_lists(
    store: &Store,
    request: &ConnectRequest,
) -> Result<SessionLists, StoreError> {
    let config = store.load()?;
    let mut lists = SessionLists::default();
    for rule in request.effective_rule_set().enabled() {
        let RuleMatcher::List { list, category } = &rule.matcher else {
            continue;
        };
        let category = category.as_deref();
        if lists.contains(list, category) {
            continue;
        }
        match choose_payload(store, &config, list, category) {
            Ok(Chosen { payload, .. }) => lists.insert(list, category, payload.as_ref()),
            Err(_) => {
                lists
                    .contents
                    .insert(list_tag(list, category), ListContent::Unreadable);
            }
        }
    }
    Ok(lists)
}

/// Which rule routes `destination` in the session `request` started.
pub fn explain(
    request: &ConnectRequest,
    lists: &SessionLists,
    destination: &Destination<'_>,
) -> Explanation {
    let domain = destination.domain.map(str::to_lowercase);
    let target = Target {
        domain: domain.as_deref(),
        ip: destination.ip,
        process: destination.process,
    };
    let rules = request.effective_rule_set();
    let temporary_count = request.temporary_rules.len();
    for (index, rule) in rules.rules.iter().enumerate() {
        if !rule.enabled {
            continue;
        }
        let temporary = index < temporary_count;
        if rule.target == RuleTarget::Exit
            && !rule.exit.as_ref().is_some_and(|exit| {
                request.extra_nodes.iter().any(|extra| extra.exit == *exit)
            })
        {
            // The renderer refuses it and the service never starts the session.
            continue;
        }
        let source = match &rule.matcher {
            RuleMatcher::Template(_) => continue,
            RuleMatcher::List { list, category } => {
                match lists.contents.get(&list_tag(list, category.as_deref())) {
                    Some(ListContent::LeftOut) => continue,
                    Some(ListContent::Rules(set)) => {
                        if !set.iter().any(|item| item.matches(&target)) {
                            continue;
                        }
                        RuleSource::List {
                            list: list.clone(),
                            category: category.clone(),
                        }
                    }
                    Some(ListContent::Unreadable) | None => {
                        return Explanation::Unverifiable {
                            rule: rule.id.clone(),
                            temporary,
                        };
                    }
                }
            }
            matcher => {
                if !matches_rule(matcher, &target) {
                    continue;
                }
                match request
                    .rule_templates
                    .iter()
                    .find(|(id, _)| *id == rule.id)
                    .filter(|_| !temporary)
                {
                    Some((_, template)) => RuleSource::Template {
                        template: *template,
                        matcher: matcher.clone(),
                    },
                    None => RuleSource::Condition(matcher.clone()),
                }
            }
        };
        return Explanation::Routed {
            reason: Reason::Rule {
                id: rule.id.clone(),
                temporary,
                source,
            },
            route: ExplainedRoute::of(rule.target, rule.exit.as_ref()),
        };
    }
    if request.settings.allow_lan && destination.ip.is_some_and(is_private) {
        return Explanation::Routed {
            reason: Reason::LocalNetwork,
            route: ExplainedRoute::Direct,
        };
    }
    Explanation::Routed {
        reason: Reason::Default,
        route: ExplainedRoute::of(rules.default_target, None),
    }
}

/// [`explain`] for a connection the engine carries, or `None` when the rules
/// give another route than the one the engine took: then the explanation is
/// not trusted.
pub fn explain_connection(
    request: &ConnectRequest,
    lists: &SessionLists,
    connection: &LiveConnection,
) -> Option<Explanation> {
    let explanation = explain(request, lists, &Destination::of(connection));
    match &explanation {
        Explanation::Routed { route, .. } if !route.agrees_with(&connection.route) => None,
        _ => Some(explanation),
    }
}

struct Target<'a> {
    /// In lower case: sing-box lowers the name before matching.
    domain: Option<&'a str>,
    ip: Option<IpAddr>,
    process: Option<&'a str>,
}

fn matches_rule(matcher: &RuleMatcher, target: &Target<'_>) -> bool {
    match matcher {
        RuleMatcher::Domain(DomainMatch::Exact(domain)) => target.domain == Some(domain.as_str()),
        RuleMatcher::Domain(DomainMatch::Suffix(suffix)) => target
            .domain
            .is_some_and(|domain| has_suffix(domain, suffix)),
        RuleMatcher::Domain(DomainMatch::Keyword(keyword)) => target
            .domain
            .is_some_and(|domain| domain.contains(keyword.as_str())),
        RuleMatcher::Process(ProcessMatch::Name(name)) => target
            .process
            .is_some_and(|path| ends_with_program(path, name)),
        RuleMatcher::Process(ProcessMatch::Path(path)) => {
            target.process == Some(path.to_string_lossy().as_ref())
        }
        RuleMatcher::IpCidr(cidr) => Cidr::parse(cidr)
            .zip(target.ip)
            .is_some_and(|(cidr, ip)| cidr.contains(ip)),
        RuleMatcher::List { .. } | RuleMatcher::Template(_) => false,
    }
}

/// sing-box `domain_suffix`: the domain itself and its subdomains, or only
/// subdomains when the suffix starts with a dot.
fn has_suffix(domain: &str, suffix: &str) -> bool {
    if suffix.starts_with('.') {
        domain.ends_with(suffix)
    } else {
        domain == suffix
            || domain
                .strip_suffix(suffix)
                .is_some_and(|rest| rest.ends_with('.'))
    }
}

/// The renderer's `(?i)(?:^|[\\/])<name>$` for a rule by program name.
fn ends_with_program(path: &str, name: &str) -> bool {
    let (path, name) = (path.to_lowercase(), name.to_lowercase());
    path.strip_suffix(&name)
        .is_some_and(|rest| rest.is_empty() || rest.ends_with(['\\', '/']))
}

/// sing-box `ip_is_private`: not a public address in sing's
/// `network.IsPublicAddr`.
fn is_private(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_link_local()
                || ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            ip.is_unique_local()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unicast_link_local()
                || ip.is_unspecified()
        }
    }
}

#[derive(Clone, Copy)]
struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn parse(text: &str) -> Option<Self> {
        let (network, prefix) = match text.split_once('/') {
            Some((ip, prefix)) => (ip.parse::<IpAddr>().ok()?, prefix.parse().ok()?),
            None => {
                let ip = text.parse::<IpAddr>().ok()?;
                (ip, if ip.is_ipv4() { 32 } else { 128 })
            }
        };
        let bits = if network.is_ipv4() { 32 } else { 128 };
        (prefix <= bits).then_some(Self { network, prefix })
    }

    fn contains(self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.prefix)).unwrap_or(0);
                u32::from(network) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(network) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// One rule of a sing-box source list. The address conditions match if any
/// one does; `process_name` and `process_path`, when present, must match too.
#[derive(Default)]
struct SourceRule {
    domains: HashSet<String>,
    suffixes: Vec<String>,
    keywords: Vec<String>,
    regexes: Vec<Regex>,
    cidrs: Vec<Cidr>,
    names: Option<HashSet<String>>,
    paths: Option<HashSet<String>>,
}

impl SourceRule {
    fn has_address(&self) -> bool {
        !self.domains.is_empty()
            || !self.suffixes.is_empty()
            || !self.keywords.is_empty()
            || !self.regexes.is_empty()
            || !self.cidrs.is_empty()
    }

    fn matches(&self, target: &Target<'_>) -> bool {
        let address = !self.has_address()
            || target.domain.is_some_and(|domain| {
                self.domains.contains(domain)
                    || self.suffixes.iter().any(|suffix| has_suffix(domain, suffix))
                    || self.keywords.iter().any(|keyword| domain.contains(keyword))
                    || self.regexes.iter().any(|regex| regex.is_match(domain))
            })
            || target
                .ip
                .is_some_and(|ip| self.cidrs.iter().any(|cidr| cidr.contains(ip)));
        let base = target
            .process
            .map(|path| path.rsplit(['\\', '/']).next().unwrap_or(path));
        address
            && self
                .names
                .as_ref()
                .is_none_or(|names| base.is_some_and(|base| names.contains(base)))
            && self
                .paths
                .as_ref()
                .is_none_or(|paths| target.process.is_some_and(|path| paths.contains(path)))
    }
}

/// `None` for anything but the conditions this module knows: the list is
/// then unreadable rather than half understood.
fn parse_source(bytes: &[u8]) -> Option<Vec<SourceRule>> {
    let root: Value = serde_json::from_slice(bytes).ok()?;
    root.get("rules")?
        .as_array()?
        .iter()
        .map(|rule| {
            let mut parsed = SourceRule::default();
            for (key, values) in rule.as_object()? {
                let values = values
                    .as_array()?
                    .iter()
                    .map(|value| value.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()?;
                match key.as_str() {
                    "domain" => parsed.domains.extend(values),
                    "domain_suffix" => parsed.suffixes.extend(values),
                    "domain_keyword" => parsed.keywords.extend(values),
                    "domain_regex" => {
                        for value in values {
                            parsed.regexes.push(Regex::new(&value).ok()?);
                        }
                    }
                    "ip_cidr" => {
                        for value in values {
                            parsed.cidrs.push(Cidr::parse(&value)?);
                        }
                    }
                    "process_name" => parsed.names.get_or_insert_default().extend(values),
                    "process_path" => parsed.paths.get_or_insert_default().extend(values),
                    _ => return None,
                }
            }
            Some(parsed)
        })
        .collect()
}

#[cfg(test)]
mod tests;
