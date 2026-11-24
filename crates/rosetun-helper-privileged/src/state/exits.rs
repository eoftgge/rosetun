//! Extra nodes that `Exit` rules route through.
//!
//! An extra node never decides whether the session is up: one without an address
//! only turns its own rules into `Block`, and one that does not answer only breaks
//! its own rules. Logs carry counts, never names or addresses.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use rosetun_config::{ExitId, Node, RuleSet, RuleTarget, Settings, uses_xray};
use rosetun_engine::{ExtraOutbound, RenderedConfig, SocksProxy, exit_tag};
use rosetun_engine_xray::SocksEndpoint;
use rosetun_ipc::{ErrorCode, ExtraNode, HelperError};

use super::{
    NameLookup, ResolvedNodeEndpoints, StartMode, SuccessfulEndpoint, node_with_endpoints,
    normalize_server, probe::resolve_node_for_apply, protected_endpoints, resolve_quiet,
    select_endpoint,
};

/// The main node's Xray outbound tag.
const TAG_MAIN: &str = "proxy";

fn resolve_fresh_node(node: &Node, lookup: NameLookup) -> Option<ResolvedNodeEndpoints> {
    let rosetun_config::Outbound::XrayBalancer(balancer) = &node.outbound else {
        let ip = node.server.parse::<IpAddr>().ok().or_else(|| {
            resolve_quiet(&node.server, node.port, lookup)
                .and_then(|addresses| select_endpoint(&addresses))
                .ok()
        })?;
        return Some(ResolvedNodeEndpoints::single(&node.server, ip));
    };
    let mut members = HashMap::new();
    let mut primary = None;
    for member in &balancer.members {
        let key = normalize_server(&member.server);
        if let Some(&existing) = members.get(&key) {
            primary.get_or_insert(existing);
            continue;
        }
        let ip = member.server.parse::<IpAddr>().ok().or_else(|| {
            resolve_quiet(&member.server, member.port, lookup)
                .and_then(|addresses| select_endpoint(&addresses))
                .ok()
        });
        if let Some(ip) = ip {
            members.insert(key, ip);
            primary.get_or_insert(ip);
        }
    }
    primary.map(|primary| ResolvedNodeEndpoints::from_members(primary, members))
}

/// Addresses for a connect or reconnect, in request order. A fresh connect
/// resolves before protection goes up; a protected reconnect cannot resolve
/// and uses only IP literals or the address remembered for the exit.
pub(super) fn start_endpoints(
    extra: &[ExtraNode],
    mode: StartMode,
    remembered: &HashMap<ExitId, SuccessfulEndpoint>,
    lookup: NameLookup,
) -> Vec<Option<ResolvedNodeEndpoints>> {
    extra
        .iter()
        .map(|extra| {
            if extra.via.is_some() {
                return extra
                    .node
                    .server
                    .parse::<IpAddr>()
                    .ok()
                    .map(|ip| ResolvedNodeEndpoints::single(&extra.node.server, ip));
            }
            match mode {
                StartMode::Fresh => resolve_fresh_node(&extra.node, lookup),
                StartMode::ProtectedReconnect => {
                    protected_endpoints(&extra.node, remembered.get(&extra.exit)).ok()
                }
            }
        })
        .collect()
}

/// Addresses for `Apply`, in request order: an IP literal, the remembered
/// address, then a lookup through the tunnel, as for the main node.
pub(super) fn apply_endpoints(
    extra: &[ExtraNode],
    remembered: &HashMap<ExitId, SuccessfulEndpoint>,
    lookup: NameLookup,
) -> Vec<Option<ResolvedNodeEndpoints>> {
    extra
        .iter()
        .map(|extra| {
            if extra.via.is_some() {
                return extra
                    .node
                    .server
                    .parse::<IpAddr>()
                    .ok()
                    .map(|ip| ResolvedNodeEndpoints::single(&extra.node.server, ip));
            }
            resolve_node_for_apply(&extra.node, remembered.get(&extra.exit), lookup)
        })
        .collect()
}

/// Remembers the addresses that were used, and forgets exits the request no
/// longer has.
pub(super) fn remember(
    remembered: &mut HashMap<ExitId, SuccessfulEndpoint>,
    extra: &[ExtraNode],
    endpoints: &[Option<ResolvedNodeEndpoints>],
) {
    remembered.retain(|exit, _| {
        extra
            .iter()
            .any(|extra| extra.exit == *exit && extra.via.is_none())
    });
    for (extra, resolved) in extra.iter().zip(endpoints) {
        if let Some(resolved) = resolved.as_ref().filter(|_| extra.via.is_none()) {
            remembered.insert(
                extra.exit.clone(),
                resolved.clone().into_successful(&extra.node.server),
            );
        }
    }
}

/// Each available exit's tag at its original request position; unavailable
/// exits and children of unavailable first hops have no tag.
pub(super) fn exit_tags(
    extra: &[ExtraNode],
    endpoints: &[Option<ResolvedNodeEndpoints>],
) -> Vec<(ExitId, Option<String>)> {
    extra
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let tag = available(extra, endpoints, index).then(|| exit_tag(index));
            (entry.exit.clone(), tag)
        })
        .collect()
}

fn available(
    extra: &[ExtraNode],
    endpoints: &[Option<ResolvedNodeEndpoints>],
    index: usize,
) -> bool {
    endpoints.get(index).is_some_and(Option::is_some)
        && extra[index].via.as_ref().is_none_or(|via| {
            extra
                .iter()
                .position(|entry| &entry.exit == via)
                .is_some_and(|parent| endpoints.get(parent).is_some_and(Option::is_some))
        })
}

/// Extra nodes that have an address, with that address substituted.
pub(super) struct ExtraNodes<'a> {
    nodes: Vec<(&'a ExitId, Node)>,
    identities: Vec<(usize, Option<&'a ExitId>)>,
    blocked: Option<RuleSet>,
    blocked_rules: usize,
}

impl std::fmt::Debug for ExtraNodes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtraNodes")
            .field("nodes", &self.nodes.len())
            .field("blocked_rules", &self.blocked_rules)
            .finish_non_exhaustive()
    }
}

impl<'a> ExtraNodes<'a> {
    pub(super) fn new(
        extra: &'a [ExtraNode],
        endpoints: &[Option<ResolvedNodeEndpoints>],
        rules: &RuleSet,
    ) -> Self {
        let mut nodes = Vec::with_capacity(extra.len());
        let mut identities = Vec::new();
        let mut unresolved = HashSet::new();
        for (index, entry) in extra.iter().enumerate() {
            match endpoints
                .get(index)
                .and_then(Option::as_ref)
                .filter(|_| available(extra, endpoints, index))
            {
                Some(resolved) => {
                    nodes.push((&entry.exit, node_with_endpoints(&entry.node, resolved)));
                    identities.push((index, entry.via.as_ref()));
                }
                None => {
                    unresolved.insert(&entry.exit);
                }
            }
        }
        let (blocked, blocked_rules) = if unresolved.is_empty() {
            (None, 0)
        } else {
            let mut rules = rules.clone();
            let mut count = 0;
            for rule in &mut rules.rules {
                if rule.target == RuleTarget::Exit
                    && rule
                        .exit
                        .as_ref()
                        .is_some_and(|exit| unresolved.contains(exit))
                {
                    rule.target = RuleTarget::Block;
                    rule.exit = None;
                    if rule.enabled {
                        count += 1;
                    }
                }
            }
            (Some(rules), count)
        };
        Self {
            nodes,
            identities,
            blocked,
            blocked_rules,
        }
    }

    /// The rule set to render: `rules` with the rules of unresolved exits blocked.
    pub(super) fn rules<'r>(&'r self, rules: &'r RuleSet) -> &'r RuleSet {
        self.blocked.as_ref().unwrap_or(rules)
    }

    pub(super) fn blocked_rules(&self) -> usize {
        self.blocked_rules
    }

    pub(super) fn len(&self) -> usize {
        self.nodes.len()
    }

    pub(super) fn outbounds<'s>(&'s self, socks: &'s XraySocks) -> Vec<ExtraOutbound<'s>> {
        self.nodes
            .iter()
            .zip(&socks.extra)
            .enumerate()
            .map(|(index, ((exit, node), socks))| ExtraOutbound {
                index: self.identities[index].0,
                via: self.identities[index].1,
                exit,
                node,
                socks: socks.as_ref().map(socks_proxy),
            })
            .collect()
    }
}

/// Loopback SOCKS endpoints for the nodes that run through Xray. All of them
/// share one Xray process.
#[derive(Debug)]
pub(super) struct XraySocks {
    main: Option<SocksEndpoint>,
    extra: Vec<Option<SocksEndpoint>>,
}

impl XraySocks {
    pub(super) fn new(
        node: &Node,
        extra: &ExtraNodes<'_>,
        settings: &Settings,
    ) -> Result<Self, HelperError> {
        let chain = |node: &Node| {
            settings.engine == rosetun_config::EngineKind::SingBox && uses_xray(node, settings)
        };
        let endpoint = |node: &Node| {
            if !chain(node) {
                return Ok(None);
            }
            SocksEndpoint::local().map(Some).map_err(|_| {
                HelperError::new(
                    ErrorCode::XrayStartFailed,
                    "Xray SOCKS endpoint is unavailable",
                )
            })
        };
        Ok(Self {
            main: endpoint(node)?,
            extra: extra
                .nodes
                .iter()
                .map(|(_, node)| endpoint(node))
                .collect::<Result<_, _>>()?,
        })
    }

    /// Whether any node, main or extra, needs Xray.
    pub(super) fn any(&self) -> bool {
        self.main.is_some() || self.extra.iter().any(Option::is_some)
    }

    pub(super) fn main(&self) -> Option<SocksProxy<'_>> {
        self.main.as_ref().map(socks_proxy)
    }

    pub(super) fn endpoints(&self) -> Vec<&SocksEndpoint> {
        self.main
            .iter()
            .chain(self.extra.iter().flatten())
            .collect()
    }

    /// The Xray configuration: the main node as `proxy`, each extra node under
    /// the tag its sing-box outbound uses.
    pub(super) fn render(
        &self,
        node: &Node,
        extra: &ExtraNodes<'_>,
        interface: &str,
        fragment: &rosetun_config::TlsFragment,
        verbose: bool,
        log_level: rosetun_config::LogLevel,
    ) -> Result<RenderedConfig, HelperError> {
        let mut tagged = Vec::new();
        if let Some(socks) = self.main.as_ref() {
            tagged.push((TAG_MAIN.to_owned(), node, socks));
        }
        for (index, ((_, node), socks)) in extra.nodes.iter().zip(&self.extra).enumerate() {
            if let Some(socks) = socks {
                tagged.push((exit_tag(extra.identities[index].0), node, socks));
            }
        }
        let nodes = tagged
            .iter()
            .map(|(tag, node, socks)| (tag.as_str(), *node, *socks))
            .collect::<Vec<_>>();
        rosetun_engine_xray::render(&nodes, interface, fragment, verbose, log_level)
            .map_err(|error| HelperError::new(ErrorCode::XrayStartFailed, error.to_string()))
    }
}

pub(super) fn socks_proxy(socks: &SocksEndpoint) -> SocksProxy<'_> {
    SocksProxy {
        address: socks.address(),
        username: socks.username(),
        password: socks.password(),
    }
}
