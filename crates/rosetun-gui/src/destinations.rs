//! What the rule destination picker offers, from the configuration alone.

use std::collections::BTreeSet;

use rosetun_config::{AppConfig, CountryCode, Exit, ExitId, ExitTarget, Selection, node_country};
use rosetun_core::resolve_exits;

pub(crate) const MAX_NODE_RESULTS: usize = 20;

/// Uses the IPC contract for every resolved path, including children of an edited A.
pub(crate) fn exit_path_supported(
    config: &AppConfig,
    editing: Option<&ExitId>,
    target: &ExitTarget,
    via: Option<&ExitId>,
) -> bool {
    let mut draft = config.clone();
    if let Some(id) = editing {
        let Some(exit) = draft.exits.iter_mut().find(|exit| &exit.id == id) else {
            return false;
        };
        exit.target = target.clone();
        exit.via = via.cloned();
    } else {
        let mut id = String::from("draft");
        while draft.exits.iter().any(|exit| exit.id.as_str() == id) {
            id.push('_');
        }
        draft.exits.push(Exit {
            id: ExitId::new(id),
            name: String::from("Draft"),
            target: target.clone(),
            via: via.cloned(),
        });
    }
    if !draft.exits.iter().any(|exit| exit.via.is_some()) {
        return true;
    }
    if draft.validate().is_err() {
        return false;
    }
    let resolved = resolve_exits(&draft.exits, &draft.subscriptions, &[], &[]);
    let mut extra_nodes = Vec::new();
    for exit in &draft.exits {
        let involved = exit.via.is_some()
            || draft
                .exits
                .iter()
                .any(|child| child.via.as_ref() == Some(&exit.id));
        if !involved {
            continue;
        }
        let Some(selection) = resolved
            .iter()
            .find(|(id, _)| id == &exit.id)
            .and_then(|(_, selection)| selection.as_ref())
        else {
            return false;
        };
        let Some((_, node)) = draft.node_at(selection) else {
            return false;
        };
        extra_nodes.push(rosetun_ipc::ExtraNode {
            exit: exit.id.clone(),
            via: exit.via.clone(),
            selection: selection.clone(),
            node: node.clone(),
        });
    }
    let Some(first) = extra_nodes.first() else {
        return false;
    };
    let request = rosetun_ipc::ConnectRequest {
        selection: first.selection.clone(),
        node: first.node.clone(),
        rule_set: rosetun_config::RuleSet::new(
            rosetun_config::RuleSetId::new("draft"),
            "Draft",
            rosetun_config::RuleTarget::Proxy,
        ),
        extra_nodes,
        temporary_rules: Vec::new(),
        lists: Vec::new(),
        settings: draft.settings,
        rule_templates: Vec::new(),
    };
    request.validate_exit_chains().is_ok()
}

pub(crate) fn exit_path_label(config: &AppConfig, exit: &Exit) -> String {
    let name = crate::display::safe_text(&exit.name);
    match &exit.via {
        Some(via) => {
            let parent = config
                .exits
                .iter()
                .find(|entry| &entry.id == via)
                .map_or_else(
                    || tr!("connection-exit-removed"),
                    |entry| crate::display::safe_text(&entry.name),
                );
            format!("{parent} → {name}")
        }
        None => name,
    }
}

pub(crate) fn exits_full(config: &AppConfig) -> bool {
    config.exits.len() >= rosetun_ipc::MAX_EXTRA_NODES
}

/// The country shown next to an exit: its own, or its node's fallback.
pub(crate) fn exit_country(exit: &Exit) -> Option<&CountryCode> {
    match &exit.target {
        ExitTarget::Country(code) => Some(code),
        ExitTarget::Node { fallback, .. } => fallback.as_ref(),
    }
}

/// Countries of subscription nodes that have no country exit yet, in code order.
pub(crate) fn new_countries(config: &AppConfig) -> Vec<CountryCode> {
    let taken: BTreeSet<&str> = config
        .exits
        .iter()
        .filter_map(|exit| match &exit.target {
            ExitTarget::Country(code) => Some(code.as_str()),
            ExitTarget::Node { .. } => None,
        })
        .collect();
    let mut codes: Vec<CountryCode> = config
        .subscriptions
        .iter()
        .flat_map(|subscription| &subscription.nodes)
        .filter_map(|node| node_country(&node.name))
        .filter(|code| !taken.contains(code.as_str()))
        .collect();
    codes.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    codes.dedup();
    codes
}

pub(crate) struct NodeMatch<'a> {
    pub(crate) selection: Selection,
    pub(crate) name: &'a str,
    /// The exit that already points to this node.
    pub(crate) exit: Option<&'a ExitId>,
}

/// Subscription nodes whose names contain `query`, ignoring case; at most `MAX_NODE_RESULTS`.
pub(crate) fn matching_nodes<'a>(config: &'a AppConfig, query: &str) -> Vec<NodeMatch<'a>> {
    let query = query.trim().to_lowercase();
    config
        .subscriptions
        .iter()
        .flat_map(|subscription| {
            subscription
                .nodes
                .iter()
                .map(move |node| (subscription, node))
        })
        .filter(|(_, node)| query.is_empty() || node.name.to_lowercase().contains(&query))
        .take(MAX_NODE_RESULTS)
        .map(|(subscription, node)| {
            let selection = Selection {
                subscription: subscription.id.clone(),
                node: node.id.clone(),
            };
            let exit = config
                .exits
                .iter()
                .find(|exit| {
                    matches!(&exit.target, ExitTarget::Node { selection: existing, .. } if existing == &selection)
                })
                .map(|exit| &exit.id);
            NodeMatch {
                selection,
                name: &node.name,
                exit,
            }
        })
        .collect()
}

/// Exits that resolve to no node right now, without delays or pinned choices:
/// their rules block until the exit is fixed.
pub(crate) fn unresolved_exits(config: &AppConfig) -> BTreeSet<ExitId> {
    resolve_exits(&config.exits, &config.subscriptions, &[], &[])
        .into_iter()
        .filter(|(_, node)| node.is_none())
        .map(|(id, _)| id)
        .collect()
}

/// What an exit leads to right now, as the Exits tab shows it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExitNow<'a> {
    Node(&'a str),
    /// A node exit whose node is gone, served by any node of this country.
    Fallback(&'a CountryCode),
    NodeGone,
    NoCountryNodes(&'a CountryCode),
}

/// `resolved` is the exit's node from `resolve_exits`.
pub(crate) fn exit_now<'a>(
    config: &'a AppConfig,
    exit: &'a Exit,
    resolved: Option<&Selection>,
) -> ExitNow<'a> {
    let node_name = |selection: &Selection| {
        config
            .subscriptions
            .iter()
            .find(|subscription| subscription.id == selection.subscription)
            .and_then(|subscription| subscription.node(&selection.node))
            .map(|node| node.name.as_str())
    };
    match (&exit.target, resolved) {
        (ExitTarget::Node { selection, .. }, Some(node)) if node == selection => {
            node_name(node).map_or(ExitNow::NodeGone, ExitNow::Node)
        }
        (
            ExitTarget::Node {
                fallback: Some(code),
                ..
            },
            Some(_),
        ) => ExitNow::Fallback(code),
        (ExitTarget::Node { .. }, _) => ExitNow::NodeGone,
        (ExitTarget::Country(code), Some(node)) => {
            node_name(node).map_or(ExitNow::NoCountryNodes(code), ExitNow::Node)
        }
        (ExitTarget::Country(code), None) => ExitNow::NoCountryNodes(code),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use rosetun_config::{Node, NodeId, Outbound, StreamSettings, Subscription, SubscriptionId};

    use super::*;

    fn country(code: &str) -> CountryCode {
        CountryCode::parse(code).unwrap()
    }

    pub(crate) fn config(nodes: &[(&str, &str)], exits: Vec<Exit>) -> AppConfig {
        AppConfig {
            subscriptions: vec![Subscription {
                id: SubscriptionId::new("sub"),
                name: "Example".into(),
                url: "https://sub.example.com/nodes".into(),
                nodes: nodes
                    .iter()
                    .map(|(id, name)| Node {
                        id: NodeId::new(*id),
                        name: (*name).into(),
                        server: "192.0.2.10".into(),
                        port: 443,
                        outbound: Outbound::Unknown {
                            scheme: "example".into(),
                            params: BTreeMap::new(),
                        },
                        stream: StreamSettings::default(),
                        raw: None,
                    })
                    .collect(),
                auto_update: false,
                updated_at_unix: None,
                user_agent: None,
                send_hwid: true,
                hwid_scope: rosetun_config::HwidScope::Machine,
                info: None,
                update_interval_hours: None,
                support_url: None,
                web_page_url: None,
                announce: None,
                notices: Vec::new(),
            }],
            exits,
            ..AppConfig::default()
        }
    }

    pub(crate) fn exit(id: &str, target: ExitTarget) -> Exit {
        Exit {
            via: None,
            id: ExitId::new(id),
            name: "Example exit".into(),
            target,
        }
    }

    #[test]
    fn country_with_an_exit_is_not_offered_again() {
        let nodes = [
            ("a", "🇳🇱 One"),
            ("b", "🇩🇪 Two"),
            ("c", "NL Three"),
            ("d", "Plain"),
        ];
        assert_eq!(
            new_countries(&config(&nodes, Vec::new())),
            [country("DE"), country("NL")]
        );
        let exits = vec![exit("1", ExitTarget::Country(country("NL")))];
        assert_eq!(new_countries(&config(&nodes, exits)), [country("DE")]);
    }

    #[test]
    fn node_search_ignores_case_marks_existing_exits_and_stops_at_twenty() {
        let names: Vec<(String, String)> = (0..30)
            .map(|index| (format!("n{index}"), format!("Example {index}")))
            .collect();
        let nodes: Vec<(&str, &str)> = names
            .iter()
            .map(|(id, name)| (id.as_str(), name.as_str()))
            .collect();
        let selection = Selection {
            subscription: SubscriptionId::new("sub"),
            node: NodeId::new("n1"),
        };
        let exits = vec![exit(
            "1",
            ExitTarget::Node {
                selection: selection.clone(),
                fallback: None,
            },
        )];
        let config = config(&nodes, exits);
        assert_eq!(matching_nodes(&config, "").len(), MAX_NODE_RESULTS);
        let found = matching_nodes(&config, " EXAMPLE 1");
        assert_eq!(found.len(), 11);
        assert_eq!(found[0].name, "Example 1");
        assert_eq!(found[0].exit, Some(&ExitId::new("1")));
        assert_eq!(found[1].exit, None);
        assert!(matching_nodes(&config, "missing").is_empty());
    }

    #[test]
    fn exit_without_a_matching_node_is_unresolved() {
        let exits = vec![
            exit("1", ExitTarget::Country(country("NL"))),
            exit("2", ExitTarget::Country(country("JP"))),
        ];
        let config = config(&[("a", "🇳🇱 One")], exits);
        assert_eq!(
            unresolved_exits(&config),
            BTreeSet::from([ExitId::new("2")])
        );
    }

    #[test]
    fn exit_now_names_the_node_the_fallback_or_the_gap() {
        let selection = |node: &str| Selection {
            subscription: SubscriptionId::new("sub"),
            node: NodeId::new(node),
        };
        let config = config(&[("a", "🇳🇱 One"), ("b", "🇳🇱 Two")], Vec::new());
        let node_exit = |node: &str, fallback: Option<CountryCode>| {
            exit(
                "1",
                ExitTarget::Node {
                    selection: selection(node),
                    fallback,
                },
            )
        };
        let present = node_exit("a", Some(country("NL")));
        assert_eq!(
            exit_now(&config, &present, Some(&selection("a"))),
            ExitNow::Node("🇳🇱 One")
        );
        let gone = node_exit("gone", Some(country("NL")));
        assert_eq!(
            exit_now(&config, &gone, Some(&selection("b"))),
            ExitNow::Fallback(&country("NL"))
        );
        let gone = node_exit("gone", None);
        assert_eq!(exit_now(&config, &gone, None), ExitNow::NodeGone);
        let nl = exit("2", ExitTarget::Country(country("NL")));
        assert_eq!(
            exit_now(&config, &nl, Some(&selection("b"))),
            ExitNow::Node("🇳🇱 Two")
        );
        let jp = exit("3", ExitTarget::Country(country("JP")));
        assert_eq!(
            exit_now(&config, &jp, None),
            ExitNow::NoCountryNodes(&country("JP"))
        );
    }
}
