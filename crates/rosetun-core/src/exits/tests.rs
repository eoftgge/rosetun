use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use rosetun_config::{
    DomainMatch, NodeId, Outbound, Rule, RuleId, RuleMatcher, RuleSet, RuleSetId, StreamSettings,
    SubscriptionId,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rosetun-exits-{}-{id}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn country(value: &str) -> CountryCode {
    CountryCode::parse(value).unwrap()
}

fn selection(subscription: &str, node: &str) -> Selection {
    Selection {
        subscription: SubscriptionId::new(subscription),
        node: NodeId::new(node),
    }
}

fn subscription(id: &str, nodes: &[(&str, &str)]) -> Subscription {
    Subscription {
        id: SubscriptionId::new(id),
        name: "Example subscription".into(),
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
        info: None,
        update_interval_hours: None,
        support_url: None,
        web_page_url: None,
        announce: None,
        notices: Vec::new(),
    }
}

fn exit(id: &str, target: ExitTarget) -> Exit {
    Exit {
        id: ExitId::new(id),
        name: "Example exit".into(),
        target,
    }
}

fn exit_rule(id: &str, exit: &ExitId, enabled: bool) -> Rule {
    Rule {
        id: RuleId::new(id),
        enabled,
        matcher: RuleMatcher::Domain(DomainMatch::Exact(format!("{id}.example.com"))),
        target: RuleTarget::Exit,
        exit: Some(exit.clone()),
    }
}

#[test]
fn creating_exits_reuses_target_and_remembers_node_country() {
    let directory = TestDirectory::new();
    let store = Store::at(directory.0.join("config.json"));
    store
        .modify(|config| {
            config.subscriptions = vec![subscription(
                "sub",
                &[("de", "Example 🇩🇪"), ("plain", "Unmarked")],
            )];
            Ok::<_, ExitError>(())
        })
        .unwrap();

    let german = exit_for_country(&store, country("DE"), "Germany").unwrap();
    assert_eq!(german.id, ExitId::new("1"));
    assert_eq!(
        exit_for_country(&store, country("DE"), "Other name").unwrap(),
        german
    );
    let node = exit_for_node(&store, &selection("sub", "de"), "Example 🇩🇪").unwrap();
    assert_eq!(node.id, ExitId::new("2"));
    assert_eq!(
        node.target,
        ExitTarget::Node {
            selection: selection("sub", "de"),
            fallback: Some(country("DE")),
        }
    );
    assert_eq!(
        exit_for_node(&store, &selection("sub", "de"), "New name").unwrap(),
        node
    );
    change_exit_target(
        &store,
        &node.id,
        ExitTarget::Node {
            selection: selection("sub", "de"),
            fallback: None,
        },
    )
    .unwrap();
    let reused = exit_for_node(&store, &selection("sub", "de"), "Again").unwrap();
    assert_eq!(reused.id, node.id);
    assert_eq!(
        reused.target,
        ExitTarget::Node {
            selection: selection("sub", "de"),
            fallback: None,
        }
    );
    let plain = exit_for_node(&store, &selection("sub", "plain"), "Plain").unwrap();
    assert_eq!(
        plain.target,
        ExitTarget::Node {
            selection: selection("sub", "plain"),
            fallback: None,
        }
    );
    assert_eq!(store.load().unwrap().exits.len(), 3);
    assert!(matches!(
        exit_for_node(&store, &selection("sub", "missing"), "Missing"),
        Err(ExitError::NodeNotFound)
    ));
    assert!(matches!(
        exit_for_country(&store, country("GB"), "   "),
        Err(ExitError::EmptyName)
    ));
}

#[test]
fn editing_and_deleting_exit_blocks_all_referencing_rules() {
    let directory = TestDirectory::new();
    let store = Store::at(directory.0.join("config.json"));
    let german = exit_for_country(&store, country("DE"), "Germany").unwrap();
    let british = exit_for_country(&store, country("GB"), "Britain").unwrap();
    store
        .modify(|config| {
            let mut first = RuleSet::new(RuleSetId::new("first"), "First", RuleTarget::Proxy);
            first.rules = vec![
                exit_rule("a", &german.id, true),
                exit_rule("b", &british.id, true),
            ];
            let mut second = RuleSet::new(RuleSetId::new("second"), "Second", RuleTarget::Direct);
            second.rules.push(exit_rule("c", &german.id, false));
            config.rule_sets = vec![first, second];
            Ok::<_, ExitError>(())
        })
        .unwrap();
    assert_eq!(exit_rule_count(&store.load().unwrap(), &german.id), 2);
    assert_eq!(exit_rule_count(&store.load().unwrap(), &british.id), 1);

    rename_exit(&store, &german.id, "  Berlin  ").unwrap();
    change_exit_target(&store, &german.id, ExitTarget::Country(country("FR"))).unwrap();
    assert_eq!(store.load().unwrap().exits[0].name, "Berlin");
    assert_eq!(
        store.load().unwrap().exits[0].target,
        ExitTarget::Country(country("FR"))
    );
    assert_eq!(delete_exit(&store, &german.id).unwrap(), 2);
    let config = store.load().unwrap();
    assert_eq!(exit_rule_count(&config, &german.id), 0);
    assert_eq!(config.rule_sets[0].rules[0].target, RuleTarget::Block);
    assert_eq!(config.rule_sets[1].rules[0].target, RuleTarget::Block);
    assert!(config.rule_sets[0].rules[0].exit.is_none());
    assert!(config.rule_sets[1].rules[0].exit.is_none());
    assert_eq!(config.rule_sets[0].rules[1].target, RuleTarget::Exit);
    assert_eq!(delete_exit(&store, &british.id).unwrap(), 1);
    assert!(matches!(
        delete_exit(&store, &german.id),
        Err(ExitError::NotFound)
    ));
}

#[test]
fn changing_rule_to_direct_clears_old_exit_reference() {
    let directory = TestDirectory::new();
    let store = Store::at(directory.0.join("config.json"));
    let german = exit_for_country(&store, country("DE"), "Germany").unwrap();
    store
        .modify(|config| {
            let mut set = RuleSet::new(RuleSetId::new("first"), "First", RuleTarget::Proxy);
            set.rules.push(exit_rule("a", &german.id, true));
            config.rule_sets.push(set);
            Ok::<_, ExitError>(())
        })
        .unwrap();
    crate::set_rule_target(
        &store,
        &RuleSetId::new("first"),
        &RuleId::new("a"),
        RuleTarget::Direct,
    )
    .unwrap();
    let config = store.load().unwrap();
    assert!(config.rule_sets[0].rules[0].exit.is_none());
    assert_eq!(exit_rule_count(&config, &german.id), 0);
}

#[test]
fn node_exit_prefers_exact_then_country_fallback_then_none() {
    let german = exit(
        "1",
        ExitTarget::Node {
            selection: selection("sub", "primary"),
            fallback: Some(country("DE")),
        },
    );
    let nodes = [subscription(
        "sub",
        &[("primary", "🇩🇪 primary"), ("fallback", "DE fallback")],
    )];
    let delays = [(selection("sub", "fallback"), Duration::from_millis(10))];
    assert_eq!(
        resolve_exits(std::slice::from_ref(&german), &nodes, &delays, &[])[0].1,
        Some(selection("sub", "primary"))
    );
    let fallback_only = [subscription("sub", &[("fallback", "DE fallback")])];
    assert_eq!(
        resolve_exits(std::slice::from_ref(&german), &fallback_only, &delays, &[])[0].1,
        Some(selection("sub", "fallback"))
    );
    let two_fallbacks = [subscription(
        "sub",
        &[("fallback", "DE fallback"), ("fast", "🇩🇪 fast")],
    )];
    let fast_delay = [(selection("sub", "fast"), Duration::from_millis(1))];
    let previous = [(german.id.clone(), selection("sub", "fallback"))];
    assert_eq!(
        resolve_exits(
            std::slice::from_ref(&german),
            &two_fallbacks,
            &fast_delay,
            &previous
        )[0]
        .1,
        Some(selection("sub", "fallback"))
    );
    assert_eq!(
        resolve_exits(std::slice::from_ref(&german), &nodes, &delays, &previous)[0].1,
        Some(selection("sub", "primary"))
    );
    assert_eq!(resolve_exits(&[german], &[], &delays, &[])[0].1, None);
}

#[test]
fn retargeted_node_overrides_previous_fallback_until_it_disappears() {
    let target = exit(
        "1",
        ExitTarget::Node {
            selection: selection("sub", "nl2"),
            fallback: Some(country("NL")),
        },
    );
    let previous = [(target.id.clone(), selection("sub", "nl1"))];
    let both = [subscription("sub", &[("nl1", "NL 1"), ("nl2", "NL 2")])];
    assert_eq!(
        resolve_exits(std::slice::from_ref(&target), &both, &[], &previous)[0].1,
        Some(selection("sub", "nl2"))
    );
    let only_old = [subscription("sub", &[("nl1", "NL 1")])];
    assert_eq!(
        resolve_exits(&[target], &only_old, &[], &previous)[0].1,
        Some(selection("sub", "nl1"))
    );
}

#[test]
fn country_exit_uses_delay_or_subscription_order_and_keeps_previous_node() {
    let german = exit("1", ExitTarget::Country(country("DE")));
    let nodes = [
        subscription("first", &[("first", "DE first"), ("other", "FR other")]),
        subscription("second", &[("fast", "🇩🇪 fast")]),
    ];
    let fast = selection("second", "fast");
    let first = selection("first", "first");
    assert_eq!(
        resolve_exits(std::slice::from_ref(&german), &nodes, &[], &[])[0].1,
        Some(first.clone())
    );
    let delays = [
        (first.clone(), Duration::from_millis(100)),
        (fast.clone(), Duration::from_millis(20)),
    ];
    assert_eq!(
        resolve_exits(std::slice::from_ref(&german), &nodes, &delays, &[])[0].1,
        Some(fast.clone())
    );
    assert_eq!(
        resolve_exits(std::slice::from_ref(&german), &nodes, &delays[1..], &[])[0].1,
        Some(fast.clone())
    );
    let previous = [(german.id.clone(), first.clone())];
    assert_eq!(
        resolve_exits(std::slice::from_ref(&german), &nodes, &delays, &previous)[0].1,
        Some(first)
    );
    let without_first = [subscription("second", &[("fast", "🇩🇪 fast")])];
    assert_eq!(
        resolve_exits(
            std::slice::from_ref(&german),
            &without_first,
            &delays,
            &previous
        )[0]
        .1,
        Some(fast.clone())
    );
    let wrong_country = [(german.id.clone(), selection("first", "other"))];
    assert_eq!(
        resolve_exits(&[german], &nodes, &delays, &wrong_country)[0].1,
        Some(fast)
    );
}
