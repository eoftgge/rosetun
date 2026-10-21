use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rosetun_config::{
    ConnectionNetwork, Node, NodeId, Outbound, Rule, RuleSet, RuleSetId, Selection, Settings,
    StreamSettings, SubscriptionId, TrojanParams,
};

use super::*;
use crate::add_list_from_bytes;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rosetun-explain-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn store(&self) -> Store {
        Store::at(self.0.join("config.json"))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn rule(id: &str, matcher: RuleMatcher, target: RuleTarget) -> Rule {
    Rule {
        id: RuleId::new(id),
        enabled: true,
        matcher,
        target,
        exit: None,
    }
}

fn list(id: &str) -> RuleMatcher {
    RuleMatcher::List {
        list: ListId::new(id),
        category: None,
    }
}

fn request(rules: Vec<Rule>) -> ConnectRequest {
    let mut set = RuleSet::new(RuleSetId::new("set"), "Set", RuleTarget::Proxy);
    set.rules = rules;
    let (rule_set, rule_templates) = set.expand_templates();
    ConnectRequest {
        selection: Selection {
            subscription: SubscriptionId::new("example"),
            node: NodeId::new("node"),
        },
        node: Node {
            id: NodeId::new("node"),
            name: "Example node".into(),
            server: "203.0.113.10".into(),
            port: 443,
            outbound: Outbound::Trojan(TrojanParams {
                password: "test-secret".into(),
            }),
            stream: StreamSettings::default(),
            raw: None,
        },
        rule_set,
        extra_nodes: Vec::new(),
        temporary_rules: Vec::new(),
        lists: Vec::new(),
        settings: Settings::default(),
        rule_templates,
    }
}

fn site(domain: &str) -> Destination<'_> {
    Destination {
        domain: Some(domain),
        ip: Some("192.0.2.1".parse().unwrap()),
        process: None,
    }
}

fn source(text: &str) -> ListPayload {
    ListPayload {
        format: PayloadFormat::Source,
        bytes: text.as_bytes().to_vec(),
    }
}

fn connection(host: &str, ip: Option<&str>, route: ConnectionRoute) -> LiveConnection {
    LiveConnection {
        id: "id".into(),
        start_unix_ms: 1,
        end_unix_ms: None,
        process: None,
        host: host.into(),
        ip: ip.map(str::to_owned),
        port: 443,
        network: ConnectionNetwork::Tcp,
        route,
        download: 0,
        upload: 0,
    }
}

#[test]
fn a_template_rule_names_its_template_and_the_matched_condition() {
    let request = request(vec![rule(
        "torrents",
        RuleMatcher::Template(RuleTemplate::Torrents),
        RuleTarget::Direct,
    )]);
    let explanation = explain(
        &request,
        &SessionLists::default(),
        &Destination {
            domain: None,
            ip: None,
            process: Some(r"C:\Program Files\Example\QBITTORRENT.EXE"),
        },
    );

    assert_eq!(
        explanation,
        Explanation::Routed {
            reason: Reason::Rule {
                id: RuleId::new("torrents"),
                temporary: false,
                source: RuleSource::Template {
                    template: RuleTemplate::Torrents,
                    matcher: RuleMatcher::Process(ProcessMatch::Name("qbittorrent.exe".into())),
                },
            },
            route: ExplainedRoute::Direct,
        }
    );
}

#[test]
fn a_temporary_rule_comes_before_the_set_and_says_so() {
    let mut request = request(vec![rule(
        "set",
        RuleMatcher::Domain(DomainMatch::Suffix("example.com".into())),
        RuleTarget::Block,
    )]);
    request.temporary_rules.push(rule(
        "temporary",
        RuleMatcher::Domain(DomainMatch::Exact("example.com".into())),
        RuleTarget::Direct,
    ));

    let Explanation::Routed { reason, route } =
        explain(&request, &SessionLists::default(), &site("example.com"))
    else {
        panic!("routed");
    };
    assert_eq!(route, ExplainedRoute::Direct);
    assert!(matches!(reason, Reason::Rule { temporary: true, ref id, .. } if id.as_str() == "temporary"));

    let Explanation::Routed { reason, route } =
        explain(&request, &SessionLists::default(), &site("www.example.com"))
    else {
        panic!("routed");
    };
    assert_eq!(route, ExplainedRoute::Block);
    assert!(matches!(reason, Reason::Rule { temporary: false, .. }));
}

#[test]
fn an_unreadable_list_stops_the_answer_and_a_left_out_one_is_passed() {
    let request = request(vec![
        rule("left-out", list("left-out"), RuleTarget::Direct),
        rule("source", list("source"), RuleTarget::Direct),
        rule("binary", list("binary"), RuleTarget::Direct),
        rule("unknown", list("unknown"), RuleTarget::Direct),
    ]);
    let mut lists = SessionLists::default();
    lists.insert(&ListId::new("left-out"), None, None);
    lists.insert(
        &ListId::new("source"),
        None,
        Some(&source(
            r#"{"version":3,"rules":[{"domain_suffix":[".example.com"]},{"domain_regex":["^re[0-9]+\\.example\\.org$"]}]}"#,
        )),
    );
    lists.insert(
        &ListId::new("binary"),
        None,
        Some(&ListPayload {
            format: PayloadFormat::Binary,
            bytes: b"SRS".to_vec(),
        }),
    );
    lists.insert(
        &ListId::new("unknown"),
        None,
        Some(&source(r#"{"version":3,"rules":[{"port":["443"]}]}"#)),
    );

    for domain in ["www.example.com", "re42.example.org"] {
        assert!(
            matches!(
                explain(&request, &lists, &site(domain)),
                Explanation::Routed { reason: Reason::Rule { ref id, .. }, .. } if id.as_str() == "source"
            ),
            "{domain}"
        );
    }
    // A suffix with a leading dot matches subdomains only.
    assert_eq!(
        explain(&request, &lists, &site("example.com")),
        Explanation::Unverifiable {
            rule: RuleId::new("binary"),
            temporary: false,
        }
    );

    let without_binary = {
        let mut request = request.clone();
        request.rule_set.rules.retain(|rule| rule.id.as_str() != "binary");
        request
    };
    assert_eq!(
        explain(&without_binary, &lists, &site("example.com")),
        Explanation::Unverifiable {
            rule: RuleId::new("unknown"),
            temporary: false,
        }
    );
}

#[test]
fn rules_by_site_need_a_name_and_local_addresses_need_allow_lan() {
    let mut request = request(vec![rule(
        "site",
        RuleMatcher::Domain(DomainMatch::Keyword("example".into())),
        RuleTarget::Direct,
    )]);
    request.rule_set.default_target = RuleTarget::Block;
    let local = Destination {
        domain: None,
        ip: Some("127.0.0.1".parse().unwrap()),
        process: None,
    };

    assert_eq!(
        explain(&request, &SessionLists::default(), &local),
        Explanation::Routed {
            reason: Reason::Default,
            route: ExplainedRoute::Block,
        }
    );
    request.settings.allow_lan = true;
    assert_eq!(
        explain(&request, &SessionLists::default(), &local),
        Explanation::Routed {
            reason: Reason::LocalNetwork,
            route: ExplainedRoute::Direct,
        }
    );
}

#[test]
fn an_explanation_the_engine_contradicts_is_not_given() {
    let request = request(vec![rule(
        "site",
        RuleMatcher::IpCidr("198.51.100.0/24".into()),
        RuleTarget::Direct,
    )]);
    let lists = SessionLists::default();

    let agreed = connection("example.com", Some("198.51.100.7"), ConnectionRoute::Direct);
    assert!(matches!(
        explain_connection(&request, &lists, &agreed),
        Some(Explanation::Routed {
            route: ExplainedRoute::Direct,
            ..
        })
    ));
    let contradicted = connection("198.51.100.7", None, ConnectionRoute::Proxy);
    assert_eq!(explain_connection(&request, &lists, &contradicted), None);
    let other = connection("example.com", None, ConnectionRoute::Other);
    assert_eq!(explain_connection(&request, &lists, &other), None);
}

#[test]
fn session_lists_are_read_as_connecting_prepares_them() {
    let directory = TestDirectory::new();
    let store = directory.store();
    let added = add_list_from_bytes(&store, "Example", "example.txt", b"example.com\n").unwrap();
    let mut request = request(vec![
        rule(
            "list",
            RuleMatcher::List {
                list: added.id.clone(),
                category: None,
            },
            RuleTarget::Direct,
        ),
        rule("missing", list("missing"), RuleTarget::Direct),
    ]);
    request.rule_set.rules.reverse();
    let lists = read_session_lists(&store, &request).unwrap();

    assert!(!format!("{lists:?}").contains("example.com"));
    assert_eq!(
        explain(&request, &lists, &site("www.example.com")),
        Explanation::Unverifiable {
            rule: RuleId::new("missing"),
            temporary: false,
        }
    );
    request.rule_set.rules.remove(0);
    assert!(matches!(
        explain(&request, &lists, &site("www.example.com")),
        Explanation::Routed {
            route: ExplainedRoute::Direct,
            ..
        }
    ));
}
