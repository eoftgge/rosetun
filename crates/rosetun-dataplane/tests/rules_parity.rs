//! Parity tests asserting that `rosetun_dataplane::rules::RuleEngine` agrees
//! with `rosetun_core::explain::explain` across rule matchers, ordering,
//! temporary rules, exits, source lists, LAN/private flags, and defaults.

use std::io;
use std::net::IpAddr;
use std::path::PathBuf;

use rosetun_config::{
    DomainMatch, ExitId, ListId, Node, NodeId, Outbound, ProcessMatch, Rule, RuleId, RuleMatcher,
    RuleSet, RuleSetId, RuleTarget, Selection, Settings, StreamSettings, SubscriptionId,
    TrojanParams, list_tag,
};
use rosetun_core::{
    Destination, ExplainedRoute, Explanation, ListPayload, PayloadFormat, Reason as CoreReason,
    SessionLists, explain,
};
use rosetun_dataplane::net::Resolve;
use rosetun_dataplane::rules::{
    Decision, Flow, ListContent, ListInput, Reason, Route, RuleEngine, RulePlan,
};
use rosetun_ipc::{ConnectRequest, ExtraNode};

type Probe<'a> = (&'a str, Option<&'a str>, Option<&'a str>, Option<&'a str>);

struct FailingResolver;

impl Resolve for FailingResolver {
    fn resolve(&self, _name: &str) -> io::Result<Vec<IpAddr>> {
        Err(io::Error::new(io::ErrorKind::NotFound, "unused"))
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

fn exit_rule(id: &str, matcher: RuleMatcher, exit: &str) -> Rule {
    Rule {
        id: RuleId::new(id),
        enabled: true,
        matcher,
        target: RuleTarget::Exit,
        exit: Some(ExitId::new(exit)),
    }
}

fn sample_node(id: &str) -> Node {
    Node {
        id: NodeId::new(id),
        name: "Example node".into(),
        server: "203.0.113.10".into(),
        port: 443,
        outbound: Outbound::Trojan(TrojanParams {
            password: "test-secret".into(),
        }),
        stream: StreamSettings::default(),
        raw: None,
    }
}

fn sample_extra(exit: &str) -> ExtraNode {
    ExtraNode {
        via: None,
        exit: ExitId::new(exit),
        selection: Selection {
            subscription: SubscriptionId::new("example"),
            node: NodeId::new(exit),
        },
        node: sample_node(exit),
    }
}

fn build_request(
    set_rules: Vec<Rule>,
    temporary_rules: Vec<Rule>,
    default_target: RuleTarget,
    extra_nodes: Vec<ExtraNode>,
    allow_lan: bool,
    private_networks: bool,
) -> ConnectRequest {
    let mut set = RuleSet::new(RuleSetId::new("set"), "Set", default_target);
    set.rules = set_rules;
    let (rule_set, rule_groups) = set.expand_groups();
    let settings = Settings {
        allow_lan,
        private_networks,
        ..Settings::default()
    };
    ConnectRequest {
        selection: Selection {
            subscription: SubscriptionId::new("example"),
            node: NodeId::new("node"),
        },
        node: sample_node("node"),
        rule_set,
        extra_nodes,
        temporary_rules,
        lists: Vec::new(),
        settings,
        rule_groups,
    }
}

fn plan_from_request(request: &ConnectRequest, lists: Vec<ListInput>) -> RulePlan {
    RulePlan {
        rules: request.effective_rule_set(),
        temporary_count: request.temporary_rules.len(),
        allow_lan: request.settings.allow_lan,
        lan_segment: Vec::new(),
        lan_servers: Vec::new(),
        private_networks: request.settings.private_networks,
        exits: request
            .extra_nodes
            .iter()
            .map(|extra| extra.exit.clone())
            .collect(),
        lists,
    }
}

fn assert_agrees(decision: &Decision, explanation: &Explanation, label: &str) {
    let Explanation::Routed { reason, route } = explanation else {
        panic!("expected Routed for {label}, got {explanation:?}");
    };
    let expected_route = match route {
        ExplainedRoute::Proxy => Route::Proxy,
        ExplainedRoute::Direct => Route::Direct,
        ExplainedRoute::Block => Route::Block,
        ExplainedRoute::Exit(exit) => Route::Exit(exit.clone()),
    };
    let expected_reason = match reason {
        CoreReason::Rule { id, temporary, .. } => Reason::Rule {
            id: id.clone(),
            temporary: *temporary,
        },
        CoreReason::LocalNetwork => Reason::LocalNetwork,
        CoreReason::PrivateNetwork => Reason::PrivateNetwork,
        CoreReason::Default => Reason::Default,
    };
    assert_eq!(decision.route, expected_route, "route mismatch for {label}");
    assert_eq!(
        decision.reason, expected_reason,
        "reason mismatch for {label}"
    );
}

#[test]
fn rule_engine_matches_core_explain_across_full_rule_and_destination_table() {
    let source_list_id = ListId::new("source-list");
    let left_out_id = ListId::new("left-out");
    let source_bytes = br#"{
        "version": 3,
        "rules": [
            {
                "domain": ["listed.example.com"],
                "domain_suffix": [".listed-sub.example.org", "listed-root.example.net"],
                "domain_keyword": ["listedkw"],
                "domain_regex": ["^rx[0-9]+\\.example\\.invalid$"],
                "ip_cidr": ["203.0.113.0/25", "2001:db8:cafe::/48"]
            },
            {
                "domain_suffix": ["proc-gated.invalid"],
                "process_name": ["tool.exe"],
                "process_path": ["/opt/tools/tool.exe"]
            }
        ]
    }"#;

    let set_rules = vec![
        Rule {
            id: RuleId::new("disabled-exact"),
            enabled: false,
            matcher: RuleMatcher::Domain(DomainMatch::Exact("exact.example.com".into())),
            target: RuleTarget::Block,
            exit: None,
        },
        exit_rule(
            "exit-absent",
            RuleMatcher::Domain(DomainMatch::Exact("exit-target.example.com".into())),
            "missing-exit",
        ),
        exit_rule(
            "exit-present",
            RuleMatcher::Domain(DomainMatch::Exact("exit-target.example.com".into())),
            "second-hop",
        ),
        rule(
            "left-out-list",
            RuleMatcher::List {
                list: left_out_id.clone(),
                category: None,
            },
            RuleTarget::Block,
        ),
        rule(
            "exact",
            RuleMatcher::Domain(DomainMatch::Exact("exact.example.com".into())),
            RuleTarget::Direct,
        ),
        rule(
            "dot-suffix",
            RuleMatcher::Domain(DomainMatch::Suffix(".subonly.example.org".into())),
            RuleTarget::Block,
        ),
        rule(
            "plain-suffix",
            RuleMatcher::Domain(DomainMatch::Suffix("suffix.example.org".into())),
            RuleTarget::Direct,
        ),
        rule(
            "keyword",
            RuleMatcher::Domain(DomainMatch::Keyword("kw-match".into())),
            RuleTarget::Block,
        ),
        rule(
            "proc-name",
            RuleMatcher::Process(ProcessMatch::Name(if cfg!(windows) {
                "browser.exe".into()
            } else {
                "browser".into()
            })),
            RuleTarget::Direct,
        ),
        rule(
            "proc-path",
            RuleMatcher::Process(ProcessMatch::Path(PathBuf::from(
                "/usr/local/bin/exact-app",
            ))),
            RuleTarget::Block,
        ),
        rule(
            "cidr-v4",
            RuleMatcher::IpCidr("192.0.2.5/24".into()),
            RuleTarget::Direct,
        ),
        rule(
            "cidr-v6",
            RuleMatcher::IpCidr("2001:db8:1::/48".into()),
            RuleTarget::Block,
        ),
        rule(
            "source-list",
            RuleMatcher::List {
                list: source_list_id.clone(),
                category: None,
            },
            RuleTarget::Direct,
        ),
    ];

    let temporary_rules = vec![
        Rule {
            id: RuleId::new("temp-disabled"),
            enabled: false,
            matcher: RuleMatcher::Domain(DomainMatch::Exact("exact.example.com".into())),
            target: RuleTarget::Block,
            exit: None,
        },
        rule(
            "temp-override",
            RuleMatcher::Domain(DomainMatch::Exact("temp.suffix.example.org".into())),
            RuleTarget::Block,
        ),
    ];

    let mut session_lists = SessionLists::default();
    session_lists.insert(&left_out_id, None, None);
    session_lists.insert(
        &source_list_id,
        None,
        Some(&ListPayload {
            format: PayloadFormat::Source,
            bytes: source_bytes.to_vec(),
        }),
    );

    let list_inputs = vec![ListInput {
        tag: list_tag(&source_list_id, None),
        content: ListContent::Source(source_bytes.to_vec()),
    }];

    let destinations: &[Probe<'_>] = &[
        ("temp override", Some("TEMP.SUFFIX.EXAMPLE.ORG"), None, None),
        ("exact uppercase", Some("EXACT.EXAMPLE.COM"), None, None),
        ("exit present", Some("exit-target.example.com"), None, None),
        ("dot-suffix sub", Some("a.subonly.example.org"), None, None),
        ("dot-suffix root", Some("subonly.example.org"), None, None),
        ("plain-suffix root", Some("suffix.example.org"), None, None),
        (
            "plain-suffix sub",
            Some("a.b.suffix.example.org"),
            None,
            None,
        ),
        (
            "plain-suffix nonboundary",
            Some("notsuffix.example.org"),
            None,
            None,
        ),
        ("keyword", Some("my-kw-match.invalid"), None, None),
        (
            "process name",
            None,
            None,
            Some(if cfg!(windows) {
                r"C:\Program Files\Example\BROWSER.EXE"
            } else {
                "/usr/bin/browser"
            }),
        ),
        ("process path", None, None, Some("/usr/local/bin/exact-app")),
        ("cidr v4", None, Some("192.0.2.200"), None),
        ("cidr v6", None, Some("2001:db8:1::99"), None),
        ("list exact", Some("listed.example.com"), None, None),
        (
            "list dot-suffix sub",
            Some("a.listed-sub.example.org"),
            None,
            None,
        ),
        (
            "list dot-suffix root",
            Some("listed-sub.example.org"),
            None,
            None,
        ),
        (
            "list plain suffix",
            Some("listed-root.example.net"),
            None,
            None,
        ),
        ("list keyword", Some("foo-listedkw-bar.invalid"), None, None),
        ("list regex", Some("rx42.example.invalid"), None, None),
        ("list cidr v4", None, Some("203.0.113.10"), None),
        ("list cidr v6", None, Some("2001:db8:cafe::1"), None),
        (
            "list process ok",
            Some("a.proc-gated.invalid"),
            None,
            Some("/opt/tools/tool.exe"),
        ),
        (
            "list process wrong path",
            Some("a.proc-gated.invalid"),
            None,
            Some("/usr/bin/tool.exe"),
        ),
        (
            "link-local v4",
            Some("exact.example.com"),
            Some("169.254.1.2"),
            None,
        ),
        ("link-local multicast", None, Some("224.0.0.251"), None),
        ("link-local v6", None, Some("fe80::1"), None),
        ("private rfc1918", None, Some("192.168.1.5"), None),
        ("private loopback", None, Some("127.0.0.1"), None),
        ("private ula", None, Some("fc00::5"), None),
        (
            "unmatched public",
            Some("unmatched.example.invalid"),
            Some("198.51.100.7"),
            None,
        ),
    ];

    for (allow_lan, private_networks) in [(false, false), (true, false), (true, true)] {
        for default_target in [
            RuleTarget::Proxy,
            RuleTarget::Direct,
            RuleTarget::Block,
            RuleTarget::Exit,
        ] {
            let request = build_request(
                set_rules.clone(),
                temporary_rules.clone(),
                default_target,
                vec![sample_extra("second-hop")],
                allow_lan,
                private_networks,
            );
            let engine =
                RuleEngine::compile(&plan_from_request(&request, list_inputs.clone())).unwrap();

            for &(label, domain, ip_text, process) in destinations {
                let ip = ip_text.map(|text| text.parse::<IpAddr>().unwrap());
                let core = explain(
                    &request,
                    &session_lists,
                    &Destination {
                        domain,
                        ip,
                        process,
                    },
                );
                let actual = engine.decide(
                    &Flow {
                        domain,
                        ip,
                        process,
                    },
                    &FailingResolver,
                );
                assert_agrees(
                    &actual,
                    &core,
                    &format!(
                        "{label} (allow_lan={allow_lan}, private={private_networks}, default={default_target:?})"
                    ),
                );
            }
        }
    }
}

#[test]
fn unexpanded_group_matcher_is_skipped_like_core_explain() {
    let mut set = RuleSet::new(RuleSetId::new("set"), "Set", RuleTarget::Proxy);
    set.rules = vec![
        rule(
            "group",
            RuleMatcher::Group {
                name: "Example".into(),
                items: vec![RuleMatcher::Domain(DomainMatch::Exact(
                    "example.com".into(),
                ))],
            },
            RuleTarget::Block,
        ),
        rule(
            "fallback",
            RuleMatcher::Domain(DomainMatch::Exact("example.com".into())),
            RuleTarget::Direct,
        ),
    ];
    let mut request = build_request(vec![], vec![], RuleTarget::Proxy, vec![], false, false);
    request.rule_set = set;

    let engine = RuleEngine::compile(&plan_from_request(&request, vec![])).unwrap();
    let dest = Destination {
        domain: Some("example.com"),
        ip: None,
        process: None,
    };
    let core = explain(&request, &SessionLists::default(), &dest);
    let actual = engine.decide(
        &Flow {
            domain: dest.domain,
            ip: dest.ip,
            process: dest.process,
        },
        &FailingResolver,
    );
    assert_agrees(&actual, &core, "unexpanded group");
}
