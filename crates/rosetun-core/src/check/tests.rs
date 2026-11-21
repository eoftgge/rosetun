use rosetun_config::{
    ExitId, ListId, Node, NodeId, Outbound, Rule, RuleId, RuleSet, RuleSetId, RuleTarget,
    RuleTemplate, Selection, Settings, StreamSettings, SubscriptionId, TrojanParams,
};
use rosetun_ipc::ExtraNode;

use super::*;
use crate::explain::{ExplainedRoute, RuleSource};
use crate::{ListPayload, PayloadFormat};

fn rule(id: &str, matcher: RuleMatcher, target: RuleTarget) -> Rule {
    Rule {
        id: RuleId::new(id),
        enabled: true,
        matcher,
        target,
        exit: None,
    }
}

fn suffix(domain: &str) -> RuleMatcher {
    RuleMatcher::Domain(DomainMatch::Suffix(domain.into()))
}

fn list(id: &str) -> RuleMatcher {
    RuleMatcher::List {
        list: ListId::new(id),
        category: None,
    }
}

fn trojan(id: &str) -> Node {
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

fn request(rules: Vec<Rule>) -> ConnectRequest {
    let mut set = RuleSet::new(RuleSetId::new("set"), "Set", RuleTarget::Proxy);
    set.rules = rules;
    let (rule_set, rule_groups) = set.expand_groups();
    ConnectRequest {
        selection: Selection {
            subscription: SubscriptionId::new("example"),
            node: NodeId::new("node"),
        },
        node: trojan("node"),
        rule_set,
        extra_nodes: Vec::new(),
        temporary_rules: Vec::new(),
        lists: Vec::new(),
        settings: Settings::default(),
        rule_groups,
    }
}

fn with_exit(mut request: ConnectRequest, exit: &str) -> ConnectRequest {
    request.extra_nodes.push(ExtraNode {
        via: None,
        exit: ExitId::new(exit),
        selection: Selection {
            subscription: SubscriptionId::new("example"),
            node: NodeId::new("other"),
        },
        node: trojan("other"),
    });
    request
}

fn site(domain: &str) -> Subject {
    Subject::Site(domain.into())
}

fn address(ip: &str) -> Subject {
    Subject::Address(ip.parse().unwrap())
}

fn source(text: &str) -> ListPayload {
    ListPayload {
        format: PayloadFormat::Source,
        bytes: text.as_bytes().to_vec(),
    }
}

fn known_rule(answer: &Answer) -> (&RuleId, bool, &RuleSource, &ExplainedRoute) {
    let Answer::Known(Explanation::Routed {
        reason: Reason::Rule {
            id,
            temporary,
            source,
        },
        route,
    }) = answer
    else {
        panic!("a rule decides: {answer:?}");
    };
    (id, *temporary, source, route)
}

fn none() -> SessionLists {
    SessionLists::default()
}

#[test]
fn a_domain_rule_decides_for_that_site_only() {
    let request = request(vec![rule(
        "one",
        RuleMatcher::Domain(DomainMatch::Exact("example.com".into())),
        RuleTarget::Direct,
    )]);

    let answer = check(&request, &none(), &site("example.com"));
    let (id, temporary, _, route) = known_rule(&answer);
    assert_eq!(id.as_str(), "one");
    assert!(!temporary);
    assert_eq!(route, &ExplainedRoute::Direct);
    assert_eq!(
        check(&request, &none(), &site("www.example.com")),
        Answer::Known(Explanation::Routed {
            reason: Reason::Default,
            route: ExplainedRoute::Proxy
        })
    );
}

#[test]
fn a_suffix_rule_covers_subdomains() {
    let request = request(vec![rule("one", suffix("example.com"), RuleTarget::Direct)]);

    for name in ["example.com", "video.example.com"] {
        let answer = check(&request, &none(), &site(name));
        assert_eq!(known_rule(&answer).3, &ExplainedRoute::Direct, "{name}");
    }
    assert!(matches!(
        check(&request, &none(), &site("notexample.com")),
        Answer::Known(Explanation::Routed {
            reason: Reason::Default,
            ..
        })
    ));
}

#[test]
fn a_keyword_rule_matches_part_of_a_name() {
    let request = request(vec![rule(
        "one",
        RuleMatcher::Domain(DomainMatch::Keyword("exam".into())),
        RuleTarget::Block,
    )]);

    let answer = check(&request, &none(), &site("my-example.com"));

    assert_eq!(known_rule(&answer).3, &ExplainedRoute::Block);
}

#[test]
fn an_address_rule_matches_an_ip_in_its_block() {
    let request = request(vec![
        rule(
            "v4",
            RuleMatcher::IpCidr("192.0.2.0/24".into()),
            RuleTarget::Direct,
        ),
        rule(
            "v6",
            RuleMatcher::IpCidr("2001:db8::/32".into()),
            RuleTarget::Block,
        ),
    ]);

    let v4 = check(&request, &none(), &address("192.0.2.77"));
    let v6 = check(&request, &none(), &address("2001:db8::1"));

    assert_eq!(known_rule(&v4).0.as_str(), "v4");
    assert_eq!(known_rule(&v6).3, &ExplainedRoute::Block);
    assert!(matches!(
        check(&request, &none(), &address("198.51.100.1")),
        Answer::Known(Explanation::Routed {
            reason: Reason::Default,
            ..
        })
    ));
}

#[test]
fn a_program_is_found_by_name_and_by_path() {
    let request = request(vec![
        rule(
            "by-name",
            RuleMatcher::Process(ProcessMatch::Name("example.exe".into())),
            RuleTarget::Direct,
        ),
        rule(
            "by-path",
            RuleMatcher::Process(ProcessMatch::Path("/opt/other/tool".into())),
            RuleTarget::Block,
        ),
    ]);

    let name = check(
        &request,
        &none(),
        &Subject::ProgramName("example.exe".into()),
    );
    let path = check(
        &request,
        &none(),
        &Subject::ProgramPath("/opt/other/tool".into()),
    );
    let inside = check(
        &request,
        &none(),
        &Subject::ProgramPath("/opt/example.exe".into()),
    );

    assert_eq!(known_rule(&name).0.as_str(), "by-name");
    assert_eq!(known_rule(&path).0.as_str(), "by-path");
    assert_eq!(known_rule(&inside).0.as_str(), "by-name");
}

#[test]
fn a_list_rule_names_the_list() {
    let request = request(vec![rule("one", list("videos"), RuleTarget::Direct)]);
    let mut lists = SessionLists::default();
    lists.insert(
        &ListId::new("videos"),
        None,
        Some(&source(
            r#"{"version":2,"rules":[{"domain_suffix":["example.com"]}]}"#,
        )),
    );

    let answer = check(&request, &lists, &site("example.com"));

    let (_, _, source, route) = known_rule(&answer);
    assert!(matches!(source, RuleSource::List { list, .. } if list.as_str() == "videos"));
    assert_eq!(route, &ExplainedRoute::Direct);
}

#[test]
fn a_group_rule_names_the_group() {
    let request = request(vec![rule(
        "torrents",
        RuleTemplate::Torrents.to_group("Torrents"),
        RuleTarget::Direct,
    )]);

    // The preset lists each system's own program names.
    let name = if cfg!(windows) {
        "qbittorrent.exe"
    } else {
        "qbittorrent"
    };
    let answer = check(&request, &none(), &Subject::ProgramName(name.into()));

    assert!(matches!(
        answer,
        Answer::Known(Explanation::Routed {
            reason: Reason::Rule {
                source: RuleSource::Group { ref name, .. },
                ..
            },
            ..
        }) if name == "Torrents"
    ));
}

#[test]
fn an_exit_rule_names_its_exit() {
    let mut exit_rule = rule("one", suffix("example.com"), RuleTarget::Exit);
    exit_rule.exit = Some(ExitId::new("japan"));
    let request = with_exit(request(vec![exit_rule]), "japan");

    let answer = check(&request, &none(), &site("example.com"));

    assert_eq!(
        known_rule(&answer).3,
        &ExplainedRoute::Exit(ExitId::new("japan"))
    );
}

#[test]
fn a_temporary_rule_wins_over_the_permanent_ones() {
    let mut request = request(vec![rule("one", suffix("example.com"), RuleTarget::Direct)]);
    request.temporary_rules = vec![rule("one", suffix("example.com"), RuleTarget::Block)];

    let answer = check(&request, &none(), &site("example.com"));

    let (id, temporary, _, route) = known_rule(&answer);
    assert_eq!(id.as_str(), "one");
    assert!(temporary);
    assert_eq!(route, &ExplainedRoute::Block);
}

#[test]
fn a_disabled_rule_is_skipped() {
    let mut off = rule("off", suffix("example.com"), RuleTarget::Block);
    off.enabled = false;
    let request = request(vec![
        off,
        rule("on", suffix("example.com"), RuleTarget::Direct),
    ]);

    let answer = check(&request, &none(), &site("example.com"));

    assert_eq!(known_rule(&answer).0.as_str(), "on");
}

#[test]
fn without_a_matching_rule_the_default_decides() {
    let mut request = request(vec![rule("one", suffix("example.com"), RuleTarget::Block)]);
    request.rule_set.default_target = RuleTarget::Direct;

    assert_eq!(
        check(&request, &none(), &site("example.org")),
        Answer::Known(Explanation::Routed {
            reason: Reason::Default,
            route: ExplainedRoute::Direct
        })
    );
}

#[test]
fn an_unreadable_list_leaves_the_answer_unverifiable() {
    let request = request(vec![rule("one", list("uploaded"), RuleTarget::Direct)]);

    assert_eq!(
        check(&request, &none(), &site("example.com")),
        Answer::Known(Explanation::Unverifiable {
            rule: RuleId::new("one"),
            temporary: false
        })
    );
}

#[test]
fn a_private_address_depends_on_the_network_when_the_local_network_is_allowed() {
    let mut request = request(vec![rule("one", suffix("example.com"), RuleTarget::Block)]);
    request.settings.allow_lan = true;

    let answer = check(&request, &none(), &address("10.0.0.5"));

    assert_eq!(
        answer,
        Answer::Depends {
            on: Unknown::Network,
            otherwise: Explanation::Routed {
                reason: Reason::Default,
                route: ExplainedRoute::Proxy
            }
        }
    );
}

#[test]
fn a_private_address_is_certain_when_the_local_network_is_not_allowed() {
    let request = request(Vec::new());

    assert!(matches!(
        check(&request, &none(), &address("10.0.0.5")),
        Answer::Known(_)
    ));
}

#[test]
fn a_link_local_address_is_the_local_network_without_asking() {
    let mut request = request(Vec::new());
    request.settings.allow_lan = true;

    assert_eq!(
        check(&request, &none(), &address("169.254.1.1")),
        Answer::Known(Explanation::Routed {
            reason: Reason::LocalNetwork,
            route: ExplainedRoute::Direct
        })
    );
}

#[test]
fn a_program_name_depends_on_the_path_when_a_path_rule_comes_first() {
    let request = request(vec![
        rule(
            "path",
            RuleMatcher::Process(ProcessMatch::Path("/opt/example/tool".into())),
            RuleTarget::Block,
        ),
        rule(
            "name",
            RuleMatcher::Process(ProcessMatch::Name("tool".into())),
            RuleTarget::Direct,
        ),
    ]);

    let by_name = check(&request, &none(), &Subject::ProgramName("tool".into()));
    let by_path = check(
        &request,
        &none(),
        &Subject::ProgramPath("/opt/example/tool".into()),
    );

    assert!(matches!(
        by_name,
        Answer::Depends {
            on: Unknown::ProgramPath,
            ..
        }
    ));
    assert_eq!(known_rule(&by_path).0.as_str(), "path");
}

#[test]
fn a_path_rule_after_the_answer_does_not_make_it_uncertain() {
    let request = request(vec![
        rule(
            "name",
            RuleMatcher::Process(ProcessMatch::Name("tool".into())),
            RuleTarget::Direct,
        ),
        rule(
            "path",
            RuleMatcher::Process(ProcessMatch::Path("/opt/example/tool".into())),
            RuleTarget::Block,
        ),
    ]);

    let answer = check(&request, &none(), &Subject::ProgramName("tool".into()));

    assert_eq!(known_rule(&answer).0.as_str(), "name");
}

#[test]
fn a_site_depends_on_its_address_when_a_public_address_rule_comes_first() {
    let request = request(vec![
        rule(
            "address",
            RuleMatcher::IpCidr("198.51.100.0/24".into()),
            RuleTarget::Block,
        ),
        rule("site", suffix("example.com"), RuleTarget::Direct),
    ]);

    let answer = check(&request, &none(), &site("example.com"));

    assert_eq!(
        answer,
        Answer::Depends {
            on: Unknown::SiteAddress,
            otherwise: Explanation::Routed {
                reason: Reason::Rule {
                    id: RuleId::new("site"),
                    temporary: false,
                    source: RuleSource::Condition(suffix("example.com"))
                },
                route: ExplainedRoute::Direct
            }
        }
    );
}

#[test]
fn a_private_address_rule_does_not_make_a_site_uncertain() {
    let request = request(vec![
        rule(
            "home",
            RuleMatcher::IpCidr("192.168.0.0/16".into()),
            RuleTarget::Direct,
        ),
        rule("site", suffix("example.com"), RuleTarget::Block),
    ]);

    assert!(matches!(
        check(&request, &none(), &site("example.com")),
        Answer::Known(_)
    ));
}

#[test]
fn a_whole_internet_address_rule_makes_a_site_uncertain() {
    let request = request(vec![rule(
        "all",
        RuleMatcher::IpCidr("0.0.0.0/0".into()),
        RuleTarget::Direct,
    )]);

    assert!(matches!(
        check(&request, &none(), &site("example.com")),
        Answer::Depends {
            on: Unknown::SiteAddress,
            ..
        }
    ));
}

#[test]
fn an_address_in_a_list_makes_a_site_uncertain() {
    let request = request(vec![
        rule("one", list("networks"), RuleTarget::Block),
        rule("two", suffix("example.com"), RuleTarget::Direct),
    ]);
    let mut lists = SessionLists::default();
    lists.insert(
        &ListId::new("networks"),
        None,
        Some(&source(
            r#"{"version":2,"rules":[{"ip_cidr":["198.51.100.0/24"]}]}"#,
        )),
    );

    assert!(matches!(
        check(&request, &lists, &site("example.com")),
        Answer::Depends {
            on: Unknown::SiteAddress,
            ..
        }
    ));
}

#[test]
fn what_is_typed_becomes_a_site() {
    for (typed, expected) in [
        ("example.com", "example.com"),
        ("  Example.COM ", "example.com"),
        ("https://www.example.com/path?x=1#top", "www.example.com"),
        ("example.com:8443", "example.com"),
        ("example.com/video", "example.com"),
        ("user@example.com", "example.com"),
        ("*.example.com", "example.com"),
        ("example.com.", "example.com"),
        ("\"example.com\"", "example.com"),
        ("пример.рф", "xn--e1afmkfd.xn--p1ai"),
    ] {
        assert_eq!(Subject::parse(typed), Ok(site(expected)), "{typed}");
    }
}

#[test]
fn what_is_typed_becomes_an_address() {
    for (typed, expected) in [
        ("192.0.2.1", "192.0.2.1"),
        ("192.0.2.1:443", "192.0.2.1"),
        ("http://192.0.2.1/", "192.0.2.1"),
        ("2001:db8::1", "2001:db8::1"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("https://[2001:db8::1]/", "2001:db8::1"),
    ] {
        assert_eq!(Subject::parse(typed), Ok(address(expected)), "{typed}");
    }
}

#[test]
fn what_is_typed_becomes_a_program() {
    for (typed, expected) in [
        ("Example.EXE", Subject::ProgramName("Example.EXE".into())),
        ("tool", Subject::ProgramName("tool".into())),
        (
            "\"C:\\Program Files\\Example\\example.exe\"",
            Subject::ProgramPath("C:\\Program Files\\Example\\example.exe".into()),
        ),
        (
            "/usr/bin/example",
            Subject::ProgramPath("/usr/bin/example".into()),
        ),
    ] {
        assert_eq!(Subject::parse(typed), Ok(expected), "{typed}");
    }
}

#[test]
fn an_unknown_input_is_refused() {
    assert_eq!(Subject::parse(""), Err(InputError::Empty));
    assert_eq!(Subject::parse("   "), Err(InputError::Empty));
    for typed in [
        "two words.com",
        "exa*mple.com",
        "relative\\path.exe",
        "example.com:port",
        "[2001:db8::1",
        "http://",
        "ftp://",
        "192.0.2.0/24",
        "2001:db8::/32",
        "a<b>.com",
    ] {
        assert_eq!(
            Subject::parse(typed),
            Err(InputError::Unrecognised),
            "{typed}"
        );
    }
}

#[test]
fn nothing_typed_shows_in_debug_output() {
    let shown = format!(
        "{:?} {:?} {:?}",
        site("example.com"),
        address("192.0.2.1"),
        Subject::ProgramPath("/opt/secret/tool".into())
    );

    for hidden in ["example", "192", "secret"] {
        assert!(!shown.contains(hidden), "{shown}");
    }
}
