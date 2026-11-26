use rosetun_config::{Exit, ExitTarget, List, ListFormat, ListSource};
use rosetun_core::{ListPayload, PayloadFormat};

use super::*;

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

/// The Rules tab on the set in use, holding exactly these rules.
fn checking(rules: Vec<Rule>) -> State {
    let mut state = state_with_rules();
    state.config.rule_sets[1].rules = rules;
    state.act(Action::OpenRules);
    state
}

fn head(input: &str, route: String) -> String {
    tr!("rule-check-head", input = input.to_owned(), route = route)
}

fn list_state() -> State {
    let mut state = checking(vec![rule(
        "videos",
        RuleMatcher::List {
            list: ListId::new("videos"),
            category: None,
        },
        RuleTarget::Direct,
    )]);
    state.config.lists.push(List {
        id: ListId::new("videos"),
        name: "Videos".into(),
        source: ListSource::File {
            original_name: "videos.json".into(),
        },
        format: ListFormat::SingBoxSource,
        auto_update: true,
        updated_at: Some(100),
        size: Some(12),
        sha256: Some("a".repeat(64)),
        categories: Vec::new(),
    });
    state
}

fn videos_payload() -> ListPayload {
    ListPayload {
        format: PayloadFormat::Source,
        bytes: br#"{"version":2,"rules":[{"domain_suffix":["example.com"]}]}"#.to_vec(),
    }
}

#[test]
fn an_empty_field_has_no_line() {
    let mut state = checking(Vec::new());

    assert_eq!(state.rule_check(), None);
    state.rules.screen.filter.search = "   ".into();
    assert_eq!(state.rule_check(), None);
    assert!(state.take_check_lists().is_none());
}

#[test]
fn a_site_is_answered_with_the_rule_that_routes_it() {
    let mut state = checking(vec![
        rule("first", suffix("example.org"), RuleTarget::Block),
        rule("second", suffix("example.com"), RuleTarget::Direct),
    ]);
    state.rules.screen.filter.search = "https://www.example.com:8443/watch".into();

    let line = state.rule_check().unwrap();

    assert_eq!(
        line.text,
        tr!(
            "rule-check-lead",
            head = head("www.example.com", tr!("direct"))
        )
    );
    assert_eq!(
        line.rule,
        Some((
            tr!("rule-check-number", number = "2".to_owned()),
            RuleId::new("second")
        ))
    );
    assert!(line.answer);
}

#[test]
fn no_matching_rule_is_the_default_rule() {
    let mut state = checking(vec![rule("one", suffix("example.org"), RuleTarget::Block)]);
    state.rules.screen.filter.search = "example.com".into();

    let line = state.rule_check().unwrap();

    assert_eq!(
        line.text,
        tr!(
            "rule-check-plain",
            head = head("example.com", tr!("proxy")),
            why = tr!("rule-check-default")
        )
    );
    assert_eq!(line.rule, None);
}

#[test]
fn the_answer_follows_an_edit_of_the_rules() {
    let mut state = checking(vec![rule("one", suffix("example.com"), RuleTarget::Direct)]);
    state.rules.screen.filter.search = "example.com".into();
    let direct = state.rule_check().unwrap();

    state.config.rule_sets[1].rules[0].target = RuleTarget::Block;
    let blocked = state.rule_check().unwrap();
    state.config.rule_sets[1].rules.clear();
    let removed = state.rule_check().unwrap();
    state.config.rule_sets[1]
        .rules
        .push(rule("one", suffix("example.com"), RuleTarget::Direct));

    assert!(direct.text.contains(&tr!("direct")));
    assert!(blocked.text.contains(&tr!("block")));
    assert!(removed.text.contains(&tr!("rule-check-default")));
    assert_eq!(state.rule_check().unwrap(), direct);
}

#[test]
fn a_disabled_rule_is_passed_over() {
    let mut off = rule("off", suffix("example.com"), RuleTarget::Block);
    off.enabled = false;
    let mut state = checking(vec![off]);
    state.rules.screen.filter.search = "example.com".into();

    assert!(
        state
            .rule_check()
            .unwrap()
            .text
            .contains(&tr!("rule-check-default"))
    );
}

#[test]
fn a_temporary_rule_stands_above_the_saved_ones() {
    let mut state = checking(vec![rule("one", suffix("example.com"), RuleTarget::Direct)]);
    state.session.temporary_rules = vec![rule("temp", suffix("example.com"), RuleTarget::Block)];
    state.rules.screen.filter.search = "example.com".into();

    let line = state.rule_check().unwrap();

    assert_eq!(
        line.text,
        tr!(
            "rule-check-plain",
            head = head("example.com", tr!("block")),
            why = tr!("rule-check-temporary")
        )
    );
    assert_eq!(line.rule, None);
}

#[test]
fn an_exit_is_named() {
    let mut state = checking(Vec::new());
    let selection = Selection {
        subscription: SubscriptionId::new("1"),
        node: NodeId::new("node"),
    };
    state.config.subscriptions.push(subscription("1"));
    state.config.subscriptions[0].nodes.push(Node {
        id: NodeId::new("node"),
        name: "Test".into(),
        server: "203.0.113.5".into(),
        port: 443,
        outbound: Outbound::Vless(VlessParams {
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            flow: None,
        }),
        stream: Default::default(),
        raw: None,
    });
    state.config.exits.push(Exit {
        id: ExitId::new("japan"),
        name: "Japan".into(),
        target: ExitTarget::Node {
            selection,
            fallback: None,
        },
        via: None,
    });
    let mut exit_rule = rule("one", suffix("example.com"), RuleTarget::Exit);
    exit_rule.exit = Some(ExitId::new("japan"));
    state.config.rule_sets[1].rules = vec![exit_rule];
    state.rules.screen.filter.search = "example.com".into();

    let line = state.rule_check().unwrap();

    assert_eq!(
        line.text,
        tr!(
            "rule-check-lead",
            head = head("example.com", "Japan".into())
        )
    );
}

#[test]
fn a_program_is_answered_by_name_and_a_path_rule_is_an_open_question() {
    let mut state = checking(vec![
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
    state.rules.screen.filter.search = "tool".into();

    let by_name = state.rule_check().unwrap();
    state.rules.screen.filter.search = "/opt/example/tool".into();
    let by_path = state.rule_check().unwrap();

    assert_eq!(
        by_name.text,
        tr!("rule-check-depends-path", input = "tool".to_owned())
    );
    assert!(by_name.hint.is_some());
    assert!(!by_name.answer);
    assert_eq!(by_path.rule.unwrap().1, RuleId::new("path"));
}

#[test]
fn a_private_address_depends_on_the_network_only_when_it_is_allowed() {
    let mut state = checking(Vec::new());
    state.rules.screen.filter.search = "192.0.2.1".into();
    state.config.settings.allow_lan = true;
    let public = state.rule_check().unwrap();
    state.rules.screen.filter.search = "192.168.1.10".into();
    let on = state.rule_check().unwrap();
    state.config.settings.allow_lan = false;
    let off = state.rule_check().unwrap();

    assert!(public.answer);
    assert!(off.answer);
    assert_eq!(
        on.text,
        tr!(
            "rule-check-depends-network",
            input = "192.168.1.10".to_owned()
        )
    );
    assert!(on.hint.is_some());
}

#[test]
fn plain_search_text_and_unmatched_bare_words_stay_quiet() {
    let mut state = checking(vec![rule(
        "exe",
        RuleMatcher::Process(ProcessMatch::Name("tool.exe".into())),
        RuleTarget::Direct,
    )]);
    for query in ["two words.com", "mydeaf", "российские"] {
        state.rules.screen.filter.search = query.into();
        assert_eq!(state.rule_check(), None, "query: {query}");
        assert!(state.take_check_lists().is_none(), "query: {query}");
    }

    // Explicit `.exe` still answers even when it hits the default rule.
    state.rules.screen.filter.search = "discord.exe".into();
    let exe = state.rule_check().unwrap();
    assert!(exe.answer);
    assert!(exe.text.contains(&tr!("rule-check-default")));
}

#[test]
fn the_check_waits_for_the_set_in_use() {
    let mut state = checking(vec![rule("one", suffix("example.com"), RuleTarget::Direct)]);
    state.rules.screen.filter.search = "example.com".into();
    assert!(state.rule_check_available());

    state.act(Action::ChooseRuleSet(RuleSetId::new("1")));

    assert!(!state.rule_check_available());
    assert_eq!(
        state.rule_check().unwrap().text,
        tr!("rule-check-other-set")
    );
    assert!(state.take_check_lists().is_none());

    state.rules.screen.filter.search = "mydeaf".into();
    assert_eq!(state.rule_check(), None);
}

#[test]
fn lists_are_read_once_and_again_when_they_change() {
    let mut state = list_state();
    state.rules.screen.filter.search = "example.com".into();

    assert_eq!(state.rule_check().unwrap().text, tr!("rule-check-checking"));
    let Some(Job::CheckLists { request, .. }) = state.take_check_lists() else {
        panic!("the list is to be read");
    };
    assert!(state.take_check_lists().is_none());
    let mut lists = rosetun_core::SessionLists::default();
    lists.insert(&ListId::new("videos"), None, Some(&videos_payload()));
    state.reduce(WorkerEvent::CheckLists {
        request,
        result: Ok(lists),
    });

    let line = state.rule_check().unwrap();
    assert_eq!(
        line.text,
        tr!(
            "rule-check-lead-basis",
            head = head("example.com", tr!("direct")),
            basis = tr!("rule-check-list", list = "Videos".to_owned())
        )
    );
    assert!(state.take_check_lists().is_none());

    state.config.lists[0].sha256 = Some("b".repeat(64));
    assert!(matches!(
        state.take_check_lists(),
        Some(Job::CheckLists { .. })
    ));
    assert_eq!(state.rule_check().unwrap().text, tr!("rule-check-checking"));
}

#[test]
fn a_stale_read_does_not_replace_a_newer_one() {
    let mut state = list_state();
    state.rules.screen.filter.search = "example.com".into();
    let Some(Job::CheckLists { request: old, .. }) = state.take_check_lists() else {
        panic!("the list is to be read");
    };
    state.config.lists[0].sha256 = Some("b".repeat(64));
    let Some(Job::CheckLists { request: new, .. }) = state.take_check_lists() else {
        panic!("the list is to be read again");
    };

    state.reduce(WorkerEvent::CheckLists {
        request: old,
        result: Ok(rosetun_core::SessionLists::default()),
    });

    assert_ne!(old, new);
    assert_eq!(state.rule_check().unwrap().text, tr!("rule-check-checking"));
}

#[test]
fn a_list_that_cannot_be_read_leaves_the_answer_unknown() {
    let mut state = list_state();
    state.rules.screen.filter.search = "example.com".into();
    let Some(Job::CheckLists { request, .. }) = state.take_check_lists() else {
        panic!("the list is to be read");
    };

    state.reduce(WorkerEvent::CheckLists {
        request,
        result: Err(StoreError::NoConfigDir),
    });

    let line = state.rule_check().unwrap();
    assert_eq!(
        line.text,
        tr!("rule-check-unknown", input = "example.com".to_owned())
    );
    assert_eq!(line.hint, Some(tr!("connections-why-unknown-list")));
}

#[test]
fn showing_a_checked_rule_clears_the_filters_and_selects_it() {
    let mut state = checking(vec![
        rule("first", suffix("example.org"), RuleTarget::Block),
        rule("second", suffix("example.com"), RuleTarget::Direct),
    ]);
    state.rules.screen.filter.search = "org".into();

    state.act(Action::ShowCheckedRule(RuleId::new("second")));

    assert_eq!(state.rules.screen.filter.search, "");
    assert_eq!(
        state.rules.screen.selected_rules,
        [RuleId::new("second")].into()
    );
    assert!(state.rules.screen.reveal_selection);
}

#[test]
fn a_rule_that_is_not_in_the_set_is_not_shown() {
    let mut state = checking(Vec::new());

    state.act(Action::ShowCheckedRule(RuleId::new("gone")));

    assert!(state.rules.screen.selected_rules.is_empty());
    assert!(!state.rules.screen.reveal_selection);
}
