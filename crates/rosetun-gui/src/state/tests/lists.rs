use std::path::PathBuf;

use rosetun_config::{List, ListFormat, ListSource};
use rosetun_core::ListError;

use super::*;

fn list(id: &str, source: ListSource) -> List {
    List {
        id: ListId::new(id),
        name: "Example".into(),
        source,
        format: ListFormat::Text,
        updated_at: Some(100),
        size: Some(12),
        sha256: Some("a".repeat(64)),
        categories: Vec::new(),
    }
}

#[test]
fn adding_url_list_keeps_detection_result_in_dialog() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    state.act(Action::OpenAddList);
    let dialog = state.lists.add.as_mut().unwrap();
    dialog.update_url("https://example.com/lists/sites.txt?token=private".into());
    assert_eq!(dialog.name, "sites");
    assert!(matches!(
        state.act(Action::SubmitAddList),
        Some(Job::AddListUrl(url, name)) if url.ends_with("token=private") && name == "sites"
    ));
    let added = list("1", ListSource::Url("https://example.com/sites.txt".into()));
    state.reduce(WorkerEvent::AddList(Ok((added.clone(), Some(56)))));
    assert_eq!(
        state.lists.add.as_ref().unwrap().result,
        Some((ListFormat::Text, 0, Some(56)))
    );
    let mut config = state.config.clone();
    config.lists.push(added);
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config,
    });
    assert_eq!(state.config.lists.len(), 1);
    assert!(state.lists.add.is_some());
}

#[test]
fn list_urls_are_redacted_from_visible_text() {
    let mut state = State::default();
    let url = "https://user:secret@example.com/private?token=private";
    state
        .config
        .lists
        .push(list("1", ListSource::Url(url.into())));
    assert_eq!(state.text(url), "example.com");
    assert!(!state.text(&format!("Failed: {url}")).contains("private"));
}

#[test]
fn adding_file_list_uses_only_a_transient_path() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    state.act(Action::OpenAddList);
    assert!(matches!(
        state.act(Action::BrowseListFile),
        Some(Job::BrowseListFile)
    ));
    state.reduce(WorkerEvent::BrowsedListFile(Some(PathBuf::from(
        "C:/lists/example.srs",
    ))));
    let dialog = state.lists.add.as_ref().unwrap();
    assert_eq!(dialog.name, "example");
    assert_eq!(dialog.url, "");
    assert!(matches!(
        state.act(Action::SubmitAddList),
        Some(Job::AddListFile(path, name)) if path == PathBuf::from("C:/lists/example.srs") && name == "example"
    ));
    let added = list(
        "1",
        ListSource::File {
            original_name: "example.srs".into(),
        },
    );
    state.reduce(WorkerEvent::AddList(Ok((added.clone(), None))));
    let mut config = state.config.clone();
    config.lists.push(added);
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config,
    });
    assert!(matches!(
        &state.config.lists[0].source,
        ListSource::File { original_name } if original_name == "example.srs"
    ));
}

#[test]
fn used_list_cannot_be_removed_and_switching_tabs_preserves_rule_selection() {
    let mut state = state_with_rules();
    let list = list("1", ListSource::Url("https://example.com/rules.txt".into()));
    state.config.lists.push(list.clone());
    state.config.rule_sets[1].rules[0].matcher = RuleMatcher::List {
        list: list.id.clone(),
        category: None,
    };
    state.act(Action::OpenRules);
    let selected = state.rules.screen.selected_set.clone();
    state.act(Action::SelectRule {
        rule: state.config.rule_sets[1].rules[0].id.clone(),
        additive: false,
        range: false,
    });
    let rule_selection = state.rules.screen.selected_rules.clone();
    state.act(Action::ShowLists);
    assert_eq!(state.lists.tab, RulesTab::Lists);
    state.act(Action::ShowRuleSets);
    assert_eq!(state.rules.screen.selected_set, selected);
    assert_eq!(state.rules.screen.selected_rules, rule_selection);
    state.act(Action::OpenRemoveList(list.id));
    assert!(state.lists.remove.is_none());
}

#[test]
fn stale_category_inspection_is_ignored_and_retried_for_new_config() {
    let mut state = State::default();
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config: AppConfig::default(),
    });
    let Some(Job::InspectListCategories { revision, .. }) = state.take_list_inspection() else {
        panic!("config must schedule inspection");
    };
    state.reduce(WorkerEvent::Config {
        generation: 2,
        config: AppConfig::default(),
    });
    state.reduce(WorkerEvent::ListAvailability {
        revision,
        result: Ok(vec![rosetun_core::MissingListCategory {
            set: None,
            rule: RuleId::new("old"),
            list: ListId::new("1"),
            category: "old".into(),
            last_good: false,
        }]),
    });
    assert!(state.lists.missing.is_empty());
    assert!(matches!(
        state.take_list_inspection(),
        Some(Job::InspectListCategories { revision: next, .. }) if next != revision
    ));
}

#[test]
fn list_rule_requires_a_dat_category_and_submits_a_valid_matcher() {
    let mut state = state_with_rules();
    let mut added = list(
        "1",
        ListSource::Url("https://example.com/geosite.dat".into()),
    );
    added.format = ListFormat::GeoSite;
    added.categories = vec!["example".into()];
    state.config.lists.push(added);
    state.act(Action::OpenRules);
    state.act(Action::OpenAddRule);
    state.act(Action::SelectRuleInput(RuleInputKind::List));
    let dialog = state.rules.screen.add.as_mut().unwrap();
    dialog.list = Some(ListId::new("1"));
    assert!(state.act(Action::SubmitAddRule).is_none());
    assert_eq!(
        state.rules.screen.add.as_ref().unwrap().error.as_deref(),
        Some("Select a category from this list")
    );
    state.rules.screen.add.as_mut().unwrap().category = "example@cn".into();
    let Some(Job::AddRule(set, matcher, RuleTarget::Proxy)) = state.act(Action::SubmitAddRule)
    else {
        panic!("a valid category must produce a list rule job");
    };
    assert!(
        matches!(&matcher, RuleMatcher::List { category: Some(value), .. } if value == "example@cn")
    );
    let mut config = state.config.clone();
    config
        .rule_sets
        .iter_mut()
        .find(|item| item.id == set)
        .unwrap()
        .rules
        .push(Rule {
            id: RuleId::new("list-rule"),
            enabled: true,
            matcher,
            target: RuleTarget::Proxy,
        });
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config,
    });
    assert!(state.config.rule_sets[1].rules.iter().any(|rule| {
        matches!(&rule.matcher, RuleMatcher::List { category: Some(value), .. } if value == "example@cn")
    }));
}

#[test]
fn missing_categories_expose_fallback_and_disabled_states_then_clear() {
    let mut state = state_with_rules();
    let mut added = list(
        "1",
        ListSource::Url("https://example.com/geosite.dat".into()),
    );
    added.format = ListFormat::GeoSite;
    state.config.lists.push(added);
    assert_eq!(
        state.list_rule_name(&ListId::new("1"), Some("example@cn")),
        "Example: example@cn"
    );
    state.config.rule_sets[1].rules[0].matcher = RuleMatcher::List {
        list: ListId::new("1"),
        category: Some("example@cn".into()),
    };
    state.config.active_rule_set = Some(RuleSetId::new("2"));
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config: state.config.clone(),
    });
    let Some(Job::InspectListCategories { revision, .. }) = state.take_list_inspection() else {
        panic!("config must schedule inspection");
    };
    let item = rosetun_core::MissingListCategory {
        set: Some(RuleSetId::new("2")),
        rule: RuleId::new("0"),
        list: ListId::new("1"),
        category: "example@cn".into(),
        last_good: true,
    };
    state.reduce(WorkerEvent::ListAvailability {
        revision,
        result: Ok(vec![item.clone()]),
    });
    assert_eq!(state.active_missing_categories(), 1);
    assert!(
        state
            .missing_list_rule(Some(&RuleSetId::new("2")), &RuleId::new("0"))
            .unwrap()
            .last_good
    );
    assert_eq!(state.lists.missing[0].category, "example@cn");
    assert_eq!(
        crate::i18n::tr_in(
            crate::i18n::Language::Russian,
            "rule-category-last-good",
            &fluent_bundle::FluentArgs::new()
        ),
        "Категории больше нет в списке · используется прошлая версия"
    );
    state.lists.missing[0].last_good = false;
    assert!(
        !state
            .missing_list_rule(Some(&RuleSetId::new("2")), &RuleId::new("0"))
            .unwrap()
            .last_good
    );
    assert_eq!(
        crate::i18n::tr_in(
            crate::i18n::Language::English,
            "rule-category-disabled",
            &fluent_bundle::FluentArgs::new()
        ),
        "Category no longer in list · rule does not work"
    );
    state.config.rule_sets[1].rules[0].matcher = RuleMatcher::List {
        list: ListId::new("1"),
        category: Some("replacement".into()),
    };
    state.reduce(WorkerEvent::Config {
        generation: 2,
        config: state.config.clone(),
    });
    assert_eq!(state.active_missing_categories(), 0);
    assert!(state.lists.missing.is_empty());
}

fn connected_state_with_list_rule() -> (State, ListId) {
    let mut state = state_for_auto_connect();
    let id = ListId::new("1");
    state.config.lists.push(list(
        "1",
        ListSource::Url("https://example.com/rules.txt".into()),
    ));
    let mut set = rule_set("1");
    set.rules[0].matcher = RuleMatcher::List {
        list: id.clone(),
        category: None,
    };
    state.config.rule_sets.push(set);
    state.config.active_rule_set = Some(RuleSetId::new("1"));
    let request = ConnectRequest::from_config(&state.config).unwrap();
    state.reduce(WorkerEvent::Connect(Ok(request)));
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        node: Some(NodeId::new("node")),
        ..Status::default()
    }));
    (state, id)
}

#[test]
fn manual_update_of_active_list_applies_on_leave_and_clears_after_apply() {
    let (mut state, id) = connected_state_with_list_rule();
    state.reduce(WorkerEvent::UpdateList {
        id,
        result: Ok(state.config.lists[0].clone()),
        manual: true,
    });
    let Some(Job::Apply(request)) = state.apply_on_leave() else {
        panic!("manual update of the active list must apply");
    };
    assert!(state.session.lists_changed_since_apply);
    state.reduce(WorkerEvent::Apply(Ok(*request)));
    assert!(!state.session.lists_changed_since_apply);
    assert!(!state.has_pending_apply());
    assert!(state.apply_on_leave().is_none());
}

#[test]
fn background_update_of_active_list_does_not_apply_on_leave() {
    let (mut state, id) = connected_state_with_list_rule();
    state.reduce(WorkerEvent::UpdateList {
        id,
        result: Ok(state.config.lists[0].clone()),
        manual: false,
    });
    assert!(!state.session.lists_changed_since_apply);
    assert!(state.apply_on_leave().is_none());
}

#[test]
fn manual_update_of_unused_list_does_not_apply_on_leave() {
    let (mut state, _) = connected_state_with_list_rule();
    let unused = list(
        "2",
        ListSource::Url("https://example.com/unused.txt".into()),
    );
    state.config.lists.push(unused.clone());
    state.reduce(WorkerEvent::UpdateList {
        id: unused.id.clone(),
        result: Ok(unused),
        manual: true,
    });
    assert!(!state.session.lists_changed_since_apply);
    assert!(state.apply_on_leave().is_none());
}

#[test]
fn manual_update_of_temporary_list_applies_on_leave() {
    let (mut state, _) = connected_state_with_list_rule();
    let temporary = list(
        "2",
        ListSource::Url("https://example.com/temporary.txt".into()),
    );
    state.config.lists.push(temporary.clone());
    state.session.temporary_rules.push(Rule {
        id: RuleId::new("temporary-list"),
        enabled: true,
        matcher: RuleMatcher::List {
            list: temporary.id.clone(),
            category: None,
        },
        target: RuleTarget::Block,
    });
    state.reduce(WorkerEvent::UpdateList {
        id: temporary.id.clone(),
        result: Ok(temporary),
        manual: true,
    });
    assert!(matches!(state.apply_on_leave(), Some(Job::Apply(_))));
}

#[test]
fn connecting_with_original_list_request_has_no_pending_apply() {
    let (mut state, _) = connected_state_with_list_rule();
    assert_eq!(
        state.session.session_request.as_ref().unwrap().lists.len(),
        0
    );
    assert!(!state.has_pending_apply());
    assert!(state.apply_on_leave().is_none());
}

#[test]
fn list_update_failures_stay_local_and_unrelated_success_does_not_clear_them() {
    let mut state = State::default();
    let id = ListId::new("1");
    state.operations.updating_lists.insert(id.clone());
    state.reduce(WorkerEvent::UpdateList {
        id: id.clone(),
        result: Err(ListError::Integrity),
        manual: false,
    });
    assert!(matches!(
        state.lists.outcomes.get(&id),
        Some(ListOutcome::Failed(_))
    ));
    assert!(state.operation_error.is_none());
    state.reduce(WorkerEvent::UpdateAll {
        subscriptions: Ok(Vec::new()),
        lists: Ok(Vec::new()),
    });
    assert!(matches!(
        state.lists.outcomes.get(&id),
        Some(ListOutcome::Failed(_))
    ));
}
