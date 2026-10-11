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
    assert_eq!(state.lists.add.as_ref().unwrap().result, Some((ListFormat::Text, 0, Some(56))));
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
fn adding_file_list_uses_only_a_transient_path() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    state.act(Action::OpenAddList);
    assert!(matches!(state.act(Action::BrowseListFile), Some(Job::BrowseListFile)));
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
fn list_update_failures_stay_local_and_unrelated_success_does_not_clear_them() {
    let mut state = State::default();
    let id = ListId::new("1");
    state.operations.updating_lists.insert(id.clone());
    state.reduce(WorkerEvent::UpdateList {
        id: id.clone(),
        result: Err(ListError::Integrity),
        manual: false,
    });
    assert!(matches!(state.lists.outcomes.get(&id), Some(ListOutcome::Failed(_))));
    assert!(state.operation_error.is_none());
    state.reduce(WorkerEvent::UpdateAll {
        subscriptions: Ok(Vec::new()),
        lists: Ok(Vec::new()),
    });
    assert!(matches!(state.lists.outcomes.get(&id), Some(ListOutcome::Failed(_))));
}
