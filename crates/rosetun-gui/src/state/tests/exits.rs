use super::*;
use rosetun_config::{CountryCode, Exit, ExitId, ExitTarget};
use rosetun_ipc::MAX_EXTRA_NODES;

use crate::destinations::tests::{config, exit};

fn country(code: &str) -> CountryCode {
    CountryCode::parse(code).unwrap()
}

fn node(id: &str) -> Selection {
    Selection {
        subscription: SubscriptionId::new("sub"),
        node: NodeId::new(id),
    }
}

fn exit_rule(id: &str, exit: &str) -> Rule {
    Rule {
        id: RuleId::new(id),
        enabled: true,
        matcher: RuleMatcher::Domain(DomainMatch::Exact(format!("{id}.example.com"))),
        target: RuleTarget::Exit,
        exit: Some(ExitId::new(exit)),
    }
}

fn visible(state: &State) -> Vec<RuleId> {
    crate::rules::visible_rules(state.selected_rules().unwrap(), &state.rules.screen.filter)
        .into_iter()
        .map(|(_, rule)| rule.id.clone())
        .collect()
}

/// Exit "1" goes to the Netherlands and has one rule in set "b"; exit "2" is unused.
fn state_with_exits() -> State {
    let mut config = config(
        &[("nl", "🇳🇱 One"), ("de", "🇩🇪 Two"), ("plain", "Plain")],
        vec![
            exit("1", ExitTarget::Country(country("NL"))),
            exit("2", ExitTarget::Country(country("DE"))),
        ],
    );
    let mut with_exit = rule_set("b");
    with_exit.rules.push(exit_rule("e", "1"));
    config.rule_sets = vec![rule_set("a"), with_exit];
    config.active_rule_set = Some(RuleSetId::new("a"));
    State {
        config_ready: true,
        config,
        ..State::default()
    }
}

#[test]
fn rule_count_click_opens_the_rules_with_that_exit() {
    let mut state = state_with_exits();
    state.act(Action::ShowExits);
    assert_eq!(state.lists.tab, RulesTab::Exits);
    assert_eq!(state.exit_rules(&ExitId::new("1")), 1);
    assert_eq!(state.exit_rules(&ExitId::new("2")), 0);
    state.rules.screen.filter.search = "first".into();

    state.act(Action::ShowExitRules(ExitId::new("1")));

    assert_eq!(state.lists.tab, RulesTab::Rules);
    assert_eq!(state.rules.screen.selected_set, Some(RuleSetId::new("b")));
    let filter = &state.rules.screen.filter;
    assert_eq!(filter.target, Some(RuleTarget::Exit));
    assert_eq!(filter.exit, Some(ExitId::new("1")));
    assert!(filter.search.is_empty());
    assert_eq!(visible(&state), [RuleId::new("e")]);

    state.act(Action::SetRuleTargetFilter(Some(RuleTarget::Exit)));
    assert_eq!(state.rules.screen.filter.exit, None);
    state.act(Action::SetRuleExitFilter(ExitId::new("2")));
    assert_eq!(state.rules.screen.filter.exit, Some(ExitId::new("2")));
    assert!(visible(&state).is_empty());
}

#[test]
fn deleting_a_used_exit_asks_and_blocks_its_rules() {
    let mut state = state_with_exits();
    state.session.temporary_rules =
        vec![exit_rule("temp", "1"), temporary_rule("other", "x.example")];
    state.rules.screen.filter.exit = Some(ExitId::new("1"));

    assert!(
        state
            .act(Action::RequestDeleteExit(ExitId::new("1")))
            .is_none()
    );
    assert_eq!(state.exits.delete.as_ref().unwrap().rules, 2);
    assert!(matches!(
        state.act(Action::ConfirmDeleteExit),
        Some(Job::DeleteExit(id)) if id == ExitId::new("1")
    ));
    assert!(state.operations.rules_edit);

    state.reduce(WorkerEvent::DeleteExit {
        id: ExitId::new("1"),
        result: Ok(1),
    });
    assert!(state.exits.delete.is_none());
    assert!(!state.operations.rules_edit);
    let temporary = &state.session.temporary_rules[0];
    assert_eq!(temporary.target, RuleTarget::Block);
    assert_eq!(temporary.exit, None);
    assert_eq!(state.session.temporary_rules[1].target, RuleTarget::Direct);
    assert_eq!(state.rules.screen.filter.exit, None);
}

#[test]
fn failed_delete_keeps_the_dialog_and_temporary_rules() {
    let mut state = state_with_exits();
    state.session.temporary_rules = vec![exit_rule("temp", "1")];
    state.act(Action::RequestDeleteExit(ExitId::new("1")));
    state.act(Action::ConfirmDeleteExit);
    state.reduce(WorkerEvent::DeleteExit {
        id: ExitId::new("1"),
        result: Err(rosetun_core::ExitError::NotFound),
    });
    let dialog = state.exits.delete.as_ref().unwrap();
    assert!(!dialog.busy && dialog.error.is_some());
    assert_eq!(state.session.temporary_rules[0].target, RuleTarget::Exit);
}

#[test]
fn deleting_an_unused_exit_needs_no_confirmation() {
    let mut state = state_with_exits();
    assert!(matches!(
        state.act(Action::RequestDeleteExit(ExitId::new("2"))),
        Some(Job::DeleteExit(id)) if id == ExitId::new("2")
    ));
    assert!(state.exits.delete.is_none());
}

#[test]
fn exit_dialog_saves_a_new_node_and_a_new_country() {
    let mut state = state_with_exits();
    state.act(Action::OpenEditExit(ExitId::new("1")));
    let dialog = state.exits.dialog.as_mut().unwrap();
    assert_eq!(dialog.kind, ExitKind::Country);
    assert_eq!(dialog.country, Some(country("NL")));
    dialog.kind = ExitKind::Node;
    dialog.name = " Work ".into();
    dialog.pick_node(&state.config, node("de"));
    let Some(Job::SaveExit { id, name, target }) = state.act(Action::SubmitExitDialog) else {
        panic!("expected a save job");
    };
    assert_eq!(id, Some(ExitId::new("1")));
    assert_eq!(name, "Work");
    assert_eq!(
        target,
        ExitTarget::Node {
            selection: node("de"),
            fallback: Some(country("DE")),
        }
    );
    state.reduce(WorkerEvent::SaveExit(Ok(())));
    assert!(state.exits.dialog.is_none());

    state.act(Action::OpenEditExit(ExitId::new("2")));
    let dialog = state.exits.dialog.as_mut().unwrap();
    dialog.country = Some(country("NL"));
    let Some(Job::SaveExit { target, .. }) = state.act(Action::SubmitExitDialog) else {
        panic!("expected a save job");
    };
    assert_eq!(target, ExitTarget::Country(country("NL")));
    state.reduce(WorkerEvent::SaveExit(Err(
        rosetun_core::ExitError::EmptyName,
    )));
    let dialog = state.exits.dialog.as_ref().unwrap();
    assert!(!dialog.busy && dialog.error.is_some());
}

#[test]
fn node_without_a_country_has_no_fallback() {
    let mut state = state_with_exits();
    state.act(Action::OpenNewExit);
    let dialog = state.exits.dialog.as_mut().unwrap();
    dialog.name = "Plain".into();
    dialog.kind = ExitKind::Node;
    dialog.pick_node(&state.config, node("plain"));
    assert!(dialog.fallback);
    assert_eq!(dialog.fallback_country, None);
    assert_eq!(
        dialog.target(),
        Some(ExitTarget::Node {
            selection: node("plain"),
            fallback: None,
        })
    );
    dialog.pick_node(&state.config, node("nl"));
    dialog.fallback = false;
    assert_eq!(
        dialog.target(),
        Some(ExitTarget::Node {
            selection: node("nl"),
            fallback: None,
        })
    );
}

#[test]
fn new_exit_respects_the_exit_limit_but_editing_does_not() {
    let mut state = state_with_exits();
    state.config.exits = (0..MAX_EXTRA_NODES)
        .map(|index| exit(&index.to_string(), ExitTarget::Country(country("NL"))))
        .collect();
    state.act(Action::OpenNewExit);
    let dialog = state.exits.dialog.as_mut().unwrap();
    dialog.name = "Extra".into();
    dialog.country = Some(country("DE"));
    assert!(!dialog.can_save(true));
    assert!(state.act(Action::SubmitExitDialog).is_none());
    state.act(Action::CancelExitDialog);

    state.act(Action::OpenEditExit(ExitId::new("0")));
    state.exits.dialog.as_mut().unwrap().country = Some(country("DE"));
    assert!(matches!(
        state.act(Action::SubmitExitDialog),
        Some(Job::SaveExit { id: Some(_), .. })
    ));
}

#[test]
fn rename_exit_sends_the_trimmed_name() {
    let mut state = state_with_exits();
    state.act(Action::OpenRenameExit(ExitId::new("2")));
    state.exits.rename.as_mut().unwrap().name = " Germany ".into();
    assert!(matches!(
        state.act(Action::SubmitRenameExit),
        Some(Job::RenameExit(id, name)) if id == ExitId::new("2") && name == "Germany"
    ));
    state.reduce(WorkerEvent::RenameExit(Ok(())));
    assert!(state.exits.rename.is_none());
}

#[test]
fn deleted_exit_closes_its_dialogs_on_reload() {
    let mut state = state_with_exits();
    state.act(Action::OpenEditExit(ExitId::new("2")));
    let mut config = state.config.clone();
    config
        .exits
        .retain(|exit: &Exit| exit.id != ExitId::new("2"));
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config,
    });
    assert!(state.exits.dialog.is_none());
}
