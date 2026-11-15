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
    let Some(Job::SaveExit {
        id, name, target, ..
    }) = state.act(Action::SubmitExitDialog)
    else {
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

fn chain_state() -> State {
    let mut state = state_with_exits();
    for node in &mut state.config.subscriptions[0].nodes {
        node.outbound = rosetun_config::Outbound::Socks5(Default::default());
        node.server = "192.0.2.20".into();
    }
    state.config.exits[1].via = Some(ExitId::new("1"));
    state
}

#[test]
fn exit_path_draft_cancel_and_save_keep_the_dependency() {
    let mut state = chain_state();
    state.act(Action::OpenEditExit(ExitId::new("2")));
    assert_eq!(
        state.exits.dialog.as_ref().unwrap().via,
        Some(ExitId::new("1"))
    );
    state.exits.dialog.as_mut().unwrap().via = None;
    state.act(Action::CancelExitDialog);
    assert_eq!(state.config.exits[1].via, Some(ExitId::new("1")));
    state.act(Action::OpenEditExit(ExitId::new("2")));
    assert!(
        matches!(state.act(Action::SubmitExitDialog), Some(Job::SaveExit { via: Some(id), .. }) if id == ExitId::new("1"))
    );
}

#[test]
fn vanished_parent_and_unsupported_target_do_not_clear_the_draft_path() {
    let mut state = chain_state();
    state.act(Action::OpenEditExit(ExitId::new("2")));
    state.exits.dialog.as_mut().unwrap().kind = ExitKind::Node;
    state
        .exits
        .dialog
        .as_mut()
        .unwrap()
        .pick_node(&state.config, node("plain"));
    state.config.subscriptions[0].nodes[2].server = "b.example.com".into();
    assert!(state.act(Action::SubmitExitDialog).is_none());
    state.config.exits.remove(0);
    state.reconcile_exits();
    assert!(state.act(Action::SubmitExitDialog).is_none());
    let dialog = state.exits.dialog.as_ref().unwrap();
    assert_eq!(dialog.via, Some(ExitId::new("1")));
    assert!(dialog.error.is_some());
}

#[test]
fn parent_deletion_names_its_children_and_cannot_be_confirmed() {
    let mut state = chain_state();
    state.act(Action::RequestDeleteExit(ExitId::new("1")));
    assert_eq!(
        state.exits.delete.as_ref().unwrap().dependents,
        vec![state.config.exits[1].name.clone()]
    );
    assert!(state.act(Action::ConfirmDeleteExit).is_none());
}

#[test]
fn path_choices_reject_self_third_hop_domains_xray_and_fragmentation() {
    let mut state = chain_state();
    let b = &state.config.exits[1];
    let supported = |config: &AppConfig, via: &ExitId| {
        crate::destinations::exit_path_supported(config, Some(&b.id), &b.target, Some(via))
    };
    assert!(supported(&state.config, &ExitId::new("1")));
    assert!(!supported(&state.config, &ExitId::new("2")));
    assert!(!crate::destinations::exit_path_supported(
        &state.config,
        None,
        &b.target,
        Some(&b.id)
    ));
    state.config.settings.tls_fragment.enabled = true;
    assert!(!supported(&state.config, &ExitId::new("1")));
    state.config.settings.tls_fragment.enabled = false;
    state.config.settings.engine = rosetun_config::EngineKind::Xray;
    assert!(!supported(&state.config, &ExitId::new("1")));
}

#[test]
fn path_candidates_follow_the_draft_target() {
    let mut state = chain_state();
    state.config.subscriptions[0].nodes[2].server = "b.example.com".into();
    state.act(Action::OpenEditExit(ExitId::new("2")));
    let config = state.config.clone();
    let dialog = state.exits.dialog.as_mut().unwrap();
    assert_eq!(dialog.via_candidates(&config), [ExitId::new("1")]);
    dialog.kind = ExitKind::Node;
    assert!(dialog.via_candidates(&config).is_empty());
    dialog.pick_node(&config, node("plain"));
    assert!(dialog.via_candidates(&config).is_empty());
    dialog.kind = ExitKind::Country;
    assert_eq!(dialog.via_candidates(&config), [ExitId::new("1")]);
}

#[test]
fn path_label_places_a_before_b() {
    let mut state = chain_state();
    state.config.exits[0].name = "A".into();
    state.config.exits[1].name = "B".into();
    assert_eq!(
        crate::destinations::exit_path_label(&state.config, &state.config.exits[1]),
        "A → B"
    );
}

#[test]
fn failed_path_apply_restores_the_path_and_preserves_temporary_rules() {
    let mut state = chain_state();
    state.helper_available = true;
    state.session.temporary_rules_loaded = true;
    state.config.active = Some(node("nl"));
    state.config.active_rule_set = Some(RuleSetId::new("b"));
    state.config.rule_sets[1]
        .rules
        .iter_mut()
        .find(|rule| rule.target == RuleTarget::Exit)
        .unwrap()
        .exit = Some(ExitId::new("2"));
    state.config.exits[1].via = None;
    let request = ConnectRequest::from_config(&state.config).unwrap();
    state.reduce(WorkerEvent::Connect(Ok(request)));
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        node: Some(NodeId::new("nl")),
        ..Status::default()
    }));
    state.session.temporary_rules_loaded = true;
    let temporary = temporary_rule("temp", "temporary.example.com");
    state.session.temporary_rules = vec![temporary.clone()];
    state.config.exits[1].via = Some(ExitId::new("1"));
    state.reduce(WorkerEvent::Config {
        generation: state.config_generation + 1,
        config: state.config.clone(),
    });
    assert!(state.can_change_temporary(), "cannot change temporary");
    let candidate = ConnectRequest::from_config(&state.config).unwrap();
    assert!(
        candidate
            .extra_nodes
            .iter()
            .any(|extra| extra.via.is_some()),
        "candidate has no path: {candidate:?}"
    );
    assert!(state.has_pending_apply(), "no pending Apply");
    assert!(state.apply_request().is_some(), "no Apply request");
    let Some(Job::Apply(request)) = state.act(Action::Apply) else {
        panic!("expected Apply");
    };
    assert_eq!(
        request
            .extra_nodes
            .iter()
            .find(|extra| extra.exit == ExitId::new("2"))
            .unwrap()
            .via,
        Some(ExitId::new("1"))
    );
    assert_eq!(request.temporary_rules, vec![temporary.clone()]);
    state.reduce(WorkerEvent::Apply(Err(HelperCommandError::Client(
        ClientError::Helper(HelperError::new(
            ErrorCode::UnsupportedRules,
            "rejected path",
        )),
    ))));
    let Some(Job::RestoreApplied(snapshot)) = state.take_restore() else {
        panic!("expected rollback");
    };
    assert_eq!(snapshot.exits[1].via, None);
    assert_eq!(state.session.temporary_rules, vec![temporary]);
}
