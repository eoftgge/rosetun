use super::*;

#[test]
fn leaving_rules_applies_edits_once_but_rule_screen_actions_do_not() {
    let mut state = connected_state_for_apply();
    assert!(state.act(Action::OpenRules).is_none());
    state.config.rule_sets[0].rules[0].target = RuleTarget::Direct;
    assert!(state.act(Action::SetRuleTargetFilter(None)).is_none());
    assert!(!matches!(
        state.act(Action::OpenAddRule),
        Some(Job::Apply(_))
    ));
    state.act(Action::CancelAddRule);
    state.config.rule_sets.push(rule_set("2"));
    assert!(
        state
            .act(Action::ChooseRuleSet(RuleSetId::new("2")))
            .is_none()
    );
    assert!(matches!(
        state.act(Action::ShowConnection),
        Some(Job::Apply(_))
    ));
    assert!(state.act(Action::OpenRules).is_none());
    assert!(state.act(Action::ShowConnection).is_none());
}

#[test]
fn leaving_settings_applies_dns_edits_but_not_without_a_connection() {
    let mut state = connected_state_for_apply();
    state.act(Action::OpenSettings);
    assert!(state.act(Action::ShowConnection).is_none());
    state.act(Action::OpenSettings);
    state.config.settings.dns = DnsPreset::Google.settings();
    assert!(matches!(
        state.act(Action::ShowConnection),
        Some(Job::Apply(_))
    ));

    let mut disconnected = state_for_auto_connect();
    disconnected.act(Action::OpenSettings);
    disconnected.config.settings.dns = DnsPreset::Google.settings();
    assert!(disconnected.act(Action::ShowConnection).is_none());
}

#[test]
fn leaving_while_rule_or_dns_save_is_running_applies_after_publication() {
    let mut state = connected_state_for_apply();
    state.act(Action::OpenRules);
    state.operations.rules_edit = true;
    assert!(state.act(Action::ShowConnection).is_none());
    assert!(state.session.apply_after_leave);
    assert!(state.take_apply().is_none());
    let mut saved = state.config.clone();
    saved.rule_sets[0].rules[0].target = RuleTarget::Direct;
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config: saved,
    });
    assert!(state.take_apply().is_none());
    state.reduce(WorkerEvent::SetRuleTarget(Ok(())));
    assert!(matches!(state.take_apply(), Some(Job::Apply(_))));

    let mut state = connected_state_for_apply();
    state.act(Action::OpenSettings);
    state.operations.settings = true;
    assert!(state.act(Action::ShowConnection).is_none());
    let mut saved = state.config.clone();
    saved.settings.dns = DnsPreset::Google.settings();
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config: saved,
    });
    state.reduce(WorkerEvent::SetDns(Ok(())));
    assert!(matches!(state.take_apply(), Some(Job::Apply(_))));
}

#[test]
fn hiding_applies_pending_edits_only_while_connected() {
    let mut state = connected_state_for_apply();
    assert!(state.apply_on_leave().is_none());
    state.config.rule_sets[0].rules[0].target = RuleTarget::Direct;
    assert!(matches!(state.apply_on_leave(), Some(Job::Apply(_))));
    assert!(state.apply_on_leave().is_none());

    let mut disconnected = state_with_rules();
    disconnected.config.rule_sets[1].rules[0].target = RuleTarget::Direct;
    assert!(disconnected.apply_on_leave().is_none());
}

#[cfg(windows)]
#[test]
fn minimizing_applies_pending_edits() {
    let mut state = connected_state_for_apply();
    state.config.settings.dns = DnsPreset::Google.settings();
    assert!(matches!(
        state.act(Action::WindowMinimized),
        Some(Job::Apply(_))
    ));
    assert!(state.act(Action::WindowMinimized).is_none());
}

#[cfg(windows)]
#[test]
fn opening_settings_keeps_autostart_load_and_queues_apply() {
    let mut state = connected_state_for_apply();
    state.act(Action::OpenRules);
    state.config.rule_sets[0].rules[0].target = RuleTarget::Direct;
    assert!(matches!(
        state.act(Action::OpenSettings),
        Some(Job::LoadAutostart)
    ));
    assert!(matches!(state.take_leave_apply(), Some(Job::Apply(_))));
    assert!(state.take_leave_apply().is_none());
}

#[test]
fn leaving_during_apply_coalesces_one_follow_up_after_success() {
    let mut state = connected_state_for_apply();
    state.act(Action::OpenRules);
    state.config.rule_sets[0].rules[0].target = RuleTarget::Direct;
    let Some(Job::Apply(first)) = state.act(Action::ShowConnection) else {
        panic!("leaving rules must apply");
    };
    state.act(Action::OpenRules);
    state.config.rule_sets[0].rules[1].target = RuleTarget::Block;
    assert!(state.act(Action::ShowConnection).is_none());
    assert!(state.session.apply_after_leave);
    state.reduce(WorkerEvent::Apply(Ok(*first)));
    let Some(Job::Apply(second)) = state.take_apply() else {
        panic!("edits made during apply must run next");
    };
    assert_eq!(second.rule_set.rules[1].target, RuleTarget::Block);
    assert!(state.take_apply().is_none());
    state.reduce(WorkerEvent::Apply(Ok(*second)));
    assert!(state.take_apply().is_none());
}

#[test]
fn temporary_rules_load_once_and_retry_busy_after_the_next_status() {
    let mut state = state_for_auto_connect();
    state.reduce(WorkerEvent::HelperAvailable {
        version: "test".into(),
    });
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        node: Some(NodeId::new("node")),
        ..Status::default()
    }));
    let Some(Job::LoadTemporaryRules(request)) = state.take_temporary_load(1_000) else {
        panic!("connected status must load temporary rules");
    };
    assert!(state.take_temporary_load(1_000).is_none());
    state.reduce(WorkerEvent::TemporaryRules {
        request,
        result: Err(HelperCommandError::Client(ClientError::Helper(
            HelperError::new(ErrorCode::Busy, "busy"),
        ))),
    });
    assert!(state.take_temporary_load(1_000).is_none());
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        node: Some(NodeId::new("node")),
        ..Status::default()
    }));
    let Some(Job::LoadTemporaryRules(next)) = state.take_temporary_load(1_000) else {
        panic!("busy load must retry on the next status");
    };
    assert_ne!(request, next);
    let rule = temporary_rule("t1", "session.example");
    state.reduce(WorkerEvent::TemporaryRules {
        request,
        result: Ok(vec![temporary_rule("t2", "stale.example")]),
    });
    state.reduce(WorkerEvent::TemporaryRules {
        request: next,
        result: Ok(vec![rule.clone()]),
    });
    assert_eq!(state.session.temporary_rules, vec![rule.clone()]);
    assert_eq!(
        state
            .session
            .session_request
            .as_ref()
            .unwrap()
            .temporary_rules,
        vec![rule]
    );
    assert!(state.take_temporary_load(1_000).is_none());
}

#[test]
fn temporary_rules_retry_closed_after_ten_seconds_and_restore_apply() {
    let mut state = state_for_auto_connect();
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        node: Some(NodeId::new("node")),
        ..Status::default()
    }));
    let Some(Job::LoadTemporaryRules(first)) = state.take_temporary_load(1_000) else {
        panic!("connected status must load temporary rules");
    };
    state.config.settings.dns = DnsPreset::Google.settings();
    assert!(state.act(Action::Apply).is_none());
    state.reduce(WorkerEvent::TemporaryRules {
        request: first,
        result: Err(HelperCommandError::Client(ClientError::Closed)),
    });
    let error = state.operation_error.clone();
    assert!(error.is_some());
    assert!(state.take_temporary_load(1_009).is_none());
    let Some(Job::LoadTemporaryRules(second)) = state.take_temporary_load(1_010) else {
        panic!("closed load must retry after ten seconds");
    };
    state.reduce(WorkerEvent::TemporaryRules {
        request: second,
        result: Err(HelperCommandError::Client(ClientError::Helper(
            HelperError::new(ErrorCode::Internal, "later failure"),
        ))),
    });
    assert_eq!(state.operation_error, error);
    assert!(state.take_temporary_load(1_019).is_none());
    let Some(Job::LoadTemporaryRules(third)) = state.take_temporary_load(1_020) else {
        panic!("repeated errors must keep retrying");
    };
    state.reduce(WorkerEvent::TemporaryRules {
        request: third,
        result: Ok(vec![]),
    });
    assert!(state.session.temporary_rules_loaded);
    assert!(matches!(state.act(Action::Apply), Some(Job::Apply(_))));
    assert!(state.operation_error.is_none());
}

#[test]
fn temporary_rules_loaded_before_config_are_kept_in_the_session_snapshot() {
    let mut state = state_for_auto_connect();
    state.config_ready = false;
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        node: Some(NodeId::new("node")),
        ..Status::default()
    }));
    let Some(Job::LoadTemporaryRules(request)) = state.take_temporary_load(1_000) else {
        panic!("connected status must load temporary rules");
    };
    let rule = temporary_rule("t1", "session.example");
    state.reduce(WorkerEvent::TemporaryRules {
        request,
        result: Ok(vec![rule.clone()]),
    });
    state.config_ready = true;
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        node: Some(NodeId::new("node")),
        ..Status::default()
    }));
    assert_eq!(
        state.session.session_request.unwrap().temporary_rules,
        vec![rule]
    );
}

#[test]
fn adding_temporary_rule_applies_immediately_without_saving() {
    let mut state = connected_state_for_apply();
    temporary_dialog(&mut state, "session.example");
    let config = state.config.clone();
    state.config.settings.dns = DnsPreset::Google.settings();
    let Some(Job::Apply(request)) = state.act(Action::SubmitAddRule) else {
        panic!("temporary rule must apply immediately");
    };
    assert_eq!(
        request.temporary_rules,
        vec![temporary_rule("t1", "session.example")]
    );
    assert_eq!(state.session.temporary_rules, request.temporary_rules);
    assert!(state.rules.screen.add.is_none());
    assert_eq!(state.config.rule_sets, config.rule_sets);
    assert_eq!(request.settings.dns, state.config.settings.dns);
    assert!(!state.pending_reconnect(SessionPart::Rules));
    assert!(state.operations.helper);
    state.reduce(WorkerEvent::Apply(Ok(*request.clone())));
    assert_eq!(
        state.session.session_request.as_ref(),
        Some(request.as_ref())
    );
    assert_eq!(state.session.temporary_rules, request.temporary_rules);
    assert!(!state.pending_reconnect(SessionPart::Rules));
    assert!(!state.pending_reconnect(SessionPart::Dns));
}

#[test]
fn temporary_rule_guards_and_duplicate_dialog_error() {
    let mut state = connected_state_for_apply();
    temporary_dialog(&mut state, "first.example");
    assert!(state.act(Action::SubmitAddRule).is_none());
    assert!(state.rules.screen.add.as_ref().unwrap().error.is_some());
    assert!(state.session.temporary_rules.is_empty());
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Disconnected,
        ..Status::default()
    }));
    temporary_dialog(&mut state, "session.example");
    assert!(!state.can_change_temporary());
    assert!(state.act(Action::SubmitAddRule).is_none());
    assert!(state.session.temporary_rules.is_empty());
}

#[test]
fn disconnect_resets_the_open_rule_dialog_to_permanent() {
    let mut state = connected_state_for_apply();
    temporary_dialog(&mut state, "session.example");
    assert!(state.rules.screen.add.as_ref().unwrap().temporary_only);
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Disconnected,
        ..Status::default()
    }));
    assert!(!state.rules.screen.add.as_ref().unwrap().temporary_only);
    assert!(matches!(
        state.act(Action::SubmitAddRule),
        Some(Job::AddRules(_, _, RuleTarget::Direct))
    ));
}

#[test]
fn new_temporary_rules_precede_existing_ones_and_survive_other_applies() {
    let mut state = connected_state_for_apply();
    let old = temporary_rule("t1", "old.example");
    state.session.temporary_rules.push(old.clone());
    state
        .session
        .session_request
        .as_mut()
        .unwrap()
        .temporary_rules
        .push(old.clone());
    temporary_dialog(&mut state, "first.example.org\nsecond.example.org");
    let Some(Job::Apply(request)) = state.act(Action::SubmitAddRule) else {
        panic!("new temporary rules must apply");
    };
    assert_eq!(request.temporary_rules[0].id, RuleId::new("t2"));
    assert_eq!(request.temporary_rules[1].id, RuleId::new("t3"));
    assert_eq!(request.temporary_rules[2], old);
    state.reduce(WorkerEvent::Apply(Ok(*request)));
    state.config.settings.dns = DnsPreset::Google.settings();
    let Some(Job::Apply(request)) = state.act(Action::Apply) else {
        panic!("DNS changes must apply with the temporary overlay");
    };
    assert_eq!(request.temporary_rules, state.session.temporary_rules);
}

#[test]
fn failed_temporary_apply_restores_the_last_helper_snapshot() {
    let mut state = connected_state_for_apply();
    let rule = temporary_rule("t1", "existing.example");
    state.session.temporary_rules.push(rule.clone());
    state
        .session
        .session_request
        .as_mut()
        .unwrap()
        .temporary_rules
        .push(rule.clone());
    temporary_dialog(&mut state, "session.example");
    assert!(matches!(
        state.act(Action::SubmitAddRule),
        Some(Job::Apply(_))
    ));
    assert_eq!(state.session.temporary_rules.len(), 2);
    state.reduce(WorkerEvent::Apply(Err(HelperCommandError::Client(
        ClientError::Helper(HelperError::new(ErrorCode::Busy, "busy")),
    ))));
    assert_eq!(state.session.temporary_rules, vec![rule.clone()]);
    assert_eq!(
        state.session.session_request.unwrap().temporary_rules,
        vec![rule]
    );
    assert!(
        state
            .operation_error
            .unwrap()
            .starts_with("Changes were not applied: ")
    );
}

#[test]
fn removing_temporary_rule_applies_and_rolls_back_on_error() {
    let mut state = connected_state_for_apply();
    let rule = temporary_rule("t1", "session.example");
    state.session.temporary_rules.push(rule.clone());
    state
        .session
        .session_request
        .as_mut()
        .unwrap()
        .temporary_rules
        .push(rule.clone());
    let Some(Job::Apply(request)) = state.act(Action::RemoveTemporary(rule.id.clone())) else {
        panic!("remove must apply");
    };
    assert!(request.temporary_rules.is_empty());
    assert!(state.session.temporary_rules.is_empty());
    state.reduce(WorkerEvent::Apply(Err(HelperCommandError::Client(
        ClientError::Helper(HelperError::new(ErrorCode::Busy, "busy")),
    ))));
    assert_eq!(state.session.temporary_rules, vec![rule.clone()]);
    let Some(Job::Apply(request)) = state.act(Action::RemoveTemporary(rule.id)) else {
        panic!("remove must remain retryable");
    };
    state.reduce(WorkerEvent::Apply(Ok(*request)));
    assert!(state.session.temporary_rules.is_empty());
    assert!(
        state
            .session
            .session_request
            .unwrap()
            .temporary_rules
            .is_empty()
    );
}

#[test]
fn keeping_temporary_rule_saves_first_then_applies_without_the_overlay() {
    let mut state = connected_state_for_apply();
    let rule = temporary_rule("t1", "session.example");
    state.session.temporary_rules.push(rule.clone());
    state
        .session
        .session_request
        .as_mut()
        .unwrap()
        .temporary_rules
        .push(rule.clone());
    state.rules.screen.selected_set = Some(RuleSetId::new("1"));
    assert!(matches!(
        state.act(Action::KeepTemporary(rule.id.clone())),
        Some(Job::AddRules(set, matchers, RuleTarget::Direct))
            if set == RuleSetId::new("1") && matchers == vec![rule.matcher.clone()]
    ));
    assert!(state.take_keep_apply().is_none());
    let permanent = Rule {
        id: RuleId::new("4"),
        ..rule.clone()
    };
    state.config.rule_sets[0].rules.insert(0, permanent.clone());
    state.reduce(WorkerEvent::AddRules(Ok(rosetun_core::AddedRules {
        added: vec![permanent],
        skipped: 0,
    })));
    let Some(Job::Apply(request)) = state.take_keep_apply() else {
        panic!("keep must apply after the permanent rule is saved");
    };
    assert!(request.temporary_rules.is_empty());
    assert_eq!(request.rule_set.rules[0].id, RuleId::new("4"));
    state.reduce(WorkerEvent::Apply(Ok(*request)));
    assert!(state.session.temporary_rules.is_empty());
    assert!(!state.pending_reconnect(SessionPart::Rules));
}

#[test]
fn keep_failure_leaves_temporary_rule_in_place() {
    let mut state = connected_state_for_apply();
    let rule = temporary_rule("t1", "session.example");
    state.session.temporary_rules.push(rule.clone());
    state.rules.screen.selected_set = Some(RuleSetId::new("1"));
    assert!(matches!(
        state.act(Action::KeepTemporary(rule.id.clone())),
        Some(Job::AddRules(_, _, _))
    ));
    state.reduce(WorkerEvent::AddRules(Err(
        rosetun_core::RuleSetError::DuplicateRule,
    )));
    assert!(state.take_keep_apply().is_none());
    assert_eq!(state.session.temporary_rules, vec![rule]);
    assert!(state.operation_error.is_some());
}

#[test]
fn terminal_status_clears_temporary_rules_and_ignores_late_loads() {
    for status in [
        ConnectionState::Disconnected,
        ConnectionState::Failed {
            failure_kind: None,
            reason: "failed".into(),
        },
        ConnectionState::FailedProtected {
            failure_kind: None,
            reason: "blocked".into(),
        },
    ] {
        let mut state = connected_state_for_apply();
        state
            .session
            .temporary_rules
            .push(temporary_rule("t1", "session.example"));
        state.reduce(WorkerEvent::Status(Status {
            state: status,
            ..Status::default()
        }));
        assert!(state.session.temporary_rules.is_empty());
        assert!(!state.session.temporary_rules_loaded);
    }
    let mut state = state_for_auto_connect();
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        ..Status::default()
    }));
    let Some(Job::LoadTemporaryRules(request)) = state.take_temporary_load(1_000) else {
        panic!("connected status must load temporary rules");
    };
    state.reduce(WorkerEvent::HelperUnavailable(ClientError::Helper(
        HelperError::new(ErrorCode::Internal, "gone"),
    )));
    state.reduce(WorkerEvent::TemporaryRules {
        request,
        result: Ok(vec![temporary_rule("t1", "stale.example")]),
    });
    assert!(state.session.temporary_rules.is_empty());
}

#[test]
fn late_apply_cannot_restore_rules_after_disconnect() {
    let mut state = connected_state_for_apply();
    temporary_dialog(&mut state, "session.example");
    let Some(Job::Apply(request)) = state.act(Action::SubmitAddRule) else {
        panic!("temporary rule must apply");
    };
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Disconnected,
        ..Status::default()
    }));
    state.reduce(WorkerEvent::Apply(Ok(*request)));
    assert!(state.session.temporary_rules.is_empty());
    assert!(state.session.session_request.is_none());
}

#[test]
fn successful_connect_has_no_pending_changes_until_dns_or_protection_changes() {
    let mut state = state_for_auto_connect();
    let request = ConnectRequest::from_config(&state.config).unwrap();
    state.reduce(WorkerEvent::Connect(Ok(request.clone())));
    assert_eq!(state.session.session_request, Some(request));
    for part in [
        SessionPart::Server,
        SessionPart::Rules,
        SessionPart::Dns,
        SessionPart::Protection,
    ] {
        assert!(!state.pending_reconnect(part));
    }

    state.config.settings.dns = DnsPreset::Google.settings();
    assert!(state.pending_reconnect(SessionPart::Dns));
    assert!(!state.pending_reconnect(SessionPart::Rules));
    assert!(!state.pending_reconnect(SessionPart::Protection));

    state.config.settings.kill_switch = !state.config.settings.kill_switch;
    assert!(state.pending_reconnect(SessionPart::Protection));
    assert!(state.pending_reconnect(SessionPart::Dns));
    assert!(!state.pending_reconnect(SessionPart::Rules));

    state.config.active = None;
    for part in [
        SessionPart::Server,
        SessionPart::Rules,
        SessionPart::Dns,
        SessionPart::Protection,
    ] {
        assert!(!state.pending_reconnect(part));
    }
}

#[test]
fn selecting_a_server_applies_once_with_the_running_protection() {
    let mut state = connected_state_for_apply();
    let mut other = state.config.subscriptions[0].nodes[0].clone();
    other.id = NodeId::new("other");
    state.config.subscriptions[0].nodes.push(other);
    let selection = Selection {
        subscription: SubscriptionId::new("1"),
        node: NodeId::new("other"),
    };
    let original = state.session.session_request.clone().unwrap();
    state.config.settings.kill_switch = !original.settings.kill_switch;
    state.config.settings.allow_lan = !original.settings.allow_lan;

    assert!(matches!(
        state.act(Action::SelectNode(
            selection.subscription.clone(),
            selection.node.clone()
        )),
        Some(Job::SelectNode(_, _))
    ));
    state.config.active = Some(selection.clone());
    state.reduce(WorkerEvent::SelectNode(Ok("Other".into())));
    assert!(state.pending_reconnect(SessionPart::Server));
    let Some(Job::Apply(request)) = state.take_apply() else {
        panic!("server choice must apply");
    };
    assert_eq!(request.selection, selection);
    assert_eq!(request.settings.kill_switch, original.settings.kill_switch);
    assert_eq!(request.settings.allow_lan, original.settings.allow_lan);
    assert!(state.operations.helper);
    assert!(
        state
            .act(Action::SelectNode(
                SubscriptionId::new("1"),
                NodeId::new("node")
            ))
            .is_none()
    );
    assert!(state.take_apply().is_none());
}

#[test]
fn server_choice_during_reconnect_does_not_apply() {
    let mut state = connected_state_for_apply();
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Reconnecting,
        ..Status::default()
    }));
    let mut other = state.config.subscriptions[0].nodes[0].clone();
    other.id = NodeId::new("other");
    state.config.subscriptions[0].nodes.push(other);
    state.config.active.as_mut().unwrap().node = NodeId::new("other");
    state.reduce(WorkerEvent::SelectNode(Ok("Other".into())));
    assert!(state.pending_reconnect(SessionPart::Server));
    assert!(!state.can_apply());
    assert!(state.take_apply().is_none());
}

#[test]
fn choosing_rule_set_applies_but_editing_a_rule_waits_for_apply() {
    let mut state = connected_state_for_apply();
    state.config.rule_sets.push(rule_set("2"));
    assert!(matches!(
        state.act(Action::SelectRuleSet(Some(RuleSetId::new("2")))),
        Some(Job::SelectRuleSet(_))
    ));
    state.config.active_rule_set = Some(RuleSetId::new("2"));
    state.reduce(WorkerEvent::SelectRuleSet(Ok(())));
    let Some(Job::Apply(request)) = state.take_apply() else {
        panic!("rule-set choice must apply");
    };
    state.reduce(WorkerEvent::Apply(Ok(*request)));

    state.config.rule_sets[1].rules[0].target = RuleTarget::Direct;
    assert!(state.pending_reconnect(SessionPart::Rules));
    assert!(state.take_apply().is_none());
    assert!(matches!(state.act(Action::Apply), Some(Job::Apply(_))));
    assert!(state.act(Action::Apply).is_none());
}

#[test]
fn selected_rule_set_waits_for_the_helper_overlay_before_applying() {
    let mut state = connected_state_for_apply();
    state.session.temporary_rules_loaded = false;
    state.config.rule_sets.push(rule_set("2"));
    state.config.active_rule_set = Some(RuleSetId::new("2"));
    state.reduce(WorkerEvent::SelectRuleSet(Ok(())));
    assert!(state.take_apply().is_none());
    assert!(state.session.apply_after_choice);
    state.session.temporary_load = Some(1);
    let temporary = temporary_rule("t1", "session.example");
    state.reduce(WorkerEvent::TemporaryRules {
        request: 1,
        result: Ok(vec![temporary.clone()]),
    });
    let Some(Job::Apply(request)) = state.take_apply() else {
        panic!("rule-set choice must apply after loading temporary rules");
    };
    assert_eq!(request.temporary_rules, vec![temporary]);
    assert_eq!(request.rule_set.id, RuleSetId::new("2"));
}

#[test]
fn selecting_the_same_server_consumes_auto_apply_without_a_job() {
    let mut state = connected_state_for_apply();
    state.reduce(WorkerEvent::SelectNode(Ok("Test".into())));
    assert!(state.take_apply().is_none());
    assert!(!state.session.apply_after_choice);
}

#[test]
fn protection_only_cannot_apply() {
    let mut state = connected_state_for_apply();
    state.config.settings.kill_switch = !state.config.settings.kill_switch;
    assert!(state.pending_reconnect(SessionPart::Protection));
    assert!(!state.can_apply());
    assert!(state.act(Action::Apply).is_none());
}

#[test]
fn applying_changes_refreshes_the_session_exit_and_delay() {
    let mut state = connected_state_for_apply();
    let mut other = state.config.subscriptions[0].nodes[0].clone();
    other.id = NodeId::new("other");
    state.config.subscriptions[0].nodes.push(other);
    state.config.active.as_mut().unwrap().node = NodeId::new("other");
    state.config.rule_sets[0].rules[0].target = RuleTarget::Direct;
    state.config.settings.dns = DnsPreset::Google.settings();
    assert!(state.pending_reconnect(SessionPart::Server));
    assert!(state.pending_reconnect(SessionPart::Rules));
    assert!(state.pending_reconnect(SessionPart::Dns));
    assert!(matches!(
        state.take_exit_lookup(),
        Some(Job::LookupExit { .. })
    ));
    state.exit = ExitLookup::Failed(ExitRoute::Tunnel);
    state.tunnel_delay = TunnelDelay::Done(ProbeOutcome::Fails);
    state.delay_last_auto = Some(now_unix());
    let Some(Job::Apply(request)) = state.act(Action::Apply) else {
        panic!("DNS change must apply");
    };
    state.reduce(WorkerEvent::Apply(Ok(*request.clone())));
    assert_eq!(
        state.session.session_request.as_ref(),
        Some(request.as_ref())
    );
    assert!(!state.pending_reconnect(SessionPart::Server));
    assert!(!state.pending_reconnect(SessionPart::Rules));
    assert!(!state.pending_reconnect(SessionPart::Dns));
    assert!(matches!(
        state.take_exit_lookup(),
        Some(Job::LookupExit {
            route: ExitRoute::Tunnel,
            ..
        })
    ));
    assert_eq!(state.tunnel_delay, TunnelDelay::Idle);
    assert!(state.delay_last_auto.is_none());
    assert!(!state.operations.helper);
}

#[test]
fn failed_apply_preserves_session_and_shows_error() {
    let mut state = connected_state_for_apply();
    let original = state.session.session_request.clone();
    state.config.settings.dns = DnsPreset::Google.settings();
    assert!(matches!(state.act(Action::Apply), Some(Job::Apply(_))));
    state.reduce(WorkerEvent::Apply(Err(HelperCommandError::Client(
        ClientError::Helper(HelperError::new(ErrorCode::Busy, "busy")),
    ))));
    assert_eq!(state.session.session_request, original);
    let failed = complete_applied_restore(&mut state);
    assert_eq!(state.session.failed_edits, Some(failed));
    assert!(!state.pending_reconnect(SessionPart::Dns));
    assert!(
        state
            .session
            .apply_failure
            .as_deref()
            .unwrap()
            .starts_with("The rules could not be applied: ")
    );
    assert!(!state.operations.helper);
    assert!(!state.can_apply());
}

#[test]
fn successful_connections_and_applies_capture_unexpanded_rule_sets() {
    let mut state = state_for_auto_connect();
    let mut set = rule_set("1");
    set.rules[0].matcher = RuleMatcher::Template(RuleTemplate::Youtube);
    state.config.rule_sets.push(set.clone());
    state.config.active_rule_set = Some(set.id.clone());
    let running = AppliedSnapshot::from_config(&state.config);
    let request = ConnectRequest::from_config(&state.config).unwrap();
    assert!(
        request
            .rule_set
            .rules
            .iter()
            .all(|rule| !matches!(rule.matcher, RuleMatcher::Template(_)))
    );

    state.connect_in_flight = true;
    state.reduce(WorkerEvent::ConnectSnapshot(running.clone()));
    state.config.rule_sets[0].rules[0].target = RuleTarget::Direct;
    state.reduce(WorkerEvent::Connect(Ok(request)));
    assert_eq!(state.session.applied_snapshot, Some(running.clone()));
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        node: Some(NodeId::new("node")),
        ..Status::default()
    }));
    let candidate = AppliedSnapshot::from_config(&state.config);
    let Some(Job::Apply(request)) = state.act(Action::Apply) else {
        panic!("changed template must apply");
    };
    assert_eq!(state.session.applied_snapshot, Some(running));
    state.reduce(WorkerEvent::Apply(Ok(*request)));
    assert_eq!(state.session.applied_snapshot, Some(candidate));
    assert!(matches!(
        state
            .session
            .applied_snapshot
            .as_ref()
            .unwrap()
            .rule_set
            .as_ref()
            .unwrap()
            .rules[0]
            .matcher,
        RuleMatcher::Template(RuleTemplate::Youtube)
    ));
    state.reduce(WorkerEvent::Status(Status::default()));
    assert!(state.session.applied_snapshot.is_none());
}

#[test]
fn unsupported_rules_and_terminal_apply_failures_restore_config() {
    for terminal in [
        None,
        Some(ConnectionState::Failed {
            failure_kind: None,
            reason: "failed".into(),
        }),
        Some(ConnectionState::FailedProtected {
            failure_kind: None,
            reason: "blocked".into(),
        }),
    ] {
        let mut state = connected_state_for_apply();
        let running = state.session.applied_snapshot.clone().unwrap();
        state.config.rule_sets[0].rules[0].target = RuleTarget::Block;
        state.config.settings.dns = DnsPreset::Google.settings();
        assert!(matches!(state.act(Action::Apply), Some(Job::Apply(_))));
        state.act(Action::OpenRules);
        assert!(state.act(Action::ShowConnection).is_none());
        assert!(state.session.apply_after_leave);
        if let Some(terminal) = terminal {
            state.reduce(WorkerEvent::Status(Status {
                state: terminal,
                ..Status::default()
            }));
        }
        state.reduce(WorkerEvent::Apply(Err(HelperCommandError::Client(
            ClientError::Helper(HelperError::new(ErrorCode::UnsupportedRules, "unsupported")),
        ))));
        assert!(state.take_apply().is_none());
        assert!(state.session.restore_pending);
        let failed = complete_applied_restore(&mut state);
        assert_eq!(state.session.failed_edits, Some(failed));
        assert_eq!(AppliedSnapshot::from_config(&state.config), running);
        assert!(state.session.apply_failure.is_some());
        assert!(state.take_apply().is_none());
        assert!(state.apply_on_leave().is_none());
    }
}

#[test]
fn restore_my_edits_makes_the_failed_variant_pending_again() {
    let mut state = connected_state_for_apply();
    state.config.rule_sets[0].rules[0].target = RuleTarget::Direct;
    state.config.settings.dns = DnsPreset::Google.settings();
    state.act(Action::Apply);
    state.reduce(WorkerEvent::Apply(Err(HelperCommandError::Client(
        ClientError::Helper(HelperError::new(ErrorCode::Busy, "busy")),
    ))));
    let failed = complete_applied_restore(&mut state);
    state.act(Action::OpenRules);
    let Some(Job::RestoreEdits(edited)) = state.act(Action::RestoreMyEdits) else {
        panic!("the recovery link must save the failed variant");
    };
    assert_eq!(edited, failed);
    assert!(state.act(Action::ShowConnection).is_none());
    let mut config = state.config.clone();
    config.rule_sets[0] = edited.rule_set.unwrap();
    config.settings.dns = edited.dns;
    state.reduce(WorkerEvent::Config {
        generation: state.config_generation + 1,
        config,
    });
    state.reduce(WorkerEvent::RestoreEdits(Ok(failed)));
    assert!(state.session.failed_edits.is_none());
    assert!(state.session.apply_failure.is_none());
    assert!(state.can_apply());
    state.act(Action::OpenRules);
    assert!(matches!(
        state.act(Action::ShowConnection),
        Some(Job::Apply(_))
    ));
}

#[test]
fn failed_disk_rollback_does_not_claim_the_rules_were_restored() {
    let mut state = connected_state_for_apply();
    state.config.settings.dns = DnsPreset::Google.settings();
    state.act(Action::Apply);
    state.reduce(WorkerEvent::Apply(Err(HelperCommandError::Client(
        ClientError::Helper(HelperError::new(ErrorCode::Busy, "busy")),
    ))));
    assert!(matches!(state.take_restore(), Some(Job::RestoreApplied(_))));
    state.reduce(WorkerEvent::RestoreApplied(Err(
        rosetun_core::RuleSetError::Store(StoreError::NoConfigDir),
    )));
    assert!(state.session.apply_failure.is_none());
    assert!(state.session.failed_edits.is_none());
    assert!(
        state
            .operation_error
            .as_deref()
            .unwrap()
            .contains("Could not restore")
    );
    state.act(Action::OpenSettings);
    assert!(state.act(Action::ShowConnection).is_none());
    assert!(matches!(state.act(Action::Apply), Some(Job::Apply(_))));
}

#[test]
fn active_status_during_connect_does_not_replace_the_submitted_request() {
    let mut state = state_for_auto_connect();
    let request = ConnectRequest::from_config(&state.config).unwrap();
    state.operations.helper = true;
    state.config.settings.dns = DnsPreset::Google.settings();
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        node: Some(NodeId::new("node")),
        ..Status::default()
    }));
    assert!(state.session.session_request.is_none());
    state.reduce(WorkerEvent::Connect(Ok(request)));
    assert!(state.pending_reconnect(SessionPart::Dns));
}

#[test]
fn rule_change_in_active_set_remains_pending_until_reverted() {
    let mut state = state_for_auto_connect();
    state.config.rule_sets.push(rule_set("1"));
    state.config.active_rule_set = Some(RuleSetId::new("1"));
    let request = ConnectRequest::from_config(&state.config).unwrap();
    state.reduce(WorkerEvent::Connect(Ok(request)));

    state.config.rule_sets[0].rules[0].target = RuleTarget::Direct;
    assert!(state.pending_reconnect(SessionPart::Rules));
    assert!(!state.pending_reconnect(SessionPart::Dns));
    state.config.rule_sets[0].rules[0].target = RuleTarget::Proxy;
    assert!(!state.pending_reconnect(SessionPart::Rules));
}

#[test]
fn disconnected_and_failed_statuses_clear_session_request_but_reconnecting_does_not() {
    for status in [
        ConnectionState::Disconnected,
        ConnectionState::Failed {
            failure_kind: None,
            reason: "failed".into(),
        },
        ConnectionState::FailedProtected {
            failure_kind: None,
            reason: "blocked".into(),
        },
    ] {
        let mut state = state_for_auto_connect();
        let request = ConnectRequest::from_config(&state.config).unwrap();
        state.reduce(WorkerEvent::Connect(Ok(request)));
        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Reconnecting,
            ..Status::default()
        }));
        assert!(state.session.session_request.is_some());
        state.reduce(WorkerEvent::Status(Status {
            state: status,
            ..Status::default()
        }));
        assert!(state.session.session_request.is_none());
        assert!(!state.pending_reconnect(SessionPart::Rules));
    }
}

#[test]
fn active_status_seeds_session_only_once_and_only_for_the_selected_node() {
    let mut matching = state_for_auto_connect();
    matching.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        node: Some(NodeId::new("node")),
        ..Status::default()
    }));
    assert_eq!(
        matching.session.session_request,
        Some(ConnectRequest::from_config(&matching.config).unwrap())
    );
    assert!(!matching.pending_reconnect(SessionPart::Dns));

    let mut mismatched = state_for_auto_connect();
    mismatched.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        node: Some(NodeId::new("other")),
        ..Status::default()
    }));
    assert!(mismatched.session.session_request.is_none());
    mismatched.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        node: Some(NodeId::new("node")),
        ..Status::default()
    }));
    assert!(mismatched.session.session_request.is_none());

    let mut missing_selection = state_for_auto_connect();
    missing_selection.config.active = None;
    missing_selection.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        node: Some(NodeId::new("node")),
        ..Status::default()
    }));
    assert!(missing_selection.session.session_request.is_none());
    assert!(!missing_selection.pending_reconnect(SessionPart::Dns));
}

#[test]
fn grouped_edit_while_connected_requires_explicit_apply() {
    let mut state = connected_state_for_apply();
    state.session.temporary_rules_loaded = true;
    state.act(Action::OpenRules);
    state.act(Action::SelectRule {
        rule: RuleId::new("0"),
        additive: false,
        range: false,
    });
    state.act(Action::SelectRule {
        rule: RuleId::new("2"),
        additive: true,
        range: false,
    });
    assert!(matches!(
        state.act(Action::MoveSelectedRulesToEnd),
        Some(Job::MoveRules(_, _, 1))
    ));
    let mut config = state.config.clone();
    let first = config.rule_sets[0].rules.remove(0);
    let last = config.rule_sets[0].rules.remove(1);
    config.rule_sets[0].rules.extend([first, last]);
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config,
    });
    state.reduce(WorkerEvent::MoveRules(Ok(())));
    assert!(state.pending_reconnect(SessionPart::Rules));
    assert!(state.can_apply());
    assert!(state.take_apply().is_none());
    state.act(Action::RequestDeleteSelectedRules);
    assert!(matches!(
        state.act(Action::ConfirmRuleDelete),
        Some(Job::RemoveRules(_, _))
    ));
    let mut config = state.config.clone();
    config.rule_sets[0]
        .rules
        .retain(|rule| !state.rules.screen.selected_rules.contains(&rule.id));
    state.reduce(WorkerEvent::Config {
        generation: 2,
        config,
    });
    state.reduce(WorkerEvent::RemoveRules(Ok(())));
    assert!(state.rules.screen.selected_rules.is_empty());
    assert!(state.pending_reconnect(SessionPart::Rules));
    assert!(state.can_apply());
    assert!(state.take_apply().is_none());
}
