use super::*;

#[test]
fn rule_selection_click_toggle_and_visible_range() {
    let mut state = state_with_rules();
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
    assert_eq!(
        state.rules.screen.selected_rules,
        [RuleId::new("0"), RuleId::new("2")].into()
    );
    state.act(Action::SelectRule {
        rule: RuleId::new("0"),
        additive: true,
        range: false,
    });
    assert_eq!(state.rules.screen.selected_rules, [RuleId::new("2")].into());
    state.act(Action::SelectRule {
        rule: RuleId::new("0"),
        additive: false,
        range: true,
    });
    assert_eq!(
        state.rules.screen.selected_rules,
        [RuleId::new("0"), RuleId::new("1"), RuleId::new("2")].into()
    );

    state.act(Action::SetRuleTypeFilter(TypeFilter::Processes));
    assert!(state.rules.screen.selected_rules.is_empty());
    state.act(Action::SetRuleTypeFilter(TypeFilter::All));
    state.config.rule_sets[1].rules[1].target = RuleTarget::Direct;
    state.act(Action::SetRuleTargetFilter(Some(RuleTarget::Proxy)));
    state.act(Action::SelectRule {
        rule: RuleId::new("0"),
        additive: false,
        range: false,
    });
    state.act(Action::SelectRule {
        rule: RuleId::new("2"),
        additive: false,
        range: true,
    });
    assert_eq!(
        state.rules.screen.selected_rules,
        [RuleId::new("0"), RuleId::new("2")].into()
    );
}

#[test]
fn select_all_ignores_temporary_and_unknown_rules_and_clears_on_set_change() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    state.rules.screen.filter.search = "second".into();
    state.act(Action::SelectVisibleRules);
    assert_eq!(state.rules.screen.selected_rules, [RuleId::new("1")].into());
    state.act(Action::SelectRule {
        rule: RuleId::new("t1"),
        additive: true,
        range: false,
    });
    state.act(Action::SelectRule {
        rule: RuleId::new("missing"),
        additive: true,
        range: false,
    });
    assert_eq!(state.rules.screen.selected_rules, [RuleId::new("1")].into());
    state.act(Action::ChooseRuleSet(RuleSetId::new("1")));
    assert!(state.rules.screen.selected_rules.is_empty());
    assert!(state.rules.screen.selection_anchor.is_none());
    state.rules.screen.filter.search.clear();
    state.act(Action::SelectVisibleRules);
    assert_eq!(state.rules.screen.selected_rules.len(), 3);
    state.act(Action::ClearRuleSelection);
    assert!(state.rules.screen.selected_rules.is_empty());
}

#[test]
fn configuration_reload_prunes_missing_rule_ids_and_anchor() {
    let mut state = state_with_rules();
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
    let mut config = state.config.clone();
    config.rule_sets[1]
        .rules
        .retain(|rule| rule.id != RuleId::new("2"));
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config,
    });
    assert_eq!(state.rules.screen.selected_rules, [RuleId::new("0")].into());
    assert!(state.rules.screen.selection_anchor.is_none());
    state.act(Action::OpenActiveRules);
    assert_eq!(state.rules.screen.selected_rules, [RuleId::new("0")].into());
}

#[test]
fn opening_and_reloading_rules_selects_active_then_first_if_missing() {
    let mut state = state_with_rules();
    assert_eq!(state.screen, Screen::Connection);
    state.act(Action::OpenRules);
    assert_eq!(state.screen, Screen::Rules);
    assert_eq!(state.rules.screen.selected_set, Some(RuleSetId::new("2")));
    state.act(Action::ChooseRuleSet(RuleSetId::new("1")));
    state.act(Action::ShowConnection);
    state.act(Action::OpenRules);
    assert_eq!(state.rules.screen.selected_set, Some(RuleSetId::new("1")));
    state.act(Action::OpenActiveRules);
    assert_eq!(state.rules.screen.selected_set, Some(RuleSetId::new("2")));
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config: AppConfig {
            rule_sets: vec![rule_set("1")],
            ..AppConfig::default()
        },
    });
    assert_eq!(state.rules.screen.selected_set, Some(RuleSetId::new("1")));
    state.reduce(WorkerEvent::Config {
        generation: 2,
        config: AppConfig::default(),
    });
    assert!(state.rules.screen.selected_set.is_none());
    state.reduce(WorkerEvent::Config {
        generation: 3,
        config: AppConfig {
            rule_sets: vec![rule_set("3"), rule_set("4")],
            ..AppConfig::default()
        },
    });
    assert_eq!(state.rules.screen.selected_set, Some(RuleSetId::new("3")));

    let mut before_load = State::default();
    before_load.act(Action::OpenRules);
    before_load.reduce(WorkerEvent::Config {
        generation: 1,
        config: state_with_rules().config,
    });
    assert_eq!(
        before_load.rules.screen.selected_set,
        Some(RuleSetId::new("2"))
    );
    let mut no_active = state_with_rules();
    no_active.config.active_rule_set = None;
    no_active.act(Action::OpenRules);
    assert_eq!(
        no_active.rules.screen.selected_set,
        Some(RuleSetId::new("1"))
    );
    no_active.act(Action::ChooseRuleSet(RuleSetId::new("2")));
    no_active.reduce(WorkerEvent::Config {
        generation: 1,
        config: AppConfig {
            rule_sets: vec![rule_set("1")],
            active_rule_set: Some(RuleSetId::new("1")),
            ..AppConfig::default()
        },
    });
    assert_eq!(
        no_active.rules.screen.selected_set,
        Some(RuleSetId::new("1"))
    );
}

#[test]
fn set_name_dialog_keeps_errors_and_success_selects_created_set() {
    let mut state = state_with_rules();
    state.act(Action::OpenCreateSet);
    assert_eq!(state.rules.screen.name.as_ref().unwrap().name, tr!("basic"));
    state.rules.screen.name.as_mut().unwrap().name = "   ".into();
    assert!(state.act(Action::SubmitSetName).is_none());
    state.rules.screen.name.as_mut().unwrap().name = "  Work  ".into();
    assert!(matches!(
        state.act(Action::SubmitSetName),
        Some(Job::CreateRuleSet(name)) if name == "Work"
    ));
    assert!(state.operations.rules_edit);
    assert!(state.act(Action::CancelSetName).is_none());
    assert!(state.rules.screen.name.is_some());
    state.reduce(WorkerEvent::CreateRuleSet(Err(RuleSetError::EmptyName)));
    assert!(!state.operations.rules_edit);
    assert!(state.operation_error.is_none());
    assert_eq!(
        state.rules.screen.name.as_ref().unwrap().error.as_deref(),
        Some("rule set name must not be empty")
    );
    state.reduce(WorkerEvent::CreateRuleSet(Ok(rule_set("3"))));
    assert_eq!(state.rules.screen.selected_set, Some(RuleSetId::new("3")));
    assert!(state.rules.screen.name.is_none());

    state.act(Action::ChooseRuleSet(RuleSetId::new("1")));
    state.act(Action::OpenRenameSet);
    assert!(matches!(
        state.act(Action::SubmitSetName),
        Some(Job::RenameRuleSet(_, _))
    ));
    state.reduce(WorkerEvent::RenameRuleSet(Err(RuleSetError::SetNotFound)));
    assert!(!state.operations.rules_edit);
    assert!(state.operation_error.is_none());
    assert!(state.rules.screen.name.as_ref().unwrap().error.is_some());
    state.reduce(WorkerEvent::RenameRuleSet(Ok(())));
    assert!(state.rules.screen.name.is_none());
}

#[test]
fn all_rule_operation_errors_clear_busy_and_use_shared_error() {
    let events = [
        WorkerEvent::DeleteRuleSet(Err(RuleSetError::SetNotFound)),
        WorkerEvent::SetDefaultTarget(Err(RuleSetError::SetNotFound)),
        WorkerEvent::AddRule(Err(RuleSetError::DuplicateRule)),
        WorkerEvent::SetRuleTarget(Err(RuleSetError::RuleNotFound)),
        WorkerEvent::SetRuleEnabled(Err(RuleSetError::RuleNotFound)),
        WorkerEvent::MoveRule(Err(RuleSetError::RuleNotFound)),
        WorkerEvent::MoveRules(Err(RuleSetError::RuleNotFound)),
        WorkerEvent::RemoveRule(Err(RuleSetError::RuleNotFound)),
        WorkerEvent::RemoveRules(Err(RuleSetError::RuleNotFound)),
    ];
    for event in events {
        let mut state = state_with_rules();
        state.operations.rules_edit = true;
        state.reduce(event);
        assert!(!state.operations.rules_edit);
        assert!(state.operation_error.is_some());
    }
    let events = [
        WorkerEvent::DeleteRuleSet(Ok(())),
        WorkerEvent::SetDefaultTarget(Ok(())),
        WorkerEvent::AddRule(Ok(rule_set("1").rules[0].clone())),
        WorkerEvent::SetRuleTarget(Ok(())),
        WorkerEvent::SetRuleEnabled(Ok(())),
        WorkerEvent::MoveRule(Ok(())),
        WorkerEvent::MoveRules(Ok(())),
        WorkerEvent::RemoveRule(Ok(())),
        WorkerEvent::RemoveRules(Ok(())),
    ];
    for event in events {
        let mut state = state_with_rules();
        state.operations.rules_edit = true;
        state.operation_error = Some("old error".into());
        state.reduce(event);
        assert!(!state.operations.rules_edit);
        assert!(state.operation_error.is_none());
    }
}

#[test]
fn set_deletion_requires_confirmation_and_reports_errors_outside_dialog() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    assert!(state.act(Action::ConfirmRuleDelete).is_none());
    state.act(Action::RequestDeleteSet);
    assert!(matches!(
        state.rules.screen.delete,
        Some(DeleteDialog::Set(_))
    ));
    assert!(matches!(
        state.act(Action::ConfirmRuleDelete),
        Some(Job::DeleteRuleSet(id)) if id == RuleSetId::new("2")
    ));
    assert!(state.act(Action::CancelRuleDelete).is_none());
    state.reduce(WorkerEvent::DeleteRuleSet(Err(RuleSetError::SetNotFound)));
    assert!(state.rules.screen.delete.is_none());
    assert_eq!(
        state.operation_error.as_deref(),
        Some("rule set does not exist")
    );
}

#[cfg(windows)]
#[test]
fn browse_executable_requires_an_idle_process_dialog() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    assert!(state.act(Action::BrowseExecutable).is_none());
    assert!(matches!(
        state.act(Action::OpenAddRule),
        Some(Job::LoadProcesses(_))
    ));
    state.rules.screen.add.as_mut().unwrap().busy = true;
    assert!(state.act(Action::BrowseExecutable).is_none());
    state.rules.screen.add.as_mut().unwrap().busy = false;
    assert!(matches!(
        state.act(Action::BrowseExecutable),
        Some(Job::BrowseExecutable)
    ));
    assert!(state.rules.screen.add.as_ref().unwrap().browsing);
    assert!(state.act(Action::BrowseExecutable).is_none());
}

#[cfg(windows)]
#[test]
fn browsed_executable_uses_the_selected_match_mode_and_clears_process_selection() {
    for (mode, expected) in [
        (ProcessMatchMode::Name, "Tool.exe"),
        (ProcessMatchMode::Path, r"C:\Apps\Tool.exe"),
    ] {
        let mut state = state_with_rules();
        state.act(Action::OpenRules);
        state.act(Action::OpenAddRule);
        state.act(Action::SelectRuleInput(RuleInputKind::Process));
        let dialog = state.rules.screen.add.as_mut().unwrap();
        dialog.match_mode = mode;
        dialog.selected_process = Some(0);
        dialog.processes.push(ProcessGroup {
            name: "Other.exe".into(),
            path: Some(r"C:\Apps\Other.exe".into()),
            count: 1,
            windowed: false,
        });
        dialog.process = "Other.exe".into();
        dialog.error = Some("previous error".into());
        dialog.focus_input = false;
        assert!(matches!(
            state.act(Action::BrowseExecutable),
            Some(Job::BrowseExecutable)
        ));
        let path = PathBuf::from(r"C:\Apps\Tool.exe");
        state.reduce(WorkerEvent::BrowsedExecutable(Some(path.clone())));
        let dialog = state.rules.screen.add.as_ref().unwrap();
        assert!(!dialog.browsing);
        assert_eq!(dialog.browsed.as_ref(), Some(&path));
        assert_eq!(dialog.process, expected);
        assert_eq!(dialog.selected_process, None);
        assert!(dialog.error.is_none());
        assert!(dialog.focus_input);
    }
}

#[cfg(windows)]
#[test]
fn cancelled_or_late_browse_does_not_replace_input() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    state.act(Action::OpenAddRule);
    state.act(Action::SelectRuleInput(RuleInputKind::Process));
    state.rules.screen.add.as_mut().unwrap().process = "current.exe".into();
    state.act(Action::BrowseExecutable);
    state.reduce(WorkerEvent::BrowsedExecutable(None));
    let dialog = state.rules.screen.add.as_ref().unwrap();
    assert!(!dialog.browsing);
    assert_eq!(dialog.process, "current.exe");
    assert!(dialog.browsed.is_none());

    state.act(Action::BrowseExecutable);
    state.act(Action::SelectRuleInput(RuleInputKind::Domain));
    state.reduce(WorkerEvent::BrowsedExecutable(Some(
        r"C:\Apps\Tool.exe".into(),
    )));
    let dialog = state.rules.screen.add.as_ref().unwrap();
    assert!(!dialog.browsing);
    assert_eq!(dialog.process, "current.exe");
    assert!(dialog.browsed.is_none());

    state.act(Action::SelectRuleInput(RuleInputKind::Process));
    state.act(Action::BrowseExecutable);
    state.act(Action::CancelAddRule);
    state.reduce(WorkerEvent::BrowsedExecutable(Some(
        r"C:\Apps\Tool.exe".into(),
    )));
    assert!(state.rules.screen.add.is_none());
}

#[cfg(windows)]
#[test]
fn browsed_executable_switches_between_name_and_path_without_a_running_process() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    state.act(Action::OpenAddRule);
    state.act(Action::SelectRuleInput(RuleInputKind::Process));
    state.act(Action::BrowseExecutable);
    state.reduce(WorkerEvent::BrowsedExecutable(Some(
        r"C:\Apps\Tool.exe".into(),
    )));
    let dialog = state.rules.screen.add.as_mut().unwrap();
    assert_eq!(dialog.process, "Tool.exe");
    assert!(dialog.selected_process.is_none());
    dialog.set_process_match_mode(ProcessMatchMode::Path);
    assert_eq!(dialog.process, r"C:\Apps\Tool.exe");
    dialog.set_process_match_mode(ProcessMatchMode::Name);
    assert_eq!(dialog.process, "Tool.exe");
}

#[test]
fn process_results_fill_only_the_current_dialog_and_are_dropped_on_close() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    assert!(state.act(Action::RefreshProcesses).is_none());
    let Some(Job::LoadProcesses(first)) = state.act(Action::OpenAddRule) else {
        panic!("new rule must load the process tab");
    };
    assert!(state.act(Action::RefreshProcesses).is_none());
    state.reduce(WorkerEvent::Processes {
        request: first,
        result: Ok(vec![RunningProcess {
            pid: 100,
            name: "Telegram.exe".into(),
            path: Some(r"C:\Apps\Telegram.exe".into()),
            has_window: true,
        }]),
    });
    let dialog = state.rules.screen.add.as_ref().unwrap();
    assert!(dialog.processes_loaded);
    assert_eq!(dialog.processes[0].name, "Telegram.exe");
    assert_eq!(dialog.processes[0].count, 1);
    state.act(Action::CancelAddRule);
    assert!(state.rules.screen.add.is_none());

    let Some(Job::LoadProcesses(second)) = state.act(Action::OpenAddRule) else {
        panic!("reopened dialog must start a new worker job");
    };
    assert_ne!(first, second);
    state.reduce(WorkerEvent::Processes {
        request: first,
        result: Ok(vec![RunningProcess {
            pid: 101,
            name: "Old.exe".into(),
            path: None,
            has_window: false,
        }]),
    });
    assert!(
        state
            .rules
            .screen
            .add
            .as_ref()
            .unwrap()
            .processes
            .is_empty()
    );
    state.reduce(WorkerEvent::Processes {
        request: second,
        result: Err(rosetun_processes::ProcessListError::Snapshot(
            std::io::Error::from_raw_os_error(5),
        )),
    });
    let dialog = state.rules.screen.add.as_ref().unwrap();
    assert!(!dialog.processes_loaded);
    assert!(dialog.processes_error.is_some());
    assert!(matches!(
        state.act(Action::RefreshProcesses),
        Some(Job::LoadProcesses(_))
    ));
}

#[test]
fn site_batch_requires_every_line_to_be_valid_and_obeys_subdomain_toggle() {
    for (subdomains, expected) in [
        (
            true,
            vec![
                RuleMatcher::Domain(DomainMatch::Suffix("youtube.com".into())),
                RuleMatcher::Domain(DomainMatch::Suffix("instagram.com".into())),
            ],
        ),
        (
            false,
            vec![
                RuleMatcher::Domain(DomainMatch::Exact("www.youtube.com".into())),
                RuleMatcher::Domain(DomainMatch::Exact("instagram.com".into())),
            ],
        ),
    ] {
        let mut state = state_with_rules();
        state.act(Action::OpenRules);
        assert!(matches!(
            state.act(Action::OpenAddRule),
            Some(Job::LoadProcesses(_))
        ));
        assert_eq!(
            state.rules.screen.add.as_ref().unwrap().kind,
            RuleInputKind::Process
        );
        state.act(Action::SelectRuleInput(RuleInputKind::Domain));
        let dialog = state.rules.screen.add.as_mut().unwrap();
        dialog.domains = "https://www.youtube.com/watch?v=1\n192.168.1.1\ninstagram.com".into();
        dialog.subdomains = subdomains;
        assert!(state.act(Action::SubmitAddRule).is_none());
        state.rules.screen.add.as_mut().unwrap().domains =
            "https://www.youtube.com/watch?v=1\ninstagram.com".into();
        assert!(matches!(
            state.act(Action::SubmitAddRule),
            Some(Job::AddRules(_, matchers, RuleTarget::Proxy)) if matchers == expected
        ));
    }
}

#[test]
fn editing_a_suffix_rule_populates_the_site_form_and_saves_only_changes() {
    let mut state = state_with_rules();
    let id = state.config.rule_sets[1].rules[0].id.clone();
    state.config.rule_sets[1].rules[0].matcher =
        RuleMatcher::Domain(DomainMatch::Suffix("example.com".into()));
    state.config.rule_sets[1].rules[0].enabled = false;
    state.act(Action::OpenRules);
    assert!(state.act(Action::OpenEditRule(id.clone())).is_none());
    let dialog = state.rules.screen.add.as_ref().unwrap();
    assert_eq!(dialog.editing.as_ref(), Some(&id));
    assert_eq!(dialog.kind, RuleInputKind::Domain);
    assert_eq!(dialog.domains, "example.com");
    assert!(dialog.subdomains);
    state.act(Action::SelectRuleInput(RuleInputKind::Process));
    assert_eq!(
        state.rules.screen.add.as_ref().unwrap().kind,
        RuleInputKind::Domain
    );
    assert!(state.act(Action::SubmitAddRule).is_none());
    assert!(state.rules.screen.add.is_none());
    assert!(!state.operations.rules_edit);

    state.act(Action::OpenEditRule(id.clone()));
    state.rules.screen.add.as_mut().unwrap().target = RuleTarget::Direct;
    assert!(matches!(
        state.act(Action::SubmitAddRule),
        Some(Job::UpdateRule(set, rule, RuleMatcher::Domain(DomainMatch::Suffix(domain)), RuleTarget::Direct))
            if set == RuleSetId::new("2") && rule == id && domain == "example.com"
    ));
    assert!(state.rules.screen.add.as_ref().unwrap().busy);
    state.reduce(WorkerEvent::UpdateRule(Err(RuleSetError::DuplicateRule)));
    let dialog = state.rules.screen.add.as_ref().unwrap();
    assert!(!dialog.busy);
    assert!(dialog.error.is_some());
    state.reduce(WorkerEvent::UpdateRule(Ok(())));
    assert!(state.rules.screen.add.is_none());
}

#[test]
fn editing_existing_suffixes_does_not_strip_www_or_reject_a_zone() {
    for domain in ["www.youtube.com", "ru"] {
        let mut state = state_with_rules();
        let id = state.config.rule_sets[1].rules[0].id.clone();
        state.config.rule_sets[1].rules[0].matcher =
            RuleMatcher::Domain(DomainMatch::Suffix(domain.into()));
        state.act(Action::OpenRules);
        state.act(Action::OpenEditRule(id.clone()));
        assert_eq!(state.rules.screen.add.as_ref().unwrap().domains, domain);
        assert!(state.act(Action::SubmitAddRule).is_none());
        assert!(state.rules.screen.add.is_none());
        state.act(Action::OpenEditRule(id.clone()));
        state.rules.screen.add.as_mut().unwrap().target = RuleTarget::Block;
        assert!(matches!(
            state.act(Action::SubmitAddRule),
            Some(Job::UpdateRule(_, _, RuleMatcher::Domain(DomainMatch::Suffix(value)), RuleTarget::Block))
                if value == domain
        ));
    }
}

#[test]
fn editing_a_path_rule_opens_advanced_and_rejects_templates() {
    let mut state = state_with_rules();
    let id = state.config.rule_sets[1].rules[1].id.clone();
    state.config.rule_sets[1].rules[1].matcher =
        RuleMatcher::Process(ProcessMatch::Path(PathBuf::from(r"C:\Apps\Tool.exe")));
    state.config.rule_sets[1].rules[2].matcher = RuleMatcher::Template(RuleTemplate::Youtube);
    assert!(
        AddRuleDialog::for_rule(
            state.config.rule_sets[1].id.clone(),
            &state.config.rule_sets[1].rules[2],
        )
        .is_none()
    );
    state.act(Action::OpenRules);
    assert!(state.act(Action::OpenEditRule(RuleId::new("2"))).is_none());
    assert!(state.rules.screen.add.is_none());
    assert!(
        state
            .act(Action::OpenEditRule(RuleId::new("missing")))
            .is_none()
    );
    let request = state.act(Action::OpenEditRule(id.clone()));
    assert!(matches!(request, Some(Job::LoadProcesses(_))));
    let dialog = state.rules.screen.add.as_ref().unwrap();
    assert_eq!(dialog.editing.as_ref(), Some(&id));
    assert_eq!(dialog.kind, RuleInputKind::Process);
    assert_eq!(dialog.process_filter, "Tool.exe");
    assert_eq!(dialog.process, r"C:\Apps\Tool.exe");
    assert!(dialog.advanced);
    assert_eq!(dialog.match_mode, ProcessMatchMode::Path);
    assert!(dialog.selected_process.is_none());
    assert!(state.act(Action::SubmitAddRule).is_none());
    assert!(state.rules.screen.add.is_none());
}

#[test]
fn add_rule_keeps_duplicate_error_in_dialog_and_resets_filters_on_success() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    state.rules.screen.filter.search = "other".into();
    state.rules.screen.filter.kind = TypeFilter::Processes;
    state.rules.screen.filter.target = Some(RuleTarget::Direct);
    state.act(Action::OpenAddRule);
    assert!(state.act(Action::SubmitAddRule).is_none());
    state.act(Action::SelectRuleInput(RuleInputKind::Domain));
    let dialog = state.rules.screen.add.as_mut().unwrap();
    dialog.domains = "*.example.com".into();
    dialog.target = RuleTarget::Direct;
    assert!(matches!(
        state.act(Action::SubmitAddRule),
        Some(Job::AddRules(set, matchers, RuleTarget::Direct))
            if set == RuleSetId::new("2") && matchers == vec![RuleMatcher::Domain(DomainMatch::Suffix("example.com".into()))]
    ));
    assert!(state.act(Action::CancelAddRule).is_none());
    state.reduce(WorkerEvent::AddRules(Err(RuleSetError::DuplicateRule)));
    let dialog = state.rules.screen.add.as_ref().unwrap();
    assert_eq!(dialog.domains, "*.example.com");
    assert_eq!(
        dialog.error.as_deref(),
        Some("this rule is already in the set")
    );
    assert!(!dialog.busy);
    assert!(!state.operations.rules_edit);
    assert!(state.operation_error.is_none());
    assert!(state.rules.screen.filter.is_active());
    assert!(matches!(
        state.act(Action::SubmitAddRule),
        Some(Job::AddRules(_, _, _))
    ));
    state.reduce(WorkerEvent::AddRules(Ok(rosetun_core::AddedRules {
        added: vec![rule_set("2").rules[0].clone()],
        skipped: 0,
    })));
    assert!(state.rules.screen.add.is_none());
    assert!(!state.rules.screen.filter.is_active());
}

#[test]
fn process_input_and_missing_set_guard_submission() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    state.act(Action::OpenAddRule);
    state.act(Action::SelectRuleInput(RuleInputKind::Process));
    state.rules.screen.add.as_mut().unwrap().process = r#""C:\Apps\curl.exe""#.into();
    assert!(matches!(
        state.act(Action::SubmitAddRule),
        Some(Job::AddRule(
            _,
            RuleMatcher::Process(rosetun_config::ProcessMatch::Path(_)),
            _
        ))
    ));
    state.reduce(WorkerEvent::AddRule(Err(RuleSetError::SetNotFound)));
    state.rules.screen.selected_set = None;
    assert!(state.act(Action::SubmitAddRule).is_none());
    state.act(Action::CancelAddRule);
    assert!(state.rules.screen.add.is_none());
}

#[test]
fn rule_target_filter_can_be_set_and_cleared() {
    let mut state = state_with_rules();
    state.act(Action::SetRuleTargetFilter(Some(RuleTarget::Block)));
    assert_eq!(state.rules.screen.filter.target, Some(RuleTarget::Block));
    state.act(Action::SetRuleTargetFilter(None));
    assert_eq!(state.rules.screen.filter.target, None);
}

#[test]
fn add_template_requires_a_selected_set_and_no_existing_template_or_edit() {
    let mut state = state_with_rules();
    let template = RuleTemplate::RussianSites;
    assert!(state.act(Action::AddTemplate(template)).is_none());
    state.act(Action::OpenRules);
    state.config.rule_sets[1].rules.clear();
    assert!(matches!(
        state.act(Action::AddTemplate(template)),
        Some(Job::AddRule(set, RuleMatcher::Template(RuleTemplate::RussianSites), RuleTarget::Direct))
            if set == RuleSetId::new("2")
    ));
    assert!(state.act(Action::AddTemplate(template)).is_none());
    state.reduce(WorkerEvent::AddRule(Err(RuleSetError::DuplicateRule)));
    assert!(state.operation_error.is_some());
    state.config.rule_sets[1].rules.push(Rule {
        id: RuleId::new("template"),
        enabled: false,
        matcher: RuleMatcher::Template(template),
        target: RuleTarget::Block,
    });
    assert!(state.act(Action::AddTemplate(template)).is_none());
}

#[test]
fn remove_template_uses_the_rule_id_and_requires_presence() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    let template = RuleTemplate::Youtube;
    assert!(state.act(Action::RemoveTemplate(template)).is_none());
    state.config.rule_sets[1].rules.push(Rule {
        id: RuleId::new("template"),
        enabled: true,
        matcher: RuleMatcher::Template(template),
        target: RuleTarget::Proxy,
    });
    assert!(matches!(
        state.act(Action::RemoveTemplate(template)),
        Some(Job::RemoveRule(set, rule))
            if set == RuleSetId::new("2") && rule == RuleId::new("template")
    ));
    assert!(state.act(Action::RemoveTemplate(template)).is_none());
    state.reduce(WorkerEvent::RemoveRule(Ok(())));
    state.config.rule_sets[1].rules.pop();
    assert!(state.act(Action::RemoveTemplate(template)).is_none());
}

#[test]
fn move_rule_to_top_checks_position_and_busy_state_but_not_filters() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    assert!(state.act(Action::MoveRuleToTop(RuleId::new("0"))).is_none());
    state.rules.screen.filter.search = "third".into();
    assert!(matches!(
        state.act(Action::MoveRuleToTop(RuleId::new("2"))),
        Some(Job::MoveRule(set, rule, 0))
            if set == RuleSetId::new("2") && rule == RuleId::new("2")
    ));
    assert!(state.act(Action::MoveRuleToTop(RuleId::new("1"))).is_none());
    state.reduce(WorkerEvent::MoveRule(Ok(())));
    assert!(state.act(Action::MoveRuleToTop(RuleId::new("0"))).is_none());
    state.rules.screen.selected_set = None;
    assert!(state.act(Action::MoveRuleToTop(RuleId::new("2"))).is_none());
}

#[test]
fn selected_rules_move_as_one_job_and_filters_block_reordering() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    for id in ["0", "2"] {
        state.act(Action::SelectRule {
            rule: RuleId::new(id),
            additive: true,
            range: false,
        });
    }
    assert!(matches!(
        state.act(Action::DropRules(vec![RuleId::new("0"), RuleId::new("2")], 1)),
        Some(Job::MoveRules(set, rules, 1))
            if set == RuleSetId::new("2") && rules == [RuleId::new("0"), RuleId::new("2")]
    ));
    assert!(state.act(Action::MoveSelectedRulesToTop).is_none());
    state.reduce(WorkerEvent::MoveRules(Ok(())));
    assert!(matches!(
        state.act(Action::MoveSelectedRulesToTop),
        Some(Job::MoveRules(_, rules, 0)) if rules.len() == 2
    ));
    state.reduce(WorkerEvent::MoveRules(Ok(())));
    assert!(matches!(
        state.act(Action::MoveSelectedRulesToEnd),
        Some(Job::MoveRules(_, rules, 1)) if rules.len() == 2
    ));
    state.reduce(WorkerEvent::MoveRules(Ok(())));
    state.rules.screen.filter.search = "first".into();
    assert!(state.act(Action::MoveSelectedRulesToTop).is_none());
    assert!(state.act(Action::MoveSelectedRulesToEnd).is_none());
    assert!(
        state
            .act(Action::DropRules(
                vec![RuleId::new("0"), RuleId::new("2")],
                0
            ))
            .is_none()
    );
    state.rules.screen.filter.search.clear();
    assert!(
        state
            .act(Action::DropRules(
                vec![RuleId::new("0"), RuleId::new("2")],
                2
            ))
            .is_none()
    );
    assert!(
        state
            .act(Action::DropRules(
                vec![RuleId::new("0"), RuleId::new("missing")],
                0
            ))
            .is_none()
    );
}

#[test]
fn selected_rules_delete_in_one_confirmed_job_and_clear_after_success() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    state.act(Action::SelectVisibleRules);
    state.act(Action::RequestDeleteSelectedRules);
    assert!(matches!(
        &state.rules.screen.delete,
        Some(DeleteDialog::Rules { set, rules })
            if set == &RuleSetId::new("2") && rules.len() == 3
    ));
    state.act(Action::CancelRuleDelete);
    assert!(state.rules.screen.delete.is_none());
    assert_eq!(state.rules.screen.selected_rules.len(), 3);
    state.rules.screen.filter.search = "first".into();
    state.act(Action::RequestDeleteSelectedRules);
    assert!(matches!(
        state.rules.screen.delete,
        Some(DeleteDialog::Rule { .. })
    ));
    state.act(Action::CancelRuleDelete);
    state.rules.screen.filter.search.clear();
    state.act(Action::RequestDeleteSelectedRules);
    assert!(matches!(
        state.act(Action::ConfirmRuleDelete),
        Some(Job::RemoveRules(set, rules))
            if set == RuleSetId::new("2") && rules.len() == 3
    ));
    assert!(state.act(Action::CancelRuleDelete).is_none());
    state.reduce(WorkerEvent::RemoveRules(Ok(())));
    assert!(state.rules.screen.delete.is_none());
    assert!(state.rules.screen.selected_rules.is_empty());
}

#[test]
fn rule_actions_reject_concurrent_changes_and_filtered_reordering() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    let rule = RuleId::new("1");
    assert!(matches!(
        state.act(Action::DropRule(rule.clone(), 0)),
        Some(Job::MoveRule(_, _, 0))
    ));
    assert!(state.act(Action::DropRule(rule.clone(), 3)).is_none());
    assert!(
        state
            .act(Action::SetRuleEnabled(rule.clone(), false))
            .is_none()
    );
    assert!(state.act(Action::SelectRuleSet(None)).is_none());
    state.reduce(WorkerEvent::MoveRule(Ok(())));
    state.rules.screen.filter.search = "second".into();
    assert!(state.act(Action::DropRule(rule.clone(), 0)).is_none());
    assert!(state.act(Action::DropRule(rule.clone(), 3)).is_none());
    state.rules.screen.filter.search.clear();
    assert!(state.act(Action::DropRule(rule.clone(), 2)).is_none());
    assert!(matches!(
        state.act(Action::DropRule(rule.clone(), 3)),
        Some(Job::MoveRule(_, _, 2))
    ));
    state.reduce(WorkerEvent::MoveRule(Ok(())));
    assert!(matches!(
        state.act(Action::SetRuleTarget(rule.clone(), RuleTarget::Direct)),
        Some(Job::SetRuleTarget(_, _, RuleTarget::Direct))
    ));
    state.reduce(WorkerEvent::SetRuleTarget(Ok(())));
    assert!(matches!(
        state.act(Action::SetRuleEnabled(rule.clone(), false)),
        Some(Job::SetRuleEnabled(_, _, false))
    ));
    state.reduce(WorkerEvent::SetRuleEnabled(Ok(())));
    assert!(matches!(
        state.act(Action::SetDefaultTarget(RuleTarget::Direct)),
        Some(Job::SetDefaultTarget(_, RuleTarget::Direct))
    ));
    state.reduce(WorkerEvent::SetDefaultTarget(Ok(())));
    assert!(
        state
            .act(Action::SetDefaultTarget(RuleTarget::Block))
            .is_none()
    );
    state.act(Action::OpenAddRule);
    state.act(Action::SelectRuleInput(RuleInputKind::Domain));
    let dialog = state.rules.screen.add.as_mut().unwrap();
    dialog.domains = "new.example".into();
    dialog.subdomains = false;
    dialog.target = RuleTarget::Block;
    assert!(matches!(
        state.act(Action::SubmitAddRule),
        Some(Job::AddRules(_, matchers, RuleTarget::Block))
            if matchers == vec![RuleMatcher::Domain(DomainMatch::Exact("new.example".into()))]
    ));
    state.reduce(WorkerEvent::AddRules(Ok(rosetun_core::AddedRules {
        added: vec![rule_set("1").rules[0].clone()],
        skipped: 0,
    })));
    state.act(Action::RequestDeleteRule(rule));
    assert!(matches!(
        state.act(Action::ConfirmRuleDelete),
        Some(Job::RemoveRule(_, _))
    ));
    state.reduce(WorkerEvent::RemoveRule(Ok(())));
    assert!(state.rules.screen.delete.is_none());
}
