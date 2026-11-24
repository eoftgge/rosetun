use super::*;
use crate::rules::group_processes;

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
    assert!(state.act(Action::ConfirmDeleteSet).is_none());
    state.act(Action::RequestDeleteSet);
    assert_eq!(state.rules.screen.delete_set, Some(RuleSetId::new("2")));
    assert!(matches!(
        state.act(Action::ConfirmDeleteSet),
        Some(Job::DeleteRuleSet(id)) if id == RuleSetId::new("2")
    ));
    assert!(state.act(Action::CancelDeleteSet).is_none());
    state.reduce(WorkerEvent::DeleteRuleSet(Err(RuleSetError::SetNotFound)));
    assert!(state.rules.screen.delete_set.is_none());
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
fn a_browsed_file_is_ticked_with_its_path_whatever_the_folder_setting_says() {
    for mode in [ProcessMatchMode::Name, ProcessMatchMode::Path] {
        let mut state = state_with_rules();
        state.act(Action::OpenRules);
        state.act(Action::OpenAddRule);
        state.act(Action::SelectRuleInput(RuleInputKind::Process));
        let dialog = state.rules.screen.add.as_mut().unwrap();
        dialog.match_mode = mode;
        dialog.tick_program("Other.exe");
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
        assert_eq!(
            dialog.chosen.len(),
            2,
            "added to the program already ticked"
        );
        assert_eq!(dialog.chosen[1].path.as_ref(), Some(&path));
        assert!(dialog.chosen[1].fixed_path);
        assert_eq!(
            dialog.process_rules(),
            Some(vec![
                RuleMatcher::Process(rosetun_config::ProcessMatch::Name("Other.exe".into())),
                RuleMatcher::Process(rosetun_config::ProcessMatch::Path(path)),
            ])
        );
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
    state
        .rules
        .screen
        .add
        .as_mut()
        .unwrap()
        .tick_program("current.exe");
    state.act(Action::BrowseExecutable);
    state.reduce(WorkerEvent::BrowsedExecutable(None));
    let dialog = state.rules.screen.add.as_ref().unwrap();
    assert!(!dialog.browsing);
    assert_eq!(dialog.chosen.len(), 1);

    state.act(Action::BrowseExecutable);
    state.act(Action::SelectRuleInput(RuleInputKind::Address));
    state.reduce(WorkerEvent::BrowsedExecutable(Some(
        r"C:\Apps\Tool.exe".into(),
    )));
    let dialog = state.rules.screen.add.as_ref().unwrap();
    assert!(!dialog.browsing);
    assert_eq!(dialog.chosen.len(), 1);

    state.act(Action::SelectRuleInput(RuleInputKind::Process));
    state.act(Action::BrowseExecutable);
    state.act(Action::CancelAddRule);
    state.reduce(WorkerEvent::BrowsedExecutable(Some(
        r"C:\Apps\Tool.exe".into(),
    )));
    assert!(state.rules.screen.add.is_none());
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
        result: Ok(group_processes(vec![RunningProcess {
            pid: 100,
            name: "Telegram.exe".into(),
            path: Some(r"C:\Apps\Telegram.exe".into()),
            has_window: true,
        }])),
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
        result: Ok(group_processes(vec![RunningProcess {
            pid: 101,
            name: "Old.exe".into(),
            path: None,
            has_window: false,
        }])),
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
fn an_address_batch_requires_every_item_to_be_valid_and_obeys_the_subdomain_choice() {
    for (subdomains, expected) in [
        (
            true,
            vec![
                RuleMatcher::Domain(DomainMatch::Suffix("youtube.com".into())),
                RuleMatcher::IpCidr("192.0.2.1/32".into()),
                RuleMatcher::Domain(DomainMatch::Suffix("instagram.com".into())),
            ],
        ),
        (
            false,
            vec![
                RuleMatcher::Domain(DomainMatch::Exact("www.youtube.com".into())),
                RuleMatcher::IpCidr("192.0.2.1/32".into()),
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
        state.act(Action::SelectRuleInput(RuleInputKind::Address));
        let dialog = state.rules.screen.add.as_mut().unwrap();
        dialog.set_addresses(
            "https://www.youtube.com/watch?v=1\n192.0.2.1\nbad..domain\ninstagram.com",
        );
        dialog.subdomains = subdomains;
        assert!(state.act(Action::SubmitAddRule).is_none());
        state
            .rules
            .screen
            .add
            .as_mut()
            .unwrap()
            .set_addresses("https://www.youtube.com/watch?v=1, 192.0.2.1; instagram.com");
        assert!(matches!(
            state.act(Action::SubmitAddRule),
            Some(Job::AddRules(_, matchers, RuleDestination::Proxy)) if matchers == expected
        ));
    }
}

#[test]
fn the_address_field_adds_multiple_addresses_and_corrects_host_bits() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    state.act(Action::OpenAddRule);
    state.act(Action::SelectRuleInput(RuleInputKind::Address));
    let dialog = state.rules.screen.add.as_mut().unwrap();
    dialog.set_addresses("192.0.2.5/24\nbad..domain\n2001:db8::1\n198.51.100.0/24");
    assert!(state.act(Action::SubmitAddRule).is_none());
    state.act(Action::CorrectRuleIps);
    let dialog = state.rules.screen.add.as_ref().unwrap();
    assert_eq!(
        dialog.address_text(),
        "192.0.2.0/24\nbad..domain\n2001:db8::1\n198.51.100.0/24"
    );
    assert!(state.act(Action::SubmitAddRule).is_none());
    state
        .rules
        .screen
        .add
        .as_mut()
        .unwrap()
        .set_addresses("192.0.2.0/24\n2001:db8::1\n198.51.100.0/24\n192.0.2.0/24");
    assert!(matches!(
        state.act(Action::SubmitAddRule),
        Some(Job::AddRules(_, matchers, RuleDestination::Proxy))
            if matchers == [
                RuleMatcher::IpCidr("192.0.2.0/24".into()),
                RuleMatcher::IpCidr("2001:db8::1/128".into()),
                RuleMatcher::IpCidr("198.51.100.0/24".into()),
            ]
    ));
}

#[test]
fn editing_an_ip_rule_opens_the_address_kind_and_updates_one_rule() {
    let mut state = state_with_rules();
    let id = state.config.rule_sets[1].rules[0].id.clone();
    state.config.rule_sets[1].rules[0].matcher = RuleMatcher::IpCidr("192.0.2.0/24".into());
    state.act(Action::OpenRules);
    state.act(Action::OpenEditRule(id.clone()));
    let dialog = state.rules.screen.add.as_ref().unwrap();
    assert_eq!(dialog.kind, RuleInputKind::Address);
    assert_eq!(dialog.address_text(), "192.0.2.0/24");
    assert!(state.act(Action::SubmitAddRule).is_none());
    assert!(state.rules.screen.add.is_none());
    state.act(Action::OpenEditRule(id.clone()));
    state
        .rules
        .screen
        .add
        .as_mut()
        .unwrap()
        .set_addresses("203.0.113.1");
    assert!(matches!(
        state.act(Action::SubmitAddRule),
        Some(Job::UpdateRule(_, rule, RuleMatcher::IpCidr(cidr), RuleDestination::Proxy))
            if rule == id && cidr == "203.0.113.1/32"
    ));
}

#[test]
fn ip_local_setting_link_closes_dialog_and_opens_connection_settings() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    state.act(Action::OpenAddRule);
    state.act(Action::SelectRuleInput(RuleInputKind::Address));
    state
        .rules
        .screen
        .add
        .as_mut()
        .unwrap()
        .set_addresses("192.0.2.1");
    assert!(!state.rules.screen.add.as_ref().unwrap().local_ip_warning());
    state.act(Action::OpenLanSettings);
    assert!(state.rules.screen.add.is_none());
    assert_eq!(state.screen, Screen::Settings);
    assert_eq!(state.settings.screen.section, SettingsSection::Connection);
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
    assert_eq!(dialog.kind, RuleInputKind::Address);
    assert_eq!(dialog.address_text(), "example.com");
    assert!(dialog.subdomains);
    state.act(Action::SelectRuleInput(RuleInputKind::Process));
    assert_eq!(
        state.rules.screen.add.as_ref().unwrap().kind,
        RuleInputKind::Address
    );
    assert!(state.act(Action::SubmitAddRule).is_none());
    assert!(state.rules.screen.add.is_none());
    assert!(!state.operations.rules_edit);

    state.act(Action::OpenEditRule(id.clone()));
    state.rules.screen.add.as_mut().unwrap().target = RuleDestination::Direct;
    assert!(matches!(
        state.act(Action::SubmitAddRule),
        Some(Job::UpdateRule(set, rule, RuleMatcher::Domain(DomainMatch::Suffix(domain)), RuleDestination::Direct))
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
        assert_eq!(
            state.rules.screen.add.as_ref().unwrap().address_text(),
            domain
        );
        assert!(state.act(Action::SubmitAddRule).is_none());
        assert!(state.rules.screen.add.is_none());
        state.act(Action::OpenEditRule(id.clone()));
        state.rules.screen.add.as_mut().unwrap().target = RuleDestination::Block;
        assert!(matches!(
            state.act(Action::SubmitAddRule),
            Some(Job::UpdateRule(_, _, RuleMatcher::Domain(DomainMatch::Suffix(value)), RuleDestination::Block))
                if value == domain
        ));
    }
}

#[test]
fn editing_a_path_rule_keeps_the_path_and_groups_open_group_editor() {
    #[cfg(windows)]
    let path = r"C:\Apps\Tool.exe";
    #[cfg(not(windows))]
    let path = "/opt/apps/Tool.exe";
    let mut state = state_with_rules();
    let id = state.config.rule_sets[1].rules[1].id.clone();
    state.config.rule_sets[1].rules[1].matcher =
        RuleMatcher::Process(ProcessMatch::Path(PathBuf::from(path)));
    state.config.rule_sets[1].rules[2].matcher = RuleTemplate::Youtube.to_group("YouTube");
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
    assert_eq!(
        state
            .rules
            .screen
            .group_editor
            .as_ref()
            .and_then(|dialog| dialog.editing.as_ref()),
        Some(&RuleId::new("2"))
    );
    state.act(Action::CancelGroupEditor);
    assert!(state.rules.screen.group_editor.is_none());
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
    assert!(dialog.process_filter.is_empty(), "the list is not narrowed");
    assert_eq!(dialog.match_mode, ProcessMatchMode::Path);
    assert_eq!(dialog.chosen.len(), 1);
    assert_eq!(dialog.chosen[0].name, "Tool.exe");
    assert_eq!(dialog.chosen[0].path, Some(PathBuf::from(path)));
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
    state.act(Action::SelectRuleInput(RuleInputKind::Address));
    let dialog = state.rules.screen.add.as_mut().unwrap();
    dialog.set_addresses("*.example.com");
    dialog.target = RuleDestination::Direct;
    assert!(matches!(
        state.act(Action::SubmitAddRule),
        Some(Job::AddRules(set, matchers, RuleDestination::Direct))
            if set == RuleSetId::new("2") && matchers == vec![RuleMatcher::Domain(DomainMatch::Suffix("example.com".into()))]
    ));
    assert!(state.act(Action::CancelAddRule).is_none());
    state.reduce(WorkerEvent::AddRules(Err(RuleSetError::DuplicateRule)));
    let dialog = state.rules.screen.add.as_ref().unwrap();
    assert_eq!(dialog.address_text(), "*.example.com");
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
    state
        .rules
        .screen
        .add
        .as_mut()
        .unwrap()
        .tick_program(r#""C:\Apps\curl.exe""#);
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
fn add_preset_group_copies_items_into_editable_group_with_chosen_destination() {
    let mut state = state_with_rules();
    let template = RuleTemplate::RussianSites;
    assert!(
        state
            .act(Action::AddPresetGroup(template, RuleDestination::Direct))
            .is_none()
    );
    state.act(Action::OpenRules);
    state.config.rule_sets[1].rules.clear();
    let expected_name = crate::i18n::template_name(template);
    assert!(matches!(
        state.act(Action::AddPresetGroup(template, RuleDestination::Block)),
        Some(Job::AddRule(
            set,
            RuleMatcher::Group { name, items },
            RuleDestination::Block
        )) if set == RuleSetId::new("2") && name == expected_name && items == template.matchers()
    ));
    assert!(
        state
            .act(Action::AddPresetGroup(template, RuleDestination::Block))
            .is_none()
    );
    state.reduce(WorkerEvent::AddRule(Err(RuleSetError::DuplicateRule)));
    assert!(state.operation_error.is_some());
}

#[test]
fn group_selection_ungroup_and_remove_group_item_validate_and_dispatch_jobs() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    assert!(state.act(Action::OpenGroupSelection).is_none());
    for id in ["0", "2"] {
        state.act(Action::SelectRule {
            rule: RuleId::new(id),
            additive: true,
            range: false,
        });
    }
    state.act(Action::OpenGroupSelection);
    let dialog = state.rules.screen.group_selection.as_mut().unwrap();
    assert_eq!(dialog.rules, vec![RuleId::new("0"), RuleId::new("2")]);
    dialog.name = "Work sites".into();
    dialog.target = RuleDestination::Direct;
    assert!(matches!(
        state.act(Action::SubmitGroupSelection),
        Some(Job::GroupRules(set, ids, name, RuleDestination::Direct))
            if set == RuleSetId::new("2")
                && ids == vec![RuleId::new("0"), RuleId::new("2")]
                && name == "Work sites"
    ));
    let grouped = Rule {
        id: RuleId::new("group"),
        enabled: true,
        matcher: RuleTemplate::Youtube.to_group("YouTube"),
        target: RuleTarget::Proxy,
        exit: None,
    };
    state.config.rule_sets[1].rules.push(grouped.clone());
    state.reduce(WorkerEvent::GroupRules(Ok(grouped)));
    assert!(state.rules.screen.group_selection.is_none());
    assert_eq!(
        state.rules.screen.selected_rules.iter().collect::<Vec<_>>(),
        [&RuleId::new("group")]
    );

    state.act(Action::ToggleGroupExpanded(RuleId::new("group")));
    assert!(
        state
            .rules
            .screen
            .expanded_groups
            .contains(&RuleId::new("group"))
    );
    assert!(matches!(
        state.act(Action::RemoveGroupItem(RuleId::new("group"), 0)),
        Some(Job::RemoveGroupItem(set, rule, 0))
            if set == RuleSetId::new("2") && rule == RuleId::new("group")
    ));
    state.reduce(WorkerEvent::RemoveGroupItem(Ok(())));
    assert!(matches!(
        state.act(Action::UngroupRule(RuleId::new("group"))),
        Some(Job::UngroupRule(set, rule))
            if set == RuleSetId::new("2") && rule == RuleId::new("group")
    ));
    assert!(
        !state
            .rules
            .screen
            .expanded_groups
            .contains(&RuleId::new("group"))
    );
    state.reduce(WorkerEvent::UngroupRule(Ok(vec![])));
}

#[test]
fn group_editor_creates_new_group_and_updates_existing_group() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    state.act(Action::OpenTemplatesCatalog);
    assert!(state.rules.screen.templates_catalog.is_some());
    state.act(Action::OpenNewGroup);
    assert!(state.rules.screen.templates_catalog.is_none());
    let dialog = state.rules.screen.group_editor.as_mut().unwrap();
    dialog.name = "Custom".into();
    dialog.input = "example.com".into();
    dialog.commit_input();
    dialog.set_item_kind(GroupItemKind::Process);
    dialog.input = "tool.exe".into();
    assert!(matches!(
        state.act(Action::SubmitGroupEditor),
        Some(Job::AddRule(set, RuleMatcher::Group { name, items }, RuleDestination::Proxy))
            if set == RuleSetId::new("2")
                && name == "Custom"
                && items == vec![
                    RuleMatcher::Domain(rosetun_config::DomainMatch::Suffix("example.com".into())),
                    RuleMatcher::Process(rosetun_config::ProcessMatch::Name("tool.exe".into())),
                ]
    ));
    state.reduce(WorkerEvent::AddRule(Ok(rule_set("2").rules[0].clone())));
    assert!(state.rules.screen.group_editor.is_none());
}

#[test]
fn group_editor_parses_address_suffixes_exact_domains_and_batches() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    state.act(Action::OpenNewGroup);
    let dialog = state.rules.screen.group_editor.as_mut().unwrap();

    // Multiple entries separated by commas and whitespace.
    dialog.input = "example.com, *.ru, .su, 192.0.2.0/24".into();
    dialog.commit_input();
    assert!(dialog.input_error.is_none());
    assert!(dialog.input.is_empty());
    assert_eq!(
        dialog.items,
        vec![
            RuleMatcher::Domain(rosetun_config::DomainMatch::Suffix("example.com".into())),
            RuleMatcher::Domain(rosetun_config::DomainMatch::Suffix("ru".into())),
            RuleMatcher::Domain(rosetun_config::DomainMatch::Suffix("su".into())),
            RuleMatcher::IpCidr("192.0.2.0/24".into()),
        ]
    );

    // Turning off subdomains adds Exact for bare domains, while keeping explicit *.tld as Suffix.
    dialog.subdomains = false;
    dialog.input = "exact.example.org, *.рф".into();
    dialog.commit_input();
    assert!(dialog.input_error.is_none());
    assert_eq!(
        &dialog.items[4..],
        &[
            RuleMatcher::Domain(rosetun_config::DomainMatch::Exact(
                "exact.example.org".into()
            )),
            RuleMatcher::Domain(rosetun_config::DomainMatch::Suffix("xn--p1ai".into())),
        ]
    );

    // Host bits in CIDR produce a clear error without mutating items.
    dialog.input = "192.0.2.5/24".into();
    dialog.commit_input();
    assert!(dialog.input_error.is_some());
    assert_eq!(dialog.items.len(), 6);
}

#[test]
fn group_editor_process_mode_handles_dotted_linux_binaries_and_paths() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    state.act(Action::OpenNewGroup);
    let dialog = state.rules.screen.group_editor.as_mut().unwrap();
    dialog.set_item_kind(GroupItemKind::Process);

    for name in ["python3.12", "game.x86_64", "app.AppImage"] {
        dialog.input = name.into();
        dialog.commit_input();
        assert!(dialog.input_error.is_none(), "{name}");
    }
    dialog.input = "/usr/bin/python3.12".into();
    dialog.commit_input();
    assert!(dialog.input_error.is_none());

    assert_eq!(
        dialog.items,
        vec![
            RuleMatcher::Process(rosetun_config::ProcessMatch::Name("python3.12".into())),
            RuleMatcher::Process(rosetun_config::ProcessMatch::Name("game.x86_64".into())),
            RuleMatcher::Process(rosetun_config::ProcessMatch::Name("app.AppImage".into())),
            RuleMatcher::Process(rosetun_config::ProcessMatch::Path(
                std::path::PathBuf::from("/usr/bin/python3.12")
            )),
        ]
    );
}

#[test]
fn group_editor_list_mode_validates_and_toggles_categories() {
    let mut state = state_with_rules();
    let geosite = rosetun_config::List {
        id: rosetun_config::ListId::new("geosite"),
        name: "GeoSite".into(),
        format: rosetun_config::ListFormat::GeoSite,
        source: rosetun_config::ListSource::File {
            original_name: "geosite.dat".into(),
        },
        categories: vec!["youtube".into(), "ru".into()],
        size: Some(100),
        updated_at: None,
        sha256: Some("abc".into()),
    };
    let plain = rosetun_config::List {
        id: rosetun_config::ListId::new("plain"),
        name: "Custom SRS".into(),
        format: rosetun_config::ListFormat::SingBoxBinary,
        source: rosetun_config::ListSource::File {
            original_name: "custom.srs".into(),
        },
        categories: Vec::new(),
        size: Some(100),
        updated_at: None,
        sha256: Some("def".into()),
    };
    state.config.lists = vec![geosite.clone(), plain.clone()];

    state.act(Action::OpenRules);
    state.act(Action::OpenNewGroup);
    let dialog = state.rules.screen.group_editor.as_mut().unwrap();
    dialog.set_item_kind(GroupItemKind::List);
    dialog.select_list(geosite.id.clone());

    // Missing category is rejected for GeoSite.
    dialog.commit_list(&geosite);
    assert!(dialog.input_error.is_some());
    assert!(dialog.items.is_empty());

    // Unknown category is rejected.
    dialog.category = "nonexistent".into();
    dialog.commit_list(&geosite);
    assert!(dialog.input_error.is_some());

    // Valid category (including @attribute) succeeds.
    dialog.category = "youtube@cn".into();
    dialog.commit_list(&geosite);
    assert!(dialog.input_error.is_none());
    assert!(dialog.category.is_empty());

    // Chip toggle adds and removes a category cleanly.
    dialog.toggle_list_category(&geosite, "ru");
    assert!(dialog.contains_list_category(&geosite.id, "ru"));
    dialog.toggle_list_category(&geosite, "ru");
    assert!(!dialog.contains_list_category(&geosite.id, "ru"));

    // Plain (non-categorized) list commits with category: None, and rejects duplicates.
    dialog.select_list(plain.id.clone());
    dialog.commit_list(&plain);
    assert!(dialog.input_error.is_none());
    dialog.commit_list(&plain);
    assert!(dialog.input_error.is_some());

    assert_eq!(
        dialog.items,
        vec![
            RuleMatcher::List {
                list: geosite.id,
                category: Some("youtube@cn".into()),
            },
            RuleMatcher::List {
                list: plain.id,
                category: None,
            },
        ]
    );
}

#[test]
fn group_editor_reorders_items_and_saves_updated_order() {
    let mut state = state_with_rules();
    let group_id = RuleId::new("g0");
    let items = vec![
        RuleMatcher::Domain(DomainMatch::Suffix("a.example".into())),
        RuleMatcher::Domain(DomainMatch::Suffix("b.example".into())),
        RuleMatcher::Domain(DomainMatch::Suffix("c.example".into())),
    ];
    state.config.rule_sets[1].rules.push(Rule {
        id: group_id.clone(),
        enabled: true,
        matcher: RuleMatcher::Group {
            name: "Bundle".into(),
            items: items.clone(),
        },
        target: RuleTarget::Proxy,
        exit: None,
    });

    state.act(Action::OpenRules);
    state.act(Action::OpenEditRule(group_id.clone()));
    let dialog = state.rules.screen.group_editor.as_mut().unwrap();

    // Out-of-bounds and no-op moves keep items untouched.
    dialog.move_item(0, 0);
    dialog.move_item(0, 99);
    dialog.move_item(99, 0);
    assert_eq!(dialog.items, items);

    // Move last item to first, then move second item down to last.
    dialog.move_item(2, 0);
    assert_eq!(
        dialog.items,
        vec![items[2].clone(), items[0].clone(), items[1].clone()]
    );
    dialog.move_item(1, 2);
    let expected = vec![items[2].clone(), items[1].clone(), items[0].clone()];
    assert_eq!(dialog.items, expected);

    // Submitting a reordered group emits UpdateRule (not treated as unchanged).
    assert!(matches!(
        state.act(Action::SubmitGroupEditor),
        Some(Job::UpdateRule(
            set,
            id,
            RuleMatcher::Group { name, items: saved },
            RuleDestination::Proxy
        )) if set == RuleSetId::new("2")
            && id == group_id
            && name == "Bundle"
            && saved == expected
    ));
}

#[test]
fn add_rules_to_group_validates_target_and_selects_updated_group() {
    let mut state = state_with_rules();
    let group_id = RuleId::new("g0");
    let group = Rule {
        id: group_id.clone(),
        enabled: true,
        matcher: RuleMatcher::Group {
            name: "Games".into(),
            items: vec![RuleMatcher::Domain(DomainMatch::Suffix(
                "steam.example".into(),
            ))],
        },
        target: RuleTarget::Direct,
        exit: None,
    };
    state.config.rule_sets[1].rules.push(group.clone());

    state.act(Action::OpenRules);
    // Rejects non-group target and self-only addition.
    assert!(
        state
            .act(Action::AddRulesToGroup(
                vec![RuleId::new("0")],
                RuleId::new("1")
            ))
            .is_none()
    );
    assert!(
        state
            .act(Action::AddRulesToGroup(
                vec![group_id.clone()],
                group_id.clone()
            ))
            .is_none()
    );

    // Filters out the target group if it was part of the selection.
    assert!(matches!(
        state.act(Action::AddRulesToGroup(
            vec![RuleId::new("0"), group_id.clone(), RuleId::new("2")],
            group_id.clone()
        )),
        Some(Job::AddRulesToGroup(set, sources, target))
            if set == RuleSetId::new("2")
                && sources == vec![RuleId::new("0"), RuleId::new("2")]
                && target == group_id
    ));
    state.reduce(WorkerEvent::AddRulesToGroup(Ok(group)));
    assert_eq!(
        state.rules.screen.selected_rules.iter().collect::<Vec<_>>(),
        vec![&group_id]
    );
    assert!(state.rules.screen.reveal_selection);
    assert_eq!(state.rules.screen.highlight_rule, Some((group_id, 1)));
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
fn selected_rules_delete_at_once_in_one_job_and_clear_after_success() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    state.act(Action::SelectVisibleRules);
    state.rules.screen.filter.search = "first".into();
    assert!(matches!(
        state.act(Action::DeleteSelectedRules),
        Some(Job::RemoveRule(set, _)) if set == RuleSetId::new("2")
    ));
    state.reduce(WorkerEvent::RemoveRule(Err(RuleSetError::RuleNotFound)));
    assert_eq!(state.rules.screen.selected_rules.len(), 3);
    state.rules.screen.filter.search.clear();
    assert!(matches!(
        state.act(Action::DeleteSelectedRules),
        Some(Job::RemoveRules(set, rules))
            if set == RuleSetId::new("2") && rules.len() == 3
    ));
    assert!(state.act(Action::DeleteSelectedRules).is_none());
    state.reduce(WorkerEvent::RemoveRules(Ok(())));
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
        state.act(Action::SetRuleTarget(rule.clone(), RuleDestination::Direct)),
        Some(Job::SetRuleTarget(_, _, RuleDestination::Direct))
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
    state.act(Action::SelectRuleInput(RuleInputKind::Address));
    let dialog = state.rules.screen.add.as_mut().unwrap();
    dialog.set_addresses("new.example");
    dialog.subdomains = false;
    dialog.target = RuleDestination::Block;
    assert!(matches!(
        state.act(Action::SubmitAddRule),
        Some(Job::AddRules(_, matchers, RuleDestination::Block))
            if matchers == vec![RuleMatcher::Domain(DomainMatch::Exact("new.example".into()))]
    ));
    state.reduce(WorkerEvent::AddRules(Ok(rosetun_core::AddedRules {
        added: vec![rule_set("1").rules[0].clone()],
        skipped: 0,
    })));
    assert!(matches!(
        state.act(Action::DeleteRule(rule)),
        Some(Job::RemoveRule(_, _))
    ));
    state.reduce(WorkerEvent::RemoveRule(Ok(())));
}

#[test]
fn editing_an_exit_rule_keeps_its_exit() {
    let mut state = state_with_rules();
    let exit = rosetun_config::ExitId::new("1");
    state.config.exits.push(rosetun_config::Exit {
        via: None,
        id: exit.clone(),
        name: "Netherlands".into(),
        target: rosetun_config::ExitTarget::Country(
            rosetun_config::CountryCode::parse("NL").unwrap(),
        ),
    });
    let id = state.config.rule_sets[1].rules[0].id.clone();
    state.config.rule_sets[1].rules[0].matcher =
        RuleMatcher::Domain(DomainMatch::Suffix("example.com".into()));
    state.config.rule_sets[1].rules[0].target = RuleTarget::Exit;
    state.config.rule_sets[1].rules[0].exit = Some(exit.clone());
    state.act(Action::OpenRules);
    state.act(Action::OpenEditRule(id.clone()));
    assert_eq!(
        state.rules.screen.add.as_ref().unwrap().target,
        RuleDestination::Exit(exit.clone())
    );
    assert!(state.act(Action::SubmitAddRule).is_none());
    assert!(state.rules.screen.add.is_none());

    state.act(Action::OpenEditRule(id.clone()));
    state
        .rules
        .screen
        .add
        .as_mut()
        .unwrap()
        .set_addresses("example.org");
    assert!(matches!(
        state.act(Action::SubmitAddRule),
        Some(Job::UpdateRule(_, rule, _, RuleDestination::Exit(kept))) if rule == id && kept == exit
    ));
}

fn running(name: &str, path: &str, has_window: bool) -> RunningProcess {
    RunningProcess {
        pid: 100,
        name: name.into(),
        path: Some(path.into()),
        has_window,
    }
}

#[test]
fn the_program_kind_reads_the_list_again_once_it_is_stale() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    let Some(Job::LoadProcesses(request)) = state.act(Action::OpenAddRule) else {
        panic!("a new rule loads the program list");
    };
    state.set_frame_time(1_000);
    state.reduce(WorkerEvent::Processes {
        request,
        result: Ok(Vec::new()),
    });
    state.act(Action::SelectRuleInput(RuleInputKind::Address));
    state.set_frame_time(1_000 + PROCESS_LIST_STALE_MS - 1);
    assert!(
        state
            .act(Action::SelectRuleInput(RuleInputKind::Process))
            .is_none()
    );
    state.act(Action::SelectRuleInput(RuleInputKind::Address));
    state.set_frame_time(1_000 + PROCESS_LIST_STALE_MS);
    assert!(matches!(
        state.act(Action::SelectRuleInput(RuleInputKind::Process)),
        Some(Job::LoadProcesses(_))
    ));
}

fn tool_paths() -> (&'static str, &'static str, &'static str) {
    #[cfg(windows)]
    return (
        r"C:\Apps\Tool.exe",
        r"C:\Other\Tool.exe",
        r"C:\Apps\Curl.exe",
    );
    #[cfg(not(windows))]
    return (
        "/opt/apps/Tool.exe",
        "/opt/other/Tool.exe",
        "/opt/apps/Curl.exe",
    );
}

/// A new rule dialog on the program kind with `processes` listed, as the service answered.
fn program_dialog(processes: Vec<RunningProcess>) -> State {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    let Some(Job::LoadProcesses(request)) = state.act(Action::OpenAddRule) else {
        panic!("a new rule loads the program list");
    };
    state.reduce(WorkerEvent::Processes {
        request,
        result: Ok(group_processes(processes)),
    });
    state
}

fn process_rule(name: &str) -> RuleMatcher {
    RuleMatcher::Process(ProcessMatch::Name(name.into()))
}

#[cfg(windows)]
#[test]
fn a_program_given_by_name_or_path_is_found_in_the_list_once_it_loads() {
    let (path, other, _) = tool_paths();
    for (matcher, expected) in [
        (
            ProcessMatch::Name("tool.exe".into()),
            crate::rules::ProgramKey::of_path(path.as_ref()),
        ),
        (
            ProcessMatch::Path(PathBuf::from(other)),
            crate::rules::ProgramKey::of_path(other.as_ref()),
        ),
        (
            ProcessMatch::Name("Missing.exe".into()),
            crate::rules::ProgramKey::of_name("missing.exe"),
        ),
    ] {
        let mut state = state_with_rules();
        let Some(Job::LoadProcesses(request)) = state.act(Action::OpenAddRuleFor(
            RuleMatcher::Process(matcher.clone()),
        )) else {
            panic!("a program rule loads the program list");
        };
        state.reduce(WorkerEvent::Processes {
            request,
            result: Ok(group_processes(vec![
                running("Tool.exe", path, true),
                running("Tool.exe", other, false),
            ])),
        });
        let dialog = state.rules.screen.add.as_ref().unwrap();
        assert_eq!(dialog.chosen.len(), 1, "{matcher:?}");
        assert_eq!(dialog.chosen[0].key, expected, "{matcher:?}");
        assert_eq!(
            dialog.match_mode,
            if matches!(matcher, ProcessMatch::Path(_)) {
                ProcessMatchMode::Path
            } else {
                ProcessMatchMode::Name
            }
        );
        assert_eq!(
            dialog.process_rules(),
            Some(vec![RuleMatcher::Process(matcher.clone())]),
            "the rule stays as it was given"
        );
    }
}

#[test]
fn any_folder_or_only_this_folder_makes_a_name_or_a_path_rule() {
    let (path, _, _) = tool_paths();
    for (mode, expected) in [
        (
            ProcessMatchMode::Name,
            ProcessMatch::Name("Tool.exe".into()),
        ),
        (
            ProcessMatchMode::Path,
            ProcessMatch::Path(PathBuf::from(path)),
        ),
    ] {
        let mut state = program_dialog(vec![running("Tool.exe", path, true)]);
        let dialog = state.rules.screen.add.as_mut().unwrap();
        dialog.toggle_listed(0);
        dialog.set_process_match_mode(mode);
        assert!(matches!(
            state.act(Action::SubmitAddRule),
            Some(Job::AddRule(_, RuleMatcher::Process(process), _)) if process == expected
        ));
    }
}

#[test]
fn ticking_a_program_twice_unticks_it_and_clear_selection_unticks_all() {
    let (path, other, third) = tool_paths();
    let mut state = program_dialog(vec![
        running("Tool.exe", path, true),
        running("Other.exe", other, true),
        running("Curl.exe", third, false),
    ]);
    let dialog = state.rules.screen.add.as_mut().unwrap();
    assert!(dialog.process_rules().is_none(), "nothing is ticked");
    let index_of = |dialog: &AddRuleDialog, name: &str| {
        dialog
            .processes
            .iter()
            .position(|group| group.name == name)
            .unwrap()
    };
    for name in ["Tool.exe", "Curl.exe"] {
        let index = index_of(dialog, name);
        dialog.toggle_listed(index);
    }
    assert_eq!(dialog.chosen.len(), 2);
    let index = index_of(dialog, "Tool.exe");
    dialog.toggle_listed(index);
    assert_eq!(dialog.chosen.len(), 1);
    assert!(!dialog.is_chosen(&dialog.processes[index].key()));
    dialog.toggle_listed(index);
    dialog.clear_chosen();
    assert!(dialog.chosen.is_empty());
    assert!(state.act(Action::SubmitAddRule).is_none());
}

#[test]
fn several_ticked_programs_are_saved_as_one_rule_each_with_one_destination() {
    let (path, other, third) = tool_paths();
    let mut state = program_dialog(vec![
        running("Tool.exe", path, true),
        running("Other.exe", other, true),
        running("Curl.exe", third, false),
    ]);
    let dialog = state.rules.screen.add.as_mut().unwrap();
    dialog.target = RuleDestination::Direct;
    for index in 0..3 {
        dialog.toggle_listed(index);
    }
    dialog.set_process_match_mode(ProcessMatchMode::Path);
    assert_eq!(dialog.process_rule_count(), 3);
    let Some(Job::AddRules(_, matchers, RuleDestination::Direct)) =
        state.act(Action::SubmitAddRule)
    else {
        panic!("several programs are added together");
    };
    let paths: Vec<_> = matchers
        .iter()
        .map(|matcher| match matcher {
            RuleMatcher::Process(ProcessMatch::Path(path)) => path.clone(),
            other => panic!("{other:?}"),
        })
        .collect();
    let mut expected: Vec<_> = [path, other, third].map(PathBuf::from).to_vec();
    expected.sort();
    let mut paths_sorted = paths;
    paths_sorted.sort();
    assert_eq!(paths_sorted, expected);
}

#[test]
fn programs_with_the_same_name_make_one_rule_for_any_folder() {
    let (path, other, _) = tool_paths();
    let mut state = program_dialog(vec![
        running("Tool.exe", path, true),
        running("Tool.exe", other, true),
    ]);
    let dialog = state.rules.screen.add.as_mut().unwrap();
    dialog.toggle_listed(0);
    dialog.toggle_listed(1);
    assert_eq!(dialog.chosen.len(), 2);
    assert_eq!(dialog.process_rule_count(), 1);
    assert!(matches!(
        state.act(Action::SubmitAddRule),
        Some(Job::AddRule(
            _,
            RuleMatcher::Process(ProcessMatch::Name(_)),
            _
        ))
    ));
}

#[test]
fn only_this_folder_needs_the_path_of_every_ticked_program() {
    let (path, _, _) = tool_paths();
    let mut state = program_dialog(vec![running("Tool.exe", path, true)]);
    let dialog = state.rules.screen.add.as_mut().unwrap();
    dialog.processes.push(crate::rules::ProcessGroup {
        name: "Hidden.exe".into(),
        path: None,
        count: 1,
        windowed: false,
    });
    dialog.toggle_listed(1);
    assert!(!dialog.full_path_available());
    dialog.set_process_match_mode(ProcessMatchMode::Path);
    assert_eq!(dialog.match_mode, ProcessMatchMode::Name, "refused");
    dialog.clear_chosen();
    dialog.toggle_listed(0);
    dialog.set_process_match_mode(ProcessMatchMode::Path);
    dialog.toggle_listed(1);
    assert_eq!(
        dialog.chosen.len(),
        1,
        "a program without a path is not ticked"
    );
}

#[test]
fn a_typed_name_or_path_is_ticked_like_a_listed_program() {
    let (path, _, _) = tool_paths();
    let mut state = program_dialog(vec![running("Tool.exe", path, true)]);
    let dialog = state.rules.screen.add.as_mut().unwrap();
    dialog.process_filter = "custom.exe".into();
    dialog.toggle_typed();
    dialog.process_filter = format!("\"{path}\"");
    dialog.toggle_typed();
    assert_eq!(dialog.chosen.len(), 2);
    assert!(dialog.chosen[1].fixed_path);
    assert_eq!(
        dialog.process_rules(),
        Some(vec![
            process_rule("custom.exe"),
            RuleMatcher::Process(ProcessMatch::Path(PathBuf::from(path))),
        ])
    );
    assert!(!dialog.folder_setting_applies() || dialog.chosen.iter().any(|item| !item.fixed_path));
}

#[test]
fn reading_the_process_list_again_keeps_the_ticks() {
    let (path, other, third) = tool_paths();
    let mut state = program_dialog(vec![
        running("Tool.exe", path, true),
        running("Other.exe", other, true),
    ]);
    let dialog = state.rules.screen.add.as_mut().unwrap();
    dialog.toggle_listed(0);
    dialog.toggle_listed(1);
    let before: Vec<_> = dialog.chosen.iter().map(|item| item.key.clone()).collect();
    let Some(Job::LoadProcesses(request)) = state.act(Action::RefreshProcesses) else {
        panic!("the list is read again");
    };
    // The list changed meanwhile: one program closed, another started.
    state.reduce(WorkerEvent::Processes {
        request,
        result: Ok(group_processes(vec![
            running("Other.exe", other, true),
            running("Curl.exe", third, true),
            running("Tool.exe", path, true),
        ])),
    });
    let dialog = state.rules.screen.add.as_ref().unwrap();
    let after: Vec<_> = dialog.chosen.iter().map(|item| item.key.clone()).collect();
    assert_eq!(after, before);
    for group in &dialog.processes {
        assert_eq!(
            dialog.is_chosen(&group.key()),
            group.name != "Curl.exe",
            "{}",
            group.name
        );
    }
    let Some(Job::LoadProcesses(request)) = state.act(Action::RefreshProcesses) else {
        panic!("the list is read again");
    };
    state.reduce(WorkerEvent::Processes {
        request,
        result: Ok(group_processes(vec![running("Curl.exe", third, true)])),
    });
    let dialog = state.rules.screen.add.as_ref().unwrap();
    assert_eq!(dialog.chosen.len(), 2, "a program that closed stays ticked");
}

#[test]
fn editing_a_program_rule_keeps_one_ticked_and_ticking_another_replaces_it() {
    let (path, other, _) = tool_paths();
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    let set = state.selected_rules().unwrap().id.clone();
    let rule = Rule {
        id: RuleId::new("program"),
        matcher: RuleMatcher::Process(ProcessMatch::Path(PathBuf::from(path))),
        target: RuleTarget::Proxy,
        enabled: true,
        exit: None,
    };
    let mut dialog = AddRuleDialog::for_rule(set, &rule).unwrap();
    dialog.processes = crate::rules::group_processes(vec![
        running("Tool.exe", path, true),
        running("Tool.exe", other, true),
    ]);
    assert_eq!(dialog.chosen.len(), 1);
    dialog.toggle_listed(1);
    assert_eq!(dialog.chosen.len(), 1);
    assert_eq!(dialog.chosen[0].path.as_deref(), Some(other.as_ref()));
    dialog.toggle_listed(1);
    assert!(
        dialog.process_rules().is_none(),
        "unticked: nothing to save"
    );
}

#[test]
fn too_many_programs_make_nothing_to_add() {
    let mut state = program_dialog(Vec::new());
    let dialog = state.rules.screen.add.as_mut().unwrap();
    for index in 0..=MAX_PROGRAMS {
        dialog.tick_program(&format!("program{index}.exe"));
    }
    assert!(dialog.too_many_programs());
    assert!(dialog.process_rules().is_none());
    assert!(state.act(Action::SubmitAddRule).is_none());
    let dialog = state.rules.screen.add.as_mut().unwrap();
    dialog.tick_program("program0.exe");
    assert!(!dialog.too_many_programs());
    assert_eq!(dialog.process_rules().unwrap().len(), MAX_PROGRAMS);
}

#[test]
fn clearing_the_chosen_programs_keeps_the_search() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    state.act(Action::OpenAddRuleFor(RuleMatcher::Process(
        ProcessMatch::Name("Tool.exe".into()),
    )));
    let dialog = state.rules.screen.add.as_mut().unwrap();
    dialog.process_filter = "to".into();
    dialog.clear_chosen();
    assert!(dialog.chosen.is_empty());
    assert_eq!(dialog.process_filter, "to");
    assert!(state.act(Action::SubmitAddRule).is_none());
}

#[test]
fn the_address_kind_adds_domain_rules_and_ip_rules_from_one_field() {
    for (subdomains, domains) in [
        (
            true,
            [
                DomainMatch::Suffix("youtube.com".into()),
                DomainMatch::Suffix("example.com".into()),
            ],
        ),
        (
            false,
            [
                DomainMatch::Exact("youtube.com".into()),
                DomainMatch::Exact("www.example.com".into()),
            ],
        ),
    ] {
        let mut state = state_with_rules();
        state.act(Action::OpenRules);
        state.act(Action::OpenAddRule);
        state.act(Action::SelectRuleInput(RuleInputKind::Address));
        let dialog = state.rules.screen.add.as_mut().unwrap();
        dialog.subdomains = subdomains;
        dialog.add_addresses(
            "youtube.com, 192.0.2.1\n198.51.100.0/24; 2001:db8::1 https://www.example.com/path",
        );
        assert_eq!(dialog.addresses.len(), 5);
        let count = dialog.address_rule_count();
        let Some(Job::AddRules(_, matchers, RuleDestination::Proxy)) =
            state.act(Action::SubmitAddRule)
        else {
            panic!("the field adds its rules in one job");
        };
        assert_eq!(
            matchers,
            [
                RuleMatcher::Domain(domains[0].clone()),
                RuleMatcher::IpCidr("192.0.2.1/32".into()),
                RuleMatcher::IpCidr("198.51.100.0/24".into()),
                RuleMatcher::IpCidr("2001:db8::1/128".into()),
                RuleMatcher::Domain(domains[1].clone()),
            ]
        );
        assert_eq!(matchers.len(), count, "the button counted these rules");
    }
}

#[test]
fn a_bad_or_repeated_address_never_reaches_the_rules() {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    state.act(Action::OpenAddRule);
    state.act(Action::SelectRuleInput(RuleInputKind::Address));
    let dialog = state.rules.screen.add.as_mut().unwrap();
    dialog.add_addresses("example.com bad..domain example.com");
    assert_eq!(dialog.addresses.len(), 2);
    assert!(state.act(Action::SubmitAddRule).is_none());
    let dialog = state.rules.screen.add.as_mut().unwrap();
    dialog.remove_last_address();
    dialog.address_input = "192.0.2.1".into();
    assert!(matches!(
        state.act(Action::SubmitAddRule),
        Some(Job::AddRules(_, matchers, _)) if matchers == [
            RuleMatcher::Domain(DomainMatch::Suffix("example.com".into())),
            RuleMatcher::IpCidr("192.0.2.1/32".into()),
        ]
    ));
    let dialog = state.rules.screen.add.as_ref().unwrap();
    assert!(
        dialog.address_input.is_empty(),
        "the typed item became a chip"
    );
    assert_eq!(dialog.addresses.len(), 2);
}

#[test]
fn the_address_field_takes_no_more_than_its_limit() {
    let mut dialog = AddRuleDialog::new(RuleSetId::new("set"));
    dialog.kind = RuleInputKind::Address;
    let items: Vec<_> = (0..=MAX_ADDRESSES)
        .map(|index| format!("site{index}.example"))
        .collect();
    dialog.add_addresses(&items.join(" "));
    assert_eq!(dialog.addresses.len(), MAX_ADDRESSES);
    assert!(dialog.too_many_addresses());
    assert!(dialog.address_rules().is_none());
    dialog.remove_address(0);
    assert!(!dialog.too_many_addresses());
    assert_eq!(
        dialog.address_rules().map(|rules| rules.len()),
        Some(MAX_ADDRESSES - 1)
    );
}

#[test]
fn editing_a_domain_or_an_ip_rule_shows_one_chip_and_takes_one() {
    for matcher in [
        RuleMatcher::Domain(DomainMatch::Exact("example.com".into())),
        RuleMatcher::IpCidr("192.0.2.0/24".into()),
    ] {
        let mut state = state_with_rules();
        let id = state.config.rule_sets[1].rules[0].id.clone();
        state.config.rule_sets[1].rules[0].matcher = matcher.clone();
        state.act(Action::OpenRules);
        state.act(Action::OpenEditRule(id.clone()));
        let dialog = state.rules.screen.add.as_mut().unwrap();
        assert_eq!(dialog.kind, RuleInputKind::Address);
        assert_eq!(dialog.addresses.len(), 1);
        dialog.add_addresses("example.org");
        assert_eq!(
            dialog.addresses.len(),
            1,
            "{matcher:?}: an edit takes one item"
        );
        dialog.remove_last_address();
        dialog.add_addresses("203.0.113.1 example.org");
        assert!(matches!(
            state.act(Action::SubmitAddRule),
            Some(Job::UpdateRule(_, rule, RuleMatcher::IpCidr(cidr), _))
                if rule == id && cidr == "203.0.113.1/32"
        ));
    }
}

#[test]
fn a_keyword_rule_does_not_open_the_dialog() {
    let mut state = state_with_rules();
    let id = state.config.rule_sets[1].rules[0].id.clone();
    state.config.rule_sets[1].rules[0].matcher =
        RuleMatcher::Domain(DomainMatch::Keyword("example".into()));
    state.act(Action::OpenRules);
    assert!(state.act(Action::OpenEditRule(id)).is_none());
    assert!(state.rules.screen.add.is_none());
    assert!(
        AddRuleDialog::new(RuleSetId::new("set"))
            .with_matcher(&RuleMatcher::Domain(DomainMatch::Keyword("example".into())))
            .is_none()
    );
}

#[cfg(not(windows))]
#[test]
fn a_program_given_by_name_is_found_in_its_own_letter_case_only() {
    for (name, found) in [("Tool", true), ("tool", false)] {
        let mut state = state_with_rules();
        let Some(Job::LoadProcesses(request)) = state.act(Action::OpenAddRuleFor(
            RuleMatcher::Process(ProcessMatch::Name(name.into())),
        )) else {
            panic!("a program rule loads the program list");
        };
        state.reduce(WorkerEvent::Processes {
            request,
            result: Ok(group_processes(vec![running(
                "Tool",
                "/opt/apps/Tool",
                true,
            )])),
        });
        let dialog = state.rules.screen.add.as_ref().unwrap();
        assert_eq!(dialog.chosen[0].path.is_some(), found, "{name}");
        assert_eq!(
            dialog.process_rules(),
            Some(vec![RuleMatcher::Process(ProcessMatch::Name(name.into()))]),
            "the rule stays as it was given"
        );
    }
}
