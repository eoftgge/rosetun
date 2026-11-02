use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rosetun_core::Store;

use super::*;
use crate::state::rules::{MAX_UNDO_RULES, MAX_UNDO_STEPS, UNDO_NOTICE_MS};

static NEXT_STORE: AtomicU64 = AtomicU64::new(0);

/// A configuration file of its own and the worker's part of every rule job, run in place.
struct Saved {
    directory: PathBuf,
    store: Store,
    generation: u64,
}

impl Saved {
    fn new(state: &State) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "rosetun-gui-rule-history-{}-{}",
            std::process::id(),
            NEXT_STORE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).unwrap();
        let store = Store::at(directory.join("config.json"));
        let config = state.config.clone();
        store
            .modify(|current| {
                *current = config;
                Ok::<_, rosetun_core::StoreError>(())
            })
            .unwrap();
        Self {
            directory,
            store,
            generation: 100,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        fs::read(self.store.path()).unwrap()
    }

    fn run(&mut self, state: &mut State, job: Option<Job>) {
        let store = &self.store;
        let event = match job.expect("the action starts a job") {
            Job::SelectRuleSet(id) => {
                WorkerEvent::SelectRuleSet(rosetun_core::select_rule_set(store, id.as_ref()))
            }
            Job::CreateRuleSet(name) => WorkerEvent::CreateRuleSet(rosetun_core::create_rule_set(
                store,
                &name,
                RuleTarget::Proxy,
            )),
            Job::RenameRuleSet(id, name) => {
                WorkerEvent::RenameRuleSet(rosetun_core::rename_rule_set(store, &id, &name))
            }
            Job::DeleteRuleSet(id) => {
                WorkerEvent::DeleteRuleSet(rosetun_core::delete_rule_set(store, &id))
            }
            Job::SetDefaultTarget(id, target) => {
                WorkerEvent::SetDefaultTarget(rosetun_core::set_default_target(store, &id, target))
            }
            Job::AddRule(set, matcher, target) => {
                WorkerEvent::AddRule(rosetun_core::add_rule(store, &set, matcher, &target))
            }
            Job::AddRules(set, matchers, target) => {
                WorkerEvent::AddRules(rosetun_core::add_rules(store, &set, matchers, &target))
            }
            Job::UpdateRule(set, rule, matcher, target) => WorkerEvent::UpdateRule(
                rosetun_core::update_rule(store, &set, &rule, matcher, &target),
            ),
            Job::SetRuleTarget(set, rule, target) => WorkerEvent::SetRuleTarget(
                rosetun_core::set_rule_target(store, &set, &rule, &target),
            ),
            Job::SetRuleEnabled(set, rule, enabled) => WorkerEvent::SetRuleEnabled(
                rosetun_core::set_rule_enabled(store, &set, &rule, enabled),
            ),
            Job::MoveRule(set, rule, to) => {
                WorkerEvent::MoveRule(rosetun_core::move_rule(store, &set, &rule, to))
            }
            Job::MoveRules(set, rules, to) => {
                WorkerEvent::MoveRules(rosetun_core::move_rules(store, &set, &rules, to))
            }
            Job::RemoveRule(set, rule) => {
                WorkerEvent::RemoveRule(rosetun_core::remove_rule(store, &set, &rule))
            }
            Job::RemoveRules(set, rules) => {
                WorkerEvent::RemoveRules(rosetun_core::remove_rules(store, &set, &rules))
            }
            Job::RestoreRuleSets(snapshot) => {
                WorkerEvent::RestoreRuleSets(rosetun_core::restore_rule_sets(store, &snapshot))
            }
            _ => panic!("not a rule job"),
        };
        self.generation += 1;
        state.reduce(WorkerEvent::Config {
            generation: self.generation,
            config: store.load().unwrap(),
        });
        state.reduce(event);
    }

    fn act(&mut self, state: &mut State, action: Action) {
        let job = state.act(action);
        self.run(state, job);
    }
}

impl Drop for Saved {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn rules_state() -> State {
    let mut state = state_with_rules();
    state.act(Action::OpenRules);
    state
}

fn select(state: &mut State, rule: &str) {
    state.act(Action::SelectRule {
        rule: RuleId::new(rule),
        additive: false,
        range: false,
    });
}

/// Puts the state where an edit needs it; the edit's own action comes after.
type Prepare = fn(&mut State);

fn no_preparation(_: &mut State) {}

fn select_first_and_last(state: &mut State) {
    select(state, "0");
    state.act(Action::SelectRule {
        rule: RuleId::new("2"),
        additive: true,
        range: false,
    });
}

fn select_first(state: &mut State) {
    select(state, "0");
}

fn open_rename(state: &mut State) {
    state.act(Action::OpenRenameSet);
    state.rules.screen.name.as_mut().unwrap().name = "Renamed".into();
}

fn open_create(state: &mut State) {
    state.act(Action::OpenCreateSet);
}

fn open_delete_set(state: &mut State) {
    state.act(Action::RequestDeleteSet);
}

fn open_new_domain(state: &mut State) {
    state.act(Action::OpenAddRule);
    state.act(Action::SelectRuleInput(RuleInputKind::Domain));
    let dialog = state.rules.screen.add.as_mut().unwrap();
    dialog.domains = "new.example".into();
    dialog.subdomains = false;
}

fn open_edit_first(state: &mut State) {
    state.act(Action::OpenEditRule(RuleId::new("0")));
    let dialog = state.rules.screen.add.as_mut().unwrap();
    dialog.domains = "changed.example".into();
    dialog.subdomains = false;
}

fn rule_edits() -> Vec<(&'static str, Prepare, Action)> {
    vec![
        (
            "enable",
            no_preparation,
            Action::SetRuleEnabled(RuleId::new("1"), false),
        ),
        (
            "target",
            no_preparation,
            Action::SetRuleTarget(RuleId::new("1"), RuleDestination::Block),
        ),
        ("drag", no_preparation, Action::DropRule(RuleId::new("2"), 0)),
        ("to top", no_preparation, Action::MoveRuleToTop(RuleId::new("2"))),
        (
            "move selected",
            select_first_and_last,
            Action::MoveSelectedRulesToEnd,
        ),
        ("delete", no_preparation, Action::DeleteRule(RuleId::new("1"))),
        ("delete key", select_first, Action::DeleteSelectedRules),
        (
            "delete selected",
            select_first_and_last,
            Action::DeleteSelectedRules,
        ),
        (
            "default",
            no_preparation,
            Action::SetDefaultTarget(RuleTarget::Direct),
        ),
        (
            "template",
            no_preparation,
            Action::AddTemplate(RuleTemplate::Youtube),
        ),
        ("add", open_new_domain, Action::SubmitAddRule),
        ("edit", open_edit_first, Action::SubmitAddRule),
        ("rename set", open_rename, Action::SubmitSetName),
        ("create set", open_create, Action::SubmitSetName),
        ("delete set", open_delete_set, Action::ConfirmDeleteSet),
        (
            "make active",
            no_preparation,
            Action::SelectRuleSet(Some(RuleSetId::new("1"))),
        ),
    ]
}

#[test]
fn every_rule_edit_is_one_step_and_undo_writes_the_file_as_before() {
    for (name, prepare, action) in rule_edits() {
        let mut state = rules_state();
        let mut saved = Saved::new(&state);
        let before = saved.bytes();
        let config = saved.store.load().unwrap();
        prepare(&mut state);

        saved.act(&mut state, action);
        assert_ne!(saved.bytes(), before, "{name}: the edit is saved");
        assert_eq!(state.rules.history.undo_len(), 1, "{name}");
        assert!(state.can_undo_rules(), "{name}");

        saved.act(&mut state, Action::UndoRules);
        assert_eq!(saved.bytes(), before, "{name}: undo restores the file");
        assert_eq!(state.config, config, "{name}");
        assert_eq!(state.rules.history.undo_len(), 0, "{name}");
        assert_eq!(state.rules.history.redo_len(), 1, "{name}");
        assert!(state.act(Action::UndoRules).is_none(), "{name}");
    }
}

#[test]
fn undo_saves_the_same_configuration_format() {
    let mut state = rules_state();
    let mut saved = Saved::new(&state);
    saved.act(&mut state, Action::DeleteRule(RuleId::new("0")));
    saved.act(&mut state, Action::UndoRules);

    let file: serde_json::Value = serde_json::from_slice(&saved.bytes()).unwrap();
    assert_eq!(
        file["version"].as_u64(),
        Some(u64::from(rosetun_config::CONFIG_VERSION))
    );
}

#[test]
fn several_steps_undo_one_by_one_in_reverse_and_redo_forward() {
    let mut state = rules_state();
    let mut saved = Saved::new(&state);
    let mut files = vec![saved.bytes()];
    for action in [
        Action::SetRuleEnabled(RuleId::new("0"), false),
        Action::DropRule(RuleId::new("2"), 0),
        Action::DeleteRule(RuleId::new("1")),
    ] {
        saved.act(&mut state, action);
        files.push(saved.bytes());
    }
    assert_eq!(state.rules.history.undo_len(), 3);

    for expected in files.iter().rev().skip(1) {
        saved.act(&mut state, Action::UndoRules);
        assert_eq!(&saved.bytes(), expected);
    }
    assert!(!state.can_undo_rules());
    for expected in files.iter().skip(1) {
        saved.act(&mut state, Action::RedoRules);
        assert_eq!(&saved.bytes(), expected);
    }
    assert!(!state.can_redo_rules());

    saved.act(&mut state, Action::UndoRules);
    saved.act(&mut state, Action::SetRuleEnabled(RuleId::new("2"), false));
    assert!(!state.can_redo_rules(), "a new edit drops the steps to redo");
}

#[test]
fn history_keeps_only_the_latest_steps() {
    let mut state = rules_state();
    let mut saved = Saved::new(&state);
    for step in 0..MAX_UNDO_STEPS + 5 {
        saved.act(
            &mut state,
            Action::SetRuleEnabled(RuleId::new("0"), step % 2 == 1),
        );
    }
    assert_eq!(state.rules.history.undo_len(), MAX_UNDO_STEPS);
}

#[test]
fn history_drops_the_oldest_steps_beyond_its_rule_budget() {
    let mut state = rules_state();
    let set = &mut state.config.rule_sets[1];
    for index in 3..=MAX_UNDO_RULES / 2 {
        set.rules.push(Rule {
            id: RuleId::new(index.to_string()),
            ..set.rules[0].clone()
        });
    }
    let mut saved = Saved::new(&state);
    for enabled in [false, true, false] {
        saved.act(&mut state, Action::SetRuleEnabled(RuleId::new("0"), enabled));
    }
    assert_eq!(state.rules.history.undo_len(), 1);
}

#[test]
fn undo_waits_for_a_running_save_and_is_not_taken_twice() {
    let mut state = rules_state();
    let mut saved = Saved::new(&state);
    saved.act(&mut state, Action::SetRuleEnabled(RuleId::new("0"), false));
    saved.act(&mut state, Action::SetRuleEnabled(RuleId::new("1"), false));

    state.operations.settings = Some(0);
    assert!(state.act(Action::UndoRules).is_none());
    state.operations.settings = None;
    state.operations.rules_edit = true;
    assert!(state.act(Action::UndoRules).is_none());
    state.operations.rules_edit = false;

    let job = state.act(Action::UndoRules);
    assert!(matches!(job, Some(Job::RestoreRuleSets(_))));
    assert!(state.act(Action::UndoRules).is_none());
    assert!(state.act(Action::RedoRules).is_none());
    saved.run(&mut state, job);
    assert_eq!(state.rules.history.undo_len(), 1);
    assert!(!state.config.rule_sets[1].rules[0].enabled);
    assert!(state.config.rule_sets[1].rules[1].enabled);
}

#[test]
fn a_failed_edit_leaves_no_step_and_a_failed_undo_keeps_it() {
    let mut state = rules_state();
    let mut saved = Saved::new(&state);
    let job = state.act(Action::SetRuleEnabled(RuleId::new("0"), false));
    assert!(job.is_some());
    state.reduce(WorkerEvent::SetRuleEnabled(Err(RuleSetError::RuleNotFound)));
    assert_eq!(state.rules.history.undo_len(), 0);

    saved.act(&mut state, Action::SetRuleEnabled(RuleId::new("0"), false));
    assert!(state.act(Action::UndoRules).is_some());
    state.reduce(WorkerEvent::RestoreRuleSets(Err(RuleSetError::SetNotFound)));
    assert!(state.operation_error.is_some());
    assert_eq!(state.rules.history.undo_len(), 1);
    assert!(state.can_undo_rules());
}

#[test]
fn deleting_shows_an_undo_notice_until_it_expires() {
    let mut state = rules_state();
    let mut saved = Saved::new(&state);
    state.set_frame_time(1_000);
    saved.act(&mut state, Action::DeleteRule(RuleId::new("1")));
    assert!(matches!(
        state.rule_notice(),
        Some((UndoNotice::RulesDeleted(1), _))
    ));
    state.set_frame_time(1_000 + UNDO_NOTICE_MS);
    assert!(state.rule_notice().is_none());

    state.set_frame_time(20_000);
    select_first_and_last(&mut state);
    saved.act(&mut state, Action::DeleteSelectedRules);
    assert!(matches!(
        state.rule_notice(),
        Some((UndoNotice::RulesDeleted(2), _))
    ));
    saved.act(&mut state, Action::UndoRules);
    assert!(state.rule_notice().is_none());

    saved.act(&mut state, Action::SetRuleEnabled(RuleId::new("0"), false));
    assert!(state.rule_notice().is_none(), "a toggle needs no notice");
    saved.act(&mut state, Action::AddTemplate(RuleTemplate::Youtube));
    saved.act(&mut state, Action::RemoveTemplate(RuleTemplate::Youtube));
    assert!(state.rule_notice().is_none(), "a template card is its own undo");

    open_delete_set(&mut state);
    saved.act(&mut state, Action::ConfirmDeleteSet);
    assert!(matches!(
        state.rule_notice(),
        Some((UndoNotice::SetDeleted, _))
    ));
}

#[test]
fn arrows_move_one_selection_and_delete_selects_the_neighbour() {
    let mut state = rules_state();
    let mut saved = Saved::new(&state);
    select(&mut state, "0");
    state.act(Action::StepRuleSelection { down: true });
    assert_eq!(
        state.rules.screen.selected_rules.iter().collect::<Vec<_>>(),
        [&RuleId::new("1")]
    );
    assert!(state.rules.screen.reveal_selection);
    state.act(Action::StepRuleSelection { down: true });
    state.act(Action::StepRuleSelection { down: true });
    assert_eq!(state.rules.screen.selection_anchor, Some(RuleId::new("2")));
    state.act(Action::StepRuleSelection { down: false });
    assert_eq!(state.rules.screen.selection_anchor, Some(RuleId::new("1")));

    saved.act(&mut state, Action::DeleteSelectedRules);
    assert_eq!(
        state.rules.screen.selected_rules.iter().collect::<Vec<_>>(),
        [&RuleId::new("2")]
    );
    saved.act(&mut state, Action::DeleteSelectedRules);
    assert_eq!(
        state.rules.screen.selected_rules.iter().collect::<Vec<_>>(),
        [&RuleId::new("0")],
        "the last rule passes the selection up"
    );

    saved.act(&mut state, Action::UndoRules);
    let ids: Vec<_> = state.config.rule_sets[1]
        .rules
        .iter()
        .map(|rule| rule.id.as_str())
        .collect();
    assert_eq!(ids, ["0", "2"], "the rule is back in its place");
}

#[test]
fn keeping_a_temporary_rule_is_not_a_step() {
    let mut state = connected_state_for_apply();
    state.session.temporary_rules_loaded = true;
    state.session.temporary_rules = vec![temporary_rule("t1", "temporary.example")];
    state.act(Action::OpenRules);
    let mut saved = Saved::new(&state);
    saved.act(&mut state, Action::KeepTemporary(RuleId::new("t1")));
    assert_eq!(state.rules.history.undo_len(), 0);
}
