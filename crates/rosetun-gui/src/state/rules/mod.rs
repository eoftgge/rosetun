use std::collections::BTreeSet;

use rosetun_config::{RuleId, RuleMatcher, RuleSet, RuleSetId, RuleTarget};

use super::{Action, Job, Screen, State};
use crate::errors;
use crate::reorder::drop_target;
use crate::rules::{RuleFilter, visible_rules};
use crate::worker::WorkerEvent;

mod dialog;

pub(crate) use dialog::{AddRuleDialog, RuleInputKind};

pub(crate) enum NameDialogKind {
    Create,
    Rename(RuleSetId),
}

pub(crate) struct NameDialog {
    pub(crate) kind: NameDialogKind,
    pub(crate) name: String,
    pub(crate) error: Option<String>,
    pub(crate) focus: bool,
}

pub(crate) enum DeleteDialog {
    Set(RuleSetId),
    Rule { set: RuleSetId, rule: RuleId },
    Rules { set: RuleSetId, rules: Vec<RuleId> },
}

#[derive(Default)]
pub(crate) struct RuleScreen {
    pub(crate) selected_set: Option<RuleSetId>,
    pub(crate) filter: RuleFilter,
    pub(crate) selected_rules: BTreeSet<RuleId>,
    pub(crate) selection_anchor: Option<RuleId>,
    pub(crate) name: Option<NameDialog>,
    pub(crate) delete: Option<DeleteDialog>,
    pub(crate) add: Option<AddRuleDialog>,
    opened: bool,
}

impl RuleScreen {
    pub(super) fn clear_selection(&mut self) {
        self.selected_rules.clear();
        self.selection_anchor = None;
    }
}

#[derive(Default)]
pub(crate) struct RulesState {
    pub(crate) screen: RuleScreen,
    next_process_request: u64,
}

impl State {
    pub(crate) fn selected_rules(&self) -> Option<&RuleSet> {
        let id = self.rules.screen.selected_set.as_ref()?;
        self.config.rule_sets.iter().find(|set| &set.id == id)
    }

    fn visible_rule_ids(&self) -> Vec<RuleId> {
        self.selected_rules()
            .map(|set| {
                visible_rules(set, &self.rules.screen.filter)
                    .into_iter()
                    .map(|(_, rule)| rule.id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn selected_rule_ids(&self) -> Vec<RuleId> {
        self.visible_rule_ids()
            .into_iter()
            .filter(|id| self.rules.screen.selected_rules.contains(id))
            .collect()
    }

    fn select_rule(&mut self, rule: RuleId, additive: bool, range: bool) {
        let visible = self.visible_rule_ids();
        let Some(index) = visible.iter().position(|id| id == &rule) else {
            return;
        };
        let selection = &mut self.rules.screen.selected_rules;
        if range {
            let anchor = self
                .rules
                .screen
                .selection_anchor
                .as_ref()
                .filter(|id| selection.contains(*id))
                .and_then(|id| visible.iter().position(|item| item == id))
                .or_else(|| visible.iter().rposition(|id| selection.contains(id)))
                .unwrap_or(index);
            selection.clear();
            selection.extend(
                visible[anchor.min(index)..=anchor.max(index)]
                    .iter()
                    .cloned(),
            );
            self.rules.screen.selection_anchor = Some(visible[anchor].clone());
        } else if additive {
            if !selection.insert(rule.clone()) {
                selection.remove(&rule);
                self.rules.screen.selection_anchor = visible
                    .iter()
                    .rev()
                    .find(|id| selection.contains(*id))
                    .cloned();
            } else {
                self.rules.screen.selection_anchor = Some(rule);
            }
        } else {
            selection.clear();
            selection.insert(rule.clone());
            self.rules.screen.selection_anchor = Some(rule);
        }
    }

    pub(crate) fn can_edit_rules(&self) -> bool {
        self.config_ready
            && !self.operations.rules_edit
            && !self.operations.rules
            && !self.operations.helper
    }

    fn preferred_set(&self) -> Option<RuleSetId> {
        self.config
            .active_rules()
            .or_else(|| self.config.rule_sets.first())
            .map(|set| set.id.clone())
    }

    pub(super) fn reconcile_selected_set(&mut self) {
        let previous = self.rules.screen.selected_set.clone();
        if self.rules.screen.opened && self.selected_rules().is_none() {
            self.rules.screen.selected_set = self.preferred_set();
        }
        if self.rules.screen.selected_set != previous {
            self.rules.screen.clear_selection();
        } else {
            let existing: BTreeSet<_> = self
                .selected_rules()
                .into_iter()
                .flat_map(|set| set.rules.iter().map(|rule| rule.id.clone()))
                .collect();
            self.rules
                .screen
                .selected_rules
                .retain(|id| existing.contains(id));
            if self
                .rules
                .screen
                .selection_anchor
                .as_ref()
                .is_some_and(|id| !self.rules.screen.selected_rules.contains(id))
            {
                self.rules.screen.selection_anchor = None;
            }
        }
        if self
            .rules
            .screen
            .add
            .as_ref()
            .is_some_and(|dialog| !self.config.rule_sets.iter().any(|set| set.id == dialog.set))
        {
            self.rules.screen.add = None;
        }
    }

    fn name_error(&mut self, error: String) {
        let message = self.text(&error);
        if let Some(dialog) = &mut self.rules.screen.name {
            dialog.error = Some(message);
        } else {
            self.operation_error = Some(message);
        }
    }

    fn finish_rule_edit(&mut self, result: Result<(), rosetun_core::RuleSetError>) {
        self.operations.rules_edit = false;
        self.operation_error = result
            .err()
            .map(|error| self.text(&errors::rule_set(crate::i18n::language(), &error)));
    }

    fn finish_dialog_rule_edit(&mut self, result: Result<(), rosetun_core::RuleSetError>) {
        self.operations.rules_edit = false;
        if self.rules.screen.add.is_some() {
            match result {
                Ok(()) => {
                    self.rules.screen.add = None;
                    self.rules.screen.filter = RuleFilter::default();
                    self.rules.screen.clear_selection();
                }
                Err(error) => {
                    let message = self.text(&errors::rule_set(crate::i18n::language(), &error));
                    if let Some(dialog) = &mut self.rules.screen.add {
                        dialog.busy = false;
                        dialog.error = Some(message);
                    }
                }
            }
        } else {
            self.operation_error = result
                .err()
                .map(|error| self.text(&errors::rule_set(crate::i18n::language(), &error)));
        }
    }

    pub(super) fn start_rule_edit(&mut self, job: Job) -> Option<Job> {
        self.operations.rules_edit = true;
        self.operation_error = None;
        Some(job)
    }

    pub(super) fn reduce_rules(&mut self, event: WorkerEvent) {
        match event {
            WorkerEvent::CreateRuleSet(result) => {
                self.operations.rules_edit = false;
                match result {
                    Ok(set) => {
                        self.rules.screen.selected_set = Some(set.id);
                        self.rules.screen.name = None;
                    }
                    Err(error) => {
                        self.name_error(errors::rule_set(crate::i18n::language(), &error))
                    }
                }
            }
            WorkerEvent::RenameRuleSet(result) => {
                self.operations.rules_edit = false;
                match result {
                    Ok(()) => self.rules.screen.name = None,
                    Err(error) => {
                        self.name_error(errors::rule_set(crate::i18n::language(), &error))
                    }
                }
            }
            WorkerEvent::DeleteRuleSet(result) => {
                self.rules.screen.delete = None;
                self.finish_rule_edit(result);
            }
            WorkerEvent::SetDefaultTarget(result) => self.finish_rule_edit(result),
            event @ WorkerEvent::Processes { .. } => self.reduce_rule_dialog(event),
            #[cfg(windows)]
            event @ WorkerEvent::BrowsedExecutable(_) => self.reduce_rule_dialog(event),
            WorkerEvent::AddRule(result) => self.finish_dialog_rule_edit(result.map(|_| ())),
            WorkerEvent::AddRules(result) => {
                if let Some(id) = self.keep_temporary.take() {
                    let success = result.is_ok();
                    self.finish_rule_edit(result.map(|_| ()));
                    if success && self.temporary_rules_loaded {
                        self.keep_apply = Some(id);
                    }
                } else {
                    self.finish_dialog_rule_edit(result.map(|_| ()));
                }
            }
            WorkerEvent::UpdateRule(result) => self.finish_dialog_rule_edit(result),
            WorkerEvent::SetRuleTarget(result) => self.finish_rule_edit(result),
            WorkerEvent::SetRuleEnabled(result) => self.finish_rule_edit(result),
            WorkerEvent::MoveRule(result) => self.finish_rule_edit(result),
            WorkerEvent::MoveRules(result) => self.finish_rule_edit(result),
            WorkerEvent::RemoveRule(result) | WorkerEvent::RemoveRules(result) => {
                if result.is_ok() {
                    self.rules.screen.clear_selection();
                }
                self.rules.screen.delete = None;
                self.finish_rule_edit(result);
            }
            _ => unreachable!("only rule events are dispatched here"),
        }
    }

    pub(super) fn act_rules(&mut self, action: Action) -> Option<Job> {
        match action {
            Action::OpenRules => {
                if !self.rules.screen.opened {
                    self.rules.screen.selected_set = self.preferred_set();
                    self.rules.screen.clear_selection();
                }
                self.rules.screen.opened = true;
                return self.show_screen(Screen::Rules);
            }
            Action::OpenActiveRules => {
                let preferred = self.preferred_set();
                if self.rules.screen.selected_set != preferred {
                    self.rules.screen.clear_selection();
                }
                self.rules.screen.selected_set = preferred;
                self.rules.screen.opened = true;
                return self.show_screen(Screen::Rules);
            }
            Action::ChooseRuleSet(id) => {
                if self.config.rule_sets.iter().any(|set| set.id == id) {
                    if self.rules.screen.selected_set.as_ref() != Some(&id) {
                        self.rules.screen.clear_selection();
                    }
                    self.rules.screen.selected_set = Some(id);
                }
            }
            Action::SetRuleTypeFilter(kind) => {
                if self.rules.screen.filter.kind != kind {
                    self.rules.screen.filter.kind = kind;
                    self.rules.screen.clear_selection();
                }
            }
            Action::SetRuleTargetFilter(target) => {
                if self.rules.screen.filter.target != target {
                    self.rules.screen.filter.target = target;
                    self.rules.screen.clear_selection();
                }
            }
            Action::SelectRule {
                rule,
                additive,
                range,
            } => {
                if self.screen == Screen::Rules {
                    self.select_rule(rule, additive, range);
                }
            }
            Action::SelectVisibleRules => {
                if self.screen == Screen::Rules {
                    let visible = self.visible_rule_ids();
                    self.rules.screen.selected_rules = visible.iter().cloned().collect();
                    self.rules.screen.selection_anchor = visible.last().cloned();
                }
            }
            Action::ClearRuleSelection => self.rules.screen.clear_selection(),
            Action::OpenCreateSet => {
                if self.can_edit_rules() && self.rules.screen.name.is_none() {
                    self.rules.screen.name = Some(NameDialog {
                        kind: NameDialogKind::Create,
                        name: tr!("basic").to_owned(),
                        error: None,
                        focus: true,
                    });
                }
            }
            Action::OpenRenameSet => {
                if self.can_edit_rules()
                    && self.rules.screen.name.is_none()
                    && let Some(set) = self.selected_rules()
                {
                    self.rules.screen.name = Some(NameDialog {
                        kind: NameDialogKind::Rename(set.id.clone()),
                        name: set.name.clone(),
                        error: None,
                        focus: true,
                    });
                }
            }
            Action::CancelSetName => {
                if !self.operations.rules_edit {
                    self.rules.screen.name = None;
                }
            }
            Action::SubmitSetName => {
                if self.can_edit_rules()
                    && let Some(dialog) = &self.rules.screen.name
                    && !dialog.name.trim().is_empty()
                {
                    let name = dialog.name.trim().to_owned();
                    let job = match &dialog.kind {
                        NameDialogKind::Create => Job::CreateRuleSet(name),
                        NameDialogKind::Rename(id) => Job::RenameRuleSet(id.clone(), name),
                    };
                    if let Some(dialog) = &mut self.rules.screen.name {
                        dialog.error = None;
                    }
                    return self.start_rule_edit(job);
                }
            }
            Action::RequestDeleteSet => {
                if self.can_edit_rules()
                    && self.rules.screen.delete.is_none()
                    && let Some(set) = self.selected_rules()
                {
                    self.rules.screen.delete = Some(DeleteDialog::Set(set.id.clone()));
                }
            }
            Action::RequestDeleteRule(rule) => {
                if self.can_edit_rules()
                    && self.rules.screen.delete.is_none()
                    && let Some(set) = self.selected_rules()
                    && set.rules.iter().any(|item| item.id == rule)
                {
                    self.rules.screen.delete = Some(DeleteDialog::Rule {
                        set: set.id.clone(),
                        rule,
                    });
                }
            }
            Action::RequestDeleteSelectedRules => {
                if self.can_edit_rules()
                    && self.rules.screen.delete.is_none()
                    && let Some(set) = self.selected_rules()
                {
                    let set_id = set.id.clone();
                    let rules = self.selected_rule_ids();
                    self.rules.screen.delete = match rules.as_slice() {
                        [] => None,
                        [rule] => Some(DeleteDialog::Rule {
                            set: set_id,
                            rule: rule.clone(),
                        }),
                        _ => Some(DeleteDialog::Rules { set: set_id, rules }),
                    };
                }
            }
            Action::CancelRuleDelete => {
                if !self.operations.rules_edit {
                    self.rules.screen.delete = None;
                }
            }
            Action::ConfirmRuleDelete => {
                if self.can_edit_rules()
                    && let Some(dialog) = &self.rules.screen.delete
                {
                    let job = match dialog {
                        DeleteDialog::Set(id) => Job::DeleteRuleSet(id.clone()),
                        DeleteDialog::Rule { set, rule } => {
                            Job::RemoveRule(set.clone(), rule.clone())
                        }
                        DeleteDialog::Rules { set, rules } => {
                            Job::RemoveRules(set.clone(), rules.clone())
                        }
                    };
                    return self.start_rule_edit(job);
                }
            }
            Action::SetDefaultTarget(target) => {
                if self.can_edit_rules()
                    && matches!(target, RuleTarget::Proxy | RuleTarget::Direct)
                    && let Some(set) = self.selected_rules()
                    && set.default_target != target
                {
                    return self.start_rule_edit(Job::SetDefaultTarget(set.id.clone(), target));
                }
            }
            Action::AddTemplate(template) => {
                if self.can_edit_rules()
                    && let Some(set) = self.selected_rules()
                    && !set.rules.iter().any(|rule| {
                        matches!(&rule.matcher, RuleMatcher::Template(current) if *current == template)
                    })
                {
                    return self.start_rule_edit(Job::AddRule(
                        set.id.clone(),
                        RuleMatcher::Template(template),
                        template.default_target(),
                    ));
                }
            }
            Action::RemoveTemplate(template) => {
                if self.can_edit_rules()
                    && let Some(set) = self.selected_rules()
                    && let Some(rule) = set.rules.iter().find(|rule| {
                        matches!(&rule.matcher, RuleMatcher::Template(current) if *current == template)
                    })
                {
                    return self.start_rule_edit(Job::RemoveRule(set.id.clone(), rule.id.clone()));
                }
            }
            action @ (Action::OpenAddRule | Action::OpenEditRule(_) | Action::CancelAddRule
            | Action::SelectRuleInput(_) | Action::RefreshProcesses | Action::SubmitAddRule) => {
                return self.act_rule_dialog(action);
            }
            #[cfg(windows)]
            Action::BrowseExecutable => return self.act_rule_dialog(Action::BrowseExecutable),
            Action::SetRuleTarget(rule, target) => {
                if self.can_edit_rules()
                    && let Some(set) = self.selected_rules()
                    && set
                        .rules
                        .iter()
                        .any(|item| item.id == rule && item.target != target)
                {
                    return self.start_rule_edit(Job::SetRuleTarget(set.id.clone(), rule, target));
                }
            }
            Action::SetRuleEnabled(rule, enabled) => {
                if self.can_edit_rules()
                    && let Some(set) = self.selected_rules()
                    && set
                        .rules
                        .iter()
                        .any(|item| item.id == rule && item.enabled != enabled)
                {
                    return self.start_rule_edit(Job::SetRuleEnabled(
                        set.id.clone(),
                        rule,
                        enabled,
                    ));
                }
            }
            Action::DropRule(rule, slot) => {
                if self.can_edit_rules()
                    && !self.rules.screen.filter.is_active()
                    && let Some(set) = self.selected_rules()
                    && let Some(from) = set.rules.iter().position(|item| item.id == rule)
                    && let Some(to) = drop_target(from, slot, set.rules.len())
                {
                    return self.start_rule_edit(Job::MoveRule(set.id.clone(), rule, to));
                }
            }
            Action::DropRules(rules, slot) => {
                if self.can_edit_rules()
                    && !self.rules.screen.filter.is_active()
                    && rules.len() >= 2
                    && rules.len() == self.rules.screen.selected_rules.len()
                    && rules.iter().cloned().collect::<BTreeSet<_>>()
                        == self.rules.screen.selected_rules
                    && let Some(set) = self.selected_rules()
                    && rules.len() <= set.rules.len()
                    && slot <= set.rules.len() - rules.len()
                    && rules
                        .iter()
                        .all(|id| set.rules.iter().any(|rule| &rule.id == id))
                {
                    return self.start_rule_edit(Job::MoveRules(set.id.clone(), rules, slot));
                }
            }
            Action::MoveRuleToTop(rule) => {
                if self.can_edit_rules()
                    && let Some(set) = self.selected_rules()
                    && set
                        .rules
                        .iter()
                        .position(|item| item.id == rule)
                        .is_some_and(|index| index > 0)
                {
                    return self.start_rule_edit(Job::MoveRule(set.id.clone(), rule, 0));
                }
            }
            move_action @ (Action::MoveSelectedRulesToTop | Action::MoveSelectedRulesToEnd) => {
                if self.can_edit_rules()
                    && !self.rules.screen.filter.is_active()
                    && let Some(set) = self.selected_rules()
                {
                    let set_id = set.id.clone();
                    let len = set.rules.len();
                    let rules = self.selected_rule_ids();
                    if rules.len() >= 2 {
                        let at_end = matches!(move_action, Action::MoveSelectedRulesToEnd);
                        let index = if at_end { len - rules.len() } else { 0 };
                        let already_there = if at_end {
                            set.rules[len - rules.len()..]
                                .iter()
                                .all(|rule| self.rules.screen.selected_rules.contains(&rule.id))
                        } else {
                            set.rules[..rules.len()]
                                .iter()
                                .all(|rule| self.rules.screen.selected_rules.contains(&rule.id))
                        };
                        if !already_there {
                            return self.start_rule_edit(Job::MoveRules(set_id, rules, index));
                        }
                    }
                }
            }
            _ => unreachable!("only rule actions are dispatched here"),
        }
        None
    }
}
