use rosetun_config::{
    AppConfig, CountryCode, Exit, ExitId, ExitTarget, RuleTarget, Selection, node_country,
};
use rosetun_core::exit_rule_count;

use super::{Action, Job, RulesTab, State};
use crate::errors;
use crate::rules::{RuleFilter, TypeFilter};
use crate::worker::WorkerEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExitKind {
    Country,
    Node,
}

/// "Edit" and "New exit".
pub(crate) struct ExitDialog {
    pub(crate) editing: Option<ExitId>,
    pub(crate) name: String,
    pub(crate) kind: ExitKind,
    pub(crate) country: Option<CountryCode>,
    pub(crate) node: Option<Selection>,
    pub(crate) node_search: String,
    /// The node's own country, the only fallback a node exit can have.
    pub(crate) fallback_country: Option<CountryCode>,
    pub(crate) fallback: bool,
    pub(crate) focus: bool,
    pub(crate) busy: bool,
    pub(crate) error: Option<String>,
}

impl ExitDialog {
    fn new() -> Self {
        Self {
            editing: None,
            name: String::new(),
            kind: ExitKind::Country,
            country: None,
            node: None,
            node_search: String::new(),
            fallback_country: None,
            fallback: true,
            focus: true,
            busy: false,
            error: None,
        }
    }

    fn edit(exit: &Exit) -> Self {
        let mut dialog = Self {
            editing: Some(exit.id.clone()),
            name: exit.name.clone(),
            ..Self::new()
        };
        match &exit.target {
            ExitTarget::Country(code) => dialog.country = Some(code.clone()),
            ExitTarget::Node {
                selection,
                fallback,
            } => {
                dialog.kind = ExitKind::Node;
                dialog.node = Some(selection.clone());
                dialog.fallback = fallback.is_some();
                dialog.fallback_country = fallback.clone();
            }
        }
        dialog
    }

    pub(crate) fn pick_node(&mut self, config: &AppConfig, selection: Selection) {
        self.fallback_country = config
            .subscriptions
            .iter()
            .find(|subscription| subscription.id == selection.subscription)
            .and_then(|subscription| subscription.node(&selection.node))
            .and_then(|node| node_country(&node.name));
        self.node = Some(selection);
        self.error = None;
    }

    pub(crate) fn target(&self) -> Option<ExitTarget> {
        match self.kind {
            ExitKind::Country => self.country.clone().map(ExitTarget::Country),
            ExitKind::Node => self.node.clone().map(|selection| ExitTarget::Node {
                selection,
                fallback: self
                    .fallback_country
                    .clone()
                    .filter(|_| self.fallback),
            }),
        }
    }

    /// Whether Save is allowed; `full` is `destinations::exits_full`.
    pub(crate) fn can_save(&self, full: bool) -> bool {
        !self.busy
            && !self.name.trim().is_empty()
            && self.target().is_some()
            && (self.editing.is_some() || !full)
    }
}

pub(crate) struct RenameExitDialog {
    pub(crate) id: ExitId,
    pub(crate) name: String,
    pub(crate) focus: bool,
    pub(crate) busy: bool,
    pub(crate) error: Option<String>,
}

pub(crate) struct DeleteExitDialog {
    pub(crate) id: ExitId,
    /// Saved and temporary rules that turn into Block.
    pub(crate) rules: usize,
    pub(crate) busy: bool,
    pub(crate) error: Option<String>,
}

#[derive(Default)]
pub(crate) struct ExitsState {
    pub(crate) dialog: Option<ExitDialog>,
    pub(crate) rename: Option<RenameExitDialog>,
    pub(crate) delete: Option<DeleteExitDialog>,
}

impl State {
    fn exit(&self, id: &ExitId) -> Option<&Exit> {
        self.config.exits.iter().find(|exit| &exit.id == id)
    }

    /// Saved and temporary rules that go through this exit.
    pub(crate) fn exit_rules(&self, id: &ExitId) -> usize {
        exit_rule_count(&self.config, id)
            + self
                .session
                .temporary_rules
                .iter()
                .filter(|rule| rule.target == RuleTarget::Exit && rule.exit.as_ref() == Some(id))
                .count()
    }

    fn exit_error(&self, error: &rosetun_core::ExitError) -> String {
        self.text(&errors::exit(crate::i18n::language(), error))
    }

    fn show_exit_rules(&mut self, id: ExitId) -> Option<Job> {
        let has_rules = |set: &rosetun_config::RuleSet| {
            set.rules
                .iter()
                .any(|rule| rule.target == RuleTarget::Exit && rule.exit.as_ref() == Some(&id))
        };
        let job = self.act_rules(Action::OpenRules);
        self.lists.tab = RulesTab::Rules;
        if !self.selected_rules().is_some_and(has_rules)
            && let Some(set) = self
                .config
                .active_rules()
                .filter(|set| has_rules(set))
                .or_else(|| self.config.rule_sets.iter().find(|set| has_rules(set)))
        {
            self.rules.screen.selected_set = Some(set.id.clone());
        }
        self.rules.screen.filter = RuleFilter {
            search: String::new(),
            kind: TypeFilter::All,
            target: Some(RuleTarget::Exit),
            exit: Some(id),
        };
        self.rules.screen.clear_selection();
        job
    }

    fn block_temporary_exit_rules(&mut self, id: &ExitId) {
        for rule in &mut self.session.temporary_rules {
            if rule.exit.as_ref() == Some(id) {
                rule.target = RuleTarget::Block;
                rule.exit = None;
            }
        }
        if self.rules.screen.filter.exit.as_ref() == Some(id) {
            self.rules.screen.filter.exit = None;
        }
        self.refresh_cached_request();
    }

    pub(super) fn act_exits(&mut self, action: Action) -> Option<Job> {
        let can_edit = self.can_edit_rules();
        match action {
            Action::ShowExits => {
                self.lists.tab = RulesTab::Exits;
                return self.act_rules(Action::OpenRules);
            }
            Action::ShowExitRules(id) => return self.show_exit_rules(id),
            Action::OpenNewExit => {
                if can_edit && self.exits.dialog.is_none() {
                    self.exits.dialog = Some(ExitDialog::new());
                }
            }
            Action::OpenEditExit(id) => {
                if can_edit
                    && self.exits.dialog.is_none()
                    && let Some(exit) = self.exit(&id)
                {
                    self.exits.dialog = Some(ExitDialog::edit(exit));
                }
            }
            Action::CancelExitDialog => {
                if self.exits.dialog.as_ref().is_some_and(|dialog| !dialog.busy) {
                    self.exits.dialog = None;
                }
            }
            Action::SubmitExitDialog => {
                let full = crate::destinations::exits_full(&self.config);
                let dialog = self.exits.dialog.as_mut()?;
                if !can_edit || !dialog.can_save(full) {
                    return None;
                }
                let target = dialog.target()?;
                dialog.busy = true;
                dialog.error = None;
                let job = Job::SaveExit {
                    id: dialog.editing.clone(),
                    name: dialog.name.trim().to_owned(),
                    target,
                };
                return self.start_rule_edit(job);
            }
            Action::OpenRenameExit(id) => {
                if can_edit
                    && self.exits.rename.is_none()
                    && let Some(exit) = self.exit(&id)
                {
                    self.exits.rename = Some(RenameExitDialog {
                        id,
                        name: exit.name.clone(),
                        focus: true,
                        busy: false,
                        error: None,
                    });
                }
            }
            Action::CancelRenameExit => {
                if self.exits.rename.as_ref().is_some_and(|dialog| !dialog.busy) {
                    self.exits.rename = None;
                }
            }
            Action::SubmitRenameExit => {
                let dialog = self.exits.rename.as_mut()?;
                if !can_edit || dialog.busy || dialog.name.trim().is_empty() {
                    return None;
                }
                dialog.busy = true;
                let job = Job::RenameExit(dialog.id.clone(), dialog.name.trim().to_owned());
                return self.start_rule_edit(job);
            }
            Action::RequestDeleteExit(id) => {
                if !can_edit || self.exits.delete.is_some() || self.exit(&id).is_none() {
                    return None;
                }
                let rules = self.exit_rules(&id);
                if rules == 0 {
                    return self.start_rule_edit(Job::DeleteExit(id));
                }
                self.exits.delete = Some(DeleteExitDialog {
                    id,
                    rules,
                    busy: false,
                    error: None,
                });
            }
            Action::CancelDeleteExit => {
                if self.exits.delete.as_ref().is_some_and(|dialog| !dialog.busy) {
                    self.exits.delete = None;
                }
            }
            Action::ConfirmDeleteExit => {
                let dialog = self.exits.delete.as_mut()?;
                if !can_edit || dialog.busy {
                    return None;
                }
                dialog.busy = true;
                dialog.error = None;
                let job = Job::DeleteExit(dialog.id.clone());
                return self.start_rule_edit(job);
            }
            _ => unreachable!("only exit actions are dispatched here"),
        }
        None
    }

    pub(super) fn reduce_exits(&mut self, event: WorkerEvent) {
        self.operations.rules_edit = false;
        match event {
            WorkerEvent::SaveExit(result) => {
                let result = result.map_err(|error| self.exit_error(&error));
                if let Some(dialog) = &mut self.exits.dialog {
                    match result {
                        Ok(()) => self.exits.dialog = None,
                        Err(error) => {
                            dialog.busy = false;
                            dialog.error = Some(error);
                        }
                    }
                } else {
                    self.operation_error = result.err();
                }
            }
            WorkerEvent::RenameExit(result) => {
                let result = result.map_err(|error| self.exit_error(&error));
                if let Some(dialog) = &mut self.exits.rename {
                    match result {
                        Ok(()) => self.exits.rename = None,
                        Err(error) => {
                            dialog.busy = false;
                            dialog.error = Some(error);
                        }
                    }
                } else {
                    self.operation_error = result.err();
                }
            }
            WorkerEvent::DeleteExit { id, result } => match result {
                Ok(_) => {
                    self.block_temporary_exit_rules(&id);
                    self.exits.delete = None;
                }
                Err(error) => {
                    let message = self.exit_error(&error);
                    match &mut self.exits.delete {
                        Some(dialog) => {
                            dialog.busy = false;
                            dialog.error = Some(message);
                        }
                        None => self.operation_error = Some(message),
                    }
                }
            },
            _ => unreachable!("only exit events are dispatched here"),
        }
    }

    pub(super) fn reconcile_exits(&mut self) {
        let exists = |id: &ExitId| self.config.exits.iter().any(|exit| &exit.id == id);
        if self
            .exits
            .rename
            .as_ref()
            .is_some_and(|dialog| !dialog.busy && !exists(&dialog.id))
        {
            self.exits.rename = None;
        }
        if self
            .exits
            .delete
            .as_ref()
            .is_some_and(|dialog| !dialog.busy && !exists(&dialog.id))
        {
            self.exits.delete = None;
        }
        if self.exits.dialog.as_ref().is_some_and(|dialog| {
            !dialog.busy && dialog.editing.as_ref().is_some_and(|id| !exists(id))
        }) {
            self.exits.dialog = None;
        }
    }
}
