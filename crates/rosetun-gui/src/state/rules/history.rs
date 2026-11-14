//! Undo and redo of rule changes. The steps live in memory while the GUI
//! runs; a restore goes through the same save as any other rule edit.

use std::collections::VecDeque;
use std::time::Duration;

use rosetun_config::{ConnectionState, RuleMatcher, RuleSetId};
use rosetun_core::{RestoredRuleSets, RuleSetError, RuleSetsSnapshot, SetSnapshot};

use crate::errors;
use crate::state::{Action, Job, SessionPart, State};
use crate::worker::WorkerEvent;

pub(crate) const MAX_UNDO_STEPS: usize = 50;
/// All steps together keep no more rules than this; the oldest steps go first.
pub(crate) const MAX_UNDO_RULES: usize = 20_000;
/// How long the notice with "Undo" stays after a step.
pub(crate) const UNDO_NOTICE_MS: u64 = 8_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UndoNotice {
    RulesDeleted(usize),
    RulesImported(usize),
    SetDeleted,
    RulesMoved(usize),
    Reverted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Restore {
    Undo,
    Redo,
    Revert,
}

enum Pending {
    Edit {
        before: RuleSetsSnapshot,
        notice: Option<UndoNotice>,
    },
    /// The new set's id is known only from the result.
    CreateSet { active: Option<RuleSetId> },
    Restore {
        kind: Restore,
        snapshot: RuleSetsSnapshot,
    },
}

enum StepOutcome {
    Failed,
    Done,
    Created(RuleSetId),
}

#[derive(Default)]
pub(crate) struct RuleHistory {
    undo: VecDeque<RuleSetsSnapshot>,
    redo: Vec<RuleSetsSnapshot>,
    pending: Option<Pending>,
    /// The notice and when it was shown, by `State::frame_time`.
    notice: Option<(UndoNotice, u64)>,
}

impl RuleHistory {
    fn push_undo(&mut self, step: RuleSetsSnapshot) {
        self.undo.push_back(step);
        while self.undo.len() > MAX_UNDO_STEPS
            || (self.undo.len() > 1
                && self
                    .undo
                    .iter()
                    .map(RuleSetsSnapshot::rule_count)
                    .sum::<usize>()
                    > MAX_UNDO_RULES)
        {
            self.undo.pop_front();
        }
    }

    fn record(&mut self, step: RuleSetsSnapshot, notice: Option<UndoNotice>, now_ms: u64) {
        self.push_undo(step);
        self.redo.clear();
        self.notice = notice.map(|notice| (notice, now_ms));
    }

    #[cfg(test)]
    pub(crate) fn undo_len(&self) -> usize {
        self.undo.len()
    }

    #[cfg(test)]
    pub(crate) fn redo_len(&self) -> usize {
        self.redo.len()
    }
}

fn step_outcome(event: &WorkerEvent) -> Option<StepOutcome> {
    let ok = match event {
        WorkerEvent::CreateRuleSet(result) => {
            return Some(match result {
                Ok(set) => StepOutcome::Created(set.id.clone()),
                Err(_) => StepOutcome::Failed,
            });
        }
        WorkerEvent::SelectRuleSet(result) => result.is_ok(),
        WorkerEvent::ImportRules(result) => result.is_ok(),
        WorkerEvent::AddRule(result) => result.is_ok(),
        WorkerEvent::AddRules(result) => result.is_ok(),
        WorkerEvent::RenameRuleSet(result)
        | WorkerEvent::DeleteRuleSet(result)
        | WorkerEvent::SetDefaultTarget(result)
        | WorkerEvent::UpdateRule(result)
        | WorkerEvent::SetRuleTarget(result)
        | WorkerEvent::SetRuleEnabled(result)
        | WorkerEvent::MoveRule(result)
        | WorkerEvent::MoveRules(result)
        | WorkerEvent::RemoveRule(result)
        | WorkerEvent::RemoveRules(result) => result.is_ok(),
        _ => return None,
    };
    Some(if ok {
        StepOutcome::Done
    } else {
        StepOutcome::Failed
    })
}

impl State {
    /// Takes the state a rule edit is about to change, before its job runs.
    /// Temporary rules of the session are not edits of the saved rules.
    pub(in crate::state) fn begin_rule_step(&mut self, job: &Job) {
        if self.rules.history.pending.is_some() {
            return;
        }
        let (id, with_active, notice) = match job {
            Job::SelectRuleSet(_) => (None, true, None),
            Job::CreateRuleSet(_) => {
                self.rules.history.pending = Some(Pending::CreateSet {
                    active: self.config.active_rule_set.clone(),
                });
                return;
            }
            Job::ImportRules(id, preview, _, _) => (
                Some(id),
                false,
                Some(UndoNotice::RulesImported(preview.rules.len())),
            ),
            Job::DeleteRuleSet(id) => (Some(id), true, Some(UndoNotice::SetDeleted)),
            Job::AddRules(_, _, _) if self.session.keep_temporary.is_some() => return,
            Job::RenameRuleSet(id, _)
            | Job::SetDefaultTarget(id, _)
            | Job::AddRule(id, _, _)
            | Job::AddRules(id, _, _)
            | Job::UpdateRule(id, _, _, _)
            | Job::SetRuleTarget(id, _, _)
            | Job::SetRuleEnabled(id, _, _)
            | Job::MoveRule(id, _, _) => (Some(id), false, None),
            Job::MoveRules(id, rules, _) => {
                (Some(id), false, Some(UndoNotice::RulesMoved(rules.len())))
            }
            Job::RemoveRule(id, rule) => {
                let template = self
                    .config
                    .rule_sets
                    .iter()
                    .find(|set| &set.id == id)
                    .and_then(|set| set.rules.iter().find(|item| &item.id == rule))
                    .is_some_and(|rule| matches!(rule.matcher, RuleMatcher::Template(_)));
                (
                    Some(id),
                    false,
                    (!template).then_some(UndoNotice::RulesDeleted(1)),
                )
            }
            Job::RemoveRules(id, rules) => {
                (Some(id), false, Some(UndoNotice::RulesDeleted(rules.len())))
            }
            _ => return,
        };
        let ids: Vec<_> = id.into_iter().cloned().collect();
        let mut before = RuleSetsSnapshot::of(&self.config, &ids, with_active);
        if let Job::ImportRules(_, preview, _, _) = job {
            before.list_ids = preview.lists.iter().map(|list| list.id.clone()).collect();
            before.lists = Some(
                self.config
                    .lists
                    .iter()
                    .filter(|list| before.list_ids.contains(&list.id))
                    .cloned()
                    .collect(),
            );
        }
        self.rules.history.pending = Some(Pending::Edit { before, notice });
    }

    /// Keeps the step of a saved rule edit, or drops it when the save failed.
    pub(in crate::state) fn finish_rule_step(&mut self, event: &WorkerEvent) {
        let Some(outcome) = step_outcome(event) else {
            return;
        };
        let history = &mut self.rules.history;
        let step = match (history.pending.take(), outcome) {
            (Some(Pending::Edit { before, notice }), StepOutcome::Done) => Some((before, notice)),
            (Some(Pending::CreateSet { active }), StepOutcome::Created(id)) => Some((
                RuleSetsSnapshot {
                    list_ids: Vec::new(),
                    lists: None,
                    sets: vec![SetSnapshot {
                        index: 0,
                        id,
                        set: None,
                    }],
                    active: Some(active),
                },
                None,
            )),
            (pending @ Some(Pending::Restore { .. }), _) => {
                history.pending = pending;
                None
            }
            _ => None,
        };
        if let Some((before, notice)) = step {
            let now = self.frame_time();
            self.rules.history.record(before, notice, now);
        }
    }

    /// No restore while another save runs: the step would race with it.
    fn can_restore_rules(&self) -> bool {
        self.can_edit_rules()
            && self.operations.settings.is_none()
            && self.rules.history.pending.is_none()
    }

    pub(crate) fn can_undo_rules(&self) -> bool {
        self.can_restore_rules() && !self.rules.history.undo.is_empty()
    }

    pub(crate) fn can_redo_rules(&self) -> bool {
        self.can_restore_rules() && !self.rules.history.redo.is_empty()
    }

    /// The notice of the last step while it is shown, and how long it stays.
    pub(crate) fn rule_notice(&self) -> Option<(UndoNotice, Duration)> {
        let (notice, shown) = self.rules.history.notice?;
        let left = (shown + UNDO_NOTICE_MS).checked_sub(self.frame_time())?;
        (left > 0 && !self.rules.history.undo.is_empty())
            .then(|| (notice, Duration::from_millis(left)))
    }

    /// The active set as the running session uses it, when the saved rules
    /// differ from it and that set still exists.
    fn revert_snapshot(&self) -> Option<RuleSetsSnapshot> {
        let applied = self.session.applied_snapshot.as_ref()?.rule_set.as_ref()?;
        let index = self
            .config
            .rule_sets
            .iter()
            .position(|set| set.id == applied.id)?;
        let switched = self.config.active_rule_set.as_ref() != Some(&applied.id);
        (switched || &self.config.rule_sets[index] != applied).then(|| RuleSetsSnapshot {
            list_ids: Vec::new(),
            lists: None,
            sets: vec![SetSnapshot {
                id: applied.id.clone(),
                index,
                set: Some(applied.clone()),
            }],
            active: switched.then(|| Some(applied.id.clone())),
        })
    }

    pub(crate) fn can_revert_rules(&self) -> bool {
        self.can_restore_rules()
            && matches!(
                self.visible_status().map(|status| &status.state),
                Some(ConnectionState::Connected)
            )
            && self.pending_reconnect(SessionPart::Rules)
            && self.revert_snapshot().is_some()
    }

    pub(in crate::state) fn act_rule_history(&mut self, action: Action) -> Option<Job> {
        let (kind, snapshot) = match action {
            Action::UndoRules if self.can_undo_rules() => {
                (Restore::Undo, self.rules.history.undo.pop_back()?)
            }
            Action::RedoRules if self.can_redo_rules() => {
                (Restore::Redo, self.rules.history.redo.pop()?)
            }
            Action::RevertRules if self.can_revert_rules() => {
                (Restore::Revert, self.revert_snapshot()?)
            }
            Action::UndoRules | Action::RedoRules | Action::RevertRules => return None,
            _ => unreachable!("only rule history actions are dispatched here"),
        };
        self.rules.history.notice = None;
        self.rules.history.pending = Some(Pending::Restore {
            kind,
            snapshot: snapshot.clone(),
        });
        self.start_rule_edit(Job::RestoreRuleSets(snapshot))
    }

    pub(in crate::state) fn reduce_rule_restore(
        &mut self,
        result: Result<RestoredRuleSets, RuleSetError>,
    ) {
        self.operations.rules_edit = false;
        let Some(Pending::Restore { kind, snapshot }) = self.rules.history.pending.take() else {
            return;
        };
        let history = &mut self.rules.history;
        match result {
            Ok(restored) => {
                match kind {
                    Restore::Undo => history.redo.push(restored.previous),
                    Restore::Redo => history.push_undo(restored.previous),
                    Restore::Revert => {
                        let now = self.frame_time();
                        self.rules.history.record(
                            restored.previous,
                            Some(UndoNotice::Reverted),
                            now,
                        );
                    }
                }
                self.operation_error = (restored.dropped > 0)
                    .then(|| crate::i18n::rules_not_restored(restored.dropped));
                if let Some(id) = snapshot
                    .sets
                    .iter()
                    .find(|entry| entry.set.is_some())
                    .map(|entry| entry.id.clone())
                    .filter(|id| self.config.rule_sets.iter().any(|set| &set.id == id))
                    && self.rules.screen.selected_set.as_ref() != Some(&id)
                {
                    self.rules.screen.selected_set = Some(id);
                    self.rules.screen.clear_selection();
                }
            }
            Err(error) => {
                match kind {
                    Restore::Undo => history.undo.push_back(snapshot),
                    Restore::Redo => history.redo.push(snapshot),
                    Restore::Revert => {}
                }
                self.operation_error =
                    Some(self.text(&errors::rule_set(crate::i18n::language(), &error)));
            }
        }
    }
}
