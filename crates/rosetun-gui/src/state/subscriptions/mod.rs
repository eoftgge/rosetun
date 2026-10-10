use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::RangeInclusive;

use rosetun_config::{
    ConnectionState, List, ListId, ListSource, NodeId, Subscription, SubscriptionId,
};
use rosetun_core::{AddFromUrlError, AddOptions, UpdateReport, UpdateSubscriptionError};

use super::{Action, Job, State};
use crate::errors;
use crate::reorder::drop_target;
use crate::worker::WorkerEvent;

mod checks;

pub(crate) use checks::PingResult;

/// Default refresh interval when the provider names none.
const AUTO_UPDATE_HOURS: u64 = 12;
/// Provider intervals outside this range are clamped.
const AUTO_UPDATE_RANGE: RangeInclusive<u64> = 1..=168;
/// A failed automatic update is retried after this long.
const AUTO_UPDATE_RETRY: u64 = 60 * 60;
/// How often the schedule is checked.
pub(in crate::state) const AUTO_UPDATE_CHECK: u64 = 60;

/// Hours between automatic updates of one subscription.
fn auto_update_hours(subscription: &Subscription) -> u64 {
    subscription
        .update_interval_hours
        .map(|hours| hours.clamp(*AUTO_UPDATE_RANGE.start(), *AUTO_UPDATE_RANGE.end()))
        .unwrap_or(AUTO_UPDATE_HOURS)
}

/// The interval the panel footer names: one value when every subscription shares it.
pub(crate) fn shared_auto_update_hours(subscriptions: &[Subscription]) -> Option<u64> {
    let first = auto_update_hours(subscriptions.first()?);
    subscriptions
        .iter()
        .all(|subscription| auto_update_hours(subscription) == first)
        .then_some(first)
}

/// Whether one subscription is due, in Unix seconds.
pub(in crate::state) fn update_due(
    subscription: &Subscription,
    now: u64,
    last_attempt: Option<u64>,
) -> bool {
    let hours = auto_update_hours(subscription);
    subscription
        .updated_at_unix
        .is_none_or(|updated| now.saturating_sub(updated) >= hours * 60 * 60)
        && last_attempt.is_none_or(|attempt| now.saturating_sub(attempt) >= AUTO_UPDATE_RETRY)
}

pub(in crate::state) fn list_update_due(list: &List, now: u64, last_attempt: Option<u64>) -> bool {
    matches!(&list.source, ListSource::Url(_))
        && list
            .updated_at
            .is_none_or(|updated| now.saturating_sub(updated) >= AUTO_UPDATE_HOURS * 60 * 60)
        && last_attempt.is_none_or(|attempt| now.saturating_sub(attempt) >= AUTO_UPDATE_RETRY)
}

pub(crate) struct AddDialog {
    pub(crate) url: String,
    pub(crate) name: String,
    pub(crate) send_hwid: bool,
    pub(crate) busy: bool,
    pub(crate) error: Option<AddFromUrlError>,
    pub(crate) focus_url: bool,
}

impl Default for AddDialog {
    fn default() -> Self {
        Self {
            url: String::new(),
            name: String::new(),
            send_hwid: true,
            busy: false,
            error: None,
            focus_url: true,
        }
    }
}

pub(crate) struct RemoveDialog {
    pub(crate) id: SubscriptionId,
    pub(crate) error: Option<String>,
}

pub(crate) struct RenameDialog {
    pub(crate) id: SubscriptionId,
    /// The name as the dialog first showed it: submitting it unchanged saves nothing.
    pub(crate) original: String,
    pub(crate) name: String,
    pub(crate) error: Option<String>,
    pub(crate) focus: bool,
}

pub(crate) enum UpdateOutcome {
    Success(UpdateReport),
    Error(UpdateSubscriptionError),
}

#[derive(Default)]
pub(crate) struct SubscriptionsState {
    next_auto_update_check: u64,
    auto_update_attempts: HashMap<SubscriptionId, u64>,
    list_auto_update_attempts: HashMap<ListId, u64>,
    pub(crate) expanded: BTreeSet<SubscriptionId>,
    pub(crate) reveal: Option<(SubscriptionId, NodeId)>,
    pub(crate) outcomes: BTreeMap<SubscriptionId, UpdateOutcome>,
    pub(crate) pings: HashMap<(SubscriptionId, NodeId), PingResult>,
    pub(crate) add: Option<AddDialog>,
    pub(crate) remove: Option<RemoveDialog>,
    pub(crate) rename: Option<RenameDialog>,
}

impl State {
    /// Starts at most one due subscription on each schedule check.
    pub(crate) fn take_auto_update(&mut self, now: u64) -> Option<Job> {
        if now < self.subscriptions.next_auto_update_check {
            return None;
        }
        self.subscriptions.next_auto_update_check = now.saturating_add(AUTO_UPDATE_CHECK);
        if !self.config_ready
            || !self.config.interface.auto_update_subscriptions
            || self.operations.update_all
            || !self.operations.updating_lists.is_empty()
            || self.operations.helper
            || matches!(
                self.status.state,
                ConnectionState::Connecting
                    | ConnectionState::Reconnecting
                    | ConnectionState::FailedProtected { .. }
            )
        {
            return None;
        }
        if let Some(id) = self
            .config
            .subscriptions
            .iter()
            .find(|subscription| {
                !self.subscription_busy(&subscription.id)
                    && update_due(
                        subscription,
                        now,
                        self.subscriptions
                            .auto_update_attempts
                            .get(&subscription.id)
                            .copied(),
                    )
            })
            .map(|subscription| subscription.id.clone())
        {
            self.subscriptions
                .auto_update_attempts
                .insert(id.clone(), now);
            self.operations.updating.insert(id.clone());
            self.subscriptions.outcomes.remove(&id);
            return Some(Job::Update(id));
        }

        let id = self
            .config
            .lists
            .iter()
            .find(|list| {
                !self.operations.updating_lists.contains(&list.id)
                    && list_update_due(
                        list,
                        now,
                        self.subscriptions
                            .list_auto_update_attempts
                            .get(&list.id)
                            .copied(),
                    )
            })?
            .id
            .clone();
        self.subscriptions
            .list_auto_update_attempts
            .insert(id.clone(), now);
        self.operations.updating_lists.insert(id.clone());
        Some(Job::UpdateList(id))
    }

    pub(crate) fn subscription_busy(&self, id: &SubscriptionId) -> bool {
        self.operations.update_all
            || self.operations.updating.contains(id)
            || (self.operations.removing
                && self
                    .subscriptions
                    .remove
                    .as_ref()
                    .is_some_and(|dialog| &dialog.id == id))
    }

    pub(crate) fn can_reorder_subscriptions(&self) -> bool {
        self.config_ready
            && !self.operations.update_all
            && self.operations.updating.is_empty()
            && self.operations.updating_lists.is_empty()
            && !self
                .subscriptions
                .add
                .as_ref()
                .is_some_and(|dialog| dialog.busy)
            && !self.operations.removing
            && !self.operations.moving_subscription
    }

    pub(super) fn reconcile_subscriptions(&mut self) {
        self.subscriptions
            .expanded
            .retain(|id| self.config.subscriptions.iter().any(|sub| &sub.id == id));
        if self
            .subscriptions
            .reveal
            .as_ref()
            .is_some_and(|(id, node)| {
                !self
                    .config
                    .subscriptions
                    .iter()
                    .any(|sub| &sub.id == id && sub.node(node).is_some())
            })
        {
            self.subscriptions.reveal = None;
        }
        self.subscriptions
            .outcomes
            .retain(|id, _| self.config.subscriptions.iter().any(|sub| &sub.id == id));
        self.subscriptions
            .auto_update_attempts
            .retain(|id, _| self.config.subscriptions.iter().any(|sub| &sub.id == id));
        self.subscriptions
            .list_auto_update_attempts
            .retain(|id, _| self.config.lists.iter().any(|list| &list.id == id));
        self.operations
            .updating_lists
            .retain(|id| self.config.lists.iter().any(|list| &list.id == id));
        self.subscriptions.pings.retain(|(id, node), _| {
            self.config
                .subscriptions
                .iter()
                .any(|sub| &sub.id == id && sub.node(node).is_some())
        });
        self.operations
            .pinging
            .retain(|id| self.config.subscriptions.iter().any(|sub| &sub.id == id));
    }

    fn update_result(
        &mut self,
        id: SubscriptionId,
        result: Result<(rosetun_config::Subscription, UpdateReport), UpdateSubscriptionError>,
    ) {
        let outcome = match result {
            Ok((_, report)) => UpdateOutcome::Success(report),
            Err(error) => UpdateOutcome::Error(error),
        };
        self.subscriptions.outcomes.insert(id, outcome);
    }

    pub(super) fn reduce_subscriptions(&mut self, event: WorkerEvent) {
        match event {
            WorkerEvent::Add(result) => match result {
                Ok((subscription, report)) => {
                    self.subscriptions.expanded.insert(subscription.id.clone());
                    self.subscriptions
                        .outcomes
                        .insert(subscription.id, UpdateOutcome::Success(report));
                    self.subscriptions.add = None;
                }
                Err(error) => {
                    if let Some(dialog) = &mut self.subscriptions.add {
                        dialog.busy = false;
                        dialog.error = Some(error);
                    }
                }
            },
            WorkerEvent::Update { id, result } => {
                self.operations.updating.remove(&id);
                self.update_result(id, result);
            }
            WorkerEvent::UpdateList(id) => {
                self.operations.updating_lists.remove(&id);
            }
            event @ (WorkerEvent::Ping { .. }
            | WorkerEvent::PingDone(_)
            | WorkerEvent::FullCheck { .. }) => self.reduce_subscription_check(event),
            WorkerEvent::UpdateAll(result) => {
                self.operations.update_all = false;
                match result {
                    Ok(results) => {
                        for (id, result) in results {
                            self.update_result(id, result);
                        }
                    }
                    Err(error) => {
                        self.operation_error =
                            Some(self.text(&errors::store(crate::i18n::language(), &error)));
                    }
                }
            }
            WorkerEvent::Remove { id, result } => {
                self.operations.removing = false;
                match result {
                    Ok(()) => {
                        self.subscriptions.expanded.remove(&id);
                        self.subscriptions.outcomes.remove(&id);
                        self.subscriptions.remove = None;
                    }
                    Err(error) => {
                        let message = self.text(&errors::remove_subscription(
                            crate::i18n::language(),
                            &error,
                        ));
                        if let Some(dialog) = &mut self.subscriptions.remove {
                            dialog.error = Some(message);
                        }
                    }
                }
            }
            WorkerEvent::RenameSubscription(result) => {
                self.operations.renaming = false;
                match result {
                    Ok(()) => self.subscriptions.rename = None,
                    Err(error) => {
                        let message = self.text(&errors::rename_subscription(
                            crate::i18n::language(),
                            &error,
                        ));
                        if let Some(dialog) = &mut self.subscriptions.rename {
                            dialog.error = Some(message);
                        } else {
                            self.operation_error = Some(message);
                        }
                    }
                }
            }
            WorkerEvent::MoveSubscription(result) => {
                self.operations.moving_subscription = false;
                self.operation_error = result.err().map(|error| {
                    self.text(&errors::move_subscription(crate::i18n::language(), &error))
                });
            }
            _ => unreachable!("only subscription events are dispatched here"),
        }
    }

    pub(super) fn act_subscriptions(&mut self, action: Action) -> Option<Job> {
        match action {
            Action::RevealServer => {
                self.subscriptions.reveal = None;
                if let Some((subscription, node)) = self.config.active_node() {
                    let id = subscription.id.clone();
                    self.subscriptions.expanded.insert(id.clone());
                    self.subscriptions.reveal = Some((id, node.id.clone()));
                } else if let Some(subscription) = self.config.subscriptions.first() {
                    self.subscriptions.expanded.insert(subscription.id.clone());
                }
            }
            Action::RevealDone => self.subscriptions.reveal = None,
            Action::ToggleExpanded(id) => {
                if !self.subscriptions.expanded.remove(&id) {
                    self.subscriptions.expanded.insert(id);
                }
            }
            Action::DropSubscription(id, slot) => {
                if self.can_reorder_subscriptions()
                    && let Some(from) = self
                        .config
                        .subscriptions
                        .iter()
                        .position(|subscription| subscription.id == id)
                    && let Some(to) = drop_target(from, slot, self.config.subscriptions.len())
                {
                    self.operations.moving_subscription = true;
                    self.operation_error = None;
                    return Some(Job::MoveSubscription(id, to));
                }
            }
            Action::OpenAdd => {
                if self.subscriptions.add.is_none() {
                    self.subscriptions.add = Some(AddDialog::default());
                }
            }
            Action::CancelAdd => {
                if self
                    .subscriptions
                    .add
                    .as_ref()
                    .is_some_and(|dialog| !dialog.busy)
                {
                    self.subscriptions.add = None;
                }
            }
            Action::SubmitAdd => {
                if let Some(dialog) = &mut self.subscriptions.add
                    && !dialog.busy
                {
                    match rosetun_core::normalize_subscription_url(&dialog.url) {
                        Ok(input) => {
                            dialog.busy = true;
                            dialog.error = None;
                            let name = (!dialog.name.trim().is_empty())
                                .then(|| dialog.name.trim().to_owned());
                            return Some(Job::Add {
                                input,
                                options: AddOptions {
                                    name,
                                    user_agent: None,
                                    send_hwid: dialog.send_hwid,
                                },
                            });
                        }
                        Err(error) => dialog.error = Some(AddFromUrlError::Url(error)),
                    }
                }
            }
            Action::Update(id) => {
                if !self.subscription_busy(&id) {
                    self.operations.updating.insert(id.clone());
                    self.subscriptions.outcomes.remove(&id);
                    return Some(Job::Update(id));
                }
            }
            Action::Ping(id) => return self.start_check(id, None, false),
            Action::PingNode(id, node) => return self.start_check(id, Some(node), false),
            Action::FullCheck(id) => return self.start_check(id, None, true),
            Action::FullCheckNode(id, node) => return self.start_check(id, Some(node), true),
            Action::UpdateAll => {
                if self.config_ready
                    && (!self.config.subscriptions.is_empty()
                        || self
                            .config
                            .lists
                            .iter()
                            .any(|list| matches!(&list.source, ListSource::Url(_))))
                    && !self.operations.update_all
                    && self.operations.updating.is_empty()
                    && self.operations.updating_lists.is_empty()
                    && !self.operations.removing
                {
                    self.operations.update_all = true;
                    self.subscriptions.outcomes.clear();
                    return Some(Job::UpdateAll);
                }
            }
            Action::RequestRemove(id) => {
                if !self.subscription_busy(&id) && !self.operations.removing {
                    self.subscriptions.remove = Some(RemoveDialog { id, error: None });
                }
            }
            Action::CancelRemove => {
                if !self.operations.removing {
                    self.subscriptions.remove = None;
                }
            }
            Action::ConfirmRemove => {
                if let Some(dialog) = &mut self.subscriptions.remove
                    && !self.operations.removing
                    && !self.operations.update_all
                    && !self.operations.updating.contains(&dialog.id)
                {
                    self.operations.removing = true;
                    dialog.error = None;
                    return Some(Job::Remove(dialog.id.clone()));
                }
            }
            Action::RequestRename(id) => {
                if self.config_ready
                    && self.subscriptions.rename.is_none()
                    && self.subscriptions.remove.is_none()
                    && !self.operations.renaming
                    && let Some(subscription) =
                        self.config.subscriptions.iter().find(|sub| sub.id == id)
                {
                    let original = self.text(&subscription.name);
                    self.subscriptions.rename = Some(RenameDialog {
                        id,
                        name: original.clone(),
                        original,
                        error: None,
                        focus: true,
                    });
                }
            }
            Action::CancelRename => {
                if !self.operations.renaming {
                    self.subscriptions.rename = None;
                }
            }
            Action::SubmitRename => {
                if let Some(dialog) = &mut self.subscriptions.rename
                    && !self.operations.renaming
                {
                    let name = dialog.name.trim();
                    if !name.is_empty() {
                        if name == dialog.original.trim() {
                            self.subscriptions.rename = None;
                        } else {
                            self.operations.renaming = true;
                            dialog.error = None;
                            return Some(Job::RenameSubscription(
                                dialog.id.clone(),
                                name.to_owned(),
                            ));
                        }
                    }
                }
            }
            Action::DismissOutcome(id) => {
                self.subscriptions.outcomes.remove(&id);
            }
            _ => unreachable!("only subscription actions are dispatched here"),
        }
        None
    }
}
