use std::collections::{BTreeMap, BTreeSet};

use rosetun_config::{AppConfig, ConnectionState, NodeId, RuleSetId, Status, SubscriptionId};
use rosetun_core::{AddFromUrlError, AddOptions, UpdateReport, UpdateSubscriptionError};
use rosetun_ipc::ClientError;

use crate::actions::{self, PrimaryAction};
use crate::display;
use crate::strings;
use crate::worker::{ConfigWorkerError, HelperCommandError, WorkerEvent};

#[derive(Default)]
pub(crate) struct Operations {
    pub(crate) helper: bool,
    pub(crate) selection: bool,
    pub(crate) rules: bool,
    pub(crate) kill_switch: bool,
    pub(crate) updating: BTreeSet<SubscriptionId>,
    pub(crate) update_all: bool,
    pub(crate) removing: bool,
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

pub(crate) enum UpdateOutcome {
    Success(UpdateReport),
    Error(UpdateSubscriptionError),
}

#[derive(Default)]
pub(crate) struct State {
    pub(crate) config: AppConfig,
    pub(crate) config_ready: bool,
    pub(crate) config_generation: u64,
    pub(crate) config_error: Option<ConfigWorkerError>,
    pub(crate) status: Status,
    pub(crate) helper_available: bool,
    pub(crate) helper_version: Option<String>,
    pub(crate) helper_error: Option<ClientError>,
    pub(crate) operation_error: Option<String>,
    pub(crate) expanded: BTreeSet<SubscriptionId>,
    pub(crate) outcomes: BTreeMap<SubscriptionId, UpdateOutcome>,
    pub(crate) operations: Operations,
    pub(crate) add: Option<AddDialog>,
    pub(crate) remove: Option<RemoveDialog>,
    pub(crate) protection_confirmation: bool,
}

pub(crate) enum Action {
    Primary,
    RequestProtectionOff,
    KeepBlocked,
    ConfirmProtectionOff,
    SelectNode(SubscriptionId, NodeId),
    SelectRuleSet(Option<RuleSetId>),
    SetKillSwitch(bool),
    ToggleExpanded(SubscriptionId),
    OpenAdd,
    CancelAdd,
    SubmitAdd,
    Update(SubscriptionId),
    UpdateAll,
    RequestRemove(SubscriptionId),
    CancelRemove,
    ConfirmRemove,
    DismissOperationError,
    DismissConfigError,
    DismissOutcome(SubscriptionId),
}

pub(crate) enum Job {
    Connect,
    Disconnect,
    SelectNode(SubscriptionId, NodeId),
    SelectRuleSet(Option<RuleSetId>),
    SetKillSwitch(bool),
    Add { input: String, options: AddOptions },
    Update(SubscriptionId),
    UpdateAll,
    Remove(SubscriptionId),
}

impl State {
    /// The last status is kept for when the helper comes back, but it is not
    /// shown while the helper is unreachable: a helper that died has already
    /// taken the engine and the kill-switch filters with it.
    pub(crate) fn visible_status(&self) -> Option<&Status> {
        self.helper_available.then_some(&self.status)
    }

    pub(crate) fn primary_action(&self) -> PrimaryAction {
        actions::primary_action(
            self.helper_available,
            &self.status,
            self.config.active_node().is_some(),
            self.operations.helper,
        )
    }

    pub(crate) fn subscription_busy(&self, id: &SubscriptionId) -> bool {
        self.operations.update_all
            || self.operations.updating.contains(id)
            || (self.operations.removing
                && self.remove.as_ref().is_some_and(|dialog| &dialog.id == id))
    }

    pub(crate) fn text(&self, value: &str) -> String {
        redact(&self.config, value)
    }

    pub(crate) fn reduce(&mut self, event: WorkerEvent) {
        match event {
            WorkerEvent::Config { generation, config } => {
                if generation <= self.config_generation {
                    return;
                }
                self.config_generation = generation;
                self.config = config;
                self.config_ready = true;
                self.config_error = None;
                self.expanded
                    .retain(|id| self.config.subscriptions.iter().any(|sub| &sub.id == id));
                self.outcomes
                    .retain(|id, _| self.config.subscriptions.iter().any(|sub| &sub.id == id));
            }
            WorkerEvent::ConfigError(error) => self.config_error = Some(error),
            WorkerEvent::HelperAvailable { version } => {
                self.helper_available = true;
                self.helper_version = Some(version);
                self.helper_error = None;
            }
            WorkerEvent::HelperUnavailable(error) => {
                self.helper_available = false;
                self.helper_error = Some(error);
                self.protection_confirmation = false;
            }
            WorkerEvent::Status(status) => {
                if !matches!(status.state, ConnectionState::FailedProtected { .. })
                    && !self.operations.helper
                {
                    self.protection_confirmation = false;
                }
                self.status = status;
            }
            WorkerEvent::Connect(result) => {
                self.operations.helper = false;
                self.helper_result(result);
            }
            WorkerEvent::Disconnect(result) => {
                self.operations.helper = false;
                if result.is_ok() {
                    self.protection_confirmation = false;
                }
                self.helper_result(result);
            }
            WorkerEvent::SelectNode(result) => {
                self.operations.selection = false;
                self.operation_error = result.err().map(|error| self.text(&error.to_string()));
            }
            WorkerEvent::SelectRuleSet(result) => {
                self.operations.rules = false;
                self.operation_error = result.err().map(|error| self.text(&error.to_string()));
            }
            WorkerEvent::SetKillSwitch(result) => {
                self.operations.kill_switch = false;
                self.operation_error = result.err().map(|error| self.text(&error.to_string()));
            }
            WorkerEvent::Add(result) => match result {
                Ok((subscription, report)) => {
                    self.expanded.insert(subscription.id.clone());
                    self.outcomes
                        .insert(subscription.id, UpdateOutcome::Success(report));
                    self.add = None;
                }
                Err(error) => {
                    if let Some(dialog) = &mut self.add {
                        dialog.busy = false;
                        dialog.error = Some(error);
                    }
                }
            },
            WorkerEvent::Update { id, result } => {
                self.operations.updating.remove(&id);
                self.update_result(id, result);
            }
            WorkerEvent::UpdateAll(result) => {
                self.operations.update_all = false;
                match result {
                    Ok(results) => {
                        for (id, result) in results {
                            self.update_result(id, result);
                        }
                    }
                    Err(error) => self.operation_error = Some(self.text(&error.to_string())),
                }
            }
            WorkerEvent::Remove { id, result } => {
                self.operations.removing = false;
                match result {
                    Ok(()) => {
                        self.expanded.remove(&id);
                        self.outcomes.remove(&id);
                        self.remove = None;
                    }
                    Err(error) => {
                        let message = self.text(&error.to_string());
                        if let Some(dialog) = &mut self.remove {
                            dialog.error = Some(message);
                        }
                    }
                }
            }
        }
    }

    fn helper_result(&mut self, result: Result<(), HelperCommandError>) {
        self.operation_error = result.err().map(|error| {
            let message = match error {
                HelperCommandError::Request(error) => actions::connect_request_message(&error),
                HelperCommandError::Client(error) => actions::helper_error_message(&error),
                other => other.to_string(),
            };
            self.text(&message)
        });
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
        self.outcomes.insert(id, outcome);
    }

    pub(crate) fn act(&mut self, action: Action) -> Option<Job> {
        match action {
            Action::Primary => {
                let job = match self.primary_action() {
                    PrimaryAction::Connect | PrimaryAction::Retry | PrimaryAction::Reconnect => {
                        Job::Connect
                    }
                    PrimaryAction::Disconnect => Job::Disconnect,
                    PrimaryAction::Disabled => return None,
                };
                self.operations.helper = true;
                self.operation_error = None;
                return Some(job);
            }
            Action::RequestProtectionOff => {
                if self.helper_available
                    && !self.operations.helper
                    && matches!(self.status.state, ConnectionState::FailedProtected { .. })
                {
                    self.protection_confirmation = true;
                }
            }
            Action::KeepBlocked => {
                if !self.operations.helper {
                    self.protection_confirmation = false;
                }
            }
            Action::ConfirmProtectionOff => {
                if self.protection_confirmation
                    && self.helper_available
                    && !self.operations.helper
                    && matches!(self.status.state, ConnectionState::FailedProtected { .. })
                {
                    self.operations.helper = true;
                    self.operation_error = None;
                    return Some(Job::Disconnect);
                }
            }
            Action::SelectNode(subscription, node) => {
                if self.config_ready && !self.operations.selection && !self.operations.helper {
                    self.operations.selection = true;
                    self.operation_error = None;
                    return Some(Job::SelectNode(subscription, node));
                }
            }
            Action::SelectRuleSet(id) => {
                if self.config_ready && !self.operations.rules && !self.operations.helper {
                    self.operations.rules = true;
                    self.operation_error = None;
                    return Some(Job::SelectRuleSet(id));
                }
            }
            Action::SetKillSwitch(enabled) => {
                if self.config_ready && !self.operations.kill_switch && !self.operations.helper {
                    self.operations.kill_switch = true;
                    self.operation_error = None;
                    return Some(Job::SetKillSwitch(enabled));
                }
            }
            Action::ToggleExpanded(id) => {
                if !self.expanded.remove(&id) {
                    self.expanded.insert(id);
                }
            }
            Action::OpenAdd => {
                if self.add.is_none() {
                    self.add = Some(AddDialog::default());
                }
            }
            Action::CancelAdd => {
                if self.add.as_ref().is_some_and(|dialog| !dialog.busy) {
                    self.add = None;
                }
            }
            Action::SubmitAdd => {
                if let Some(dialog) = &mut self.add
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
                        Err(message) => dialog.error = Some(AddFromUrlError::Url(message)),
                    }
                }
            }
            Action::Update(id) => {
                if !self.subscription_busy(&id) {
                    self.operations.updating.insert(id.clone());
                    self.outcomes.remove(&id);
                    return Some(Job::Update(id));
                }
            }
            Action::UpdateAll => {
                if self.config_ready
                    && !self.config.subscriptions.is_empty()
                    && !self.operations.update_all
                    && self.operations.updating.is_empty()
                    && !self.operations.removing
                {
                    self.operations.update_all = true;
                    self.outcomes.clear();
                    return Some(Job::UpdateAll);
                }
            }
            Action::RequestRemove(id) => {
                if !self.subscription_busy(&id) && !self.operations.removing {
                    self.remove = Some(RemoveDialog { id, error: None });
                }
            }
            Action::CancelRemove => {
                if !self.operations.removing {
                    self.remove = None;
                }
            }
            Action::ConfirmRemove => {
                if let Some(dialog) = &mut self.remove
                    && !self.operations.removing
                    && !self.operations.update_all
                    && !self.operations.updating.contains(&dialog.id)
                {
                    self.operations.removing = true;
                    dialog.error = None;
                    return Some(Job::Remove(dialog.id.clone()));
                }
            }
            Action::DismissOperationError => self.operation_error = None,
            Action::DismissConfigError => self.config_error = None,
            Action::DismissOutcome(id) => {
                self.outcomes.remove(&id);
            }
        }
        None
    }
}

pub(crate) fn redact(config: &AppConfig, value: &str) -> String {
    config
        .subscriptions
        .iter()
        .fold(display::safe_multiline(value), |text, subscription| {
            display::provider_multiline(&text, &subscription.url)
        })
}

pub(crate) fn primary_label(state: &State) -> &'static str {
    if !state.helper_available {
        return strings::CONNECT;
    }
    if state.operations.helper || state.status.state.is_transitional() {
        match state.status.state {
            ConnectionState::Reconnecting => strings::RECONNECTING_ACTION,
            ConnectionState::Connected | ConnectionState::FailedProtected { .. }
                if state.operations.helper =>
            {
                strings::WORKING
            }
            _ => strings::CONNECTING_ACTION,
        }
    } else if state.primary_action() == PrimaryAction::Disabled {
        strings::CONNECT
    } else {
        state.primary_action().label()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rosetun_core::{RemoveSubscriptionError, StoreError};
    use rosetun_ipc::ConnectRequestError;

    fn report() -> UpdateReport {
        UpdateReport {
            added: 2,
            removed: 1,
            retained: 3,
            selection_cleared: true,
            skipped: BTreeMap::new(),
            notices: vec![],
        }
    }

    fn subscription(id: &str) -> rosetun_config::Subscription {
        rosetun_config::Subscription {
            id: SubscriptionId::new(id),
            name: "Provider".into(),
            url: "https://example.com/secret-path".into(),
            nodes: vec![],
            auto_update: false,
            updated_at_unix: None,
            user_agent: None,
            send_hwid: true,
            info: None,
            update_interval_hours: None,
            support_url: None,
            web_page_url: None,
            announce: None,
            notices: vec![],
        }
    }

    #[test]
    fn helper_recovery_keeps_last_status_hidden_until_available() {
        let mut state = State::default();
        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connected,
            ..Status::default()
        }));
        state.reduce(WorkerEvent::HelperUnavailable(ClientError::Closed));
        assert!(!state.helper_available);
        assert!(matches!(state.status.state, ConnectionState::Connected));
        assert!(state.visible_status().is_none());
        state.reduce(WorkerEvent::HelperAvailable {
            version: "test".into(),
        });
        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Disconnected,
            ..Status::default()
        }));
        assert!(state.helper_available);
        assert!(state.helper_error.is_none());
        assert!(matches!(
            state.visible_status().map(|status| &status.state),
            Some(ConnectionState::Disconnected)
        ));
    }

    #[test]
    fn configuration_replacement_ignores_stale_publications_and_retains_valid_data_on_error() {
        let mut state = State::default();
        let config = AppConfig {
            subscriptions: vec![subscription("1")],
            ..AppConfig::default()
        };
        state.reduce(WorkerEvent::Config {
            generation: 2,
            config: config.clone(),
        });
        state.reduce(WorkerEvent::Config {
            generation: 1,
            config: AppConfig::default(),
        });
        state.reduce(WorkerEvent::ConfigError(ConfigWorkerError::Store(
            StoreError::NoConfigDir,
        )));
        assert_eq!(state.config, config);
        assert!(state.config_error.is_some());
        state.reduce(WorkerEvent::Config {
            generation: 3,
            config: AppConfig::default(),
        });
        assert!(state.config.subscriptions.is_empty());
        assert!(state.config_error.is_none());
    }

    #[test]
    fn command_completion_clears_flags_and_maps_selection_errors() {
        let mut state = State::default();
        state.operations.helper = true;
        state.reduce(WorkerEvent::Connect(Err(HelperCommandError::Request(
            ConnectRequestError::NodeNotFound,
        ))));
        assert!(!state.operations.helper);
        assert_eq!(
            state.operation_error.as_deref(),
            Some(strings::SELECT_SERVER)
        );
        state.operations.selection = true;
        state.reduce(WorkerEvent::SelectNode(Err(
            rosetun_core::SelectNodeError::NodeNotFound,
        )));
        assert!(!state.operations.selection);
        state.operations.rules = true;
        state.reduce(WorkerEvent::SelectRuleSet(Ok(())));
        assert!(!state.operations.rules);
        assert!(state.operation_error.is_none());
        state.operations.kill_switch = true;
        state.reduce(WorkerEvent::SetKillSwitch(Err(StoreError::NoConfigDir)));
        assert!(!state.operations.kill_switch);
        assert!(state.operation_error.is_some());
    }

    #[test]
    fn update_all_associates_outcomes_with_subscription_ids() {
        let mut state = State::default();
        state.operations.update_all = true;
        state.reduce(WorkerEvent::UpdateAll(Ok(vec![
            (
                SubscriptionId::new("2"),
                Err(UpdateSubscriptionError::NotFound),
            ),
            (SubscriptionId::new("1"), Ok((subscription("1"), report()))),
        ])));
        assert!(!state.operations.update_all);
        assert!(matches!(
            state.outcomes[&SubscriptionId::new("1")],
            UpdateOutcome::Success(_)
        ));
        assert!(matches!(
            state.outcomes[&SubscriptionId::new("2")],
            UpdateOutcome::Error(_)
        ));
        state.operations.update_all = true;
        state.reduce(WorkerEvent::UpdateAll(Err(StoreError::NoConfigDir)));
        assert!(!state.operations.update_all);
        assert!(state.operation_error.is_some());
    }

    #[test]
    fn add_failure_keeps_inputs_and_success_closes_and_expands() {
        let mut state = State::default();
        state.act(Action::OpenAdd);
        state.add.as_mut().unwrap().url = "https://example.com/sub".into();
        assert!(matches!(
            state.act(Action::SubmitAdd),
            Some(Job::Add { .. })
        ));
        assert!(state.act(Action::CancelAdd).is_none());
        assert!(state.add.is_some());
        state.reduce(WorkerEvent::Add(Err(AddFromUrlError::MissingHost)));
        let dialog = state.add.as_ref().unwrap();
        assert_eq!(dialog.url, "https://example.com/sub");
        assert!(!dialog.busy);
        assert!(dialog.error.is_some());
        state.reduce(WorkerEvent::Add(Ok((subscription("1"), report()))));
        assert!(state.add.is_none());
        assert!(state.expanded.contains(&SubscriptionId::new("1")));
    }

    #[test]
    fn protected_disconnect_requires_explicit_confirmation() {
        let mut state = State {
            helper_available: true,
            status: Status {
                state: ConnectionState::FailedProtected {
                    reason: "failed".into(),
                },
                ..Status::default()
            },
            ..State::default()
        };
        assert!(state.act(Action::ConfirmProtectionOff).is_none());
        assert!(matches!(state.act(Action::Primary), Some(Job::Connect)));
        state.reduce(WorkerEvent::Connect(Ok(())));
        state.act(Action::RequestProtectionOff);
        assert!(state.protection_confirmation);
        assert!(matches!(
            state.act(Action::ConfirmProtectionOff),
            Some(Job::Disconnect)
        ));
        state.reduce(WorkerEvent::Disconnect(Err(HelperCommandError::Client(
            ClientError::Closed,
        ))));
        assert!(state.protection_confirmation);
        assert!(!state.operations.helper);
        state.act(Action::KeepBlocked);
        assert!(!state.protection_confirmation);
    }

    #[test]
    fn individual_update_and_remove_failures_clear_their_flags() {
        let mut state = State::default();
        let id = SubscriptionId::new("1");
        assert!(matches!(
            state.act(Action::Update(id.clone())),
            Some(Job::Update(_))
        ));
        assert!(state.act(Action::Update(id.clone())).is_none());
        state.reduce(WorkerEvent::Update {
            id: id.clone(),
            result: Err(UpdateSubscriptionError::NotFound),
        });
        assert!(!state.subscription_busy(&id));
        state.act(Action::RequestRemove(id.clone()));
        assert!(matches!(
            state.act(Action::ConfirmRemove),
            Some(Job::Remove(_))
        ));
        state.reduce(WorkerEvent::Remove {
            id,
            result: Err(RemoveSubscriptionError::SubscriptionNotFound),
        });
        assert!(!state.operations.removing);
        assert!(state.remove.as_ref().unwrap().error.is_some());
    }

    #[test]
    fn provider_controlled_labels_cannot_echo_subscription_urls() {
        let mut state = State::default();
        state.config.subscriptions.push(subscription("1"));
        assert_eq!(
            state.text("🇩🇪 https://example.com/secret-path\nnext"),
            "[DE] https://example.com/…\nnext"
        );
    }
}
