use std::collections::{BTreeMap, BTreeSet};

use rosetun_config::{
    AppConfig, ConnectionState, NodeId, RuleId, RuleMatcher, RuleSet, RuleSetId, RuleTarget,
    Status, SubscriptionId,
};
use rosetun_core::{AddFromUrlError, AddOptions, UpdateReport, UpdateSubscriptionError};
use rosetun_ipc::ClientError;

use crate::actions::{self, PrimaryAction};
use crate::display;
use crate::rules::{
    ProcessGroup, ProcessMatchMode, RuleFilter, TypeFilter, drop_target, group_processes,
};
use crate::strings;
use crate::worker::{ConfigWorkerError, HelperCommandError, WorkerEvent};

#[derive(Default)]
pub(crate) struct Operations {
    pub(crate) helper: bool,
    pub(crate) selection: bool,
    pub(crate) rules: bool,
    pub(crate) rules_edit: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Screen {
    #[default]
    Connection,
    Rules,
}

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum RuleInputKind {
    #[default]
    Domain,
    Process,
}

pub(crate) struct AddRuleDialog {
    pub(crate) set: RuleSetId,
    pub(crate) kind: RuleInputKind,
    pub(crate) target: RuleTarget,
    pub(crate) domain: String,
    pub(crate) process: String,
    pub(crate) process_filter: String,
    pub(crate) processes: Vec<ProcessGroup>,
    pub(crate) selected_process: Option<usize>,
    pub(crate) match_mode: ProcessMatchMode,
    pub(crate) load_request: Option<u64>,
    pub(crate) processes_loaded: bool,
    pub(crate) processes_error: Option<String>,
    pub(crate) busy: bool,
    pub(crate) error: Option<String>,
    pub(crate) focus_input: bool,
}

impl AddRuleDialog {
    fn new(set: RuleSetId) -> Self {
        Self {
            set,
            kind: RuleInputKind::Domain,
            target: RuleTarget::Proxy,
            domain: String::new(),
            process: String::new(),
            process_filter: String::new(),
            processes: Vec::new(),
            selected_process: None,
            match_mode: ProcessMatchMode::Name,
            load_request: None,
            processes_loaded: false,
            processes_error: None,
            busy: false,
            error: None,
            focus_input: true,
        }
    }
}

#[derive(Default)]
pub(crate) struct RuleScreen {
    pub(crate) selected_set: Option<RuleSetId>,
    pub(crate) filter: RuleFilter,
    pub(crate) name: Option<NameDialog>,
    pub(crate) delete: Option<DeleteDialog>,
    pub(crate) add: Option<AddRuleDialog>,
    opened: bool,
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
    pub(crate) screen: Screen,
    pub(crate) rule_screen: RuleScreen,
    next_process_request: u64,
    pub(crate) expanded: BTreeSet<SubscriptionId>,
    pub(crate) outcomes: BTreeMap<SubscriptionId, UpdateOutcome>,
    pub(crate) operations: Operations,
    pub(crate) add: Option<AddDialog>,
    pub(crate) remove: Option<RemoveDialog>,
    pub(crate) protection_confirmation: bool,
}

pub(crate) enum Action {
    ShowConnection,
    OpenRules,
    OpenActiveRules,
    ChooseRuleSet(RuleSetId),
    SetRuleTypeFilter(TypeFilter),
    ToggleRuleTargetFilter(RuleTarget),
    OpenCreateSet,
    OpenRenameSet,
    CancelSetName,
    SubmitSetName,
    RequestDeleteSet,
    RequestDeleteRule(RuleId),
    CancelRuleDelete,
    ConfirmRuleDelete,
    SetDefaultTarget(RuleTarget),
    OpenAddRule,
    CancelAddRule,
    SelectRuleInput(RuleInputKind),
    RefreshProcesses,
    SubmitAddRule,
    SetRuleTarget(RuleId, RuleTarget),
    SetRuleEnabled(RuleId, bool),
    MoveRule(RuleId, usize),
    DropRule(RuleId, usize),
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
    CreateRuleSet(String),
    RenameRuleSet(RuleSetId, String),
    DeleteRuleSet(RuleSetId),
    SetDefaultTarget(RuleSetId, RuleTarget),
    LoadProcesses(u64),
    AddRule(RuleSetId, RuleMatcher, RuleTarget),
    SetRuleTarget(RuleSetId, RuleId, RuleTarget),
    SetRuleEnabled(RuleSetId, RuleId, bool),
    MoveRule(RuleSetId, RuleId, usize),
    RemoveRule(RuleSetId, RuleId),
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

    pub(crate) fn selected_rules(&self) -> Option<&RuleSet> {
        let id = self.rule_screen.selected_set.as_ref()?;
        self.config.rule_sets.iter().find(|set| &set.id == id)
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

    fn reconcile_selected_set(&mut self) {
        if self.rule_screen.opened && self.selected_rules().is_none() {
            self.rule_screen.selected_set = self.preferred_set();
        }
        if self
            .rule_screen
            .add
            .as_ref()
            .is_some_and(|dialog| !self.config.rule_sets.iter().any(|set| set.id == dialog.set))
        {
            self.rule_screen.add = None;
        }
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
                self.reconcile_selected_set();
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
            WorkerEvent::CreateRuleSet(result) => {
                self.operations.rules_edit = false;
                match result {
                    Ok(set) => {
                        self.rule_screen.selected_set = Some(set.id);
                        self.rule_screen.name = None;
                    }
                    Err(error) => self.name_error(error.to_string()),
                }
            }
            WorkerEvent::RenameRuleSet(result) => {
                self.operations.rules_edit = false;
                match result {
                    Ok(()) => self.rule_screen.name = None,
                    Err(error) => self.name_error(error.to_string()),
                }
            }
            WorkerEvent::DeleteRuleSet(result) => {
                self.rule_screen.delete = None;
                self.finish_rule_edit(result);
            }
            WorkerEvent::SetDefaultTarget(result) => self.finish_rule_edit(result),
            WorkerEvent::Processes { request, result } => {
                if let Some(dialog) = &mut self.rule_screen.add
                    && dialog.load_request == Some(request)
                {
                    dialog.load_request = None;
                    match result {
                        Ok(processes) => {
                            dialog.processes = group_processes(processes);
                            dialog.processes_loaded = true;
                            dialog.selected_process = None;
                            dialog.processes_error = None;
                        }
                        Err(error) => dialog.processes_error = Some(error.to_string()),
                    }
                }
            }
            WorkerEvent::AddRule(result) => {
                self.operations.rules_edit = false;
                if self.rule_screen.add.is_some() {
                    match result {
                        Ok(_) => {
                            self.rule_screen.add = None;
                            self.rule_screen.filter = RuleFilter::default();
                        }
                        Err(error) => {
                            let message = self.text(&error.to_string());
                            if let Some(dialog) = &mut self.rule_screen.add {
                                dialog.busy = false;
                                dialog.error = Some(message);
                            }
                        }
                    }
                } else {
                    self.operation_error = result.err().map(|error| self.text(&error.to_string()));
                }
            }
            WorkerEvent::SetRuleTarget(result) => self.finish_rule_edit(result),
            WorkerEvent::SetRuleEnabled(result) => self.finish_rule_edit(result),
            WorkerEvent::MoveRule(result) => self.finish_rule_edit(result),
            WorkerEvent::RemoveRule(result) => {
                self.rule_screen.delete = None;
                self.finish_rule_edit(result);
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

    fn name_error(&mut self, error: String) {
        let message = self.text(&error);
        if let Some(dialog) = &mut self.rule_screen.name {
            dialog.error = Some(message);
        } else {
            self.operation_error = Some(message);
        }
    }

    fn finish_rule_edit(&mut self, result: Result<(), rosetun_core::RuleSetError>) {
        self.operations.rules_edit = false;
        self.operation_error = result.err().map(|error| self.text(&error.to_string()));
    }

    fn start_rule_edit(&mut self, job: Job) -> Option<Job> {
        self.operations.rules_edit = true;
        self.operation_error = None;
        Some(job)
    }

    fn load_processes(&mut self) -> Option<Job> {
        let dialog = self.rule_screen.add.as_mut()?;
        if dialog.kind != RuleInputKind::Process || dialog.load_request.is_some() || dialog.busy {
            return None;
        }
        self.next_process_request += 1;
        dialog.load_request = Some(self.next_process_request);
        dialog.processes_error = None;
        Some(Job::LoadProcesses(self.next_process_request))
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
            Action::ShowConnection => self.screen = Screen::Connection,
            Action::OpenRules => {
                if !self.rule_screen.opened {
                    self.rule_screen.selected_set = self.preferred_set();
                }
                self.rule_screen.opened = true;
                self.screen = Screen::Rules;
            }
            Action::OpenActiveRules => {
                self.rule_screen.selected_set = self.preferred_set();
                self.rule_screen.opened = true;
                self.screen = Screen::Rules;
            }
            Action::ChooseRuleSet(id) => {
                if self.config.rule_sets.iter().any(|set| set.id == id) {
                    self.rule_screen.selected_set = Some(id);
                }
            }
            Action::SetRuleTypeFilter(kind) => self.rule_screen.filter.kind = kind,
            Action::ToggleRuleTargetFilter(target) => {
                let filter = &mut self.rule_screen.filter.target;
                *filter = if *filter == Some(target) {
                    None
                } else {
                    Some(target)
                };
            }
            Action::OpenCreateSet => {
                if self.can_edit_rules() && self.rule_screen.name.is_none() {
                    self.rule_screen.name = Some(NameDialog {
                        kind: NameDialogKind::Create,
                        name: strings::BASIC.to_owned(),
                        error: None,
                        focus: true,
                    });
                }
            }
            Action::OpenRenameSet => {
                if self.can_edit_rules()
                    && self.rule_screen.name.is_none()
                    && let Some(set) = self.selected_rules()
                {
                    self.rule_screen.name = Some(NameDialog {
                        kind: NameDialogKind::Rename(set.id.clone()),
                        name: set.name.clone(),
                        error: None,
                        focus: true,
                    });
                }
            }
            Action::CancelSetName => {
                if !self.operations.rules_edit {
                    self.rule_screen.name = None;
                }
            }
            Action::SubmitSetName => {
                if self.can_edit_rules()
                    && let Some(dialog) = &self.rule_screen.name
                    && !dialog.name.trim().is_empty()
                {
                    let name = dialog.name.trim().to_owned();
                    let job = match &dialog.kind {
                        NameDialogKind::Create => Job::CreateRuleSet(name),
                        NameDialogKind::Rename(id) => Job::RenameRuleSet(id.clone(), name),
                    };
                    if let Some(dialog) = &mut self.rule_screen.name {
                        dialog.error = None;
                    }
                    return self.start_rule_edit(job);
                }
            }
            Action::RequestDeleteSet => {
                if self.can_edit_rules()
                    && self.rule_screen.delete.is_none()
                    && let Some(set) = self.selected_rules()
                {
                    self.rule_screen.delete = Some(DeleteDialog::Set(set.id.clone()));
                }
            }
            Action::RequestDeleteRule(rule) => {
                if self.can_edit_rules()
                    && self.rule_screen.delete.is_none()
                    && let Some(set) = self.selected_rules()
                    && set.rules.iter().any(|item| item.id == rule)
                {
                    self.rule_screen.delete = Some(DeleteDialog::Rule {
                        set: set.id.clone(),
                        rule,
                    });
                }
            }
            Action::CancelRuleDelete => {
                if !self.operations.rules_edit {
                    self.rule_screen.delete = None;
                }
            }
            Action::ConfirmRuleDelete => {
                if self.can_edit_rules()
                    && let Some(dialog) = &self.rule_screen.delete
                {
                    let job = match dialog {
                        DeleteDialog::Set(id) => Job::DeleteRuleSet(id.clone()),
                        DeleteDialog::Rule { set, rule } => {
                            Job::RemoveRule(set.clone(), rule.clone())
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
            Action::OpenAddRule => {
                if self.can_edit_rules()
                    && self.rule_screen.add.is_none()
                    && let Some(set) = self.selected_rules()
                {
                    self.rule_screen.add = Some(AddRuleDialog::new(set.id.clone()));
                }
            }
            Action::CancelAddRule => {
                if self
                    .rule_screen
                    .add
                    .as_ref()
                    .is_some_and(|dialog| !dialog.busy)
                {
                    self.rule_screen.add = None;
                }
            }
            Action::SelectRuleInput(kind) => {
                if let Some(dialog) = &mut self.rule_screen.add
                    && !dialog.busy
                    && dialog.kind != kind
                {
                    dialog.kind = kind;
                    dialog.error = None;
                    dialog.focus_input = true;
                    if kind == RuleInputKind::Process && !dialog.processes_loaded {
                        return self.load_processes();
                    }
                }
            }
            Action::RefreshProcesses => return self.load_processes(),
            Action::SubmitAddRule => {
                if self.can_edit_rules()
                    && let Some(dialog) = &self.rule_screen.add
                    && !dialog.busy
                    && self.rule_screen.selected_set.as_ref() == Some(&dialog.set)
                {
                    let matcher = match dialog.kind {
                        RuleInputKind::Domain => rosetun_core::parse_domain_input(&dialog.domain)
                            .ok()
                            .map(RuleMatcher::Domain),
                        RuleInputKind::Process => {
                            rosetun_core::parse_process_input(&dialog.process)
                                .ok()
                                .map(RuleMatcher::Process)
                        }
                    };
                    if let Some(matcher) = matcher {
                        let job = Job::AddRule(dialog.set.clone(), matcher, dialog.target);
                        if let Some(dialog) = &mut self.rule_screen.add {
                            dialog.busy = true;
                            dialog.error = None;
                        }
                        return self.start_rule_edit(job);
                    }
                }
            }
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
            Action::MoveRule(rule, to_index) => {
                if self.can_edit_rules()
                    && !self.rule_screen.filter.is_active()
                    && let Some(set) = self.selected_rules()
                    && let Some(from) = set.rules.iter().position(|item| item.id == rule)
                    && to_index < set.rules.len()
                    && from != to_index
                {
                    return self.start_rule_edit(Job::MoveRule(set.id.clone(), rule, to_index));
                }
            }
            Action::DropRule(rule, slot) => {
                if self.can_edit_rules()
                    && !self.rule_screen.filter.is_active()
                    && let Some(set) = self.selected_rules()
                    && let Some(from) = set.rules.iter().position(|item| item.id == rule)
                    && let Some(to) = drop_target(from, slot, set.rules.len())
                {
                    return self.start_rule_edit(Job::MoveRule(set.id.clone(), rule, to));
                }
            }
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
                if self.config_ready
                    && !self.operations.rules
                    && !self.operations.rules_edit
                    && !self.operations.helper
                {
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
    use rosetun_config::{DomainMatch, Rule, RuleMatcher};
    use rosetun_core::{RemoveSubscriptionError, RuleSetError, StoreError};
    use rosetun_ipc::ConnectRequestError;
    use rosetun_processes::RunningProcess;

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

    fn rule_set(id: &str) -> RuleSet {
        let mut set = RuleSet::new(RuleSetId::new(id), id, RuleTarget::Proxy);
        for (index, domain) in ["first.example", "second.example", "third.example"]
            .into_iter()
            .enumerate()
        {
            set.rules.push(Rule {
                id: RuleId::new(index.to_string()),
                enabled: true,
                matcher: RuleMatcher::Domain(DomainMatch::Exact(domain.into())),
                target: RuleTarget::Proxy,
            });
        }
        set
    }

    fn state_with_rules() -> State {
        State {
            config_ready: true,
            config: AppConfig {
                rule_sets: vec![rule_set("1"), rule_set("2")],
                active_rule_set: Some(RuleSetId::new("2")),
                ..AppConfig::default()
            },
            ..State::default()
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

    #[test]
    fn opening_and_reloading_rules_selects_active_then_first_if_missing() {
        let mut state = state_with_rules();
        assert_eq!(state.screen, Screen::Connection);
        state.act(Action::OpenRules);
        assert_eq!(state.screen, Screen::Rules);
        assert_eq!(state.rule_screen.selected_set, Some(RuleSetId::new("2")));
        state.act(Action::ChooseRuleSet(RuleSetId::new("1")));
        state.act(Action::ShowConnection);
        state.act(Action::OpenRules);
        assert_eq!(state.rule_screen.selected_set, Some(RuleSetId::new("1")));
        state.act(Action::OpenActiveRules);
        assert_eq!(state.rule_screen.selected_set, Some(RuleSetId::new("2")));
        state.reduce(WorkerEvent::Config {
            generation: 1,
            config: AppConfig {
                rule_sets: vec![rule_set("1")],
                ..AppConfig::default()
            },
        });
        assert_eq!(state.rule_screen.selected_set, Some(RuleSetId::new("1")));
        state.reduce(WorkerEvent::Config {
            generation: 2,
            config: AppConfig::default(),
        });
        assert!(state.rule_screen.selected_set.is_none());
        state.reduce(WorkerEvent::Config {
            generation: 3,
            config: AppConfig {
                rule_sets: vec![rule_set("3"), rule_set("4")],
                ..AppConfig::default()
            },
        });
        assert_eq!(state.rule_screen.selected_set, Some(RuleSetId::new("3")));

        let mut before_load = State::default();
        before_load.act(Action::OpenRules);
        before_load.reduce(WorkerEvent::Config {
            generation: 1,
            config: state_with_rules().config,
        });
        assert_eq!(
            before_load.rule_screen.selected_set,
            Some(RuleSetId::new("2"))
        );
        let mut no_active = state_with_rules();
        no_active.config.active_rule_set = None;
        no_active.act(Action::OpenRules);
        assert_eq!(
            no_active.rule_screen.selected_set,
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
            no_active.rule_screen.selected_set,
            Some(RuleSetId::new("1"))
        );
    }

    #[test]
    fn set_name_dialog_keeps_errors_and_success_selects_created_set() {
        let mut state = state_with_rules();
        state.act(Action::OpenCreateSet);
        assert_eq!(
            state.rule_screen.name.as_ref().unwrap().name,
            strings::BASIC
        );
        state.rule_screen.name.as_mut().unwrap().name = "   ".into();
        assert!(state.act(Action::SubmitSetName).is_none());
        state.rule_screen.name.as_mut().unwrap().name = "  Work  ".into();
        assert!(matches!(
            state.act(Action::SubmitSetName),
            Some(Job::CreateRuleSet(name)) if name == "Work"
        ));
        assert!(state.operations.rules_edit);
        assert!(state.act(Action::CancelSetName).is_none());
        assert!(state.rule_screen.name.is_some());
        state.reduce(WorkerEvent::CreateRuleSet(Err(RuleSetError::EmptyName)));
        assert!(!state.operations.rules_edit);
        assert!(state.operation_error.is_none());
        assert_eq!(
            state.rule_screen.name.as_ref().unwrap().error.as_deref(),
            Some("rule set name must not be empty")
        );
        state.reduce(WorkerEvent::CreateRuleSet(Ok(rule_set("3"))));
        assert_eq!(state.rule_screen.selected_set, Some(RuleSetId::new("3")));
        assert!(state.rule_screen.name.is_none());

        state.act(Action::ChooseRuleSet(RuleSetId::new("1")));
        state.act(Action::OpenRenameSet);
        assert!(matches!(
            state.act(Action::SubmitSetName),
            Some(Job::RenameRuleSet(_, _))
        ));
        state.reduce(WorkerEvent::RenameRuleSet(Err(RuleSetError::SetNotFound)));
        assert!(!state.operations.rules_edit);
        assert!(state.operation_error.is_none());
        assert!(state.rule_screen.name.as_ref().unwrap().error.is_some());
        state.reduce(WorkerEvent::RenameRuleSet(Ok(())));
        assert!(state.rule_screen.name.is_none());
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
            WorkerEvent::RemoveRule(Err(RuleSetError::RuleNotFound)),
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
            WorkerEvent::RemoveRule(Ok(())),
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
            state.rule_screen.delete,
            Some(DeleteDialog::Set(_))
        ));
        assert!(matches!(
            state.act(Action::ConfirmRuleDelete),
            Some(Job::DeleteRuleSet(id)) if id == RuleSetId::new("2")
        ));
        assert!(state.act(Action::CancelRuleDelete).is_none());
        state.reduce(WorkerEvent::DeleteRuleSet(Err(RuleSetError::SetNotFound)));
        assert!(state.rule_screen.delete.is_none());
        assert_eq!(
            state.operation_error.as_deref(),
            Some("rule set does not exist")
        );
    }

    #[test]
    fn process_results_fill_only_the_current_dialog_and_are_dropped_on_close() {
        let mut state = state_with_rules();
        state.act(Action::OpenRules);
        assert!(state.act(Action::RefreshProcesses).is_none());
        state.act(Action::OpenAddRule);
        let Some(Job::LoadProcesses(first)) =
            state.act(Action::SelectRuleInput(RuleInputKind::Process))
        else {
            panic!("process tab must start a worker job");
        };
        assert!(state.act(Action::RefreshProcesses).is_none());
        state.reduce(WorkerEvent::Processes {
            request: first,
            result: Ok(vec![RunningProcess {
                pid: 100,
                name: "Telegram.exe".into(),
                path: Some(r"C:\Apps\Telegram.exe".into()),
            }]),
        });
        let dialog = state.rule_screen.add.as_ref().unwrap();
        assert!(dialog.processes_loaded);
        assert_eq!(dialog.processes[0].name, "Telegram.exe");
        assert_eq!(dialog.processes[0].count, 1);
        state.act(Action::CancelAddRule);
        assert!(state.rule_screen.add.is_none());

        state.act(Action::OpenAddRule);
        let Some(Job::LoadProcesses(second)) =
            state.act(Action::SelectRuleInput(RuleInputKind::Process))
        else {
            panic!("reopened dialog must start a new worker job");
        };
        assert_ne!(first, second);
        state.reduce(WorkerEvent::Processes {
            request: first,
            result: Ok(vec![RunningProcess {
                pid: 101,
                name: "Old.exe".into(),
                path: None,
            }]),
        });
        assert!(state.rule_screen.add.as_ref().unwrap().processes.is_empty());
        state.reduce(WorkerEvent::Processes {
            request: second,
            result: Err(rosetun_processes::ProcessListError::Snapshot(
                std::io::Error::from_raw_os_error(5),
            )),
        });
        let dialog = state.rule_screen.add.as_ref().unwrap();
        assert!(!dialog.processes_loaded);
        assert!(dialog.processes_error.is_some());
        assert!(matches!(
            state.act(Action::RefreshProcesses),
            Some(Job::LoadProcesses(_))
        ));
    }

    #[test]
    fn add_rule_keeps_duplicate_error_in_dialog_and_resets_filters_on_success() {
        let mut state = state_with_rules();
        state.act(Action::OpenRules);
        state.rule_screen.filter.search = "other".into();
        state.rule_screen.filter.kind = TypeFilter::Processes;
        state.rule_screen.filter.target = Some(RuleTarget::Direct);
        state.act(Action::OpenAddRule);
        assert!(state.act(Action::SubmitAddRule).is_none());
        let dialog = state.rule_screen.add.as_mut().unwrap();
        dialog.domain = "*.example.com".into();
        dialog.target = RuleTarget::Direct;
        assert!(matches!(
            state.act(Action::SubmitAddRule),
            Some(Job::AddRule(set, RuleMatcher::Domain(DomainMatch::Suffix(domain)), RuleTarget::Direct))
                if set == RuleSetId::new("2") && domain == "example.com"
        ));
        assert!(state.act(Action::CancelAddRule).is_none());
        state.reduce(WorkerEvent::AddRule(Err(RuleSetError::DuplicateRule)));
        let dialog = state.rule_screen.add.as_ref().unwrap();
        assert_eq!(dialog.domain, "*.example.com");
        assert_eq!(
            dialog.error.as_deref(),
            Some("this rule is already in the set")
        );
        assert!(!dialog.busy);
        assert!(!state.operations.rules_edit);
        assert!(state.operation_error.is_none());
        assert!(state.rule_screen.filter.is_active());
        assert!(matches!(
            state.act(Action::SubmitAddRule),
            Some(Job::AddRule(_, _, _))
        ));
        state.reduce(WorkerEvent::AddRule(Ok(rule_set("2").rules[0].clone())));
        assert!(state.rule_screen.add.is_none());
        assert!(!state.rule_screen.filter.is_active());
    }

    #[test]
    fn process_input_and_missing_set_guard_submission() {
        let mut state = state_with_rules();
        state.act(Action::OpenRules);
        state.act(Action::OpenAddRule);
        state.act(Action::SelectRuleInput(RuleInputKind::Process));
        state.rule_screen.add.as_mut().unwrap().process = r#""C:\Apps\curl.exe""#.into();
        assert!(matches!(
            state.act(Action::SubmitAddRule),
            Some(Job::AddRule(
                _,
                RuleMatcher::Process(rosetun_config::ProcessMatch::Path(_)),
                _
            ))
        ));
        state.reduce(WorkerEvent::AddRule(Err(RuleSetError::SetNotFound)));
        state.rule_screen.selected_set = None;
        assert!(state.act(Action::SubmitAddRule).is_none());
        state.act(Action::CancelAddRule);
        assert!(state.rule_screen.add.is_none());
    }

    #[test]
    fn rule_actions_reject_concurrent_changes_and_filtered_reordering() {
        let mut state = state_with_rules();
        state.act(Action::OpenRules);
        let rule = RuleId::new("1");
        assert!(matches!(
            state.act(Action::MoveRule(rule.clone(), 0)),
            Some(Job::MoveRule(_, _, 0))
        ));
        assert!(state.act(Action::MoveRule(rule.clone(), 2)).is_none());
        assert!(
            state
                .act(Action::SetRuleEnabled(rule.clone(), false))
                .is_none()
        );
        assert!(state.act(Action::SelectRuleSet(None)).is_none());
        state.reduce(WorkerEvent::MoveRule(Ok(())));
        state.rule_screen.filter.search = "second".into();
        assert!(state.act(Action::MoveRule(rule.clone(), 2)).is_none());
        assert!(state.act(Action::DropRule(rule.clone(), 3)).is_none());
        state.rule_screen.filter.search.clear();
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
        let dialog = state.rule_screen.add.as_mut().unwrap();
        dialog.domain = "new.example".into();
        dialog.target = RuleTarget::Block;
        assert!(matches!(
            state.act(Action::SubmitAddRule),
            Some(Job::AddRule(
                _,
                RuleMatcher::Domain(DomainMatch::Exact(_)),
                RuleTarget::Block
            ))
        ));
        state.reduce(WorkerEvent::AddRule(Ok(rule_set("1").rules[0].clone())));
        state.act(Action::RequestDeleteRule(rule));
        assert!(matches!(
            state.act(Action::ConfirmRuleDelete),
            Some(Job::RemoveRule(_, _))
        ));
        state.reduce(WorkerEvent::RemoveRule(Ok(())));
        assert!(state.rule_screen.delete.is_none());
    }
}
