use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rosetun_config::{
    AppConfig, DnsSettings, LanguageSetting, NodeId, RuleId, RuleMatcher, RuleSetId, RuleTarget,
    RuleTemplate, Status, SubscriptionId,
};
use rosetun_core::{AddOptions, AppliedSnapshot, DnsPreset, SettingChange};
use rosetun_ipc::{ClientError, ConnectRequest};

use crate::display;
use crate::rules::TypeFilter;
use crate::worker::{ConfigWorkerError, FailureInterference, WorkerEvent};

mod connection;
mod rules;
mod session;
mod settings;
mod subscriptions;
mod traffic;
mod updates;

pub(crate) use connection::{ExitLookup, ExitRoute, TunnelDelay, primary_label};
use rules::RulesState;
pub(crate) use rules::{AddRuleDialog, DeleteDialog, NameDialogKind, RuleInputKind};
pub(crate) use session::SessionPart;
use session::SessionState;
use settings::SettingsState;
pub(crate) use settings::{AboutFolder, SettingsSection};
use subscriptions::SubscriptionsState;
pub(crate) use subscriptions::{AddDialog, PingResult, UpdateOutcome, shared_auto_update_hours};
pub(crate) use traffic::TrafficRange;
use traffic::TrafficState;
use updates::UpdatesState;

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default()
}

#[derive(Default)]
pub(crate) struct Operations {
    pub(crate) helper: bool,
    pub(crate) selection: bool,
    pub(crate) rules: bool,
    pub(crate) rules_edit: bool,
    pub(crate) kill_switch: bool,
    pub(crate) settings: bool,
    pub(crate) updating: BTreeSet<SubscriptionId>,
    pub(crate) pinging: BTreeSet<SubscriptionId>,
    pub(crate) update_all: bool,
    pub(crate) removing: bool,
    pub(crate) renaming: bool,
    pub(crate) moving_subscription: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Screen {
    #[default]
    Connection,
    Traffic,
    Rules,
    Settings,
}

pub(crate) struct State {
    pub(crate) config: AppConfig,
    pub(crate) config_ready: bool,
    auto_connect_pending: bool,
    pub(crate) subscriptions: SubscriptionsState,
    pub(crate) updates: UpdatesState,
    status_received: bool,
    pub(crate) config_generation: u64,
    pub(crate) config_error: Option<ConfigWorkerError>,
    pub(crate) status: Status,
    pub(crate) tunnel_delay: TunnelDelay,
    delay_last_auto: Option<u64>,
    pub(crate) session: SessionState,
    pub(crate) exit: ExitLookup,
    exit_route: Option<ExitRoute>,
    exit_generation: u64,
    pub(crate) exit_revealed: bool,
    pub(crate) traffic: TrafficState,
    pub(crate) helper_available: bool,
    pub(crate) helper_version: Option<String>,
    pub(crate) helper_error: Option<ClientError>,
    pub(crate) operation_error: Option<String>,
    pub(crate) failure_interference: Option<FailureInterference>,
    failure_interference_checked: bool,
    failure_interference_request: u64,
    pub(crate) cancel_in_flight: bool,
    connect_in_flight: bool,
    cancelled_connect: bool,
    deferred_connect: Option<ConnectRequest>,
    pub(crate) screen: Screen,
    pub(crate) rules: RulesState,
    pub(crate) settings: SettingsState,
    pub(crate) operations: Operations,
    pub(crate) protection_confirmation: bool,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: AppConfig::default(),
            config_ready: false,
            auto_connect_pending: true,
            subscriptions: SubscriptionsState::default(),
            updates: UpdatesState::default(),
            status_received: false,
            config_generation: 0,
            config_error: None,
            status: Status::default(),
            tunnel_delay: TunnelDelay::Idle,
            delay_last_auto: None,
            session: SessionState::default(),
            exit: ExitLookup::None,
            exit_route: None,
            exit_generation: 0,
            exit_revealed: false,
            traffic: TrafficState::default(),
            helper_available: false,
            helper_version: None,
            helper_error: None,
            operation_error: None,
            failure_interference: None,
            failure_interference_checked: false,
            failure_interference_request: 0,
            cancel_in_flight: false,
            connect_in_flight: false,
            cancelled_connect: false,
            deferred_connect: None,
            screen: Screen::default(),
            rules: RulesState::default(),
            settings: SettingsState::default(),
            operations: Operations::default(),
            protection_confirmation: false,
        }
    }
}

pub(crate) enum Action {
    ShowConnection,
    OpenTraffic,
    SetTrafficRange(TrafficRange),
    OpenSettings,
    #[cfg(windows)]
    WindowMinimized,
    OpenSettingsSection(SettingsSection),
    SetInterfaceScale(u16),
    SetLanguage(LanguageSetting),
    SetReduceMotion(bool),
    #[cfg(windows)]
    SetAutostart(bool),
    #[cfg(windows)]
    SetCloseToTray(bool),
    SetConnectOnStart(bool),
    SetAutoReconnect(bool),
    SetAutoUpdateSubscriptions(bool),
    SetCheckUpdates(bool),
    CheckUpdatesNow,
    SkipVersion,
    SaveDns,
    SelectCustomDns,
    SetDnsPreset(DnsPreset),
    RequestResetSettings,
    CancelResetSettings,
    ConfirmResetSettings,
    SetVerboseLog(bool),
    #[cfg(windows)]
    OpenFolder(AboutFolder),
    OpenRules,
    OpenActiveRules,
    ChooseRuleSet(RuleSetId),
    SetRuleTypeFilter(TypeFilter),
    SetRuleTargetFilter(Option<RuleTarget>),
    SelectRule {
        rule: RuleId,
        additive: bool,
        range: bool,
    },
    SelectVisibleRules,
    ClearRuleSelection,
    OpenCreateSet,
    OpenRenameSet,
    CancelSetName,
    SubmitSetName,
    RequestDeleteSet,
    RequestDeleteRule(RuleId),
    RequestDeleteSelectedRules,
    CancelRuleDelete,
    ConfirmRuleDelete,
    SetDefaultTarget(RuleTarget),
    AddTemplate(RuleTemplate),
    RemoveTemplate(RuleTemplate),
    OpenAddRule,
    OpenEditRule(RuleId),
    CancelAddRule,
    SelectRuleInput(RuleInputKind),
    RefreshProcesses,
    #[cfg(windows)]
    BrowseExecutable,
    SubmitAddRule,
    AddTemporary(Vec<RuleMatcher>, RuleTarget),
    RemoveTemporary(RuleId),
    KeepTemporary(RuleId),
    SetRuleTarget(RuleId, RuleTarget),
    SetRuleEnabled(RuleId, bool),
    DropRule(RuleId, usize),
    DropRules(Vec<RuleId>, usize),
    MoveRuleToTop(RuleId),
    MoveSelectedRulesToTop,
    MoveSelectedRulesToEnd,
    Primary,
    CancelConnection,
    Apply,
    RestoreMyEdits,
    RequestProtectionOff,
    KeepBlocked,
    ConfirmProtectionOff,
    SelectNode(SubscriptionId, NodeId),
    RevealServer,
    RevealDone,
    ToggleExitReveal,
    MeasureDelay,
    SelectRuleSet(Option<RuleSetId>),
    SetKillSwitch(bool),
    ToggleExpanded(SubscriptionId),
    DropSubscription(SubscriptionId, usize),
    OpenAdd,
    CancelAdd,
    SubmitAdd,
    Update(SubscriptionId),
    Ping(SubscriptionId),
    PingNode(SubscriptionId, NodeId),
    FullCheck(SubscriptionId),
    FullCheckNode(SubscriptionId, NodeId),
    UpdateAll,
    RequestRemove(SubscriptionId),
    CancelRemove,
    ConfirmRemove,
    RequestRename(SubscriptionId),
    CancelRename,
    SubmitRename,
    DismissOperationError,
    DismissApplyFailure,
    DismissConfigError,
    DismissOutcome(SubscriptionId),
}

pub(crate) enum Job {
    Connect,
    CheckFailureInterference {
        request: u64,
        own_alias: String,
    },
    Apply(Box<ConnectRequest>),
    RestoreApplied(AppliedSnapshot),
    RestoreEdits(AppliedSnapshot),
    LoadTemporaryRules(u64),
    Disconnect,
    SetInterfaceScale(u16),
    SetLanguage(LanguageSetting),
    Setting(SettingChange),
    #[cfg(windows)]
    LoadAutostart,
    #[cfg(windows)]
    SetAutostart(bool),
    SkipVersion(String),
    CheckUpdates,
    SetDns(DnsSettings),
    ResetSettings,
    SetVerboseLog(bool),
    #[cfg(windows)]
    OpenFolder(PathBuf),
    SelectNode(SubscriptionId, NodeId),
    SelectRuleSet(Option<RuleSetId>),
    CreateRuleSet(String),
    RenameRuleSet(RuleSetId, String),
    DeleteRuleSet(RuleSetId),
    SetDefaultTarget(RuleSetId, RuleTarget),
    LoadProcesses(u64),
    #[cfg(windows)]
    BrowseExecutable,
    AddRule(RuleSetId, RuleMatcher, RuleTarget),
    AddRules(RuleSetId, Vec<RuleMatcher>, RuleTarget),
    UpdateRule(RuleSetId, RuleId, RuleMatcher, RuleTarget),
    SetRuleTarget(RuleSetId, RuleId, RuleTarget),
    SetRuleEnabled(RuleSetId, RuleId, bool),
    MoveRule(RuleSetId, RuleId, usize),
    MoveRules(RuleSetId, Vec<RuleId>, usize),
    RemoveRule(RuleSetId, RuleId),
    RemoveRules(RuleSetId, Vec<RuleId>),
    SetKillSwitch(bool),
    Add {
        input: String,
        options: AddOptions,
    },
    Update(SubscriptionId),
    Ping(SubscriptionId),
    PingNode(SubscriptionId, NodeId),
    FullCheck(SubscriptionId),
    FullCheckNode(SubscriptionId, NodeId),
    TunnelDelay,
    LookupExit {
        generation: u64,
        route: ExitRoute,
    },
    UpdateAll,
    Remove(SubscriptionId),
    RenameSubscription(SubscriptionId, String),
    MoveSubscription(SubscriptionId, usize),
}

impl State {
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
                if self.settings.screen.opened && !self.settings.screen.dirty {
                    self.settings.screen.sync_dns(&self.config.settings.dns);
                }
                self.reconcile_subscriptions();
                self.reconcile_selected_set();
            }
            WorkerEvent::ConfigError(error) => self.config_error = Some(error),
            event @ (WorkerEvent::HelperAvailable { .. }
            | WorkerEvent::HelperUnavailable(_)
            | WorkerEvent::Status(_)
            | WorkerEvent::FailureInterference { .. }
            | WorkerEvent::Exit { .. }
            | WorkerEvent::ConnectSnapshot(_)
            | WorkerEvent::Connect(_)
            | WorkerEvent::Disconnect(_)
            | WorkerEvent::SelectNode(_)
            | WorkerEvent::SelectRuleSet(_)
            | WorkerEvent::SetKillSwitch(_)
            | WorkerEvent::TunnelDelay(_)) => self.reduce_connection(event),
            event @ WorkerEvent::TemporaryRules { .. } => self.reduce_session(event),
            event @ (WorkerEvent::Apply(_)
            | WorkerEvent::RestoreApplied(_)
            | WorkerEvent::RestoreEdits(_)) => self.reduce_session(event),
            event @ (WorkerEvent::CreateRuleSet(_)
            | WorkerEvent::RenameRuleSet(_)
            | WorkerEvent::DeleteRuleSet(_)
            | WorkerEvent::SetDefaultTarget(_)
            | WorkerEvent::Processes { .. }
            | WorkerEvent::AddRule(_)
            | WorkerEvent::AddRules(_)
            | WorkerEvent::UpdateRule(_)
            | WorkerEvent::SetRuleTarget(_)
            | WorkerEvent::SetRuleEnabled(_)
            | WorkerEvent::MoveRule(_)
            | WorkerEvent::MoveRules(_)
            | WorkerEvent::RemoveRule(_)
            | WorkerEvent::RemoveRules(_)) => self.reduce_rules(event),
            #[cfg(windows)]
            event @ WorkerEvent::BrowsedExecutable(_) => self.reduce_rules(event),
            event @ (WorkerEvent::SetInterfaceScale(_)
            | WorkerEvent::SetLanguage(_)
            | WorkerEvent::Setting(_, _)
            | WorkerEvent::SkipVersion(_)
            | WorkerEvent::SetDns(_)
            | WorkerEvent::ResetSettings(_)
            | WorkerEvent::SetVerboseLog(_)) => self.reduce_settings(event),
            #[cfg(windows)]
            event @ (WorkerEvent::AutostartLoaded(_)
            | WorkerEvent::SetAutostart(_)
            | WorkerEvent::OpenFolder(_)) => self.reduce_settings(event),
            WorkerEvent::UpdateCheck { checked_at, result } => {
                self.reduce_updates(result, checked_at);
            }
            event @ (WorkerEvent::Add(_)
            | WorkerEvent::Update { .. }
            | WorkerEvent::Ping { .. }
            | WorkerEvent::PingDone(_)
            | WorkerEvent::FullCheck { .. }) => self.reduce_subscriptions(event),
            event @ (WorkerEvent::UpdateAll(_)
            | WorkerEvent::Remove { .. }
            | WorkerEvent::RenameSubscription(_)
            | WorkerEvent::MoveSubscription(_)) => self.reduce_subscriptions(event),
        }
    }

    pub(crate) fn act(&mut self, action: Action) -> Option<Job> {
        match action {
            action @ (Action::ShowConnection
            | Action::Primary
            | Action::CancelConnection
            | Action::RequestProtectionOff
            | Action::KeepBlocked
            | Action::ConfirmProtectionOff
            | Action::SelectNode(_, _)
            | Action::ToggleExitReveal
            | Action::MeasureDelay
            | Action::SelectRuleSet(_)
            | Action::SetKillSwitch(_)) => return self.act_connection(action),
            action @ (Action::OpenTraffic | Action::SetTrafficRange(_)) => {
                return self.act_traffic(action);
            }
            #[cfg(windows)]
            action @ Action::WindowMinimized => return self.act_session(action),
            action @ (Action::OpenSettings
            | Action::OpenSettingsSection(_)
            | Action::SetInterfaceScale(_)
            | Action::SetLanguage(_)
            | Action::SetReduceMotion(_)
            | Action::SetConnectOnStart(_)
            | Action::SetAutoReconnect(_)
            | Action::SetAutoUpdateSubscriptions(_)
            | Action::SetCheckUpdates(_)
            | Action::SaveDns
            | Action::SelectCustomDns
            | Action::SetDnsPreset(_)
            | Action::RequestResetSettings
            | Action::CancelResetSettings
            | Action::ConfirmResetSettings
            | Action::SetVerboseLog(_)) => return self.act_settings(action),
            #[cfg(windows)]
            action @ (Action::SetAutostart(_)
            | Action::SetCloseToTray(_)
            | Action::OpenFolder(_)) => {
                return self.act_settings(action);
            }
            action @ (Action::CheckUpdatesNow | Action::SkipVersion) => {
                return self.act_updates(action);
            }
            action @ (Action::OpenRules
            | Action::OpenActiveRules
            | Action::ChooseRuleSet(_)
            | Action::SetRuleTypeFilter(_)
            | Action::SetRuleTargetFilter(_)
            | Action::SelectRule { .. }
            | Action::SelectVisibleRules
            | Action::ClearRuleSelection
            | Action::OpenCreateSet
            | Action::OpenRenameSet
            | Action::CancelSetName
            | Action::SubmitSetName
            | Action::RequestDeleteSet
            | Action::RequestDeleteRule(_)
            | Action::RequestDeleteSelectedRules
            | Action::CancelRuleDelete
            | Action::ConfirmRuleDelete
            | Action::SetDefaultTarget(_)
            | Action::AddTemplate(_)
            | Action::RemoveTemplate(_)
            | Action::OpenAddRule
            | Action::OpenEditRule(_)
            | Action::CancelAddRule
            | Action::SelectRuleInput(_)
            | Action::RefreshProcesses
            | Action::SubmitAddRule) => return self.act_rules(action),
            #[cfg(windows)]
            action @ Action::BrowseExecutable => return self.act_rules(action),
            action @ (Action::AddTemporary(_, _)
            | Action::RemoveTemporary(_)
            | Action::KeepTemporary(_)) => return self.act_session(action),
            action @ (Action::SetRuleTarget(_, _)
            | Action::SetRuleEnabled(_, _)
            | Action::DropRule(_, _)
            | Action::DropRules(_, _)
            | Action::MoveRuleToTop(_)
            | Action::MoveSelectedRulesToTop
            | Action::MoveSelectedRulesToEnd) => return self.act_rules(action),
            action @ (Action::Apply | Action::RestoreMyEdits) => {
                return self.act_session(action);
            }
            action @ (Action::RevealServer | Action::RevealDone) => {
                return self.act_subscriptions(action);
            }
            action @ (Action::ToggleExpanded(_)
            | Action::DropSubscription(_, _)
            | Action::OpenAdd
            | Action::CancelAdd
            | Action::SubmitAdd
            | Action::Update(_)
            | Action::Ping(_)
            | Action::PingNode(_, _)
            | Action::FullCheck(_)
            | Action::FullCheckNode(_, _)
            | Action::UpdateAll
            | Action::RequestRemove(_)
            | Action::CancelRemove
            | Action::ConfirmRemove
            | Action::RequestRename(_)
            | Action::CancelRename
            | Action::SubmitRename
            | Action::DismissOutcome(_)) => return self.act_subscriptions(action),
            Action::DismissOperationError => self.operation_error = None,
            Action::DismissApplyFailure => return self.act_session(Action::DismissApplyFailure),
            Action::DismissConfigError => self.config_error = None,
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

#[cfg(test)]
mod tests;
