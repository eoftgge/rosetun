use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rosetun_config::{
    AccentPreset, AppConfig, DnsSettings, ExitId, ExitTarget, LanguageSetting, ListId, ListSource, NodeId,
    RuleId, RuleMatcher, RuleSetId, RuleTarget, RuleTemplate, Status, SubscriptionId, XrayUse,
};
use rosetun_core::{
    AddOptions, AppliedSnapshot, DnsPreset, NewExit, RuleDestination, SettingChange,
};
use rosetun_ipc::{ClientError, ConnectRequest};

use crate::display;
use crate::rules::TypeFilter;
use crate::worker::{ConfigWorkerError, FailureInterference, WorkerEvent};

mod connection;
mod exits;
mod lists;
mod route_reason;
mod rules;
mod session;
mod settings;
mod subscriptions;
mod system_checks;
mod traffic;
mod updates;

pub(crate) use connection::{ExitLookup, ExitRoute, SessionExitRow, TunnelDelay, primary_label};
use exits::ExitsState;
pub(crate) use exits::{ExitDialog, ExitKind};
use lists::ListsState;
pub(crate) use lists::{AddListDialog, ListOutcome, RulesTab, source_file_name, used_by};
use rules::RulesState;
pub(crate) use rules::{AddRuleDialog, DeleteDialog, NameDialogKind, RuleInputKind};
use session::SessionState;
pub(crate) use session::{ExitInputs, SessionPart};
use settings::SettingsState;
pub(crate) use settings::{AboutFolder, SettingsSection};
use subscriptions::SubscriptionsState;
pub(crate) use subscriptions::{
    AddDialog, OpenedLink, PingResult, QrSource, QrStage, UpdateOutcome, shared_auto_update_hours,
};
use system_checks::SystemChecksState;
use traffic::TrafficState;
pub(crate) use traffic::{
    ConnectionRow, ConnectionsNotice, ConnectionsTab, ConnectionsView, ProgramGroup, RouteFilter,
    TrafficRange, program_rule, site_rule,
};
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
    pub(crate) lockdown: bool,
    pub(crate) settings: bool,
    pub(crate) updating: BTreeSet<SubscriptionId>,
    pub(crate) updating_lists: BTreeSet<ListId>,
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
    /// The technical reason under a failure is expanded; window state only.
    pub(crate) failure_details_open: bool,
    pub(crate) traffic: TrafficState,
    pub(crate) helper_available: bool,
    pub(crate) helper_version: Option<String>,
    pub(crate) helper_error: Option<ClientError>,
    pub(crate) operation_error: Option<String>,
    pub(crate) failure_interference: Option<FailureInterference>,
    pub(crate) system_checks: SystemChecksState,
    failure_interference_checked: bool,
    failure_interference_request: u64,
    pub(crate) cancel_in_flight: bool,
    connect_in_flight: bool,
    cancelled_connect: bool,
    deferred_connect: Option<ConnectRequest>,
    pub(crate) screen: Screen,
    pub(crate) rules: RulesState,
    pub(crate) lists: ListsState,
    pub(crate) exits: ExitsState,
    pub(crate) settings: SettingsState,
    pub(crate) operations: Operations,
    pub(crate) protection_confirmation: bool,
    /// The Lockdown value waiting for the user's confirmation.
    pub(crate) lockdown_confirmation: Option<bool>,
    lockdown_lan_pending: bool,
    /// The Lockdown command in flight only brings its LAN access in line
    /// with the saved "Local network" value.
    lockdown_lan_sync: bool,
    /// The administrator prompt for a "Local network" change was declined:
    /// the setting is saved, but Lockdown keeps its previous LAN access.
    pub(crate) lockdown_lan_kept: bool,
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
            failure_details_open: false,
            traffic: TrafficState::default(),
            helper_available: false,
            helper_version: None,
            helper_error: None,
            operation_error: None,
            failure_interference: None,
            system_checks: SystemChecksState::default(),
            failure_interference_checked: false,
            failure_interference_request: 0,
            cancel_in_flight: false,
            connect_in_flight: false,
            cancelled_connect: false,
            deferred_connect: None,
            screen: Screen::default(),
            rules: RulesState::default(),
            lists: ListsState::default(),
            exits: ExitsState::default(),
            settings: SettingsState::default(),
            operations: Operations::default(),
            protection_confirmation: false,
            lockdown_confirmation: None,
            lockdown_lan_pending: false,
            lockdown_lan_sync: false,
            lockdown_lan_kept: false,
        }
    }
}

pub(crate) enum Action {
    ShowConnection,
    OpenTraffic,
    SetTrafficRange(TrafficRange),
    SetConnectionsTab(ConnectionsTab),
    SetConnectionsFilter(String),
    SetConnectionsView(ConnectionsView),
    SetConnectionsRoute(RouteFilter),
    /// Show or hide a program's connections under it, by path.
    ToggleProgramGroup(Option<String>),
    /// By the engine's connection id; `None` closes the details.
    SelectConnection(Option<String>),
    CloseConnection(String),
    OpenSettings,
    #[cfg(windows)]
    WindowMinimized,
    OpenSettingsSection(SettingsSection),
    CheckSystem,
    ShowSystemChecks,
    OpenLanSettings,
    SetInterfaceScale(u16),
    SetLanguage(LanguageSetting),
    SetAccent(AccentPreset),
    SetReduceMotion(bool),
    #[cfg(windows)]
    SetAutostart(bool),
    #[cfg(windows)]
    SetCloseToTray(bool),
    SetConnectOnStart(bool),
    SetAutoReconnect(bool),
    SetAllowLan(bool),
    SetXray(XrayUse),
    EnableXrayAutoAndConnect,
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
    SaveReport,
    #[cfg(windows)]
    ShowReportFolder,
    #[cfg(windows)]
    OpenFolder(AboutFolder),
    OpenRules,
    OpenActiveRules,
    ShowLists,
    ShowRuleSets,
    OpenAddList,
    CancelAddList,
    BrowseListFile,
    SubmitAddList,
    UpdateListManual(ListId),
    UpdateListFile(ListId),
    OpenRenameList(ListId),
    CancelRenameList,
    SubmitRenameList,
    OpenRemoveList(ListId),
    CancelRemoveList,
    ConfirmRemoveList,
    DismissListsError,
    ShowExits,
    ShowExitRules(ExitId),
    OpenNewExit,
    OpenEditExit(ExitId),
    CancelExitDialog,
    SubmitExitDialog,
    OpenRenameExit(ExitId),
    CancelRenameExit,
    SubmitRenameExit,
    RequestDeleteExit(ExitId),
    CancelDeleteExit,
    ConfirmDeleteExit,
    ChooseRuleSet(RuleSetId),
    SetRuleTypeFilter(TypeFilter),
    SetRuleTargetFilter(Option<RuleTarget>),
    SetRuleExitFilter(ExitId),
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
    /// From the Traffic tab: the add-rule dialog of the active set with this condition.
    OpenAddRuleFor(RuleMatcher),
    OpenEditRule(RuleId),
    CancelAddRule,
    SelectRuleInput(RuleInputKind),
    CorrectRuleIps,
    RefreshProcesses,
    #[cfg(windows)]
    BrowseExecutable,
    SubmitAddRule,
    AddTemporary(Vec<RuleMatcher>, RuleDestination),
    RemoveTemporary(RuleId),
    KeepTemporary(RuleId),
    SetRuleTarget(RuleId, RuleDestination),
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
    ToggleFailureDetails,
    MeasureDelay,
    SelectRuleSet(Option<RuleSetId>),
    SetKillSwitch(bool),
    RequestLockdown(bool),
    CancelLockdown,
    ConfirmLockdown,
    ToggleExpanded(SubscriptionId),
    DropSubscription(SubscriptionId, usize),
    OpenAdd,
    OpenLink(OpenedLink),
    CancelAdd,
    SubmitAdd,
    ReadQr(QrSource),
    CancelQr,
    ChooseQrLink(usize),
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
    Connect(ExitInputs),
    CheckSystem {
        request: u64,
        own_alias: String,
        /// A tunnel or its protection carries the traffic: no DNS check.
        guarded: bool,
    },
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
    SetAccent(AccentPreset),
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
    SaveReport {
        snapshot: Box<crate::report::ReportSnapshot>,
        own_alias: String,
    },
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
    AddRule(RuleSetId, RuleMatcher, RuleDestination),
    AddRules(RuleSetId, Vec<RuleMatcher>, RuleDestination),
    UpdateRule(RuleSetId, RuleId, RuleMatcher, RuleDestination),
    SetRuleTarget(RuleSetId, RuleId, RuleDestination),
    CreateExit(NewExit),
    SaveExit {
        id: Option<ExitId>,
        name: String,
        target: ExitTarget,
    },
    RenameExit(ExitId, String),
    DeleteExit(ExitId),
    SetRuleEnabled(RuleSetId, RuleId, bool),
    MoveRule(RuleSetId, RuleId, usize),
    MoveRules(RuleSetId, Vec<RuleId>, usize),
    RemoveRule(RuleSetId, RuleId),
    RemoveRules(RuleSetId, Vec<RuleId>),
    SetKillSwitch(bool),
    SetLockdown(bool),
    Add {
        input: String,
        options: AddOptions,
    },
    ReadQr {
        request: u64,
        source: QrSource,
    },
    PollScreenClip {
        request: u64,
        sequence: u32,
    },
    Update(SubscriptionId),
    UpdateList(ListId),
    UpdateListManual(ListId),
    UpdateListFile(ListId),
    AddListUrl(String, String),
    AddListFile(PathBuf, String),
    BrowseListFile,
    InspectListCategories {
        revision: u64,
        temporary: Vec<rosetun_config::Rule>,
    },
    RenameList(ListId, String),
    RemoveList(ListId),
    Ping(SubscriptionId),
    PingNode(SubscriptionId, NodeId),
    FullCheck(SubscriptionId),
    FullCheckNode(SubscriptionId, NodeId),
    TunnelDelay,
    Connections,
    ProgramNames(Vec<String>),
    SessionLists {
        request: u64,
        session: Box<ConnectRequest>,
    },
    CloseConnection(String),
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

    /// How long until the earliest scheduled `take_*` becomes due; `None` when nothing is scheduled.
    pub(crate) fn next_wake(&self, now: u64) -> Option<Duration> {
        [
            self.temporary_load_due(),
            self.auto_update_due(),
            self.update_check_due(now),
            self.tunnel_delay_due(),
            self.connections_due(),
            self.screen_clip_due(),
        ]
        .into_iter()
        .flatten()
        .min()
        .map(|due| Duration::from_secs(due.saturating_sub(now)))
    }

    pub(crate) fn reduce(&mut self, event: WorkerEvent) {
        match event {
            WorkerEvent::Config { generation, config } => {
                if generation <= self.config_generation {
                    return;
                }
                self.config_generation = generation;
                self.config = config;
                self.cache_config_request();
                self.config_ready = true;
                self.config_error = None;
                if self.settings.screen.opened && !self.settings.screen.dirty {
                    self.settings.screen.sync_dns(&self.config.settings.dns);
                }
                self.reconcile_subscriptions();
                self.reconcile_lists();
                self.reconcile_exits();
                self.reconcile_selected_set();
                self.request_list_inspection();
                self.apply_pending_link();
            }
            WorkerEvent::ConfigError(error) => self.config_error = Some(error),
            WorkerEvent::SystemChecks { request, results } => {
                self.reduce_system_checks(request, results);
            }
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
            | WorkerEvent::SetLockdown { .. }
            | WorkerEvent::TunnelDelay(_)) => self.reduce_connection(event),
            event @ WorkerEvent::TemporaryRules { .. } => self.reduce_session(event),
            WorkerEvent::Connections {
                result,
                received_ms,
            } => self.reduce_connections(result, received_ms),
            WorkerEvent::ProgramNames(names) => self.reduce_program_names(names),
            WorkerEvent::SessionLists { request, result } => {
                self.reduce_session_lists(request, result);
            }
            WorkerEvent::CloseConnection(result) => self.reduce_close_connection(result),
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
            | WorkerEvent::CreateExit(_)
            | WorkerEvent::SetRuleEnabled(_)
            | WorkerEvent::MoveRule(_)
            | WorkerEvent::MoveRules(_)
            | WorkerEvent::RemoveRule(_)
            | WorkerEvent::RemoveRules(_)) => self.reduce_rules(event),
            #[cfg(windows)]
            event @ WorkerEvent::BrowsedExecutable(_) => self.reduce_rules(event),
            event @ (WorkerEvent::SaveExit(_)
            | WorkerEvent::RenameExit(_)
            | WorkerEvent::DeleteExit { .. }) => self.reduce_exits(event),
            event @ (WorkerEvent::SetInterfaceScale(_)
            | WorkerEvent::SetLanguage(_)
            | WorkerEvent::SetAccent(_)
            | WorkerEvent::Setting(_, _)
            | WorkerEvent::SkipVersion(_)
            | WorkerEvent::SetDns(_)
            | WorkerEvent::ResetSettings(_)
            | WorkerEvent::SetVerboseLog(_)) => self.reduce_settings(event),
            #[cfg(windows)]
            event @ (WorkerEvent::ReportSaved { .. }
            | WorkerEvent::AutostartLoaded(_)
            | WorkerEvent::SetAutostart(_)
            | WorkerEvent::OpenFolder(_)) => self.reduce_settings(event),
            WorkerEvent::UpdateCheck { checked_at, result } => {
                self.reduce_updates(result, checked_at);
            }
            event @ (WorkerEvent::Qr { .. } | WorkerEvent::QrScreenClip { .. }) => {
                self.reduce_qr(event);
            }
            event @ (WorkerEvent::Add(_)
            | WorkerEvent::Update { .. }
            | WorkerEvent::Ping { .. }
            | WorkerEvent::PingDone(_)
            | WorkerEvent::FullCheck { .. }) => self.reduce_subscriptions(event),
            event @ (WorkerEvent::UpdateAll { .. }
            | WorkerEvent::Remove { .. }
            | WorkerEvent::RenameSubscription(_)
            | WorkerEvent::MoveSubscription(_)) => self.reduce_subscriptions(event),
            event @ (WorkerEvent::BrowsedListFile(_)
            | WorkerEvent::AddList(_)
            | WorkerEvent::ListAvailability { .. }
            | WorkerEvent::UpdateList { .. }
            | WorkerEvent::FileListUpdateCancelled(_)
            | WorkerEvent::RenameList(_)
            | WorkerEvent::RemoveList(_)) => self.reduce_lists(event),
        }
    }

    pub(crate) fn act(&mut self, action: Action) -> Option<Job> {
        match action {
            action @ (Action::CheckSystem | Action::ShowSystemChecks) => {
                return self.act_system_checks(action);
            }
            action @ (Action::ShowConnection
            | Action::Primary
            | Action::CancelConnection
            | Action::RequestProtectionOff
            | Action::KeepBlocked
            | Action::ConfirmProtectionOff
            | Action::SelectNode(_, _)
            | Action::ToggleExitReveal
            | Action::ToggleFailureDetails
            | Action::MeasureDelay
            | Action::SelectRuleSet(_)
            | Action::SetKillSwitch(_)
            | Action::RequestLockdown(_)
            | Action::CancelLockdown
            | Action::ConfirmLockdown) => return self.act_connection(action),
            action @ (Action::OpenTraffic
            | Action::SetTrafficRange(_)
            | Action::SetConnectionsTab(_)
            | Action::SetConnectionsFilter(_)
            | Action::SetConnectionsView(_)
            | Action::SetConnectionsRoute(_)
            | Action::ToggleProgramGroup(_)
            | Action::SelectConnection(_)
            | Action::CloseConnection(_)) => {
                return self.act_traffic(action);
            }
            #[cfg(windows)]
            action @ Action::WindowMinimized => return self.act_session(action),
            action @ (Action::OpenSettings
            | Action::OpenSettingsSection(_)
            | Action::OpenLanSettings
            | Action::SetInterfaceScale(_)
            | Action::SetLanguage(_)
            | Action::SetAccent(_)
            | Action::SetReduceMotion(_)
            | Action::SetConnectOnStart(_)
            | Action::SetAutoReconnect(_)
            | Action::SetAllowLan(_)
            | Action::SetXray(_)
            | Action::EnableXrayAutoAndConnect
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
            | Action::SaveReport
            | Action::ShowReportFolder
            | Action::OpenFolder(_)) => {
                return self.act_settings(action);
            }
            action @ (Action::CheckUpdatesNow | Action::SkipVersion) => {
                return self.act_updates(action);
            }
            action @ (Action::ShowLists
            | Action::ShowRuleSets
            | Action::OpenAddList
            | Action::CancelAddList
            | Action::BrowseListFile
            | Action::SubmitAddList
            | Action::UpdateListManual(_)
            | Action::UpdateListFile(_)
            | Action::OpenRenameList(_)
            | Action::CancelRenameList
            | Action::SubmitRenameList
            | Action::OpenRemoveList(_)
            | Action::CancelRemoveList
            | Action::ConfirmRemoveList
            | Action::DismissListsError) => return self.act_lists(action),
            action @ (Action::ShowExits
            | Action::ShowExitRules(_)
            | Action::OpenNewExit
            | Action::OpenEditExit(_)
            | Action::CancelExitDialog
            | Action::SubmitExitDialog
            | Action::OpenRenameExit(_)
            | Action::CancelRenameExit
            | Action::SubmitRenameExit
            | Action::RequestDeleteExit(_)
            | Action::CancelDeleteExit
            | Action::ConfirmDeleteExit) => return self.act_exits(action),
            action @ (Action::OpenRules
            | Action::OpenActiveRules
            | Action::ChooseRuleSet(_)
            | Action::SetRuleTypeFilter(_)
            | Action::SetRuleTargetFilter(_)
            | Action::SetRuleExitFilter(_)
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
            | Action::OpenAddRuleFor(_)
            | Action::OpenEditRule(_)
            | Action::CancelAddRule
            | Action::SelectRuleInput(_)
            | Action::CorrectRuleIps
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
            action @ (Action::ReadQr(_) | Action::CancelQr | Action::ChooseQrLink(_)) => {
                return self.act_qr(action);
            }
            action @ (Action::RevealServer | Action::RevealDone | Action::OpenLink(_)) => {
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
            Action::DismissConfigError => {
                if !self.config_unreadable() {
                    self.config_error = None;
                }
            }
        }
        None
    }
}

pub(crate) fn redact(config: &AppConfig, value: &str) -> String {
    let text = config
        .subscriptions
        .iter()
        .fold(display::safe_multiline(value), |text, subscription| {
            display::provider_multiline(&text, &subscription.url)
        });
    config.lists.iter().fold(text, |text, list| {
        let ListSource::Url(url) = &list.source else {
            return text;
        };
        if url.is_empty() {
            return text;
        }
        let host = url::Url::parse(url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .unwrap_or_else(|| "[URL]".to_owned());
        text.replace(url, &host)
    })
}

#[cfg(test)]
mod tests;
