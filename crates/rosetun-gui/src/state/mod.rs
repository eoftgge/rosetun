use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rosetun_config::{
    AppConfig, ConnectionState, DnsSettings, FailureKind, LanguageSetting, NodeId, RuleId,
    RuleMatcher, RuleSetId, RuleTarget, RuleTemplate, Status, SubscriptionId,
};
use rosetun_core::{AddOptions, AppliedSnapshot, DnsPreset};
use rosetun_ipc::{ClientError, ConnectRequest, ErrorCode, HelperError, ProbeOutcome};

use crate::actions::{self, PrimaryAction};
use crate::display;
use crate::errors;
use crate::rules::TypeFilter;
use crate::worker::{ConfigWorkerError, FailureInterference, HelperCommandError, WorkerEvent};

mod rules;
mod session;
mod settings;
mod subscriptions;
mod traffic;
mod updates;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TunnelDelay {
    Idle,
    Measuring,
    Done(ProbeOutcome),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExitRoute {
    /// Connected: the server's exit.
    Tunnel,
    /// Disconnected, failed, or the service is down: the user's own address.
    Direct,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExitLookup {
    /// Not meaningful in this state (connecting, reconnecting, blocked).
    None,
    Pending(ExitRoute),
    Known {
        route: ExitRoute,
        info: rosetun_core::ExitInfo,
    },
    Failed(ExitRoute),
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
    SetReduceMotion(bool),
    #[cfg(windows)]
    LoadAutostart,
    #[cfg(windows)]
    SetAutostart(bool),
    #[cfg(windows)]
    SetCloseToTray(bool),
    SetConnectOnStart(bool),
    SetAutoReconnect(bool),
    SetAutoUpdateSubscriptions(bool),
    SetCheckUpdates(bool),
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

fn diagnosable_failure(state: &ConnectionState) -> bool {
    matches!(
        state,
        ConnectionState::Failed {
            failure_kind: Some(
                FailureKind::EngineNotReady
                    | FailureKind::ServerUnreachable
                    | FailureKind::ServerRejected
                    | FailureKind::ServerClosed
            ),
            ..
        } | ConnectionState::FailedProtected {
            failure_kind: Some(
                FailureKind::EngineNotReady
                    | FailureKind::ServerUnreachable
                    | FailureKind::ServerRejected
                    | FailureKind::ServerClosed
            ),
            ..
        }
    )
}

/// The helper already put this failure into the status the card shows.
fn reported_by_status(error: &HelperCommandError) -> bool {
    matches!(
        error,
        HelperCommandError::Client(ClientError::Helper(HelperError {
            code: ErrorCode::EngineFailed
                | ErrorCode::RoutingFailed
                | ErrorCode::UnsupportedRules
                | ErrorCode::Cancelled,
            ..
        }))
    )
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

    /// Connects once after start when the user asked for it.
    pub(crate) fn take_auto_connect(&mut self) -> Option<Job> {
        if !self.auto_connect_pending
            || !self.config_ready
            || !self.helper_available
            || !self.status_received
        {
            return None;
        }
        self.auto_connect_pending = false;
        if self.config.interface.connect_on_start
            && matches!(self.status.state, ConnectionState::Disconnected)
            && !self.operations.helper
            && self.primary_action() == PrimaryAction::Connect
        {
            self.operations.helper = true;
            self.connect_in_flight = true;
            self.reset_failure_interference();
            self.cancelled_connect = false;
            self.deferred_connect = None;
            self.operation_error = None;
            return Some(Job::Connect);
        }
        None
    }

    /// Starts one lookup after the route changes.
    pub(crate) fn take_exit_lookup(&mut self) -> Option<Job> {
        let route = if !self.helper_available {
            self.helper_error.as_ref().map(|_| ExitRoute::Direct)
        } else if !self.status_received {
            None
        } else {
            match self.status.state {
                ConnectionState::Disconnected | ConnectionState::Failed { .. } => {
                    Some(ExitRoute::Direct)
                }
                ConnectionState::Connected => Some(ExitRoute::Tunnel),
                ConnectionState::Connecting
                | ConnectionState::Reconnecting
                | ConnectionState::FailedProtected { .. } => None,
            }
        };
        let Some(route) = route else {
            self.exit = ExitLookup::None;
            self.exit_route = None;
            self.exit_revealed = false;
            return None;
        };
        if self.exit_route == Some(route) {
            return None;
        }
        self.exit_route = Some(route);
        self.exit_generation += 1;
        self.exit = ExitLookup::Pending(route);
        self.exit_revealed = false;
        Some(Job::LookupExit {
            generation: self.exit_generation,
            route,
        })
    }

    fn reset_failure_interference(&mut self) {
        self.failure_interference = None;
        self.failure_interference_checked = false;
        self.failure_interference_request = self.failure_interference_request.wrapping_add(1);
    }

    pub(crate) fn take_failure_interference(&mut self) -> Option<Job> {
        if !self.helper_available
            || !self.config_ready
            || !self.status_received
            || self.failure_interference_checked
            || !diagnosable_failure(&self.status.state)
        {
            return None;
        }
        self.failure_interference_checked = true;
        self.failure_interference_request = self.failure_interference_request.wrapping_add(1);
        Some(Job::CheckFailureInterference {
            request: self.failure_interference_request,
            own_alias: self.config.settings.tun.name.clone(),
        })
    }

    pub(crate) fn take_tunnel_delay(&mut self, now: u64) -> Option<Job> {
        if !self.status_received
            || !matches!(
                self.visible_status().map(|status| &status.state),
                Some(ConnectionState::Connected)
            )
        {
            return None;
        }
        let since = self.status.since_unix?;
        if now.saturating_sub(since) < 3
            || !matches!(self.tunnel_delay, TunnelDelay::Idle)
            || self
                .delay_last_auto
                .is_some_and(|last| now.saturating_sub(last) < 10)
        {
            return None;
        }
        self.delay_last_auto = Some(now);
        self.tunnel_delay = TunnelDelay::Measuring;
        Some(Job::TunnelDelay)
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
                if self.settings.screen.opened && !self.settings.screen.dirty {
                    self.settings.screen.sync_dns(&self.config.settings.dns);
                }
                self.reconcile_subscriptions();
                self.reconcile_selected_set();
            }
            WorkerEvent::ConfigError(error) => self.config_error = Some(error),
            WorkerEvent::HelperAvailable { version } => {
                self.helper_available = true;
                self.helper_version = Some(version);
                self.helper_error = None;
                self.status_received = false;
                self.clear_temporary();
                self.tunnel_delay = TunnelDelay::Idle;
                self.delay_last_auto = None;
            }
            WorkerEvent::HelperUnavailable(error) => {
                self.helper_available = false;
                self.clear_temporary();
                self.tunnel_delay = TunnelDelay::Idle;
                self.delay_last_auto = None;
                self.session.session_request = None;
                self.clear_applied_state();
                self.session.session_snapshot_checked = false;
                self.session.helper_lost();
                self.session.queued_leave_apply = None;
                self.clear_traffic_history();
                self.helper_error = Some(error);
                self.protection_confirmation = false;
                self.reset_failure_interference();
                self.cancel_in_flight = false;
                self.connect_in_flight = false;
                self.cancelled_connect = true;
                self.deferred_connect = None;
            }
            WorkerEvent::Status(status) => {
                if (status.state.is_transitional() && !self.status.state.is_transitional())
                    || (matches!(
                        status.state,
                        ConnectionState::Connected
                            | ConnectionState::Disconnected
                            | ConnectionState::Failed { .. }
                            | ConnectionState::FailedProtected { .. }
                    ) && self.status.state != status.state)
                {
                    self.reset_failure_interference();
                }
                if (!self.helper_available || !matches!(status.state, ConnectionState::Connected))
                    && let Some(dialog) = &mut self.rules.screen.add
                {
                    dialog.temporary_only = false;
                }
                if !self.helper_available
                    || !matches!(status.state, ConnectionState::Connected)
                    || status.since_unix != self.status.since_unix
                {
                    self.tunnel_delay = TunnelDelay::Idle;
                    self.delay_last_auto = None;
                }
                self.status_received = true;
                self.reduce_session_status(&status);
                self.reduce_traffic_status(&status);
                if !matches!(status.state, ConnectionState::FailedProtected { .. })
                    && !self.operations.helper
                {
                    self.protection_confirmation = false;
                }
                self.status = status;
            }
            WorkerEvent::FailureInterference { request, hints } => {
                if self.failure_interference_checked
                    && request == self.failure_interference_request
                    && self.helper_available
                    && diagnosable_failure(&self.status.state)
                {
                    self.failure_interference = Some(hints);
                }
            }
            event @ WorkerEvent::TemporaryRules { .. } => self.reduce_session(event),
            WorkerEvent::Exit {
                generation,
                route,
                result,
            } => {
                if generation != self.exit_generation
                    || !matches!(&self.exit, ExitLookup::Pending(pending) if *pending == route)
                {
                    return;
                }
                self.exit = match result {
                    Ok(info) => ExitLookup::Known { route, info },
                    Err(_) => ExitLookup::Failed(route),
                };
                self.exit_revealed = false;
            }
            WorkerEvent::ConnectSnapshot(snapshot) => {
                if self.connect_in_flight {
                    self.session.connect_snapshot = Some(snapshot);
                }
            }
            WorkerEvent::Connect(result) => {
                self.connect_in_flight = false;
                let snapshot = self.session.connect_snapshot.take();
                if self.cancelled_connect {
                    if self.cancel_in_flight {
                        self.session.deferred_snapshot = snapshot;
                        self.deferred_connect = result.ok();
                    }
                    self.operations.helper = self.cancel_in_flight;
                    return;
                }
                self.operations.helper = false;
                match result {
                    Ok(request) => {
                        self.session.temporary_rules = request.temporary_rules.clone();
                        self.session.temporary_rules_loaded = true;
                        self.session.temporary_load = None;
                        self.session.session_request = Some(request);
                        self.session.applied_snapshot = snapshot.or_else(|| {
                            self.config_ready
                                .then(|| AppliedSnapshot::from_config(&self.config))
                        });
                        self.session.session_snapshot_checked = true;
                        self.operation_error = None;
                    }
                    Err(error) if reported_by_status(&error) => self.operation_error = None,
                    Err(error) => self.helper_result(Err(error)),
                }
            }
            event @ (WorkerEvent::Apply(_)
            | WorkerEvent::RestoreApplied(_)
            | WorkerEvent::RestoreEdits(_)) => self.reduce_session(event),
            WorkerEvent::Disconnect(result) => {
                let cancelling = std::mem::take(&mut self.cancel_in_flight);
                self.operations.helper = cancelling && self.connect_in_flight;
                if result.is_ok() {
                    self.protection_confirmation = false;
                    self.deferred_connect = None;
                    self.session.session_request = None;
                    self.clear_temporary();
                    self.clear_applied_state();
                } else if cancelling {
                    self.cancelled_connect = false;
                    if let Some(request) = self.deferred_connect.take() {
                        self.session.temporary_rules = request.temporary_rules.clone();
                        self.session.temporary_rules_loaded = true;
                        self.session.session_request = Some(request);
                        self.session.applied_snapshot =
                            self.session.deferred_snapshot.take().or_else(|| {
                                self.config_ready
                                    .then(|| AppliedSnapshot::from_config(&self.config))
                            });
                        self.session.session_snapshot_checked = true;
                    }
                }
                self.helper_result(result);
            }
            WorkerEvent::SelectNode(result) => {
                self.operations.selection = false;
                self.session.set_apply_after_choice(
                    result.is_ok()
                        && matches!(
                            self.visible_status().map(|status| &status.state),
                            Some(ConnectionState::Connected)
                        ),
                );
                self.operation_error = result
                    .err()
                    .map(|error| self.text(&errors::select_node(crate::i18n::language(), &error)));
            }
            WorkerEvent::SelectRuleSet(result) => {
                self.operations.rules = false;
                self.session.set_apply_after_choice(
                    result.is_ok()
                        && matches!(
                            self.visible_status().map(|status| &status.state),
                            Some(ConnectionState::Connected)
                        ),
                );
                self.operation_error = result.err().map(|error| {
                    self.text(&errors::select_rule_set(crate::i18n::language(), &error))
                });
            }
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
            WorkerEvent::SetKillSwitch(result) => {
                self.operations.kill_switch = false;
                self.operation_error = result
                    .err()
                    .map(|error| self.text(&errors::store(crate::i18n::language(), &error)));
            }
            event @ (WorkerEvent::SetInterfaceScale(_)
            | WorkerEvent::SetLanguage(_)
            | WorkerEvent::SetReduceMotion(_)
            | WorkerEvent::SetConnectOnStart(_)
            | WorkerEvent::SetAutoReconnect(_)
            | WorkerEvent::SetAutoUpdateSubscriptions(_)
            | WorkerEvent::SetCheckUpdates(_)
            | WorkerEvent::SkipVersion(_)
            | WorkerEvent::SetDns(_)
            | WorkerEvent::ResetSettings(_)
            | WorkerEvent::SetVerboseLog(_)) => self.reduce_settings(event),
            #[cfg(windows)]
            event @ (WorkerEvent::AutostartLoaded(_)
            | WorkerEvent::SetAutostart(_)
            | WorkerEvent::SetCloseToTray(_)
            | WorkerEvent::OpenFolder(_)) => self.reduce_settings(event),
            WorkerEvent::UpdateCheck { checked_at, result } => {
                self.reduce_updates(result, checked_at);
            }
            event @ (WorkerEvent::Add(_)
            | WorkerEvent::Update { .. }
            | WorkerEvent::Ping { .. }
            | WorkerEvent::PingDone(_)
            | WorkerEvent::FullCheck { .. }) => self.reduce_subscriptions(event),
            WorkerEvent::TunnelDelay(result) => {
                if !self.status_received
                    || !matches!(
                        self.visible_status().map(|status| &status.state),
                        Some(ConnectionState::Connected)
                    )
                    || !matches!(self.tunnel_delay, TunnelDelay::Measuring)
                {
                    return;
                }
                self.tunnel_delay = match result {
                    Ok(outcome) => TunnelDelay::Done(outcome),
                    Err(HelperCommandError::Client(ClientError::Helper(HelperError {
                        code: ErrorCode::InvalidState | ErrorCode::Busy,
                        ..
                    }))) => TunnelDelay::Idle,
                    Err(_) => TunnelDelay::Done(ProbeOutcome::Fails),
                };
            }
            event @ (WorkerEvent::UpdateAll(_)
            | WorkerEvent::Remove { .. }
            | WorkerEvent::RenameSubscription(_)
            | WorkerEvent::MoveSubscription(_)) => self.reduce_subscriptions(event),
        }
    }

    fn helper_result(&mut self, result: Result<(), HelperCommandError>) {
        self.operation_error = result
            .err()
            .map(|error| self.text(&errors::helper_command(crate::i18n::language(), &error)));
    }

    pub(crate) fn act(&mut self, action: Action) -> Option<Job> {
        match action {
            Action::ShowConnection => return self.show_screen(Screen::Connection),
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
            Action::Primary => {
                let job = match self.primary_action() {
                    PrimaryAction::Connect | PrimaryAction::Retry | PrimaryAction::Reconnect => {
                        Job::Connect
                    }
                    PrimaryAction::Disconnect => Job::Disconnect,
                    PrimaryAction::Disabled => return None,
                };
                self.connect_in_flight = matches!(job, Job::Connect);
                if self.connect_in_flight {
                    self.reset_failure_interference();
                    self.cancelled_connect = false;
                    self.deferred_connect = None;
                }
                self.operations.helper = true;
                self.operation_error = None;
                return Some(job);
            }
            Action::CancelConnection => {
                if self.helper_available
                    && self.status.state.is_transitional()
                    && !self.cancel_in_flight
                {
                    self.cancel_in_flight = true;
                    self.cancelled_connect = true;
                    self.operations.helper = true;
                    self.operation_error = None;
                    return Some(Job::Disconnect);
                }
            }
            action @ (Action::Apply | Action::RestoreMyEdits) => {
                return self.act_session(action);
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
            action @ (Action::RevealServer | Action::RevealDone) => {
                return self.act_subscriptions(action);
            }
            Action::ToggleExitReveal => {
                if matches!(self.exit, ExitLookup::Known { .. }) {
                    self.exit_revealed = !self.exit_revealed;
                }
            }
            Action::MeasureDelay => {
                if self.status_received
                    && matches!(
                        self.visible_status().map(|status| &status.state),
                        Some(ConnectionState::Connected)
                    )
                    && !matches!(self.tunnel_delay, TunnelDelay::Measuring)
                {
                    self.tunnel_delay = TunnelDelay::Measuring;
                    return Some(Job::TunnelDelay);
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

pub(crate) fn primary_label(state: &State) -> String {
    if !state.helper_available {
        return tr!("connect");
    }
    if state.operations.helper || state.status.state.is_transitional() {
        match state.status.state {
            ConnectionState::Reconnecting if state.operations.helper => tr!("working"),
            ConnectionState::Reconnecting => tr!("disconnect"),
            ConnectionState::Connected | ConnectionState::FailedProtected { .. }
                if state.operations.helper =>
            {
                tr!("working")
            }
            _ => tr!("connecting-action"),
        }
    } else if state.primary_action() == PrimaryAction::Disabled {
        tr!("connect")
    } else {
        state.primary_action().label()
    }
}

#[cfg(test)]
mod tests;
