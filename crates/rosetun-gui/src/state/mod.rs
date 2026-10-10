use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rosetun_config::{
    AppConfig, ConnectionState, DnsSettings, DomainMatch, FailureKind, LanguageSetting, NodeId,
    ProcessMatch, Rule, RuleId, RuleMatcher, RuleSet, RuleSetId, RuleTarget, RuleTemplate, Status,
    Subscription, SubscriptionId,
};
use rosetun_core::{
    AddFromUrlError, AddOptions, AppliedSnapshot, DnsPreset, Ping, UpdateReport,
    UpdateSubscriptionError,
};
use rosetun_ipc::{ClientError, ConnectRequest, ErrorCode, HelperError, ProbeOutcome, ProbeResult};

use crate::actions::{self, PrimaryAction};
use crate::display;
use crate::errors;
use crate::reorder::drop_target;
use crate::rules::{
    ProcessGroup, ProcessMatchMode, RuleFilter, TypeFilter, group_processes, visible_rules,
};
use crate::worker::{ConfigWorkerError, FailureInterference, HelperCommandError, WorkerEvent};

mod updates;

use updates::UpdatesState;

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default()
}

/// Default refresh interval when the provider names none.
const AUTO_UPDATE_HOURS: u64 = 12;
/// Provider intervals outside this range are clamped.
const AUTO_UPDATE_RANGE: RangeInclusive<u64> = 1..=168;
/// A failed automatic update is retried after this long.
const AUTO_UPDATE_RETRY: u64 = 60 * 60;
/// How often the schedule is checked.
const AUTO_UPDATE_CHECK: u64 = 60;
const TRAFFIC_HISTORY: usize = 900;

/// Hours between automatic updates of one subscription.
pub(crate) fn auto_update_hours(subscription: &Subscription) -> u64 {
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
fn update_due(subscription: &Subscription, now: u64, last_attempt: Option<u64>) -> bool {
    let hours = auto_update_hours(subscription);
    subscription
        .updated_at_unix
        .is_none_or(|updated| now.saturating_sub(updated) >= hours * 60 * 60)
        && last_attempt.is_none_or(|attempt| now.saturating_sub(attempt) >= AUTO_UPDATE_RETRY)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PingResult {
    Pending,
    /// TCP connect time.
    Answered(Duration),
    /// No TCP answer.
    NoAnswer,
    /// A request through the node answered.
    Works(Duration),
    /// A request through the node failed.
    Fails,
    Unresolved,
    Unsupported,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum TrafficRange {
    #[default]
    OneMinute,
    FiveMinutes,
    FifteenMinutes,
}

impl TrafficRange {
    pub(crate) fn samples_per_bar(self) -> usize {
        match self {
            Self::OneMinute => 1,
            Self::FiveMinutes => 5,
            Self::FifteenMinutes => 15,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SettingsSection {
    #[default]
    General,
    Connection,
    Network,
    Service,
    About,
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
    Rules { set: RuleSetId, rules: Vec<RuleId> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum RuleInputKind {
    Domain,
    #[default]
    Process,
}

pub(crate) struct AddRuleDialog {
    pub(crate) set: RuleSetId,
    pub(crate) kind: RuleInputKind,
    pub(crate) target: RuleTarget,
    pub(crate) domains: String,
    pub(crate) subdomains: bool,
    pub(crate) show_all: bool,
    pub(crate) advanced: bool,
    pub(crate) temporary_only: bool,
    pub(crate) editing: Option<RuleId>,
    original_domain: Option<DomainMatch>,
    pub(crate) process: String,
    pub(crate) process_filter: String,
    pub(crate) processes: Vec<ProcessGroup>,
    pub(crate) selected_process: Option<usize>,
    pub(crate) match_mode: ProcessMatchMode,
    #[cfg(windows)]
    pub(crate) browsing: bool,
    #[cfg(windows)]
    pub(crate) browsed: Option<PathBuf>,
    pub(crate) load_request: Option<u64>,
    pub(crate) processes_loaded: bool,
    pub(crate) processes_error: Option<String>,
    pub(crate) busy: bool,
    pub(crate) error: Option<String>,
    pub(crate) focus_input: bool,
}

impl AddRuleDialog {
    pub(crate) fn new(set: RuleSetId) -> Self {
        Self {
            set,
            kind: RuleInputKind::Process,
            target: RuleTarget::Proxy,
            domains: String::new(),
            subdomains: true,
            show_all: false,
            advanced: false,
            temporary_only: false,
            editing: None,
            original_domain: None,
            process: String::new(),
            process_filter: String::new(),
            processes: Vec::new(),
            selected_process: None,
            match_mode: ProcessMatchMode::Name,
            #[cfg(windows)]
            browsing: false,
            #[cfg(windows)]
            browsed: None,
            load_request: None,
            processes_loaded: false,
            processes_error: None,
            busy: false,
            error: None,
            focus_input: true,
        }
    }

    fn for_rule(set: RuleSetId, rule: &Rule) -> Option<Self> {
        let mut dialog = Self::new(set);
        dialog.editing = Some(rule.id.clone());
        dialog.target = rule.target;
        match &rule.matcher {
            RuleMatcher::Domain(domain) => {
                dialog.kind = RuleInputKind::Domain;
                dialog.subdomains = matches!(domain, DomainMatch::Suffix(_));
                dialog.domains = rosetun_core::rule_value_text(&rule.matcher)
                    .trim_start_matches("*.")
                    .to_owned();
                dialog.original_domain = Some(domain.clone());
            }
            RuleMatcher::Process(process) => {
                dialog.process = rosetun_core::rule_value_text(&rule.matcher);
                match process {
                    ProcessMatch::Name(name) => dialog.process_filter = name.clone(),
                    ProcessMatch::Path(path) => {
                        dialog.match_mode = ProcessMatchMode::Path;
                        dialog.advanced = true;
                        dialog.process_filter = path
                            .file_name()
                            .map_or_else(|| path.to_string_lossy(), |name| name.to_string_lossy())
                            .into_owned();
                        #[cfg(windows)]
                        {
                            dialog.browsed = Some(path.clone());
                        }
                    }
                }
            }
            _ => return None,
        }
        Some(dialog)
    }

    pub(crate) fn unchanged_domain(&self) -> Option<DomainMatch> {
        let original = self.original_domain.as_ref()?;
        let matcher = RuleMatcher::Domain(original.clone());
        let value = rosetun_core::rule_value_text(&matcher);
        let value = value.strip_prefix("*.").unwrap_or(&value);
        (self.domains.trim() == value
            && self.subdomains == matches!(original, DomainMatch::Suffix(_)))
        .then(|| original.clone())
    }

    pub(crate) fn set_process_match_mode(&mut self, mode: ProcessMatchMode) {
        self.match_mode = mode;
        if let Some(group) = self
            .selected_process
            .and_then(|index| self.processes.get(index))
        {
            let value = match mode {
                ProcessMatchMode::Name => Some(group.name.clone()),
                ProcessMatchMode::Path => group
                    .path
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned()),
            };
            if let Some(value) = value {
                self.process = value;
            }
        } else {
            #[cfg(windows)]
            if let Some(path) = &self.browsed {
                self.process = browsed_process_value(path, mode);
                self.error = None;
                return;
            }
            if mode == ProcessMatchMode::Name
                && let Ok(ProcessMatch::Path(path)) =
                    rosetun_core::parse_process_input(&self.process)
                && let Some(name) = path.file_name()
            {
                self.process = name.to_string_lossy().into_owned();
            }
        }
        self.error = None;
    }
}

#[cfg(windows)]
fn browsed_process_value(path: &std::path::Path, mode: ProcessMatchMode) -> String {
    match mode {
        ProcessMatchMode::Name => path
            .file_name()
            .map_or_else(|| path.to_string_lossy(), |name| name.to_string_lossy())
            .into_owned(),
        ProcessMatchMode::Path => path.to_string_lossy().into_owned(),
    }
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
    fn clear_selection(&mut self) {
        self.selected_rules.clear();
        self.selection_anchor = None;
    }
}

#[derive(Default)]
pub(crate) struct SettingsScreen {
    pub(crate) section: SettingsSection,
    pub(crate) custom_dns: bool,
    pub(crate) reset_open: bool,
    pub(crate) server: String,
    pub(crate) server_name: String,
    pub(crate) port: String,
    pub(crate) path: String,
    pub(crate) dirty: bool,
    pub(crate) config_folder: Option<PathBuf>,
    pub(crate) licenses_folder: Option<PathBuf>,
    #[cfg(windows)]
    pub(crate) autostart: Option<bool>,
    opened: bool,
}

impl SettingsScreen {
    fn sync_dns(&mut self, dns: &DnsSettings) {
        self.custom_dns = DnsPreset::matching(dns).is_none();
        self.server = dns.server.to_string();
        self.server_name = dns.server_name.clone();
        self.port = dns.port.map_or_else(String::new, |port| port.to_string());
        self.path = dns.path.clone().unwrap_or_default();
    }

    pub(crate) fn parsed_dns(&self) -> Result<DnsSettings, rosetun_core::DnsInputError> {
        rosetun_core::parse_dns_input(&self.server, &self.server_name, &self.port, &self.path)
    }
}

pub(crate) enum SessionPart {
    Server,
    Rules,
    Dns,
    Protection,
}

pub(crate) struct State {
    pub(crate) config: AppConfig,
    pub(crate) config_ready: bool,
    auto_connect_pending: bool,
    next_auto_update_check: u64,
    auto_update_attempts: HashMap<SubscriptionId, u64>,
    pub(crate) updates: UpdatesState,
    status_received: bool,
    pub(crate) config_generation: u64,
    pub(crate) config_error: Option<ConfigWorkerError>,
    pub(crate) status: Status,
    pub(crate) tunnel_delay: TunnelDelay,
    delay_last_auto: Option<u64>,
    session_request: Option<ConnectRequest>,
    applied_snapshot: Option<AppliedSnapshot>,
    connect_snapshot: Option<AppliedSnapshot>,
    deferred_snapshot: Option<AppliedSnapshot>,
    apply_candidate: Option<AppliedSnapshot>,
    apply_baseline: Option<AppliedSnapshot>,
    failed_edits: Option<AppliedSnapshot>,
    blocked_auto_apply: Option<AppliedSnapshot>,
    restore_pending: bool,
    pending_restore: Option<Job>,
    restore_reason: Option<String>,
    pub(crate) apply_failure: Option<String>,
    pub(crate) temporary_rules: Vec<Rule>,
    temporary_rules_loaded: bool,
    temporary_load: Option<u64>,
    next_temporary_load: u64,
    temporary_retry: bool,
    temporary_waiting_status: bool,
    temporary_last_load: Option<u64>,
    temporary_error_reported: bool,
    temporary_before_apply: Option<Vec<Rule>>,
    keep_temporary: Option<RuleId>,
    keep_apply: Option<RuleId>,
    session_snapshot_checked: bool,
    apply_after_choice: bool,
    apply_in_flight: bool,
    apply_after_leave: bool,
    queued_leave_apply: Option<Job>,
    pub(crate) exit: ExitLookup,
    exit_route: Option<ExitRoute>,
    exit_generation: u64,
    pub(crate) exit_revealed: bool,
    /// Rates of the last 15 minutes, one sample per status; newest last.
    pub(crate) traffic_history: VecDeque<(u64, u64)>,
    pub(crate) traffic_range: TrafficRange,
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
    pub(crate) rule_screen: RuleScreen,
    pub(crate) settings_screen: SettingsScreen,
    next_process_request: u64,
    pub(crate) expanded: BTreeSet<SubscriptionId>,
    pub(crate) reveal: Option<(SubscriptionId, NodeId)>,
    pub(crate) outcomes: BTreeMap<SubscriptionId, UpdateOutcome>,
    pub(crate) pings: HashMap<(SubscriptionId, NodeId), PingResult>,
    pub(crate) operations: Operations,
    pub(crate) add: Option<AddDialog>,
    pub(crate) remove: Option<RemoveDialog>,
    pub(crate) rename: Option<RenameDialog>,
    pub(crate) protection_confirmation: bool,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: AppConfig::default(),
            config_ready: false,
            auto_connect_pending: true,
            next_auto_update_check: 0,
            auto_update_attempts: HashMap::new(),
            updates: UpdatesState::default(),
            status_received: false,
            config_generation: 0,
            config_error: None,
            status: Status::default(),
            tunnel_delay: TunnelDelay::Idle,
            delay_last_auto: None,
            session_request: None,
            applied_snapshot: None,
            connect_snapshot: None,
            deferred_snapshot: None,
            apply_candidate: None,
            apply_baseline: None,
            failed_edits: None,
            blocked_auto_apply: None,
            restore_pending: false,
            pending_restore: None,
            restore_reason: None,
            apply_failure: None,
            temporary_rules: Vec::new(),
            temporary_rules_loaded: false,
            temporary_load: None,
            next_temporary_load: 0,
            temporary_retry: true,
            temporary_waiting_status: false,
            temporary_last_load: None,
            temporary_error_reported: false,
            temporary_before_apply: None,
            keep_temporary: None,
            keep_apply: None,
            session_snapshot_checked: false,
            apply_after_choice: false,
            apply_in_flight: false,
            apply_after_leave: false,
            queued_leave_apply: None,
            exit: ExitLookup::None,
            exit_route: None,
            exit_generation: 0,
            exit_revealed: false,
            traffic_history: VecDeque::new(),
            traffic_range: TrafficRange::default(),
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
            rule_screen: RuleScreen::default(),
            settings_screen: SettingsScreen::default(),
            next_process_request: 0,
            expanded: BTreeSet::new(),
            reveal: None,
            outcomes: BTreeMap::new(),
            pings: HashMap::new(),
            operations: Operations::default(),
            add: None,
            remove: None,
            rename: None,
            protection_confirmation: false,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum AboutFolder {
    Config,
    Licenses,
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

    pub(crate) fn pending_reconnect(&self, part: SessionPart) -> bool {
        let Some(session) = &self.session_request else {
            return false;
        };
        let Ok(current) = ConnectRequest::from_config(&self.config) else {
            return false;
        };
        match part {
            SessionPart::Server => session.selection != current.selection,
            SessionPart::Rules => session.rule_set != current.rule_set,
            SessionPart::Dns => session.settings.dns != current.settings.dns,
            SessionPart::Protection => session.settings.kill_switch != current.settings.kill_switch,
        }
    }

    fn apply_request(&self) -> Option<ConnectRequest> {
        let session = self.session_request.as_ref()?;
        let mut request = ConnectRequest::from_config(&self.config).ok()?;
        request.settings.engine = session.settings.engine;
        request.settings.tun = session.settings.tun.clone();
        request.settings.kill_switch = session.settings.kill_switch;
        request.settings.allow_lan = session.settings.allow_lan;
        request.temporary_rules = self.temporary_rules.clone();
        Some(request)
    }

    pub(crate) fn can_change_temporary(&self) -> bool {
        self.helper_available
            && self.config_ready
            && self.temporary_rules_loaded
            && !self.operations.helper
            && !self.restore_pending
            && self.session_request.is_some()
            && matches!(
                self.visible_status().map(|status| &status.state),
                Some(ConnectionState::Connected)
            )
    }

    fn has_pending_apply(&self) -> bool {
        let Some(session) = &self.session_request else {
            return false;
        };
        let Ok(current) = ConnectRequest::from_config(&self.config) else {
            return false;
        };
        session.selection != current.selection
            || session.rule_set != current.rule_set
            || session.settings.dns != current.settings.dns
    }

    fn saving_config(&self) -> bool {
        self.operations.rules || self.operations.rules_edit || self.operations.settings
    }

    pub(crate) fn can_apply(&self) -> bool {
        self.can_change_temporary() && !self.saving_config() && self.has_pending_apply()
    }

    fn start_apply(&mut self) {
        self.operations.helper = true;
        self.apply_in_flight = true;
        self.apply_baseline = self.applied_snapshot.clone();
        self.apply_candidate = Some(AppliedSnapshot::from_config(&self.config));
        self.apply_failure = None;
        self.blocked_auto_apply = None;
        self.operation_error = None;
    }

    pub(crate) fn apply_on_leave(&mut self) -> Option<Job> {
        if self.saving_config() {
            if self.helper_available
                && !self.restore_pending
                && matches!(self.status.state, ConnectionState::Connected)
            {
                self.apply_after_leave = true;
            }
            return None;
        }
        if self
            .blocked_auto_apply
            .as_ref()
            .is_some_and(|blocked| blocked == &AppliedSnapshot::from_config(&self.config))
        {
            return None;
        }
        self.blocked_auto_apply = None;
        if self.can_apply() {
            return self.act(Action::Apply);
        }
        if self.apply_in_flight && self.has_pending_apply() {
            self.apply_after_leave = true;
        }
        None
    }

    fn show_screen(&mut self, screen: Screen) -> Option<Job> {
        let job =
            if self.screen != screen && matches!(self.screen, Screen::Rules | Screen::Settings) {
                self.apply_on_leave()
            } else {
                None
            };
        self.screen = screen;
        job
    }

    pub(crate) fn take_leave_apply(&mut self) -> Option<Job> {
        self.queued_leave_apply.take()
    }

    pub(crate) fn take_restore(&mut self) -> Option<Job> {
        self.pending_restore.take()
    }

    pub(crate) fn can_restore_edits(&self) -> bool {
        self.failed_edits.is_some()
            && self.config_ready
            && !self.restore_pending
            && !self.operations.helper
            && !self.operations.settings
            && !self.operations.rules_edit
    }

    pub(crate) fn take_apply(&mut self) -> Option<Job> {
        if !(self.apply_after_choice || self.apply_after_leave)
            || !self.temporary_rules_loaded
            || self.operations.helper
            || self.saving_config()
            || self.restore_pending
        {
            return None;
        }
        self.apply_after_choice = false;
        self.apply_after_leave = false;
        self.act(Action::Apply)
    }

    pub(crate) fn take_temporary_load(&mut self, now: u64) -> Option<Job> {
        if !self.helper_available
            || !self.status_received
            || !matches!(self.status.state, ConnectionState::Connected)
            || self.temporary_rules_loaded
            || self.temporary_load.is_some()
            || !self.temporary_retry
            || self.operations.helper
            || self
                .temporary_last_load
                .is_some_and(|last| now.saturating_sub(last) < 10)
        {
            return None;
        }
        self.next_temporary_load += 1;
        self.temporary_load = Some(self.next_temporary_load);
        self.temporary_retry = false;
        self.temporary_last_load = Some(now);
        Some(Job::LoadTemporaryRules(self.next_temporary_load))
    }

    pub(crate) fn take_keep_apply(&mut self) -> Option<Job> {
        if !self.can_change_temporary() {
            return None;
        }
        let id = self.keep_apply.take()?;
        self.act(Action::RemoveTemporary(id))
    }

    fn clear_applied_state(&mut self) {
        self.applied_snapshot = None;
        self.connect_snapshot = None;
        self.deferred_snapshot = None;
        self.apply_candidate = None;
        self.apply_baseline = None;
        self.failed_edits = None;
        self.blocked_auto_apply = None;
        self.apply_failure = None;
        self.restore_reason = None;
        self.restore_pending = false;
        self.pending_restore = None;
        self.apply_after_leave = false;
    }

    fn clear_temporary(&mut self) {
        self.temporary_rules.clear();
        self.temporary_rules_loaded = false;
        self.temporary_load = None;
        self.temporary_retry = true;
        self.temporary_waiting_status = false;
        self.temporary_last_load = None;
        self.temporary_error_reported = false;
        self.temporary_before_apply = None;
        self.keep_temporary = None;
        self.keep_apply = None;
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

    /// Starts at most one due subscription on each schedule check.
    pub(crate) fn take_auto_update(&mut self, now: u64) -> Option<Job> {
        if now < self.next_auto_update_check {
            return None;
        }
        self.next_auto_update_check = now.saturating_add(AUTO_UPDATE_CHECK);
        if !self.config_ready
            || !self.config.interface.auto_update_subscriptions
            || self.operations.update_all
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
        let id = self
            .config
            .subscriptions
            .iter()
            .find(|subscription| {
                !self.subscription_busy(&subscription.id)
                    && update_due(
                        subscription,
                        now,
                        self.auto_update_attempts.get(&subscription.id).copied(),
                    )
            })?
            .id
            .clone();
        self.auto_update_attempts.insert(id.clone(), now);
        self.operations.updating.insert(id.clone());
        self.outcomes.remove(&id);
        Some(Job::Update(id))
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

    pub(crate) fn can_ping(&self) -> bool {
        !self.operations.helper
            && (!self.helper_available
                || matches!(
                    self.status.state,
                    ConnectionState::Disconnected | ConnectionState::Failed { .. }
                ))
    }

    /// Reset is allowed only when the running tunnel cannot disagree with the
    /// kill switch value that will be written to the configuration.
    pub(crate) fn can_reset_settings(&self) -> bool {
        self.can_edit_settings()
            && !self.operations.helper
            && !self.operations.kill_switch
            && (!self.helper_available
                || matches!(
                    self.status.state,
                    ConnectionState::Disconnected | ConnectionState::Failed { .. }
                ))
    }

    pub(crate) fn can_full_check(&self) -> bool {
        self.helper_available && self.config_ready
    }

    pub(crate) fn best_ping(&self, subscription: &Subscription) -> Option<Duration> {
        subscription
            .nodes
            .iter()
            .filter_map(
                |node| match self.pings.get(&(subscription.id.clone(), node.id.clone())) {
                    Some(PingResult::Answered(elapsed) | PingResult::Works(elapsed)) => {
                        Some(*elapsed)
                    }
                    _ => None,
                },
            )
            .min()
    }

    fn start_check(&mut self, id: SubscriptionId, node: Option<NodeId>, full: bool) -> Option<Job> {
        if !(if full {
            self.can_full_check()
        } else {
            self.can_ping()
        }) || self.operations.pinging.contains(&id)
            || self.subscription_busy(&id)
        {
            return None;
        }
        let subscription = self
            .config
            .subscriptions
            .iter()
            .find(|subscription| subscription.id == id && !subscription.nodes.is_empty())?;
        if node
            .as_ref()
            .is_some_and(|selected| subscription.node(selected).is_none())
        {
            return None;
        }
        for current in &subscription.nodes {
            if node.as_ref().is_none_or(|selected| selected == &current.id) {
                self.pings
                    .insert((id.clone(), current.id.clone()), PingResult::Pending);
            }
        }
        self.operations.pinging.insert(id.clone());
        Some(match (full, node) {
            (false, None) => Job::Ping(id),
            (false, Some(node)) => Job::PingNode(id, node),
            (true, None) => Job::FullCheck(id),
            (true, Some(node)) => Job::FullCheckNode(id, node),
        })
    }

    pub(crate) fn subscription_busy(&self, id: &SubscriptionId) -> bool {
        self.operations.update_all
            || self.operations.updating.contains(id)
            || (self.operations.removing
                && self.remove.as_ref().is_some_and(|dialog| &dialog.id == id))
    }

    pub(crate) fn can_reorder_subscriptions(&self) -> bool {
        self.config_ready
            && !self.operations.update_all
            && self.operations.updating.is_empty()
            && !self.add.as_ref().is_some_and(|dialog| dialog.busy)
            && !self.operations.removing
            && !self.operations.moving_subscription
    }

    pub(crate) fn text(&self, value: &str) -> String {
        redact(&self.config, value)
    }

    pub(crate) fn selected_rules(&self) -> Option<&RuleSet> {
        let id = self.rule_screen.selected_set.as_ref()?;
        self.config.rule_sets.iter().find(|set| &set.id == id)
    }

    fn visible_rule_ids(&self) -> Vec<RuleId> {
        self.selected_rules()
            .map(|set| {
                visible_rules(set, &self.rule_screen.filter)
                    .into_iter()
                    .map(|(_, rule)| rule.id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn selected_rule_ids(&self) -> Vec<RuleId> {
        self.visible_rule_ids()
            .into_iter()
            .filter(|id| self.rule_screen.selected_rules.contains(id))
            .collect()
    }

    fn select_rule(&mut self, rule: RuleId, additive: bool, range: bool) {
        let visible = self.visible_rule_ids();
        let Some(index) = visible.iter().position(|id| id == &rule) else {
            return;
        };
        let selection = &mut self.rule_screen.selected_rules;
        if range {
            let anchor = self
                .rule_screen
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
            self.rule_screen.selection_anchor = Some(visible[anchor].clone());
        } else if additive {
            if !selection.insert(rule.clone()) {
                selection.remove(&rule);
                self.rule_screen.selection_anchor = visible
                    .iter()
                    .rev()
                    .find(|id| selection.contains(*id))
                    .cloned();
            } else {
                self.rule_screen.selection_anchor = Some(rule);
            }
        } else {
            selection.clear();
            selection.insert(rule.clone());
            self.rule_screen.selection_anchor = Some(rule);
        }
    }

    pub(crate) fn can_edit_rules(&self) -> bool {
        self.config_ready
            && !self.operations.rules_edit
            && !self.operations.rules
            && !self.operations.helper
    }

    pub(crate) fn can_edit_settings(&self) -> bool {
        self.config_ready && !self.operations.settings
    }

    fn start_settings(&mut self, job: Job) -> Option<Job> {
        self.operations.settings = true;
        self.operation_error = None;
        Some(job)
    }

    fn preferred_set(&self) -> Option<RuleSetId> {
        self.config
            .active_rules()
            .or_else(|| self.config.rule_sets.first())
            .map(|set| set.id.clone())
    }

    fn reconcile_selected_set(&mut self) {
        let previous = self.rule_screen.selected_set.clone();
        if self.rule_screen.opened && self.selected_rules().is_none() {
            self.rule_screen.selected_set = self.preferred_set();
        }
        if self.rule_screen.selected_set != previous {
            self.rule_screen.clear_selection();
        } else {
            let existing: BTreeSet<_> = self
                .selected_rules()
                .into_iter()
                .flat_map(|set| set.rules.iter().map(|rule| rule.id.clone()))
                .collect();
            self.rule_screen
                .selected_rules
                .retain(|id| existing.contains(id));
            if self
                .rule_screen
                .selection_anchor
                .as_ref()
                .is_some_and(|id| !self.rule_screen.selected_rules.contains(id))
            {
                self.rule_screen.selection_anchor = None;
            }
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
                if self.settings_screen.opened && !self.settings_screen.dirty {
                    self.settings_screen.sync_dns(&self.config.settings.dns);
                }
                self.expanded
                    .retain(|id| self.config.subscriptions.iter().any(|sub| &sub.id == id));
                if self.reveal.as_ref().is_some_and(|(id, node)| {
                    !self
                        .config
                        .subscriptions
                        .iter()
                        .any(|sub| &sub.id == id && sub.node(node).is_some())
                }) {
                    self.reveal = None;
                }
                self.outcomes
                    .retain(|id, _| self.config.subscriptions.iter().any(|sub| &sub.id == id));
                self.auto_update_attempts
                    .retain(|id, _| self.config.subscriptions.iter().any(|sub| &sub.id == id));
                self.pings.retain(|(id, node), _| {
                    self.config
                        .subscriptions
                        .iter()
                        .any(|sub| &sub.id == id && sub.node(node).is_some())
                });
                self.operations
                    .pinging
                    .retain(|id| self.config.subscriptions.iter().any(|sub| &sub.id == id));
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
                self.session_request = None;
                self.clear_applied_state();
                self.session_snapshot_checked = false;
                self.apply_after_choice = false;
                self.apply_in_flight = false;
                self.queued_leave_apply = None;
                self.traffic_history.clear();
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
                    && let Some(dialog) = &mut self.rule_screen.add
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
                if self.temporary_waiting_status
                    && matches!(status.state, ConnectionState::Connected)
                {
                    self.temporary_retry = true;
                    self.temporary_waiting_status = false;
                }
                if self.helper_available {
                    match status.state {
                        ConnectionState::Disconnected
                        | ConnectionState::Failed { .. }
                        | ConnectionState::FailedProtected { .. } => {
                            self.session_request = None;
                            self.session_snapshot_checked = false;
                            self.apply_after_choice = false;
                            if matches!(status.state, ConnectionState::Disconnected) {
                                self.clear_applied_state();
                            } else {
                                self.applied_snapshot = None;
                                if !self.apply_in_flight {
                                    self.apply_after_leave = false;
                                }
                            }
                            self.clear_temporary();
                        }
                        ConnectionState::Connected
                            if self.session_request.is_none()
                                && !self.session_snapshot_checked
                                && self.config_ready
                                && !self.operations.helper
                                && !self.restore_pending =>
                        {
                            self.session_snapshot_checked = true;
                            if let Ok(mut request) = ConnectRequest::from_config(&self.config)
                                && status.node.as_ref() == Some(&request.selection.node)
                            {
                                if self.temporary_rules_loaded {
                                    request.temporary_rules = self.temporary_rules.clone();
                                }
                                self.session_request = Some(request);
                                self.applied_snapshot =
                                    Some(AppliedSnapshot::from_config(&self.config));
                            }
                        }
                        _ => {}
                    }
                }
                if self.helper_available
                    && matches!(
                        status.state,
                        ConnectionState::Connected | ConnectionState::Reconnecting
                    )
                {
                    self.traffic_history
                        .push_back((status.traffic.down_bps, status.traffic.up_bps));
                    if self.traffic_history.len() > TRAFFIC_HISTORY {
                        self.traffic_history.pop_front();
                    }
                } else {
                    self.traffic_history.clear();
                }
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
            WorkerEvent::TemporaryRules { request, result } => {
                if self.temporary_load != Some(request)
                    || !self.helper_available
                    || matches!(
                        self.status.state,
                        ConnectionState::Disconnected
                            | ConnectionState::Failed { .. }
                            | ConnectionState::FailedProtected { .. }
                    )
                {
                    return;
                }
                self.temporary_load = None;
                match result {
                    Ok(rules) => {
                        if let Some(session) = &mut self.session_request {
                            session.temporary_rules = rules.clone();
                        }
                        self.temporary_rules = rules;
                        self.temporary_rules_loaded = true;
                        self.temporary_error_reported = false;
                        self.operation_error = None;
                    }
                    Err(HelperCommandError::Client(ClientError::Helper(HelperError {
                        code: ErrorCode::Busy,
                        ..
                    }))) => {
                        self.temporary_waiting_status = true;
                        self.temporary_last_load = None;
                    }
                    Err(error) => {
                        self.temporary_retry = true;
                        if !self.temporary_error_reported {
                            self.temporary_error_reported = true;
                            self.helper_result(Err(error));
                        }
                    }
                }
            }
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
                    self.connect_snapshot = Some(snapshot);
                }
            }
            WorkerEvent::Connect(result) => {
                self.connect_in_flight = false;
                let snapshot = self.connect_snapshot.take();
                if self.cancelled_connect {
                    if self.cancel_in_flight {
                        self.deferred_snapshot = snapshot;
                        self.deferred_connect = result.ok();
                    }
                    self.operations.helper = self.cancel_in_flight;
                    return;
                }
                self.operations.helper = false;
                match result {
                    Ok(request) => {
                        self.temporary_rules = request.temporary_rules.clone();
                        self.temporary_rules_loaded = true;
                        self.temporary_load = None;
                        self.session_request = Some(request);
                        self.applied_snapshot = snapshot.or_else(|| {
                            self.config_ready
                                .then(|| AppliedSnapshot::from_config(&self.config))
                        });
                        self.session_snapshot_checked = true;
                        self.operation_error = None;
                    }
                    Err(error) if reported_by_status(&error) => self.operation_error = None,
                    Err(error) => self.helper_result(Err(error)),
                }
            }
            WorkerEvent::Apply(result) => {
                self.operations.helper = false;
                self.apply_in_flight = false;
                let before = self.temporary_before_apply.take();
                let baseline = self.apply_baseline.take();
                let candidate = self.apply_candidate.take();
                if !self.helper_available
                    || matches!(self.status.state, ConnectionState::Disconnected)
                {
                    self.apply_after_leave = false;
                    return;
                }
                match result {
                    Ok(request) => {
                        if matches!(
                            self.status.state,
                            ConnectionState::Failed { .. }
                                | ConnectionState::FailedProtected { .. }
                        ) {
                            self.apply_after_leave = false;
                            return;
                        }
                        self.temporary_rules = request.temporary_rules.clone();
                        self.session_request = Some(request);
                        self.applied_snapshot = candidate;
                        self.failed_edits = None;
                        self.blocked_auto_apply = None;
                        self.apply_failure = None;
                        self.operation_error = None;
                        self.exit_route = None;
                        self.tunnel_delay = TunnelDelay::Idle;
                        self.delay_last_auto = None;
                    }
                    Err(error) => {
                        if let Some(before) = before {
                            self.temporary_rules = before;
                        }
                        self.apply_after_leave = false;
                        self.apply_after_choice = false;
                        let cancelled = matches!(
                            &error,
                            HelperCommandError::Client(ClientError::Helper(HelperError {
                                code: ErrorCode::Cancelled,
                                ..
                            }))
                        );
                        let reason = errors::helper_command(crate::i18n::language(), &error);
                        let changed = baseline
                            .as_ref()
                            .zip(candidate.as_ref())
                            .is_some_and(|(running, edited)| running != edited);
                        self.blocked_auto_apply = candidate;
                        if changed {
                            self.restore_pending = true;
                            self.restore_reason = Some(reason);
                            self.pending_restore = baseline.map(Job::RestoreApplied);
                        } else if cancelled {
                            self.operation_error = None;
                        } else {
                            self.operation_error =
                                Some(self.text(&crate::i18n::apply_failed(&reason)));
                        }
                    }
                }
            }
            WorkerEvent::RestoreApplied(result) => {
                if !self.restore_pending {
                    return;
                }
                self.restore_pending = false;
                let reason = self.restore_reason.take().unwrap_or_default();
                match result {
                    Ok(failed) => {
                        self.failed_edits = Some(failed);
                        self.apply_failure = Some(
                            self.text(&tr!("apply-failed-restored-template", reason = &reason)),
                        );
                        self.operation_error = None;
                        self.settings_screen.dirty = false;
                        if self.settings_screen.opened {
                            self.settings_screen.sync_dns(&self.config.settings.dns);
                        }
                    }
                    Err(error) => {
                        let storage = errors::rule_set(crate::i18n::language(), &error);
                        self.operation_error = Some(self.text(&tr!(
                            "apply-rollback-failed-template",
                            reason = &reason,
                            error = &storage
                        )));
                    }
                }
            }
            WorkerEvent::RestoreEdits(result) => {
                if !self.restore_pending {
                    return;
                }
                self.restore_pending = false;
                match result {
                    Ok(_) => {
                        self.failed_edits = None;
                        self.blocked_auto_apply = None;
                        self.apply_failure = None;
                        self.operation_error = None;
                        self.settings_screen.dirty = false;
                        if self.settings_screen.opened {
                            self.settings_screen.sync_dns(&self.config.settings.dns);
                        }
                    }
                    Err(error) => {
                        self.operation_error =
                            Some(self.text(&errors::rule_set(crate::i18n::language(), &error)));
                    }
                }
            }
            WorkerEvent::Disconnect(result) => {
                let cancelling = std::mem::take(&mut self.cancel_in_flight);
                self.operations.helper = cancelling && self.connect_in_flight;
                if result.is_ok() {
                    self.protection_confirmation = false;
                    self.deferred_connect = None;
                    self.session_request = None;
                    self.clear_temporary();
                    self.clear_applied_state();
                } else if cancelling {
                    self.cancelled_connect = false;
                    if let Some(request) = self.deferred_connect.take() {
                        self.temporary_rules = request.temporary_rules.clone();
                        self.temporary_rules_loaded = true;
                        self.session_request = Some(request);
                        self.applied_snapshot = self.deferred_snapshot.take().or_else(|| {
                            self.config_ready
                                .then(|| AppliedSnapshot::from_config(&self.config))
                        });
                        self.session_snapshot_checked = true;
                    }
                }
                self.helper_result(result);
            }
            WorkerEvent::SelectNode(result) => {
                self.operations.selection = false;
                self.apply_after_choice = result.is_ok()
                    && matches!(
                        self.visible_status().map(|status| &status.state),
                        Some(ConnectionState::Connected)
                    );
                self.operation_error = result
                    .err()
                    .map(|error| self.text(&errors::select_node(crate::i18n::language(), &error)));
            }
            WorkerEvent::SelectRuleSet(result) => {
                self.operations.rules = false;
                self.apply_after_choice = result.is_ok()
                    && matches!(
                        self.visible_status().map(|status| &status.state),
                        Some(ConnectionState::Connected)
                    );
                self.operation_error = result.err().map(|error| {
                    self.text(&errors::select_rule_set(crate::i18n::language(), &error))
                });
            }
            WorkerEvent::CreateRuleSet(result) => {
                self.operations.rules_edit = false;
                match result {
                    Ok(set) => {
                        self.rule_screen.selected_set = Some(set.id);
                        self.rule_screen.name = None;
                    }
                    Err(error) => {
                        self.name_error(errors::rule_set(crate::i18n::language(), &error))
                    }
                }
            }
            WorkerEvent::RenameRuleSet(result) => {
                self.operations.rules_edit = false;
                match result {
                    Ok(()) => self.rule_screen.name = None,
                    Err(error) => {
                        self.name_error(errors::rule_set(crate::i18n::language(), &error))
                    }
                }
            }
            WorkerEvent::DeleteRuleSet(result) => {
                self.rule_screen.delete = None;
                self.finish_rule_edit(result);
            }
            WorkerEvent::SetDefaultTarget(result) => self.finish_rule_edit(result),
            WorkerEvent::Processes { request, result } => {
                let message = result
                    .as_ref()
                    .err()
                    .map(|error| self.text(&errors::process_list(crate::i18n::language(), error)));
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
                        Err(_) => dialog.processes_error = message,
                    }
                }
            }
            #[cfg(windows)]
            WorkerEvent::BrowsedExecutable(path) => {
                if let Some(dialog) = &mut self.rule_screen.add {
                    if !dialog.browsing {
                        return;
                    }
                    dialog.browsing = false;
                    if dialog.kind == RuleInputKind::Process
                        && let Some(path) = path
                    {
                        dialog.process = browsed_process_value(&path, dialog.match_mode);
                        dialog.process_filter = path
                            .file_name()
                            .map_or_else(|| path.to_string_lossy(), |name| name.to_string_lossy())
                            .into_owned();
                        dialog.browsed = Some(path);
                        dialog.selected_process = None;
                        dialog.error = None;
                        dialog.focus_input = true;
                    }
                }
            }
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
                    self.rule_screen.clear_selection();
                }
                self.rule_screen.delete = None;
                self.finish_rule_edit(result);
            }
            WorkerEvent::SetKillSwitch(result) => {
                self.operations.kill_switch = false;
                self.operation_error = result
                    .err()
                    .map(|error| self.text(&errors::store(crate::i18n::language(), &error)));
            }
            WorkerEvent::SetInterfaceScale(result) => self.finish_settings(result),
            WorkerEvent::SetLanguage(result) => self.finish_settings(result),
            #[cfg(windows)]
            WorkerEvent::AutostartLoaded(result) => match result {
                Ok(enabled) => self.settings_screen.autostart = Some(enabled),
                Err(error) => {
                    self.settings_screen.autostart = None;
                    let message = tr!("error-autostart-read", detail = error.to_string());
                    self.operation_error = Some(self.text(&message));
                }
            },
            #[cfg(windows)]
            WorkerEvent::SetAutostart(result) => {
                self.operations.settings = false;
                self.settings_screen.autostart = result.as_ref().ok().copied();
                self.operation_error = result.err().map(|error| {
                    let message = tr!("error-autostart-write", detail = error.to_string());
                    self.text(&message)
                });
            }
            #[cfg(windows)]
            WorkerEvent::SetCloseToTray(result) => self.finish_settings(result),
            WorkerEvent::SetReduceMotion(result) => self.finish_settings(result),
            WorkerEvent::SetConnectOnStart(result) => self.finish_settings(result),
            WorkerEvent::SetAutoReconnect(result) => self.finish_settings(result),
            WorkerEvent::SetAutoUpdateSubscriptions(result) => self.finish_settings(result),
            WorkerEvent::SetCheckUpdates(result) => self.finish_settings(result),
            WorkerEvent::SkipVersion(result) => self.finish_settings(result),
            WorkerEvent::UpdateCheck { checked_at, result } => {
                self.reduce_updates(result, checked_at);
            }
            WorkerEvent::SetDns(result) => {
                if result.is_ok() {
                    self.settings_screen.dirty = false;
                    self.settings_screen.sync_dns(&self.config.settings.dns);
                } else if !self.settings_screen.dirty {
                    self.settings_screen.sync_dns(&self.config.settings.dns);
                }
                self.finish_settings(result);
            }
            WorkerEvent::ResetSettings(result) => {
                if result.is_ok() {
                    self.settings_screen.dirty = false;
                    self.settings_screen.sync_dns(&self.config.settings.dns);
                }
                self.settings_screen.reset_open = false;
                self.finish_settings(result);
            }
            WorkerEvent::SetVerboseLog(result) => self.finish_settings(result),
            #[cfg(windows)]
            WorkerEvent::OpenFolder(result) => {
                self.operations.settings = false;
                self.operation_error = result.err().map(|error| {
                    let message = tr!("error-open-folder", detail = error.to_string());
                    self.text(&message)
                });
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
            WorkerEvent::Ping {
                subscription,
                node,
                result,
            } => {
                if self.operations.pinging.contains(&subscription)
                    && self
                        .config
                        .subscriptions
                        .iter()
                        .any(|sub| sub.id == subscription && sub.node(&node).is_some())
                {
                    let result = match result {
                        Ping::Answered(elapsed) => PingResult::Answered(elapsed),
                        Ping::NoAnswer => PingResult::NoAnswer,
                        Ping::Unsupported => PingResult::Unsupported,
                    };
                    self.pings.insert((subscription, node), result);
                }
            }
            WorkerEvent::PingDone(subscription) => {
                self.operations.pinging.remove(&subscription);
                for ((id, _), result) in &mut self.pings {
                    if id == &subscription && *result == PingResult::Pending {
                        *result = PingResult::NoAnswer;
                    }
                }
            }
            WorkerEvent::FullCheck {
                subscription,
                result,
            } => {
                if !self.operations.pinging.remove(&subscription) {
                    return;
                }
                self.pings
                    .retain(|(id, _), ping| id != &subscription || *ping != PingResult::Pending);
                match result {
                    Ok(results) => {
                        for ProbeResult { node, outcome } in results {
                            if self
                                .config
                                .subscriptions
                                .iter()
                                .any(|sub| sub.id == subscription && sub.node(&node).is_some())
                            {
                                let ping = match outcome {
                                    ProbeOutcome::Works { millis } => {
                                        PingResult::Works(Duration::from_millis(u64::from(millis)))
                                    }
                                    ProbeOutcome::Fails => PingResult::Fails,
                                    ProbeOutcome::Unresolved => PingResult::Unresolved,
                                    ProbeOutcome::Unsupported => PingResult::Unsupported,
                                };
                                self.pings.insert((subscription.clone(), node), ping);
                            }
                        }
                    }
                    Err(error) => {
                        self.operation_error = Some(
                            if matches!(
                                &error,
                                HelperCommandError::Client(ClientError::Helper(HelperError {
                                    code: ErrorCode::Busy,
                                    ..
                                }))
                            ) {
                                tr!("full-check-busy").to_owned()
                            } else {
                                self.text(&errors::helper_command(crate::i18n::language(), &error))
                            },
                        );
                    }
                }
            }
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
                        self.expanded.remove(&id);
                        self.outcomes.remove(&id);
                        self.remove = None;
                    }
                    Err(error) => {
                        let message = self.text(&errors::remove_subscription(
                            crate::i18n::language(),
                            &error,
                        ));
                        if let Some(dialog) = &mut self.remove {
                            dialog.error = Some(message);
                        }
                    }
                }
            }
            WorkerEvent::RenameSubscription(result) => {
                self.operations.renaming = false;
                match result {
                    Ok(()) => self.rename = None,
                    Err(error) => {
                        let message = self.text(&errors::rename_subscription(
                            crate::i18n::language(),
                            &error,
                        ));
                        if let Some(dialog) = &mut self.rename {
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
        self.operation_error = result
            .err()
            .map(|error| self.text(&errors::rule_set(crate::i18n::language(), &error)));
    }

    fn finish_dialog_rule_edit(&mut self, result: Result<(), rosetun_core::RuleSetError>) {
        self.operations.rules_edit = false;
        if self.rule_screen.add.is_some() {
            match result {
                Ok(()) => {
                    self.rule_screen.add = None;
                    self.rule_screen.filter = RuleFilter::default();
                    self.rule_screen.clear_selection();
                }
                Err(error) => {
                    let message = self.text(&errors::rule_set(crate::i18n::language(), &error));
                    if let Some(dialog) = &mut self.rule_screen.add {
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

    fn start_rule_edit(&mut self, job: Job) -> Option<Job> {
        self.operations.rules_edit = true;
        self.operation_error = None;
        Some(job)
    }

    fn finish_settings(&mut self, result: Result<(), rosetun_core::SettingsError>) {
        self.operations.settings = false;
        self.operation_error = result
            .err()
            .map(|error| self.text(&errors::settings(crate::i18n::language(), &error)));
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
        self.operation_error = result
            .err()
            .map(|error| self.text(&errors::helper_command(crate::i18n::language(), &error)));
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
            Action::ShowConnection => return self.show_screen(Screen::Connection),
            Action::OpenTraffic => return self.show_screen(Screen::Traffic),
            Action::SetTrafficRange(range) => self.traffic_range = range,
            #[cfg(windows)]
            Action::WindowMinimized => return self.apply_on_leave(),
            Action::OpenSettings => {
                if !self.settings_screen.opened {
                    self.settings_screen.opened = true;
                    if self.config_ready {
                        self.settings_screen.sync_dns(&self.config.settings.dns);
                    }
                }
                let job = self.show_screen(Screen::Settings);
                #[cfg(windows)]
                {
                    self.queued_leave_apply = job;
                    self.settings_screen.autostart = None;
                    return Some(Job::LoadAutostart);
                }
                #[cfg(not(windows))]
                return job;
            }
            Action::OpenSettingsSection(section) => {
                self.settings_screen.section = section;
            }
            Action::SetInterfaceScale(percent) => {
                if self.can_edit_settings()
                    && self.config.interface.scale_percent != percent
                    && rosetun_core::INTERFACE_SCALES.contains(&percent)
                {
                    return self.start_settings(Job::SetInterfaceScale(percent));
                }
            }
            Action::SetLanguage(language) => {
                if self.can_edit_settings() && self.config.interface.language != language {
                    return self.start_settings(Job::SetLanguage(language));
                }
            }
            Action::SetReduceMotion(enabled) => {
                if self.can_edit_settings() && self.config.interface.reduce_motion != enabled {
                    return self.start_settings(Job::SetReduceMotion(enabled));
                }
            }
            #[cfg(windows)]
            Action::SetAutostart(enabled) => {
                if self.can_edit_settings()
                    && self.settings_screen.autostart.is_some()
                    && self.settings_screen.autostart != Some(enabled)
                {
                    return self.start_settings(Job::SetAutostart(enabled));
                }
            }
            #[cfg(windows)]
            Action::SetCloseToTray(enabled) => {
                if self.can_edit_settings() && self.config.interface.close_to_tray != enabled {
                    return self.start_settings(Job::SetCloseToTray(enabled));
                }
            }
            Action::SetConnectOnStart(enabled) => {
                if self.can_edit_settings() && self.config.interface.connect_on_start != enabled {
                    return self.start_settings(Job::SetConnectOnStart(enabled));
                }
            }
            Action::SetAutoReconnect(enabled) => {
                if self.can_edit_settings() && self.config.settings.auto_reconnect != enabled {
                    return self.start_settings(Job::SetAutoReconnect(enabled));
                }
            }
            Action::SetAutoUpdateSubscriptions(enabled) => {
                if self.can_edit_settings()
                    && self.config.interface.auto_update_subscriptions != enabled
                {
                    return self.start_settings(Job::SetAutoUpdateSubscriptions(enabled));
                }
            }
            Action::SetCheckUpdates(enabled) => {
                if self.can_edit_settings() && self.config.interface.check_updates != enabled {
                    return self.start_settings(Job::SetCheckUpdates(enabled));
                }
            }
            action @ (Action::CheckUpdatesNow | Action::SkipVersion) => {
                return self.act_updates(action);
            }
            Action::SaveDns => {
                if self.can_edit_settings()
                    && self.settings_screen.custom_dns
                    && let Ok(dns) = self.settings_screen.parsed_dns()
                    && dns != self.config.settings.dns
                {
                    return self.start_settings(Job::SetDns(dns));
                }
            }
            Action::SelectCustomDns => {
                if self.can_edit_settings() {
                    self.settings_screen.custom_dns = true;
                }
            }
            Action::SetDnsPreset(preset) => {
                if self.can_edit_settings() {
                    self.settings_screen.custom_dns = false;
                    self.settings_screen.dirty = false;
                    self.settings_screen.sync_dns(&preset.settings());
                    if self.config.settings.dns != preset.settings() {
                        return self.start_settings(Job::SetDns(preset.settings()));
                    }
                }
            }
            Action::RequestResetSettings => {
                if self.can_reset_settings() {
                    self.settings_screen.reset_open = true;
                }
            }
            Action::CancelResetSettings => {
                if !self.operations.settings {
                    self.settings_screen.reset_open = false;
                }
            }
            Action::ConfirmResetSettings => {
                if self.settings_screen.reset_open && self.can_reset_settings() {
                    return self.start_settings(Job::ResetSettings);
                }
            }
            Action::SetVerboseLog(on) => {
                if self.can_edit_settings()
                    && self.config.settings.verbose_log_active(now_unix()) != on
                {
                    return self.start_settings(Job::SetVerboseLog(on));
                }
            }
            #[cfg(windows)]
            Action::OpenFolder(folder) => {
                let path = match folder {
                    AboutFolder::Config => &self.settings_screen.config_folder,
                    AboutFolder::Licenses => &self.settings_screen.licenses_folder,
                };
                if self.can_edit_settings()
                    && let Some(path) = path
                {
                    return self.start_settings(Job::OpenFolder(path.clone()));
                }
            }
            Action::OpenRules => {
                if !self.rule_screen.opened {
                    self.rule_screen.selected_set = self.preferred_set();
                    self.rule_screen.clear_selection();
                }
                self.rule_screen.opened = true;
                return self.show_screen(Screen::Rules);
            }
            Action::OpenActiveRules => {
                let preferred = self.preferred_set();
                if self.rule_screen.selected_set != preferred {
                    self.rule_screen.clear_selection();
                }
                self.rule_screen.selected_set = preferred;
                self.rule_screen.opened = true;
                return self.show_screen(Screen::Rules);
            }
            Action::ChooseRuleSet(id) => {
                if self.config.rule_sets.iter().any(|set| set.id == id) {
                    if self.rule_screen.selected_set.as_ref() != Some(&id) {
                        self.rule_screen.clear_selection();
                    }
                    self.rule_screen.selected_set = Some(id);
                }
            }
            Action::SetRuleTypeFilter(kind) => {
                if self.rule_screen.filter.kind != kind {
                    self.rule_screen.filter.kind = kind;
                    self.rule_screen.clear_selection();
                }
            }
            Action::SetRuleTargetFilter(target) => {
                if self.rule_screen.filter.target != target {
                    self.rule_screen.filter.target = target;
                    self.rule_screen.clear_selection();
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
                    self.rule_screen.selected_rules = visible.iter().cloned().collect();
                    self.rule_screen.selection_anchor = visible.last().cloned();
                }
            }
            Action::ClearRuleSelection => self.rule_screen.clear_selection(),
            Action::OpenCreateSet => {
                if self.can_edit_rules() && self.rule_screen.name.is_none() {
                    self.rule_screen.name = Some(NameDialog {
                        kind: NameDialogKind::Create,
                        name: tr!("basic").to_owned(),
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
            Action::RequestDeleteSelectedRules => {
                if self.can_edit_rules()
                    && self.rule_screen.delete.is_none()
                    && let Some(set) = self.selected_rules()
                {
                    let set_id = set.id.clone();
                    let rules = self.selected_rule_ids();
                    self.rule_screen.delete = match rules.as_slice() {
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
            Action::OpenAddRule => {
                if self.can_edit_rules()
                    && self.rule_screen.add.is_none()
                    && let Some(set) = self.selected_rules()
                {
                    self.rule_screen.add = Some(AddRuleDialog::new(set.id.clone()));
                    return self.load_processes();
                }
            }
            Action::OpenEditRule(id) => {
                if self.can_edit_rules()
                    && self.rule_screen.add.is_none()
                    && let Some(set) = self.selected_rules()
                    && let Some(rule) = set
                        .rules
                        .iter()
                        .find(|rule| rule.id == id && crate::rules::editable(&rule.matcher))
                    && let Some(dialog) = AddRuleDialog::for_rule(set.id.clone(), rule)
                {
                    self.rule_screen.add = Some(dialog);
                    if self.rule_screen.add.as_ref().unwrap().kind == RuleInputKind::Process {
                        return self.load_processes();
                    }
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
                    && dialog.editing.is_none()
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
            #[cfg(windows)]
            Action::BrowseExecutable => {
                if let Some(dialog) = &mut self.rule_screen.add
                    && dialog.kind == RuleInputKind::Process
                    && !dialog.busy
                    && !dialog.browsing
                {
                    dialog.browsing = true;
                    return Some(Job::BrowseExecutable);
                }
            }
            Action::SubmitAddRule => {
                if self.can_edit_rules()
                    && let Some(dialog) = &self.rule_screen.add
                    && !dialog.busy
                    && self.rule_screen.selected_set.as_ref() == Some(&dialog.set)
                {
                    let matchers: Option<Vec<_>> = match dialog.kind {
                        RuleInputKind::Domain => {
                            if let Some(original) = dialog.unchanged_domain() {
                                Some(vec![RuleMatcher::Domain(original)])
                            } else {
                                let parsed = rosetun_core::parse_domain_lines(
                                    &dialog.domains,
                                    dialog.subdomains,
                                );
                                (parsed.errors.is_empty() && !parsed.domains.is_empty()).then(|| {
                                    parsed.domains.into_iter().map(RuleMatcher::Domain).collect()
                                })
                            }
                        }
                        RuleInputKind::Process => rosetun_core::parse_process_input(&dialog.process)
                            .ok()
                            .map(|process| vec![RuleMatcher::Process(process)]),
                    };
                    if let Some(mut matchers) = matchers {
                        if dialog.temporary_only && dialog.editing.is_none() {
                            let target = dialog.target;
                            return self.act(Action::AddTemporary(matchers, target));
                        }
                        let job = if let Some(id) = &dialog.editing {
                            if matchers.len() != 1 {
                                return None;
                            }
                            let current = self
                                .selected_rules()
                                .and_then(|set| set.rules.iter().find(|rule| &rule.id == id))?;
                            let matcher = matchers.pop().unwrap();
                            if current.matcher == matcher && current.target == dialog.target {
                                self.rule_screen.add = None;
                                return None;
                            }
                            Job::UpdateRule(dialog.set.clone(), id.clone(), matcher, dialog.target)
                        } else if dialog.kind == RuleInputKind::Domain {
                            Job::AddRules(dialog.set.clone(), matchers, dialog.target)
                        } else {
                            Job::AddRule(dialog.set.clone(), matchers.pop().unwrap(), dialog.target)
                        };
                        if let Some(dialog) = &mut self.rule_screen.add {
                            dialog.busy = true;
                            dialog.error = None;
                        }
                        return self.start_rule_edit(job);
                    }
                }
            }
            Action::AddTemporary(matchers, target) => {
                if self.can_change_temporary()
                    && self.can_edit_rules()
                    && let Some(dialog) = &self.rule_screen.add
                    && dialog.temporary_only
                    && dialog.editing.is_none()
                    && !dialog.busy
                    && self.config.active_rule_set.as_ref() == Some(&dialog.set)
                    && self.rule_screen.selected_set.as_ref() == Some(&dialog.set)
                    && let Some(set) = self.selected_rules()
                {
                    let existing: Vec<_> = self
                        .temporary_rules
                        .iter()
                        .chain(set.rules.iter())
                        .cloned()
                        .collect();
                    let added = rosetun_core::temporary_rules(&existing, matchers, target).added;
                    if added.is_empty() {
                        let message = self.text(&errors::rule_set(
                            crate::i18n::language(),
                            &rosetun_core::RuleSetError::DuplicateRule,
                        ));
                        if let Some(dialog) = &mut self.rule_screen.add {
                            dialog.error = Some(message);
                        }
                        return None;
                    }
                    let before = std::mem::take(&mut self.temporary_rules);
                    self.temporary_rules = added.into_iter().chain(before.iter().cloned()).collect();
                    if let Some(request) = self.apply_request() {
                        self.temporary_before_apply = Some(before);
                        self.start_apply();
                        self.rule_screen.add = None;
                        self.rule_screen.filter = RuleFilter::default();
                        self.rule_screen.clear_selection();
                        return Some(Job::Apply(Box::new(request)));
                    }
                    self.temporary_rules = before;
                }
            }
            Action::RemoveTemporary(id) => {
                if self.can_change_temporary()
                    && !self.operations.rules_edit
                    && let Some(index) = self.temporary_rules.iter().position(|rule| rule.id == id)
                {
                    let before = self.temporary_rules.clone();
                    self.temporary_rules.remove(index);
                    if let Some(request) = self.apply_request() {
                        self.temporary_before_apply = Some(before);
                        self.start_apply();
                        return Some(Job::Apply(Box::new(request)));
                    }
                    self.temporary_rules = before;
                }
            }
            Action::KeepTemporary(id) => {
                if self.can_change_temporary()
                    && self.can_edit_rules()
                    && self.keep_apply.is_none()
                    && self.config.active_rule_set == self.rule_screen.selected_set
                    && let Some(set) = self.selected_rules()
                    && let Some(rule) = self.temporary_rules.iter().find(|rule| rule.id == id)
                {
                    let job = Job::AddRules(set.id.clone(), vec![rule.matcher.clone()], rule.target);
                    self.keep_temporary = Some(id);
                    return self.start_rule_edit(job);
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
            Action::DropRules(rules, slot) => {
                if self.can_edit_rules()
                    && !self.rule_screen.filter.is_active()
                    && rules.len() >= 2
                    && rules.len() == self.rule_screen.selected_rules.len()
                    && rules.iter().cloned().collect::<BTreeSet<_>>()
                        == self.rule_screen.selected_rules
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
                    && !self.rule_screen.filter.is_active()
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
                                .all(|rule| self.rule_screen.selected_rules.contains(&rule.id))
                        } else {
                            set.rules[..rules.len()]
                                .iter()
                                .all(|rule| self.rule_screen.selected_rules.contains(&rule.id))
                        };
                        if !already_there {
                            return self.start_rule_edit(Job::MoveRules(set_id, rules, index));
                        }
                    }
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
            Action::Apply => {
                if self.can_apply() && let Some(request) = self.apply_request() {
                    self.start_apply();
                    return Some(Job::Apply(Box::new(request)));
                }
            }
            Action::RestoreMyEdits => {
                if self.can_restore_edits() {
                    self.restore_pending = true;
                    return self.failed_edits.clone().map(Job::RestoreEdits);
                }
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
            Action::RevealServer => {
                self.reveal = None;
                if let Some((subscription, node)) = self.config.active_node() {
                    let id = subscription.id.clone();
                    self.expanded.insert(id.clone());
                    self.reveal = Some((id, node.id.clone()));
                } else if let Some(subscription) = self.config.subscriptions.first() {
                    self.expanded.insert(subscription.id.clone());
                }
            }
            Action::RevealDone => self.reveal = None,
            Action::ToggleExitReveal => {
                if matches!(self.exit, ExitLookup::Known { .. }) {
                    self.exit_revealed = !self.exit_revealed;
                }
            }
            Action::MeasureDelay => {
                if self.status_received
                    && matches!(self.visible_status().map(|status| &status.state), Some(ConnectionState::Connected))
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
            Action::ToggleExpanded(id) => {
                if !self.expanded.remove(&id) {
                    self.expanded.insert(id);
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
                        Err(error) => dialog.error = Some(AddFromUrlError::Url(error)),
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
            Action::Ping(id) => return self.start_check(id, None, false),
            Action::PingNode(id, node) => return self.start_check(id, Some(node), false),
            Action::FullCheck(id) => return self.start_check(id, None, true),
            Action::FullCheckNode(id, node) => return self.start_check(id, Some(node), true),
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
            Action::RequestRename(id) => {
                if self.config_ready
                    && self.rename.is_none()
                    && self.remove.is_none()
                    && !self.operations.renaming
                    && let Some(subscription) =
                        self.config.subscriptions.iter().find(|sub| sub.id == id)
                {
                    let original = self.text(&subscription.name);
                    self.rename = Some(RenameDialog {
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
                    self.rename = None;
                }
            }
            Action::SubmitRename => {
                if let Some(dialog) = &mut self.rename
                    && !self.operations.renaming
                {
                    let name = dialog.name.trim();
                    if !name.is_empty() {
                        if name == dialog.original.trim() {
                            self.rename = None;
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
            Action::DismissOperationError => self.operation_error = None,
            Action::DismissApplyFailure => self.apply_failure = None,
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
