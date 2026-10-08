use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rosetun_config::{
    AppConfig, ConnectionState, DnsSettings, DomainMatch, LanguageSetting, NodeId, ProcessMatch,
    Rule, RuleId, RuleMatcher, RuleSet, RuleSetId, RuleTarget, RuleTemplate, Status, Subscription,
    SubscriptionId,
};
use rosetun_core::{
    AddFromUrlError, AddOptions, DnsPreset, Ping, UpdateReport, UpdateSubscriptionError,
};
use rosetun_ipc::{ClientError, ConnectRequest, ErrorCode, HelperError, ProbeOutcome, ProbeResult};

use crate::actions::{self, PrimaryAction};
use crate::display;
use crate::errors;
use crate::reorder::drop_target;
use crate::rules::{ProcessGroup, ProcessMatchMode, RuleFilter, TypeFilter, group_processes};
use crate::strings::{fill, t};
use crate::worker::{ConfigWorkerError, HelperCommandError, WorkerEvent};

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
const TRAFFIC_HISTORY: usize = 60;

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
    Rules,
    Settings,
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
    pub(crate) name: Option<NameDialog>,
    pub(crate) delete: Option<DeleteDialog>,
    pub(crate) add: Option<AddRuleDialog>,
    opened: bool,
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
    status_received: bool,
    pub(crate) config_generation: u64,
    pub(crate) config_error: Option<ConfigWorkerError>,
    pub(crate) status: Status,
    pub(crate) tunnel_delay: TunnelDelay,
    delay_last_auto: Option<u64>,
    session_request: Option<ConnectRequest>,
    session_snapshot_checked: bool,
    apply_after_choice: bool,
    pub(crate) exit: ExitLookup,
    exit_route: Option<ExitRoute>,
    exit_generation: u64,
    pub(crate) exit_revealed: bool,
    /// Rates of the last minute, one sample per status; newest last.
    pub(crate) traffic_history: VecDeque<(u64, u64)>,
    pub(crate) helper_available: bool,
    pub(crate) helper_version: Option<String>,
    pub(crate) helper_error: Option<ClientError>,
    pub(crate) operation_error: Option<String>,
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
            status_received: false,
            config_generation: 0,
            config_error: None,
            status: Status::default(),
            tunnel_delay: TunnelDelay::Idle,
            delay_last_auto: None,
            session_request: None,
            session_snapshot_checked: false,
            apply_after_choice: false,
            exit: ExitLookup::None,
            exit_route: None,
            exit_generation: 0,
            exit_revealed: false,
            traffic_history: VecDeque::new(),
            helper_available: false,
            helper_version: None,
            helper_error: None,
            operation_error: None,
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
    OpenSettings,
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
    OpenCreateSet,
    OpenRenameSet,
    CancelSetName,
    SubmitSetName,
    RequestDeleteSet,
    RequestDeleteRule(RuleId),
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
    SetRuleTarget(RuleId, RuleTarget),
    SetRuleEnabled(RuleId, bool),
    DropRule(RuleId, usize),
    MoveRuleToTop(RuleId),
    Primary,
    Apply,
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
    DismissConfigError,
    DismissOutcome(SubscriptionId),
}

pub(crate) enum Job {
    Connect,
    Apply(Box<ConnectRequest>),
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
    RemoveRule(RuleSetId, RuleId),
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

/// The helper already put this failure into the status the card shows.
fn reported_by_status(error: &HelperCommandError) -> bool {
    matches!(
        error,
        HelperCommandError::Client(ClientError::Helper(HelperError {
            code: ErrorCode::EngineFailed | ErrorCode::RoutingFailed | ErrorCode::UnsupportedRules,
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
        Some(request)
    }

    pub(crate) fn can_apply(&self) -> bool {
        if !self.helper_available
            || !self.config_ready
            || self.operations.helper
            || !matches!(
                self.visible_status().map(|status| &status.state),
                Some(ConnectionState::Connected)
            )
        {
            return false;
        }
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

    pub(crate) fn take_apply(&mut self) -> Option<Job> {
        if !std::mem::take(&mut self.apply_after_choice) || !self.can_apply() {
            return None;
        }
        self.act(Action::Apply)
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
                self.tunnel_delay = TunnelDelay::Idle;
                self.delay_last_auto = None;
            }
            WorkerEvent::HelperUnavailable(error) => {
                self.helper_available = false;
                self.tunnel_delay = TunnelDelay::Idle;
                self.delay_last_auto = None;
                self.session_request = None;
                self.session_snapshot_checked = false;
                self.apply_after_choice = false;
                self.traffic_history.clear();
                self.helper_error = Some(error);
                self.protection_confirmation = false;
            }
            WorkerEvent::Status(status) => {
                if !self.helper_available
                    || !matches!(status.state, ConnectionState::Connected)
                    || status.since_unix != self.status.since_unix
                {
                    self.tunnel_delay = TunnelDelay::Idle;
                    self.delay_last_auto = None;
                }
                self.status_received = true;
                if self.helper_available {
                    match status.state {
                        ConnectionState::Disconnected
                        | ConnectionState::Failed { .. }
                        | ConnectionState::FailedProtected { .. } => {
                            self.session_request = None;
                            self.session_snapshot_checked = false;
                            self.apply_after_choice = false;
                        }
                        ConnectionState::Connected
                            if self.session_request.is_none()
                                && !self.session_snapshot_checked
                                && self.config_ready
                                && !self.operations.helper =>
                        {
                            self.session_snapshot_checked = true;
                            if let Ok(request) = ConnectRequest::from_config(&self.config)
                                && status.node.as_ref() == Some(&request.selection.node)
                            {
                                self.session_request = Some(request);
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
            WorkerEvent::Connect(result) => {
                self.operations.helper = false;
                match result {
                    Ok(request) => {
                        self.session_request = Some(request);
                        self.session_snapshot_checked = true;
                        self.operation_error = None;
                    }
                    Err(error) if reported_by_status(&error) => self.operation_error = None,
                    Err(error) => self.helper_result(Err(error)),
                }
            }
            WorkerEvent::Apply(result) => {
                self.operations.helper = false;
                match result {
                    Ok(request) => {
                        self.session_request = Some(request);
                        self.operation_error = None;
                        self.exit_route = None;
                        self.tunnel_delay = TunnelDelay::Idle;
                        self.delay_last_auto = None;
                    }
                    Err(error) => {
                        let reason = errors::helper_command(t(), &error);
                        self.operation_error = Some(self.text(&t().apply_failed(&reason)));
                    }
                }
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
                self.apply_after_choice = result.is_ok()
                    && matches!(
                        self.visible_status().map(|status| &status.state),
                        Some(ConnectionState::Connected)
                    );
                self.operation_error = result
                    .err()
                    .map(|error| self.text(&errors::select_node(t(), &error)));
            }
            WorkerEvent::SelectRuleSet(result) => {
                self.operations.rules = false;
                self.apply_after_choice = result.is_ok()
                    && matches!(
                        self.visible_status().map(|status| &status.state),
                        Some(ConnectionState::Connected)
                    );
                self.operation_error = result
                    .err()
                    .map(|error| self.text(&errors::select_rule_set(t(), &error)));
            }
            WorkerEvent::CreateRuleSet(result) => {
                self.operations.rules_edit = false;
                match result {
                    Ok(set) => {
                        self.rule_screen.selected_set = Some(set.id);
                        self.rule_screen.name = None;
                    }
                    Err(error) => self.name_error(errors::rule_set(t(), &error)),
                }
            }
            WorkerEvent::RenameRuleSet(result) => {
                self.operations.rules_edit = false;
                match result {
                    Ok(()) => self.rule_screen.name = None,
                    Err(error) => self.name_error(errors::rule_set(t(), &error)),
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
                    .map(|error| self.text(&errors::process_list(t(), error)));
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
            WorkerEvent::AddRules(result) => self.finish_dialog_rule_edit(result.map(|_| ())),
            WorkerEvent::UpdateRule(result) => self.finish_dialog_rule_edit(result),
            WorkerEvent::SetRuleTarget(result) => self.finish_rule_edit(result),
            WorkerEvent::SetRuleEnabled(result) => self.finish_rule_edit(result),
            WorkerEvent::MoveRule(result) => self.finish_rule_edit(result),
            WorkerEvent::RemoveRule(result) => {
                self.rule_screen.delete = None;
                self.finish_rule_edit(result);
            }
            WorkerEvent::SetKillSwitch(result) => {
                self.operations.kill_switch = false;
                self.operation_error = result
                    .err()
                    .map(|error| self.text(&errors::store(t(), &error)));
            }
            WorkerEvent::SetInterfaceScale(result) => self.finish_settings(result),
            WorkerEvent::SetLanguage(result) => self.finish_settings(result),
            #[cfg(windows)]
            WorkerEvent::AutostartLoaded(result) => match result {
                Ok(enabled) => self.settings_screen.autostart = Some(enabled),
                Err(error) => {
                    self.settings_screen.autostart = None;
                    let message =
                        fill(t().errors.autostart_read, &[("detail", &error.to_string())]);
                    self.operation_error = Some(self.text(&message));
                }
            },
            #[cfg(windows)]
            WorkerEvent::SetAutostart(result) => {
                self.operations.settings = false;
                self.settings_screen.autostart = result.as_ref().ok().copied();
                self.operation_error = result.err().map(|error| {
                    let message = fill(
                        t().errors.autostart_write,
                        &[("detail", &error.to_string())],
                    );
                    self.text(&message)
                });
            }
            #[cfg(windows)]
            WorkerEvent::SetCloseToTray(result) => self.finish_settings(result),
            WorkerEvent::SetReduceMotion(result) => self.finish_settings(result),
            WorkerEvent::SetConnectOnStart(result) => self.finish_settings(result),
            WorkerEvent::SetAutoReconnect(result) => self.finish_settings(result),
            WorkerEvent::SetAutoUpdateSubscriptions(result) => self.finish_settings(result),
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
                    let message = fill(t().errors.open_folder, &[("detail", &error.to_string())]);
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
                                t().full_check_busy.to_owned()
                            } else {
                                self.text(&errors::helper_command(t(), &error))
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
                        self.operation_error = Some(self.text(&errors::store(t(), &error)));
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
                        let message = self.text(&errors::remove_subscription(t(), &error));
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
                        let message = self.text(&errors::rename_subscription(t(), &error));
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
                self.operation_error = result
                    .err()
                    .map(|error| self.text(&errors::move_subscription(t(), &error)));
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
            .map(|error| self.text(&errors::rule_set(t(), &error)));
    }

    fn finish_dialog_rule_edit(&mut self, result: Result<(), rosetun_core::RuleSetError>) {
        self.operations.rules_edit = false;
        if self.rule_screen.add.is_some() {
            match result {
                Ok(()) => {
                    self.rule_screen.add = None;
                    self.rule_screen.filter = RuleFilter::default();
                }
                Err(error) => {
                    let message = self.text(&errors::rule_set(t(), &error));
                    if let Some(dialog) = &mut self.rule_screen.add {
                        dialog.busy = false;
                        dialog.error = Some(message);
                    }
                }
            }
        } else {
            self.operation_error = result
                .err()
                .map(|error| self.text(&errors::rule_set(t(), &error)));
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
            .map(|error| self.text(&errors::settings(t(), &error)));
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
            .map(|error| self.text(&errors::helper_command(t(), &error)));
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
            Action::OpenSettings => {
                if !self.settings_screen.opened {
                    self.settings_screen.opened = true;
                    if self.config_ready {
                        self.settings_screen.sync_dns(&self.config.settings.dns);
                    }
                }
                self.screen = Screen::Settings;
                #[cfg(windows)]
                {
                    self.settings_screen.autostart = None;
                    return Some(Job::LoadAutostart);
                }
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
            Action::SetRuleTargetFilter(target) => self.rule_screen.filter.target = target,
            Action::OpenCreateSet => {
                if self.can_edit_rules() && self.rule_screen.name.is_none() {
                    self.rule_screen.name = Some(NameDialog {
                        kind: NameDialogKind::Create,
                        name: t().basic.to_owned(),
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
            Action::Apply => {
                if self.can_apply() && let Some(request) = self.apply_request() {
                    self.operations.helper = true;
                    self.operation_error = None;
                    return Some(Job::Apply(Box::new(request)));
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
        return t().connect;
    }
    if state.operations.helper || state.status.state.is_transitional() {
        match state.status.state {
            ConnectionState::Reconnecting if state.operations.helper => t().working,
            ConnectionState::Reconnecting => t().disconnect,
            ConnectionState::Connected | ConnectionState::FailedProtected { .. }
                if state.operations.helper =>
            {
                t().working
            }
            _ => t().connecting_action,
        }
    } else if state.primary_action() == PrimaryAction::Disabled {
        t().connect
    } else {
        state.primary_action().label()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rosetun_config::{
        DomainMatch, Node, NodeId, Outbound, Rule, RuleMatcher, Selection, VlessParams,
    };
    use rosetun_core::{FetchError, ParseError, RemoveSubscriptionError, RuleSetError, StoreError};
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

    fn state_with_subscriptions() -> State {
        State {
            config_ready: true,
            config: AppConfig {
                subscriptions: ["1", "2", "3"].map(subscription).to_vec(),
                ..AppConfig::default()
            },
            ..State::default()
        }
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

    fn state_for_auto_connect() -> State {
        let mut provider = subscription("1");
        provider.nodes.push(Node {
            id: NodeId::new("node"),
            name: "Test".into(),
            server: "127.0.0.1".into(),
            port: 443,
            outbound: Outbound::Vless(VlessParams {
                uuid: "00000000-0000-0000-0000-000000000000".into(),
                flow: None,
            }),
            stream: Default::default(),
            raw: None,
        });
        let mut config = AppConfig::default();
        config.subscriptions.push(provider);
        config.active = Some(Selection {
            subscription: SubscriptionId::new("1"),
            node: NodeId::new("node"),
        });
        config.interface.connect_on_start = true;
        State {
            config,
            config_ready: true,
            helper_available: true,
            ..State::default()
        }
    }

    #[test]
    fn reveal_server_opens_the_selected_subscription_and_clears_after_scroll() {
        let mut state = state_for_auto_connect();
        let id = SubscriptionId::new("1");
        let node = NodeId::new("node");
        assert!(state.act(Action::RevealServer).is_none());
        assert!(state.expanded.contains(&id));
        assert_eq!(state.reveal, Some((id, node)));
        assert!(state.act(Action::RevealDone).is_none());
        assert_eq!(state.reveal, None);
    }

    #[test]
    fn reveal_server_clears_a_node_removed_by_a_config_update() {
        let mut state = state_for_auto_connect();
        state.act(Action::RevealServer);
        state.reduce(WorkerEvent::Config {
            generation: 1,
            config: AppConfig::default(),
        });
        assert_eq!(state.reveal, None);
    }

    #[test]
    fn reveal_server_without_selection_opens_the_first_subscription() {
        let mut state = state_with_subscriptions();
        assert!(state.act(Action::RevealServer).is_none());
        assert_eq!(state.expanded.len(), 1);
        assert!(state.expanded.contains(&SubscriptionId::new("1")));
        assert_eq!(state.reveal, None);
    }

    #[test]
    fn subscription_drops_resolve_gaps_and_reject_no_op_or_missing_ids() {
        for (id, slot, to_index) in [("3", 0, 0), ("1", 3, 2), ("2", 3, 2)] {
            let mut state = state_with_subscriptions();
            assert!(matches!(
                state.act(Action::DropSubscription(SubscriptionId::new(id), slot)),
                Some(Job::MoveSubscription(moved, to))
                    if moved == SubscriptionId::new(id) && to == to_index
            ));
            assert!(state.operations.moving_subscription);
            state.reduce(WorkerEvent::MoveSubscription(Ok(())));
            assert!(!state.operations.moving_subscription);
        }

        let mut state = state_with_subscriptions();
        let id = SubscriptionId::new("2");
        assert!(state.act(Action::DropSubscription(id.clone(), 1)).is_none());
        assert!(state.act(Action::DropSubscription(id.clone(), 2)).is_none());
        assert!(state.act(Action::DropSubscription(id, 4)).is_none());
        assert!(
            state
                .act(Action::DropSubscription(SubscriptionId::new("missing"), 0))
                .is_none()
        );
        assert!(!state.operations.moving_subscription);
    }

    #[test]
    fn subscription_drops_wait_for_other_subscription_operations() {
        let mut state = state_with_subscriptions();
        let drop = || Action::DropSubscription(SubscriptionId::new("2"), 0);
        state.config_ready = false;
        assert!(state.act(drop()).is_none());
        state.config_ready = true;
        state.operations.updating.insert(SubscriptionId::new("3"));
        assert!(state.act(drop()).is_none());
        state.operations.updating.clear();
        state.operations.update_all = true;
        assert!(state.act(drop()).is_none());
        state.operations.update_all = false;
        state.add = Some(AddDialog {
            busy: true,
            ..AddDialog::default()
        });
        assert!(state.act(drop()).is_none());
        state.add = None;
        state.operations.removing = true;
        assert!(state.act(drop()).is_none());
        state.operations.removing = false;
        assert!(matches!(
            state.act(drop()),
            Some(Job::MoveSubscription(_, 0))
        ));
        assert!(state.act(drop()).is_none());
    }

    #[test]
    fn subscription_move_completion_clears_busy_and_reports_errors() {
        let mut state = state_with_subscriptions();
        assert!(
            state
                .act(Action::DropSubscription(SubscriptionId::new("2"), 0))
                .is_some()
        );
        state.reduce(WorkerEvent::MoveSubscription(Err(
            rosetun_core::MoveSubscriptionError::NotFound,
        )));
        assert!(!state.operations.moving_subscription);
        assert_eq!(
            state.operation_error.as_deref(),
            Some("subscription does not exist")
        );
        assert!(
            state
                .act(Action::DropSubscription(SubscriptionId::new("2"), 0))
                .is_some()
        );
        assert!(state.operation_error.is_none());
        state.reduce(WorkerEvent::MoveSubscription(Ok(())));
        assert!(!state.operations.moving_subscription);
        assert!(state.operation_error.is_none());
    }

    #[test]
    fn update_due_uses_default_and_clamped_provider_intervals() {
        let mut sub = subscription("1");
        let now = 200 * 60 * 60;
        assert!(update_due(&sub, now, None));
        sub.updated_at_unix = Some(now - 11 * 60 * 60);
        assert!(!update_due(&sub, now, None));
        sub.updated_at_unix = Some(now - 12 * 60 * 60);
        assert!(update_due(&sub, now, None));

        sub.update_interval_hours = Some(1);
        sub.updated_at_unix = Some(now - 2 * 60 * 60);
        assert!(update_due(&sub, now, None));
        sub.update_interval_hours = Some(0);
        sub.updated_at_unix = Some(now - 60 * 60);
        assert!(update_due(&sub, now, None));
        sub.update_interval_hours = Some(1000);
        sub.updated_at_unix = Some(now - 167 * 60 * 60);
        assert!(!update_due(&sub, now, None));
        sub.updated_at_unix = Some(now - 168 * 60 * 60);
        assert!(update_due(&sub, now, None));
        assert!(!update_due(&sub, now, Some(now - 10 * 60)));
        assert!(update_due(&sub, now, Some(now - 2 * 60 * 60)));
    }

    #[test]
    fn shared_auto_update_interval_requires_matching_subscriptions() {
        assert_eq!(shared_auto_update_hours(&[]), None);
        let mut subscriptions = vec![subscription("1"), subscription("2")];
        assert_eq!(shared_auto_update_hours(&subscriptions), Some(12));
        subscriptions[0].update_interval_hours = Some(0);
        assert_eq!(shared_auto_update_hours(&subscriptions[..1]), Some(1));
        subscriptions[0].update_interval_hours = Some(500);
        assert_eq!(shared_auto_update_hours(&subscriptions[..1]), Some(168));
        subscriptions[0].update_interval_hours = Some(12);
        subscriptions[1].update_interval_hours = Some(24);
        assert_eq!(shared_auto_update_hours(&subscriptions), None);
    }

    #[test]
    fn renaming_subscription_validates_and_tracks_the_result() {
        let mut state = state_with_subscriptions();
        let id = SubscriptionId::new("1");
        state.config.subscriptions[0].name = "🇳🇱 Provider".to_owned();
        state.act(Action::RequestRename(id.clone()));
        let dialog = state.rename.as_ref().unwrap();
        assert_eq!(dialog.name, "[NL] Provider");
        assert_eq!(dialog.original, dialog.name);
        assert!(dialog.focus);
        assert!(state.act(Action::RequestRename(id.clone())).is_none());
        assert_eq!(state.rename.as_ref().unwrap().name, "[NL] Provider");

        state.rename.as_mut().unwrap().name = "  [NL] Provider  ".to_owned();
        assert!(state.act(Action::SubmitRename).is_none());
        assert!(state.rename.is_none());
        state.act(Action::RequestRename(id.clone()));
        state.rename.as_mut().unwrap().name = "   ".to_owned();
        assert!(state.act(Action::SubmitRename).is_none());
        assert!(state.rename.is_some());

        state.rename.as_mut().unwrap().name = "  New name  ".to_owned();
        assert!(matches!(
            state.act(Action::SubmitRename),
            Some(Job::RenameSubscription(job_id, name)) if job_id == id && name == "New name"
        ));
        assert!(state.operations.renaming);
        assert!(state.act(Action::SubmitRename).is_none());
        state.act(Action::CancelRename);
        assert!(state.rename.is_some());
        state.reduce(WorkerEvent::RenameSubscription(Err(
            rosetun_core::RenameSubscriptionError::EmptyName,
        )));
        assert!(!state.operations.renaming);
        assert_eq!(
            state.rename.as_ref().unwrap().error.as_deref(),
            Some(t().errors.subscription_name_empty)
        );
        assert!(state.act(Action::SubmitRename).is_some());
        state.reduce(WorkerEvent::RenameSubscription(Ok(())));
        assert!(state.rename.is_none());
        assert!(!state.operations.renaming);
    }

    #[test]
    fn auto_update_checks_once_per_minute_and_starts_one_due_subscription() {
        let mut state = state_with_subscriptions();
        let now = 200_000;
        assert!(
            matches!(state.take_auto_update(now), Some(Job::Update(id)) if id == SubscriptionId::new("1"))
        );
        assert!(state.take_auto_update(now).is_none());
        state.reduce(WorkerEvent::Update {
            id: SubscriptionId::new("1"),
            result: Err(UpdateSubscriptionError::NotFound),
        });
        assert!(
            matches!(state.take_auto_update(now + AUTO_UPDATE_CHECK), Some(Job::Update(id)) if id == SubscriptionId::new("2"))
        );
        assert!(
            !state
                .operations
                .updating
                .contains(&SubscriptionId::new("1"))
        );
        assert!(
            state
                .operations
                .updating
                .contains(&SubscriptionId::new("2"))
        );
    }

    #[test]
    fn auto_update_waits_for_config_and_update_all() {
        let mut state = state_with_subscriptions();
        state.config_ready = false;
        assert!(state.take_auto_update(1_000).is_none());
        state.config_ready = true;
        state.operations.update_all = true;
        assert!(state.take_auto_update(1_060).is_none());
        state.operations.update_all = false;
        assert!(matches!(
            state.take_auto_update(1_120),
            Some(Job::Update(_))
        ));
    }

    #[test]
    fn primary_label_matches_reconnecting_action_and_busy_state() {
        let mut state = State {
            helper_available: true,
            ..State::default()
        };
        state.status.state = ConnectionState::Reconnecting;
        assert_eq!(state.primary_action(), PrimaryAction::Disconnect);
        assert_eq!(primary_label(&state), t().disconnect);

        state.operations.helper = true;
        assert_eq!(state.primary_action(), PrimaryAction::Disabled);
        assert_eq!(primary_label(&state), t().working);

        state.operations.helper = false;
        state.status.state = ConnectionState::Connecting;
        assert_eq!(primary_label(&state), t().connecting_action);
    }

    #[test]
    fn auto_update_respects_setting_and_connection_transitions() {
        let mut state = state_with_subscriptions();
        state.config.interface.auto_update_subscriptions = false;
        assert!(state.take_auto_update(1_000).is_none());
        state.config.interface.auto_update_subscriptions = true;
        state.status.state = ConnectionState::Connecting;
        assert!(state.take_auto_update(1_060).is_none());
        state.status.state = ConnectionState::Reconnecting;
        assert!(state.take_auto_update(1_120).is_none());
        state.status.state = ConnectionState::FailedProtected {
            reason: "failure".into(),
        };
        assert!(state.take_auto_update(1_180).is_none());
        state.status.state = ConnectionState::Connected;
        assert!(matches!(
            state.take_auto_update(1_240),
            Some(Job::Update(_))
        ));
    }

    #[test]
    fn auto_connect_waits_for_config_helper_and_first_status_then_runs_once() {
        let mut state = state_for_auto_connect();
        assert!(state.take_auto_connect().is_none());
        assert!(state.auto_connect_pending);
        state.config_ready = false;
        state.reduce(WorkerEvent::Status(Status::default()));
        assert!(state.take_auto_connect().is_none());
        state.config_ready = true;
        state.helper_available = false;
        assert!(state.take_auto_connect().is_none());
        state.helper_available = true;
        state.operation_error = Some("previous error".into());
        assert!(matches!(state.take_auto_connect(), Some(Job::Connect)));
        assert!(!state.auto_connect_pending);
        assert!(state.operations.helper);
        assert!(state.operation_error.is_none());
        assert!(state.take_auto_update(1_000).is_none());
        assert!(state.take_auto_connect().is_none());
    }

    #[test]
    fn auto_connect_does_not_run_if_already_connected_or_disabled_or_no_server() {
        let mut connected = state_for_auto_connect();
        connected.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connected,
            ..Status::default()
        }));
        assert!(connected.take_auto_connect().is_none());
        assert!(!connected.auto_connect_pending);

        let mut disabled = state_for_auto_connect();
        disabled.config.interface.connect_on_start = false;
        disabled.reduce(WorkerEvent::Status(Status::default()));
        assert!(disabled.take_auto_connect().is_none());
        assert!(!disabled.auto_connect_pending);

        let mut no_server = state_for_auto_connect();
        no_server.config.active = None;
        no_server.reduce(WorkerEvent::Status(Status::default()));
        assert!(no_server.take_auto_connect().is_none());
        assert!(!no_server.auto_connect_pending);
    }

    fn exit_info(ip: &str) -> rosetun_core::ExitInfo {
        rosetun_core::ExitInfo {
            ip: ip.parse().unwrap(),
            country: Some("NL".into()),
        }
    }

    #[test]
    fn exit_lookup_waits_for_status_and_runs_once_per_route() {
        let mut state = State::default();
        assert!(state.take_exit_lookup().is_none());
        assert_eq!(state.exit, ExitLookup::None);
        state.reduce(WorkerEvent::HelperAvailable {
            version: "test".into(),
        });
        assert!(state.take_exit_lookup().is_none());

        state.reduce(WorkerEvent::Status(Status::default()));
        assert!(matches!(
            state.take_exit_lookup(),
            Some(Job::LookupExit {
                generation: 1,
                route: ExitRoute::Direct
            })
        ));
        assert_eq!(state.exit, ExitLookup::Pending(ExitRoute::Direct));
        assert!(state.take_exit_lookup().is_none());

        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connecting,
            ..Status::default()
        }));
        assert!(state.take_exit_lookup().is_none());
        assert_eq!(state.exit, ExitLookup::None);
        assert!(!state.exit_revealed);

        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connected,
            ..Status::default()
        }));
        assert!(matches!(
            state.take_exit_lookup(),
            Some(Job::LookupExit {
                generation: 2,
                route: ExitRoute::Tunnel
            })
        ));
        assert_eq!(state.exit, ExitLookup::Pending(ExitRoute::Tunnel));
        assert!(state.take_exit_lookup().is_none());

        for connection in [
            ConnectionState::Reconnecting,
            ConnectionState::FailedProtected {
                reason: "failure".into(),
            },
        ] {
            state.reduce(WorkerEvent::Status(Status {
                state: connection,
                ..Status::default()
            }));
            assert!(state.take_exit_lookup().is_none());
            assert_eq!(state.exit, ExitLookup::None);
        }
        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Failed {
                reason: "failure".into(),
            },
            ..Status::default()
        }));
        assert!(matches!(
            state.take_exit_lookup(),
            Some(Job::LookupExit {
                generation: 3,
                route: ExitRoute::Direct
            })
        ));
    }

    #[test]
    fn exit_lookup_uses_direct_route_when_helper_is_unavailable() {
        let mut state = State::default();
        state.reduce(WorkerEvent::HelperUnavailable(ClientError::Closed));
        assert!(matches!(
            state.take_exit_lookup(),
            Some(Job::LookupExit {
                generation: 1,
                route: ExitRoute::Direct
            })
        ));
        assert!(state.take_exit_lookup().is_none());

        state.reduce(WorkerEvent::HelperAvailable {
            version: "test".into(),
        });
        assert!(state.take_exit_lookup().is_none());
        assert_eq!(state.exit, ExitLookup::None);
        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connected,
            ..Status::default()
        }));
        assert!(matches!(
            state.take_exit_lookup(),
            Some(Job::LookupExit {
                generation: 2,
                route: ExitRoute::Tunnel
            })
        ));
    }

    #[test]
    fn exit_lookup_discards_old_replies_and_hides_new_addresses() {
        let mut state = State::default();
        state.reduce(WorkerEvent::HelperAvailable {
            version: "test".into(),
        });
        state.reduce(WorkerEvent::Status(Status::default()));
        assert!(state.take_exit_lookup().is_some());
        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connected,
            ..Status::default()
        }));
        assert!(state.take_exit_lookup().is_some());
        state.reduce(WorkerEvent::Exit {
            generation: 1,
            route: ExitRoute::Direct,
            result: Ok(exit_info("203.0.113.1")),
        });
        assert_eq!(state.exit, ExitLookup::Pending(ExitRoute::Tunnel));

        state.reduce(WorkerEvent::Exit {
            generation: 2,
            route: ExitRoute::Tunnel,
            result: Ok(exit_info("203.0.113.2")),
        });
        assert!(matches!(state.exit, ExitLookup::Known { .. }));
        assert!(!state.exit_revealed);
        state.act(Action::ToggleExitReveal);
        assert!(state.exit_revealed);
        state.act(Action::ToggleExitReveal);
        assert!(!state.exit_revealed);
        state.act(Action::ToggleExitReveal);

        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Reconnecting,
            ..Status::default()
        }));
        assert!(state.take_exit_lookup().is_none());
        assert_eq!(state.exit, ExitLookup::None);
        assert!(!state.exit_revealed);
        state.reduce(WorkerEvent::Exit {
            generation: 2,
            route: ExitRoute::Tunnel,
            result: Ok(exit_info("203.0.113.2")),
        });
        assert_eq!(state.exit, ExitLookup::None);
        state.act(Action::ToggleExitReveal);
        assert!(!state.exit_revealed);

        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connected,
            ..Status::default()
        }));
        assert!(matches!(
            state.take_exit_lookup(),
            Some(Job::LookupExit {
                generation: 3,
                route: ExitRoute::Tunnel
            })
        ));
        state.reduce(WorkerEvent::Exit {
            generation: 3,
            route: ExitRoute::Tunnel,
            result: Ok(exit_info("203.0.113.3")),
        });
        assert!(matches!(
            &state.exit,
            ExitLookup::Known { info, .. } if info.ip == "203.0.113.3".parse::<std::net::IpAddr>().unwrap()
        ));
        assert!(!state.exit_revealed);
    }

    #[test]
    fn exit_lookup_failure_does_not_retry_until_route_changes() {
        let mut state = State::default();
        state.reduce(WorkerEvent::HelperUnavailable(ClientError::Closed));
        assert!(state.take_exit_lookup().is_some());
        state.reduce(WorkerEvent::Exit {
            generation: 1,
            route: ExitRoute::Direct,
            result: Err(rosetun_core::ExitInfoError::Parse),
        });
        assert_eq!(state.exit, ExitLookup::Failed(ExitRoute::Direct));
        assert!(state.take_exit_lookup().is_none());
    }

    #[test]
    fn ping_starts_only_with_tunnel_down_and_marks_nodes_pending() {
        let mut state = state_for_auto_connect();
        let id = SubscriptionId::new("1");
        let node = NodeId::new("node");
        state.status.state = ConnectionState::Connected;
        assert!(state.act(Action::Ping(id.clone())).is_none());
        state.status.state = ConnectionState::Disconnected;
        state.operations.helper = true;
        assert!(state.act(Action::Ping(id.clone())).is_none());
        state.operations.helper = false;
        assert!(
            matches!(state.act(Action::Ping(id.clone())), Some(Job::Ping(found)) if found == id)
        );
        assert_eq!(state.pings[&(id.clone(), node)], PingResult::Pending);
        assert!(state.operations.pinging.contains(&id));
        assert!(state.act(Action::Ping(id.clone())).is_none());
        state.reduce(WorkerEvent::PingDone(id.clone()));
        assert!(!state.operations.pinging.contains(&id));
    }

    #[test]
    fn ping_results_finish_missing_answers_and_prune_removed_nodes() {
        let mut state = state_for_auto_connect();
        let mut second = state.config.subscriptions[0].nodes[0].clone();
        second.id = NodeId::new("second");
        state.config.subscriptions[0].nodes.push(second);
        let id = SubscriptionId::new("1");
        let first = NodeId::new("node");
        let second = NodeId::new("second");
        assert!(matches!(
            state.act(Action::Ping(id.clone())),
            Some(Job::Ping(_))
        ));
        state.reduce(WorkerEvent::Ping {
            subscription: id.clone(),
            node: first.clone(),
            result: Ping::Answered(Duration::from_millis(118)),
        });
        state.reduce(WorkerEvent::PingDone(id.clone()));
        assert_eq!(
            state.pings[&(id.clone(), first.clone())],
            PingResult::Answered(Duration::from_millis(118))
        );
        assert_eq!(
            state.pings[&(id.clone(), second.clone())],
            PingResult::NoAnswer
        );
        assert_eq!(
            state.best_ping(&state.config.subscriptions[0]),
            Some(Duration::from_millis(118))
        );

        state.config.subscriptions[0]
            .nodes
            .retain(|node| node.id != first);
        state.reduce(WorkerEvent::Config {
            generation: 1,
            config: state.config.clone(),
        });
        assert!(!state.pings.contains_key(&(id, first)));
        assert!(state.best_ping(&state.config.subscriptions[0]).is_none());
    }

    #[test]
    fn single_node_ping_preserves_other_results_and_rejects_busy_checks() {
        let mut state = state_for_auto_connect();
        let id = SubscriptionId::new("1");
        let first = NodeId::new("node");
        let mut other = state.config.subscriptions[0].nodes[0].clone();
        other.id = NodeId::new("second");
        state.config.subscriptions[0].nodes.push(other);
        let second = NodeId::new("second");
        let previous = PingResult::Works(Duration::from_millis(44));
        state.pings.insert((id.clone(), second.clone()), previous);

        assert!(matches!(
            state.act(Action::PingNode(id.clone(), first.clone())),
            Some(Job::PingNode(subscription, node)) if subscription == id && node == first
        ));
        assert_eq!(
            state.pings[&(id.clone(), first.clone())],
            PingResult::Pending
        );
        assert_eq!(state.pings[&(id.clone(), second.clone())], previous);
        assert!(state.act(Action::Ping(id.clone())).is_none());
        assert!(
            state
                .act(Action::FullCheckNode(id.clone(), second.clone()))
                .is_none()
        );

        state.reduce(WorkerEvent::PingDone(id.clone()));
        assert_eq!(
            state.pings[&(id.clone(), first.clone())],
            PingResult::NoAnswer
        );
        assert_eq!(state.pings[&(id.clone(), second.clone())], previous);
        assert!(matches!(
            state.act(Action::PingNode(id.clone(), first.clone())),
            Some(Job::PingNode(_, _))
        ));
        state.reduce(WorkerEvent::Ping {
            subscription: id.clone(),
            node: first.clone(),
            result: Ping::Answered(Duration::from_millis(90)),
        });
        state.reduce(WorkerEvent::PingDone(id.clone()));
        assert_eq!(
            state.pings[&(id.clone(), first)],
            PingResult::Answered(Duration::from_millis(90))
        );
        assert_eq!(state.pings[&(id, second)], previous);
    }

    #[test]
    fn single_node_check_rejects_missing_nodes_and_connected_quick_checks() {
        let mut state = state_for_auto_connect();
        let id = SubscriptionId::new("1");
        let node = NodeId::new("node");
        let missing = NodeId::new("missing");
        assert!(
            state
                .act(Action::PingNode(id.clone(), missing.clone()))
                .is_none()
        );
        assert!(
            state
                .act(Action::FullCheckNode(id.clone(), missing))
                .is_none()
        );
        assert!(state.pings.is_empty());
        assert!(!state.operations.pinging.contains(&id));

        state.status.state = ConnectionState::Connected;
        assert!(
            state
                .act(Action::PingNode(id.clone(), node.clone()))
                .is_none()
        );
        assert!(matches!(
            state.act(Action::FullCheckNode(id.clone(), node.clone())),
            Some(Job::FullCheckNode(subscription, selected)) if subscription == id && selected == node
        ));
    }

    #[test]
    fn single_node_full_check_preserves_other_results_and_ignores_removed_node() {
        let mut state = state_for_auto_connect();
        let id = SubscriptionId::new("1");
        let first = NodeId::new("node");
        let mut other = state.config.subscriptions[0].nodes[0].clone();
        other.id = NodeId::new("second");
        state.config.subscriptions[0].nodes.push(other);
        let second = NodeId::new("second");
        let previous = PingResult::Answered(Duration::from_millis(55));
        state.pings.insert((id.clone(), second.clone()), previous);

        assert!(matches!(
            state.act(Action::FullCheckNode(id.clone(), first.clone())),
            Some(Job::FullCheckNode(_, _))
        ));
        assert_eq!(
            state.pings[&(id.clone(), first.clone())],
            PingResult::Pending
        );
        assert_eq!(state.pings[&(id.clone(), second.clone())], previous);
        state.reduce(WorkerEvent::FullCheck {
            subscription: id.clone(),
            result: Err(HelperCommandError::Client(ClientError::Closed)),
        });
        assert!(!state.pings.contains_key(&(id.clone(), first.clone())));
        assert_eq!(state.pings[&(id.clone(), second.clone())], previous);
        assert!(!state.operations.pinging.contains(&id));

        state.act(Action::FullCheckNode(id.clone(), first.clone()));
        state.reduce(WorkerEvent::FullCheck {
            subscription: id.clone(),
            result: Ok(vec![ProbeResult {
                node: first.clone(),
                outcome: ProbeOutcome::Works { millis: 76 },
            }]),
        });
        assert_eq!(
            state.pings[&(id.clone(), first.clone())],
            PingResult::Works(Duration::from_millis(76))
        );
        assert_eq!(state.pings[&(id.clone(), second.clone())], previous);

        state.act(Action::FullCheckNode(id.clone(), first.clone()));
        state.config.subscriptions[0]
            .nodes
            .retain(|node| node.id != first);
        state.reduce(WorkerEvent::Config {
            generation: 1,
            config: state.config.clone(),
        });
        state.reduce(WorkerEvent::FullCheck {
            subscription: id.clone(),
            result: Ok(vec![ProbeResult {
                node: first.clone(),
                outcome: ProbeOutcome::Fails,
            }]),
        });
        assert!(!state.pings.contains_key(&(id.clone(), first)));
        assert_eq!(state.pings[&(id.clone(), second)], previous);
        assert!(!state.operations.pinging.contains(&id));
    }

    #[test]
    fn full_check_runs_while_connected_and_maps_outcomes() {
        let mut state = state_for_auto_connect();
        let id = SubscriptionId::new("1");
        let mut second = state.config.subscriptions[0].nodes[0].clone();
        second.id = NodeId::new("second");
        state.config.subscriptions[0].nodes.push(second);
        state.status.state = ConnectionState::Connected;
        assert!(!state.can_ping());
        assert!(state.can_full_check());
        assert!(matches!(
            state.act(Action::FullCheck(id.clone())),
            Some(Job::FullCheck(_))
        ));
        assert_eq!(
            state.pings[&(id.clone(), NodeId::new("node"))],
            PingResult::Pending
        );
        assert_eq!(
            state.pings[&(id.clone(), NodeId::new("second"))],
            PingResult::Pending
        );
        assert!(state.act(Action::FullCheck(id.clone())).is_none());
        state.reduce(WorkerEvent::FullCheck {
            subscription: id.clone(),
            result: Ok(vec![
                ProbeResult {
                    node: NodeId::new("node"),
                    outcome: ProbeOutcome::Works { millis: 85 },
                },
                ProbeResult {
                    node: NodeId::new("second"),
                    outcome: ProbeOutcome::Fails,
                },
                ProbeResult {
                    node: NodeId::new("removed"),
                    outcome: ProbeOutcome::Unresolved,
                },
            ]),
        });
        assert_eq!(
            state.pings[&(id.clone(), NodeId::new("node"))],
            PingResult::Works(Duration::from_millis(85))
        );
        assert_eq!(
            state.pings[&(id.clone(), NodeId::new("second"))],
            PingResult::Fails
        );
        assert!(
            !state
                .pings
                .contains_key(&(id.clone(), NodeId::new("removed")))
        );
        assert!(!state.operations.pinging.contains(&id));
    }

    #[test]
    fn full_check_clears_missing_results_and_pending_on_error() {
        let mut state = state_for_auto_connect();
        let id = SubscriptionId::new("1");
        let mut second = state.config.subscriptions[0].nodes[0].clone();
        second.id = NodeId::new("second");
        state.config.subscriptions[0].nodes.push(second);
        state.act(Action::FullCheck(id.clone()));
        state.reduce(WorkerEvent::FullCheck {
            subscription: id.clone(),
            result: Ok(vec![ProbeResult {
                node: NodeId::new("node"),
                outcome: ProbeOutcome::Unresolved,
            }]),
        });
        assert_eq!(
            state.pings[&(id.clone(), NodeId::new("node"))],
            PingResult::Unresolved
        );
        assert!(
            !state
                .pings
                .contains_key(&(id.clone(), NodeId::new("second")))
        );
        state.act(Action::FullCheck(id.clone()));
        state.reduce(WorkerEvent::FullCheck {
            subscription: id.clone(),
            result: Err(HelperCommandError::Client(ClientError::Helper(
                HelperError::new(ErrorCode::Busy, ""),
            ))),
        });
        assert!(!state.pings.contains_key(&(id.clone(), NodeId::new("node"))));
        assert!(!state.operations.pinging.contains(&id));
        assert_eq!(state.operation_error.as_deref(), Some(t().full_check_busy));

        state.act(Action::FullCheck(id.clone()));
        state.reduce(WorkerEvent::FullCheck {
            subscription: id.clone(),
            result: Err(HelperCommandError::Client(ClientError::Closed)),
        });
        assert_eq!(
            state.operation_error.as_deref(),
            Some(
                errors::helper_command(t(), &HelperCommandError::Client(ClientError::Closed))
                    .as_str()
            )
        );
        assert!(!state.pings.contains_key(&(id, NodeId::new("second"))));
    }

    #[test]
    fn best_ping_ignores_unanswered_nodes_and_chooses_smallest_answer() {
        let mut state = state_for_auto_connect();
        let id = SubscriptionId::new("1");
        let mut second = state.config.subscriptions[0].nodes[0].clone();
        second.id = NodeId::new("second");
        state.config.subscriptions[0].nodes.push(second);
        assert!(state.best_ping(&state.config.subscriptions[0]).is_none());
        state.pings.insert(
            (id.clone(), NodeId::new("node")),
            PingResult::Answered(Duration::from_millis(118)),
        );
        state.pings.insert(
            (id.clone(), NodeId::new("second")),
            PingResult::Works(Duration::from_millis(40)),
        );
        assert_eq!(
            state.best_ping(&state.config.subscriptions[0]),
            Some(Duration::from_millis(40))
        );
        state
            .pings
            .insert((id, NodeId::new("second")), PingResult::Fails);
        assert_eq!(
            state.best_ping(&state.config.subscriptions[0]),
            Some(Duration::from_millis(118))
        );
    }

    #[test]
    fn tunnel_delay_starts_after_three_seconds_once_per_session() {
        let mut state = state_for_auto_connect();
        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connected,
            since_unix: Some(1_000),
            ..Status::default()
        }));
        assert!(state.take_tunnel_delay(1_002).is_none());
        assert!(matches!(
            state.take_tunnel_delay(1_003),
            Some(Job::TunnelDelay)
        ));
        assert_eq!(state.tunnel_delay, TunnelDelay::Measuring);
        assert!(state.take_tunnel_delay(1_004).is_none());
        state.reduce(WorkerEvent::TunnelDelay(Ok(ProbeOutcome::Works {
            millis: 85,
        })));
        assert_eq!(
            state.tunnel_delay,
            TunnelDelay::Done(ProbeOutcome::Works { millis: 85 })
        );
        assert!(state.take_tunnel_delay(1_100).is_none());

        state.reduce(WorkerEvent::Status(Status::default()));
        assert_eq!(state.tunnel_delay, TunnelDelay::Idle);
        assert!(state.take_tunnel_delay(1_200).is_none());
        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connected,
            since_unix: Some(1_200),
            ..Status::default()
        }));
        assert!(state.take_tunnel_delay(1_202).is_none());
        assert!(matches!(
            state.take_tunnel_delay(1_203),
            Some(Job::TunnelDelay)
        ));
    }

    #[test]
    fn tunnel_delay_retries_busy_auto_measurements_after_ten_seconds() {
        let mut state = state_for_auto_connect();
        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connected,
            since_unix: Some(1_000),
            ..Status::default()
        }));
        assert!(matches!(
            state.take_tunnel_delay(1_003),
            Some(Job::TunnelDelay)
        ));
        state.reduce(WorkerEvent::TunnelDelay(Err(HelperCommandError::Client(
            ClientError::Helper(HelperError::new(ErrorCode::Busy, "")),
        ))));
        assert_eq!(state.tunnel_delay, TunnelDelay::Idle);
        assert!(state.take_tunnel_delay(1_012).is_none());
        assert!(matches!(
            state.take_tunnel_delay(1_013),
            Some(Job::TunnelDelay)
        ));
        state.reduce(WorkerEvent::TunnelDelay(Err(HelperCommandError::Client(
            ClientError::Helper(HelperError::new(ErrorCode::Busy, "")),
        ))));
        assert!(state.take_tunnel_delay(1_022).is_none());
        assert!(matches!(
            state.take_tunnel_delay(1_023),
            Some(Job::TunnelDelay)
        ));
    }

    #[test]
    fn tunnel_delay_manual_refresh_and_stale_completion() {
        let mut state = state_for_auto_connect();
        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connected,
            since_unix: Some(1_000),
            ..Status::default()
        }));
        assert!(matches!(
            state.act(Action::MeasureDelay),
            Some(Job::TunnelDelay)
        ));
        assert!(state.act(Action::MeasureDelay).is_none());
        state.reduce(WorkerEvent::TunnelDelay(Err(HelperCommandError::Client(
            ClientError::Helper(HelperError::new(ErrorCode::Busy, "")),
        ))));
        assert_eq!(state.tunnel_delay, TunnelDelay::Idle);
        assert!(state.operation_error.is_none());
        assert!(matches!(
            state.take_tunnel_delay(1_003),
            Some(Job::TunnelDelay)
        ));
        assert!(state.act(Action::MeasureDelay).is_none());
        state.reduce(WorkerEvent::TunnelDelay(Err(HelperCommandError::Client(
            ClientError::Closed,
        ))));
        assert_eq!(state.tunnel_delay, TunnelDelay::Done(ProbeOutcome::Fails));
        assert!(matches!(
            state.act(Action::MeasureDelay),
            Some(Job::TunnelDelay)
        ));
        state.reduce(WorkerEvent::Status(Status::default()));
        assert_eq!(state.tunnel_delay, TunnelDelay::Idle);
        assert!(state.act(Action::MeasureDelay).is_none());
        state.reduce(WorkerEvent::TunnelDelay(Ok(ProbeOutcome::Works {
            millis: 25,
        })));
        assert_eq!(state.tunnel_delay, TunnelDelay::Idle);
    }

    #[test]
    fn traffic_history_tracks_a_minute_and_clears_when_tunnel_or_helper_stops() {
        let mut state = State {
            helper_available: true,
            ..State::default()
        };
        for down in 0..=TRAFFIC_HISTORY as u64 {
            let mut status = Status {
                state: ConnectionState::Connected,
                ..Status::default()
            };
            status.traffic.down_bps = down;
            status.traffic.up_bps = down + 1;
            state.reduce(WorkerEvent::Status(status));
        }
        assert_eq!(state.traffic_history.len(), TRAFFIC_HISTORY);
        assert_eq!(state.traffic_history.front(), Some(&(1, 2)));
        assert_eq!(state.traffic_history.back(), Some(&(60, 61)));

        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Reconnecting,
            ..Status::default()
        }));
        assert_eq!(state.traffic_history.len(), TRAFFIC_HISTORY);
        state.reduce(WorkerEvent::Status(Status::default()));
        assert!(state.traffic_history.is_empty());

        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connected,
            ..Status::default()
        }));
        assert_eq!(state.traffic_history.len(), 1);
        state.reduce(WorkerEvent::HelperUnavailable(ClientError::Closed));
        assert!(state.traffic_history.is_empty());
        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connected,
            ..Status::default()
        }));
        assert!(state.traffic_history.is_empty());
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

    fn connected_state_for_apply() -> State {
        let mut state = state_for_auto_connect();
        state.config.rule_sets.push(rule_set("1"));
        state.config.active_rule_set = Some(RuleSetId::new("1"));
        let request = ConnectRequest::from_config(&state.config).unwrap();
        state.reduce(WorkerEvent::Connect(Ok(request)));
        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connected,
            node: Some(NodeId::new("node")),
            since_unix: Some(now_unix().saturating_sub(30)),
            ..Status::default()
        }));
        state
    }

    #[test]
    fn successful_connect_has_no_pending_changes_until_dns_or_protection_changes() {
        let mut state = state_for_auto_connect();
        let request = ConnectRequest::from_config(&state.config).unwrap();
        state.reduce(WorkerEvent::Connect(Ok(request.clone())));
        assert_eq!(state.session_request, Some(request));
        for part in [
            SessionPart::Server,
            SessionPart::Rules,
            SessionPart::Dns,
            SessionPart::Protection,
        ] {
            assert!(!state.pending_reconnect(part));
        }

        state.config.settings.dns = DnsPreset::Google.settings();
        assert!(state.pending_reconnect(SessionPart::Dns));
        assert!(!state.pending_reconnect(SessionPart::Rules));
        assert!(!state.pending_reconnect(SessionPart::Protection));

        state.config.settings.kill_switch = !state.config.settings.kill_switch;
        assert!(state.pending_reconnect(SessionPart::Protection));
        assert!(state.pending_reconnect(SessionPart::Dns));
        assert!(!state.pending_reconnect(SessionPart::Rules));

        state.config.active = None;
        for part in [
            SessionPart::Server,
            SessionPart::Rules,
            SessionPart::Dns,
            SessionPart::Protection,
        ] {
            assert!(!state.pending_reconnect(part));
        }
    }

    #[test]
    fn selecting_a_server_applies_once_with_the_running_protection() {
        let mut state = connected_state_for_apply();
        let mut other = state.config.subscriptions[0].nodes[0].clone();
        other.id = NodeId::new("other");
        state.config.subscriptions[0].nodes.push(other);
        let selection = Selection {
            subscription: SubscriptionId::new("1"),
            node: NodeId::new("other"),
        };
        let original = state.session_request.clone().unwrap();
        state.config.settings.kill_switch = !original.settings.kill_switch;
        state.config.settings.allow_lan = !original.settings.allow_lan;

        assert!(matches!(
            state.act(Action::SelectNode(
                selection.subscription.clone(),
                selection.node.clone()
            )),
            Some(Job::SelectNode(_, _))
        ));
        state.config.active = Some(selection.clone());
        state.reduce(WorkerEvent::SelectNode(Ok("Other".into())));
        assert!(state.pending_reconnect(SessionPart::Server));
        let Some(Job::Apply(request)) = state.take_apply() else {
            panic!("server choice must apply");
        };
        assert_eq!(request.selection, selection);
        assert_eq!(request.settings.kill_switch, original.settings.kill_switch);
        assert_eq!(request.settings.allow_lan, original.settings.allow_lan);
        assert!(state.operations.helper);
        assert!(
            state
                .act(Action::SelectNode(
                    SubscriptionId::new("1"),
                    NodeId::new("node")
                ))
                .is_none()
        );
        assert!(state.take_apply().is_none());
    }

    #[test]
    fn server_choice_during_reconnect_does_not_apply() {
        let mut state = connected_state_for_apply();
        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Reconnecting,
            ..Status::default()
        }));
        let mut other = state.config.subscriptions[0].nodes[0].clone();
        other.id = NodeId::new("other");
        state.config.subscriptions[0].nodes.push(other);
        state.config.active.as_mut().unwrap().node = NodeId::new("other");
        state.reduce(WorkerEvent::SelectNode(Ok("Other".into())));
        assert!(state.pending_reconnect(SessionPart::Server));
        assert!(!state.can_apply());
        assert!(state.take_apply().is_none());
    }

    #[test]
    fn choosing_rule_set_applies_but_editing_a_rule_waits_for_apply() {
        let mut state = connected_state_for_apply();
        state.config.rule_sets.push(rule_set("2"));
        assert!(matches!(
            state.act(Action::SelectRuleSet(Some(RuleSetId::new("2")))),
            Some(Job::SelectRuleSet(_))
        ));
        state.config.active_rule_set = Some(RuleSetId::new("2"));
        state.reduce(WorkerEvent::SelectRuleSet(Ok(())));
        let Some(Job::Apply(request)) = state.take_apply() else {
            panic!("rule-set choice must apply");
        };
        state.reduce(WorkerEvent::Apply(Ok(*request)));

        state.config.rule_sets[1].rules[0].target = RuleTarget::Direct;
        assert!(state.pending_reconnect(SessionPart::Rules));
        assert!(state.take_apply().is_none());
        assert!(matches!(state.act(Action::Apply), Some(Job::Apply(_))));
        assert!(state.act(Action::Apply).is_none());
    }

    #[test]
    fn selecting_the_same_server_consumes_auto_apply_without_a_job() {
        let mut state = connected_state_for_apply();
        state.reduce(WorkerEvent::SelectNode(Ok("Test".into())));
        assert!(state.take_apply().is_none());
        assert!(!state.apply_after_choice);
    }

    #[test]
    fn protection_only_cannot_apply() {
        let mut state = connected_state_for_apply();
        state.config.settings.kill_switch = !state.config.settings.kill_switch;
        assert!(state.pending_reconnect(SessionPart::Protection));
        assert!(!state.can_apply());
        assert!(state.act(Action::Apply).is_none());
    }

    #[test]
    fn applying_changes_refreshes_the_session_exit_and_delay() {
        let mut state = connected_state_for_apply();
        let mut other = state.config.subscriptions[0].nodes[0].clone();
        other.id = NodeId::new("other");
        state.config.subscriptions[0].nodes.push(other);
        state.config.active.as_mut().unwrap().node = NodeId::new("other");
        state.config.rule_sets[0].rules[0].target = RuleTarget::Direct;
        state.config.settings.dns = DnsPreset::Google.settings();
        assert!(state.pending_reconnect(SessionPart::Server));
        assert!(state.pending_reconnect(SessionPart::Rules));
        assert!(state.pending_reconnect(SessionPart::Dns));
        assert!(matches!(
            state.take_exit_lookup(),
            Some(Job::LookupExit { .. })
        ));
        state.exit = ExitLookup::Failed(ExitRoute::Tunnel);
        state.tunnel_delay = TunnelDelay::Done(ProbeOutcome::Fails);
        state.delay_last_auto = Some(now_unix());
        let Some(Job::Apply(request)) = state.act(Action::Apply) else {
            panic!("DNS change must apply");
        };
        state.reduce(WorkerEvent::Apply(Ok(*request.clone())));
        assert_eq!(state.session_request.as_ref(), Some(request.as_ref()));
        assert!(!state.pending_reconnect(SessionPart::Server));
        assert!(!state.pending_reconnect(SessionPart::Rules));
        assert!(!state.pending_reconnect(SessionPart::Dns));
        assert!(matches!(
            state.take_exit_lookup(),
            Some(Job::LookupExit {
                route: ExitRoute::Tunnel,
                ..
            })
        ));
        assert_eq!(state.tunnel_delay, TunnelDelay::Idle);
        assert!(state.delay_last_auto.is_none());
        assert!(!state.operations.helper);
    }

    #[test]
    fn failed_apply_preserves_session_and_shows_error() {
        let mut state = connected_state_for_apply();
        let original = state.session_request.clone();
        state.config.settings.dns = DnsPreset::Google.settings();
        assert!(matches!(state.act(Action::Apply), Some(Job::Apply(_))));
        state.reduce(WorkerEvent::Apply(Err(HelperCommandError::Client(
            ClientError::Helper(HelperError::new(ErrorCode::Busy, "busy")),
        ))));
        assert_eq!(state.session_request, original);
        assert!(state.pending_reconnect(SessionPart::Dns));
        assert!(
            state
                .operation_error
                .as_deref()
                .unwrap()
                .starts_with("Changes were not applied: ")
        );
        assert!(!state.operations.helper);
        assert!(state.can_apply());
    }

    #[test]
    fn active_status_during_connect_does_not_replace_the_submitted_request() {
        let mut state = state_for_auto_connect();
        let request = ConnectRequest::from_config(&state.config).unwrap();
        state.operations.helper = true;
        state.config.settings.dns = DnsPreset::Google.settings();
        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connected,
            node: Some(NodeId::new("node")),
            ..Status::default()
        }));
        assert!(state.session_request.is_none());
        state.reduce(WorkerEvent::Connect(Ok(request)));
        assert!(state.pending_reconnect(SessionPart::Dns));
    }

    #[test]
    fn rule_change_in_active_set_remains_pending_until_reverted() {
        let mut state = state_for_auto_connect();
        state.config.rule_sets.push(rule_set("1"));
        state.config.active_rule_set = Some(RuleSetId::new("1"));
        let request = ConnectRequest::from_config(&state.config).unwrap();
        state.reduce(WorkerEvent::Connect(Ok(request)));

        state.config.rule_sets[0].rules[0].target = RuleTarget::Direct;
        assert!(state.pending_reconnect(SessionPart::Rules));
        assert!(!state.pending_reconnect(SessionPart::Dns));
        state.config.rule_sets[0].rules[0].target = RuleTarget::Proxy;
        assert!(!state.pending_reconnect(SessionPart::Rules));
    }

    #[test]
    fn disconnected_and_failed_statuses_clear_session_request_but_reconnecting_does_not() {
        for status in [
            ConnectionState::Disconnected,
            ConnectionState::Failed {
                reason: "failed".into(),
            },
            ConnectionState::FailedProtected {
                reason: "blocked".into(),
            },
        ] {
            let mut state = state_for_auto_connect();
            let request = ConnectRequest::from_config(&state.config).unwrap();
            state.reduce(WorkerEvent::Connect(Ok(request)));
            state.reduce(WorkerEvent::Status(Status {
                state: ConnectionState::Reconnecting,
                ..Status::default()
            }));
            assert!(state.session_request.is_some());
            state.reduce(WorkerEvent::Status(Status {
                state: status,
                ..Status::default()
            }));
            assert!(state.session_request.is_none());
            assert!(!state.pending_reconnect(SessionPart::Rules));
        }
    }

    #[test]
    fn active_status_seeds_session_only_once_and_only_for_the_selected_node() {
        let mut matching = state_for_auto_connect();
        matching.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connected,
            node: Some(NodeId::new("node")),
            ..Status::default()
        }));
        assert_eq!(
            matching.session_request,
            Some(ConnectRequest::from_config(&matching.config).unwrap())
        );
        assert!(!matching.pending_reconnect(SessionPart::Dns));

        let mut mismatched = state_for_auto_connect();
        mismatched.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connected,
            node: Some(NodeId::new("other")),
            ..Status::default()
        }));
        assert!(mismatched.session_request.is_none());
        mismatched.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connected,
            node: Some(NodeId::new("node")),
            ..Status::default()
        }));
        assert!(mismatched.session_request.is_none());

        let mut missing_selection = state_for_auto_connect();
        missing_selection.config.active = None;
        missing_selection.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connected,
            node: Some(NodeId::new("node")),
            ..Status::default()
        }));
        assert!(missing_selection.session_request.is_none());
        assert!(!missing_selection.pending_reconnect(SessionPart::Dns));
    }

    #[test]
    fn command_completion_clears_flags_and_maps_selection_errors() {
        let mut state = State::default();
        state.operations.helper = true;
        state.reduce(WorkerEvent::Connect(Err(HelperCommandError::Request(
            ConnectRequestError::NodeNotFound,
        ))));
        assert!(!state.operations.helper);
        assert_eq!(state.operation_error.as_deref(), Some(t().select_server));
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
    fn failed_connect_reported_by_status_has_no_second_error() {
        for code in [
            ErrorCode::EngineFailed,
            ErrorCode::RoutingFailed,
            ErrorCode::UnsupportedRules,
        ] {
            let mut state = State {
                status: Status {
                    state: ConnectionState::Failed {
                        reason: "boom".into(),
                    },
                    ..Status::default()
                },
                operation_error: Some("old error".into()),
                ..State::default()
            };
            state.operations.helper = true;
            state.reduce(WorkerEvent::Connect(Err(HelperCommandError::Client(
                ClientError::Helper(HelperError::new(code, "boom")),
            ))));
            assert!(!state.operations.helper);
            assert!(state.operation_error.is_none());
            assert!(matches!(state.status.state, ConnectionState::Failed { .. }));
        }
    }

    #[test]
    fn busy_connect_and_failed_disconnect_still_show_errors() {
        let mut state = State::default();
        state.operations.helper = true;
        state.reduce(WorkerEvent::Connect(Err(HelperCommandError::Client(
            ClientError::Helper(HelperError::new(ErrorCode::Busy, "retry")),
        ))));
        assert!(!state.operations.helper);
        assert_eq!(
            state.operation_error.as_deref(),
            Some("the service is busy with another operation: retry")
        );

        state.operations.helper = true;
        state.reduce(WorkerEvent::Disconnect(Err(HelperCommandError::Client(
            ClientError::Helper(HelperError::new(ErrorCode::EngineFailed, "boom")),
        ))));
        assert!(!state.operations.helper);
        assert_eq!(
            state.operation_error.as_deref(),
            Some("the engine failed: boom")
        );
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
    fn provider_announcement_in_translated_error_redacts_subscription_url() {
        let url = "https://sub.example.com/private-token";
        let mut subscription = subscription("1");
        subscription.url = url.into();
        let config = AppConfig {
            subscriptions: vec![subscription],
            ..AppConfig::default()
        };
        let error = UpdateSubscriptionError::Fetch {
            source: FetchError::Parse(ParseError::DeviceLimit {
                max_devices_reached: true,
                not_supported: false,
                announce: Some(format!("see {url}")),
            }),
            message: "CLI only".into(),
        };
        let text = redact(
            &config,
            &errors::update_subscription(&crate::strings::RU, &error),
        );
        assert!(!text.contains("private-token"));
        assert!(text.contains("https://sub.example.com/…"));
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
        let request = ConnectRequest::from_config(&state_for_auto_connect().config).unwrap();
        state.reduce(WorkerEvent::Connect(Ok(request)));
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
        assert_eq!(state.rule_screen.name.as_ref().unwrap().name, t().basic);
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

    #[cfg(windows)]
    #[test]
    fn browse_executable_requires_an_idle_process_dialog() {
        let mut state = state_with_rules();
        state.act(Action::OpenRules);
        assert!(state.act(Action::BrowseExecutable).is_none());
        assert!(matches!(
            state.act(Action::OpenAddRule),
            Some(Job::LoadProcesses(_))
        ));
        state.rule_screen.add.as_mut().unwrap().busy = true;
        assert!(state.act(Action::BrowseExecutable).is_none());
        state.rule_screen.add.as_mut().unwrap().busy = false;
        assert!(matches!(
            state.act(Action::BrowseExecutable),
            Some(Job::BrowseExecutable)
        ));
        assert!(state.rule_screen.add.as_ref().unwrap().browsing);
        assert!(state.act(Action::BrowseExecutable).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn browsed_executable_uses_the_selected_match_mode_and_clears_process_selection() {
        for (mode, expected) in [
            (ProcessMatchMode::Name, "Tool.exe"),
            (ProcessMatchMode::Path, r"C:\Apps\Tool.exe"),
        ] {
            let mut state = state_with_rules();
            state.act(Action::OpenRules);
            state.act(Action::OpenAddRule);
            state.act(Action::SelectRuleInput(RuleInputKind::Process));
            let dialog = state.rule_screen.add.as_mut().unwrap();
            dialog.match_mode = mode;
            dialog.selected_process = Some(0);
            dialog.processes.push(ProcessGroup {
                name: "Other.exe".into(),
                path: Some(r"C:\Apps\Other.exe".into()),
                count: 1,
                windowed: false,
            });
            dialog.process = "Other.exe".into();
            dialog.error = Some("previous error".into());
            dialog.focus_input = false;
            assert!(matches!(
                state.act(Action::BrowseExecutable),
                Some(Job::BrowseExecutable)
            ));
            let path = PathBuf::from(r"C:\Apps\Tool.exe");
            state.reduce(WorkerEvent::BrowsedExecutable(Some(path.clone())));
            let dialog = state.rule_screen.add.as_ref().unwrap();
            assert!(!dialog.browsing);
            assert_eq!(dialog.browsed.as_ref(), Some(&path));
            assert_eq!(dialog.process, expected);
            assert_eq!(dialog.selected_process, None);
            assert!(dialog.error.is_none());
            assert!(dialog.focus_input);
        }
    }

    #[cfg(windows)]
    #[test]
    fn cancelled_or_late_browse_does_not_replace_input() {
        let mut state = state_with_rules();
        state.act(Action::OpenRules);
        state.act(Action::OpenAddRule);
        state.act(Action::SelectRuleInput(RuleInputKind::Process));
        state.rule_screen.add.as_mut().unwrap().process = "current.exe".into();
        state.act(Action::BrowseExecutable);
        state.reduce(WorkerEvent::BrowsedExecutable(None));
        let dialog = state.rule_screen.add.as_ref().unwrap();
        assert!(!dialog.browsing);
        assert_eq!(dialog.process, "current.exe");
        assert!(dialog.browsed.is_none());

        state.act(Action::BrowseExecutable);
        state.act(Action::SelectRuleInput(RuleInputKind::Domain));
        state.reduce(WorkerEvent::BrowsedExecutable(Some(
            r"C:\Apps\Tool.exe".into(),
        )));
        let dialog = state.rule_screen.add.as_ref().unwrap();
        assert!(!dialog.browsing);
        assert_eq!(dialog.process, "current.exe");
        assert!(dialog.browsed.is_none());

        state.act(Action::SelectRuleInput(RuleInputKind::Process));
        state.act(Action::BrowseExecutable);
        state.act(Action::CancelAddRule);
        state.reduce(WorkerEvent::BrowsedExecutable(Some(
            r"C:\Apps\Tool.exe".into(),
        )));
        assert!(state.rule_screen.add.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn browsed_executable_switches_between_name_and_path_without_a_running_process() {
        let mut state = state_with_rules();
        state.act(Action::OpenRules);
        state.act(Action::OpenAddRule);
        state.act(Action::SelectRuleInput(RuleInputKind::Process));
        state.act(Action::BrowseExecutable);
        state.reduce(WorkerEvent::BrowsedExecutable(Some(
            r"C:\Apps\Tool.exe".into(),
        )));
        let dialog = state.rule_screen.add.as_mut().unwrap();
        assert_eq!(dialog.process, "Tool.exe");
        assert!(dialog.selected_process.is_none());
        dialog.set_process_match_mode(ProcessMatchMode::Path);
        assert_eq!(dialog.process, r"C:\Apps\Tool.exe");
        dialog.set_process_match_mode(ProcessMatchMode::Name);
        assert_eq!(dialog.process, "Tool.exe");
    }

    #[test]
    fn process_results_fill_only_the_current_dialog_and_are_dropped_on_close() {
        let mut state = state_with_rules();
        state.act(Action::OpenRules);
        assert!(state.act(Action::RefreshProcesses).is_none());
        let Some(Job::LoadProcesses(first)) = state.act(Action::OpenAddRule) else {
            panic!("new rule must load the process tab");
        };
        assert!(state.act(Action::RefreshProcesses).is_none());
        state.reduce(WorkerEvent::Processes {
            request: first,
            result: Ok(vec![RunningProcess {
                pid: 100,
                name: "Telegram.exe".into(),
                path: Some(r"C:\Apps\Telegram.exe".into()),
                has_window: true,
            }]),
        });
        let dialog = state.rule_screen.add.as_ref().unwrap();
        assert!(dialog.processes_loaded);
        assert_eq!(dialog.processes[0].name, "Telegram.exe");
        assert_eq!(dialog.processes[0].count, 1);
        state.act(Action::CancelAddRule);
        assert!(state.rule_screen.add.is_none());

        let Some(Job::LoadProcesses(second)) = state.act(Action::OpenAddRule) else {
            panic!("reopened dialog must start a new worker job");
        };
        assert_ne!(first, second);
        state.reduce(WorkerEvent::Processes {
            request: first,
            result: Ok(vec![RunningProcess {
                pid: 101,
                name: "Old.exe".into(),
                path: None,
                has_window: false,
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
    fn site_batch_requires_every_line_to_be_valid_and_obeys_subdomain_toggle() {
        for (subdomains, expected) in [
            (
                true,
                vec![
                    RuleMatcher::Domain(DomainMatch::Suffix("youtube.com".into())),
                    RuleMatcher::Domain(DomainMatch::Suffix("instagram.com".into())),
                ],
            ),
            (
                false,
                vec![
                    RuleMatcher::Domain(DomainMatch::Exact("www.youtube.com".into())),
                    RuleMatcher::Domain(DomainMatch::Exact("instagram.com".into())),
                ],
            ),
        ] {
            let mut state = state_with_rules();
            state.act(Action::OpenRules);
            assert!(matches!(
                state.act(Action::OpenAddRule),
                Some(Job::LoadProcesses(_))
            ));
            assert_eq!(
                state.rule_screen.add.as_ref().unwrap().kind,
                RuleInputKind::Process
            );
            state.act(Action::SelectRuleInput(RuleInputKind::Domain));
            let dialog = state.rule_screen.add.as_mut().unwrap();
            dialog.domains = "https://www.youtube.com/watch?v=1\n192.168.1.1\ninstagram.com".into();
            dialog.subdomains = subdomains;
            assert!(state.act(Action::SubmitAddRule).is_none());
            state.rule_screen.add.as_mut().unwrap().domains =
                "https://www.youtube.com/watch?v=1\ninstagram.com".into();
            assert!(matches!(
                state.act(Action::SubmitAddRule),
                Some(Job::AddRules(_, matchers, RuleTarget::Proxy)) if matchers == expected
            ));
        }
    }

    #[test]
    fn editing_a_suffix_rule_populates_the_site_form_and_saves_only_changes() {
        let mut state = state_with_rules();
        let id = state.config.rule_sets[1].rules[0].id.clone();
        state.config.rule_sets[1].rules[0].matcher =
            RuleMatcher::Domain(DomainMatch::Suffix("example.com".into()));
        state.config.rule_sets[1].rules[0].enabled = false;
        state.act(Action::OpenRules);
        assert!(state.act(Action::OpenEditRule(id.clone())).is_none());
        let dialog = state.rule_screen.add.as_ref().unwrap();
        assert_eq!(dialog.editing.as_ref(), Some(&id));
        assert_eq!(dialog.kind, RuleInputKind::Domain);
        assert_eq!(dialog.domains, "example.com");
        assert!(dialog.subdomains);
        state.act(Action::SelectRuleInput(RuleInputKind::Process));
        assert_eq!(
            state.rule_screen.add.as_ref().unwrap().kind,
            RuleInputKind::Domain
        );
        assert!(state.act(Action::SubmitAddRule).is_none());
        assert!(state.rule_screen.add.is_none());
        assert!(!state.operations.rules_edit);

        state.act(Action::OpenEditRule(id.clone()));
        state.rule_screen.add.as_mut().unwrap().target = RuleTarget::Direct;
        assert!(matches!(
            state.act(Action::SubmitAddRule),
            Some(Job::UpdateRule(set, rule, RuleMatcher::Domain(DomainMatch::Suffix(domain)), RuleTarget::Direct))
                if set == RuleSetId::new("2") && rule == id && domain == "example.com"
        ));
        assert!(state.rule_screen.add.as_ref().unwrap().busy);
        state.reduce(WorkerEvent::UpdateRule(Err(RuleSetError::DuplicateRule)));
        let dialog = state.rule_screen.add.as_ref().unwrap();
        assert!(!dialog.busy);
        assert!(dialog.error.is_some());
        state.reduce(WorkerEvent::UpdateRule(Ok(())));
        assert!(state.rule_screen.add.is_none());
    }

    #[test]
    fn editing_existing_suffixes_does_not_strip_www_or_reject_a_zone() {
        for domain in ["www.youtube.com", "ru"] {
            let mut state = state_with_rules();
            let id = state.config.rule_sets[1].rules[0].id.clone();
            state.config.rule_sets[1].rules[0].matcher =
                RuleMatcher::Domain(DomainMatch::Suffix(domain.into()));
            state.act(Action::OpenRules);
            state.act(Action::OpenEditRule(id.clone()));
            assert_eq!(state.rule_screen.add.as_ref().unwrap().domains, domain);
            assert!(state.act(Action::SubmitAddRule).is_none());
            assert!(state.rule_screen.add.is_none());
            state.act(Action::OpenEditRule(id.clone()));
            state.rule_screen.add.as_mut().unwrap().target = RuleTarget::Block;
            assert!(matches!(
                state.act(Action::SubmitAddRule),
                Some(Job::UpdateRule(_, _, RuleMatcher::Domain(DomainMatch::Suffix(value)), RuleTarget::Block))
                    if value == domain
            ));
        }
    }

    #[test]
    fn editing_a_path_rule_opens_advanced_and_rejects_templates() {
        let mut state = state_with_rules();
        let id = state.config.rule_sets[1].rules[1].id.clone();
        state.config.rule_sets[1].rules[1].matcher =
            RuleMatcher::Process(ProcessMatch::Path(PathBuf::from(r"C:\Apps\Tool.exe")));
        state.config.rule_sets[1].rules[2].matcher = RuleMatcher::Template(RuleTemplate::Youtube);
        assert!(
            AddRuleDialog::for_rule(
                state.config.rule_sets[1].id.clone(),
                &state.config.rule_sets[1].rules[2],
            )
            .is_none()
        );
        state.act(Action::OpenRules);
        assert!(state.act(Action::OpenEditRule(RuleId::new("2"))).is_none());
        assert!(state.rule_screen.add.is_none());
        assert!(
            state
                .act(Action::OpenEditRule(RuleId::new("missing")))
                .is_none()
        );
        let request = state.act(Action::OpenEditRule(id.clone()));
        assert!(matches!(request, Some(Job::LoadProcesses(_))));
        let dialog = state.rule_screen.add.as_ref().unwrap();
        assert_eq!(dialog.editing.as_ref(), Some(&id));
        assert_eq!(dialog.kind, RuleInputKind::Process);
        assert_eq!(dialog.process_filter, "Tool.exe");
        assert_eq!(dialog.process, r"C:\Apps\Tool.exe");
        assert!(dialog.advanced);
        assert_eq!(dialog.match_mode, ProcessMatchMode::Path);
        assert!(dialog.selected_process.is_none());
        assert!(state.act(Action::SubmitAddRule).is_none());
        assert!(state.rule_screen.add.is_none());
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
        state.act(Action::SelectRuleInput(RuleInputKind::Domain));
        let dialog = state.rule_screen.add.as_mut().unwrap();
        dialog.domains = "*.example.com".into();
        dialog.target = RuleTarget::Direct;
        assert!(matches!(
            state.act(Action::SubmitAddRule),
            Some(Job::AddRules(set, matchers, RuleTarget::Direct))
                if set == RuleSetId::new("2") && matchers == vec![RuleMatcher::Domain(DomainMatch::Suffix("example.com".into()))]
        ));
        assert!(state.act(Action::CancelAddRule).is_none());
        state.reduce(WorkerEvent::AddRules(Err(RuleSetError::DuplicateRule)));
        let dialog = state.rule_screen.add.as_ref().unwrap();
        assert_eq!(dialog.domains, "*.example.com");
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
            Some(Job::AddRules(_, _, _))
        ));
        state.reduce(WorkerEvent::AddRules(Ok(rosetun_core::AddedRules {
            added: vec![rule_set("2").rules[0].clone()],
            skipped: 0,
        })));
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
    fn rule_target_filter_can_be_set_and_cleared() {
        let mut state = state_with_rules();
        state.act(Action::SetRuleTargetFilter(Some(RuleTarget::Block)));
        assert_eq!(state.rule_screen.filter.target, Some(RuleTarget::Block));
        state.act(Action::SetRuleTargetFilter(None));
        assert_eq!(state.rule_screen.filter.target, None);
    }

    #[test]
    fn add_template_requires_a_selected_set_and_no_existing_template_or_edit() {
        let mut state = state_with_rules();
        let template = RuleTemplate::RussianSites;
        assert!(state.act(Action::AddTemplate(template)).is_none());
        state.act(Action::OpenRules);
        state.config.rule_sets[1].rules.clear();
        assert!(matches!(
            state.act(Action::AddTemplate(template)),
            Some(Job::AddRule(set, RuleMatcher::Template(RuleTemplate::RussianSites), RuleTarget::Direct))
                if set == RuleSetId::new("2")
        ));
        assert!(state.act(Action::AddTemplate(template)).is_none());
        state.reduce(WorkerEvent::AddRule(Err(RuleSetError::DuplicateRule)));
        assert!(state.operation_error.is_some());
        state.config.rule_sets[1].rules.push(Rule {
            id: RuleId::new("template"),
            enabled: false,
            matcher: RuleMatcher::Template(template),
            target: RuleTarget::Block,
        });
        assert!(state.act(Action::AddTemplate(template)).is_none());
    }

    #[test]
    fn remove_template_uses_the_rule_id_and_requires_presence() {
        let mut state = state_with_rules();
        state.act(Action::OpenRules);
        let template = RuleTemplate::Youtube;
        assert!(state.act(Action::RemoveTemplate(template)).is_none());
        state.config.rule_sets[1].rules.push(Rule {
            id: RuleId::new("template"),
            enabled: true,
            matcher: RuleMatcher::Template(template),
            target: RuleTarget::Proxy,
        });
        assert!(matches!(
            state.act(Action::RemoveTemplate(template)),
            Some(Job::RemoveRule(set, rule))
                if set == RuleSetId::new("2") && rule == RuleId::new("template")
        ));
        assert!(state.act(Action::RemoveTemplate(template)).is_none());
        state.reduce(WorkerEvent::RemoveRule(Ok(())));
        state.config.rule_sets[1].rules.pop();
        assert!(state.act(Action::RemoveTemplate(template)).is_none());
    }

    #[test]
    fn move_rule_to_top_checks_position_and_busy_state_but_not_filters() {
        let mut state = state_with_rules();
        state.act(Action::OpenRules);
        assert!(state.act(Action::MoveRuleToTop(RuleId::new("0"))).is_none());
        state.rule_screen.filter.search = "third".into();
        assert!(matches!(
            state.act(Action::MoveRuleToTop(RuleId::new("2"))),
            Some(Job::MoveRule(set, rule, 0))
                if set == RuleSetId::new("2") && rule == RuleId::new("2")
        ));
        assert!(state.act(Action::MoveRuleToTop(RuleId::new("1"))).is_none());
        state.reduce(WorkerEvent::MoveRule(Ok(())));
        assert!(state.act(Action::MoveRuleToTop(RuleId::new("0"))).is_none());
        state.rule_screen.selected_set = None;
        assert!(state.act(Action::MoveRuleToTop(RuleId::new("2"))).is_none());
    }

    #[test]
    fn rule_actions_reject_concurrent_changes_and_filtered_reordering() {
        let mut state = state_with_rules();
        state.act(Action::OpenRules);
        let rule = RuleId::new("1");
        assert!(matches!(
            state.act(Action::DropRule(rule.clone(), 0)),
            Some(Job::MoveRule(_, _, 0))
        ));
        assert!(state.act(Action::DropRule(rule.clone(), 3)).is_none());
        assert!(
            state
                .act(Action::SetRuleEnabled(rule.clone(), false))
                .is_none()
        );
        assert!(state.act(Action::SelectRuleSet(None)).is_none());
        state.reduce(WorkerEvent::MoveRule(Ok(())));
        state.rule_screen.filter.search = "second".into();
        assert!(state.act(Action::DropRule(rule.clone(), 0)).is_none());
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
        state.act(Action::SelectRuleInput(RuleInputKind::Domain));
        let dialog = state.rule_screen.add.as_mut().unwrap();
        dialog.domains = "new.example".into();
        dialog.subdomains = false;
        dialog.target = RuleTarget::Block;
        assert!(matches!(
            state.act(Action::SubmitAddRule),
            Some(Job::AddRules(_, matchers, RuleTarget::Block))
                if matchers == vec![RuleMatcher::Domain(DomainMatch::Exact("new.example".into()))]
        ));
        state.reduce(WorkerEvent::AddRules(Ok(rosetun_core::AddedRules {
            added: vec![rule_set("1").rules[0].clone()],
            skipped: 0,
        })));
        state.act(Action::RequestDeleteRule(rule));
        assert!(matches!(
            state.act(Action::ConfirmRuleDelete),
            Some(Job::RemoveRule(_, _))
        ));
        state.reduce(WorkerEvent::RemoveRule(Ok(())));
        assert!(state.rule_screen.delete.is_none());
    }

    #[test]
    fn settings_section_survives_navigation_between_tabs() {
        let mut state = State::default();
        assert_eq!(state.settings_screen.section, SettingsSection::General);
        state.act(Action::OpenSettings);
        state.act(Action::OpenSettingsSection(SettingsSection::Service));
        assert_eq!(state.settings_screen.section, SettingsSection::Service);
        state.act(Action::ShowConnection);
        state.act(Action::OpenSettings);
        assert_eq!(state.screen, Screen::Settings);
        assert_eq!(state.settings_screen.section, SettingsSection::Service);
    }

    #[test]
    fn settings_dns_form_initializes_on_open_and_follows_clean_config() {
        let mut state = State::default();
        let mut config = AppConfig::default();
        config.settings.dns =
            rosetun_core::parse_dns_input("1.1.1.1", "cloudflare-dns.com", "8443", "/dns-query")
                .unwrap();
        state.reduce(WorkerEvent::Config {
            generation: 1,
            config: config.clone(),
        });
        assert!(state.settings_screen.server.is_empty());
        state.act(Action::OpenSettings);
        assert_eq!(state.screen, Screen::Settings);
        assert_eq!(state.settings_screen.server, "1.1.1.1");
        assert_eq!(state.settings_screen.server_name, "cloudflare-dns.com");
        assert_eq!(state.settings_screen.port, "8443");
        assert_eq!(state.settings_screen.path, "/dns-query");
        assert!(state.settings_screen.custom_dns);

        config.settings.dns = DnsSettings::default();
        state.reduce(WorkerEvent::Config {
            generation: 2,
            config,
        });
        assert_eq!(state.settings_screen.server, "1.1.1.1");
        assert_eq!(state.settings_screen.server_name, "cloudflare-dns.com");
        assert!(state.settings_screen.port.is_empty());
        assert!(state.settings_screen.path.is_empty());
        assert!(!state.settings_screen.custom_dns);
    }

    #[test]
    fn saved_google_and_presets_select_the_correct_card_and_job() {
        let mut state = State::default();
        let mut config = AppConfig::default();
        config.settings.dns = DnsPreset::Google.settings();
        state.reduce(WorkerEvent::Config {
            generation: 1,
            config,
        });
        state.act(Action::OpenSettings);
        assert!(!state.settings_screen.custom_dns);
        assert_eq!(
            DnsPreset::matching(&state.config.settings.dns),
            Some(DnsPreset::Google)
        );
        assert!(state.act(Action::SetDnsPreset(DnsPreset::Google)).is_none());
        assert!(matches!(
            state.act(Action::SetDnsPreset(DnsPreset::Quad9)),
            Some(Job::SetDns(dns)) if dns == DnsPreset::Quad9.settings()
        ));
        assert!(!state.settings_screen.custom_dns);
    }

    #[test]
    fn selecting_saved_preset_leaves_no_job_and_failed_preset_restores_saved_dns() {
        let mut state = State {
            config_ready: true,
            ..State::default()
        };
        state.act(Action::OpenSettings);
        state.act(Action::SelectCustomDns);
        state.settings_screen.server = "9.9.9.9".into();
        state.settings_screen.dirty = true;
        assert!(
            state
                .act(Action::SetDnsPreset(DnsPreset::Cloudflare))
                .is_none()
        );
        assert!(!state.settings_screen.custom_dns);
        assert!(!state.settings_screen.dirty);
        assert_eq!(state.settings_screen.server, "1.1.1.1");

        assert!(matches!(
            state.act(Action::SetDnsPreset(DnsPreset::Quad9)),
            Some(Job::SetDns(_))
        ));
        state.reduce(WorkerEvent::SetDns(Err(
            rosetun_core::SettingsError::Store(StoreError::NoConfigDir),
        )));
        assert_eq!(state.settings_screen.server, "1.1.1.1");
        assert!(!state.settings_screen.custom_dns);
    }

    #[test]
    fn settings_reset_requires_disconnection_and_resynchronizes_dns() {
        let mut state = State {
            config_ready: true,
            helper_available: true,
            ..State::default()
        };
        state.config.settings.dns =
            rosetun_core::parse_dns_input("1.0.0.1", "cloudflare-dns.com", "", "").unwrap();
        state.act(Action::OpenSettings);
        assert!(state.settings_screen.custom_dns);
        state.settings_screen.server = "8.8.8.8".into();
        state.settings_screen.dirty = true;
        state.status.state = ConnectionState::Connected;
        assert!(!state.can_reset_settings());
        state.act(Action::RequestResetSettings);
        assert!(!state.settings_screen.reset_open);

        state.status.state = ConnectionState::Disconnected;
        state.operations.kill_switch = true;
        assert!(!state.can_reset_settings());
        state.operations.kill_switch = false;
        state.act(Action::RequestResetSettings);
        assert!(state.settings_screen.reset_open);
        assert!(matches!(
            state.act(Action::ConfirmResetSettings),
            Some(Job::ResetSettings)
        ));
        state.act(Action::CancelResetSettings);
        assert!(state.settings_screen.reset_open);
        state.reduce(WorkerEvent::Config {
            generation: 1,
            config: AppConfig::default(),
        });
        assert!(state.settings_screen.dirty);
        state.reduce(WorkerEvent::ResetSettings(Ok(())));
        assert!(!state.settings_screen.reset_open);
        assert!(!state.operations.settings);
        assert!(!state.settings_screen.dirty);
        assert!(!state.settings_screen.custom_dns);
        assert_eq!(state.settings_screen.server, "1.1.1.1");
    }

    #[test]
    fn settings_reset_failure_closes_confirmation_and_reports_error() {
        let mut state = State {
            config_ready: true,
            ..State::default()
        };
        state.act(Action::RequestResetSettings);
        assert!(state.settings_screen.reset_open);
        assert!(matches!(
            state.act(Action::ConfirmResetSettings),
            Some(Job::ResetSettings)
        ));
        state.reduce(WorkerEvent::ResetSettings(Err(
            rosetun_core::SettingsError::Store(StoreError::NoConfigDir),
        )));
        assert!(!state.settings_screen.reset_open);
        assert!(!state.operations.settings);
        assert_eq!(
            state.operation_error.as_deref(),
            Some("could not determine the configuration directory")
        );
    }

    #[test]
    fn settings_dns_form_preserves_unsaved_input_across_config_reloads() {
        let mut state = State::default();
        state.act(Action::OpenSettings);
        state.reduce(WorkerEvent::Config {
            generation: 1,
            config: AppConfig::default(),
        });
        assert_eq!(state.settings_screen.server, "1.1.1.1");
        state.act(Action::SelectCustomDns);
        assert!(state.settings_screen.custom_dns);
        state.settings_screen.server = "8.8.8.8".into();
        state.settings_screen.server_name = "dns.google".into();
        state.settings_screen.port = "8443".into();
        state.settings_screen.dirty = true;
        let mut config = AppConfig::default();
        config.settings.kill_switch = true;
        state.reduce(WorkerEvent::Config {
            generation: 2,
            config,
        });
        assert_eq!(state.settings_screen.server, "8.8.8.8");
        assert_eq!(state.settings_screen.server_name, "dns.google");
        assert!(state.settings_screen.dirty);

        let Some(Job::SetDns(dns)) = state.act(Action::SaveDns) else {
            panic!("expected DNS save");
        };
        assert_eq!(dns.server_name, "dns.google");
        assert!(state.operations.settings);
        assert!(state.act(Action::SetDnsPreset(DnsPreset::Quad9)).is_none());
        assert_eq!(state.settings_screen.server, "8.8.8.8");
        let mut config = state.config.clone();
        config.settings.dns = dns;
        state.reduce(WorkerEvent::Config {
            generation: 3,
            config,
        });
        assert!(state.settings_screen.dirty);
        state.reduce(WorkerEvent::SetDns(Ok(())));
        assert!(!state.operations.settings);
        assert!(!state.settings_screen.dirty);
        assert_eq!(state.settings_screen.server, "8.8.8.8");
        assert!(state.act(Action::SaveDns).is_none());
        assert!(state.settings_screen.custom_dns);
    }

    #[test]
    fn expired_verbose_log_can_be_turned_on_again() {
        let mut state = State {
            config_ready: true,
            ..State::default()
        };
        state.config.settings.verbose_log_until = Some(now_unix().saturating_sub(1));
        assert!(state.act(Action::SetVerboseLog(false)).is_none());
        assert!(matches!(
            state.act(Action::SetVerboseLog(true)),
            Some(Job::SetVerboseLog(true))
        ));
    }

    #[test]
    fn settings_operations_clear_busy_and_report_errors() {
        let mut state = State {
            config_ready: true,
            ..State::default()
        };
        assert!(state.act(Action::SetInterfaceScale(95)).is_none());
        assert!(state.act(Action::SetInterfaceScale(100)).is_none());
        assert!(matches!(
            state.act(Action::SetInterfaceScale(125)),
            Some(Job::SetInterfaceScale(125))
        ));
        assert!(state.operations.settings);
        assert!(state.act(Action::SetVerboseLog(true)).is_none());
        state.reduce(WorkerEvent::SetInterfaceScale(Err(
            rosetun_core::SettingsError::UnsupportedScale,
        )));
        assert!(!state.operations.settings);
        assert_eq!(
            state.operation_error.as_deref(),
            Some("unsupported interface scale")
        );

        assert!(matches!(
            state.act(Action::SetVerboseLog(true)),
            Some(Job::SetVerboseLog(true))
        ));
        state.reduce(WorkerEvent::SetVerboseLog(Err(
            rosetun_core::SettingsError::Store(StoreError::NoConfigDir),
        )));
        assert!(!state.operations.settings);
        assert_eq!(
            state.operation_error.as_deref(),
            Some("could not determine the configuration directory")
        );

        state.act(Action::OpenSettings);
        state.act(Action::SelectCustomDns);
        assert!(!state.settings_screen.dirty);
        state.settings_screen.server = "bad".into();
        assert!(state.act(Action::SaveDns).is_none());
        state.settings_screen.server = "8.8.8.8".into();
        state.settings_screen.dirty = true;
        assert!(matches!(state.act(Action::SaveDns), Some(Job::SetDns(_))));
        state.reduce(WorkerEvent::SetDns(Err(
            rosetun_core::SettingsError::Store(StoreError::NoConfigDir),
        )));
        assert!(!state.operations.settings);
        assert!(state.settings_screen.dirty);
        assert_eq!(state.settings_screen.server, "8.8.8.8");
        assert_eq!(
            state.operation_error.as_deref(),
            Some("could not determine the configuration directory")
        );
    }

    #[test]
    fn changing_language_uses_a_settings_job_and_completion_clears_busy() {
        let mut state = State::default();
        assert!(
            state
                .act(Action::SetLanguage(LanguageSetting::Russian))
                .is_none()
        );
        state.config_ready = true;
        assert!(
            state
                .act(Action::SetLanguage(LanguageSetting::System))
                .is_none()
        );
        assert!(matches!(
            state.act(Action::SetLanguage(LanguageSetting::Russian)),
            Some(Job::SetLanguage(LanguageSetting::Russian))
        ));
        assert!(state.operations.settings);
        assert!(
            state
                .act(Action::SetLanguage(LanguageSetting::English))
                .is_none()
        );
        state.reduce(WorkerEvent::SetLanguage(Ok(())));
        assert!(!state.operations.settings);
        let mut config = state.config.clone();
        config.interface.language = LanguageSetting::Russian;
        state.reduce(WorkerEvent::Config {
            generation: 1,
            config,
        });
        assert!(
            state
                .act(Action::SetLanguage(LanguageSetting::Russian))
                .is_none()
        );
    }

    #[test]
    fn reduce_motion_setting_uses_a_settings_job_and_saved_value() {
        let mut state = State::default();
        assert!(state.act(Action::SetReduceMotion(true)).is_none());
        state.config_ready = true;
        assert!(state.act(Action::SetReduceMotion(false)).is_none());
        assert!(matches!(
            state.act(Action::SetReduceMotion(true)),
            Some(Job::SetReduceMotion(true))
        ));
        assert!(state.operations.settings);
        assert!(state.act(Action::SetReduceMotion(true)).is_none());
        state.reduce(WorkerEvent::SetReduceMotion(Ok(())));
        assert!(!state.operations.settings);
        let mut config = state.config.clone();
        config.interface.reduce_motion = true;
        state.reduce(WorkerEvent::Config {
            generation: 1,
            config,
        });
        assert!(state.act(Action::SetReduceMotion(true)).is_none());
    }

    #[test]
    fn connection_settings_jobs_respect_busy_state_and_saved_values() {
        let mut state = State {
            config_ready: true,
            ..State::default()
        };
        assert!(state.act(Action::SetConnectOnStart(false)).is_none());
        assert!(state.act(Action::SetAutoReconnect(true)).is_none());
        assert!(matches!(
            state.act(Action::SetConnectOnStart(true)),
            Some(Job::SetConnectOnStart(true))
        ));
        assert!(state.act(Action::SetAutoReconnect(false)).is_none());
        state.reduce(WorkerEvent::SetConnectOnStart(Ok(())));
        assert!(matches!(
            state.act(Action::SetAutoReconnect(false)),
            Some(Job::SetAutoReconnect(false))
        ));
        state.reduce(WorkerEvent::SetAutoReconnect(Err(
            rosetun_core::SettingsError::Store(StoreError::NoConfigDir),
        )));
        assert!(!state.operations.settings);
        assert!(state.operation_error.is_some());
        let mut config = AppConfig::default();
        config.interface.connect_on_start = true;
        config.settings.auto_reconnect = false;
        state.reduce(WorkerEvent::Config {
            generation: 1,
            config,
        });
        assert!(state.act(Action::SetConnectOnStart(true)).is_none());
        assert!(state.act(Action::SetAutoReconnect(false)).is_none());
    }

    #[test]
    fn auto_update_setting_uses_settings_job_and_respects_busy_state() {
        let mut state = State {
            config_ready: true,
            ..State::default()
        };
        assert!(
            state
                .act(Action::SetAutoUpdateSubscriptions(true))
                .is_none()
        );
        assert!(matches!(
            state.act(Action::SetAutoUpdateSubscriptions(false)),
            Some(Job::SetAutoUpdateSubscriptions(false))
        ));
        assert!(
            state
                .act(Action::SetAutoUpdateSubscriptions(false))
                .is_none()
        );
        state.reduce(WorkerEvent::SetAutoUpdateSubscriptions(Ok(())));
        state.config.interface.auto_update_subscriptions = false;
        assert!(
            state
                .act(Action::SetAutoUpdateSubscriptions(false))
                .is_none()
        );
    }

    #[cfg(windows)]
    #[test]
    fn opening_settings_refreshes_autostart_every_time() {
        let mut state = State::default();
        assert!(matches!(
            state.act(Action::OpenSettings),
            Some(Job::LoadAutostart)
        ));
        assert_eq!(state.settings_screen.autostart, None);
        state.reduce(WorkerEvent::AutostartLoaded(Ok(true)));
        assert_eq!(state.settings_screen.autostart, Some(true));

        state.act(Action::ShowConnection);
        assert!(matches!(
            state.act(Action::OpenSettings),
            Some(Job::LoadAutostart)
        ));
        assert_eq!(state.settings_screen.autostart, None);
        state.reduce(WorkerEvent::AutostartLoaded(Ok(false)));
        assert_eq!(state.settings_screen.autostart, Some(false));
        state.reduce(WorkerEvent::AutostartLoaded(Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "registry read denied",
        ))));
        assert_eq!(state.settings_screen.autostart, None);
        assert_eq!(
            state.operation_error.as_deref(),
            Some("could not read the autostart setting: registry read denied")
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_settings_jobs_respect_busy_state_and_saved_values() {
        let mut state = State {
            config_ready: true,
            ..State::default()
        };
        assert!(state.act(Action::SetAutostart(true)).is_none());
        state.reduce(WorkerEvent::AutostartLoaded(Ok(false)));
        assert!(state.act(Action::SetAutostart(false)).is_none());
        assert!(state.act(Action::SetCloseToTray(true)).is_none());
        assert!(matches!(
            state.act(Action::SetAutostart(true)),
            Some(Job::SetAutostart(true))
        ));
        assert!(state.operations.settings);
        assert!(state.act(Action::SetCloseToTray(false)).is_none());
        state.reduce(WorkerEvent::SetAutostart(Ok(true)));
        assert!(!state.operations.settings);
        assert_eq!(state.settings_screen.autostart, Some(true));

        assert!(matches!(
            state.act(Action::SetCloseToTray(false)),
            Some(Job::SetCloseToTray(false))
        ));
        assert!(state.operations.settings);
        assert!(state.act(Action::SetAutostart(false)).is_none());
        state.reduce(WorkerEvent::SetCloseToTray(Err(
            rosetun_core::SettingsError::Store(StoreError::NoConfigDir),
        )));
        assert!(!state.operations.settings);
        assert_eq!(
            state.operation_error.as_deref(),
            Some("could not determine the configuration directory")
        );
        assert!(matches!(
            state.act(Action::SetCloseToTray(false)),
            Some(Job::SetCloseToTray(false))
        ));
        let mut config = AppConfig::default();
        config.interface.close_to_tray = false;
        state.reduce(WorkerEvent::Config {
            generation: 1,
            config,
        });
        state.reduce(WorkerEvent::SetCloseToTray(Ok(())));
        assert!(!state.operations.settings);
        assert!(state.operation_error.is_none());
        assert!(state.act(Action::SetCloseToTray(false)).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn failed_autostart_write_clears_busy_and_loaded_state() {
        let mut state = State {
            config_ready: true,
            ..State::default()
        };
        state.reduce(WorkerEvent::AutostartLoaded(Ok(false)));
        assert!(matches!(
            state.act(Action::SetAutostart(true)),
            Some(Job::SetAutostart(true))
        ));
        state.reduce(WorkerEvent::SetAutostart(Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "registry write denied",
        ))));
        assert!(!state.operations.settings);
        assert_eq!(state.settings_screen.autostart, None);
        assert_eq!(
            state.operation_error.as_deref(),
            Some("could not change autostart: registry write denied")
        );
        assert!(state.act(Action::SetAutostart(true)).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn folder_launch_uses_the_worker_and_reports_failures() {
        let mut state = State {
            config_ready: true,
            ..State::default()
        };
        state.settings_screen.config_folder = Some(PathBuf::from("C:\\Users\\Test\\Rosetun"));
        assert!(
            state
                .act(Action::OpenFolder(AboutFolder::Licenses))
                .is_none()
        );
        assert!(matches!(
            state.act(Action::OpenFolder(AboutFolder::Config)),
            Some(Job::OpenFolder(path)) if path.as_path() == std::path::Path::new("C:\\Users\\Test\\Rosetun")
        ));
        assert!(state.operations.settings);
        state.reduce(WorkerEvent::OpenFolder(Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "explorer unavailable",
        ))));
        assert!(!state.operations.settings);
        assert_eq!(
            state.operation_error.as_deref(),
            Some("could not open the folder: explorer unavailable")
        );

        let licenses = PathBuf::from("C:\\Program Files\\Rosetun\\licenses");
        state.settings_screen.licenses_folder = Some(licenses.clone());
        assert!(matches!(
            state.act(Action::OpenFolder(AboutFolder::Licenses)),
            Some(Job::OpenFolder(path)) if path == licenses
        ));
    }
}
