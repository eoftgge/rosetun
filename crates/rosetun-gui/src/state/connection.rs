use rosetun_config::{
    ConnectStage, ConnectionState, Exit, FailureKind, Status, Transport, XrayUse,
};
use rosetun_core::AppliedSnapshot;
use rosetun_ipc::{ClientError, ErrorCode, ExitOutcome, HelperError, ProbeOutcome, TunnelDelays};

use super::{Action, Job, Screen, State};
use crate::actions::{self, PrimaryAction};
use crate::errors;
use crate::worker::{HelperCommandError, LockdownChange, WorkerEvent};

/// The engine check after a cold boot can wait for an antivirus; past this
/// the connection screen says why.
const ENGINE_CHECK_HINT_AFTER_SECS: u64 = 10;

/// The connect stage under the hero title, and a hint below it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StageLine {
    pub(crate) text: String,
    pub(crate) hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TunnelDelay {
    Idle,
    Measuring,
    Done(TunnelDelays),
}

impl TunnelDelay {
    pub(crate) fn proxy(&self) -> Option<ProbeOutcome> {
        match self {
            Self::Done(delays) => Some(delays.proxy),
            Self::Idle | Self::Measuring => None,
        }
    }
}

/// A row of "Rules through other servers": an exit of the running session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionExitRow<'a> {
    /// `None` when the exit was deleted after the session started.
    pub(crate) exit: Option<&'a Exit>,
    pub(crate) node: &'a str,
    /// `None` until the delay check answers for this exit.
    pub(crate) outcome: Option<ExitOutcome>,
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
                | ErrorCode::NoNetwork
                | ErrorCode::XrayStartFailed
                | ErrorCode::XrayStopped
                | ErrorCode::RoutingFailed
                | ErrorCode::ServerNameUnresolved
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

    pub(crate) fn stage_line(&self, now_unix: u64) -> Option<StageLine> {
        let status = self
            .visible_status()
            .filter(|status| status.state.is_transitional())?;
        let stage = status.connect_stage?;
        let seconds = now_unix.saturating_sub(status.stage_since_unix.unwrap_or(now_unix));
        Some(StageLine {
            text: crate::i18n::connection_stage(stage, status.xray, seconds),
            hint: (stage == ConnectStage::CheckingEngine && seconds > ENGINE_CHECK_HINT_AFTER_SECS)
                .then(|| tr!("stage-checking-engine-hint")),
        })
    }

    /// The tray says what a connect waits for only while it checks the
    /// engine, the one stage that can take a minute without a fault.
    pub(crate) fn tray_stage_label(&self) -> Option<String> {
        let status = self
            .visible_status()
            .filter(|status| status.state.is_transitional())?;
        (status.connect_stage == Some(ConnectStage::CheckingEngine))
            .then(|| crate::i18n::stage_label(ConnectStage::CheckingEngine, status.xray))
    }

    /// The failure's technical reason as shown and copied. Users paste it into
    /// public issues, so it is scrubbed like a report: it may name the node
    /// (`dial tcp <address>:443`).
    pub(crate) fn failure_details(&self) -> Option<String> {
        match &self.visible_status()?.state {
            ConnectionState::Failed { reason, .. }
            | ConnectionState::FailedProtected { reason, .. } => {
                Some(rosetun_config::redact_report_text(&self.text(reason)))
            }
            _ => None,
        }
    }

    /// Lockdown is per machine, so only the service knows whether it is on.
    pub(crate) fn lockdown_active(&self) -> bool {
        self.visible_status().is_some_and(|status| status.lockdown)
    }

    pub(crate) fn can_change_lockdown(&self) -> bool {
        self.config_ready
            && self.helper_available
            && self.status_received
            && !self.operations.helper
            && !self.operations.lockdown
    }

    /// Lockdown keeps its own LAN permits, so a saved "Local network" change
    /// is sent to it at once.
    pub(crate) fn take_lockdown_lan(&mut self) -> Option<Job> {
        if !self.lockdown_lan_pending {
            return None;
        }
        if !self.lockdown_active() {
            self.lockdown_lan_pending = false;
            return None;
        }
        if !self.can_change_lockdown() {
            return None;
        }
        self.lockdown_lan_pending = false;
        self.lockdown_lan_sync = true;
        self.operations.lockdown = true;
        Some(Job::SetLockdown(true))
    }

    pub(super) fn queue_lockdown_lan(&mut self) {
        self.lockdown_lan_pending = self.lockdown_active();
    }

    pub(crate) fn primary_action(&self) -> PrimaryAction {
        let action = actions::primary_action(
            self.helper_available,
            &self.status,
            self.config.active_node().is_some(),
            self.operations.helper,
        );
        match action {
            PrimaryAction::Connect | PrimaryAction::Retry | PrimaryAction::Reconnect
                if self.xhttp_without_xray() =>
            {
                PrimaryAction::Disabled
            }
            action => action,
        }
    }

    /// sing-box has no XHTTP, so with Xray turned off such a server cannot connect.
    pub(crate) fn xhttp_without_xray(&self) -> bool {
        self.config.settings.xray == XrayUse::Off
            && self
                .config
                .active_node()
                .is_some_and(|(_, node)| matches!(node.stream.transport, Transport::Xhttp { .. }))
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
            return Some(Job::Connect(self.exit_inputs()));
        }
        None
    }

    /// Connects to a server picked in the tray once its choice is saved.
    pub(crate) fn take_choice_connect(&mut self) -> Option<Job> {
        if !self.connect_after_choice || self.operations.selection {
            return None;
        }
        self.connect_after_choice = false;
        match self.primary_action() {
            PrimaryAction::Connect | PrimaryAction::Retry => self.act(Action::Primary),
            _ => None,
        }
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

    /// The exits of the running session with their last delay, in request order.
    pub(crate) fn session_exit_rows(&self) -> Vec<SessionExitRow<'_>> {
        if !matches!(
            self.visible_status().map(|status| &status.state),
            Some(ConnectionState::Connected | ConnectionState::Reconnecting)
        ) {
            return Vec::new();
        }
        let Some(request) = self.session.session_request.as_ref() else {
            return Vec::new();
        };
        let delays = match &self.tunnel_delay {
            TunnelDelay::Done(delays) => delays.exits.as_slice(),
            TunnelDelay::Idle | TunnelDelay::Measuring => &[],
        };
        request
            .extra_nodes
            .iter()
            .map(|extra| SessionExitRow {
                exit: self.config.exits.iter().find(|exit| exit.id == extra.exit),
                node: &extra.node.name,
                outcome: delays
                    .iter()
                    .find(|delay| delay.exit == extra.exit)
                    .map(|delay| delay.outcome),
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn set_session_request_for_test(&mut self, request: rosetun_ipc::ConnectRequest) {
        self.session.session_request = Some(request);
    }

    pub(super) fn tunnel_delay_due(&self) -> Option<u64> {
        if !self.status_received
            || !matches!(
                self.visible_status().map(|status| &status.state),
                Some(ConnectionState::Connected)
            )
            || !matches!(self.tunnel_delay, TunnelDelay::Idle)
        {
            return None;
        }
        let since = self.status.since_unix?;
        let retry = self
            .delay_last_auto
            .map_or(0, |last| last.saturating_add(10));
        Some(since.saturating_add(3).max(retry))
    }

    pub(crate) fn take_tunnel_delay(&mut self, now: u64) -> Option<Job> {
        if now < self.tunnel_delay_due()? {
            return None;
        }
        self.delay_last_auto = Some(now);
        self.tunnel_delay = TunnelDelay::Measuring;
        Some(Job::TunnelDelay)
    }

    pub(super) fn helper_result(&mut self, result: Result<(), HelperCommandError>) {
        self.operation_error = result
            .err()
            .map(|error| self.text(&errors::helper_command(crate::i18n::language(), &error)));
    }

    pub(super) fn reduce_connection(&mut self, event: WorkerEvent) {
        match event {
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
                self.refresh_cached_request();
                self.clear_applied_state();
                self.session.session_snapshot_checked = false;
                self.session.helper_lost();
                self.session.queued_leave_apply = None;
                self.operations.helper = false;
                self.clear_traffic_history();
                self.helper_error = Some(error);
                self.protection_confirmation = false;
                self.lockdown_confirmation = None;
                self.lockdown_lan_pending = false;
                self.lockdown_lan_sync = false;
                self.reset_failure_interference();
                self.reset_system_failure();
                self.cancel_in_flight = false;
                self.connect_in_flight = false;
                self.cancelled_connect = true;
                self.deferred_connect = None;
            }
            WorkerEvent::Status(status) => {
                if status.state.is_transitional() && !self.status.state.is_transitional() {
                    self.reset_system_failure();
                }
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
                if self.status.state != status.state {
                    self.failure_details_open = false;
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
                        self.refresh_cached_request();
                        self.session.temporary_rules_loaded = true;
                        self.session.temporary_load = None;
                        self.session.session_request = Some(request);
                        self.refresh_cached_request();
                        self.session.lists_changed_since_apply = false;
                        self.traffic.lists.forget();
                        self.clear_delayed_list_updates();
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
            WorkerEvent::Disconnect(result) => {
                let cancelling = std::mem::take(&mut self.cancel_in_flight);
                self.operations.helper = cancelling && self.connect_in_flight;
                if result.is_ok() {
                    self.protection_confirmation = false;
                    self.deferred_connect = None;
                    self.session.session_request = None;
                    self.refresh_cached_request();
                    self.clear_temporary();
                    self.clear_applied_state();
                } else if cancelling {
                    self.cancelled_connect = false;
                    if let Some(request) = self.deferred_connect.take() {
                        self.session.temporary_rules = request.temporary_rules.clone();
                        self.refresh_cached_request();
                        self.session.temporary_rules_loaded = true;
                        self.session.session_request = Some(request);
                        self.refresh_cached_request();
                        self.session.lists_changed_since_apply = false;
                        self.traffic.lists.forget();
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
                self.connect_after_choice &= result.is_ok();
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
            WorkerEvent::SetKillSwitch(result) => {
                self.operations.kill_switch = false;
                self.operation_error = result
                    .err()
                    .map(|error| self.text(&errors::store(crate::i18n::language(), &error)));
            }
            WorkerEvent::SetLockdown { enabled, result } => {
                self.operations.lockdown = false;
                let lan_sync = std::mem::take(&mut self.lockdown_lan_sync);
                match result {
                    Ok(change) => {
                        if change == LockdownChange::Done {
                            self.status.lockdown = enabled;
                            self.lockdown_lan_kept = false;
                        } else if lan_sync {
                            self.lockdown_lan_kept = true;
                        }
                        self.lockdown_confirmation = None;
                        self.operation_error = None;
                    }
                    Err(error) => self.helper_result(Err(error)),
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
                    Ok(delays) => TunnelDelay::Done(delays),
                    Err(HelperCommandError::Client(ClientError::Helper(HelperError {
                        code: ErrorCode::InvalidState | ErrorCode::Busy,
                        ..
                    }))) => TunnelDelay::Idle,
                    Err(_) => TunnelDelay::Done(TunnelDelays {
                        proxy: ProbeOutcome::Fails,
                        exits: Vec::new(),
                    }),
                };
            }
            _ => unreachable!("only connection events are dispatched here"),
        }
    }

    pub(super) fn act_connection(&mut self, action: Action) -> Option<Job> {
        match action {
            Action::ShowConnection => return self.show_screen(Screen::Connection),
            Action::Primary => {
                let job = match self.primary_action() {
                    PrimaryAction::Connect | PrimaryAction::Retry | PrimaryAction::Reconnect => {
                        Job::Connect(self.exit_inputs())
                    }
                    PrimaryAction::Disconnect => Job::Disconnect,
                    PrimaryAction::Disabled => return None,
                };
                self.connect_in_flight = matches!(job, Job::Connect(_));
                if self.connect_in_flight {
                    self.reset_failure_interference();
                    self.reset_system_failure();
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
            Action::SelectNodeFromTray(subscription, node) => {
                let disconnected = matches!(
                    self.visible_status().map(|status| &status.state),
                    Some(ConnectionState::Disconnected | ConnectionState::Failed { .. })
                );
                let job = self.act_connection(Action::SelectNode(subscription, node));
                if job.is_some() {
                    self.connect_after_choice = disconnected;
                }
                return job;
            }
            Action::ToggleExitReveal => {
                if matches!(self.exit, ExitLookup::Known { .. }) {
                    self.exit_revealed = !self.exit_revealed;
                }
            }
            Action::ToggleFailureDetails => {
                if self.failure_details().is_some() {
                    self.failure_details_open = !self.failure_details_open;
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
                if self.config_ready
                    && !self.operations.kill_switch
                    && !self.operations.helper
                    && !self.lockdown_active()
                {
                    self.operations.kill_switch = true;
                    self.operation_error = None;
                    return Some(Job::SetKillSwitch(enabled));
                }
            }
            Action::RequestLockdown(enabled) => {
                if self.can_change_lockdown() && enabled != self.lockdown_active() {
                    self.operation_error = None;
                    self.lockdown_confirmation = Some(enabled);
                }
            }
            Action::CancelLockdown => {
                if !self.operations.lockdown {
                    self.lockdown_confirmation = None;
                }
            }
            Action::ConfirmLockdown => {
                if let Some(enabled) = self.lockdown_confirmation
                    && self.can_change_lockdown()
                {
                    self.operations.lockdown = true;
                    self.lockdown_lan_sync = false;
                    self.operation_error = None;
                    return Some(Job::SetLockdown(enabled));
                }
            }
            _ => unreachable!("only connection actions are dispatched here"),
        }
        None
    }
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
