use rosetun_config::{ConnectionState, FailureKind, Status};
use rosetun_core::AppliedSnapshot;
use rosetun_ipc::{ClientError, ErrorCode, HelperError, ProbeOutcome};

use super::{Action, Job, Screen, State};
use crate::actions::{self, PrimaryAction};
use crate::errors;
use crate::worker::{HelperCommandError, WorkerEvent};

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
            WorkerEvent::SetKillSwitch(result) => {
                self.operations.kill_switch = false;
                self.operation_error = result
                    .err()
                    .map(|error| self.text(&errors::store(crate::i18n::language(), &error)));
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
            _ => unreachable!("only connection events are dispatched here"),
        }
    }

    pub(super) fn act_connection(&mut self, action: Action) -> Option<Job> {
        match action {
            Action::ShowConnection => return self.show_screen(Screen::Connection),
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
