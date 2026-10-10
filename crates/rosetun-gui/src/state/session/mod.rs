use rosetun_config::{ConnectionState, Rule, RuleId, Status};
use rosetun_core::AppliedSnapshot;
use rosetun_ipc::{ClientError, ConnectRequest, ErrorCode, HelperError};

use super::{Action, Job, Screen, State, TunnelDelay};
use crate::errors;
use crate::rules::RuleFilter;
use crate::worker::{HelperCommandError, WorkerEvent};

pub(crate) enum SessionPart {
    Server,
    Rules,
    Dns,
    Protection,
}

enum ApplyFlow {
    Idle,
    Applying {
        baseline: Option<AppliedSnapshot>,
        // Disconnect clears the snapshot but keeps the in-flight completion pending.
        candidate: Option<AppliedSnapshot>,
        temporary_before: Option<Vec<Rule>>,
    },
    RestoringApplied {
        reason: String,
        queued_baseline: Option<AppliedSnapshot>,
    },
    RestoringEdits,
}

impl ApplyFlow {
    fn restore_pending(&self) -> bool {
        matches!(self, Self::RestoringApplied { .. } | Self::RestoringEdits)
    }

    fn applying(&self) -> bool {
        matches!(self, Self::Applying { .. })
    }
}

// Recoverable edits remain available while a later apply is in flight.
#[derive(Default)]
enum ApplyRecovery {
    #[default]
    Clean,
    Blocked(AppliedSnapshot),
    Restorable {
        edits: AppliedSnapshot,
        message: Option<String>,
        blocked: Option<AppliedSnapshot>,
    },
}

impl ApplyRecovery {
    fn failed_edits(&self) -> Option<&AppliedSnapshot> {
        match self {
            Self::Restorable { edits, .. } => Some(edits),
            _ => None,
        }
    }

    fn blocked(&self) -> Option<&AppliedSnapshot> {
        match self {
            Self::Blocked(candidate) => Some(candidate),
            Self::Restorable { blocked, .. } => blocked.as_ref(),
            Self::Clean => None,
        }
    }

    fn message(&self) -> Option<&str> {
        match self {
            Self::Restorable { message, .. } => message.as_deref(),
            _ => None,
        }
    }

    fn clear_message(&mut self) {
        if let Self::Restorable { message, .. } = self {
            *message = None;
        }
    }

    fn clear_block(&mut self) {
        match self {
            Self::Blocked(_) => *self = Self::Clean,
            Self::Restorable { blocked, .. } => *blocked = None,
            Self::Clean => {}
        }
    }

    fn block(&mut self, candidate: Option<AppliedSnapshot>) {
        match self {
            Self::Restorable { blocked, .. } => *blocked = candidate,
            _ => *self = candidate.map_or(Self::Clean, Self::Blocked),
        }
    }

    fn restored(&mut self, edits: AppliedSnapshot, message: String) {
        *self = Self::Restorable {
            edits,
            message: Some(message),
            blocked: self.blocked().cloned(),
        };
    }
}

#[derive(Clone, Copy, Default)]
enum AutoApplyIntent {
    #[default]
    None,
    Choice,
    Leave,
    Both,
}

impl AutoApplyIntent {
    fn after_choice(self) -> bool {
        matches!(self, Self::Choice | Self::Both)
    }

    fn after_leave(self) -> bool {
        matches!(self, Self::Leave | Self::Both)
    }

    fn set_choice(&mut self, enabled: bool) {
        *self = match (enabled, self.after_leave()) {
            (false, false) => Self::None,
            (true, false) => Self::Choice,
            (false, true) => Self::Leave,
            (true, true) => Self::Both,
        };
    }

    fn set_leave(&mut self, enabled: bool) {
        *self = match (self.after_choice(), enabled) {
            (false, false) => Self::None,
            (true, false) => Self::Choice,
            (false, true) => Self::Leave,
            (true, true) => Self::Both,
        };
    }
}

pub(crate) struct SessionState {
    pub(super) session_request: Option<ConnectRequest>,
    pub(super) applied_snapshot: Option<AppliedSnapshot>,
    pub(super) connect_snapshot: Option<AppliedSnapshot>,
    pub(super) deferred_snapshot: Option<AppliedSnapshot>,
    flow: ApplyFlow,
    recovery: ApplyRecovery,
    intent: AutoApplyIntent,
    pub(crate) temporary_rules: Vec<Rule>,
    pub(super) temporary_rules_loaded: bool,
    pub(super) temporary_load: Option<u64>,
    pub(super) next_temporary_load: u64,
    pub(super) temporary_retry: bool,
    pub(super) temporary_waiting_status: bool,
    pub(super) temporary_last_load: Option<u64>,
    pub(super) temporary_error_reported: bool,
    pub(super) keep_temporary: Option<RuleId>,
    pub(super) keep_apply: Option<RuleId>,
    pub(super) session_snapshot_checked: bool,
    pub(super) queued_leave_apply: Option<Job>,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            session_request: None,
            applied_snapshot: None,
            connect_snapshot: None,
            deferred_snapshot: None,
            flow: ApplyFlow::Idle,
            recovery: ApplyRecovery::default(),
            intent: AutoApplyIntent::None,
            temporary_rules: Vec::new(),
            temporary_rules_loaded: false,
            temporary_load: None,
            next_temporary_load: 0,
            temporary_retry: true,
            temporary_waiting_status: false,
            temporary_last_load: None,
            temporary_error_reported: false,
            keep_temporary: None,
            keep_apply: None,
            session_snapshot_checked: false,
            queued_leave_apply: None,
        }
    }
}

impl SessionState {
    pub(super) fn set_apply_after_choice(&mut self, enabled: bool) {
        self.intent.set_choice(enabled);
    }

    pub(super) fn helper_lost(&mut self) {
        self.flow = ApplyFlow::Idle;
        self.intent = AutoApplyIntent::None;
    }

    #[cfg(test)]
    pub(in crate::state) fn restore_pending(&self) -> bool {
        self.flow.restore_pending()
    }

    #[cfg(test)]
    pub(in crate::state) fn apply_after_leave(&self) -> bool {
        self.intent.after_leave()
    }

    #[cfg(test)]
    pub(in crate::state) fn apply_after_choice(&self) -> bool {
        self.intent.after_choice()
    }

    pub(crate) fn apply_failure(&self) -> Option<&str> {
        self.recovery.message()
    }

    #[cfg(test)]
    pub(in crate::state) fn failed_edits(&self) -> Option<&AppliedSnapshot> {
        self.recovery.failed_edits()
    }
}

impl State {
    pub(crate) fn pending_reconnect(&self, part: SessionPart) -> bool {
        let Some(session) = &self.session.session_request else {
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
        let session = self.session.session_request.as_ref()?;
        let mut request = ConnectRequest::from_config(&self.config).ok()?;
        request.settings.engine = session.settings.engine;
        request.settings.tun = session.settings.tun.clone();
        request.settings.kill_switch = session.settings.kill_switch;
        request.settings.allow_lan = session.settings.allow_lan;
        request.temporary_rules = self.session.temporary_rules.clone();
        Some(request)
    }

    pub(crate) fn can_change_temporary(&self) -> bool {
        self.helper_available
            && self.config_ready
            && self.session.temporary_rules_loaded
            && !self.operations.helper
            && !self.session.flow.restore_pending()
            && self.session.session_request.is_some()
            && matches!(
                self.visible_status().map(|status| &status.state),
                Some(ConnectionState::Connected)
            )
    }

    fn has_pending_apply(&self) -> bool {
        let Some(session) = &self.session.session_request else {
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

    pub(super) fn start_apply(&mut self, temporary_before: Option<Vec<Rule>>) {
        self.operations.helper = true;
        self.session.flow = ApplyFlow::Applying {
            baseline: self.session.applied_snapshot.clone(),
            candidate: Some(AppliedSnapshot::from_config(&self.config)),
            temporary_before,
        };
        self.session.recovery.clear_message();
        self.session.recovery.clear_block();
        self.operation_error = None;
    }

    pub(crate) fn apply_on_leave(&mut self) -> Option<Job> {
        if self.saving_config() {
            if self.helper_available
                && !self.session.flow.restore_pending()
                && matches!(self.status.state, ConnectionState::Connected)
            {
                self.session.intent.set_leave(true);
            }
            return None;
        }
        if self
            .session
            .recovery
            .blocked()
            .is_some_and(|blocked| blocked == &AppliedSnapshot::from_config(&self.config))
        {
            return None;
        }
        self.session.recovery.clear_block();
        if self.can_apply() {
            return self.act(Action::Apply);
        }
        if self.session.flow.applying() && self.has_pending_apply() {
            self.session.intent.set_leave(true);
        }
        None
    }

    pub(super) fn show_screen(&mut self, screen: Screen) -> Option<Job> {
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
        self.session.queued_leave_apply.take()
    }

    pub(crate) fn take_restore(&mut self) -> Option<Job> {
        match &mut self.session.flow {
            ApplyFlow::RestoringApplied {
                queued_baseline, ..
            } => queued_baseline.take().map(Job::RestoreApplied),
            _ => None,
        }
    }

    pub(crate) fn can_restore_edits(&self) -> bool {
        self.session.recovery.failed_edits().is_some()
            && self.config_ready
            && !self.session.flow.restore_pending()
            && !self.operations.helper
            && !self.operations.settings
            && !self.operations.rules_edit
    }

    pub(crate) fn take_apply(&mut self) -> Option<Job> {
        if !(self.session.intent.after_choice() || self.session.intent.after_leave())
            || !self.session.temporary_rules_loaded
            || self.operations.helper
            || self.saving_config()
            || self.session.flow.restore_pending()
        {
            return None;
        }
        self.session.intent = AutoApplyIntent::None;
        self.act(Action::Apply)
    }

    pub(crate) fn take_temporary_load(&mut self, now: u64) -> Option<Job> {
        if !self.helper_available
            || !self.status_received
            || !matches!(self.status.state, ConnectionState::Connected)
            || self.session.temporary_rules_loaded
            || self.session.temporary_load.is_some()
            || !self.session.temporary_retry
            || self.operations.helper
            || self
                .session
                .temporary_last_load
                .is_some_and(|last| now.saturating_sub(last) < 10)
        {
            return None;
        }
        self.session.next_temporary_load += 1;
        self.session.temporary_load = Some(self.session.next_temporary_load);
        self.session.temporary_retry = false;
        self.session.temporary_last_load = Some(now);
        Some(Job::LoadTemporaryRules(self.session.next_temporary_load))
    }

    pub(crate) fn take_keep_apply(&mut self) -> Option<Job> {
        if !self.can_change_temporary() {
            return None;
        }
        let id = self.session.keep_apply.take()?;
        self.act(Action::RemoveTemporary(id))
    }

    pub(super) fn clear_applied_state(&mut self) {
        self.session.applied_snapshot = None;
        self.session.connect_snapshot = None;
        self.session.deferred_snapshot = None;
        if let ApplyFlow::Applying {
            baseline,
            candidate,
            ..
        } = &mut self.session.flow
        {
            *baseline = None;
            *candidate = None;
        } else {
            self.session.flow = ApplyFlow::Idle;
        }
        self.session.recovery = ApplyRecovery::default();
        self.session.intent.set_leave(false);
    }

    pub(super) fn clear_temporary(&mut self) {
        self.session.temporary_rules.clear();
        self.session.temporary_rules_loaded = false;
        self.session.temporary_load = None;
        self.session.temporary_retry = true;
        self.session.temporary_waiting_status = false;
        self.session.temporary_last_load = None;
        self.session.temporary_error_reported = false;
        if let ApplyFlow::Applying {
            temporary_before, ..
        } = &mut self.session.flow
        {
            *temporary_before = None;
        }
        self.session.keep_temporary = None;
        self.session.keep_apply = None;
    }

    pub(super) fn reduce_session_status(&mut self, status: &Status) {
        if self.session.temporary_waiting_status
            && matches!(status.state, ConnectionState::Connected)
        {
            self.session.temporary_retry = true;
            self.session.temporary_waiting_status = false;
        }
        if self.helper_available {
            match status.state {
                ConnectionState::Disconnected
                | ConnectionState::Failed { .. }
                | ConnectionState::FailedProtected { .. } => {
                    self.session.session_request = None;
                    self.session.session_snapshot_checked = false;
                    self.session.intent.set_choice(false);
                    if matches!(status.state, ConnectionState::Disconnected) {
                        self.clear_applied_state();
                    } else {
                        self.session.applied_snapshot = None;
                        if !self.session.flow.applying() {
                            self.session.intent.set_leave(false);
                        }
                    }
                    self.clear_temporary();
                }
                ConnectionState::Connected
                    if self.session.session_request.is_none()
                        && !self.session.session_snapshot_checked
                        && self.config_ready
                        && !self.operations.helper
                        && !self.session.flow.restore_pending() =>
                {
                    self.session.session_snapshot_checked = true;
                    if let Ok(mut request) = ConnectRequest::from_config(&self.config)
                        && status.node.as_ref() == Some(&request.selection.node)
                    {
                        if self.session.temporary_rules_loaded {
                            request.temporary_rules = self.session.temporary_rules.clone();
                        }
                        self.session.session_request = Some(request);
                        self.session.applied_snapshot =
                            Some(AppliedSnapshot::from_config(&self.config));
                    }
                }
                _ => {}
            }
        }
    }

    pub(super) fn reduce_session(&mut self, event: WorkerEvent) {
        match event {
            WorkerEvent::TemporaryRules { request, result } => {
                if self.session.temporary_load != Some(request)
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
                self.session.temporary_load = None;
                match result {
                    Ok(rules) => {
                        if let Some(session) = &mut self.session.session_request {
                            session.temporary_rules = rules.clone();
                        }
                        self.session.temporary_rules = rules;
                        self.session.temporary_rules_loaded = true;
                        self.session.temporary_error_reported = false;
                        self.operation_error = None;
                    }
                    Err(HelperCommandError::Client(ClientError::Helper(HelperError {
                        code: ErrorCode::Busy,
                        ..
                    }))) => {
                        self.session.temporary_waiting_status = true;
                        self.session.temporary_last_load = None;
                    }
                    Err(error) => {
                        self.session.temporary_retry = true;
                        if !self.session.temporary_error_reported {
                            self.session.temporary_error_reported = true;
                            self.helper_result(Err(error));
                        }
                    }
                }
            }
            WorkerEvent::Apply(result) => {
                self.operations.helper = false;
                let flow = std::mem::replace(&mut self.session.flow, ApplyFlow::Idle);
                let (before, baseline, candidate) = match flow {
                    ApplyFlow::Applying {
                        baseline,
                        candidate,
                        temporary_before,
                    } => (temporary_before, baseline, candidate),
                    other => {
                        self.session.flow = other;
                        (None, None, None)
                    }
                };
                if !self.helper_available
                    || matches!(self.status.state, ConnectionState::Disconnected)
                {
                    self.session.intent.set_leave(false);
                    return;
                }
                match result {
                    Ok(request) => {
                        if matches!(
                            self.status.state,
                            ConnectionState::Failed { .. }
                                | ConnectionState::FailedProtected { .. }
                        ) {
                            self.session.intent.set_leave(false);
                            return;
                        }
                        self.session.temporary_rules = request.temporary_rules.clone();
                        self.session.session_request = Some(request);
                        self.session.applied_snapshot = candidate;
                        self.session.recovery = ApplyRecovery::default();
                        self.operation_error = None;
                        self.exit_route = None;
                        self.tunnel_delay = TunnelDelay::Idle;
                        self.delay_last_auto = None;
                    }
                    Err(error) => {
                        if let Some(before) = before {
                            self.session.temporary_rules = before;
                        }
                        self.session.intent = AutoApplyIntent::None;
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
                        self.session.recovery.block(candidate);
                        if changed {
                            self.session.flow = ApplyFlow::RestoringApplied {
                                reason,
                                queued_baseline: baseline,
                            };
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
                if !self.session.flow.restore_pending() {
                    return;
                }
                let flow = std::mem::replace(&mut self.session.flow, ApplyFlow::Idle);
                let reason = match flow {
                    ApplyFlow::RestoringApplied { reason, .. } => reason,
                    _ => String::new(),
                };
                match result {
                    Ok(failed) => {
                        let message =
                            self.text(&tr!("apply-failed-restored-template", reason = &reason));
                        self.session.recovery.restored(failed, message);
                        self.operation_error = None;
                        self.settings.screen.dirty = false;
                        if self.settings.screen.opened {
                            self.settings.screen.sync_dns(&self.config.settings.dns);
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
                if !self.session.flow.restore_pending() {
                    return;
                }
                self.session.flow = ApplyFlow::Idle;
                match result {
                    Ok(_) => {
                        self.session.recovery = ApplyRecovery::default();
                        self.operation_error = None;
                        self.settings.screen.dirty = false;
                        if self.settings.screen.opened {
                            self.settings.screen.sync_dns(&self.config.settings.dns);
                        }
                    }
                    Err(error) => {
                        self.operation_error =
                            Some(self.text(&errors::rule_set(crate::i18n::language(), &error)));
                    }
                }
            }
            _ => unreachable!("only session events are dispatched here"),
        }
    }

    pub(super) fn act_session(&mut self, action: Action) -> Option<Job> {
        match action {
            #[cfg(windows)]
            Action::WindowMinimized => return self.apply_on_leave(),
            Action::AddTemporary(matchers, target) => {
                if self.can_change_temporary()
                    && self.can_edit_rules()
                    && let Some(dialog) = &self.rules.screen.add
                    && dialog.temporary_only
                    && dialog.editing.is_none()
                    && !dialog.busy
                    && self.config.active_rule_set.as_ref() == Some(&dialog.set)
                    && self.rules.screen.selected_set.as_ref() == Some(&dialog.set)
                    && let Some(set) = self.selected_rules()
                {
                    let existing: Vec<_> = self
                        .session
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
                        if let Some(dialog) = &mut self.rules.screen.add {
                            dialog.error = Some(message);
                        }
                        return None;
                    }
                    let before = std::mem::take(&mut self.session.temporary_rules);
                    self.session.temporary_rules =
                        added.into_iter().chain(before.iter().cloned()).collect();
                    if let Some(request) = self.apply_request() {
                        self.start_apply(Some(before));
                        self.rules.screen.add = None;
                        self.rules.screen.filter = RuleFilter::default();
                        self.rules.screen.clear_selection();
                        return Some(Job::Apply(Box::new(request)));
                    }
                    self.session.temporary_rules = before;
                }
            }
            Action::RemoveTemporary(id) => {
                if self.can_change_temporary()
                    && !self.operations.rules_edit
                    && let Some(index) = self
                        .session
                        .temporary_rules
                        .iter()
                        .position(|rule| rule.id == id)
                {
                    let before = self.session.temporary_rules.clone();
                    self.session.temporary_rules.remove(index);
                    if let Some(request) = self.apply_request() {
                        self.start_apply(Some(before));
                        return Some(Job::Apply(Box::new(request)));
                    }
                    self.session.temporary_rules = before;
                }
            }
            Action::KeepTemporary(id) => {
                if self.can_change_temporary()
                    && self.can_edit_rules()
                    && self.session.keep_apply.is_none()
                    && self.config.active_rule_set == self.rules.screen.selected_set
                    && let Some(set) = self.selected_rules()
                    && let Some(rule) = self
                        .session
                        .temporary_rules
                        .iter()
                        .find(|rule| rule.id == id)
                {
                    let job =
                        Job::AddRules(set.id.clone(), vec![rule.matcher.clone()], rule.target);
                    self.session.keep_temporary = Some(id);
                    return self.start_rule_edit(job);
                }
            }
            Action::Apply => {
                if self.can_apply()
                    && let Some(request) = self.apply_request()
                {
                    self.start_apply(None);
                    return Some(Job::Apply(Box::new(request)));
                }
            }
            Action::RestoreMyEdits => {
                if self.can_restore_edits() {
                    self.session.flow = ApplyFlow::RestoringEdits;
                    return self
                        .session
                        .recovery
                        .failed_edits()
                        .cloned()
                        .map(Job::RestoreEdits);
                }
            }
            Action::DismissApplyFailure => self.session.recovery.clear_message(),
            _ => unreachable!("only session actions are dispatched here"),
        }
        None
    }
}
