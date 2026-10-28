//! Quitting the client while the service holds a tunnel: ask, disconnect first, or leave it.

use rosetun_config::{ConnectionState, QuitAction};

use super::{Action, Job, State};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuitDecision {
    Ask,
    Disconnect,
    Leave,
}

#[derive(Debug, Default)]
pub(crate) struct QuitState {
    pub(crate) asking: bool,
    pub(crate) remember: bool,
    /// The answer, waiting for the app to act on it: `true` disconnects first.
    answered: Option<bool>,
}

/// `state` is `None` while the service cannot be reached.
fn holds_tunnel(state: Option<&ConnectionState>) -> bool {
    matches!(
        state,
        Some(
            ConnectionState::Connected
                | ConnectionState::Connecting
                | ConnectionState::Reconnecting
                | ConnectionState::FailedProtected { .. }
        )
    )
}

/// A Windows session that is ending never waits for an answer.
pub(crate) fn quit_decision(
    state: Option<&ConnectionState>,
    action: QuitAction,
    session_ending: bool,
) -> QuitDecision {
    if session_ending || !holds_tunnel(state) {
        return QuitDecision::Leave;
    }
    match action {
        QuitAction::Ask => QuitDecision::Ask,
        QuitAction::Disconnect => QuitDecision::Disconnect,
        QuitAction::KeepConnected => QuitDecision::Leave,
    }
}

impl State {
    pub(crate) fn quit_decision(&self, session_ending: bool) -> QuitDecision {
        quit_decision(
            self.visible_status().map(|status| &status.state),
            self.config.interface.quit_action,
            session_ending,
        )
    }

    pub(crate) fn open_quit_dialog(&mut self) {
        if !self.quit.asking {
            self.quit = QuitState {
                asking: true,
                ..QuitState::default()
            };
        }
    }

    pub(crate) fn take_quit(&mut self) -> Option<bool> {
        self.quit.answered.take()
    }

    /// The same request as the Disconnect button, or as cancelling a connect in progress.
    pub(crate) fn quit_disconnect(&mut self) -> Option<Job> {
        if !self.helper_available {
            return None;
        }
        match self.status.state {
            ConnectionState::Connecting | ConnectionState::Reconnecting => {
                self.act_connection(Action::CancelConnection)
            }
            ConnectionState::Connected | ConnectionState::FailedProtected { .. } => {
                self.operations.helper = true;
                self.operation_error = None;
                Some(Job::Disconnect)
            }
            ConnectionState::Disconnected | ConnectionState::Failed { .. } => None,
        }
    }

    /// Nothing the quit started is still on its way: the service answered,
    /// settings are saved and, when disconnecting, the tunnel is gone.
    pub(crate) fn quit_settled(&self, disconnecting: bool) -> bool {
        let tunnel_left =
            disconnecting && holds_tunnel(self.visible_status().map(|status| &status.state));
        !(self.operations.helper || self.saves_settings() || tunnel_left)
    }

    pub(crate) fn saves_settings(&self) -> bool {
        self.operations.settings.is_some() || !self.settings.queued.is_empty()
    }

    pub(super) fn act_quit(&mut self, action: Action) -> Option<Job> {
        match action {
            Action::SetRememberQuit(remember) => self.quit.remember = remember,
            Action::CancelQuit => self.quit = QuitState::default(),
            Action::Quit { disconnect } => {
                if !self.quit.asking {
                    return None;
                }
                let remember = self.quit.remember;
                self.quit = QuitState {
                    answered: Some(disconnect),
                    ..QuitState::default()
                };
                if remember {
                    let action = if disconnect {
                        QuitAction::Disconnect
                    } else {
                        QuitAction::KeepConnected
                    };
                    return self.act(Action::SetOnQuit(action));
                }
            }
            _ => unreachable!("only quit actions are dispatched here"),
        }
        None
    }
}
