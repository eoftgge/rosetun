//! Keeps the desktop's proxy settings in step with the session: pointed at the
//! local proxy while it listens, and back to the user's otherwise.

use rosetun_config::ConnectionState;

use super::{Job, State};
use crate::worker::{SystemProxyOutcome, SystemProxyWish};

/// What the GUI has asked of the desktop.
#[derive(Debug, Default)]
pub(crate) struct SystemProxySync {
    applied: Option<SystemProxyWish>,
    in_flight: bool,
    /// The last change did not go through.
    pub(crate) failed: bool,
    /// This desktop's settings cannot be changed: the user points programs at
    /// the proxy by hand.
    pub(crate) manual: bool,
}

/// What the status asks of the desktop. `None` keeps what is there: an engine
/// restart is short, and programs would lose their proxy only to get it back.
fn wish_for(
    state: &ConnectionState,
    local_proxy_port: Option<u16>,
    helper_available: bool,
) -> Option<SystemProxyWish> {
    if !helper_available {
        return Some(SystemProxyWish::Clear);
    }
    match (state, local_proxy_port) {
        (ConnectionState::Connected, Some(port)) => Some(SystemProxyWish::Listen(port)),
        (ConnectionState::Connected, None) => Some(SystemProxyWish::Clear),
        (ConnectionState::Connecting | ConnectionState::Reconnecting, _) => None,
        (ConnectionState::FailedProtected { .. }, Some(_)) => None,
        (
            ConnectionState::Disconnected
            | ConnectionState::Failed { .. }
            | ConnectionState::FailedProtected { .. },
            _,
        ) => Some(SystemProxyWish::Clear),
    }
}

impl State {
    /// The next change for the desktop, one at a time and only once the service
    /// has answered or is known to be away: this also restores what a crash left.
    pub(crate) fn take_system_proxy(&mut self) -> Option<Job> {
        if self.system_proxy.in_flight || (self.helper_available && !self.status_received) {
            return None;
        }
        let wish = wish_for(
            &self.status.state,
            self.status.local_proxy_port,
            self.helper_available,
        )?;
        if self.system_proxy.applied == Some(wish) {
            return None;
        }
        self.system_proxy.in_flight = true;
        Some(Job::SyncSystemProxy(wish))
    }

    pub(super) fn reduce_system_proxy(
        &mut self,
        wish: SystemProxyWish,
        outcome: SystemProxyOutcome,
    ) {
        let sync = &mut self.system_proxy;
        sync.in_flight = false;
        // A failure counts as done: the next change of state tries again, not
        // every frame.
        sync.applied = Some(wish);
        sync.failed = outcome == SystemProxyOutcome::Failed;
        sync.manual = outcome == SystemProxyOutcome::Manual;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed() -> ConnectionState {
        ConnectionState::Failed {
            reason: String::new(),
            failure_kind: None,
        }
    }

    fn held() -> ConnectionState {
        ConnectionState::FailedProtected {
            reason: String::new(),
            failure_kind: None,
        }
    }

    #[test]
    fn the_proxy_is_set_only_while_the_session_listens() {
        use SystemProxyWish::{Clear, Listen};
        let wish = |state: &ConnectionState, port| wish_for(state, port, true);
        assert_eq!(
            wish(&ConnectionState::Connected, Some(10808)),
            Some(Listen(10808))
        );
        assert_eq!(wish(&ConnectionState::Connected, None), Some(Clear));
        assert_eq!(wish(&ConnectionState::Disconnected, None), Some(Clear));
        assert_eq!(
            wish(&ConnectionState::Disconnected, Some(10808)),
            Some(Clear)
        );
        assert_eq!(wish(&failed(), Some(10808)), Some(Clear));
    }

    #[test]
    fn an_engine_restart_keeps_the_settings_where_they_are() {
        let wish = |state: &ConnectionState, port| wish_for(state, port, true);
        assert_eq!(wish(&ConnectionState::Connecting, Some(10808)), None);
        assert_eq!(wish(&ConnectionState::Reconnecting, Some(10808)), None);
        assert_eq!(wish(&ConnectionState::Reconnecting, None), None);
        assert_eq!(wish(&held(), Some(10808)), None);
        assert_eq!(wish(&held(), None), Some(SystemProxyWish::Clear));
    }

    #[test]
    fn a_service_that_is_away_gives_the_settings_back() {
        assert_eq!(
            wish_for(&ConnectionState::Connected, Some(10808), false),
            Some(SystemProxyWish::Clear)
        );
    }
}
