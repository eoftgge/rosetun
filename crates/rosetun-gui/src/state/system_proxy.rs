//! Keeps the desktop's proxy settings in step with the session: pointed at the
//! local proxy while it listens, and back to the user's otherwise.

use std::net::IpAddr;

use rosetun_config::{ConnectionMode, ConnectionState};

use super::{Action, Job, State};
use crate::display;
use crate::worker::{SystemProxyOutcome, SystemProxyWish};

/// How often the shown address for other devices is read again while it shows:
/// the computer moves between networks, and the read costs nothing.
const LAN_ADDRESS_INTERVAL_MS: u64 = 10_000;

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
    /// A change of port or sharing is saved, and the running session
    /// should take it, once the save is through.
    session_follows: bool,
    /// The computer's address for other devices.
    pub(crate) lan_address: Option<IpAddr>,
    lan_address_read_ms: Option<u64>,
    lan_address_in_flight: bool,
}

impl SystemProxySync {
    pub(super) fn follow_session(&mut self) {
        self.session_follows = true;
    }
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

    /// Port and sharing changes follow the session under its standing protection.
    pub(crate) fn take_local_proxy_apply(&mut self) -> Option<Job> {
        if !self.system_proxy.session_follows {
            return None;
        }
        if !self.session_up() {
            self.system_proxy.session_follows = false;
            return None;
        }
        if self.connection_mode_next_connect()
            || !self.can_apply()
            || !self.pending_reconnect(super::SessionPart::LocalProxy)
        {
            return None;
        }
        self.system_proxy.session_follows = false;
        self.act(Action::Apply)
    }

    /// The kill switch's caption: in the proxy mode it holds all the time.
    pub(crate) fn kill_switch_detail(&self) -> String {
        match self.config.settings.connection_mode {
            ConnectionMode::Tun => tr!("kill-switch-detail"),
            ConnectionMode::SystemProxy => tr!("kill-switch-proxy-detail"),
        }
    }

    pub(crate) fn session_kill_switch_detail(&self) -> String {
        match self.status.protection.connection_mode {
            Some(ConnectionMode::Tun) => tr!("kill-switch-detail"),
            Some(ConnectionMode::SystemProxy) => tr!("kill-switch-proxy-detail"),
            None => self.kill_switch_detail(),
        }
    }

    /// What goes through the VPN in the chosen mode, and what happens to the rest.
    pub(crate) fn connection_mode_detail(&self) -> String {
        let settings = &self.config.settings;
        match settings.connection_mode {
            ConnectionMode::Tun => tr!("connection-mode-tun-detail"),
            ConnectionMode::SystemProxy if settings.kill_switch || self.lockdown_active() => {
                tr!("connection-mode-proxy-strict-detail")
            }
            ConnectionMode::SystemProxy => tr!("connection-mode-proxy-detail"),
        }
    }

    /// Lockdown keeps its own "Local network", which follows this setting
    /// unless the last change could not reach it.
    pub(crate) fn lockdown_lan_open(&self) -> bool {
        self.config.settings.allow_lan && !self.lockdown_lan_kept
    }

    /// Whether other devices can use the session's proxy, as far as the settings say.
    pub(crate) fn shares_local_proxy(&self) -> bool {
        let settings = &self.config.settings;
        settings.connection_mode == ConnectionMode::SystemProxy && settings.local_proxy.share_on_lan
    }

    pub(crate) fn take_lan_address(&mut self) -> Option<Job> {
        if !self.shares_local_proxy() || self.system_proxy.lan_address_in_flight {
            return None;
        }
        let now = display::monotonic_ms();
        let read = self.system_proxy.lan_address_read_ms;
        if read.is_some_and(|read| now.saturating_sub(read) < LAN_ADDRESS_INTERVAL_MS) {
            return None;
        }
        self.system_proxy.lan_address_read_ms = Some(now);
        self.system_proxy.lan_address_in_flight = true;
        Some(Job::ReadLanAddress)
    }

    pub(super) fn reduce_lan_address(&mut self, address: Option<IpAddr>) {
        self.system_proxy.lan_address_in_flight = false;
        self.system_proxy.lan_address = address;
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
