use std::collections::VecDeque;

use rosetun_config::{ConnectionRoute, ConnectionState, LiveConnection, Status};
use rosetun_ipc::{ClientError, ErrorCode, HelperError};

use super::{Action, Job, Screen, State};
use crate::worker::HelperCommandError;

pub(super) const TRAFFIC_HISTORY: usize = 900;

/// An answer older than this is from an earlier visit to the tab and is not shown.
const CONNECTIONS_STALE_SECS: u64 = 3;

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
pub(crate) enum ConnectionsTab {
    #[default]
    Active,
    Closed,
}

/// Why the connections table shows no rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionsNotice {
    Disconnected,
    Denied,
    Loading,
    Empty,
    NoMatch,
}

/// The session's connections as the service last answered, newest first.
/// Memory only: the list is the user's browsing history.
#[derive(Default)]
pub(crate) struct ConnectionsList {
    pub(crate) tab: ConnectionsTab,
    pub(crate) filter: String,
    pub(crate) active: Vec<LiveConnection>,
    pub(crate) closed: Vec<LiveConnection>,
    /// The service answered since the tab was opened.
    pub(crate) received: bool,
    /// The tunnel belongs to another Windows account.
    pub(crate) denied: bool,
    pending: bool,
    last_request: Option<u64>,
}

impl ConnectionsList {
    fn forget(&mut self) {
        self.active = Vec::new();
        self.closed = Vec::new();
        self.received = false;
        self.denied = false;
    }

    /// The selected tab's connections that match the filter by program or
    /// address, ignoring letter case.
    pub(crate) fn visible(&self) -> Vec<&LiveConnection> {
        let list = match self.tab {
            ConnectionsTab::Active => &self.active,
            ConnectionsTab::Closed => &self.closed,
        };
        let filter = self.filter.trim().to_lowercase();
        list.iter()
            .filter(|connection| {
                filter.is_empty()
                    || connection.host.to_lowercase().contains(&filter)
                    || format!("{}:{}", connection.host, connection.port)
                        .to_lowercase()
                        .contains(&filter)
                    || connection
                        .process
                        .as_deref()
                        .is_some_and(|process| process.to_lowercase().contains(&filter))
            })
            .collect()
    }
}

#[derive(Default)]
pub(crate) struct TrafficState {
    /// Rates of the last 15 minutes, one sample per status; newest last.
    pub(crate) traffic_history: VecDeque<(u64, u64)>,
    pub(crate) traffic_range: TrafficRange,
    pub(crate) connections: ConnectionsList,
    /// The window is hidden in the tray, so nobody sees the list.
    window_hidden: bool,
}

impl State {
    pub(super) fn reduce_traffic_status(&mut self, status: &Status) {
        if self.helper_available
            && matches!(
                status.state,
                ConnectionState::Connected | ConnectionState::Reconnecting
            )
        {
            self.traffic
                .traffic_history
                .push_back((status.traffic.down_bps, status.traffic.up_bps));
            if self.traffic.traffic_history.len() > TRAFFIC_HISTORY {
                self.traffic.traffic_history.pop_front();
            }
        } else {
            self.traffic.traffic_history.clear();
            self.traffic.connections.forget();
        }
    }

    pub(super) fn clear_traffic_history(&mut self) {
        self.traffic.traffic_history.clear();
        self.traffic.connections.forget();
    }

    pub(crate) fn set_window_hidden(&mut self, hidden: bool) {
        self.traffic.window_hidden = hidden;
    }

    /// Whether there is a tunnel whose connections the service can list.
    pub(crate) fn connections_available(&self) -> bool {
        self.helper_available
            && self.visible_status().is_some_and(|status| {
                matches!(
                    status.state,
                    ConnectionState::Connected | ConnectionState::Reconnecting
                )
            })
    }

    /// Once a second, only while the Traffic tab is on screen.
    pub(super) fn connections_due(&self) -> Option<u64> {
        if self.screen != Screen::Traffic
            || self.traffic.window_hidden
            || self.traffic.connections.pending
            || !self.connections_available()
        {
            return None;
        }
        Some(
            self.traffic
                .connections
                .last_request
                .map_or(0, |last| last.saturating_add(1)),
        )
    }

    pub(crate) fn take_connections(&mut self, now: u64) -> Option<Job> {
        if now < self.connections_due()? {
            return None;
        }
        let list = &mut self.traffic.connections;
        if list
            .last_request
            .is_none_or(|last| now.saturating_sub(last) > CONNECTIONS_STALE_SECS)
        {
            list.forget();
        }
        list.pending = true;
        list.last_request = Some(now);
        Some(Job::Connections)
    }

    pub(super) fn reduce_connections(
        &mut self,
        result: Result<(Vec<LiveConnection>, Vec<LiveConnection>), HelperCommandError>,
    ) {
        self.traffic.connections.pending = false;
        if !self.connections_available() {
            self.traffic.connections.forget();
            return;
        }
        let list = &mut self.traffic.connections;
        match result {
            Ok((active, closed)) => {
                list.active = active;
                list.closed = closed;
                list.received = true;
                list.denied = false;
            }
            Err(HelperCommandError::Client(ClientError::Helper(HelperError {
                code: ErrorCode::AccessDenied,
                ..
            }))) => {
                list.forget();
                list.denied = true;
            }
            // A busy service or a lost pipe keeps the last answer until the next second.
            Err(_) => {}
        }
    }

    /// What to show instead of the table, or `None` when it has rows.
    pub(crate) fn connections_notice(&self) -> Option<ConnectionsNotice> {
        let list = &self.traffic.connections;
        if !self.connections_available() {
            Some(ConnectionsNotice::Disconnected)
        } else if list.denied {
            Some(ConnectionsNotice::Denied)
        } else if !list.received {
            Some(ConnectionsNotice::Loading)
        } else if match list.tab {
            ConnectionsTab::Active => list.active.is_empty(),
            ConnectionsTab::Closed => list.closed.is_empty(),
        } {
            Some(ConnectionsNotice::Empty)
        } else if list.visible().is_empty() {
            Some(ConnectionsNotice::NoMatch)
        } else {
            None
        }
    }

    /// "Through VPN", "Direct", or the exit's name.
    pub(crate) fn connection_route_label(&self, route: &ConnectionRoute) -> String {
        match route {
            ConnectionRoute::Proxy => tr!("proxy"),
            ConnectionRoute::Direct => tr!("direct"),
            ConnectionRoute::Exit(id) => self
                .config
                .exits
                .iter()
                .find(|exit| &exit.id == id)
                .map_or_else(
                    || tr!("target-exit-any"),
                    |exit| crate::display::safe_text(&exit.name),
                ),
            ConnectionRoute::Other => tr!("connections-route-other"),
        }
    }

    pub(super) fn act_traffic(&mut self, action: Action) -> Option<Job> {
        match action {
            Action::OpenTraffic => self.show_screen(Screen::Traffic),
            Action::SetTrafficRange(range) => {
                self.traffic.traffic_range = range;
                None
            }
            Action::SetConnectionsTab(tab) => {
                self.traffic.connections.tab = tab;
                None
            }
            Action::SetConnectionsFilter(filter) => {
                self.traffic.connections.filter = filter;
                None
            }
            _ => unreachable!("only traffic actions are dispatched here"),
        }
    }
}
