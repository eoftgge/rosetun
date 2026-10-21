use std::collections::{HashMap, HashSet, VecDeque};

use rosetun_config::{
    ConnectionRoute, ConnectionState, DomainMatch, ExitId, LiveConnection, ProcessMatch,
    RuleMatcher, Status,
};
use rosetun_ipc::{ClientError, ErrorCode, HelperError};

use super::{Action, Job, Screen, State};
use crate::worker::HelperCommandError;

pub(super) const TRAFFIC_HISTORY: usize = 900;

/// An answer older than this is from an earlier visit to the tab and is not shown.
const CONNECTIONS_STALE_SECS: u64 = 3;
/// A connection's speed is its bytes over about this much time, so one late
/// or early answer does not swing it.
const RATE_WINDOW_MS: u64 = 3_000;
/// An answer this soon after the last measured one leaves the speed as it is:
/// its bytes may be as old as the previous ones.
const RATE_MIN_STEP_MS: u64 = 500;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ConnectionsView {
    #[default]
    ByProgram,
    All,
}

/// Which route the list shows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum RouteFilter {
    #[default]
    Any,
    Proxy,
    Direct,
    Exit(ExitId),
}

impl RouteFilter {
    pub(crate) fn matches(&self, route: &ConnectionRoute) -> bool {
        match (self, route) {
            (Self::Any, _)
            | (Self::Proxy, ConnectionRoute::Proxy)
            | (Self::Direct, ConnectionRoute::Direct) => true,
            (Self::Exit(id), ConnectionRoute::Exit(route)) => id == route,
            _ => false,
        }
    }
}

/// Why the connections table shows no rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionsNotice {
    Disconnected,
    Denied,
    Loading,
    Empty,
    NoRouteMatch,
    NoMatch,
}

/// The connections of one program.
pub(crate) struct ProgramGroup<'a> {
    pub(crate) path: Option<&'a str>,
    pub(crate) connections: Vec<&'a LiveConnection>,
    /// Each route once, in the order first met.
    pub(crate) routes: Vec<&'a ConnectionRoute>,
    pub(crate) down_rate: u64,
    /// Both directions over the connections' lifetimes.
    pub(crate) transferred: u64,
}

/// One row of the grouped list. Groups are flattened so that every row has
/// the same height, as `ScrollArea::show_rows` needs.
pub(crate) enum ConnectionRow<'a> {
    Program {
        group: ProgramGroup<'a>,
        expanded: bool,
    },
    Connection(&'a LiveConnection),
}

/// Program names read from version resources, by full path. The reading
/// happens on a worker; until then a program shows its file name. Memory only,
/// cleared with the list when the tunnel goes away.
#[derive(Default)]
pub(crate) struct ProgramNames {
    names: HashMap<String, String>,
    requested: HashSet<String>,
    queued: Vec<String>,
}

impl ProgramNames {
    fn queue(&mut self, connections: &[LiveConnection]) {
        for path in connections.iter().filter_map(|c| c.process.as_deref()) {
            if self.requested.insert(path.to_owned()) {
                self.queued.push(path.to_owned());
            }
        }
    }

    /// "System and other" for a connection without a program.
    pub(crate) fn name(&self, path: Option<&str>) -> String {
        match path {
            Some(path) => self
                .names
                .get(path)
                .cloned()
                .unwrap_or_else(|| crate::programs::file_stem(path).to_owned()),
            None => tr!("connections-system-program"),
        }
    }
}

/// The session's connections as the service last answered, newest first.
/// Memory only: the list is the user's browsing history.
#[derive(Default)]
pub(crate) struct ConnectionsList {
    pub(crate) view: ConnectionsView,
    pub(crate) tab: ConnectionsTab,
    pub(crate) route: RouteFilter,
    pub(crate) filter: String,
    /// Programs whose connections are shown under them, by path.
    pub(crate) expanded: HashSet<Option<String>>,
    /// The connection whose details are open, by id.
    pub(crate) selected: Option<String>,
    /// The id being closed by the service.
    pub(crate) closing: Option<String>,
    pub(crate) active: Vec<LiveConnection>,
    pub(crate) closed: Vec<LiveConnection>,
    /// The service answered since the tab was opened.
    pub(crate) received: bool,
    /// The tunnel belongs to another Windows account.
    pub(crate) denied: bool,
    pub(crate) programs: ProgramNames,
    /// Arrival time in milliseconds and bytes down and up by connection id,
    /// oldest first, reaching back about `RATE_WINDOW_MS`.
    samples: HashMap<String, VecDeque<(u64, u64, u64)>>,
    pending: bool,
    last_request: Option<u64>,
}

impl ConnectionsList {
    fn forget(&mut self) {
        self.active = Vec::new();
        self.closed = Vec::new();
        self.received = false;
        self.denied = false;
        self.selected = None;
        self.samples = HashMap::new();
    }

    /// Adds each active connection's bytes at `received_ms` and forgets the
    /// connections no longer in the answer.
    fn measure(&mut self, active: &[LiveConnection], received_ms: u64) {
        let mut samples = HashMap::with_capacity(active.len());
        for connection in active.iter().filter(|c| !c.id.is_empty()) {
            let mut points = self.samples.remove(&connection.id).unwrap_or_default();
            if points
                .back()
                .is_none_or(|&(at, _, _)| received_ms >= at.saturating_add(RATE_MIN_STEP_MS))
            {
                points.push_back((received_ms, connection.download, connection.upload));
                while points.len() > 2 && points[1].0.saturating_add(RATE_WINDOW_MS) <= received_ms
                {
                    points.pop_front();
                }
            }
            samples.insert(connection.id.clone(), points);
        }
        self.samples = samples;
    }

    /// Down and up bytes a second, once the connection was in two answers
    /// far enough apart.
    pub(crate) fn rate(&self, connection: &LiveConnection) -> Option<(u64, u64)> {
        if connection.id.is_empty() {
            return None;
        }
        let points = self.samples.get(&connection.id)?;
        let (&(first_ms, first_down, first_up), &(last_ms, last_down, last_up)) =
            (points.front()?, points.back()?);
        let elapsed = last_ms.checked_sub(first_ms).filter(|ms| *ms > 0)?;
        let per_second = |from: u64, to: u64| {
            u64::try_from(u128::from(to.saturating_sub(from)) * 1_000 / u128::from(elapsed))
                .unwrap_or(u64::MAX)
        };
        Some((
            per_second(first_down, last_down),
            per_second(first_up, last_up),
        ))
    }

    /// Still open, so the service can close it.
    pub(crate) fn can_close(&self, connection: &LiveConnection) -> bool {
        !connection.id.is_empty()
            && connection.end_unix_ms.is_none()
            && self.active.iter().any(|active| active.id == connection.id)
    }

    /// The selected connection, in either tab.
    pub(crate) fn selected_connection(&self) -> Option<&LiveConnection> {
        let id = self.selected.as_deref()?;
        self.active
            .iter()
            .chain(&self.closed)
            .find(|connection| connection.id == id)
    }

    fn tab_list(&self) -> &[LiveConnection] {
        match self.tab {
            ConnectionsTab::Active => &self.active,
            ConnectionsTab::Closed => &self.closed,
        }
    }

    /// The tunnel went away: the names go with the list.
    fn clear(&mut self) {
        self.forget();
        self.programs = ProgramNames::default();
        self.expanded = HashSet::new();
    }

    /// The selected tab's connections on the selected route that match the
    /// filter by program path, program name or address, ignoring letter case.
    pub(crate) fn visible(&self) -> Vec<&LiveConnection> {
        let filter = self.filter.trim().to_lowercase();
        self.tab_list()
            .iter()
            .filter(|connection| self.route.matches(&connection.route))
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
                    || self
                        .programs
                        .name(connection.process.as_deref())
                        .to_lowercase()
                        .contains(&filter)
            })
            .collect()
    }

    /// The visible connections by program, the fastest download first, then
    /// the most transferred.
    pub(crate) fn groups(&self) -> Vec<ProgramGroup<'_>> {
        let mut groups: Vec<ProgramGroup<'_>> = Vec::new();
        let mut index = HashMap::new();
        for connection in self.visible() {
            let path = connection.process.as_deref();
            let slot = *index.entry(path).or_insert_with(|| {
                groups.push(ProgramGroup {
                    path,
                    connections: Vec::new(),
                    routes: Vec::new(),
                    down_rate: 0,
                    transferred: 0,
                });
                groups.len() - 1
            });
            let group = &mut groups[slot];
            if !group.routes.contains(&&connection.route) {
                group.routes.push(&connection.route);
            }
            group.down_rate += self.rate(connection).map_or(0, |(down, _)| down);
            group.transferred += connection.download.saturating_add(connection.upload);
            group.connections.push(connection);
        }
        groups.sort_by(|left, right| {
            right
                .down_rate
                .cmp(&left.down_rate)
                .then(right.transferred.cmp(&left.transferred))
        });
        groups
    }

    pub(crate) fn rows(&self) -> Vec<ConnectionRow<'_>> {
        let mut rows = Vec::new();
        for group in self.groups() {
            let expanded = self.expanded.contains(&group.path.map(str::to_owned));
            let connections = if expanded {
                group.connections.clone()
            } else {
                Vec::new()
            };
            rows.push(ConnectionRow::Program { group, expanded });
            rows.extend(connections.into_iter().map(ConnectionRow::Connection));
        }
        rows
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
            self.traffic.connections.clear();
        }
    }

    pub(super) fn clear_traffic_history(&mut self) {
        self.traffic.traffic_history.clear();
        self.traffic.connections.clear();
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
        received_ms: u64,
    ) {
        self.traffic.connections.pending = false;
        if !self.connections_available() {
            self.traffic.connections.clear();
            return;
        }
        let list = &mut self.traffic.connections;
        match result {
            Ok((active, closed)) => {
                list.programs.queue(&active);
                list.programs.queue(&closed);
                list.measure(&active, received_ms);
                if let Some(id) = &list.selected
                    && !active.iter().chain(&closed).any(|c| &c.id == id)
                {
                    list.selected = None;
                }
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

    /// Paths seen since the last call, each once per session.
    pub(crate) fn take_program_names(&mut self) -> Option<Job> {
        let queued = std::mem::take(&mut self.traffic.connections.programs.queued);
        (!queued.is_empty()).then_some(Job::ProgramNames(queued))
    }

    pub(super) fn reduce_program_names(&mut self, names: Vec<(String, String)>) {
        let programs = &mut self.traffic.connections.programs;
        for (path, name) in names {
            // A path read before a disconnect belongs to the old session.
            if programs.requested.contains(&path) {
                programs.names.insert(path, name);
            }
        }
    }

    pub(super) fn reduce_close_connection(&mut self, result: Result<(), HelperCommandError>) {
        self.traffic.connections.closing = None;
        self.helper_result(result);
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
        } else if list.tab_list().is_empty() {
            Some(ConnectionsNotice::Empty)
        } else if !list
            .tab_list()
            .iter()
            .any(|connection| list.route.matches(&connection.route))
        {
            Some(ConnectionsNotice::NoRouteMatch)
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
            Action::SetConnectionsView(view) => {
                self.traffic.connections.view = view;
                None
            }
            Action::SetConnectionsRoute(route) => {
                self.traffic.connections.route = route;
                None
            }
            Action::SelectConnection(id) => {
                let list = &mut self.traffic.connections;
                list.selected = id.filter(|id| {
                    !id.is_empty()
                        && list
                            .active
                            .iter()
                            .chain(&list.closed)
                            .any(|connection| &connection.id == id)
                });
                None
            }
            Action::CloseConnection(id) => {
                let list = &mut self.traffic.connections;
                if !self.helper_available
                    || list.closing.is_some()
                    || id.is_empty()
                    || !list.active.iter().any(|connection| connection.id == id)
                {
                    return None;
                }
                list.closing = Some(id.clone());
                Some(Job::CloseConnection(id))
            }
            Action::ToggleProgramGroup(path) => {
                let expanded = &mut self.traffic.connections.expanded;
                if !expanded.remove(&path) {
                    expanded.insert(path);
                }
                None
            }
            _ => unreachable!("only traffic actions are dispatched here"),
        }
    }
}

/// A rule condition for a connection's site: its domain with subdomains, or
/// its address when the engine saw no name.
pub(crate) fn site_rule(host: &str) -> RuleMatcher {
    match rosetun_core::parse_ip_cidr(host) {
        Ok(address) => RuleMatcher::IpCidr(address),
        Err(_) => RuleMatcher::Domain(DomainMatch::Suffix(host.to_owned())),
    }
}

/// A rule condition for a connection's program by its full path.
pub(crate) fn program_rule(path: &str) -> RuleMatcher {
    RuleMatcher::Process(ProcessMatch::Path(path.into()))
}
