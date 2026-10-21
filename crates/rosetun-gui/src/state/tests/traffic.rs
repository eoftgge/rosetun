use super::super::traffic::TRAFFIC_HISTORY;
use super::*;

#[test]
fn traffic_history_tracks_15_minutes_and_clears_when_tunnel_or_helper_stops() {
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
    assert_eq!(state.traffic.traffic_history.len(), TRAFFIC_HISTORY);
    assert_eq!(state.traffic.traffic_history.front(), Some(&(1, 2)));
    assert_eq!(state.traffic.traffic_history.back(), Some(&(900, 901)));

    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Reconnecting,
        ..Status::default()
    }));
    assert_eq!(state.traffic.traffic_history.len(), TRAFFIC_HISTORY);
    state.reduce(WorkerEvent::Status(Status::default()));
    assert!(state.traffic.traffic_history.is_empty());

    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        ..Status::default()
    }));
    assert_eq!(state.traffic.traffic_history.len(), 1);
    state.reduce(WorkerEvent::HelperUnavailable(ClientError::Closed));
    assert!(state.traffic.traffic_history.is_empty());
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        ..Status::default()
    }));
    assert!(state.traffic.traffic_history.is_empty());
}

#[test]
fn opening_traffic_and_selecting_range_only_changes_ui_state() {
    let mut state = State::default();
    assert_eq!(state.traffic.traffic_range, TrafficRange::OneMinute);
    assert!(state.act(Action::OpenTraffic).is_none());
    assert_eq!(state.screen, Screen::Traffic);
    assert!(
        state
            .act(Action::SetTrafficRange(TrafficRange::FiveMinutes))
            .is_none()
    );
    assert_eq!(state.traffic.traffic_range, TrafficRange::FiveMinutes);
    assert!(
        state
            .act(Action::SetTrafficRange(TrafficRange::FifteenMinutes))
            .is_none()
    );
    assert_eq!(state.traffic.traffic_range, TrafficRange::FifteenMinutes);
    assert!(state.act(Action::ShowConnection).is_none());
    assert_eq!(state.screen, Screen::Connection);
    assert!(state.act(Action::OpenTraffic).is_none());
    assert_eq!(state.traffic.traffic_range, TrafficRange::FifteenMinutes);
}

fn connected_on_traffic() -> State {
    let mut state = State {
        helper_available: true,
        ..State::default()
    };
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        ..Status::default()
    }));
    assert!(state.act(Action::OpenTraffic).is_none());
    state
}

fn live(
    host: &str,
    process: Option<&str>,
    route: rosetun_config::ConnectionRoute,
) -> rosetun_config::LiveConnection {
    rosetun_config::LiveConnection {
        id: format!("{host}-id"),
        start_unix_ms: 1_000,
        end_unix_ms: None,
        process: process.map(str::to_owned),
        host: host.to_owned(),
        port: 443,
        network: rosetun_config::ConnectionNetwork::Tcp,
        route,
        download: 2,
        upload: 1,
    }
}

#[test]
fn connections_are_requested_only_while_the_traffic_tab_is_open() {
    let mut state = State {
        helper_available: true,
        ..State::default()
    };
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        ..Status::default()
    }));
    assert!(state.take_connections(100).is_none(), "another tab is open");

    assert!(state.act(Action::OpenTraffic).is_none());
    assert!(matches!(
        state.take_connections(100),
        Some(Job::Connections)
    ));
    assert!(
        state.take_connections(105).is_none(),
        "one request at a time"
    );
    state.reduce(WorkerEvent::Connections(Ok((Vec::new(), Vec::new()))));
    assert!(state.take_connections(100).is_none(), "once a second");
    assert_eq!(state.connections_due(), Some(101));
    assert!(matches!(
        state.take_connections(101),
        Some(Job::Connections)
    ));
    state.reduce(WorkerEvent::Connections(Ok((Vec::new(), Vec::new()))));

    state.set_window_hidden(true);
    assert!(
        state.take_connections(102).is_none(),
        "the window is in the tray"
    );
    assert_eq!(state.connections_due(), None);
    state.set_window_hidden(false);

    assert!(state.act(Action::ShowConnection).is_none());
    assert!(state.take_connections(103).is_none(), "the tab was left");
    assert_eq!(state.connections_due(), None);

    state.reduce(WorkerEvent::Status(Status::default()));
    assert!(state.act(Action::OpenTraffic).is_none());
    assert!(state.take_connections(104).is_none(), "not connected");
}

#[test]
fn connections_filter_matches_program_and_address_ignoring_case() {
    let mut state = connected_on_traffic();
    let _ = state.take_connections(100);
    state.reduce(WorkerEvent::Connections(Ok((
        vec![
            live(
                "Example.com",
                Some(r"C:\Program Files\Example\Browser.exe"),
                rosetun_config::ConnectionRoute::Proxy,
            ),
            live(
                "192.0.2.10",
                Some(r"C:\Games\Game.exe"),
                rosetun_config::ConnectionRoute::Direct,
            ),
            live("203.0.113.5", None, rosetun_config::ConnectionRoute::Proxy),
        ],
        Vec::new(),
    ))));
    let hosts = |state: &State| -> Vec<String> {
        state
            .traffic
            .connections
            .visible()
            .iter()
            .map(|c| c.host.clone())
            .collect()
    };
    assert_eq!(hosts(&state).len(), 3);

    for (filter, expected) in [
        ("EXAMPLE.COM", vec!["Example.com"]),
        ("browser", vec!["Example.com"]),
        ("game.EXE", vec!["192.0.2.10"]),
        ("192.0.2.10:443", vec!["192.0.2.10"]),
        ("  203.0  ", vec!["203.0.113.5"]),
    ] {
        assert!(
            state
                .act(Action::SetConnectionsFilter(filter.to_owned()))
                .is_none()
        );
        assert_eq!(hosts(&state), expected, "{filter}");
    }
    assert!(
        state
            .act(Action::SetConnectionsFilter("nothing".to_owned()))
            .is_none()
    );
    assert_eq!(state.connections_notice(), Some(ConnectionsNotice::NoMatch));
}

#[test]
fn connection_routes_name_the_exit() {
    let mut state = connected_on_traffic();
    state.config.exits.push(rosetun_config::Exit {
        id: rosetun_config::ExitId::new("work"),
        name: "Work".to_owned(),
        target: rosetun_config::ExitTarget::Country(
            rosetun_config::CountryCode::parse("NL").unwrap(),
        ),
    });
    let label = |route| state.connection_route_label(&route);

    assert_eq!(
        label(rosetun_config::ConnectionRoute::Exit(
            rosetun_config::ExitId::new("work")
        )),
        "Work"
    );
    assert_eq!(label(rosetun_config::ConnectionRoute::Proxy), tr!("proxy"));
    assert_eq!(
        label(rosetun_config::ConnectionRoute::Direct),
        tr!("direct")
    );
    assert_eq!(
        label(rosetun_config::ConnectionRoute::Exit(
            rosetun_config::ExitId::new("gone")
        )),
        tr!("target-exit-any")
    );
    assert_eq!(
        label(rosetun_config::ConnectionRoute::Other),
        tr!("connections-route-other")
    );
}

#[test]
fn connections_empty_states_follow_the_session_and_the_answer() {
    let mut state = State::default();
    assert!(state.act(Action::OpenTraffic).is_none());
    assert_eq!(
        state.connections_notice(),
        Some(ConnectionsNotice::Disconnected)
    );

    let mut state = connected_on_traffic();
    assert_eq!(state.connections_notice(), Some(ConnectionsNotice::Loading));
    let _ = state.take_connections(100);
    state.reduce(WorkerEvent::Connections(Ok((Vec::new(), Vec::new()))));
    assert_eq!(state.connections_notice(), Some(ConnectionsNotice::Empty));

    let _ = state.take_connections(101);
    state.reduce(WorkerEvent::Connections(Ok((
        vec![live(
            "example.com",
            None,
            rosetun_config::ConnectionRoute::Proxy,
        )],
        Vec::new(),
    ))));
    assert_eq!(state.connections_notice(), None);
    assert!(
        state
            .act(Action::SetConnectionsTab(ConnectionsTab::Closed))
            .is_none()
    );
    assert_eq!(state.connections_notice(), Some(ConnectionsNotice::Empty));

    let _ = state.take_connections(102);
    state.reduce(WorkerEvent::Connections(Err(HelperCommandError::Client(
        ClientError::Helper(HelperError::new(ErrorCode::AccessDenied, "another account")),
    ))));
    assert_eq!(state.connections_notice(), Some(ConnectionsNotice::Denied));
    assert!(state.traffic.connections.active.is_empty());

    let _ = state.take_connections(103);
    state.reduce(WorkerEvent::Connections(Ok((
        vec![live(
            "example.com",
            None,
            rosetun_config::ConnectionRoute::Proxy,
        )],
        Vec::new(),
    ))));
    state.reduce(WorkerEvent::Status(Status::default()));
    assert_eq!(
        state.connections_notice(),
        Some(ConnectionsNotice::Disconnected)
    );
    assert!(
        state.traffic.connections.active.is_empty(),
        "cleared on disconnect"
    );
}

#[test]
fn an_old_answer_is_dropped_when_the_tab_is_opened_again() {
    let mut state = connected_on_traffic();
    let _ = state.take_connections(100);
    state.reduce(WorkerEvent::Connections(Ok((
        vec![live(
            "example.com",
            None,
            rosetun_config::ConnectionRoute::Proxy,
        )],
        Vec::new(),
    ))));
    assert!(state.act(Action::ShowConnection).is_none());
    assert!(state.act(Action::OpenTraffic).is_none());
    assert!(state.take_connections(200).is_some());
    assert_eq!(state.connections_notice(), Some(ConnectionsNotice::Loading));
}

#[test]
fn program_names_are_read_once_per_path_and_cleared_on_disconnect() {
    let browser = r"C:\Program Files\Example\browser.exe";
    let game = r"C:\Games\Game.EXE";
    let mut state = connected_on_traffic();
    let _ = state.take_connections(100);
    state.reduce(WorkerEvent::Connections(Ok((
        vec![
            live(
                "example.com",
                Some(browser),
                rosetun_config::ConnectionRoute::Proxy,
            ),
            live(
                "example.net",
                Some(browser),
                rosetun_config::ConnectionRoute::Proxy,
            ),
            live("203.0.113.5", None, rosetun_config::ConnectionRoute::Direct),
        ],
        vec![live(
            "192.0.2.10",
            Some(game),
            rosetun_config::ConnectionRoute::Direct,
        )],
    ))));
    let Some(Job::ProgramNames(paths)) = state.take_program_names() else {
        panic!("new paths are read");
    };
    assert_eq!(paths, [browser, game]);
    assert!(state.take_program_names().is_none());

    let programs = &state.traffic.connections.programs;
    assert_eq!(
        programs.name(Some(browser)),
        "browser",
        "the file name until read"
    );
    assert_eq!(programs.name(Some(game)), "Game");
    assert_eq!(programs.name(None), tr!("connections-system-program"));

    state.reduce(WorkerEvent::ProgramNames(vec![(
        browser.to_owned(),
        "Example Browser".to_owned(),
    )]));
    assert_eq!(
        state.traffic.connections.programs.name(Some(browser)),
        "Example Browser"
    );
    assert!(
        state
            .act(Action::SetConnectionsFilter("example browser".to_owned()))
            .is_none()
    );
    assert_eq!(state.traffic.connections.visible().len(), 2);

    let _ = state.take_connections(101);
    state.reduce(WorkerEvent::Connections(Ok((
        vec![live(
            "example.com",
            Some(browser),
            rosetun_config::ConnectionRoute::Proxy,
        )],
        Vec::new(),
    ))));
    assert!(
        state.take_program_names().is_none(),
        "a read path is not read again"
    );

    state.reduce(WorkerEvent::Status(Status::default()));
    assert_eq!(
        state.traffic.connections.programs.name(Some(browser)),
        "browser",
        "cleared on disconnect"
    );
    state.reduce(WorkerEvent::ProgramNames(vec![(
        game.to_owned(),
        "Late Game".to_owned(),
    )]));
    assert_eq!(state.traffic.connections.programs.name(Some(game)), "Game");
}

fn answer(state: &mut State, now: u64, active: Vec<rosetun_config::LiveConnection>) {
    assert!(matches!(
        state.take_connections(now),
        Some(Job::Connections)
    ));
    state.reduce(WorkerEvent::Connections(Ok((active, Vec::new()))));
}

fn with_bytes(
    mut connection: rosetun_config::LiveConnection,
    download: u64,
    upload: u64,
) -> rosetun_config::LiveConnection {
    connection.download = download;
    connection.upload = upload;
    connection
}

#[test]
fn connections_group_by_program_with_one_group_for_no_program() {
    use rosetun_config::ConnectionRoute;
    let browser = r"C:\Program Files\Example\browser.exe";
    let mut state = connected_on_traffic();
    assert_eq!(state.traffic.connections.view, ConnectionsView::ByProgram);
    answer(
        &mut state,
        100,
        vec![
            live("example.com", Some(browser), ConnectionRoute::Proxy),
            live("203.0.113.5", None, ConnectionRoute::Direct),
            live("example.net", Some(browser), ConnectionRoute::Direct),
            live("example.org", Some(browser), ConnectionRoute::Proxy),
            live("198.51.100.7", None, ConnectionRoute::Direct),
        ],
    );
    let list = &state.traffic.connections;
    let groups = list.groups();
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].path, Some(browser));
    assert_eq!(groups[0].connections.len(), 3);
    assert_eq!(
        groups[0].routes,
        [&ConnectionRoute::Proxy, &ConnectionRoute::Direct],
        "each route once"
    );
    assert_eq!(groups[0].transferred, 9);
    assert_eq!(groups[1].path, None);
    assert_eq!(groups[1].connections.len(), 2);
    assert_eq!(
        list.programs.name(groups[1].path),
        tr!("connections-system-program")
    );

    assert!(
        state
            .act(Action::SetConnectionsView(ConnectionsView::All))
            .is_none()
    );
    assert_eq!(state.traffic.connections.view, ConnectionsView::All);
    assert_eq!(state.traffic.connections.visible().len(), 5);
}

#[test]
fn connections_filter_by_route_and_by_exit() {
    use rosetun_config::{ConnectionRoute, ExitId};
    let mut state = connected_on_traffic();
    answer(
        &mut state,
        100,
        vec![
            live("example.com", None, ConnectionRoute::Proxy),
            live("example.net", None, ConnectionRoute::Direct),
            live(
                "example.org",
                None,
                ConnectionRoute::Exit(ExitId::new("work")),
            ),
            live(
                "example.edu",
                None,
                ConnectionRoute::Exit(ExitId::new("home")),
            ),
        ],
    );
    let hosts = |state: &State| -> Vec<String> {
        state
            .traffic
            .connections
            .visible()
            .iter()
            .map(|c| c.host.clone())
            .collect()
    };
    for (filter, expected) in [
        (RouteFilter::Proxy, vec!["example.com"]),
        (RouteFilter::Direct, vec!["example.net"]),
        (RouteFilter::Exit(ExitId::new("work")), vec!["example.org"]),
        (
            RouteFilter::Any,
            vec!["example.com", "example.net", "example.org", "example.edu"],
        ),
    ] {
        assert!(
            state
                .act(Action::SetConnectionsRoute(filter.clone()))
                .is_none()
        );
        assert_eq!(hosts(&state), expected, "{filter:?}");
    }

    assert!(
        state
            .act(Action::SetConnectionsRoute(RouteFilter::Exit(ExitId::new(
                "gone"
            ))))
            .is_none()
    );
    assert_eq!(
        state.connections_notice(),
        Some(ConnectionsNotice::NoRouteMatch)
    );
    assert!(
        state
            .act(Action::SetConnectionsRoute(RouteFilter::Direct))
            .is_none()
    );
    assert!(
        state
            .act(Action::SetConnectionsFilter("example.com".to_owned()))
            .is_none()
    );
    assert_eq!(state.connections_notice(), Some(ConnectionsNotice::NoMatch));
}

#[test]
fn connection_speed_comes_from_the_same_id_in_two_answers() {
    use rosetun_config::ConnectionRoute;
    let mut state = connected_on_traffic();
    let first = live("example.com", None, ConnectionRoute::Proxy);
    let mut unnamed = live("example.net", None, ConnectionRoute::Proxy);
    unnamed.id = String::new();
    answer(
        &mut state,
        100,
        vec![with_bytes(first.clone(), 1_000, 100), unnamed.clone()],
    );
    let list = &state.traffic.connections;
    assert_eq!(
        list.rate(&list.active[0]),
        None,
        "the first answer has no speed"
    );

    let mut other = live("example.org", None, ConnectionRoute::Proxy);
    other.id = "example.com-id-2".to_owned();
    answer(
        &mut state,
        102,
        vec![
            with_bytes(first.clone(), 5_000, 300),
            with_bytes(unnamed, 9_000, 9_000),
            other,
        ],
    );
    let list = &state.traffic.connections;
    assert_eq!(list.rate(&list.active[0]), Some((2_000, 100)));
    assert_eq!(list.rate(&list.active[1]), None, "no id, no speed");
    assert_eq!(list.rate(&list.active[2]), None, "a new id starts again");

    answer(&mut state, 103, vec![with_bytes(first, 4_000, 300)]);
    let list = &state.traffic.connections;
    assert_eq!(list.rate(&list.active[0]), Some((0, 0)), "never negative");
}

#[test]
fn program_groups_sort_by_speed_then_by_volume() {
    use rosetun_config::ConnectionRoute;
    let (slow, fast, big) = (r"C:\slow.exe", r"C:\fast.exe", r"C:\big.exe");
    let mut state = connected_on_traffic();
    let connections = |slow_bytes, fast_bytes| {
        vec![
            with_bytes(
                live("slow.example", Some(slow), ConnectionRoute::Proxy),
                slow_bytes,
                0,
            ),
            with_bytes(
                live("big.example", Some(big), ConnectionRoute::Proxy),
                50_000,
                0,
            ),
            with_bytes(
                live("fast.example", Some(fast), ConnectionRoute::Proxy),
                fast_bytes,
                0,
            ),
        ]
    };
    answer(&mut state, 100, connections(10, 0));
    let order = |state: &State| -> Vec<Option<String>> {
        state
            .traffic
            .connections
            .groups()
            .iter()
            .map(|group| group.path.map(str::to_owned))
            .collect()
    };
    assert_eq!(
        order(&state),
        [
            Some(big.to_owned()),
            Some(slow.to_owned()),
            Some(fast.to_owned())
        ],
        "without speed, by volume"
    );
    answer(&mut state, 101, connections(1_010, 9_000));
    assert_eq!(
        order(&state),
        [
            Some(fast.to_owned()),
            Some(slow.to_owned()),
            Some(big.to_owned())
        ]
    );
    assert_eq!(state.traffic.connections.groups()[0].down_rate, 9_000);
}

#[test]
fn expanded_programs_stay_open_across_answers() {
    use rosetun_config::ConnectionRoute;
    let browser = r"C:\Program Files\Example\browser.exe";
    let mut state = connected_on_traffic();
    let connections = || {
        vec![
            live("example.com", Some(browser), ConnectionRoute::Proxy),
            live("example.net", Some(browser), ConnectionRoute::Proxy),
            live("203.0.113.5", None, ConnectionRoute::Direct),
        ]
    };
    answer(&mut state, 100, connections());
    assert_eq!(state.traffic.connections.rows().len(), 2, "collapsed");
    assert!(
        state
            .act(Action::ToggleProgramGroup(Some(browser.to_owned())))
            .is_none()
    );
    assert!(state.act(Action::ToggleProgramGroup(None)).is_none());

    answer(&mut state, 101, connections());
    let shape: Vec<_> = state
        .traffic
        .connections
        .rows()
        .iter()
        .map(|row| match row {
            ConnectionRow::Program { expanded, .. } => format!("program {expanded}"),
            ConnectionRow::Connection(connection) => connection.host.clone(),
        })
        .collect();
    assert_eq!(
        shape,
        [
            "program true",
            "example.com",
            "example.net",
            "program true",
            "203.0.113.5"
        ]
    );

    assert!(state.act(Action::ToggleProgramGroup(None)).is_none());
    assert_eq!(state.traffic.connections.rows().len(), 4);
}

#[test]
fn selection_follows_the_id_stays_when_closed_and_clears_when_gone() {
    use rosetun_config::ConnectionRoute;
    let mut state = connected_on_traffic();
    let mut unnamed = live("example.net", None, ConnectionRoute::Proxy);
    unnamed.id = String::new();
    answer(
        &mut state,
        100,
        vec![live("example.com", None, ConnectionRoute::Proxy), unnamed],
    );
    assert!(
        state
            .act(Action::SelectConnection(Some("example.com-id".to_owned())))
            .is_none()
    );
    assert_eq!(
        state
            .traffic
            .connections
            .selected_connection()
            .map(|c| c.host.as_str()),
        Some("example.com")
    );
    assert!(
        state
            .act(Action::SelectConnection(Some(String::new())))
            .is_none()
    );
    assert_eq!(
        state.traffic.connections.selected, None,
        "a connection without an id cannot be selected"
    );
    assert!(
        state
            .act(Action::SelectConnection(Some("example.com-id".to_owned())))
            .is_none()
    );

    let mut moved = live("example.com", None, ConnectionRoute::Proxy);
    moved.download = 900;
    answer(
        &mut state,
        101,
        vec![live("example.org", None, ConnectionRoute::Proxy), moved],
    );
    assert_eq!(
        state
            .traffic
            .connections
            .selected_connection()
            .map(|c| c.download),
        Some(900),
        "kept by id, not by position"
    );
    let list = &state.traffic.connections;
    assert!(list.can_close(list.selected_connection().unwrap()));

    let mut closed = live("example.com", None, ConnectionRoute::Proxy);
    closed.end_unix_ms = Some(2_000);
    assert!(matches!(
        state.take_connections(102),
        Some(Job::Connections)
    ));
    state.reduce(WorkerEvent::Connections(Ok((Vec::new(), vec![closed]))));
    assert!(
        state.traffic.connections.selected_connection().is_some(),
        "a closed connection stays selected"
    );
    let list = &state.traffic.connections;
    assert!(
        !list.can_close(list.selected_connection().unwrap()),
        "a closed connection has nothing to close"
    );

    answer(&mut state, 103, Vec::new());
    assert_eq!(state.traffic.connections.selected, None);
    assert!(state.traffic.connections.selected_connection().is_none());
}

#[test]
fn rule_conditions_for_a_site_an_address_and_a_program() {
    use rosetun_config::{DomainMatch, ProcessMatch};
    assert_eq!(
        crate::state::site_rule("www.example.com"),
        RuleMatcher::Domain(DomainMatch::Suffix("www.example.com".into()))
    );
    assert_eq!(
        crate::state::site_rule("192.0.2.10"),
        RuleMatcher::IpCidr("192.0.2.10/32".into())
    );
    assert_eq!(
        crate::state::site_rule("2001:db8::1"),
        RuleMatcher::IpCidr("2001:db8::1/128".into())
    );
    let path = r"C:\Program Files\Example\browser.exe";
    assert_eq!(
        crate::state::program_rule(path),
        RuleMatcher::Process(ProcessMatch::Path(path.into()))
    );
}

#[test]
fn creating_a_rule_from_a_connection_opens_the_filled_dialog() {
    let path = r"C:\Program Files\Example\browser.exe";
    let open = |matcher: RuleMatcher| {
        let mut state = state_with_rules();
        assert!(state.act(Action::OpenTraffic).is_none());
        let job = state.act(Action::OpenAddRuleFor(matcher));
        assert_eq!(state.screen, Screen::Rules);
        assert_eq!(
            state.rules.screen.selected_set,
            Some(RuleSetId::new("2")),
            "the active set"
        );
        (state, job)
    };

    let (state, job) = open(crate::state::site_rule("www.example.com"));
    assert!(job.is_none());
    let dialog = state.rules.screen.add.as_ref().unwrap();
    assert_eq!(dialog.kind, RuleInputKind::Domain);
    assert_eq!(dialog.domains, "www.example.com");
    assert!(dialog.subdomains);
    assert_eq!(dialog.editing, None);
    assert_eq!(dialog.target, rosetun_core::RuleDestination::Proxy);

    let (state, _) = open(crate::state::site_rule("192.0.2.10"));
    let dialog = state.rules.screen.add.as_ref().unwrap();
    assert_eq!(dialog.kind, RuleInputKind::Ip);
    assert_eq!(dialog.ips, "192.0.2.10/32");

    let (state, job) = open(crate::state::program_rule(path));
    assert!(matches!(job, Some(Job::LoadProcesses(_))));
    let dialog = state.rules.screen.add.as_ref().unwrap();
    assert_eq!(dialog.kind, RuleInputKind::Process);
    assert_eq!(dialog.process, path);
    assert_eq!(dialog.match_mode, ProcessMatchMode::Path);
    assert_eq!(dialog.editing, None);
}

#[test]
fn closing_sends_the_id_once_and_only_for_an_active_connection() {
    use rosetun_config::ConnectionRoute;
    let mut state = connected_on_traffic();
    let mut closed = live("example.net", None, ConnectionRoute::Proxy);
    closed.end_unix_ms = Some(2_000);
    assert!(matches!(
        state.take_connections(100),
        Some(Job::Connections)
    ));
    state.reduce(WorkerEvent::Connections(Ok((
        vec![live("example.com", None, ConnectionRoute::Proxy)],
        vec![closed],
    ))));

    assert!(
        state
            .act(Action::CloseConnection("example.net-id".to_owned()))
            .is_none(),
        "a closed connection cannot be closed"
    );
    assert!(
        state
            .act(Action::CloseConnection("unknown".to_owned()))
            .is_none()
    );
    let Some(Job::CloseConnection(id)) =
        state.act(Action::CloseConnection("example.com-id".to_owned()))
    else {
        panic!("an active connection is closed through the worker");
    };
    assert_eq!(id, "example.com-id");
    assert_eq!(
        state.traffic.connections.closing.as_deref(),
        Some("example.com-id")
    );
    assert!(
        state
            .act(Action::CloseConnection("example.com-id".to_owned()))
            .is_none(),
        "one request at a time"
    );

    state.reduce(WorkerEvent::CloseConnection(Err(
        HelperCommandError::Client(ClientError::Closed),
    )));
    assert_eq!(state.traffic.connections.closing, None);
    assert!(state.operation_error.is_some(), "shown as other errors are");

    assert!(matches!(
        state.act(Action::CloseConnection("example.com-id".to_owned())),
        Some(Job::CloseConnection(_))
    ));
    state.reduce(WorkerEvent::CloseConnection(Ok(())));
    assert_eq!(state.traffic.connections.closing, None);
    assert_eq!(state.operation_error, None);
}
