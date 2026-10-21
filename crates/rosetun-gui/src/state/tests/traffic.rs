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
            live("example.com", Some(browser), rosetun_config::ConnectionRoute::Proxy),
            live("example.net", Some(browser), rosetun_config::ConnectionRoute::Proxy),
            live("203.0.113.5", None, rosetun_config::ConnectionRoute::Direct),
        ],
        vec![live("192.0.2.10", Some(game), rosetun_config::ConnectionRoute::Direct)],
    ))));
    let Some(Job::ProgramNames(paths)) = state.take_program_names() else {
        panic!("new paths are read");
    };
    assert_eq!(paths, [browser, game]);
    assert!(state.take_program_names().is_none());

    let programs = &state.traffic.connections.programs;
    assert_eq!(programs.name(Some(browser)), "browser", "the file name until read");
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
        vec![live("example.com", Some(browser), rosetun_config::ConnectionRoute::Proxy)],
        Vec::new(),
    ))));
    assert!(state.take_program_names().is_none(), "a read path is not read again");

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
