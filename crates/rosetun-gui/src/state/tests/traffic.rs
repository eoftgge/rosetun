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
    assert_eq!(state.traffic_history.len(), TRAFFIC_HISTORY);
    assert_eq!(state.traffic_history.front(), Some(&(1, 2)));
    assert_eq!(state.traffic_history.back(), Some(&(900, 901)));

    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Reconnecting,
        ..Status::default()
    }));
    assert_eq!(state.traffic_history.len(), TRAFFIC_HISTORY);
    state.reduce(WorkerEvent::Status(Status::default()));
    assert!(state.traffic_history.is_empty());

    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        ..Status::default()
    }));
    assert_eq!(state.traffic_history.len(), 1);
    state.reduce(WorkerEvent::HelperUnavailable(ClientError::Closed));
    assert!(state.traffic_history.is_empty());
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        ..Status::default()
    }));
    assert!(state.traffic_history.is_empty());
}

#[test]
fn opening_traffic_and_selecting_range_only_changes_ui_state() {
    let mut state = State::default();
    assert_eq!(state.traffic_range, TrafficRange::OneMinute);
    assert!(state.act(Action::OpenTraffic).is_none());
    assert_eq!(state.screen, Screen::Traffic);
    assert!(
        state
            .act(Action::SetTrafficRange(TrafficRange::FiveMinutes))
            .is_none()
    );
    assert_eq!(state.traffic_range, TrafficRange::FiveMinutes);
    assert!(
        state
            .act(Action::SetTrafficRange(TrafficRange::FifteenMinutes))
            .is_none()
    );
    assert_eq!(state.traffic_range, TrafficRange::FifteenMinutes);
    assert!(state.act(Action::ShowConnection).is_none());
    assert_eq!(state.screen, Screen::Connection);
    assert!(state.act(Action::OpenTraffic).is_none());
    assert_eq!(state.traffic_range, TrafficRange::FifteenMinutes);
}
