use super::*;

fn connected_since(since: u64) -> State {
    let mut state = State::default();
    state.reduce(WorkerEvent::HelperAvailable {
        version: "0.9.0".into(),
    });
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        since_unix: Some(since),
        ..Status::default()
    }));
    assert!(state.take_temporary_load(since).is_some());
    state
}

#[test]
fn nothing_scheduled_wakes_never() {
    assert_eq!(State::default().next_wake(1_000), None);
}

#[test]
fn wakes_at_the_nearest_deadline() {
    let mut state = connected_since(1_000);
    state.config_ready = true;
    state.config.interface.last_update_check = Some(1_000);
    assert!(state.take_auto_update(1_000).is_none());
    // Tunnel delay at 1_003, subscription check at 1_060, update check a day later.
    assert_eq!(state.next_wake(1_001), Some(Duration::from_secs(2)));
    assert!(state.take_tunnel_delay(1_003).is_some());
    assert_eq!(state.next_wake(1_003), Some(Duration::from_secs(57)));
}

#[test]
fn past_deadline_wakes_now() {
    let state = connected_since(1_000);
    assert_eq!(state.next_wake(1_050), Some(Duration::ZERO));
}
