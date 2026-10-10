use super::super::updates::{UPDATE_CHECK_INTERVAL, UPDATE_CHECK_RETRY};
use super::*;

#[test]
fn missing_last_check_starts_immediately_after_config_load_then_waits_a_day() {
    let mut state = State::default();
    assert!(state.take_update_check(1_000).is_none());
    state.config_ready = true;
    assert!(matches!(
        state.take_update_check(1_001),
        Some(Job::CheckUpdates)
    ));
    assert!(state.take_update_check(1_001).is_none());
    state.finish_update_check(Ok(None), 1_002);
    assert_eq!(state.config.interface.last_update_check, Some(1_002));
    assert!(!state.updates.update_check_failed);
    assert!(
        state
            .take_update_check(1_002 + UPDATE_CHECK_INTERVAL - 1)
            .is_none()
    );
    assert!(matches!(
        state.take_update_check(1_002 + UPDATE_CHECK_INTERVAL),
        Some(Job::CheckUpdates)
    ));
}

#[test]
fn recent_check_waits_for_the_remaining_hours_and_old_or_future_check_runs_now() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    let now = 200_000;
    state.config.interface.last_update_check = Some(now - 2 * 60 * 60);
    assert!(state.take_update_check(now).is_none());
    assert!(state.take_update_check(now + 22 * 60 * 60 - 1).is_none());
    assert!(matches!(
        state.take_update_check(now + 22 * 60 * 60),
        Some(Job::CheckUpdates)
    ));

    let mut old = State {
        config_ready: true,
        ..State::default()
    };
    old.config.interface.last_update_check = Some(now - 30 * 60 * 60);
    assert!(matches!(
        old.take_update_check(now),
        Some(Job::CheckUpdates)
    ));

    let mut future = State {
        config_ready: true,
        ..State::default()
    };
    future.config.interface.last_update_check = Some(now + 60);
    assert!(matches!(
        future.take_update_check(now),
        Some(Job::CheckUpdates)
    ));
}

#[test]
fn failed_release_check_preserves_timestamp_and_retries_in_six_hours() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    state.config.interface.last_update_check = Some(1_000);
    assert!(matches!(
        state.take_update_check(100_000),
        Some(Job::CheckUpdates)
    ));
    state.finish_update_check(Err(UpdateCheckError::Parse), 100_005);
    assert_eq!(state.config.interface.last_update_check, Some(1_000));
    assert!(state.updates.update_check_failed);
    assert!(
        state
            .take_update_check(100_005 + UPDATE_CHECK_RETRY - 1)
            .is_none()
    );
    assert!(matches!(
        state.take_update_check(100_005 + UPDATE_CHECK_RETRY),
        Some(Job::CheckUpdates)
    ));
    state.finish_update_check(Ok(None), 100_006 + UPDATE_CHECK_RETRY);
    assert!(!state.updates.update_check_failed);
    assert_eq!(
        state.config.interface.last_update_check,
        Some(100_006 + UPDATE_CHECK_RETRY)
    );
}

#[test]
fn release_check_waits_for_setting_and_safe_connection_state() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    state.config.interface.check_updates = false;
    assert!(state.take_update_check(1_000).is_none());
    state.config.interface.check_updates = true;
    state.helper_available = true;
    state.status.state = ConnectionState::Connecting;
    assert!(state.take_update_check(1_060).is_none());
    state.status.state = ConnectionState::Reconnecting;
    assert!(state.take_update_check(1_120).is_none());
    state.status.state = ConnectionState::FailedProtected {
        failure_kind: None,
        reason: "failure".into(),
    };
    assert!(state.take_update_check(1_180).is_none());
    state.status.state = ConnectionState::Connected;
    assert!(state.take_update_check(1_239).is_none());
    assert!(matches!(
        state.take_update_check(1_240),
        Some(Job::CheckUpdates)
    ));
}

#[test]
fn skipped_release_stays_known_and_a_newer_release_is_shown() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    let release = |version: &str| Release {
        version: version.into(),
        url: "https://example.com/release".into(),
        prerelease: true,
    };
    state.config.interface.skipped_version = Some("999.0.0-alpha.3".into());
    state.take_update_check(1_000);
    state.finish_update_check(Ok(Some(release("999.0.0-alpha.3"))), 1_001);
    assert!(state.available_update().is_none());
    assert_eq!(
        state.updates.newest_release.as_ref().unwrap().version,
        "999.0.0-alpha.3"
    );

    state.take_update_check(1_001 + UPDATE_CHECK_INTERVAL);
    state.finish_update_check(
        Ok(Some(release("999.0.0-alpha.4"))),
        1_002 + UPDATE_CHECK_INTERVAL,
    );
    assert_eq!(state.available_update().unwrap().version, "999.0.0-alpha.4");
    state.config.interface.skipped_version = Some("999.0.0-alpha.4".into());
    let config = state.config.clone();
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config,
    });
    assert!(state.available_update().is_none());
    assert_eq!(
        state.updates.newest_release.as_ref().unwrap().version,
        "999.0.0-alpha.4"
    );
    state.config.interface.check_updates = false;
    state.config.interface.skipped_version = None;
    assert!(state.available_update().is_some());
}

#[test]
fn manual_update_check_works_when_automatic_checks_are_off() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    state.config.interface.check_updates = false;
    assert!(state.take_update_check(100_000).is_none());
    assert!(matches!(
        state.act(Action::CheckUpdatesNow),
        Some(Job::CheckUpdates)
    ));
    assert!(state.act(Action::CheckUpdatesNow).is_none());
    state.reduce(WorkerEvent::UpdateCheck {
        checked_at: 100_001,
        result: Err(UpdateCheckError::Parse),
    });
    assert!(state.updates.update_check_failed);
    assert!(state.config.interface.last_update_check.is_none());
    assert!(matches!(
        state.act(Action::CheckUpdatesNow),
        Some(Job::CheckUpdates)
    ));
    state.reduce(WorkerEvent::UpdateCheck {
        checked_at: 100_002,
        result: Ok(None),
    });
    assert!(!state.updates.update_check_failed);
    assert_eq!(state.config.interface.last_update_check, Some(100_002));
}

#[test]
fn manual_update_check_is_blocked_in_transitional_states() {
    let mut state = State {
        config_ready: true,
        helper_available: true,
        ..State::default()
    };
    for status in [
        ConnectionState::Connecting,
        ConnectionState::Reconnecting,
        ConnectionState::FailedProtected {
            failure_kind: None,
            reason: "failure".into(),
        },
    ] {
        state.status.state = status;
        assert!(!state.can_check_updates());
        assert!(state.act(Action::CheckUpdatesNow).is_none());
    }
    state.status.state = ConnectionState::Connected;
    assert!(state.can_check_updates());
}
