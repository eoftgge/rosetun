use super::*;

#[test]
fn auto_connect_waits_for_config_helper_and_first_status_then_runs_once() {
    let mut state = state_for_auto_connect();
    assert!(state.take_auto_connect().is_none());
    assert!(state.auto_connect_pending);
    state.config_ready = false;
    state.reduce(WorkerEvent::Status(Status::default()));
    assert!(state.take_auto_connect().is_none());
    state.config_ready = true;
    state.helper_available = false;
    assert!(state.take_auto_connect().is_none());
    state.helper_available = true;
    state.operation_error = Some("previous error".into());
    assert!(matches!(state.take_auto_connect(), Some(Job::Connect)));
    assert!(!state.auto_connect_pending);
    assert!(state.operations.helper);
    assert!(state.operation_error.is_none());
    assert!(state.take_auto_update(1_000).is_none());
    assert!(state.take_auto_connect().is_none());
}

#[test]
fn auto_connect_does_not_run_if_already_connected_or_disabled_or_no_server() {
    let mut connected = state_for_auto_connect();
    connected.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        ..Status::default()
    }));
    assert!(connected.take_auto_connect().is_none());
    assert!(!connected.auto_connect_pending);

    let mut disabled = state_for_auto_connect();
    disabled.config.interface.connect_on_start = false;
    disabled.reduce(WorkerEvent::Status(Status::default()));
    assert!(disabled.take_auto_connect().is_none());
    assert!(!disabled.auto_connect_pending);

    let mut no_server = state_for_auto_connect();
    no_server.config.active = None;
    no_server.reduce(WorkerEvent::Status(Status::default()));
    assert!(no_server.take_auto_connect().is_none());
    assert!(!no_server.auto_connect_pending);
}

#[test]
fn configuration_replacement_ignores_stale_publications_and_retains_valid_data_on_error() {
    let mut state = State::default();
    let config = AppConfig {
        subscriptions: vec![subscription("1")],
        ..AppConfig::default()
    };
    state.reduce(WorkerEvent::Config {
        generation: 2,
        config: config.clone(),
    });
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config: AppConfig::default(),
    });
    state.reduce(WorkerEvent::ConfigError(ConfigWorkerError::Store(
        StoreError::NoConfigDir,
    )));
    assert_eq!(state.config, config);
    assert!(state.config_error.is_some());
    state.reduce(WorkerEvent::Config {
        generation: 3,
        config: AppConfig::default(),
    });
    assert!(state.config.subscriptions.is_empty());
    assert!(state.config_error.is_none());
}
