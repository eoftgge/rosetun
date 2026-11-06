use rosetun_ipc::{ClientError, ErrorCode, HelperError};

use super::*;
use crate::state::ServiceGroup;
use crate::worker::ServiceGroupResult;

#[test]
fn a_relaunched_run_connects_when_the_first_status_shows_the_hold() {
    let mut state = state_for_auto_connect();
    state.config.interface.connect_on_start = false;
    state.start_relaunched();
    assert!(state.take_auto_connect().is_none());
    state.reduce(WorkerEvent::Status(Status {
        upgrade_hold: true,
        ..Status::default()
    }));
    assert!(matches!(state.take_auto_connect(), Some(Job::Connect(_))));
}

#[test]
fn a_relaunched_run_without_the_hold_does_not_connect_by_itself() {
    let mut state = state_for_auto_connect();
    state.config.interface.connect_on_start = false;
    state.start_relaunched();
    state.reduce(WorkerEvent::Status(Status::default()));
    assert!(state.take_auto_connect().is_none());
    // Only the first status decides: a later hold is an ordinary one.
    state.reduce(WorkerEvent::Status(Status {
        upgrade_hold: true,
        ..Status::default()
    }));
    assert!(state.take_auto_connect().is_none());
}

#[test]
fn the_service_answers_also_when_it_refuses_this_programs_protocol() {
    let mut state = State::default();
    state.reduce(WorkerEvent::HelperUnavailable(ClientError::Closed));
    assert!(!state.take_helper_answered());
    state.reduce(WorkerEvent::HelperUnavailable(ClientError::Helper(
        HelperError::new(ErrorCode::ProtocolMismatch, ""),
    )));
    assert!(state.take_helper_answered());
    assert!(!state.take_helper_answered(), "once for each answer");
}

#[test]
fn a_refused_socket_offers_the_group_until_it_is_joined() {
    let mut state = State::default();
    assert!(state.act(Action::JoinServiceGroup).is_none());
    state.reduce(WorkerEvent::HelperUnavailable(ClientError::SocketDenied));
    assert!(state.service_socket_denied());
    assert!(matches!(
        state.act(Action::JoinServiceGroup),
        Some(Job::JoinServiceGroup)
    ));
    assert!(
        state.act(Action::JoinServiceGroup).is_none(),
        "one at a time"
    );
    state.reduce(WorkerEvent::JoinServiceGroup(ServiceGroupResult::Declined));
    assert_eq!(state.service_group, ServiceGroup::Offered);
    state.act(Action::JoinServiceGroup);
    state.reduce(WorkerEvent::JoinServiceGroup(ServiceGroupResult::Joined));
    assert_eq!(state.service_group, ServiceGroup::Joined);
    assert!(state.act(Action::JoinServiceGroup).is_none());
}

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
    assert!(matches!(state.take_auto_connect(), Some(Job::Connect(_))));
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

#[test]
fn after_an_upgrade_the_gui_connects_even_without_connect_at_startup() {
    let mut state = state_for_auto_connect();
    state.config.interface.connect_on_start = false;
    state.start_after_upgrade();
    state.reduce(WorkerEvent::Status(Status {
        upgrade_hold: true,
        ..Status::default()
    }));

    assert!(matches!(state.take_auto_connect(), Some(Job::Connect(_))));
    assert!(!state.take_upgrade_attention());
}

#[test]
fn a_failed_connect_after_an_upgrade_asks_for_the_window() {
    let mut state = state_for_auto_connect();
    state.start_after_upgrade();
    state.reduce(WorkerEvent::Status(Status::default()));
    state.take_auto_connect().unwrap();

    state.reduce(WorkerEvent::Connect(Err(HelperCommandError::Client(
        ClientError::Helper(HelperError::new(ErrorCode::Internal, "")),
    ))));

    assert!(state.take_upgrade_attention());
    assert!(!state.take_upgrade_attention(), "asked once");
}

#[test]
fn after_an_upgrade_without_a_server_the_window_explains() {
    let mut state = state_for_auto_connect();
    state.config.active = None;
    state.start_after_upgrade();
    state.reduce(WorkerEvent::Status(Status::default()));

    assert!(state.take_auto_connect().is_none());
    assert!(state.take_upgrade_attention());
}

#[test]
fn an_ordinary_start_never_asks_for_the_window() {
    let mut state = state_for_auto_connect();
    state.config.active = None;
    state.reduce(WorkerEvent::Status(Status::default()));
    assert!(state.take_auto_connect().is_none());
    assert!(!state.take_upgrade_attention());
}
