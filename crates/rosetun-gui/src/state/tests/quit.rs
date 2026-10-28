use rosetun_config::QuitAction;

use super::*;
use crate::state::QuitDecision;
use crate::state::quit::quit_decision;

fn failed() -> ConnectionState {
    ConnectionState::Failed {
        reason: "test".into(),
        failure_kind: None,
    }
}

fn failed_protected() -> ConnectionState {
    ConnectionState::FailedProtected {
        reason: "test".into(),
        failure_kind: None,
    }
}

fn holding_states() -> [ConnectionState; 4] {
    [
        ConnectionState::Connected,
        ConnectionState::Connecting,
        ConnectionState::Reconnecting,
        failed_protected(),
    ]
}

fn state_in(connection: ConnectionState) -> State {
    State {
        config_ready: true,
        helper_available: true,
        status: Status {
            state: connection,
            ..Status::default()
        },
        ..State::default()
    }
}

#[test]
fn a_held_tunnel_asks_by_default() {
    for connection in holding_states() {
        assert_eq!(
            quit_decision(Some(&connection), QuitAction::Ask, false),
            QuitDecision::Ask
        );
    }
}

#[test]
fn a_remembered_choice_is_followed_without_asking() {
    for connection in holding_states() {
        assert_eq!(
            quit_decision(Some(&connection), QuitAction::Disconnect, false),
            QuitDecision::Disconnect
        );
        assert_eq!(
            quit_decision(Some(&connection), QuitAction::KeepConnected, false),
            QuitDecision::Leave
        );
    }
}

#[test]
fn without_a_tunnel_or_service_quitting_leaves_at_once() {
    for action in [
        QuitAction::Ask,
        QuitAction::Disconnect,
        QuitAction::KeepConnected,
    ] {
        for connection in [ConnectionState::Disconnected, failed()] {
            assert_eq!(
                quit_decision(Some(&connection), action, false),
                QuitDecision::Leave
            );
        }
        assert_eq!(quit_decision(None, action, false), QuitDecision::Leave);
    }
}

#[test]
fn an_ending_windows_session_never_asks_or_disconnects() {
    for connection in holding_states() {
        for action in [QuitAction::Ask, QuitAction::Disconnect] {
            assert_eq!(
                quit_decision(Some(&connection), action, true),
                QuitDecision::Leave
            );
        }
    }
}

#[test]
fn an_unavailable_service_is_not_asked_about() {
    let mut state = state_in(ConnectionState::Connected);
    state.helper_available = false;

    assert_eq!(state.quit_decision(false), QuitDecision::Leave);
}

#[test]
fn cancel_closes_the_question_without_quitting() {
    let mut state = state_in(ConnectionState::Connected);
    state.open_quit_dialog();
    assert!(state.act(Action::SetRememberQuit(true)).is_none());

    assert!(state.act(Action::CancelQuit).is_none());
    assert!(!state.quit.asking);
    assert!(!state.quit.remember);
    assert_eq!(state.take_quit(), None);
}

#[test]
fn an_answer_without_remembering_saves_nothing() {
    let mut state = state_in(ConnectionState::Connected);
    state.open_quit_dialog();

    assert!(state.act(Action::Quit { disconnect: false }).is_none());
    assert!(!state.quit.asking);
    assert_eq!(state.take_quit(), Some(false));
    assert_eq!(state.take_quit(), None);
}

#[test]
fn a_remembered_answer_is_saved_as_the_quit_action() {
    for (disconnect, saved) in [
        (true, QuitAction::Disconnect),
        (false, QuitAction::KeepConnected),
    ] {
        let mut state = state_in(ConnectionState::Connected);
        state.open_quit_dialog();
        state.act(Action::SetRememberQuit(true));

        assert!(matches!(
            state.act(Action::Quit { disconnect }),
            Some(Job::Setting(SettingChange::QuitAction(action))) if action == saved
        ));
        assert_eq!(state.take_quit(), Some(disconnect));
        assert!(!state.quit_settled(false), "the save is waited for");
    }
}

#[test]
fn a_remembered_answer_waits_behind_a_running_save() {
    let mut state = state_in(ConnectionState::Connected);
    state.operations.settings = Some(0);
    state.open_quit_dialog();
    state.act(Action::SetRememberQuit(true));

    assert!(state.act(Action::Quit { disconnect: true }).is_none());
    assert_eq!(state.take_quit(), Some(true));
    assert!(state.saves_settings());

    state.reduce(WorkerEvent::Setting(
        SettingChange::CheckUpdates(false),
        Ok(()),
    ));
    assert!(matches!(
        state.take_queued_setting(),
        Some(Job::Setting(SettingChange::QuitAction(
            QuitAction::Disconnect
        )))
    ));
}

#[test]
fn an_answer_after_the_question_closed_is_ignored() {
    let mut state = state_in(ConnectionState::Connected);

    assert!(state.act(Action::Quit { disconnect: true }).is_none());
    assert_eq!(state.take_quit(), None);
}

#[test]
fn the_quit_setting_saves_only_a_change() {
    let mut state = state_in(ConnectionState::Disconnected);

    assert!(state.act(Action::SetOnQuit(QuitAction::Ask)).is_none());
    assert!(matches!(
        state.act(Action::SetOnQuit(QuitAction::KeepConnected)),
        Some(Job::Setting(SettingChange::QuitAction(
            QuitAction::KeepConnected
        )))
    ));
}

#[test]
fn quitting_disconnects_like_the_disconnect_button() {
    for connection in [ConnectionState::Connected, failed_protected()] {
        let mut state = state_in(connection);

        assert!(matches!(state.quit_disconnect(), Some(Job::Disconnect)));
        assert!(state.operations.helper);
    }
}

#[test]
fn quitting_during_a_connect_cancels_it() {
    for connection in [ConnectionState::Connecting, ConnectionState::Reconnecting] {
        let mut state = state_in(connection);

        assert!(matches!(state.quit_disconnect(), Some(Job::Disconnect)));
        assert!(state.cancel_in_flight);
    }
}

#[test]
fn nothing_is_disconnected_without_a_tunnel_or_service() {
    assert!(
        state_in(ConnectionState::Disconnected)
            .quit_disconnect()
            .is_none()
    );
    assert!(state_in(failed()).quit_disconnect().is_none());
    let mut unavailable = state_in(ConnectionState::Connected);
    unavailable.helper_available = false;
    assert!(unavailable.quit_disconnect().is_none());
}

#[test]
fn a_disconnecting_quit_waits_for_the_tunnel_to_go() {
    let mut state = state_in(ConnectionState::Connected);
    state.quit_disconnect();
    state.reduce(WorkerEvent::Disconnect(Ok(())));

    assert!(state.quit_settled(false));
    assert!(
        !state.quit_settled(true),
        "the status still shows the tunnel"
    );

    state.status.state = ConnectionState::Disconnected;
    assert!(state.quit_settled(true));
}
