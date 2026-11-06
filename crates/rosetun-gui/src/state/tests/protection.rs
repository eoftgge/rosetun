use super::*;

const NONE: ProtectionCapabilities = ProtectionCapabilities {
    kill_switch: false,
    lockdown: false,
};

fn answered(protection: Option<ProtectionCapabilities>) -> State {
    let mut state = state_for_auto_connect();
    state.config.settings.kill_switch = true;
    if let Some(protection) = protection {
        state.reduce(WorkerEvent::HelperAvailable {
            version: "test".into(),
            protection,
        });
    } else {
        state.helper_available = true;
    }
    state.reduce(WorkerEvent::Status(Status::default()));
    state
}

/// The request the worker sends for a connect from this state.
fn connect_request(state: &mut State) -> ConnectRequest {
    let Some(Job::Connect(inputs)) = state.act(Action::Primary) else {
        panic!("expected a connect job");
    };
    inputs.limit(ConnectRequest::from_config_with_exits(&state.config, inputs.context()).unwrap())
}

#[test]
fn nothing_is_called_unavailable_before_the_helper_answers() {
    let mut state = answered(None);
    assert_eq!(state.protection, None);
    assert!(!state.kill_switch_unavailable());
    assert!(!state.lockdown_unavailable());
    assert!(state.can_change_lockdown());
    assert!(state.act(Action::RequestLockdown(true)).is_none());
    assert_eq!(state.lockdown_confirmation, Some(true));
    assert!(connect_request(&mut state).settings.kill_switch);
}

#[test]
fn a_helper_with_the_full_protection_changes_nothing() {
    let mut state = answered(Some(crate::worker::FULL_PROTECTION));
    assert_eq!(state.protection, Some(crate::worker::FULL_PROTECTION));
    assert!(!state.kill_switch_unavailable());
    assert!(!state.lockdown_unavailable());
    assert!(state.can_change_lockdown());
    assert!(state.act(Action::RequestLockdown(true)).is_none());
    assert_eq!(state.lockdown_confirmation, Some(true));
    assert!(matches!(
        state.act(Action::SetKillSwitch(false)),
        Some(Job::SetKillSwitch(false))
    ));
    state.operations.kill_switch = false;
    assert!(connect_request(&mut state).settings.kill_switch);
}

#[test]
fn without_protection_both_switches_are_unavailable_and_do_nothing() {
    let mut state = answered(Some(NONE));
    assert!(state.kill_switch_unavailable());
    assert!(state.lockdown_unavailable());
    assert!(!state.can_change_lockdown());

    assert!(state.act(Action::RequestLockdown(true)).is_none());
    assert_eq!(state.lockdown_confirmation, None);
    assert!(state.act(Action::ConfirmLockdown).is_none());
    assert!(!state.operations.lockdown);
    assert!(state.act(Action::SetKillSwitch(false)).is_none());
    assert!(!state.operations.kill_switch);
}

#[test]
fn without_a_kill_switch_a_connect_asks_for_none_and_the_setting_stays() {
    let mut state = answered(Some(NONE));

    let request = connect_request(&mut state);

    assert!(!request.settings.kill_switch);
    assert!(state.config.settings.kill_switch);
}

#[test]
fn a_lockdown_only_gap_still_connects_with_the_kill_switch() {
    let mut state = answered(Some(ProtectionCapabilities {
        kill_switch: true,
        lockdown: false,
    }));
    assert!(!state.kill_switch_unavailable());
    assert!(state.lockdown_unavailable());
    assert!(state.act(Action::RequestLockdown(true)).is_none());
    assert_eq!(state.lockdown_confirmation, None);
    assert!(connect_request(&mut state).settings.kill_switch);
}

#[test]
fn a_session_without_a_kill_switch_does_not_ask_to_reconnect_for_one() {
    let mut state = answered(Some(NONE));
    let request = connect_request(&mut state);
    state.reduce(WorkerEvent::Connect(Ok(request)));
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        node: Some(NodeId::new("node")),
        since_unix: Some(now_unix().saturating_sub(30)),
        ..Status::default()
    }));
    assert!(!state.running_session_protected());
    assert!(!state.pending_reconnect(SessionPart::Protection));
    state.refresh_cached_request();
    state.cache_config_request();
    assert!(!state.pending_reconnect(SessionPart::Protection));
    assert!(state.config.settings.kill_switch);
}

#[test]
fn the_helper_answering_later_rebuilds_the_cached_request() {
    let mut state = answered(None);
    state.cache_config_request();
    let builds = state.session.request_builds;

    state.reduce(WorkerEvent::HelperAvailable {
        version: "test".into(),
        protection: NONE,
    });

    assert!(state.session.request_builds > builds);
}

#[test]
fn what_the_helper_can_give_is_kept_when_the_connection_is_lost() {
    let mut state = answered(Some(NONE));

    state.reduce(WorkerEvent::HelperUnavailable(ClientError::Closed));

    assert!(!state.helper_available);
    assert_eq!(state.protection, Some(NONE));
    assert!(state.kill_switch_unavailable());
}

#[test]
fn the_unavailable_texts_read_right_in_both_languages() {
    use crate::i18n::{self, Language};

    for (language, caption, error) in [
        (
            Language::English,
            "Not available on this system.",
            "Kill switch is not available on this system.",
        ),
        (
            Language::Russian,
            "Недоступен в этой системе.",
            "Kill switch недоступен в этой системе.",
        ),
    ] {
        i18n::in_language(language, || {
            assert_eq!(tr!("kill-switch-unavailable"), caption);
            assert_eq!(
                errors::client(
                    language,
                    &ClientError::Helper(HelperError::new(ErrorCode::ProtectionUnavailable, "x"))
                ),
                error
            );
        });
    }
}

fn connected_with(protection: rosetun_config::ProtectionState) -> State {
    let mut state = answered(Some(ProtectionCapabilities {
        kill_switch: true,
        lockdown: true,
    }));
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        protection,
        ..Status::default()
    }));
    state
}

fn dns_lock_missing() -> rosetun_config::ProtectionState {
    rosetun_config::ProtectionState {
        requested: rosetun_config::RequestedProtection::DnsLock,
        shortfall: Some(rosetun_config::ProtectionShortfallCode::FirewallRefused.into()),
        ..Default::default()
    }
}

#[test]
fn the_warning_shows_only_while_requested_protection_is_missing() {
    let missing = connected_with(dns_lock_missing());
    assert_eq!(
        missing.missing_protection(),
        Some(rosetun_config::ProtectionShortfallCode::FirewallRefused)
    );

    // The same failure, but a kill switch covers what was asked for.
    let covered = connected_with(rosetun_config::ProtectionState {
        installed: rosetun_config::InstalledProtection::KillSwitch,
        ..dns_lock_missing()
    });
    assert_eq!(covered.missing_protection(), None);

    let in_place = connected_with(rosetun_config::ProtectionState {
        installed: rosetun_config::InstalledProtection::DnsLock,
        requested: rosetun_config::RequestedProtection::DnsLock,
        ..Default::default()
    });
    assert_eq!(in_place.missing_protection(), None);

    let nothing_asked = connected_with(rosetun_config::ProtectionState::default());
    assert_eq!(nothing_asked.missing_protection(), None);
}

#[test]
fn the_warning_does_not_outlive_the_session() {
    let mut state = connected_with(dns_lock_missing());
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Disconnected,
        protection: dns_lock_missing(),
        ..Status::default()
    }));
    assert_eq!(state.missing_protection(), None);
}

#[test]
fn the_tray_tooltip_carries_the_warning_only_while_it_is_shown() {
    let missing = connected_with(dns_lock_missing());
    let warning = tr!("tray-protection-missing");
    assert!(
        crate::tray::tray_view(&missing, true)
            .tooltip
            .contains(&warning)
    );

    let in_place = connected_with(rosetun_config::ProtectionState::default());
    assert!(
        !crate::tray::tray_view(&in_place, true)
            .tooltip
            .contains(&warning)
    );
}

#[test]
fn every_reason_reads_in_the_warning() {
    for code in [
        rosetun_config::ProtectionShortfallCode::FirewallUnavailable,
        rosetun_config::ProtectionShortfallCode::FirewallRefused,
        rosetun_config::ProtectionShortfallCode::TunnelNotPermitted,
        rosetun_config::ProtectionShortfallCode::NoTunnelDns,
    ] {
        let text = crate::i18n::missing_protection(code);
        assert!(!text.contains("protection-"), "{text}");
    }
}

#[test]
fn rules_that_cannot_be_checked_are_said_while_it_lasts() {
    let failing = connected_with(rosetun_config::ProtectionState {
        check_failed: true,
        ..Default::default()
    });
    assert!(failing.protection_unverified());
    let fine = connected_with(rosetun_config::ProtectionState::default());
    assert!(!fine.protection_unverified());
}

#[test]
fn a_task_that_could_not_start_says_so_and_nothing_stays_waiting() {
    let mut state = answered(None);
    state.operations.helper = true;
    state.operations.lockdown = true;

    state.reduce(WorkerEvent::TaskNotStarted);

    assert!(!state.operations.helper);
    assert!(!state.operations.lockdown);
    assert!(state.operation_error.is_some());
}
