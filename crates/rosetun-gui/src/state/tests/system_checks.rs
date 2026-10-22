use super::*;
use rosetun_core::{CheckDetail, CheckKind, CheckResult, CheckStatus};

fn warning() -> CheckResult {
    CheckResult {
        kind: CheckKind::Clock,
        status: CheckStatus::Warning,
        detail: CheckDetail::Clock {
            minutes: 12,
            ahead: false,
        },
    }
}

fn failure() -> Status {
    Status {
        state: ConnectionState::Failed {
            reason: "no reply from 192.0.2.1".into(),
            failure_kind: None,
        },
        ..Status::default()
    }
}

#[test]
fn button_starts_one_check_and_the_result_reaches_the_card() {
    let mut state = State::default();
    let Some(Job::CheckSystem {
        request,
        own_alias,
        guarded,
    }) = state.act(Action::CheckSystem)
    else {
        panic!("expected a system check job");
    };
    assert_eq!(own_alias, state.config.settings.tun.name);
    assert!(!guarded);
    assert!(state.system_checks.checking);
    assert!(state.act(Action::CheckSystem).is_none());
    state.reduce(WorkerEvent::SystemChecks {
        request,
        results: vec![warning()],
    });
    assert!(!state.system_checks.checking);
    assert_eq!(state.system_checks.results.as_ref().unwrap(), &[warning()]);
    assert!(state.system_checks.checked_at.is_some());
    assert!(state.system_checks.failure_warning.is_none());
}

#[test]
fn failed_and_failed_protected_start_once_per_connect_attempt() {
    for protected in [false, true] {
        let mut state = State {
            helper_available: true,
            config_ready: true,
            ..State::default()
        };
        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connecting,
            ..Status::default()
        }));
        let mut failed = failure();
        if protected {
            failed.state = ConnectionState::FailedProtected {
                reason: "no reply from 192.0.2.1".into(),
                failure_kind: None,
            };
        }
        state.reduce(WorkerEvent::Status(failed.clone()));
        let Some(Job::CheckSystem { request, .. }) = state.take_system_check() else {
            panic!("expected an automatic check");
        };
        assert!(state.take_system_check().is_none());
        state.reduce(WorkerEvent::SystemChecks {
            request,
            results: vec![warning()],
        });
        assert_eq!(state.system_checks.failure_warning, Some(warning()));
        state.reduce(WorkerEvent::Status(failed));
        assert!(state.take_system_check().is_none());
        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connecting,
            ..Status::default()
        }));
        assert!(state.system_checks.failure_warning.is_none());
        state.reduce(WorkerEvent::Status(failure()));
        assert!(matches!(
            state.take_system_check(),
            Some(Job::CheckSystem { .. })
        ));
    }
}

#[test]
fn late_results_from_an_old_attempt_cannot_create_a_failure_hint() {
    let mut state = State {
        helper_available: true,
        config_ready: true,
        ..State::default()
    };
    state.reduce(WorkerEvent::Status(failure()));
    let Some(Job::CheckSystem { request, .. }) = state.take_system_check() else {
        panic!("expected an automatic check");
    };
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connecting,
        ..Status::default()
    }));
    state.reduce(WorkerEvent::SystemChecks {
        request,
        results: vec![warning()],
    });
    assert!(state.system_checks.failure_warning.is_none());
    assert!(state.system_checks.results.is_none());
}

#[test]
fn details_link_opens_the_service_settings_section() {
    let mut state = State::default();
    let _ = state.act(Action::ShowSystemChecks);
    assert_eq!(state.screen, Screen::Settings);
    assert_eq!(state.settings.screen.section, SettingsSection::Service);
}

#[test]
fn an_unresolved_server_name_gets_no_system_check_hint() {
    let mut state = State {
        helper_available: true,
        config_ready: true,
        ..State::default()
    };
    let unresolved = Status {
        state: ConnectionState::Failed {
            reason: "failed to resolve the VPN server name".into(),
            failure_kind: Some(rosetun_config::FailureKind::ServerNameUnresolved),
        },
        ..Status::default()
    };
    state.reduce(WorkerEvent::Status(unresolved));
    assert!(state.take_system_check().is_none());
    let Some(Job::CheckSystem { request, .. }) = state.act(Action::CheckSystem) else {
        panic!("the button still checks");
    };
    state.reduce(WorkerEvent::SystemChecks {
        request,
        results: vec![warning()],
    });
    assert!(state.system_checks.failure_warning.is_none());
    assert_eq!(state.system_checks.results.as_ref().unwrap(), &[warning()]);
}
