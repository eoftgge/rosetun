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

fn dns(status: CheckStatus) -> CheckResult {
    CheckResult {
        kind: CheckKind::DnsSubstitution,
        status,
        detail: if status == CheckStatus::Warning {
            CheckDetail::DnsSubstitution {
                server: "192.0.2.53".into(),
            }
        } else {
            CheckDetail::None
        },
    }
}

fn run_check(state: &mut State, results: Vec<CheckResult>) -> bool {
    let Some(Job::CheckSystem {
        request, guarded, ..
    }) = state.act(Action::CheckSystem)
    else {
        panic!("expected a system check job");
    };
    state.reduce(WorkerEvent::SystemChecks { request, results });
    guarded
}

#[test]
fn dns_row_reads_differently_in_each_state() {
    let detail = |status| crate::i18n::check_detail(&dns(status));
    assert_eq!(detail(CheckStatus::Ok), tr!("system-check-dns-ok"));
    assert_eq!(
        detail(CheckStatus::Skipped),
        tr!("system-check-offline-only")
    );
    assert_eq!(
        detail(CheckStatus::Unavailable),
        tr!("system-check-unavailable")
    );
    let found = detail(CheckStatus::Warning);
    assert!(found.contains("192.0.2.53"), "{found}");
    assert_ne!(found, tr!("system-check-unavailable"));
}

#[test]
fn dns_check_is_guarded_under_a_tunnel_or_protection_only() {
    for (connection, expected) in [
        (ConnectionState::Disconnected, false),
        (failure().state, false),
        (ConnectionState::Connecting, true),
        (ConnectionState::Connected, true),
        (ConnectionState::Reconnecting, true),
        (
            ConnectionState::FailedProtected {
                reason: "no reply from 192.0.2.1".into(),
                failure_kind: None,
            },
            true,
        ),
    ] {
        let mut state = State::default();
        state.reduce(WorkerEvent::Status(Status {
            state: connection.clone(),
            ..Status::default()
        }));
        assert_eq!(
            run_check(&mut state, Vec::new()),
            expected,
            "{connection:?}"
        );
    }
}

#[test]
fn a_skipped_dns_check_keeps_the_last_verdict_and_gives_no_failure_hint() {
    let mut state = State {
        helper_available: true,
        config_ready: true,
        ..State::default()
    };
    run_check(&mut state, vec![dns(CheckStatus::Warning)]);
    run_check(&mut state, vec![dns(CheckStatus::Skipped)]);
    assert_eq!(
        state.system_checks.last_dns,
        Some(dns(CheckStatus::Warning))
    );
    assert_eq!(
        state.system_checks.results.as_deref(),
        Some(&[dns(CheckStatus::Skipped)][..])
    );

    state.reduce(WorkerEvent::Status(failure()));
    let Some(Job::CheckSystem { request, .. }) = state.take_system_check() else {
        panic!("expected an automatic check");
    };
    state.reduce(WorkerEvent::SystemChecks {
        request,
        results: vec![dns(CheckStatus::Warning)],
    });
    assert!(state.system_checks.failure_warning.is_none());
}

#[test]
fn name_lookup_failures_get_the_dns_hint_only_after_substitution_was_found() {
    let id = rosetun_config::SubscriptionId::new("test-subscription");
    let unresolved = |protected| Status {
        state: if protected {
            ConnectionState::FailedProtected {
                reason: "failed to resolve the VPN server name".into(),
                failure_kind: Some(rosetun_config::FailureKind::ServerNameUnresolved),
            }
        } else {
            ConnectionState::Failed {
                reason: "failed to resolve the VPN server name".into(),
                failure_kind: Some(rosetun_config::FailureKind::ServerNameUnresolved),
            }
        },
        ..Status::default()
    };
    let host_not_found = || {
        UpdateOutcome::Error(rosetun_core::UpdateSubscriptionError::Fetch {
            source: rosetun_core::FetchError::HostNotFound,
            message: "subscription server name could not be resolved".into(),
        })
    };

    for last in [
        None,
        Some(CheckStatus::Ok),
        Some(CheckStatus::Unavailable),
        Some(CheckStatus::Warning),
    ] {
        let mut state = State::default();
        if let Some(status) = last {
            run_check(&mut state, vec![dns(status)]);
        }
        let expected = last == Some(CheckStatus::Warning);
        for protected in [false, true] {
            state.status = unresolved(protected);
            assert_eq!(state.dns_hint_for_failure(), expected, "{last:?}");
        }
        state
            .subscriptions
            .outcomes
            .insert(id.clone(), host_not_found());
        assert_eq!(state.dns_hint_for_update(&id), expected, "{last:?}");
    }

    // Other failures never get it, even with substitution found.
    let mut state = State::default();
    run_check(&mut state, vec![dns(CheckStatus::Warning)]);
    state.status = failure();
    assert!(!state.dns_hint_for_failure());
    state.subscriptions.outcomes.insert(
        id.clone(),
        UpdateOutcome::Error(rosetun_core::UpdateSubscriptionError::Fetch {
            source: rosetun_core::FetchError::Timeout,
            message: "timed out".into(),
        }),
    );
    assert!(!state.dns_hint_for_update(&id));
}
