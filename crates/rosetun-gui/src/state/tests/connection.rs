use super::*;

#[test]
fn primary_label_matches_reconnecting_action_and_busy_state() {
    let mut state = State {
        helper_available: true,
        ..State::default()
    };
    state.status.state = ConnectionState::Reconnecting;
    assert_eq!(state.primary_action(), PrimaryAction::Disconnect);
    assert_eq!(primary_label(&state), tr!("disconnect"));

    state.operations.helper = true;
    assert_eq!(state.primary_action(), PrimaryAction::Disabled);
    assert_eq!(primary_label(&state), tr!("working"));

    state.operations.helper = false;
    state.status.state = ConnectionState::Connecting;
    assert_eq!(primary_label(&state), tr!("connecting-action"));
}

#[test]
fn exit_lookup_waits_for_status_and_runs_once_per_route() {
    let mut state = State::default();
    assert!(state.take_exit_lookup().is_none());
    assert_eq!(state.exit, ExitLookup::None);
    state.reduce(WorkerEvent::HelperAvailable {
        version: "test".into(),
    });
    assert!(state.take_exit_lookup().is_none());

    state.reduce(WorkerEvent::Status(Status::default()));
    assert!(matches!(
        state.take_exit_lookup(),
        Some(Job::LookupExit {
            generation: 1,
            route: ExitRoute::Direct
        })
    ));
    assert_eq!(state.exit, ExitLookup::Pending(ExitRoute::Direct));
    assert!(state.take_exit_lookup().is_none());

    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connecting,
        ..Status::default()
    }));
    assert!(state.take_exit_lookup().is_none());
    assert_eq!(state.exit, ExitLookup::None);
    assert!(!state.exit_revealed);

    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        ..Status::default()
    }));
    assert!(matches!(
        state.take_exit_lookup(),
        Some(Job::LookupExit {
            generation: 2,
            route: ExitRoute::Tunnel
        })
    ));
    assert_eq!(state.exit, ExitLookup::Pending(ExitRoute::Tunnel));
    assert!(state.take_exit_lookup().is_none());

    for connection in [
        ConnectionState::Reconnecting,
        ConnectionState::FailedProtected {
            failure_kind: None,
            reason: "failure".into(),
        },
    ] {
        state.reduce(WorkerEvent::Status(Status {
            state: connection,
            ..Status::default()
        }));
        assert!(state.take_exit_lookup().is_none());
        assert_eq!(state.exit, ExitLookup::None);
    }
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Failed {
            failure_kind: None,
            reason: "failure".into(),
        },
        ..Status::default()
    }));
    assert!(matches!(
        state.take_exit_lookup(),
        Some(Job::LookupExit {
            generation: 3,
            route: ExitRoute::Direct
        })
    ));
}

#[test]
fn exit_lookup_uses_direct_route_when_helper_is_unavailable() {
    let mut state = State::default();
    state.reduce(WorkerEvent::HelperUnavailable(ClientError::Closed));
    assert!(matches!(
        state.take_exit_lookup(),
        Some(Job::LookupExit {
            generation: 1,
            route: ExitRoute::Direct
        })
    ));
    assert!(state.take_exit_lookup().is_none());

    state.reduce(WorkerEvent::HelperAvailable {
        version: "test".into(),
    });
    assert!(state.take_exit_lookup().is_none());
    assert_eq!(state.exit, ExitLookup::None);
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        ..Status::default()
    }));
    assert!(matches!(
        state.take_exit_lookup(),
        Some(Job::LookupExit {
            generation: 2,
            route: ExitRoute::Tunnel
        })
    ));
}

#[test]
fn exit_lookup_discards_old_replies_and_hides_new_addresses() {
    let mut state = State::default();
    state.reduce(WorkerEvent::HelperAvailable {
        version: "test".into(),
    });
    state.reduce(WorkerEvent::Status(Status::default()));
    assert!(state.take_exit_lookup().is_some());
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        ..Status::default()
    }));
    assert!(state.take_exit_lookup().is_some());
    state.reduce(WorkerEvent::Exit {
        generation: 1,
        route: ExitRoute::Direct,
        result: Ok(exit_info("203.0.113.1")),
    });
    assert_eq!(state.exit, ExitLookup::Pending(ExitRoute::Tunnel));

    state.reduce(WorkerEvent::Exit {
        generation: 2,
        route: ExitRoute::Tunnel,
        result: Ok(exit_info("203.0.113.2")),
    });
    assert!(matches!(state.exit, ExitLookup::Known { .. }));
    assert!(!state.exit_revealed);
    state.act(Action::ToggleExitReveal);
    assert!(state.exit_revealed);
    state.act(Action::ToggleExitReveal);
    assert!(!state.exit_revealed);
    state.act(Action::ToggleExitReveal);

    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Reconnecting,
        ..Status::default()
    }));
    assert!(state.take_exit_lookup().is_none());
    assert_eq!(state.exit, ExitLookup::None);
    assert!(!state.exit_revealed);
    state.reduce(WorkerEvent::Exit {
        generation: 2,
        route: ExitRoute::Tunnel,
        result: Ok(exit_info("203.0.113.2")),
    });
    assert_eq!(state.exit, ExitLookup::None);
    state.act(Action::ToggleExitReveal);
    assert!(!state.exit_revealed);

    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        ..Status::default()
    }));
    assert!(matches!(
        state.take_exit_lookup(),
        Some(Job::LookupExit {
            generation: 3,
            route: ExitRoute::Tunnel
        })
    ));
    state.reduce(WorkerEvent::Exit {
        generation: 3,
        route: ExitRoute::Tunnel,
        result: Ok(exit_info("203.0.113.3")),
    });
    assert!(matches!(
        &state.exit,
        ExitLookup::Known { info, .. } if info.ip == "203.0.113.3".parse::<std::net::IpAddr>().unwrap()
    ));
    assert!(!state.exit_revealed);
}

#[test]
fn exit_lookup_failure_does_not_retry_until_route_changes() {
    let mut state = State::default();
    state.reduce(WorkerEvent::HelperUnavailable(ClientError::Closed));
    assert!(state.take_exit_lookup().is_some());
    state.reduce(WorkerEvent::Exit {
        generation: 1,
        route: ExitRoute::Direct,
        result: Err(rosetun_core::ExitInfoError::Parse),
    });
    assert_eq!(state.exit, ExitLookup::Failed(ExitRoute::Direct));
    assert!(state.take_exit_lookup().is_none());
}

#[test]
fn tunnel_delay_starts_after_three_seconds_once_per_session() {
    let mut state = state_for_auto_connect();
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        since_unix: Some(1_000),
        ..Status::default()
    }));
    assert!(state.take_tunnel_delay(1_002).is_none());
    assert!(matches!(
        state.take_tunnel_delay(1_003),
        Some(Job::TunnelDelay)
    ));
    assert_eq!(state.tunnel_delay, TunnelDelay::Measuring);
    assert!(state.take_tunnel_delay(1_004).is_none());
    state.reduce(WorkerEvent::TunnelDelay(Ok(ProbeOutcome::Works {
        millis: 85,
    })));
    assert_eq!(
        state.tunnel_delay,
        TunnelDelay::Done(ProbeOutcome::Works { millis: 85 })
    );
    assert!(state.take_tunnel_delay(1_100).is_none());

    state.reduce(WorkerEvent::Status(Status::default()));
    assert_eq!(state.tunnel_delay, TunnelDelay::Idle);
    assert!(state.take_tunnel_delay(1_200).is_none());
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        since_unix: Some(1_200),
        ..Status::default()
    }));
    assert!(state.take_tunnel_delay(1_202).is_none());
    assert!(matches!(
        state.take_tunnel_delay(1_203),
        Some(Job::TunnelDelay)
    ));
}

#[test]
fn tunnel_delay_retries_busy_auto_measurements_after_ten_seconds() {
    let mut state = state_for_auto_connect();
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        since_unix: Some(1_000),
        ..Status::default()
    }));
    assert!(matches!(
        state.take_tunnel_delay(1_003),
        Some(Job::TunnelDelay)
    ));
    state.reduce(WorkerEvent::TunnelDelay(Err(HelperCommandError::Client(
        ClientError::Helper(HelperError::new(ErrorCode::Busy, "")),
    ))));
    assert_eq!(state.tunnel_delay, TunnelDelay::Idle);
    assert!(state.take_tunnel_delay(1_012).is_none());
    assert!(matches!(
        state.take_tunnel_delay(1_013),
        Some(Job::TunnelDelay)
    ));
    state.reduce(WorkerEvent::TunnelDelay(Err(HelperCommandError::Client(
        ClientError::Helper(HelperError::new(ErrorCode::Busy, "")),
    ))));
    assert!(state.take_tunnel_delay(1_022).is_none());
    assert!(matches!(
        state.take_tunnel_delay(1_023),
        Some(Job::TunnelDelay)
    ));
}

#[test]
fn tunnel_delay_manual_refresh_and_stale_completion() {
    let mut state = state_for_auto_connect();
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        since_unix: Some(1_000),
        ..Status::default()
    }));
    assert!(matches!(
        state.act(Action::MeasureDelay),
        Some(Job::TunnelDelay)
    ));
    assert!(state.act(Action::MeasureDelay).is_none());
    state.reduce(WorkerEvent::TunnelDelay(Err(HelperCommandError::Client(
        ClientError::Helper(HelperError::new(ErrorCode::Busy, "")),
    ))));
    assert_eq!(state.tunnel_delay, TunnelDelay::Idle);
    assert!(state.operation_error.is_none());
    assert!(matches!(
        state.take_tunnel_delay(1_003),
        Some(Job::TunnelDelay)
    ));
    assert!(state.act(Action::MeasureDelay).is_none());
    state.reduce(WorkerEvent::TunnelDelay(Err(HelperCommandError::Client(
        ClientError::Closed,
    ))));
    assert_eq!(state.tunnel_delay, TunnelDelay::Done(ProbeOutcome::Fails));
    assert!(matches!(
        state.act(Action::MeasureDelay),
        Some(Job::TunnelDelay)
    ));
    state.reduce(WorkerEvent::Status(Status::default()));
    assert_eq!(state.tunnel_delay, TunnelDelay::Idle);
    assert!(state.act(Action::MeasureDelay).is_none());
    state.reduce(WorkerEvent::TunnelDelay(Ok(ProbeOutcome::Works {
        millis: 25,
    })));
    assert_eq!(state.tunnel_delay, TunnelDelay::Idle);
}

#[test]
fn helper_recovery_keeps_last_status_hidden_until_available() {
    let mut state = State::default();
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connected,
        ..Status::default()
    }));
    state.reduce(WorkerEvent::HelperUnavailable(ClientError::Closed));
    assert!(!state.helper_available);
    assert!(matches!(state.status.state, ConnectionState::Connected));
    assert!(state.visible_status().is_none());
    state.reduce(WorkerEvent::HelperAvailable {
        version: "test".into(),
    });
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Disconnected,
        ..Status::default()
    }));
    assert!(state.helper_available);
    assert!(state.helper_error.is_none());
    assert!(matches!(
        state.visible_status().map(|status| &status.state),
        Some(ConnectionState::Disconnected)
    ));
}

#[test]
fn failure_conflicts_are_checked_once_and_stale_results_are_ignored() {
    let mut state = state_for_auto_connect();
    let failure = Status {
        state: ConnectionState::Failed {
            reason: "dial tcp 203.0.113.10:443: i/o timeout".into(),
            failure_kind: Some(FailureKind::ServerUnreachable),
        },
        ..Status::default()
    };
    state.reduce(WorkerEvent::Status(failure.clone()));
    let Some(Job::CheckFailureInterference { request, own_alias }) =
        state.take_failure_interference()
    else {
        panic!("expected one failure check");
    };
    assert_eq!(own_alias, state.config.settings.tun.name);
    assert!(state.take_failure_interference().is_none());
    state.reduce(WorkerEvent::FailureInterference {
        request,
        hints: FailureInterference {
            other_vpns: vec!["Example VPN".into()],
            traffic_tools: vec!["winws.exe".into()],
        },
    });
    assert_eq!(
        state.failure_interference.as_ref().unwrap().other_vpns,
        ["Example VPN"]
    );
    state.reduce(WorkerEvent::Status(failure));
    assert!(state.take_failure_interference().is_none());
    assert!(matches!(state.act(Action::Primary), Some(Job::Connect)));
    assert!(state.failure_interference.is_none());
    state.reduce(WorkerEvent::FailureInterference {
        request,
        hints: FailureInterference {
            other_vpns: vec!["Stale VPN".into()],
            ..FailureInterference::default()
        },
    });
    assert!(state.failure_interference.is_none());
}

#[test]
fn unrelated_and_dns_timeout_failures_do_not_scan_for_conflicts() {
    let mut state = state_for_auto_connect();
    for kind in [None, Some(FailureKind::DnsTimeout)] {
        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Failed {
                reason: "no DNS answer".into(),
                failure_kind: kind,
            },
            ..Status::default()
        }));
        assert!(state.take_failure_interference().is_none());
    }
}

#[test]
fn cancelling_a_connect_ignores_a_late_success_in_either_order() {
    for connect_first in [false, true] {
        let mut state = state_for_auto_connect();
        let request = ConnectRequest::from_config(&state.config).unwrap();
        assert!(matches!(state.act(Action::Primary), Some(Job::Connect)));
        state.reduce(WorkerEvent::Status(Status {
            state: ConnectionState::Connecting,
            ..Status::default()
        }));
        assert!(matches!(
            state.act(Action::CancelConnection),
            Some(Job::Disconnect)
        ));
        assert!(state.act(Action::CancelConnection).is_none());
        if connect_first {
            state.reduce(WorkerEvent::Connect(Ok(request)));
            assert!(state.operations.helper);
            assert!(state.session_request.is_none());
            state.reduce(WorkerEvent::Disconnect(Ok(())));
        } else {
            state.reduce(WorkerEvent::Disconnect(Ok(())));
            assert!(state.operations.helper);
            state.reduce(WorkerEvent::Connect(Ok(request)));
        }
        state.reduce(WorkerEvent::Status(Status::default()));
        assert!(state.session_request.is_none());
        assert!(!state.operations.helper);
        assert!(!state.cancel_in_flight);
        assert!(matches!(state.act(Action::Primary), Some(Job::Connect)));
        assert!(!state.cancelled_connect);
    }
}

#[test]
fn failed_cancellation_restores_a_completed_connect() {
    let mut state = state_for_auto_connect();
    let request = ConnectRequest::from_config(&state.config).unwrap();
    assert!(matches!(state.act(Action::Primary), Some(Job::Connect)));
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Connecting,
        ..Status::default()
    }));
    assert!(matches!(
        state.act(Action::CancelConnection),
        Some(Job::Disconnect)
    ));
    state.reduce(WorkerEvent::Connect(Ok(request.clone())));
    state.reduce(WorkerEvent::Disconnect(Err(HelperCommandError::Client(
        ClientError::Closed,
    ))));
    assert_eq!(state.session_request, Some(request));
    assert!(!state.cancel_in_flight);
    assert!(!state.cancelled_connect);
    assert!(!state.operations.helper);
    assert!(state.operation_error.is_some());
}

#[test]
fn cancelling_an_automatic_reconnect_needs_no_connect_worker() {
    let mut state = state_for_auto_connect();
    state.reduce(WorkerEvent::Status(Status {
        state: ConnectionState::Reconnecting,
        ..Status::default()
    }));
    assert!(matches!(
        state.act(Action::CancelConnection),
        Some(Job::Disconnect)
    ));
    state.reduce(WorkerEvent::Disconnect(Ok(())));
    assert!(!state.operations.helper);
}

#[test]
fn command_completion_clears_flags_and_maps_selection_errors() {
    let mut state = State::default();
    state.operations.helper = true;
    state.reduce(WorkerEvent::Connect(Err(HelperCommandError::Request(
        ConnectRequestError::NodeNotFound,
    ))));
    assert!(!state.operations.helper);
    assert_eq!(
        state.operation_error.as_deref(),
        Some(tr!("select-server")).as_deref()
    );
    state.operations.selection = true;
    state.reduce(WorkerEvent::SelectNode(Err(
        rosetun_core::SelectNodeError::NodeNotFound,
    )));
    assert!(!state.operations.selection);
    state.operations.rules = true;
    state.reduce(WorkerEvent::SelectRuleSet(Ok(())));
    assert!(!state.operations.rules);
    assert!(state.operation_error.is_none());
    state.operations.kill_switch = true;
    state.reduce(WorkerEvent::SetKillSwitch(Err(StoreError::NoConfigDir)));
    assert!(!state.operations.kill_switch);
    assert!(state.operation_error.is_some());
}

#[test]
fn failed_connect_reported_by_status_has_no_second_error() {
    for code in [
        ErrorCode::EngineFailed,
        ErrorCode::RoutingFailed,
        ErrorCode::UnsupportedRules,
    ] {
        let mut state = State {
            status: Status {
                state: ConnectionState::Failed {
                    failure_kind: None,
                    reason: "boom".into(),
                },
                ..Status::default()
            },
            operation_error: Some("old error".into()),
            ..State::default()
        };
        state.operations.helper = true;
        state.reduce(WorkerEvent::Connect(Err(HelperCommandError::Client(
            ClientError::Helper(HelperError::new(code, "boom")),
        ))));
        assert!(!state.operations.helper);
        assert!(state.operation_error.is_none());
        assert!(matches!(state.status.state, ConnectionState::Failed { .. }));
    }
}

#[test]
fn busy_connect_and_failed_disconnect_still_show_errors() {
    let mut state = State::default();
    state.operations.helper = true;
    state.reduce(WorkerEvent::Connect(Err(HelperCommandError::Client(
        ClientError::Helper(HelperError::new(ErrorCode::Busy, "retry")),
    ))));
    assert!(!state.operations.helper);
    assert_eq!(
        state.operation_error.as_deref(),
        Some("the service is busy with another operation: retry")
    );

    state.operations.helper = true;
    state.reduce(WorkerEvent::Disconnect(Err(HelperCommandError::Client(
        ClientError::Helper(HelperError::new(ErrorCode::EngineFailed, "boom")),
    ))));
    assert!(!state.operations.helper);
    assert_eq!(
        state.operation_error.as_deref(),
        Some("the engine failed: boom")
    );
}

#[test]
fn protected_disconnect_requires_explicit_confirmation() {
    let mut state = State {
        helper_available: true,
        status: Status {
            state: ConnectionState::FailedProtected {
                failure_kind: None,
                reason: "failed".into(),
            },
            ..Status::default()
        },
        ..State::default()
    };
    assert!(state.act(Action::ConfirmProtectionOff).is_none());
    assert!(matches!(state.act(Action::Primary), Some(Job::Connect)));
    let request = ConnectRequest::from_config(&state_for_auto_connect().config).unwrap();
    state.reduce(WorkerEvent::Connect(Ok(request)));
    state.act(Action::RequestProtectionOff);
    assert!(state.protection_confirmation);
    assert!(matches!(
        state.act(Action::ConfirmProtectionOff),
        Some(Job::Disconnect)
    ));
    state.reduce(WorkerEvent::Disconnect(Err(HelperCommandError::Client(
        ClientError::Closed,
    ))));
    assert!(state.protection_confirmation);
    assert!(!state.operations.helper);
    state.act(Action::KeepBlocked);
    assert!(!state.protection_confirmation);
}
