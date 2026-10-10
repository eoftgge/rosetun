use super::super::subscriptions::{AUTO_UPDATE_CHECK, update_due};
use super::*;

#[test]
fn reveal_server_opens_the_selected_subscription_and_clears_after_scroll() {
    let mut state = state_for_auto_connect();
    let id = SubscriptionId::new("1");
    let node = NodeId::new("node");
    assert!(state.act(Action::RevealServer).is_none());
    assert!(state.subscriptions.expanded.contains(&id));
    assert_eq!(state.subscriptions.reveal, Some((id, node)));
    assert!(state.act(Action::RevealDone).is_none());
    assert_eq!(state.subscriptions.reveal, None);
}

#[test]
fn reveal_server_clears_a_node_removed_by_a_config_update() {
    let mut state = state_for_auto_connect();
    state.act(Action::RevealServer);
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config: AppConfig::default(),
    });
    assert_eq!(state.subscriptions.reveal, None);
}

#[test]
fn reveal_server_without_selection_opens_the_first_subscription() {
    let mut state = state_with_subscriptions();
    assert!(state.act(Action::RevealServer).is_none());
    assert_eq!(state.subscriptions.expanded.len(), 1);
    assert!(
        state
            .subscriptions
            .expanded
            .contains(&SubscriptionId::new("1"))
    );
    assert_eq!(state.subscriptions.reveal, None);
}

#[test]
fn subscription_drops_resolve_gaps_and_reject_no_op_or_missing_ids() {
    for (id, slot, to_index) in [("3", 0, 0), ("1", 3, 2), ("2", 3, 2)] {
        let mut state = state_with_subscriptions();
        assert!(matches!(
            state.act(Action::DropSubscription(SubscriptionId::new(id), slot)),
            Some(Job::MoveSubscription(moved, to))
                if moved == SubscriptionId::new(id) && to == to_index
        ));
        assert!(state.operations.moving_subscription);
        state.reduce(WorkerEvent::MoveSubscription(Ok(())));
        assert!(!state.operations.moving_subscription);
    }

    let mut state = state_with_subscriptions();
    let id = SubscriptionId::new("2");
    assert!(state.act(Action::DropSubscription(id.clone(), 1)).is_none());
    assert!(state.act(Action::DropSubscription(id.clone(), 2)).is_none());
    assert!(state.act(Action::DropSubscription(id, 4)).is_none());
    assert!(
        state
            .act(Action::DropSubscription(SubscriptionId::new("missing"), 0))
            .is_none()
    );
    assert!(!state.operations.moving_subscription);
}

#[test]
fn subscription_drops_wait_for_other_subscription_operations() {
    let mut state = state_with_subscriptions();
    let drop = || Action::DropSubscription(SubscriptionId::new("2"), 0);
    state.config_ready = false;
    assert!(state.act(drop()).is_none());
    state.config_ready = true;
    state.operations.updating.insert(SubscriptionId::new("3"));
    assert!(state.act(drop()).is_none());
    state.operations.updating.clear();
    state.operations.update_all = true;
    assert!(state.act(drop()).is_none());
    state.operations.update_all = false;
    state.subscriptions.add = Some(AddDialog {
        busy: true,
        ..AddDialog::default()
    });
    assert!(state.act(drop()).is_none());
    state.subscriptions.add = None;
    state.operations.removing = true;
    assert!(state.act(drop()).is_none());
    state.operations.removing = false;
    assert!(matches!(
        state.act(drop()),
        Some(Job::MoveSubscription(_, 0))
    ));
    assert!(state.act(drop()).is_none());
}

#[test]
fn subscription_move_completion_clears_busy_and_reports_errors() {
    let mut state = state_with_subscriptions();
    assert!(
        state
            .act(Action::DropSubscription(SubscriptionId::new("2"), 0))
            .is_some()
    );
    state.reduce(WorkerEvent::MoveSubscription(Err(
        rosetun_core::MoveSubscriptionError::NotFound,
    )));
    assert!(!state.operations.moving_subscription);
    assert_eq!(
        state.operation_error.as_deref(),
        Some("subscription does not exist")
    );
    assert!(
        state
            .act(Action::DropSubscription(SubscriptionId::new("2"), 0))
            .is_some()
    );
    assert!(state.operation_error.is_none());
    state.reduce(WorkerEvent::MoveSubscription(Ok(())));
    assert!(!state.operations.moving_subscription);
    assert!(state.operation_error.is_none());
}

#[test]
fn update_due_uses_default_and_clamped_provider_intervals() {
    let mut sub = subscription("1");
    let now = 200 * 60 * 60;
    assert!(update_due(&sub, now, None));
    sub.updated_at_unix = Some(now - 11 * 60 * 60);
    assert!(!update_due(&sub, now, None));
    sub.updated_at_unix = Some(now - 12 * 60 * 60);
    assert!(update_due(&sub, now, None));

    sub.update_interval_hours = Some(1);
    sub.updated_at_unix = Some(now - 2 * 60 * 60);
    assert!(update_due(&sub, now, None));
    sub.update_interval_hours = Some(0);
    sub.updated_at_unix = Some(now - 60 * 60);
    assert!(update_due(&sub, now, None));
    sub.update_interval_hours = Some(1000);
    sub.updated_at_unix = Some(now - 167 * 60 * 60);
    assert!(!update_due(&sub, now, None));
    sub.updated_at_unix = Some(now - 168 * 60 * 60);
    assert!(update_due(&sub, now, None));
    assert!(!update_due(&sub, now, Some(now - 10 * 60)));
    assert!(update_due(&sub, now, Some(now - 2 * 60 * 60)));
}

#[test]
fn shared_auto_update_interval_requires_matching_subscriptions() {
    assert_eq!(shared_auto_update_hours(&[]), None);
    let mut subscriptions = vec![subscription("1"), subscription("2")];
    assert_eq!(shared_auto_update_hours(&subscriptions), Some(12));
    subscriptions[0].update_interval_hours = Some(0);
    assert_eq!(shared_auto_update_hours(&subscriptions[..1]), Some(1));
    subscriptions[0].update_interval_hours = Some(500);
    assert_eq!(shared_auto_update_hours(&subscriptions[..1]), Some(168));
    subscriptions[0].update_interval_hours = Some(12);
    subscriptions[1].update_interval_hours = Some(24);
    assert_eq!(shared_auto_update_hours(&subscriptions), None);
}

#[test]
fn renaming_subscription_validates_and_tracks_the_result() {
    let mut state = state_with_subscriptions();
    let id = SubscriptionId::new("1");
    state.config.subscriptions[0].name = "🇳🇱 Provider".to_owned();
    state.act(Action::RequestRename(id.clone()));
    let dialog = state.subscriptions.rename.as_ref().unwrap();
    assert_eq!(dialog.name, "[NL] Provider");
    assert_eq!(dialog.original, dialog.name);
    assert!(dialog.focus);
    assert!(state.act(Action::RequestRename(id.clone())).is_none());
    assert_eq!(
        state.subscriptions.rename.as_ref().unwrap().name,
        "[NL] Provider"
    );

    state.subscriptions.rename.as_mut().unwrap().name = "  [NL] Provider  ".to_owned();
    assert!(state.act(Action::SubmitRename).is_none());
    assert!(state.subscriptions.rename.is_none());
    state.act(Action::RequestRename(id.clone()));
    state.subscriptions.rename.as_mut().unwrap().name = "   ".to_owned();
    assert!(state.act(Action::SubmitRename).is_none());
    assert!(state.subscriptions.rename.is_some());

    state.subscriptions.rename.as_mut().unwrap().name = "  New name  ".to_owned();
    assert!(matches!(
        state.act(Action::SubmitRename),
        Some(Job::RenameSubscription(job_id, name)) if job_id == id && name == "New name"
    ));
    assert!(state.operations.renaming);
    assert!(state.act(Action::SubmitRename).is_none());
    state.act(Action::CancelRename);
    assert!(state.subscriptions.rename.is_some());
    state.reduce(WorkerEvent::RenameSubscription(Err(
        rosetun_core::RenameSubscriptionError::EmptyName,
    )));
    assert!(!state.operations.renaming);
    assert_eq!(
        state
            .subscriptions
            .rename
            .as_ref()
            .unwrap()
            .error
            .as_deref(),
        Some(tr!("error-subscription-name-empty")).as_deref()
    );
    assert!(state.act(Action::SubmitRename).is_some());
    state.reduce(WorkerEvent::RenameSubscription(Ok(())));
    assert!(state.subscriptions.rename.is_none());
    assert!(!state.operations.renaming);
}

#[test]
fn auto_update_checks_once_per_minute_and_starts_one_due_subscription() {
    let mut state = state_with_subscriptions();
    let now = 200_000;
    assert!(
        matches!(state.take_auto_update(now), Some(Job::Update(id)) if id == SubscriptionId::new("1"))
    );
    assert!(state.take_auto_update(now).is_none());
    state.reduce(WorkerEvent::Update {
        id: SubscriptionId::new("1"),
        result: Err(UpdateSubscriptionError::NotFound),
    });
    assert!(
        matches!(state.take_auto_update(now + AUTO_UPDATE_CHECK), Some(Job::Update(id)) if id == SubscriptionId::new("2"))
    );
    assert!(
        !state
            .operations
            .updating
            .contains(&SubscriptionId::new("1"))
    );
    assert!(
        state
            .operations
            .updating
            .contains(&SubscriptionId::new("2"))
    );
}

#[test]
fn auto_update_waits_for_config_and_update_all() {
    let mut state = state_with_subscriptions();
    state.config_ready = false;
    assert!(state.take_auto_update(1_000).is_none());
    state.config_ready = true;
    state.operations.update_all = true;
    assert!(state.take_auto_update(1_060).is_none());
    state.operations.update_all = false;
    assert!(matches!(
        state.take_auto_update(1_120),
        Some(Job::Update(_))
    ));
}

#[test]
fn auto_update_respects_setting_and_connection_transitions() {
    let mut state = state_with_subscriptions();
    state.config.interface.auto_update_subscriptions = false;
    assert!(state.take_auto_update(1_000).is_none());
    state.config.interface.auto_update_subscriptions = true;
    state.status.state = ConnectionState::Connecting;
    assert!(state.take_auto_update(1_060).is_none());
    state.status.state = ConnectionState::Reconnecting;
    assert!(state.take_auto_update(1_120).is_none());
    state.status.state = ConnectionState::FailedProtected {
        failure_kind: None,
        reason: "failure".into(),
    };
    assert!(state.take_auto_update(1_180).is_none());
    state.status.state = ConnectionState::Connected;
    assert!(matches!(
        state.take_auto_update(1_240),
        Some(Job::Update(_))
    ));
}

#[test]
fn ping_starts_only_with_tunnel_down_and_marks_nodes_pending() {
    let mut state = state_for_auto_connect();
    let id = SubscriptionId::new("1");
    let node = NodeId::new("node");
    state.status.state = ConnectionState::Connected;
    assert!(state.act(Action::Ping(id.clone())).is_none());
    state.status.state = ConnectionState::Disconnected;
    state.operations.helper = true;
    assert!(state.act(Action::Ping(id.clone())).is_none());
    state.operations.helper = false;
    assert!(matches!(state.act(Action::Ping(id.clone())), Some(Job::Ping(found)) if found == id));
    assert_eq!(
        state.subscriptions.pings[&(id.clone(), node)],
        PingResult::Pending
    );
    assert!(state.operations.pinging.contains(&id));
    assert!(state.act(Action::Ping(id.clone())).is_none());
    state.reduce(WorkerEvent::PingDone(id.clone()));
    assert!(!state.operations.pinging.contains(&id));
}

#[test]
fn ping_results_finish_missing_answers_and_prune_removed_nodes() {
    let mut state = state_for_auto_connect();
    let mut second = state.config.subscriptions[0].nodes[0].clone();
    second.id = NodeId::new("second");
    state.config.subscriptions[0].nodes.push(second.clone());
    let mut udp = second;
    udp.id = NodeId::new("udp");
    udp.outbound = rosetun_config::Outbound::Hysteria2(rosetun_config::Hysteria2Params {
        password: "test-secret".into(),
        obfs_password: None,
        port_ranges: Vec::new(),
        up_mbps: None,
        down_mbps: None,
    });
    state.config.subscriptions[0].nodes.push(udp);
    let id = SubscriptionId::new("1");
    let first = NodeId::new("node");
    let second = NodeId::new("second");
    assert!(matches!(
        state.act(Action::Ping(id.clone())),
        Some(Job::Ping(_))
    ));
    state.reduce(WorkerEvent::Ping {
        subscription: id.clone(),
        node: first.clone(),
        result: Ping::Answered(Duration::from_millis(118)),
    });
    state.reduce(WorkerEvent::Ping {
        subscription: id.clone(),
        node: NodeId::new("udp"),
        result: Ping::Unsupported,
    });
    state.reduce(WorkerEvent::PingDone(id.clone()));
    assert_eq!(
        state.subscriptions.pings[&(id.clone(), first.clone())],
        PingResult::Answered(Duration::from_millis(118))
    );
    assert_eq!(
        state.subscriptions.pings[&(id.clone(), second.clone())],
        PingResult::NoAnswer
    );
    assert_eq!(
        state.subscriptions.pings[&(id.clone(), NodeId::new("udp"))],
        PingResult::Unsupported
    );
    assert_eq!(
        state.best_ping(&state.config.subscriptions[0]),
        Some(Duration::from_millis(118))
    );

    state.config.subscriptions[0]
        .nodes
        .retain(|node| node.id != first);
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config: state.config.clone(),
    });
    assert!(!state.subscriptions.pings.contains_key(&(id, first)));
    assert!(state.best_ping(&state.config.subscriptions[0]).is_none());
}

#[test]
fn single_node_ping_preserves_other_results_and_rejects_busy_checks() {
    let mut state = state_for_auto_connect();
    let id = SubscriptionId::new("1");
    let first = NodeId::new("node");
    let mut other = state.config.subscriptions[0].nodes[0].clone();
    other.id = NodeId::new("second");
    state.config.subscriptions[0].nodes.push(other);
    let second = NodeId::new("second");
    let previous = PingResult::Works(Duration::from_millis(44));
    state
        .subscriptions
        .pings
        .insert((id.clone(), second.clone()), previous);

    assert!(matches!(
        state.act(Action::PingNode(id.clone(), first.clone())),
        Some(Job::PingNode(subscription, node)) if subscription == id && node == first
    ));
    assert_eq!(
        state.subscriptions.pings[&(id.clone(), first.clone())],
        PingResult::Pending
    );
    assert_eq!(
        state.subscriptions.pings[&(id.clone(), second.clone())],
        previous
    );
    assert!(state.act(Action::Ping(id.clone())).is_none());
    assert!(
        state
            .act(Action::FullCheckNode(id.clone(), second.clone()))
            .is_none()
    );

    state.reduce(WorkerEvent::PingDone(id.clone()));
    assert_eq!(
        state.subscriptions.pings[&(id.clone(), first.clone())],
        PingResult::NoAnswer
    );
    assert_eq!(
        state.subscriptions.pings[&(id.clone(), second.clone())],
        previous
    );
    assert!(matches!(
        state.act(Action::PingNode(id.clone(), first.clone())),
        Some(Job::PingNode(_, _))
    ));
    state.reduce(WorkerEvent::Ping {
        subscription: id.clone(),
        node: first.clone(),
        result: Ping::Answered(Duration::from_millis(90)),
    });
    state.reduce(WorkerEvent::PingDone(id.clone()));
    assert_eq!(
        state.subscriptions.pings[&(id.clone(), first)],
        PingResult::Answered(Duration::from_millis(90))
    );
    assert_eq!(state.subscriptions.pings[&(id, second)], previous);
}

#[test]
fn single_node_check_rejects_missing_nodes_and_connected_quick_checks() {
    let mut state = state_for_auto_connect();
    let id = SubscriptionId::new("1");
    let node = NodeId::new("node");
    let missing = NodeId::new("missing");
    assert!(
        state
            .act(Action::PingNode(id.clone(), missing.clone()))
            .is_none()
    );
    assert!(
        state
            .act(Action::FullCheckNode(id.clone(), missing))
            .is_none()
    );
    assert!(state.subscriptions.pings.is_empty());
    assert!(!state.operations.pinging.contains(&id));

    state.status.state = ConnectionState::Connected;
    assert!(
        state
            .act(Action::PingNode(id.clone(), node.clone()))
            .is_none()
    );
    assert!(matches!(
        state.act(Action::FullCheckNode(id.clone(), node.clone())),
        Some(Job::FullCheckNode(subscription, selected)) if subscription == id && selected == node
    ));
}

#[test]
fn single_node_full_check_preserves_other_results_and_ignores_removed_node() {
    let mut state = state_for_auto_connect();
    let id = SubscriptionId::new("1");
    let first = NodeId::new("node");
    let mut other = state.config.subscriptions[0].nodes[0].clone();
    other.id = NodeId::new("second");
    state.config.subscriptions[0].nodes.push(other);
    let second = NodeId::new("second");
    let previous = PingResult::Answered(Duration::from_millis(55));
    state
        .subscriptions
        .pings
        .insert((id.clone(), second.clone()), previous);

    assert!(matches!(
        state.act(Action::FullCheckNode(id.clone(), first.clone())),
        Some(Job::FullCheckNode(_, _))
    ));
    assert_eq!(
        state.subscriptions.pings[&(id.clone(), first.clone())],
        PingResult::Pending
    );
    assert_eq!(
        state.subscriptions.pings[&(id.clone(), second.clone())],
        previous
    );
    state.reduce(WorkerEvent::FullCheck {
        subscription: id.clone(),
        result: Err(HelperCommandError::Client(ClientError::Closed)),
    });
    assert!(
        !state
            .subscriptions
            .pings
            .contains_key(&(id.clone(), first.clone()))
    );
    assert_eq!(
        state.subscriptions.pings[&(id.clone(), second.clone())],
        previous
    );
    assert!(!state.operations.pinging.contains(&id));

    state.act(Action::FullCheckNode(id.clone(), first.clone()));
    state.reduce(WorkerEvent::FullCheck {
        subscription: id.clone(),
        result: Ok(vec![ProbeResult {
            node: first.clone(),
            outcome: ProbeOutcome::Works { millis: 76 },
        }]),
    });
    assert_eq!(
        state.subscriptions.pings[&(id.clone(), first.clone())],
        PingResult::Works(Duration::from_millis(76))
    );
    assert_eq!(
        state.subscriptions.pings[&(id.clone(), second.clone())],
        previous
    );

    state.act(Action::FullCheckNode(id.clone(), first.clone()));
    state.config.subscriptions[0]
        .nodes
        .retain(|node| node.id != first);
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config: state.config.clone(),
    });
    state.reduce(WorkerEvent::FullCheck {
        subscription: id.clone(),
        result: Ok(vec![ProbeResult {
            node: first.clone(),
            outcome: ProbeOutcome::Fails,
        }]),
    });
    assert!(!state.subscriptions.pings.contains_key(&(id.clone(), first)));
    assert_eq!(state.subscriptions.pings[&(id.clone(), second)], previous);
    assert!(!state.operations.pinging.contains(&id));
}

#[test]
fn full_check_runs_while_connected_and_maps_outcomes() {
    let mut state = state_for_auto_connect();
    let id = SubscriptionId::new("1");
    let mut second = state.config.subscriptions[0].nodes[0].clone();
    second.id = NodeId::new("second");
    state.config.subscriptions[0].nodes.push(second);
    state.status.state = ConnectionState::Connected;
    assert!(!state.can_ping());
    assert!(state.can_full_check());
    assert!(matches!(
        state.act(Action::FullCheck(id.clone())),
        Some(Job::FullCheck(_))
    ));
    assert_eq!(
        state.subscriptions.pings[&(id.clone(), NodeId::new("node"))],
        PingResult::Pending
    );
    assert_eq!(
        state.subscriptions.pings[&(id.clone(), NodeId::new("second"))],
        PingResult::Pending
    );
    assert!(state.act(Action::FullCheck(id.clone())).is_none());
    state.reduce(WorkerEvent::FullCheck {
        subscription: id.clone(),
        result: Ok(vec![
            ProbeResult {
                node: NodeId::new("node"),
                outcome: ProbeOutcome::Works { millis: 85 },
            },
            ProbeResult {
                node: NodeId::new("second"),
                outcome: ProbeOutcome::Fails,
            },
            ProbeResult {
                node: NodeId::new("removed"),
                outcome: ProbeOutcome::Unresolved,
            },
        ]),
    });
    assert_eq!(
        state.subscriptions.pings[&(id.clone(), NodeId::new("node"))],
        PingResult::Works(Duration::from_millis(85))
    );
    assert_eq!(
        state.subscriptions.pings[&(id.clone(), NodeId::new("second"))],
        PingResult::Fails
    );
    assert!(
        !state
            .subscriptions
            .pings
            .contains_key(&(id.clone(), NodeId::new("removed")))
    );
    assert!(!state.operations.pinging.contains(&id));
}

#[test]
fn full_check_clears_missing_results_and_pending_on_error() {
    let mut state = state_for_auto_connect();
    let id = SubscriptionId::new("1");
    let mut second = state.config.subscriptions[0].nodes[0].clone();
    second.id = NodeId::new("second");
    state.config.subscriptions[0].nodes.push(second);
    state.act(Action::FullCheck(id.clone()));
    state.reduce(WorkerEvent::FullCheck {
        subscription: id.clone(),
        result: Ok(vec![ProbeResult {
            node: NodeId::new("node"),
            outcome: ProbeOutcome::Unresolved,
        }]),
    });
    assert_eq!(
        state.subscriptions.pings[&(id.clone(), NodeId::new("node"))],
        PingResult::Unresolved
    );
    assert!(
        !state
            .subscriptions
            .pings
            .contains_key(&(id.clone(), NodeId::new("second")))
    );
    state.act(Action::FullCheck(id.clone()));
    state.reduce(WorkerEvent::FullCheck {
        subscription: id.clone(),
        result: Err(HelperCommandError::Client(ClientError::Helper(
            HelperError::new(ErrorCode::Busy, ""),
        ))),
    });
    assert!(
        !state
            .subscriptions
            .pings
            .contains_key(&(id.clone(), NodeId::new("node")))
    );
    assert!(!state.operations.pinging.contains(&id));
    assert_eq!(
        state.operation_error.as_deref(),
        Some(tr!("full-check-busy")).as_deref()
    );

    state.act(Action::FullCheck(id.clone()));
    state.reduce(WorkerEvent::FullCheck {
        subscription: id.clone(),
        result: Err(HelperCommandError::Client(ClientError::Closed)),
    });
    assert_eq!(
        state.operation_error.as_deref(),
        Some(
            errors::helper_command(
                crate::i18n::language(),
                &HelperCommandError::Client(ClientError::Closed)
            )
            .as_str()
        )
    );
    assert!(
        !state
            .subscriptions
            .pings
            .contains_key(&(id, NodeId::new("second")))
    );
}

#[test]
fn best_ping_ignores_unanswered_nodes_and_chooses_smallest_answer() {
    let mut state = state_for_auto_connect();
    let id = SubscriptionId::new("1");
    let mut second = state.config.subscriptions[0].nodes[0].clone();
    second.id = NodeId::new("second");
    state.config.subscriptions[0].nodes.push(second);
    assert!(state.best_ping(&state.config.subscriptions[0]).is_none());
    state.subscriptions.pings.insert(
        (id.clone(), NodeId::new("node")),
        PingResult::Answered(Duration::from_millis(118)),
    );
    state.subscriptions.pings.insert(
        (id.clone(), NodeId::new("second")),
        PingResult::Works(Duration::from_millis(40)),
    );
    assert_eq!(
        state.best_ping(&state.config.subscriptions[0]),
        Some(Duration::from_millis(40))
    );
    state
        .subscriptions
        .pings
        .insert((id, NodeId::new("second")), PingResult::Fails);
    assert_eq!(
        state.best_ping(&state.config.subscriptions[0]),
        Some(Duration::from_millis(118))
    );
}

#[test]
fn update_all_associates_outcomes_with_subscription_ids() {
    let mut state = State::default();
    state.operations.update_all = true;
    state.reduce(WorkerEvent::UpdateAll(Ok(vec![
        (
            SubscriptionId::new("2"),
            Err(UpdateSubscriptionError::NotFound),
        ),
        (SubscriptionId::new("1"), Ok((subscription("1"), report()))),
    ])));
    assert!(!state.operations.update_all);
    assert!(matches!(
        state.subscriptions.outcomes[&SubscriptionId::new("1")],
        UpdateOutcome::Success(_)
    ));
    assert!(matches!(
        state.subscriptions.outcomes[&SubscriptionId::new("2")],
        UpdateOutcome::Error(_)
    ));
    state.operations.update_all = true;
    state.reduce(WorkerEvent::UpdateAll(Err(StoreError::NoConfigDir)));
    assert!(!state.operations.update_all);
    assert!(state.operation_error.is_some());
}

#[test]
fn provider_announcement_in_translated_error_redacts_subscription_url() {
    let url = "https://sub.example.com/private-token";
    let mut subscription = subscription("1");
    subscription.url = url.into();
    let config = AppConfig {
        subscriptions: vec![subscription],
        ..AppConfig::default()
    };
    let error = UpdateSubscriptionError::Fetch {
        source: FetchError::Parse(ParseError::DeviceLimit {
            max_devices_reached: true,
            not_supported: false,
            announce: Some(format!("see {url}")),
        }),
        message: "CLI only".into(),
    };
    let text = redact(
        &config,
        &errors::update_subscription(crate::i18n::Language::Russian, &error),
    );
    assert!(!text.contains("private-token"));
    assert!(text.contains("https://sub.example.com/…"));
}

#[test]
fn add_failure_keeps_inputs_and_success_closes_and_expands() {
    let mut state = State::default();
    state.act(Action::OpenAdd);
    state.subscriptions.add.as_mut().unwrap().url = "https://example.com/sub".into();
    assert!(matches!(
        state.act(Action::SubmitAdd),
        Some(Job::Add { .. })
    ));
    assert!(state.act(Action::CancelAdd).is_none());
    assert!(state.subscriptions.add.is_some());
    state.reduce(WorkerEvent::Add(Err(AddFromUrlError::MissingHost)));
    let dialog = state.subscriptions.add.as_ref().unwrap();
    assert_eq!(dialog.url, "https://example.com/sub");
    assert!(!dialog.busy);
    assert!(dialog.error.is_some());
    state.reduce(WorkerEvent::Add(Ok((subscription("1"), report()))));
    assert!(state.subscriptions.add.is_none());
    assert!(
        state
            .subscriptions
            .expanded
            .contains(&SubscriptionId::new("1"))
    );
}

#[test]
fn individual_update_and_remove_failures_clear_their_flags() {
    let mut state = State::default();
    let id = SubscriptionId::new("1");
    assert!(matches!(
        state.act(Action::Update(id.clone())),
        Some(Job::Update(_))
    ));
    assert!(state.act(Action::Update(id.clone())).is_none());
    state.reduce(WorkerEvent::Update {
        id: id.clone(),
        result: Err(UpdateSubscriptionError::NotFound),
    });
    assert!(!state.subscription_busy(&id));
    state.act(Action::RequestRemove(id.clone()));
    assert!(matches!(
        state.act(Action::ConfirmRemove),
        Some(Job::Remove(_))
    ));
    state.reduce(WorkerEvent::Remove {
        id,
        result: Err(RemoveSubscriptionError::SubscriptionNotFound),
    });
    assert!(!state.operations.removing);
    assert!(state.subscriptions.remove.as_ref().unwrap().error.is_some());
}

#[test]
fn provider_controlled_labels_cannot_echo_subscription_urls() {
    let mut state = State::default();
    state.config.subscriptions.push(subscription("1"));
    assert_eq!(
        state.text("🇩🇪 https://example.com/secret-path\nnext"),
        "[DE] https://example.com/…\nnext"
    );
}
