use super::*;

impl WorkerDispatcher {
    pub(crate) fn select_node(&self, subscription: SubscriptionId, node: NodeId) {
        self.spawn_complete("rosetun-select-node", move |store| {
            WorkerEvent::SelectNode(select_node(store, &subscription, &node))
        });
    }

    pub(crate) fn add(&self, input: String, options: AddOptions) {
        self.spawn_complete("rosetun-add", move |store| {
            let result = prepare_subscription(store, &input, options).and_then(|prepared| {
                add_prepared_subscription(store, prepared, Timeouts::default())
            });
            if let Err(error) = &result {
                log_subscription_error("add", error);
            }
            WorkerEvent::Add(result)
        });
    }

    pub(crate) fn update(&self, id: SubscriptionId) {
        self.spawn_complete("rosetun-update", move |store| {
            let result = update_subscription(store, &id, Timeouts::default());
            if let Err(error) = &result {
                log_subscription_error("update", error);
            }
            WorkerEvent::Update { id, result }
        });
    }

    pub(crate) fn ping(&self, id: SubscriptionId, node: Option<NodeId>) {
        self.spawn_task("rosetun-ping", move |publisher| {
            let subscription = publisher.store.load().ok().and_then(|config| {
                config
                    .subscriptions
                    .into_iter()
                    .find(|subscription| subscription.id == id)
            });
            if let Some(subscription) = subscription {
                let nodes = check_nodes(&subscription, node.as_ref());
                let (tcp_nodes, unsupported) = ping_targets(&nodes);
                for node in unsupported {
                    emit(
                        &publisher.tx,
                        &publisher.repaint,
                        WorkerEvent::Ping {
                            subscription: id.clone(),
                            node: node.id.clone(),
                            result: Ping::Unsupported,
                        },
                    );
                }
                let targets: Vec<_> = tcp_nodes
                    .iter()
                    .map(|node| (node.server.clone(), node.port))
                    .collect();
                if !targets.is_empty() {
                    ping_all(&targets, PING_PARALLEL, PING_TIMEOUT, |index, result| {
                        emit(
                            &publisher.tx,
                            &publisher.repaint,
                            WorkerEvent::Ping {
                                subscription: id.clone(),
                                node: tcp_nodes[index].id.clone(),
                                result,
                            },
                        );
                    });
                }
            }
            emit(&publisher.tx, &publisher.repaint, WorkerEvent::PingDone(id));
        });
    }

    pub(crate) fn full_check(&self, id: SubscriptionId, node: Option<NodeId>) {
        self.spawn_complete("rosetun-full-check", move |store| {
            let result = store
                .load()
                .map_err(HelperCommandError::Store)
                .and_then(|config| {
                    let Some(subscription) = config.subscriptions.iter().find(|sub| sub.id == id)
                    else {
                        return Ok(Vec::new());
                    };
                    let nodes = check_nodes(subscription, node.as_ref())
                        .into_iter()
                        .take(MAX_PROBE_NODES)
                        .cloned()
                        .collect();
                    let request = ProbeRequest {
                        nodes,
                        settings: config.settings.clone(),
                    };
                    if request.nodes.is_empty() {
                        return Ok(Vec::new());
                    }
                    with_helper(|client| client.probe_nodes(request))
                });
            WorkerEvent::FullCheck {
                subscription: id,
                result,
            }
        });
    }

    pub(crate) fn update_all(&self) {
        self.spawn_complete("rosetun-update-all", move |store| {
            let result = update_all(store, Timeouts::default());
            match &result {
                Ok(results) => {
                    for (_, outcome) in results {
                        if let Err(error) = outcome {
                            log_subscription_error("update all", error);
                        }
                    }
                }
                Err(error) => log_subscription_error("update all", error),
            }
            WorkerEvent::UpdateAll(result)
        });
    }

    pub(crate) fn remove(&self, id: SubscriptionId) {
        self.spawn_complete("rosetun-remove", move |store| {
            let result = remove_subscription(store, &id);
            if let Err(error) = &result {
                log_subscription_error("remove", error);
            }
            WorkerEvent::Remove { id, result }
        });
    }

    pub(crate) fn rename_subscription(&self, id: SubscriptionId, name: String) {
        self.spawn_complete("rosetun-rename-subscription", move |store| {
            let result = rename_subscription(store, &id, &name);
            if let Err(error) = &result {
                log_subscription_error("rename", error);
            }
            WorkerEvent::RenameSubscription(result)
        });
    }

    pub(crate) fn move_subscription(&self, id: SubscriptionId, to_index: usize) {
        self.spawn_complete("rosetun-move-subscription", move |store| {
            let result = move_subscription(store, &id, to_index);
            if let Err(error) = &result {
                log_subscription_error("move", error);
            }
            WorkerEvent::MoveSubscription(result)
        });
    }
}

fn check_nodes<'a>(subscription: &'a Subscription, selected: Option<&NodeId>) -> Vec<&'a Node> {
    subscription
        .nodes
        .iter()
        .filter(|node| selected.is_none_or(|id| &node.id == id))
        .collect()
}

fn ping_targets<'a>(nodes: &[&'a Node]) -> (Vec<&'a Node>, Vec<&'a Node>) {
    nodes
        .iter()
        .copied()
        .partition(|node| !matches!(&node.outbound, rosetun_config::Outbound::Hysteria2(_)))
}

fn log_subscription_error(operation: &str, error: &impl std::fmt::Display) {
    let message = without_urls(&error.to_string());
    tracing::warn!(operation, error = %message, "Subscription operation failed");
}

fn without_urls(message: &str) -> String {
    message
        .split_whitespace()
        .map(|word| if word.contains("://") { "[URL]" } else { word })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_nodes_selects_one_node_or_all_and_skips_removed_nodes() {
        let first = Node {
            id: NodeId::new("first"),
            name: "First".into(),
            server: "127.0.0.1".into(),
            port: 443,
            outbound: rosetun_config::Outbound::Vless(rosetun_config::VlessParams {
                uuid: "00000000-0000-0000-0000-000000000000".into(),
                flow: None,
            }),
            stream: Default::default(),
            raw: None,
        };
        let mut second = first.clone();
        second.id = NodeId::new("second");
        let subscription = Subscription {
            id: SubscriptionId::new("test"),
            name: "Test".into(),
            url: "https://example.com/sub".into(),
            nodes: vec![first, second],
            auto_update: false,
            updated_at_unix: None,
            user_agent: None,
            send_hwid: true,
            info: None,
            update_interval_hours: None,
            support_url: None,
            web_page_url: None,
            announce: None,
            notices: vec![],
        };
        assert_eq!(check_nodes(&subscription, None).len(), 2);
        assert_eq!(
            check_nodes(&subscription, Some(&NodeId::new("second")))[0].id,
            NodeId::new("second")
        );
        assert!(check_nodes(&subscription, Some(&NodeId::new("removed"))).is_empty());
    }

    #[test]
    fn hysteria2_is_excluded_from_tcp_ping_without_dropping_vless() {
        let tcp = Node {
            id: NodeId::new("tcp"),
            name: "TCP".into(),
            server: "192.0.2.1".into(),
            port: 443,
            outbound: rosetun_config::Outbound::Vless(rosetun_config::VlessParams {
                uuid: "11111111-1111-1111-1111-111111111111".into(),
                flow: None,
            }),
            stream: Default::default(),
            raw: None,
        };
        let mut udp = tcp.clone();
        udp.id = NodeId::new("udp");
        udp.outbound = rosetun_config::Outbound::Hysteria2(rosetun_config::Hysteria2Params {
            password: "test-secret".into(),
            obfs_password: None,
            port_ranges: Vec::new(),
            up_mbps: None,
            down_mbps: None,
        });
        let (targets, unsupported) = ping_targets(&[&udp, &tcp]);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].id, tcp.id);
        assert_eq!(unsupported.len(), 1);
        assert_eq!(unsupported[0].id, udp.id);
    }

    #[test]
    fn subscription_errors_do_not_log_urls_or_tokens() {
        assert_eq!(
            without_urls(
                "request failed for happ://add/https://example.com/sub?token=secret: timeout"
            ),
            "request failed for [URL] timeout"
        );
        assert_eq!(
            without_urls("subscription does not exist"),
            "subscription does not exist"
        );
    }
}
