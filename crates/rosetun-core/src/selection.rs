use rosetun_config::{AppConfig, NodeId, RuleSetId, Selection, SubscriptionId};

use crate::{Store, StoreError};

/// How many recently chosen servers the tray offers.
pub const MAX_RECENT_SERVERS: usize = 5;

#[derive(Debug, thiserror::Error)]
pub enum SelectNodeError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("subscription does not exist")]
    SubscriptionNotFound,
    #[error("node is not in the specified subscription")]
    NodeNotFound,
}

/// Selects an existing node in the current configuration.
/// Returns the node name only after the configuration has been saved.
pub fn select_node(
    store: &Store,
    subscription_id: &SubscriptionId,
    node_id: &NodeId,
) -> Result<String, SelectNodeError> {
    store.modify(|config| {
        let subscription = config
            .subscriptions
            .iter()
            .find(|subscription| &subscription.id == subscription_id)
            .ok_or(SelectNodeError::SubscriptionNotFound)?;

        let node_name = subscription
            .node(node_id)
            .ok_or(SelectNodeError::NodeNotFound)?
            .name
            .clone();

        let selection = Selection {
            subscription: subscription_id.clone(),
            node: node_id.clone(),
        };
        remember_server(config, &selection);
        config.active = Some(selection);

        Ok(node_name)
    })
}

/// Puts `selection` first among the recent servers. Servers that no
/// subscription has any more drop out here, in the same save.
fn remember_server(config: &mut AppConfig, selection: &Selection) {
    let mut recent = std::mem::take(&mut config.interface.recent_servers);
    recent.retain(|item| item != selection && config.node_at(item).is_some());
    recent.insert(0, selection.clone());
    recent.truncate(MAX_RECENT_SERVERS);
    config.interface.recent_servers = recent;
}

#[derive(Debug, thiserror::Error)]
pub enum SelectRuleSetError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("rule set does not exist")]
    NotFound,
}

pub fn select_rule_set(
    store: &Store,
    rule_set_id: Option<&RuleSetId>,
) -> Result<(), SelectRuleSetError> {
    store.modify(|config| {
        if let Some(id) = rule_set_id
            && !config.rule_sets.iter().any(|rule_set| &rule_set.id == id)
        {
            return Err(SelectRuleSetError::NotFound);
        }
        config.active_rule_set = rule_set_id.cloned();
        Ok(())
    })
}

pub fn set_kill_switch(store: &Store, enabled: bool) -> Result<(), StoreError> {
    store.modify(|config| {
        config.settings.kill_switch = enabled;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use rosetun_config::{Node, Subscription};

    use super::*;

    fn config(nodes: &[&str]) -> AppConfig {
        let nodes = nodes
            .iter()
            .map(|id| {
                serde_json::from_value::<Node>(serde_json::json!({
                    "id": id,
                    "name": id,
                    "server": "example.com",
                    "port": 443,
                    "outbound": {"trojan": {"password": "test"}},
                }))
                .unwrap()
            })
            .collect();
        AppConfig {
            subscriptions: vec![Subscription {
                nodes,
                ..serde_json::from_value(serde_json::json!({
                    "id": "provider",
                    "name": "Provider",
                    "url": "https://example.com",
                }))
                .unwrap()
            }],
            ..AppConfig::default()
        }
    }

    fn pick(node: &str) -> Selection {
        Selection {
            subscription: SubscriptionId::new("provider"),
            node: NodeId::new(node),
        }
    }

    fn recent(config: &AppConfig) -> Vec<&str> {
        config
            .interface
            .recent_servers
            .iter()
            .map(|selection| selection.node.as_str())
            .collect()
    }

    #[test]
    fn recent_servers_keep_the_last_five_newest_first() {
        let mut config = config(&["a", "b", "c", "d", "e", "f"]);
        for node in ["a", "b", "c", "d", "e", "f"] {
            remember_server(&mut config, &pick(node));
        }
        assert_eq!(recent(&config), ["f", "e", "d", "c", "b"]);
    }

    #[test]
    fn choosing_a_recent_server_again_moves_it_to_the_top() {
        let mut config = config(&["a", "b", "c"]);
        for node in ["a", "b", "c", "a"] {
            remember_server(&mut config, &pick(node));
        }
        assert_eq!(recent(&config), ["a", "c", "b"]);
    }

    #[test]
    fn a_vanished_server_drops_out_on_the_next_choice() {
        let mut config = config(&["a", "b"]);
        config.interface.recent_servers = vec![pick("gone"), pick("a")];
        remember_server(&mut config, &pick("b"));
        assert_eq!(recent(&config), ["b", "a"]);
    }
}
