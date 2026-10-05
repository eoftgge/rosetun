use rosetun_config::{NodeId, RuleSetId, Selection, SubscriptionId};

use crate::{Store, StoreError};

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

        config.active = Some(Selection {
            subscription: subscription_id.clone(),
            node: node_id.clone(),
        });

        Ok(node_name)
    })
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
