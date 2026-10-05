use rosetun_config::{NodeId, Selection, SubscriptionId};

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
