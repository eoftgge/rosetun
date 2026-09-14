use serde::{Deserialize, Serialize};

use crate::{Node, NodeId, SubscriptionId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    pub id: SubscriptionId,
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub auto_update: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at_unix: Option<u64>,
}

impl Subscription {
    pub fn node(&self, id: &NodeId) -> Option<&Node> {
        self.nodes.iter().find(|node| &node.id == id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Selection {
    pub subscription: SubscriptionId,
    pub node: NodeId,
}