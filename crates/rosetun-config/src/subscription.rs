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

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SubscriptionInfo {
    #[serde(default)]
    pub upload: u64,
    #[serde(default)]
    pub download: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire_unix: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::SubscriptionInfo;

    #[test]
    fn subscription_info_round_trip() {
        let info = SubscriptionInfo {
            upload: 1,
            download: 2,
            total: Some(3),
            expire_unix: Some(4),
        };

        let encoded = serde_json::to_string(&info).unwrap();
        let decoded: SubscriptionInfo = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded, info);
    }

    #[test]
    fn subscription_info_missing_fields_use_defaults() {
        let info: SubscriptionInfo = serde_json::from_str("{}").unwrap();

        assert_eq!(info, SubscriptionInfo::default());
    }

    #[test]
    fn subscription_info_unlimited_fields_are_omitted() {
        let encoded = serde_json::to_value(SubscriptionInfo::default()).unwrap();

        assert_eq!(
            encoded,
            serde_json::json!({
                "upload": 0,
                "download": 0,
            })
        );
    }
}
