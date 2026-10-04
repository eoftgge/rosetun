use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Node, NodeId, SubscriptionId};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(default = "crate::default_true")]
    pub send_hwid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<SubscriptionInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_interval_hours: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_page_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announce: Option<String>,
    #[serde(default)]
    pub notices: Vec<String>,
}

impl fmt::Debug for Subscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subscription")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("host", &debug_host(&self.url))
            .field("node_count", &self.nodes.len())
            .finish()
    }
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

fn debug_host(value: &str) -> &str {
    // Only a conservative authority projection is used for diagnostics; malformed
    // input is hidden rather than echoed, including credentials and URL suffixes.
    let Some((scheme, remainder)) = value.split_once("://") else {
        return "<redacted>";
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return "<redacted>";
    }

    let authority = remainder
        .split(['/', '?', '#', '\\'])
        .next()
        .unwrap_or_default();
    let authority = authority.rsplit('@').next().unwrap_or_default();

    if let Some(ipv6) = authority.strip_prefix('[') {
        let Some((address, suffix)) = ipv6.split_once(']') else {
            return "<redacted>";
        };
        if address.parse::<std::net::Ipv6Addr>().is_err()
            || (!suffix.is_empty()
                && suffix
                    .strip_prefix(':')
                    .is_none_or(|port| port.parse::<u16>().is_err()))
        {
            return "<redacted>";
        }
        return &authority[..address.len() + 2];
    }

    let host = authority.split(':').next().unwrap_or_default();
    if host.is_empty()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return "<redacted>";
    }
    host
}

#[cfg(test)]
mod tests {
    use super::{Subscription, SubscriptionInfo};

    #[test]
    fn old_subscription_uses_new_field_defaults() {
        let subscription: Subscription = serde_json::from_value(serde_json::json!({
            "id": "1",
            "name": "Example",
            "url": "https://sub.example.com/private?token=secret"
        }))
        .unwrap();

        assert!(subscription.send_hwid);
        assert!(subscription.user_agent.is_none());
        assert!(subscription.info.is_none());
        assert!(subscription.update_interval_hours.is_none());
        assert!(subscription.support_url.is_none());
        assert!(subscription.web_page_url.is_none());
        assert!(subscription.announce.is_none());
        assert!(subscription.notices.is_empty());
    }

    #[test]
    fn explicit_no_hwid_survives_round_trip() {
        let subscription: Subscription = serde_json::from_value(serde_json::json!({
            "id": "1",
            "name": "Example",
            "url": "https://sub.example.com/private",
            "send_hwid": false
        }))
        .unwrap();

        let encoded = serde_json::to_vec(&subscription).unwrap();
        let decoded: Subscription = serde_json::from_slice(&encoded).unwrap();

        assert!(!decoded.send_hwid);
        assert_eq!(decoded, subscription);
    }

    #[test]
    fn subscription_debug_does_not_expose_url_or_nodes() {
        let subscription: Subscription = serde_json::from_value(serde_json::json!({
            "id": "1",
            "name": "Example",
            "url": "https://user:password@sub.example.com/private-path?token=query-secret",
            "nodes": [{
                "id": "node",
                "name": "Node",
                "server": "node.example.com",
                "port": 443,
                "outbound": {
                    "trojan": {
                        "password": "node-secret"
                    }
                }
            }]
        }))
        .unwrap();

        let debug = format!("{subscription:?}");

        assert!(debug.contains("sub.example.com"));
        assert!(debug.contains("node_count: 1"));
        for secret in [
            "password",
            "private-path",
            "query-secret",
            "node-secret",
            "node.example.com",
        ] {
            assert!(!debug.contains(secret));
        }
    }

    #[test]
    fn debug_host_handles_ipv6_and_hides_invalid_input() {
        assert_eq!(
            super::debug_host("https://user:secret@[2001:db8::1]:443/private"),
            "[2001:db8::1]"
        );
        for value in [
            "secret-without-a-scheme",
            "file:///private",
            "https://",
            "https://[invalid]/private",
            "https://bad%20host/private",
            "https://bad\nhost/private",
        ] {
            assert_eq!(super::debug_host(value), "<redacted>");
        }
    }

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
