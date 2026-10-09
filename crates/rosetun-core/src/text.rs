use crate::FetchError;
use rosetun_config::{Node, Outbound, SubscriptionInfo, TlsMode, Transport};
use rosetun_subscription::ParseError;

pub fn terminal_text(input: &str) -> String {
    input
        .chars()
        .map(|character| {
            if character.is_control()
                || matches!(
                    character,
                    '\u{061c}'
                        | '\u{200e}'
                        | '\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{2028}'
                        | '\u{2029}'
                )
            {
                ' '
            } else {
                character
            }
        })
        .collect()
}

pub fn provider_text(text: &str, subscription_url: &str) -> String {
    let mut output = terminal_text(text);
    let secret = terminal_text(subscription_url);
    if !secret.is_empty() {
        output = output.replace(&secret, &crate::redacted_subscription_url(subscription_url));
    }

    if let Ok(url) = url::Url::parse(subscription_url) {
        let mut path_and_query = url.path().to_owned();
        if let Some(query) = url.query() {
            path_and_query.push('?');
            path_and_query.push_str(query);
        }
        if path_and_query.len() > 8 {
            output = output.replace(&terminal_text(&path_and_query), "/…");
        }
    }

    output
}

pub fn fetch_error_message(error: &FetchError, subscription_url: &str) -> String {
    match error {
        FetchError::Parse(ParseError::DeviceLimit {
            max_devices_reached,
            not_supported,
            announce,
        }) => {
            let message = if *max_devices_reached {
                "device limit reached for this subscription; remove an old device in your provider's panel"
            } else if *not_supported {
                "the panel did not accept this device ID"
            } else {
                "subscription access was refused by the device policy"
            };

            let mut output = message.to_owned();
            if let Some(announce) = announce {
                output.push_str("\n  announce: ");
                output.push_str(&provider_text(announce, subscription_url));
            }
            output
        }
        FetchError::Parse(ParseError::NoUsableNodes { skipped, notices }) => {
            let mut output = error.to_string();
            for notice in notices {
                output.push_str("\n  notice: ");
                output.push_str(&provider_text(notice, subscription_url));
            }
            for (reason, count) in crate::group_skipped(skipped) {
                output.push_str(&format!(
                    "\n  skipped {count}: {}",
                    terminal_text(&reason.to_string())
                ));
            }
            output
        }
        _ => terminal_text(&error.to_string()),
    }
}

fn count_text(count: u64, unit: &str) -> String {
    if count == 1 {
        format!("1 {unit}")
    } else {
        format!("{count} {unit}s")
    }
}

pub fn updated_text(timestamp: u64, now: u64) -> String {
    let elapsed = now.saturating_sub(timestamp);
    match elapsed {
        0..60 => "just now".to_owned(),
        60..3600 => format!("{} ago", count_text(elapsed / 60, "minute")),
        3600..86400 => format!("{} ago", count_text(elapsed / 3600, "hour")),
        _ => format!("{} ago", count_text(elapsed / 86400, "day")),
    }
}

pub fn expiry_text(expiry: u64, now: u64) -> String {
    const DAY: u64 = 24 * 60 * 60;
    if expiry >= now {
        format!("expires in {}", count_text((expiry - now) / DAY, "day"))
    } else {
        format!("expired {} ago", count_text((now - expiry) / DAY, "day"))
    }
}

pub fn traffic_text(info: &SubscriptionInfo) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    let used = (info.upload as f64 + info.download as f64) / GIB;
    match info.total {
        Some(total) => format!("{used:.2} / {:.2} GiB", total as f64 / GIB),
        None => format!("{used:.2} GiB / unknown"),
    }
}

pub fn node_protocol(node: &Node) -> &'static str {
    match &node.outbound {
        Outbound::Vless(_) => "vless",
        Outbound::Vmess(_) => "vmess",
        Outbound::Trojan(_) => "trojan",
        Outbound::Shadowsocks(_) => "shadowsocks",
        Outbound::Hysteria2(_) => "hysteria2",
        Outbound::Unknown { .. } => "unknown",
    }
}

pub fn node_transport(node: &Node) -> &'static str {
    if matches!(node.outbound, Outbound::Hysteria2(_)) {
        return "quic";
    }
    match &node.stream.transport {
        Transport::Tcp => "tcp",
        Transport::Ws { .. } => "ws",
        Transport::Grpc { .. } => "grpc",
        Transport::HttpUpgrade { .. } => "httpupgrade",
    }
}

pub fn node_tls(node: &Node) -> &'static str {
    if matches!(node.outbound, Outbound::Hysteria2(_)) {
        return "tls";
    }
    match &node.stream.tls {
        TlsMode::Plain => "plain",
        TlsMode::Tls(_) => "tls",
        TlsMode::Reality(_) => "reality",
    }
}

pub fn node_address(node: &Node) -> String {
    if node.server.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{}]:{}", node.server, node.port)
    } else {
        format!("{}:{}", node.server, node.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rosetun_subscription::{SkipReason, Skipped};

    #[test]
    fn hysteria2_details_show_quic_and_tls() {
        let node = Node {
            id: rosetun_config::NodeId::new("test"),
            name: "Test".into(),
            server: "example.com".into(),
            port: 443,
            outbound: Outbound::Hysteria2(rosetun_config::Hysteria2Params {
                password: "test-secret".into(),
                obfs_password: None,
                port_ranges: Vec::new(),
                up_mbps: None,
                down_mbps: None,
            }),
            stream: rosetun_config::StreamSettings {
                tls: TlsMode::Tls(Default::default()),
                ..Default::default()
            },
            raw: None,
        };
        assert_eq!(node_protocol(&node), "hysteria2");
        assert_eq!(node_transport(&node), "quic");
        assert_eq!(node_tls(&node), "tls");
        assert_eq!(node_address(&node), "example.com:443");
    }

    #[test]
    fn generic_device_policy_refusal_has_a_message() {
        let error = FetchError::Parse(ParseError::DeviceLimit {
            max_devices_reached: false,
            not_supported: false,
            announce: None,
        });
        assert_eq!(
            fetch_error_message(
                &error,
                "https://sub.example.com/private-token?key=query-secret"
            ),
            "subscription access was refused by the device policy"
        );
    }

    #[test]
    fn update_age_handles_interval_boundaries_and_future_timestamps() {
        for (elapsed, expected) in [
            (0, "just now"),
            (59, "just now"),
            (60, "1 minute ago"),
            (120, "2 minutes ago"),
            (3599, "59 minutes ago"),
            (3600, "1 hour ago"),
            (7200, "2 hours ago"),
            (86399, "23 hours ago"),
            (86400, "1 day ago"),
            (172800, "2 days ago"),
        ] {
            assert_eq!(updated_text(0, elapsed), expected);
        }
        assert_eq!(updated_text(101, 100), "just now");
        assert_eq!(updated_text(u64::MAX, 0), "just now");
    }

    #[test]
    fn expiry_uses_signed_direction_without_unsigned_underflow() {
        assert_eq!(expiry_text(86_400, 0), "expires in 1 day");
        assert_eq!(expiry_text(0, 86_400), "expired 1 day ago");
        assert_eq!(expiry_text(172_800, 0), "expires in 2 days");
        assert_eq!(expiry_text(0, 172_800), "expired 2 days ago");
        assert_eq!(expiry_text(100, 100), "expires in 0 days");
        assert_eq!(expiry_text(99, 100), "expired 0 days ago");
    }

    #[test]
    fn device_limit_message_uses_flags_and_redacts_announcement() {
        let error = FetchError::Parse(ParseError::DeviceLimit {
            max_devices_reached: true,
            not_supported: true,
            announce: Some("Visit https://sub.example.com/private-token".to_owned()),
        });
        let message = fetch_error_message(&error, "https://sub.example.com/private-token");
        assert!(message.contains("device limit reached"));
        assert!(message.contains("announce:"));
        assert!(!message.contains("private-token"));

        let error = FetchError::Parse(ParseError::DeviceLimit {
            max_devices_reached: false,
            not_supported: true,
            announce: None,
        });
        assert_eq!(
            fetch_error_message(&error, "https://sub.example.com/private-token"),
            "the panel did not accept this device ID"
        );
    }

    #[test]
    fn no_usable_nodes_includes_notices_and_grouped_skips() {
        let error = FetchError::Parse(ParseError::NoUsableNodes {
            skipped: vec![
                Skipped {
                    index: 1,
                    scheme: None,
                    reason: SkipReason::ServiceRecord,
                },
                Skipped {
                    index: 2,
                    scheme: None,
                    reason: SkipReason::ServiceRecord,
                },
            ],
            notices: vec!["Subscription expired".to_owned()],
        });
        let message = fetch_error_message(
            &error,
            "https://sub.example.com/private-token?key=query-secret",
        );
        assert!(message.contains("notice: Subscription expired"));
        assert!(message.contains("skipped 2: record contains a provider notice"));
    }

    #[test]
    fn traffic_preserves_binary_units_and_two_decimal_places() {
        let mut info = SubscriptionInfo {
            upload: 1 << 30,
            download: 1 << 29,
            total: Some(10 << 30),
            expire_unix: None,
        };
        assert_eq!(traffic_text(&info), "1.50 / 10.00 GiB");
        info.total = None;
        assert_eq!(traffic_text(&info), "1.50 GiB / unknown");
        info.upload = u64::MAX;
        info.download = u64::MAX;
        assert_eq!(traffic_text(&info), "34359738368.00 GiB / unknown");
    }

    #[test]
    fn node_labels_and_ipv6_address_preserve_cli_format() {
        let mut node: Node = serde_json::from_value(serde_json::json!({
            "id": "node", "name": "Test", "server": "example.com", "port": 443,
            "outbound": { "trojan": { "password": "secret" } }
        }))
        .unwrap();
        assert_eq!(node_protocol(&node), "trojan");
        assert_eq!(node_transport(&node), "tcp");
        assert_eq!(node_tls(&node), "plain");
        assert_eq!(node_address(&node), "example.com:443");
        node.server = "2001:db8::1".to_owned();
        assert_eq!(node_address(&node), "[2001:db8::1]:443");
        node.server = "192.0.2.1".to_owned();
        assert_eq!(node_address(&node), "192.0.2.1:443");
    }
}
