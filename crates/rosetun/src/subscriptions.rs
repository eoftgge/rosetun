use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use rosetun_config::{Outbound, Subscription, SubscriptionId, TlsMode, Transport};
use rosetun_core::{Timeouts, fetch_error_message, provider_text, terminal_text};

use crate::subcommands::SubCommand;

pub(crate) fn run(command: SubCommand) -> Result<(), String> {
    match command {
        SubCommand::Add {
            url,
            name,
            user_agent,
            send_hwid,
        } => add(&url, name, user_agent, send_hwid),
        SubCommand::Update { id } => update_subscriptions(id.as_deref()),
        SubCommand::List => list(),
        SubCommand::Remove { id } => remove(&id),
    }
}

fn now_unix() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before the Unix epoch".to_owned())
}

fn add(
    input: &str,
    name: Option<String>,
    user_agent: Option<String>,
    send_hwid: bool,
) -> Result<(), String> {
    let url = rosetun_core::normalize_subscription_url(input)?;
    let current_store = rosetun_core::Store::open_default().map_err(|error| error.to_string())?;
    let config = current_store.load().map_err(|error| error.to_string())?;

    if let Some(existing) = config.subscriptions.iter().find(|sub| sub.url == url) {
        return Err(format!(
            "already added as {}",
            terminal_text(existing.id.as_str())
        ));
    }

    let parsed_url = url::Url::parse(&url).map_err(|_| "invalid subscription URL".to_owned())?;
    let host = parsed_url
        .host_str()
        .ok_or_else(|| "subscription URL requires a host".to_owned())?
        .to_owned();

    if parsed_url.scheme() == "http" {
        eprintln!(
            "warning: this subscription uses HTTP; its token is transmitted without encryption"
        );
    }

    let mut subscription = Subscription {
        id: SubscriptionId::new("pending"),
        name: host.clone(),
        url,
        nodes: Vec::new(),
        auto_update: false,
        updated_at_unix: None,
        user_agent,
        send_hwid,
        info: None,
        update_interval_hours: None,
        support_url: None,
        web_page_url: None,
        announce: None,
        notices: Vec::new(),
    };

    let parsed = rosetun_core::fetch(&subscription, Timeouts::default())
        .map_err(|error| fetch_error_message(&error, &subscription.url))?;

    // The parser already applies profile-title and Content-Disposition priority.
    subscription.name = name.or_else(|| parsed.meta.title.clone()).unwrap_or(host);

    let now = now_unix()?;
    let (subscription, report) =
        rosetun_core::add_subscription(&current_store, subscription, parsed, now)
            .map_err(|error| error.to_string())?;

    println!("subscription added:");
    print_subscription(&subscription, now);
    print_details(&report.skipped, &report.notices, &subscription.url);

    Ok(())
}

fn update_subscriptions(id: Option<&str>) -> Result<(), String> {
    let store = rosetun_core::Store::open_default().map_err(|error| error.to_string())?;
    let initial = store.load().map_err(|error| error.to_string())?;
    let timeouts = Timeouts::default();

    let results = match id {
        Some(id) => {
            let id = SubscriptionId::new(id);
            if !initial
                .subscriptions
                .iter()
                .any(|subscription| subscription.id == id)
            {
                return Err("subscription does not exist".to_owned());
            }

            let result = rosetun_core::update_subscription(&store, &id, timeouts);
            vec![(id, result)]
        }
        None => rosetun_core::update_all(&store, timeouts).map_err(|error| error.to_string())?,
    };

    let now = now_unix()?;
    let mut failed = false;
    for (id, result) in results {
        let (subscription, report) = match result {
            Ok(updated) => updated,
            Err(error) => {
                let original = initial
                    .subscriptions
                    .iter()
                    .find(|subscription| subscription.id == id);
                let label = match original {
                    Some(subscription) => format!(
                        "{} ({})",
                        terminal_text(id.as_str()),
                        terminal_text(&subscription.name)
                    ),
                    None => terminal_text(id.as_str()),
                };
                eprintln!("{label}: {error}");
                failed = true;
                continue;
            }
        };

        let label = format!(
            "{} ({})",
            terminal_text(id.as_str()),
            terminal_text(&subscription.name)
        );
        println!(
            "{label}: updated; {} added, {} removed, {} retained",
            report.added, report.removed, report.retained
        );
        if report.selection_cleared {
            println!("active node selection cleared: the selected node was removed");
        }
        print_details(&report.skipped, &report.notices, &subscription.url);
        print_info(&subscription, now);
    }

    if failed {
        Err("one or more subscriptions could not be updated".to_owned())
    } else {
        Ok(())
    }
}

fn list() -> Result<(), String> {
    let config = rosetun_core::Store::open_default()
        .map_err(|error| error.to_string())?
        .load()
        .map_err(|error| error.to_string())?;
    let now = now_unix()?;

    if config.subscriptions.is_empty() {
        println!("no subscriptions");
    }
    for subscription in &config.subscriptions {
        print_subscription(subscription, now);
    }
    Ok(())
}

fn remove(id: &str) -> Result<(), String> {
    let current_store = rosetun_core::Store::open_default().map_err(|error| error.to_string())?;

    rosetun_core::remove_subscription(&current_store, &SubscriptionId::new(id))
        .map_err(|error| error.to_string())?;

    println!("removed subscription: {}", terminal_text(id));

    Ok(())
}

pub(crate) fn nodes(id: Option<&str>) -> Result<(), String> {
    let path = rosetun_core::Store::open_default()
        .map_err(|error| error.to_string())?
        .path()
        .to_owned();
    let config = rosetun_core::Store::at(&path)
        .load()
        .map_err(|error| error.to_string())?;

    if let Some(id) = id
        && !config.subscriptions.iter().any(|sub| sub.id.as_str() == id)
    {
        return Err("subscription does not exist".to_owned());
    }

    println!("  SUBSCRIPTION\tNODE\tNAME\tPROTOCOL\tTRANSPORT\tTLS\tSERVER");
    for subscription in &config.subscriptions {
        if id.is_some_and(|id| subscription.id.as_str() != id) {
            continue;
        }
        for node in &subscription.nodes {
            let active = config.active.as_ref().is_some_and(|selection| {
                selection.subscription == subscription.id && selection.node == node.id
            });

            let protocol = match &node.outbound {
                Outbound::Vless(_) => "vless",
                Outbound::Vmess(_) => "vmess",
                Outbound::Trojan(_) => "trojan",
                Outbound::Shadowsocks(_) => "shadowsocks",
                Outbound::Unknown { .. } => "unknown",
            };
            let transport = match &node.stream.transport {
                Transport::Tcp => "tcp",
                Transport::Ws { .. } => "ws",
                Transport::Grpc { .. } => "grpc",
                Transport::HttpUpgrade { .. } => "httpupgrade",
            };
            let tls = match &node.stream.tls {
                TlsMode::Plain => "plain",
                TlsMode::Tls(_) => "tls",
                TlsMode::Reality(_) => "reality",
            };
            let server = if node.server.parse::<std::net::Ipv6Addr>().is_ok() {
                format!("[{}]:{}", node.server, node.port)
            } else {
                format!("{}:{}", node.server, node.port)
            };

            println!(
                "{} {}\t{}\t{}\t{protocol}\t{transport}\t{tls}\t{}",
                if active { "*" } else { " " },
                terminal_text(subscription.id.as_str()),
                terminal_text(node.id.as_str()),
                terminal_text(&node.name),
                terminal_text(&server),
            );
        }
    }
    Ok(())
}

fn print_subscription(subscription: &Subscription, now: u64) {
    println!(
        "{}: {} | {} | {} nodes",
        terminal_text(subscription.id.as_str()),
        terminal_text(&subscription.name),
        rosetun_core::redacted_subscription_url(&subscription.url),
        subscription.nodes.len()
    );
    match subscription.updated_at_unix {
        Some(timestamp) => println!("  last updated: {}", updated_text(timestamp, now)),
        None => println!("  last updated: never"),
    }
    print_info(subscription, now);
}

fn print_info(subscription: &Subscription, now: u64) {
    if let Some(info) = &subscription.info {
        const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
        let used = (info.upload as f64 + info.download as f64) / GIB;
        match info.total {
            Some(total) => println!("  traffic: {used:.2} / {:.2} GiB", total as f64 / GIB),
            None => println!("  traffic: {used:.2} GiB / unknown"),
        }
        if let Some(expiry) = info.expire_unix {
            println!("  {}", expiry_text(expiry, now));
        }
    }
    if let Some(announce) = &subscription.announce {
        println!("  announce: {}", provider_text(announce, &subscription.url));
    }
    if let Some(url) = &subscription.support_url {
        println!("  support: {}", terminal_text(url));
    }
    if let Some(url) = &subscription.web_page_url {
        println!("  web page: {}", terminal_text(url));
    }
}

fn count_text(count: u64, unit: &str) -> String {
    if count == 1 {
        format!("1 {unit}")
    } else {
        format!("{count} {unit}s")
    }
}

fn updated_text(timestamp: u64, now: u64) -> String {
    let elapsed = now.saturating_sub(timestamp);
    match elapsed {
        0..60 => "just now".to_owned(),
        60..3600 => format!("{} ago", count_text(elapsed / 60, "minute")),
        3600..86400 => format!("{} ago", count_text(elapsed / 3600, "hour")),
        _ => format!("{} ago", count_text(elapsed / 86400, "day")),
    }
}

fn expiry_text(expiry: u64, now: u64) -> String {
    const DAY: u64 = 24 * 60 * 60;
    if expiry >= now {
        format!("expires in {}", count_text((expiry - now) / DAY, "day"))
    } else {
        format!("expired {} ago", count_text((now - expiry) / DAY, "day"))
    }
}

fn print_details(skipped: &BTreeMap<String, usize>, notices: &[String], subscription_url: &str) {
    for (reason, count) in skipped {
        println!("  skipped {count}: {}", terminal_text(reason));
    }
    for notice in notices {
        println!("  notice: {}", provider_text(notice, subscription_url));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rosetun_core::FetchError;
    use rosetun_subscription::{ParseError, SkipReason, Skipped};

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
}
