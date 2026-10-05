use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use rosetun_config::{AppConfig, Outbound, Subscription, SubscriptionId, TlsMode, Transport};
use rosetun_subscription::ParseError;

use crate::fetch::{self, FetchError, Timeouts};
use crate::subcommands::SubCommand;
use crate::{store, subscription_url, update};

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

fn next_id(config: &AppConfig) -> Result<SubscriptionId, String> {
    let mut candidate = 1u64;
    loop {
        let id = SubscriptionId::new(candidate.to_string());
        if !config.subscriptions.iter().any(|sub| sub.id == id) {
            return Ok(id);
        }
        candidate = candidate
            .checked_add(1)
            .ok_or_else(|| "no subscription IDs are available".to_owned())?;
    }
}

fn add(
    input: &str,
    name: Option<String>,
    user_agent: Option<String>,
    send_hwid: bool,
) -> Result<(), String> {
    let url = subscription_url::normalize(input)?;
    let path = store::config_path().map_err(|error| error.to_string())?;
    let mut config = store::load(&path).map_err(|error| error.to_string())?;

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

    let id = next_id(&config)?;
    let mut subscription = Subscription {
        id: id.clone(),
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

    let parsed = fetch::fetch(&subscription, Timeouts::default())
        .map_err(|error| fetch_error_message(&error))?;

    // The parser already applies profile-title and Content-Disposition priority.
    subscription.name = name.or_else(|| parsed.meta.title.clone()).unwrap_or(host);

    let now = now_unix()?;
    config.subscriptions.push(subscription);
    let report = update::apply_update(&mut config, &id, parsed, now);

    store::save(&path, &config).map_err(|error| error.to_string())?;

    let subscription = config
        .subscriptions
        .last()
        .expect("the newly added subscription is present");
    println!("subscription added:");
    print_subscription(subscription, now);
    print_details(&report.skipped, &report.notices);

    Ok(())
}

fn update_subscriptions(id: Option<&str>) -> Result<(), String> {
    let path = store::config_path().map_err(|error| error.to_string())?;
    let mut config = store::load(&path).map_err(|error| error.to_string())?;

    let ids: Vec<_> = match id {
        Some(id) => {
            let id = SubscriptionId::new(id);
            if !config.subscriptions.iter().any(|sub| sub.id == id) {
                return Err("subscription does not exist".to_owned());
            }
            vec![id]
        }
        None => config
            .subscriptions
            .iter()
            .map(|sub| sub.id.clone())
            .collect(),
    };

    let mut failed = false;
    for id in ids {
        let subscription = config
            .subscriptions
            .iter()
            .find(|sub| sub.id == id)
            .expect("the update target is present");

        let label = format!(
            "{} ({})",
            terminal_text(id.as_str()),
            terminal_text(&subscription.name)
        );

        let parsed = match fetch::fetch(subscription, Timeouts::default()) {
            Ok(parsed) => parsed,
            Err(error) => {
                eprintln!("{label}: {}", fetch_error_message(&error));
                failed = true;
                continue;
            }
        };

        let now = now_unix()?;

        // Stage the replacement so a failed save also leaves the in-memory
        // configuration unchanged for subsequent subscriptions.
        let mut candidate = config.clone();
        let report = update::apply_update(&mut candidate, &id, parsed, now);
        if let Err(error) = store::save(&path, &candidate) {
            eprintln!("{label}: {error}");
            failed = true;
            continue;
        }
        config = candidate;

        println!(
            "{label}: updated; {} added, {} removed, {} retained",
            report.added, report.removed, report.retained
        );
        if report.selection_cleared {
            println!("active node selection cleared: the selected node was removed");
        }
        print_details(&report.skipped, &report.notices);

        let subscription = config
            .subscriptions
            .iter()
            .find(|sub| sub.id == id)
            .expect("the updated subscription is present");
        print_info(subscription, now);
    }

    if failed {
        Err("one or more subscriptions could not be updated".to_owned())
    } else {
        Ok(())
    }
}

fn list() -> Result<(), String> {
    let path = store::config_path().map_err(|error| error.to_string())?;
    let config = store::load(&path).map_err(|error| error.to_string())?;
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
    let path = store::config_path().map_err(|error| error.to_string())?;
    let mut config = store::load(&path).map_err(|error| error.to_string())?;
    let id = SubscriptionId::new(id);
    let index = config
        .subscriptions
        .iter()
        .position(|sub| sub.id == id)
        .ok_or_else(|| "subscription does not exist".to_owned())?;

    let selection_cleared = config
        .active
        .as_ref()
        .is_some_and(|selection| selection.subscription == id);

    config.subscriptions.remove(index);
    if selection_cleared {
        config.active = None;
    }

    store::save(&path, &config).map_err(|error| error.to_string())?;
    println!("subscription {} removed", terminal_text(id.as_str()));
    if selection_cleared {
        println!("active node selection cleared");
    }
    Ok(())
}

pub(crate) fn nodes(id: Option<&str>) -> Result<(), String> {
    let path = store::config_path().map_err(|error| error.to_string())?;
    let config = store::load(&path).map_err(|error| error.to_string())?;

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
        subscription_url::redacted(&subscription.url),
        subscription.nodes.len()
    );
    match subscription.updated_at_unix {
        Some(timestamp) => println!("  last updated: {timestamp} (Unix seconds)"),
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
        println!("  announce: {}", terminal_text(announce));
    }
}

fn expiry_text(expiry: u64, now: u64) -> String {
    const DAY: u64 = 24 * 60 * 60;
    if expiry >= now {
        format!("expires in {} days", (expiry - now) / DAY)
    } else {
        format!("expired {} days ago", (now - expiry) / DAY)
    }
}

fn print_details(skipped: &BTreeMap<String, usize>, notices: &[String]) {
    for (reason, count) in skipped {
        println!("  skipped {count}: {}", terminal_text(reason));
    }
    for notice in notices {
        println!("  notice: {}", terminal_text(notice));
    }
}

fn fetch_error_message(error: &FetchError) -> String {
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
                output.push_str(&terminal_text(announce));
            }
            output
        }
        FetchError::Parse(ParseError::NoUsableNodes { skipped, notices }) => {
            let mut output = error.to_string();
            for notice in notices {
                output.push_str("\n  notice: ");
                output.push_str(&terminal_text(notice));
            }
            for (reason, count) in update::group_skipped(skipped) {
                output.push_str(&format!("\n  skipped {count}: {}", terminal_text(&reason)));
            }
            output
        }
        _ => terminal_text(&error.to_string()),
    }
}

fn terminal_text(input: &str) -> String {
    let cleaned: String = input
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
        .collect();

    let mut output = String::new();
    let mut remainder = cleaned.as_str();

    // Even an announcement can echo a subscription URL. Redact every HTTP URL
    // before terminal output, not just the subscription's dedicated URL field.
    while let Some(offset) = find_http_url(remainder) {
        output.push_str(&remainder[..offset]);
        remainder = &remainder[offset..];

        let end = remainder
            .find(char::is_whitespace)
            .unwrap_or(remainder.len());
        output.push_str(&subscription_url::redacted(&remainder[..end]));
        remainder = &remainder[end..];
    }
    output.push_str(remainder);
    output
}

fn find_http_url(input: &str) -> Option<usize> {
    input.char_indices().find_map(|(offset, _)| {
        let suffix = &input[offset..];
        let found = suffix
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
            || suffix
                .get(..8)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"));
        found.then_some(offset)
    })
}

#[cfg(test)]
mod tests {
    use rosetun_subscription::{SkipReason, Skipped};

    use super::*;

    #[test]
    fn terminal_text_removes_controls_and_bidi_markers() {
        assert_eq!(
            terminal_text("Name\n\x1b[31m\u{202e}text\u{2066}"),
            "Name  [31m text "
        );
    }

    #[test]
    fn terminal_text_redacts_urls_inside_server_text() {
        let text = terminal_text(
            "See (https://user:password@sub.example.com/private-token?key=query-secret) now",
        );

        assert!(text.contains("https://sub.example.com/…"));
        assert!(!text.contains("password"));
        assert!(!text.contains("private-token"));
        assert!(!text.contains("query-secret"));
    }

    #[test]
    fn terminal_text_handles_uppercase_schemes_and_unicode() {
        assert_eq!(
            terminal_text("消息 HTTPS://sub.example.com/private"),
            "消息 https://sub.example.com/…"
        );
    }

    #[test]
    fn expiry_uses_signed_direction_without_unsigned_underflow() {
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
        let message = fetch_error_message(&error);

        assert!(message.contains("device limit reached"));
        assert!(message.contains("announce:"));
        assert!(!message.contains("private-token"));

        let error = FetchError::Parse(ParseError::DeviceLimit {
            max_devices_reached: false,
            not_supported: true,
            announce: None,
        });
        assert_eq!(
            fetch_error_message(&error),
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

        let message = fetch_error_message(&error);
        assert!(message.contains("notice: Subscription expired"));
        assert!(message.contains("skipped 2: record contains a provider notice"));
    }

    #[test]
    fn empty_configuration_allocates_id_one() {
        assert_eq!(
            next_id(&AppConfig::default()).unwrap(),
            SubscriptionId::new("1")
        );
    }
}
