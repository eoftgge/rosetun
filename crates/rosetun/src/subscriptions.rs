use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use rosetun_config::{AppConfig, Outbound, Subscription, SubscriptionId, TlsMode, Transport};
use rosetun_subscription::ParseError;

use crate::fetch::{self, FetchError, Timeouts};
use crate::subcommands::SubCommand;
use crate::{subscription_url, update};

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
    let url = subscription_url::normalize(input)?;
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

    let parsed = fetch::fetch(&subscription, Timeouts::default())
        .map_err(|error| fetch_error_message(&error, &subscription.url))?;

    let skipped = update::group_skipped(&parsed.skipped);

    // The parser already applies profile-title and Content-Disposition priority.
    subscription.name = name.or(parsed.meta.title).unwrap_or(host);

    let now = now_unix()?;
    subscription.nodes = parsed.nodes;
    subscription.info = parsed.meta.info;
    subscription.update_interval_hours = parsed.meta.update_interval_hours;
    subscription.support_url = parsed.meta.support_url;
    subscription.web_page_url = parsed.meta.web_page_url;
    subscription.announce = parsed.meta.announce;
    subscription.notices = parsed.meta.notices;
    subscription.updated_at_unix = Some(now);

    let subscription = rosetun_core::add_subscription(&current_store, subscription)
        .map_err(|error| error.to_string())?;

    println!("subscription added:");
    print_subscription(&subscription, now);
    print_details(&skipped, &subscription.notices, &subscription.url);

    Ok(())
}

fn commit_update(
    path: &std::path::Path,
    config: &mut AppConfig,
    id: &SubscriptionId,
    fetched: Result<rosetun_subscription::Parsed, FetchError>,
    now: u64,
) -> Result<update::UpdateReport, String> {
    let requested = config
        .subscriptions
        .iter()
        .find(|subscription| &subscription.id == id)
        .ok_or_else(|| "subscription does not exist".to_owned())?;

    let parsed = fetched.map_err(|error| fetch_error_message(&error, &requested.url))?;
    let current_store = rosetun_core::Store::at(path);
    let report = rosetun_core::commit_subscription_update(&current_store, requested, parsed, now)
        .map_err(|error| error.to_string())?;

    *config = current_store.load().map_err(|error| {
        format!("subscription update was saved, but configuration could not be reloaded: {error}")
    })?;

    Ok(report)
}

fn update_subscriptions(id: Option<&str>) -> Result<(), String> {
    let path = rosetun_core::Store::open_default()
        .map_err(|error| error.to_string())?
        .path()
        .to_owned();
    let mut config = rosetun_core::Store::at(&path)
        .load()
        .map_err(|error| error.to_string())?;

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

        let fetched = fetch::fetch(subscription, Timeouts::default());
        let now = now_unix()?;
        let report = match commit_update(&path, &mut config, &id, fetched, now) {
            Ok(report) => report,
            Err(message) => {
                eprintln!("{label}: {message}");
                failed = true;
                continue;
            }
        };

        println!(
            "{label}: updated; {} added, {} removed, {} retained",
            report.added, report.removed, report.retained
        );
        if report.selection_cleared {
            println!("active node selection cleared: the selected node was removed");
        }
        let subscription = config
            .subscriptions
            .iter()
            .find(|sub| sub.id == id)
            .expect("the updated subscription is present");
        print_details(&report.skipped, &report.notices, &subscription.url);
        print_info(subscription, now);
    }

    if failed {
        Err("one or more subscriptions could not be updated".to_owned())
    } else {
        Ok(())
    }
}

fn list() -> Result<(), String> {
    let path = rosetun_core::Store::open_default()
        .map_err(|error| error.to_string())?
        .path()
        .to_owned();
    let config = rosetun_core::Store::at(&path)
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
        subscription_url::redacted(&subscription.url),
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

fn updated_text(timestamp: u64, now: u64) -> String {
    let elapsed = now.saturating_sub(timestamp);
    match elapsed {
        0..60 => "just now".to_owned(),
        60..3600 => format!("{} minutes ago", elapsed / 60),
        3600..86400 => format!("{} hours ago", elapsed / 3600),
        _ => format!("{} days ago", elapsed / 86400),
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

fn print_details(skipped: &BTreeMap<String, usize>, notices: &[String], subscription_url: &str) {
    for (reason, count) in skipped {
        println!("  skipped {count}: {}", terminal_text(reason));
    }
    for notice in notices {
        println!("  notice: {}", provider_text(notice, subscription_url));
    }
}

fn fetch_error_message(error: &FetchError, subscription_url: &str) -> String {
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
            for (reason, count) in update::group_skipped(skipped) {
                output.push_str(&format!("\n  skipped {count}: {}", terminal_text(&reason)));
            }
            output
        }
        _ => terminal_text(&error.to_string()),
    }
}

pub(crate) fn terminal_text(input: &str) -> String {
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

fn provider_text(text: &str, subscription_url: &str) -> String {
    let mut output = terminal_text(text);
    let secret = terminal_text(subscription_url);
    if !secret.is_empty() {
        output = output.replace(&secret, &subscription_url::redacted(subscription_url));
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

#[cfg(test)]
mod tests {
    use rosetun_subscription::{SkipReason, Skipped};

    use super::*;

    static NEXT_DIRECTORY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            loop {
                let sequence = NEXT_DIRECTORY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "rosetun-subscriptions-{}-{sequence}",
                    std::process::id()
                ));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("could not create test directory: {error}"),
                }
            }
        }

        fn config_path(&self) -> std::path::PathBuf {
            self.0.join("config.json")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn save_config(
        path: &std::path::Path,
        config: &AppConfig,
    ) -> Result<(), rosetun_core::StoreError> {
        rosetun_core::Store::at(path).modify(|current| {
            *current = config.clone();
            Ok::<_, rosetun_core::StoreError>(())
        })
    }

    fn test_subscription(id: &str) -> Subscription {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "name": "Chosen name",
            "url": format!("https://sub.example.com/private-token?id={id}"),
            "nodes": [{
                "id": "old",
                "name": "Old node",
                "server": "old.example.com",
                "port": 443,
                "outbound": {
                    "trojan": {
                        "password": "old-secret"
                    }
                }
            }],
            "updated_at_unix": 1
        }))
        .unwrap()
    }

    fn test_config() -> AppConfig {
        AppConfig {
            subscriptions: vec![test_subscription("1")],
            active: Some(rosetun_config::Selection {
                subscription: SubscriptionId::new("1"),
                node: rosetun_config::NodeId::new("old"),
            }),
            ..AppConfig::default()
        }
    }

    fn successful_update() -> rosetun_subscription::Parsed {
        rosetun_subscription::parse(b"trojan://new-secret@new.example.com:443#New", &|name| {
            match name {
                "profile-title" => Some("Changed provider title".to_owned()),
                "profile-update-interval" => Some("12".to_owned()),
                "subscription-userinfo" => {
                    Some("upload=10; download=20; total=100; expire=200".to_owned())
                }
                _ => None,
            }
        })
        .unwrap()
    }

    #[test]
    fn commit_reloads_preferences_changed_during_fetch() {
        let directory = TestDirectory::new();
        let path = directory.config_path();
        let mut config = test_config();
        save_config(&path, &config).unwrap();

        let mut external = config.clone();
        external.subscriptions[0].name = "Renamed during fetch".to_owned();
        external.subscriptions[0].auto_update = true;
        external.active = None;
        save_config(&path, &external).unwrap();

        commit_update(
            &path,
            &mut config,
            &SubscriptionId::new("1"),
            Ok(successful_update()),
            42,
        )
        .unwrap();

        let saved = rosetun_core::Store::at(&path).load().unwrap();
        assert_eq!(config, saved);
        assert_eq!(saved.subscriptions[0].name, "Renamed during fetch");
        assert!(saved.subscriptions[0].auto_update);
        assert!(saved.active.is_none());
        assert_eq!(saved.rule_sets, external.rule_sets);
        assert_eq!(saved.active_rule_set, external.active_rule_set);
    }

    #[test]
    fn successful_update_is_persisted_and_dangling_selection_is_cleared() {
        let directory = TestDirectory::new();
        let path = directory.config_path();
        let mut config = test_config();
        save_config(&path, &config).unwrap();

        let report = commit_update(
            &path,
            &mut config,
            &SubscriptionId::new("1"),
            Ok(successful_update()),
            42,
        )
        .unwrap();

        assert!(report.selection_cleared);
        assert_eq!(report.added, 1);
        assert_eq!(report.removed, 1);
        assert_eq!(report.retained, 0);
        assert!(config.active.is_none());

        let saved = rosetun_core::Store::at(&path).load().unwrap();
        assert_eq!(saved, config);
        assert_eq!(saved.subscriptions[0].name, "Chosen name");
        assert_eq!(saved.subscriptions[0].updated_at_unix, Some(42));
        assert_eq!(saved.subscriptions[0].update_interval_hours, Some(12));
        assert_eq!(saved.subscriptions[0].info.as_ref().unwrap().download, 20);
        assert_eq!(saved.subscriptions[0].nodes[0].server, "new.example.com");
    }

    #[test]
    fn fetch_and_parse_errors_preserve_disk_and_memory() {
        let directory = TestDirectory::new();
        let path = directory.config_path();
        let original = test_config();
        save_config(&path, &original).unwrap();
        let original_bytes = std::fs::read(&path).unwrap();

        let errors = [
            FetchError::RequestFailed,
            FetchError::ResponseTooLarge,
            FetchError::AccessDenied,
            FetchError::Parse(ParseError::DeviceLimit {
                max_devices_reached: true,
                not_supported: false,
                announce: Some("Device limit reached".to_owned()),
            }),
            FetchError::Parse(ParseError::NoUsableNodes {
                skipped: Vec::new(),
                notices: vec!["Subscription expired".to_owned()],
            }),
        ];

        for error in errors {
            let mut config = original.clone();
            assert!(
                commit_update(
                    &path,
                    &mut config,
                    &SubscriptionId::new("1"),
                    Err(error),
                    42,
                )
                .is_err()
            );
            assert_eq!(config, original);
            assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
            assert!(!directory.0.join("config.json.tmp").exists());
        }
    }

    #[test]
    fn failed_save_preserves_memory_and_previous_file() {
        let directory = TestDirectory::new();
        let path = directory.config_path();
        let mut config = test_config();
        save_config(&path, &config).unwrap();

        let original = config.clone();
        let original_bytes = std::fs::read(&path).unwrap();
        std::fs::create_dir(directory.0.join("config.json.tmp")).unwrap();

        assert!(
            commit_update(
                &path,
                &mut config,
                &SubscriptionId::new("1"),
                Ok(successful_update()),
                42,
            )
            .is_err()
        );
        assert_eq!(config, original);
        assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
    }

    #[test]
    fn failed_subscription_does_not_prevent_a_later_successful_commit() {
        let directory = TestDirectory::new();
        let path = directory.config_path();
        let mut config = test_config();
        config.subscriptions.push(test_subscription("2"));
        save_config(&path, &config).unwrap();
        let first = config.subscriptions[0].clone();

        assert!(
            commit_update(
                &path,
                &mut config,
                &SubscriptionId::new("1"),
                Err(FetchError::AccessDenied),
                42,
            )
            .is_err()
        );
        commit_update(
            &path,
            &mut config,
            &SubscriptionId::new("2"),
            Ok(successful_update()),
            43,
        )
        .unwrap();

        assert_eq!(config.subscriptions[0], first);
        assert_eq!(config.subscriptions[1].updated_at_unix, Some(43));
        assert_eq!(rosetun_core::Store::at(&path).load().unwrap(), config);
        assert!(config.active.is_some());
    }

    #[test]
    fn unknown_update_target_does_not_create_configuration() {
        let directory = TestDirectory::new();
        let path = directory.config_path();
        let mut config = AppConfig::default();

        assert!(
            commit_update(
                &path,
                &mut config,
                &SubscriptionId::new("missing"),
                Ok(successful_update()),
                42,
            )
            .is_err()
        );
        assert_eq!(config, AppConfig::default());
        assert!(!path.exists());
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
    fn terminal_text_removes_controls_and_bidi_markers() {
        assert_eq!(
            terminal_text("Name\n\x1b[31m\u{202e}text\u{2066}"),
            "Name  [31m text "
        );
    }

    #[test]
    fn provider_text_preserves_renewal_links() {
        assert_eq!(
            provider_text(
                "Renew at https://t.me/example_bot",
                "https://sub.example.com/private-token?key=query-secret",
            ),
            "Renew at https://t.me/example_bot"
        );
    }

    #[test]
    fn provider_text_redacts_subscription_url_and_token_path() {
        let subscription_url = "https://sub.example.com/private-token?key=query-secret";

        assert_eq!(
            provider_text(
                &format!("Subscription: {subscription_url}"),
                subscription_url,
            ),
            "Subscription: https://sub.example.com/…"
        );
        assert_eq!(
            provider_text(
                "Subscription path: /private-token?key=query-secret",
                subscription_url,
            ),
            "Subscription path: /…"
        );
    }

    #[test]
    fn provider_text_does_not_redact_short_paths() {
        assert_eq!(
            provider_text("Open /renew", "https://sub.example.com/renew"),
            "Open /renew"
        );
    }

    #[test]
    fn terminal_text_preserves_links_and_unicode() {
        assert_eq!(
            terminal_text("消息 HTTPS://sub.example.com/private"),
            "消息 HTTPS://sub.example.com/private"
        );
    }

    #[test]
    fn provider_text_removes_controls_and_bidi() {
        assert_eq!(
            provider_text(
                "Renew\nat\u{202e} https://t.me/example_bot\x1b",
                "https://sub.example.com/private-token",
            ),
            "Renew at  https://t.me/example_bot "
        );
    }

    #[test]
    fn update_age_handles_interval_boundaries_and_future_timestamps() {
        for (elapsed, expected) in [
            (0, "just now"),
            (59, "just now"),
            (60, "1 minutes ago"),
            (3599, "59 minutes ago"),
            (3600, "1 hours ago"),
            (86399, "23 hours ago"),
            (86400, "1 days ago"),
            (172800, "2 days ago"),
        ] {
            assert_eq!(updated_text(0, elapsed), expected);
        }
        assert_eq!(updated_text(101, 100), "just now");
        assert_eq!(updated_text(u64::MAX, 0), "just now");
    }

    #[test]
    fn terminal_text_handles_uppercase_schemes_and_unicode() {
        assert_eq!(
            terminal_text("消息 HTTPS://sub.example.com/private"),
            "消息 HTTPS://sub.example.com/private"
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
