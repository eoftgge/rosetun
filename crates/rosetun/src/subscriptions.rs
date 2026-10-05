use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use rosetun_config::{Subscription, SubscriptionId};
use rosetun_core::{
    Timeouts, expiry_text, node_address, node_protocol, node_tls, node_transport, provider_text,
    terminal_text, traffic_text, updated_text,
};

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
    let current_store = rosetun_core::Store::open_default().map_err(|error| error.to_string())?;
    let prepared = rosetun_core::prepare_subscription(
        &current_store,
        input,
        rosetun_core::AddOptions {
            name,
            user_agent,
            send_hwid,
        },
    )
    .map_err(|error| error.to_string())?;

    if prepared.uses_plain_http() {
        eprintln!(
            "warning: this subscription uses HTTP; its token is transmitted without encryption"
        );
    }
    let (subscription, report) =
        rosetun_core::add_prepared_subscription(&current_store, prepared, Timeouts::default())
            .map_err(|error| error.to_string())?;

    println!("subscription added:");
    print_subscription(&subscription, subscription.updated_at_unix.unwrap_or(0));
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
    let config = rosetun_core::Store::open_default()
        .map_err(|error| error.to_string())?
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

            let protocol = node_protocol(node);
            let transport = node_transport(node);
            let tls = node_tls(node);
            let server = node_address(node);

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
        println!("  traffic: {}", traffic_text(info));
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

fn print_details(skipped: &BTreeMap<String, usize>, notices: &[String], subscription_url: &str) {
    for (reason, count) in skipped {
        println!("  skipped {count}: {}", terminal_text(reason));
    }
    for notice in notices {
        println!("  notice: {}", provider_text(notice, subscription_url));
    }
}
