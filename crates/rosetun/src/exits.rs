//! `rosetun exits`: what each exit goes through now. Never prints node addresses.

use rosetun_config::{AppConfig, ConnectionState, Exit, ExitId, ExitTarget, Selection};
use rosetun_core::terminal_text;
use rosetun_ipc::{ExitDelay, ExitOutcome, HelperClient, ProbeOutcome, SessionExit};

pub(crate) fn run() -> Result<(), String> {
    let config = rosetun_core::Store::open_default()
        .map_err(|error| error.to_string())?
        .load()
        .map_err(|error| error.to_string())?;
    let session = session_exits();
    println!("  ID\tNAME\tTYPE\tNOW\tRULES");
    for line in lines(&config, session.as_deref()) {
        println!("{line}");
    }
    Ok(())
}

/// The running session's exit nodes, or `None` when there is no session to ask.
fn session_exits() -> Option<Vec<SessionExit>> {
    let endpoint = rosetun_ipc::default_endpoint();
    let client_name = concat!("rosetun/", env!("CARGO_PKG_VERSION"));
    let mut client = HelperClient::connect(&endpoint, client_name).ok()?;
    let status = client.status().ok()?;
    if !matches!(
        status.state,
        ConnectionState::Connected | ConnectionState::Reconnecting
    ) {
        return None;
    }
    match client.session_exits() {
        Ok(exits) => Some(exits),
        Err(error) => {
            eprintln!("could not read the session's exits, showing the configured choice: {error}");
            None
        }
    }
}

/// One line per exit: id, name, type, the node now and the rule count. With a
/// session, "now" is the node the service holds; otherwise the resolution a
/// connect would make without delays.
fn lines(config: &AppConfig, session: Option<&[SessionExit]>) -> Vec<String> {
    let resolved = match session {
        Some(_) => Vec::new(),
        None => rosetun_core::resolve_exits(&config.exits, &config.subscriptions, &[], &[]),
    };
    config
        .exits
        .iter()
        .map(|exit| {
            let now = match session {
                Some(session) => session
                    .iter()
                    .find(|entry| entry.exit == exit.id)
                    .map_or_else(
                        || "not in this session".to_owned(),
                        |entry| node_name(config, &entry.selection),
                    ),
                None => resolved
                    .iter()
                    .find(|(id, _)| id == &exit.id)
                    .and_then(|(_, selection)| selection.as_ref())
                    .map_or_else(
                        || "no node (rules block)".to_owned(),
                        |selection| node_name(config, selection),
                    ),
            };
            format!(
                "  {}\t{}\t{}\t{now}\t{}",
                terminal_text(exit.id.as_str()),
                terminal_text(&exit.name),
                kind(exit),
                rosetun_core::exit_rule_count(config, &exit.id),
            )
        })
        .collect()
}

fn kind(exit: &Exit) -> String {
    match &exit.target {
        ExitTarget::Country(code) => format!("country {}", code.as_str()),
        ExitTarget::Node {
            fallback: Some(code),
            ..
        } => format!("node, fallback {}", code.as_str()),
        ExitTarget::Node { fallback: None, .. } => "node".to_owned(),
    }
}

fn node_name(config: &AppConfig, selection: &Selection) -> String {
    config
        .subscriptions
        .iter()
        .find(|subscription| subscription.id == selection.subscription)
        .and_then(|subscription| subscription.node(&selection.node))
        .map_or_else(
            || "node not in subscriptions".to_owned(),
            |node| terminal_text(&node.name),
        )
}

/// `rosetun delay` lines after the main one, one per exit of the session.
pub(crate) fn delay_lines(config: Option<&AppConfig>, exits: &[ExitDelay]) -> Vec<String> {
    exits
        .iter()
        .map(|delay| {
            let name = config
                .and_then(|config| config.exits.iter().find(|exit| exit.id == delay.exit))
                .map_or_else(
                    || terminal_text(delay.exit.as_str()),
                    |exit| terminal_text(&exit.name),
                );
            let outcome = match delay.outcome {
                ExitOutcome::Probed(ProbeOutcome::Works { millis }) => format!("works {millis} ms"),
                ExitOutcome::Probed(_) => "not answering".to_owned(),
                ExitOutcome::NoAddress => "no address (rules block)".to_owned(),
            };
            format!("  {name}\t{outcome}")
        })
        .collect()
}

/// Pins for `apply`: each exit keeps the node the session already uses.
pub(crate) fn pinned(session: Vec<SessionExit>) -> Vec<(ExitId, Selection)> {
    session
        .into_iter()
        .map(|entry| (entry.exit, entry.selection))
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use rosetun_config::{
        CountryCode, Node, NodeId, Outbound, Rule, RuleId, RuleMatcher, RuleSet, RuleSetId,
        RuleTarget, StreamSettings, Subscription, SubscriptionId,
    };

    use super::*;

    pub(crate) fn selection(node: &str) -> Selection {
        Selection {
            subscription: SubscriptionId::new("sub"),
            node: NodeId::new(node),
        }
    }

    /// The main node plus two Dutch nodes; one country exit used by one rule.
    pub(crate) fn config() -> AppConfig {
        let node = |id: &str, name: &str| Node {
            id: NodeId::new(id),
            name: name.into(),
            server: "192.0.2.10".into(),
            port: 443,
            outbound: Outbound::Unknown {
                scheme: "example".into(),
                params: BTreeMap::new(),
            },
            stream: StreamSettings::default(),
            raw: None,
        };
        let mut rules = RuleSet::new(RuleSetId::new("set"), "Set", RuleTarget::Proxy);
        rules.rules.push(Rule {
            id: RuleId::new("through-nl"),
            enabled: true,
            matcher: RuleMatcher::IpCidr("198.51.100.0/24".into()),
            target: RuleTarget::Exit,
            exit: Some(ExitId::new("nl")),
        });
        AppConfig {
            subscriptions: vec![Subscription {
                id: SubscriptionId::new("sub"),
                name: "Example".into(),
                url: "https://sub.example.com/nodes".into(),
                nodes: vec![
                    node("main", "Main"),
                    node("nl-1", "\u{1f1f3}\u{1f1f1} One"),
                    node("nl-2", "\u{1f1f3}\u{1f1f1} Two"),
                ],
                auto_update: false,
                updated_at_unix: None,
                user_agent: None,
                send_hwid: true,
                hwid_scope: rosetun_config::HwidScope::Machine,
                info: None,
                update_interval_hours: None,
                support_url: None,
                web_page_url: None,
                announce: None,
                notices: Vec::new(),
            }],
            exits: vec![Exit {
                id: ExitId::new("nl"),
                name: "Dutch".into(),
                target: ExitTarget::Country(CountryCode::parse("NL").unwrap()),
            }],
            active: Some(selection("main")),
            active_rule_set: Some(RuleSetId::new("set")),
            rule_sets: vec![rules],
            ..AppConfig::default()
        }
    }

    #[test]
    fn lines_show_the_session_node_or_the_resolution_without_addresses() {
        let config = config();
        let offline = lines(&config, None);
        assert_eq!(offline.len(), 1);
        assert!(offline[0].contains("nl\tDutch\tcountry NL\t"));
        assert!(offline[0].ends_with("One\t1"));
        let session = [SessionExit {
            exit: ExitId::new("nl"),
            selection: selection("nl-2"),
        }];
        let connected = lines(&config, Some(&session));
        assert!(connected[0].ends_with("Two\t1"));
        assert!(lines(&config, Some(&[]))[0].contains("not in this session"));
        for line in offline.iter().chain(&connected) {
            assert!(!line.contains("192.0.2.10"));
        }
    }

    #[test]
    fn delay_lines_name_each_outcome() {
        let config = config();
        let delays = [
            ExitDelay {
                exit: ExitId::new("nl"),
                outcome: ExitOutcome::Probed(ProbeOutcome::Works { millis: 84 }),
            },
            ExitDelay {
                exit: ExitId::new("gone"),
                outcome: ExitOutcome::Probed(ProbeOutcome::Fails),
            },
            ExitDelay {
                exit: ExitId::new("nl"),
                outcome: ExitOutcome::NoAddress,
            },
        ];
        assert_eq!(
            delay_lines(Some(&config), &delays),
            [
                "  Dutch\tworks 84 ms",
                "  gone\tnot answering",
                "  Dutch\tno address (rules block)",
            ]
        );
    }
}
