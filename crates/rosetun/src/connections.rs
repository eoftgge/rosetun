//! `rosetun connections`: the running session's connections, for the account
//! that connected it. The list is a browsing history: it is printed, never logged.

use std::process::ExitCode;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rosetun_config::{
    ConnectionNetwork, ConnectionRoute, ConnectionState, LiveConnection, RuleId, Status,
};
use rosetun_core::{Explanation, Reason, RuleSource, SessionLists, terminal_text};
use rosetun_ipc::{ClientError, ConnectRequest, ErrorCode, HelperClient};

/// The service collects the list only after it was asked for it; its next
/// poll of the engine follows within a quarter of a second.
const FIRST_POLL: Duration = Duration::from_millis(1500);

/// Characters of the id shown in the table; `close` accepts them when they
/// name one active connection.
const SHORT_ID_CHARS: usize = 8;

pub(crate) fn run(client: &mut HelperClient) -> ExitCode {
    let status = match require_connected(client, "see") {
        Ok(status) => status,
        Err(code) => return code,
    };
    match read(client) {
        Ok((active, closed)) => {
            let rules = SessionRules::read(client, &status);
            let now = now_unix_ms();
            println!("active: {}, closed: {}", active.len(), closed.len());
            println!(
                "STATE\tID\tNET\tROUTE\tDOWN\tUP\tSECONDS\tDESTINATION\tPROGRAM\tRULE{}",
                if rules.changed { " (changed)" } else { "" }
            );
            for (state, connection) in active
                .iter()
                .map(|connection| ("active", connection))
                .chain(closed.iter().map(|connection| ("closed", connection)))
            {
                println!(
                    "{}\t{}",
                    line(state, connection, now),
                    rules.rule(connection)
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => report(&error, "read"),
    }
}

/// The running session's rules as connecting from this account's
/// configuration would send them: the set and lists from the configuration,
/// the temporary rules and the exits' nodes from the service. The service
/// does not hand out the set it runs, so a configuration saved after the
/// session started may differ from it.
struct SessionRules {
    request: Option<ConnectRequest>,
    lists: SessionLists,
    /// The active set's rule ids, numbered as the rules table numbers them.
    numbers: Vec<RuleId>,
    changed: bool,
}

impl SessionRules {
    fn read(client: &mut HelperClient, status: &Status) -> Self {
        let mut rules = Self {
            request: None,
            lists: SessionLists::default(),
            numbers: Vec::new(),
            changed: true,
        };
        let temporary = match client.temporary_rules() {
            Ok(temporary) => temporary,
            Err(error) => {
                tracing::warn!(%error, "could not read the temporary rules");
                return rules;
            }
        };
        let pinned = match client.session_exits() {
            Ok(session) => crate::exits::pinned(session),
            Err(error) => {
                tracing::warn!(%error, "could not read the session's exits");
                return rules;
            }
        };
        let store = match rosetun_core::Store::open_default() {
            Ok(store) => store,
            Err(error) => {
                tracing::warn!(%error, "could not open the configuration");
                return rules;
            }
        };
        let config = match store.load() {
            Ok(config) => config,
            Err(error) => {
                tracing::warn!(%error, "could not read the configuration");
                return rules;
            }
        };
        let Ok(request) = crate::apply_request(&config, temporary, pinned) else {
            return rules;
        };
        match rosetun_core::read_session_lists(&store, &request) {
            Ok(lists) => rules.lists = lists,
            Err(error) => tracing::warn!(%error, "could not read the session's lists"),
        }
        rules.numbers = config
            .active_rules()
            .map(|set| set.rules.iter().map(|rule| rule.id.clone()).collect())
            .unwrap_or_default();
        rules.changed = saved_since(&store, status.since_unix);
        rules.request = Some(request);
        rules
    }

    /// `temporary`, `rule 3`, `template youtube`, `list`, `lan`, `default`
    /// or `unknown`.
    fn rule(&self, connection: &LiveConnection) -> String {
        let explanation = self
            .request
            .as_ref()
            .and_then(|request| rosetun_core::explain_connection(request, &self.lists, connection));
        let Some(Explanation::Routed { reason, .. }) = explanation else {
            return "unknown".to_owned();
        };
        match reason {
            Reason::Rule {
                temporary: true, ..
            } => "temporary".to_owned(),
            Reason::Rule {
                source: RuleSource::Template { template, .. },
                ..
            } => format!("template {}", template.key()),
            Reason::Rule {
                source: RuleSource::List { .. },
                ..
            } => "list".to_owned(),
            Reason::Rule { id, .. } => self
                .numbers
                .iter()
                .position(|number| *number == id)
                .map_or_else(|| "rule".to_owned(), |index| format!("rule {}", index + 1)),
            Reason::LocalNetwork => "lan".to_owned(),
            Reason::Default => "default".to_owned(),
        }
    }
}

/// The configuration was saved after the session started, or it is not known when.
fn saved_since(store: &rosetun_core::Store, since_unix: Option<u64>) -> bool {
    let Some(since) = since_unix else {
        return true;
    };
    std::fs::metadata(store.path())
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .is_none_or(|modified| modified.as_secs() >= since)
}

/// `rosetun connections close <id>`: a full id goes to the service as typed,
/// a shown short id is first matched against the active connections.
pub(crate) fn close(client: &mut HelperClient, id: &str) -> ExitCode {
    if id.is_empty() {
        eprintln!("the connection ID is empty");
        return ExitCode::FAILURE;
    }
    if let Err(code) = require_connected(client, "close") {
        return code;
    }
    let full = if id.chars().count() > SHORT_ID_CHARS {
        id.to_owned()
    } else {
        let active = match read(client) {
            Ok((active, _)) => active,
            Err(error) => return report(&error, "close"),
        };
        match matching(&active, id).as_slice() {
            [one] => (*one).to_owned(),
            [] => {
                eprintln!("no active connection has the ID {}", terminal_text(id));
                return ExitCode::FAILURE;
            }
            several => {
                eprintln!("the ID {} is ambiguous; use one of:", terminal_text(id));
                for full in several {
                    eprintln!("  {}", terminal_text(full));
                }
                return ExitCode::FAILURE;
            }
        }
    };
    match client.close_connection(&full) {
        Ok(()) => {
            println!("closed");
            ExitCode::SUCCESS
        }
        Err(error) => report(&error, "close"),
    }
}

fn require_connected(client: &mut HelperClient, verb: &str) -> Result<Status, ExitCode> {
    match client.status() {
        Ok(status)
            if matches!(
                status.state,
                ConnectionState::Connected | ConnectionState::Reconnecting
            ) =>
        {
            Ok(status)
        }
        Ok(_) => {
            eprintln!("not connected; connect to {verb} the tunnel's connections");
            Err(ExitCode::FAILURE)
        }
        Err(error) => Err(report(&error, verb)),
    }
}

fn read(
    client: &mut HelperClient,
) -> Result<(Vec<LiveConnection>, Vec<LiveConnection>), ClientError> {
    client.connections().and_then(|_| {
        thread::sleep(FIRST_POLL);
        client.connections()
    })
}

/// Full ids of active connections that `id` names: exactly, or else as the
/// start of each.
fn matching<'a>(active: &'a [LiveConnection], id: &str) -> Vec<&'a str> {
    let ids = active
        .iter()
        .map(|connection| connection.id.as_str())
        .filter(|full| !full.is_empty());
    if let Some(exact) = ids.clone().find(|full| *full == id) {
        return vec![exact];
    }
    let mut found: Vec<_> = ids.filter(|full| full.starts_with(id)).collect();
    found.sort_unstable();
    found.dedup();
    found
}

fn report(error: &ClientError, verb: &str) -> ExitCode {
    match error {
        ClientError::Helper(helper) if helper.code == ErrorCode::AccessDenied => eprintln!(
            "the tunnel is connected from another Windows account; only that account can {verb} its connections"
        ),
        ClientError::Helper(helper) if helper.code == ErrorCode::Busy => {
            eprintln!("the service is busy; try again in a moment");
        }
        _ if verb == "close" => tracing::error!(%error, "failed to close the connection"),
        _ => tracing::error!(%error, "failed to get connections"),
    }
    ExitCode::FAILURE
}

fn line(state: &str, connection: &LiveConnection, now_unix_ms: u64) -> String {
    let network = match connection.network {
        ConnectionNetwork::Tcp => "tcp",
        ConnectionNetwork::Udp => "udp",
    };
    let route = match &connection.route {
        ConnectionRoute::Proxy => "proxy".to_owned(),
        ConnectionRoute::Direct => "direct".to_owned(),
        ConnectionRoute::Exit(exit) => format!("exit:{}", terminal_text(exit.as_str())),
        ConnectionRoute::Other => "other".to_owned(),
    };
    let end = connection.end_unix_ms.unwrap_or(now_unix_ms);
    let seconds = end.saturating_sub(connection.start_unix_ms) / 1000;
    let program = connection.process.as_deref().unwrap_or("-");
    let id: String = connection.id.chars().take(SHORT_ID_CHARS).collect();
    let id = if id.is_empty() {
        "-".to_owned()
    } else {
        terminal_text(&id).replace('\t', " ")
    };
    format!(
        "{state}\t{id}\t{network}\t{route}\t{}\t{}\t{seconds}\t{}:{}\t{}",
        connection.download,
        connection.upload,
        terminal_text(&connection.host).replace('\t', " "),
        connection.port,
        terminal_text(program).replace('\t', " "),
    )
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::{line, matching};
    use rosetun_config::{ConnectionNetwork, ConnectionRoute, ExitId, LiveConnection};

    #[test]
    fn a_line_has_every_column_and_no_control_characters() {
        let connection = LiveConnection {
            id: "0d5c1f2e-7a3b-4c9d-8e1f-2a3b4c5d6e7f".to_owned(),
            start_unix_ms: 1_000,
            end_unix_ms: Some(6_500),
            process: Some("C:\\Program Files\\Example\\app.exe".to_owned()),
            host: "example.com\u{1b}[2J".to_owned(),
            ip: None,
            port: 443,
            network: ConnectionNetwork::Udp,
            route: ConnectionRoute::Exit(ExitId::new("work")),
            download: 7,
            upload: 5,
        };

        let text = line("closed", &connection, 99_000);
        assert!(!text.contains('\u{1b}'));
        let columns: Vec<_> = text.split('\t').collect();
        assert_eq!(
            columns[..7],
            ["closed", "0d5c1f2e", "udp", "exit:work", "7", "5", "5"]
        );
        assert!(columns[7].starts_with("example.com"));
        assert!(columns[7].ends_with(":443"));
        assert_eq!(columns[8], "C:\\Program Files\\Example\\app.exe");

        let active = LiveConnection {
            id: String::new(),
            end_unix_ms: None,
            process: None,
            route: ConnectionRoute::Direct,
            ..connection
        };
        let columns: Vec<_> = line("active", &active, 11_000)
            .split('\t')
            .map(str::to_owned)
            .collect();
        assert_eq!(columns[1], "-");
        assert_eq!(columns[3], "direct");
        assert_eq!(columns[6], "10");
        assert_eq!(columns[8], "-");
    }

    #[test]
    fn a_short_id_closes_only_when_it_names_one_connection() {
        let with_id = |id: &str| LiveConnection {
            id: id.to_owned(),
            start_unix_ms: 1,
            end_unix_ms: None,
            process: None,
            host: "example.com".to_owned(),
            ip: None,
            port: 443,
            network: ConnectionNetwork::Tcp,
            route: ConnectionRoute::Proxy,
            download: 0,
            upload: 0,
        };
        let active = [
            with_id("0d5c1f2e-7a3b-4c9d-8e1f-2a3b4c5d6e7f"),
            with_id("0d5c1f2e-0000-4c9d-8e1f-2a3b4c5d6e7f"),
            with_id("9b1e4d2a-7a3b-4c9d-8e1f-2a3b4c5d6e7f"),
            with_id("short"),
            with_id("shorter"),
            with_id(""),
        ];
        assert_eq!(
            matching(&active, "9b1e4d2a"),
            ["9b1e4d2a-7a3b-4c9d-8e1f-2a3b4c5d6e7f"]
        );
        assert_eq!(matching(&active, "0d5c1f2e").len(), 2);
        assert_eq!(matching(&active, "short"), ["short"]);
        assert!(matching(&active, "ffffffff").is_empty());
    }

    #[test]
    fn the_rule_column_names_what_routed_the_connection() {
        use rosetun_config::{
            DomainMatch, Node, NodeId, Outbound, ProcessMatch, Rule, RuleId, RuleMatcher, RuleSet,
            RuleSetId, RuleTarget, RuleTemplate, Selection, Settings, SubscriptionId, TrojanParams,
        };
        use rosetun_ipc::ConnectRequest;

        use super::SessionRules;

        let rule = |id: &str, matcher| Rule {
            id: RuleId::new(id),
            enabled: true,
            matcher,
            target: RuleTarget::Direct,
            exit: None,
        };
        let mut set = RuleSet::new(RuleSetId::new("set"), "Set", RuleTarget::Proxy);
        set.rules = vec![
            rule("torrents", RuleMatcher::Template(RuleTemplate::Torrents)),
            rule(
                "site",
                RuleMatcher::Domain(DomainMatch::Suffix("example.com".into())),
            ),
        ];
        let numbers = set.rules.iter().map(|rule| rule.id.clone()).collect();
        let (rule_set, rule_templates) = set.expand_templates();
        let request = ConnectRequest {
            selection: Selection {
                subscription: SubscriptionId::new("example"),
                node: NodeId::new("node"),
            },
            node: Node {
                id: NodeId::new("node"),
                name: "Example node".into(),
                server: "203.0.113.10".into(),
                port: 443,
                outbound: Outbound::Trojan(TrojanParams {
                    password: "test-secret".into(),
                }),
                stream: Default::default(),
                raw: None,
            },
            rule_set,
            extra_nodes: Vec::new(),
            temporary_rules: vec![rule(
                "temporary",
                RuleMatcher::Process(ProcessMatch::Path(
                    r"C:\Program Files\Example\app.exe".into(),
                )),
            )],
            lists: Vec::new(),
            settings: Settings::default(),
            rule_templates,
        };
        let rules = SessionRules {
            request: Some(request),
            lists: Default::default(),
            numbers,
            changed: false,
        };
        let connection = |host: &str, process: Option<&str>, route| LiveConnection {
            id: "id".to_owned(),
            start_unix_ms: 1,
            end_unix_ms: None,
            process: process.map(str::to_owned),
            host: host.to_owned(),
            ip: Some("192.0.2.1".to_owned()),
            port: 443,
            network: ConnectionNetwork::Tcp,
            route,
            download: 0,
            upload: 0,
        };

        for (expected, host, process, route) in [
            (
                "temporary",
                "example.com",
                Some(r"C:\Program Files\Example\app.exe"),
                ConnectionRoute::Direct,
            ),
            (
                "template torrents",
                "nothing.invalid",
                Some(r"C:\Program Files\Example\qbittorrent.exe"),
                ConnectionRoute::Direct,
            ),
            ("rule 2", "www.example.com", None, ConnectionRoute::Direct),
            ("default", "nothing.invalid", None, ConnectionRoute::Proxy),
            ("unknown", "nothing.invalid", None, ConnectionRoute::Direct),
        ] {
            assert_eq!(rules.rule(&connection(host, process, route)), expected);
        }
        let unknown = SessionRules {
            request: None,
            ..rules
        };
        assert_eq!(
            unknown.rule(&connection("example.com", None, ConnectionRoute::Direct)),
            "unknown"
        );
    }
}
