use std::io::{self, BufRead, Read, Write};
use std::process::ExitCode;

use rosetun_config::{
    AppConfig, ConnectionState, DomainMatch, ExitId, Rule, RuleId, RuleMatcher, RuleTarget,
    Selection,
    rules_exchange::{self, System},
};
use rosetun_core::{
    Answer, ExplainedRoute, Explanation, InputError, Reason, RuleSource, SessionLists, Store,
    Subject, Unknown, check, read_session_lists, rule_value_text, terminal_text,
};
use rosetun_ipc::{ConnectRequest, ExitContext, HelperClient};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command {
    Export {
        selected: Option<Vec<RuleId>>,
        urls: bool,
        path: String,
    },
    Import {
        replace: bool,
        yes: bool,
        path: String,
    },
    /// Where the rules send a site, an IP address or a program.
    Test { input: String },
}
pub(crate) fn parse(args: &[&str]) -> Result<Command, String> {
    let usage = "rules export [--selected-ids ID,...] [--with-list-urls] [FILE|-], rules import [--replace] [--yes] FILE|- or rules test ADDRESS|PROGRAM";
    let Some((&kind, args)) = args.split_first() else {
        return Err(usage.into());
    };
    if kind == "test" {
        return match args {
            [input] => Ok(Command::Test {
                input: (*input).to_owned(),
            }),
            _ => Err(usage.into()),
        };
    }
    let mut selected = None;
    let mut urls = false;
    let mut replace = false;
    let mut yes = false;
    let mut path = None;
    let mut args = args.iter();
    while let Some(&arg) = args.next() {
        match (kind, arg) {
            ("export", "--selected-ids") if selected.is_none() => {
                let ids = args
                    .next()
                    .ok_or(usage)?
                    .split(',')
                    .map(RuleId::new)
                    .collect::<Vec<_>>();
                if ids
                    .iter()
                    .any(|id| id.as_str().is_empty() || id.as_str().starts_with('-'))
                {
                    return Err(usage.into());
                }
                selected = Some(ids);
            }
            ("export", "--with-list-urls") if !urls => urls = true,
            ("import", "--replace") if !replace => replace = true,
            ("import", "--yes") if !yes => yes = true,
            (_, value) if (value == "-" || !value.starts_with('-')) && path.is_none() => {
                path = Some(value.to_owned());
            }
            _ => return Err(usage.into()),
        }
    }
    match kind {
        "export" => Ok(Command::Export {
            selected,
            urls,
            path: path.unwrap_or_else(|| "-".into()),
        }),
        "import" => Ok(Command::Import {
            replace,
            yes,
            path: path.ok_or(usage)?,
        }),
        _ => Err(usage.into()),
    }
}
fn confirm(label: &str, console: bool) -> Result<bool, String> {
    eprint!("{label} [y/N] ");
    io::stderr().flush().map_err(|_| "could not write prompt")?;
    let mut answer = String::new();
    if console {
        let path = if cfg!(windows) { "CONIN$" } else { "/dev/tty" };
        let input = std::fs::File::open(path).map_err(
            |_| "confirmation requires a terminal; review the preview and retry with --yes",
        )?;
        io::BufReader::new(input)
            .read_line(&mut answer)
            .map_err(|_| "could not read confirmation")?;
    } else {
        io::stdin()
            .lock()
            .read_line(&mut answer)
            .map_err(|_| "could not read confirmation")?;
    }
    Ok(answer.trim().eq_ignore_ascii_case("y") || answer.trim().eq_ignore_ascii_case("yes"))
}
pub(crate) fn run(command: Command) -> ExitCode {
    match command {
        Command::Test { input } => test(&input),
        exchange => crate::local_result(run_exchange(exchange)),
    }
}

fn run_exchange(command: Command) -> Result<(), String> {
    let store = Store::open_default().map_err(|error| error.to_string())?;
    let config = store.load().map_err(|error| error.to_string())?;
    let set = config.active_rules().ok_or("select a rule set first")?;
    match command {
        Command::Test { .. } => return Err("not an exchange command".into()),
        Command::Export {
            selected,
            urls,
            path,
        } => {
            if selected.as_ref().is_some_and(|ids| {
                ids.iter()
                    .any(|id| !set.rules.iter().any(|rule| &rule.id == id))
            }) {
                return Err("selected rule does not exist".into());
            }
            let text =
                rules_exchange::export(&config, set, selected.as_deref(), urls, System::current())
                    .map_err(|error| error.to_string())?;
            if path == "-" {
                println!("{text}");
            } else {
                std::fs::write(path, text).map_err(|_| "could not write rules file")?;
            }
        }
        Command::Import { replace, yes, path } => {
            let console = path == "-";
            let input: Box<dyn Read> = if path == "-" {
                Box::new(io::stdin())
            } else {
                Box::new(std::fs::File::open(path).map_err(|_| "could not read rules file")?)
            };
            let mut text = String::new();
            input
                .take((rules_exchange::MAX_DOCUMENT_BYTES + 1) as u64)
                .read_to_string(&mut text)
                .map_err(|_| "could not read rules document")?;
            let document = rules_exchange::parse(&text).map_err(|error| error.to_string())?;
            let preview =
                rules_exchange::preview(&document, &config, set, replace, System::current());
            eprintln!(
                "Add {} rules · Skip {} duplicates · Disable {} rules · Invalid {}",
                preview.rules.len(),
                preview.duplicates,
                preview.rules.iter().filter(|rule| !rule.enabled).count(),
                preview.entries.iter().filter(|entry| entry.invalid).count()
            );
            for rule in &preview.rules {
                let label = match &rule.matcher {
                    rosetun_config::RuleMatcher::List { list, category } => preview
                        .lists
                        .iter()
                        .chain(&config.lists)
                        .find(|entry| &entry.id == list)
                        .map_or_else(
                            || "List required".into(),
                            |entry| {
                                let source = match &entry.source {
                                    rosetun_config::ListSource::Url(value) => {
                                        rosetun_core::redacted_subscription_url(value)
                                    }
                                    rosetun_config::ListSource::File { original_name }
                                        if original_name == "list-required" =>
                                    {
                                        "list required".into()
                                    }
                                    rosetun_config::ListSource::File { original_name } => {
                                        original_name.clone()
                                    }
                                };
                                format!(
                                    "{} ({source}) {}",
                                    entry.name,
                                    category.as_deref().unwrap_or_default()
                                )
                            },
                        ),
                    matcher => rosetun_core::rule_value_text(matcher),
                };
                let target = rule
                    .exit
                    .as_ref()
                    .and_then(|id| config.exits.iter().find(|exit| &exit.id == id))
                    .map_or_else(
                        || target_text(rule.target).into(),
                        |exit| format!("{}: {}", target_text(rule.target), exit.name),
                    );
                eprintln!(
                    "{} → {}{}",
                    terminal_text(&label),
                    terminal_text(&target),
                    if rule.enabled { "" } else { " (disabled)" }
                );
            }
            for entry in &preview.entries {
                for warning in &entry.warnings {
                    eprintln!("Rule {}: {}", entry.index + 1, warning_text(*warning));
                }
            }
            if document.default_target == Some(RuleTarget::Direct) {
                eprintln!("Warning: the imported default sends traffic directly");
            }
            let change_default = if !yes && let Some(target) = document.default_target {
                confirm(
                    &format!("Replace default rule: {}?", target_text(target)),
                    console,
                )?
            } else {
                false
            };
            if !yes
                && !confirm(
                    if replace {
                        "Replace rules?"
                    } else {
                        "Add rules?"
                    },
                    console,
                )?
            {
                return Ok(());
            }
            rosetun_core::rules_exchange::apply(&store, &set.id, &preview, replace, change_default)
                .map_err(|error| error.to_string())?;
            eprintln!("Added {} rules", preview.rules.len());
        }
    }
    Ok(())
}
/// `rosetun rules test ADDRESS|PROGRAM`: where the rules in use send it. Exit
/// code 0 for an answer, also an uncertain one, 2 for input that is no site,
/// address or program.
fn test(input: &str) -> ExitCode {
    let subject = match Subject::parse(input) {
        Ok(subject) => subject,
        Err(error @ (InputError::Empty | InputError::Unrecognised)) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    match answer(&subject) {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn answer(subject: &Subject) -> Result<String, String> {
    let store = Store::open_default().map_err(|error| error.to_string())?;
    let config = store.load().map_err(|error| error.to_string())?;
    let (temporary, pinned) = session_rules();
    let request = ConnectRequest::for_routing_check(
        &config,
        temporary,
        ExitContext {
            delays: &[],
            selected: &pinned,
        },
    )
    .map_err(|error| error.to_string())?;
    let lists = read_session_lists(&store, &request).unwrap_or_else(|error| {
        eprintln!("could not read the lists, rules on them are left open: {error}");
        SessionLists::default()
    });
    Ok(describe(
        &config,
        subject,
        &check(&request, &lists, subject),
    ))
}

/// The running session's temporary rules and exits, or nothing when there is
/// no session to ask: then the saved rules are all there is.
fn session_rules() -> (Vec<Rule>, Vec<(ExitId, Selection)>) {
    let endpoint = rosetun_ipc::default_endpoint();
    let client_name = concat!("rosetun/", env!("CARGO_PKG_VERSION"));
    let Ok(mut client) = HelperClient::connect(&endpoint, client_name) else {
        return (Vec::new(), Vec::new());
    };
    let running = client.status().is_ok_and(|status| {
        matches!(
            status.state,
            ConnectionState::Connected | ConnectionState::Reconnecting
        )
    });
    if !running {
        return (Vec::new(), Vec::new());
    }
    match (client.temporary_rules(), client.session_exits()) {
        (Ok(temporary), Ok(exits)) => (temporary, crate::exits::pinned(exits)),
        _ => {
            eprintln!("could not read the session's rules, showing the saved ones");
            (Vec::new(), Vec::new())
        }
    }
}

/// The one line `rules test` prints.
fn describe(config: &AppConfig, subject: &Subject, answer: &Answer) -> String {
    let input = terminal_text(&match subject {
        Subject::Site(domain) => {
            rule_value_text(&RuleMatcher::Domain(DomainMatch::Exact(domain.clone())))
        }
        Subject::Address(ip) => ip.to_string(),
        Subject::ProgramName(program) | Subject::ProgramPath(program) => program.clone(),
    });
    let outcome = |explanation: &Explanation| match explanation {
        Explanation::Routed { reason, route } => format!(
            "{} · {}",
            route_text(config, route),
            reason_text(config, reason)
        ),
        Explanation::Unverifiable { .. } => LIST_UNREADABLE.to_owned(),
    };
    match answer {
        Answer::Known(Explanation::Unverifiable { .. }) => {
            format!("{input} → unknown · {LIST_UNREADABLE}")
        }
        Answer::Known(explanation) => format!("{input} → {}", outcome(explanation)),
        Answer::Depends { on, otherwise } => {
            let why = match on {
                Unknown::Network => "depends on the network, which only the service knows",
                Unknown::ProgramPath => "depends on the program's folder, give the full path",
                Unknown::SiteAddress => "depends on the address the site resolves to",
            };
            format!("{input} → {why} · by the rules: {}", outcome(otherwise))
        }
    }
}

const LIST_UNREADABLE: &str = "a list on the way cannot be read here";

fn route_text(config: &AppConfig, route: &ExplainedRoute) -> String {
    match route {
        ExplainedRoute::Proxy => target_text(RuleTarget::Proxy).into(),
        ExplainedRoute::Direct => target_text(RuleTarget::Direct).into(),
        ExplainedRoute::Block => target_text(RuleTarget::Block).into(),
        ExplainedRoute::Exit(id) => config.exits.iter().find(|exit| exit.id == *id).map_or_else(
            || target_text(RuleTarget::Exit).into(),
            |exit| {
                format!(
                    "{}: {}",
                    target_text(RuleTarget::Exit),
                    terminal_text(&exit.name)
                )
            },
        ),
    }
}

fn reason_text(config: &AppConfig, reason: &Reason) -> String {
    match reason {
        Reason::Rule {
            temporary: true, ..
        } => "temporary rule".into(),
        Reason::Rule { id, source, .. } => {
            let number = config.active_rules().and_then(|set| {
                set.rules
                    .iter()
                    .position(|rule| rule.id == *id)
                    .map(|index| index + 1)
            });
            let Some(number) = number else {
                return "rule of the running set".into();
            };
            match source {
                RuleSource::Condition(_) => format!("rule {number}"),
                RuleSource::Group { name, .. } => {
                    format!(
                        "group \u{201c}{}\u{201d} · rule {number}",
                        terminal_text(name)
                    )
                }
                RuleSource::List { list, category } => {
                    let name = config
                        .lists
                        .iter()
                        .find(|entry| entry.id == *list)
                        .map_or("unknown source", |entry| entry.name.as_str());
                    let name = match category {
                        Some(category) => format!("{name}: {category}"),
                        None => name.to_owned(),
                    };
                    format!(
                        "list \u{201c}{}\u{201d} · rule {number}",
                        terminal_text(&name)
                    )
                }
            }
        }
        Reason::LocalNetwork => "local network".into(),
        Reason::PrivateNetwork => "private network behind the router".into(),
        Reason::Default => "default rule".into(),
    }
}

fn warning_text(warning: rules_exchange::Warning) -> &'static str {
    use rules_exchange::Warning;
    match warning {
        Warning::OtherSystem => "for another system",
        Warning::NeedsList => "list required",
        Warning::NeedsFile => "list file required",
        Warning::ExitReplaced => "server unavailable; use VPN",
        Warning::BroadDirect => "warning: broad rule sends traffic directly",
    }
}

fn target_text(target: RuleTarget) -> &'static str {
    match target {
        RuleTarget::Proxy => "Through VPN",
        RuleTarget::Direct => "Direct",
        RuleTarget::Block => "Block",
        RuleTarget::Exit => "Through server",
    }
}

#[cfg(test)]
mod tests {
    use rosetun_config::{List, ListFormat, ListId, ListSource, ProcessMatch, RuleSet, RuleSetId};
    use rosetun_core::ListPayload;

    use super::*;

    fn rule(id: &str, matcher: RuleMatcher, target: RuleTarget) -> Rule {
        Rule {
            id: RuleId::new(id),
            enabled: true,
            matcher,
            target,
            exit: None,
        }
    }

    fn config_with(rules: Vec<Rule>) -> AppConfig {
        let mut set = RuleSet::new(RuleSetId::new("set"), "Set", RuleTarget::Proxy);
        set.rules = rules;
        AppConfig {
            rule_sets: vec![set],
            active_rule_set: Some(RuleSetId::new("set")),
            lists: vec![List {
                id: ListId::new("videos"),
                name: "Videos".into(),
                source: ListSource::File {
                    original_name: "videos.json".into(),
                },
                format: ListFormat::SingBoxSource,
                updated_at: None,
                size: None,
                sha256: None,
                categories: Vec::new(),
                auto_update: true,
            }],
            ..AppConfig::default()
        }
    }

    fn line(config: &AppConfig, lists: &SessionLists, input: &str) -> String {
        let subject = Subject::parse(input).unwrap();
        let request =
            ConnectRequest::for_routing_check(config, Vec::new(), ExitContext::default()).unwrap();
        describe(config, &subject, &check(&request, lists, &subject))
    }

    #[test]
    fn the_line_names_the_route_and_the_rule() {
        let config = config_with(vec![
            rule(
                "one",
                RuleMatcher::Domain(DomainMatch::Suffix("example.com".into())),
                RuleTarget::Direct,
            ),
            rule(
                "two",
                RuleMatcher::IpCidr("192.0.2.0/24".into()),
                RuleTarget::Block,
            ),
            rule(
                "three",
                RuleMatcher::Process(ProcessMatch::Name("tool.exe".into())),
                RuleTarget::Direct,
            ),
            rule(
                "four",
                rosetun_config::RuleTemplate::Torrents.to_group("Torrents"),
                RuleTarget::Block,
            ),
        ]);
        let none = SessionLists::default();

        assert_eq!(
            line(&config, &none, "https://video.example.com/watch"),
            "video.example.com → Direct · rule 1"
        );
        assert_eq!(
            line(&config, &none, "192.0.2.9"),
            "192.0.2.9 → Block · rule 2"
        );
        assert_eq!(
            line(&config, &none, "tool.exe"),
            "tool.exe → Direct · rule 3"
        );
        assert_eq!(
            line(&config, &none, "example.org"),
            concat!(
                "example.org → depends on the address the site resolves to ",
                "· by the rules: Through VPN · default rule"
            )
        );
        assert_eq!(
            line(&config_with(Vec::new()), &none, "example.org"),
            "example.org → Through VPN · default rule"
        );
    }

    #[test]
    fn a_list_is_named_with_its_rule() {
        let config = config_with(vec![rule(
            "one",
            RuleMatcher::List {
                list: ListId::new("videos"),
                category: None,
            },
            RuleTarget::Direct,
        )]);
        let mut lists = SessionLists::default();
        lists.insert(
            &ListId::new("videos"),
            None,
            Some(&ListPayload {
                format: rosetun_core::PayloadFormat::Source,
                bytes: br#"{"version":2,"rules":[{"domain_suffix":["example.com"]}]}"#.to_vec(),
            }),
        );

        assert_eq!(
            line(&config, &lists, "example.com"),
            "example.com → Direct · list \u{201c}Videos\u{201d} · rule 1"
        );
        assert_eq!(
            line(&config, &SessionLists::default(), "example.com"),
            "example.com → unknown · a list on the way cannot be read here"
        );
    }

    #[test]
    fn what_the_client_cannot_know_is_said_with_the_rules_answer() {
        let mut config = config_with(Vec::new());
        config.settings.allow_lan = true;

        assert_eq!(
            line(&config, &SessionLists::default(), "192.168.1.10"),
            "192.168.1.10 → depends on the network, which only the service knows \
             · by the rules: Through VPN · default rule"
        );
    }

    #[test]
    fn the_test_command_takes_one_address_or_program() {
        assert!(matches!(
            parse(&["test", "example.com"]),
            Ok(Command::Test { input }) if input == "example.com"
        ));
        for args in [vec!["test"], vec!["test", "a", "b"]] {
            assert!(parse(&args).is_err());
        }
    }

    #[test]
    fn input_that_is_nothing_known_exits_with_two() {
        for input in ["", "two words.com", "192.0.2.0/24"] {
            assert_eq!(
                format!("{:?}", test(input)),
                format!("{:?}", ExitCode::from(2)),
                "{input:?}"
            );
        }
    }
    #[test]
    fn parser_checks_exchange_options() {
        assert!(matches!(
            parse(&["export"]),
            Ok(Command::Export { urls: false, .. })
        ));
        assert!(matches!(
            parse(&["export", "--selected-ids", "1,2", "--with-list-urls", "-"]),
            Ok(Command::Export { urls: true, .. })
        ));
        assert!(matches!(
            parse(&["import", "--replace", "--yes", "-"]),
            Ok(Command::Import {
                replace: true,
                yes: true,
                ..
            })
        ));
        for args in [
            vec!["import"],
            vec!["export", "--yes"],
            vec!["export", "a", "b"],
            vec!["import", "--with-list-urls", "a"],
            vec!["export", "--selected-ids", "--with-list-urls"],
        ] {
            assert!(parse(&args).is_err());
        }
    }
}
