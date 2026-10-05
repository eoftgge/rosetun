#![allow(unreachable_pub)]

mod subcommands;
mod subscriptions;

use std::path::Path;
use std::process::ExitCode;

use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::prelude::*;

use rosetun_config::{NodeId, SubscriptionId};
use rosetun_core::terminal_text;
use rosetun_ipc::{ConnectRequest, HelperClient};

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Status,
    Connect {
        request_path: Option<String>,
    },
    Select {
        subscription_id: String,
        node_id: String,
    },
    Sub(subcommands::SubCommand),
    Nodes {
        subscription_id: Option<String>,
    },
    Config,
    Disconnect,
    Shutdown,
}

fn main() -> ExitCode {
    let env_filter = tracing_subscriber::EnvFilter::try_from_env("ROSETUN_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    // HTTP-library diagnostics can contain subscription URIs, so an environment
    // log filter must never be able to enable their terminal output.
    let safe_targets =
        filter_fn(|metadata| !rosetun_core::is_sensitive_log_target(metadata.target()));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_filter(safe_targets))
        .init();

    let command = match parse_command() {
        Ok(command) => command,
        Err(message) => {
            eprintln!("{message}");
            print_usage();
            return ExitCode::FAILURE;
        }
    };

    match command {
        Command::Select {
            subscription_id,
            node_id,
        } => local_result(select_node(&subscription_id, &node_id)),
        Command::Sub(command) => local_result(subscriptions::run(command)),
        Command::Nodes { subscription_id } => {
            local_result(subscriptions::nodes(subscription_id.as_deref()))
        }
        Command::Config => local_result(print_config()),
        Command::Connect { request_path } => match prepare_connect_request(request_path.as_deref())
        {
            Ok(request) => with_helper(|client| connect(client, request)),
            Err(message) => local_result(Err(message)),
        },
        Command::Status => with_helper(status),
        Command::Disconnect => with_helper(disconnect),
        Command::Shutdown => with_helper(shutdown),
    }
}

fn connect(client: &mut HelperClient, request: ConnectRequest) -> ExitCode {
    match client.connect_tunnel(request) {
        Ok(()) => {
            println!("tunnel connection started");
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!(%error, "failed to connect tunnel");
            ExitCode::FAILURE
        }
    }
}

fn status(client: &mut HelperClient) -> ExitCode {
    match client.status() {
        Ok(status) => {
            println!("state: {:?}", status.state);
            println!("engine:      {:?}", status.engine);
            println!(
                "traffic: up {} B/s down {} B/s",
                status.traffic.up_bps, status.traffic.down_bps
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!(%error, "failed to get status");
            ExitCode::FAILURE
        }
    }
}

fn disconnect(client: &mut HelperClient) -> ExitCode {
    match client.disconnect_tunnel() {
        Ok(()) => {
            println!("tunnel disconnected");
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!(%error, "failed to disconnect tunnel");
            ExitCode::FAILURE
        }
    }
}

fn shutdown(client: &mut HelperClient) -> ExitCode {
    match client.shutdown() {
        Ok(()) => {
            println!("helper shut down");
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!(%error, "failed to shut down helper");
            ExitCode::FAILURE
        }
    }
}

fn with_helper(run: impl FnOnce(&mut HelperClient) -> ExitCode) -> ExitCode {
    let endpoint = rosetun_ipc::default_endpoint();
    let client_name = concat!("rosetun/", env!("CARGO_PKG_VERSION"));
    match HelperClient::connect(&endpoint, client_name) {
        Ok(mut client) => {
            tracing::info!(helper = client.helper_version(), "connection established");
            run(&mut client)
        }
        Err(error) => {
            tracing::error!(endpoint = %endpoint.display(), %error, "helper unavailable");
            ExitCode::FAILURE
        }
    }
}

fn local_result(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn prepare_connect_request(request_path: Option<&str>) -> Result<ConnectRequest, String> {
    if let Some(path) = request_path {
        return read_connect_request(Path::new(path));
    }

    if let Some(path) = request_path {
        return read_connect_request(Path::new(path));
    }

    let current_store = rosetun_core::Store::open_default().map_err(|error| error.to_string())?;
    let config = current_store.load().map_err(|error| error.to_string())?;
    ConnectRequest::from_config(&config).map_err(|error| match error {
        rosetun_ipc::ConnectRequestError::NodeNotFound
        | rosetun_ipc::ConnectRequestError::SelectionMissing => {
            "select an existing node with rosetun select <subscription-id> <node-id>".to_owned()
        }
        rosetun_ipc::ConnectRequestError::RuleSetNotFound => error.to_string(),
    })
}

fn select_node(subscription_id: &str, node_id: &str) -> Result<(), String> {
    let current_store = rosetun_core::Store::open_default().map_err(|error| error.to_string())?;

    let node_name = rosetun_core::select_node(
        &current_store,
        &SubscriptionId::new(subscription_id),
        &NodeId::new(node_id),
    )
    .map_err(|error| error.to_string())?;

    println!("selected node: {}", terminal_text(&node_name));

    Ok(())
}

fn print_config() -> Result<(), String> {
    let current_store = rosetun_core::Store::open_default().map_err(|error| error.to_string())?;
    let path = current_store.path();
    println!("configuration path: {}", path.display());

    match std::fs::metadata(path) {
        Ok(_) => println!("file exists: yes"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("file exists: no");
        }
        Err(error) => {
            println!("file exists: unknown");
            return Err(format!("could not inspect {}: {error}", path.display()));
        }
    }

    let config = match current_store.load() {
        Ok(config) => config,
        Err(error) => {
            println!("validation: failed");
            println!("active node: unavailable");
            println!("active rule set: unavailable");

            return Err(error.to_string());
        }
    };

    println!("validation: passed");

    match config.active_node() {
        Some((subscription, node)) => {
            println!(
                "active subscription: {}",
                terminal_text(subscription.id.as_str())
            );
            println!("active node id: {}", terminal_text(node.id.as_str()));
            println!("active node name: {}", terminal_text(&node.name));
        }
        None => println!("active node: none"),
    }

    match config.active_rules() {
        Some(rule_set) => {
            println!(
                "active rule set id: {}",
                terminal_text(rule_set.id.as_str())
            );
            println!("active rule set name: {}", terminal_text(&rule_set.name));
        }
        None => println!("active rule set: none (connect uses Default, proxy)"),
    }

    Ok(())
}

fn parse_command() -> Result<Command, String> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    parse_command_arguments(&arguments)
}

fn parse_command_arguments(arguments: &[String]) -> Result<Command, String> {
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();

    match arguments.as_slice() {
        [] | ["status"] => Ok(Command::Status),
        ["connect"] => Ok(Command::Connect { request_path: None }),
        ["connect", path] => Ok(Command::Connect {
            request_path: Some((*path).to_owned()),
        }),
        ["select", subscription_id, node_id] => Ok(Command::Select {
            subscription_id: (*subscription_id).to_owned(),
            node_id: (*node_id).to_owned(),
        }),
        ["sub", arguments @ ..] => subcommands::parse(arguments).map(Command::Sub),
        ["nodes", arguments @ ..] => subcommands::parse_nodes(arguments)
            .map(|subscription_id| Command::Nodes { subscription_id }),
        ["config"] => Ok(Command::Config),
        ["disconnect"] => Ok(Command::Disconnect),
        ["shutdown"] => Ok(Command::Shutdown),
        ["connect", ..] => Err("connect accepts zero or one request JSON path".to_owned()),
        ["select", ..] => Err("select requires exactly a subscription ID and a node ID".to_owned()),
        ["config", ..] => Err("config does not accept arguments".to_owned()),
        ["status", ..] => Err("status does not accept arguments".to_owned()),
        ["disconnect", ..] => Err("disconnect does not accept arguments".to_owned()),
        ["shutdown", ..] => Err("shutdown does not accept arguments".to_owned()),
        [_, ..] => Err("unknown command".to_owned()),
    }
}

fn read_connect_request(path: &Path) -> Result<ConnectRequest, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;

    serde_json::from_str(&contents)
        .map_err(|error| format!("could not parse {}: {error}", path.display()))
}

fn print_usage() {
    eprintln!(
        "\
Usage:
  rosetun [status]
  rosetun connect [request.json]
  rosetun select <subscription-id> <node-id>
  rosetun sub add <url> [--name <name>] [--user-agent <ua>] [--no-hwid]
  rosetun sub update [<id>]
  rosetun sub list
  rosetun sub remove <id>
  rosetun nodes [<sub-id>]
  rosetun config
  rosetun disconnect
  rosetun shutdown

Subscription and node commands are local and do not require the helper.
Options for sub add may appear in any order after the URL."
    );
}

#[cfg(test)]
mod tests {
    use super::{Command, parse_command_arguments};

    fn parse(arguments: &[&str]) -> Result<Command, String> {
        let arguments: Vec<String> = arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect();
        parse_command_arguments(&arguments)
    }

    #[test]
    fn valid_commands_are_parsed() {
        assert_eq!(parse(&[]), Ok(Command::Status));
        assert_eq!(parse(&["status"]), Ok(Command::Status));
        assert_eq!(
            parse(&["connect"]),
            Ok(Command::Connect { request_path: None })
        );
        assert_eq!(
            parse(&["connect", "request.json"]),
            Ok(Command::Connect {
                request_path: Some("request.json".to_owned()),
            })
        );
        assert_eq!(
            parse(&["select", "subscription", "node"]),
            Ok(Command::Select {
                subscription_id: "subscription".to_owned(),
                node_id: "node".to_owned(),
            })
        );
        assert_eq!(parse(&["config"]), Ok(Command::Config));
        assert_eq!(parse(&["disconnect"]), Ok(Command::Disconnect));
        assert_eq!(parse(&["shutdown"]), Ok(Command::Shutdown));
    }

    #[test]
    fn connect_rejects_more_than_one_path() {
        for arguments in [
            vec!["connect", "a", "b"],
            vec!["connect", "request.json", "extra", "another"],
        ] {
            assert_eq!(
                parse(&arguments),
                Err("connect accepts zero or one request JSON path".to_owned())
            );
        }
    }

    #[test]
    fn select_requires_exactly_two_arguments() {
        for arguments in [
            vec!["select"],
            vec!["select", "subscription"],
            vec!["select", "subscription", "node", "extra"],
        ] {
            assert_eq!(
                parse(&arguments),
                Err("select requires exactly a subscription ID and a node ID".to_owned())
            );
        }
    }

    #[test]
    fn commands_without_parameters_reject_extra_arguments() {
        for command in ["status", "config", "disconnect", "shutdown"] {
            for arguments in [vec![command, "extra"], vec![command, "extra", "another"]] {
                assert_eq!(
                    parse(&arguments),
                    Err(format!("{command} does not accept arguments"))
                );
            }
        }
    }

    #[test]
    fn unknown_commands_are_rejected() {
        assert_eq!(parse(&["unknown"]), Err("unknown command".to_owned()));
        assert_eq!(
            parse(&["unknown", "extra"]),
            Err("unknown command".to_owned())
        );
    }

    #[test]
    fn subscription_commands_are_parsed() {
        use crate::subcommands::SubCommand;

        assert_eq!(
            parse(&["sub", "add", "https://sub.example.com/token"]),
            Ok(Command::Sub(SubCommand::Add {
                url: "https://sub.example.com/token".to_owned(),
                name: None,
                user_agent: None,
                send_hwid: true,
            }))
        );
        assert_eq!(
            parse(&[
                "sub",
                "add",
                "https://sub.example.com/token",
                "--no-hwid",
                "--user-agent",
                "Client/1",
                "--name",
                "Example",
            ]),
            Ok(Command::Sub(SubCommand::Add {
                url: "https://sub.example.com/token".to_owned(),
                name: Some("Example".to_owned()),
                user_agent: Some("Client/1".to_owned()),
                send_hwid: false,
            }))
        );
        assert_eq!(
            parse(&["sub", "update"]),
            Ok(Command::Sub(SubCommand::Update { id: None }))
        );
        assert_eq!(
            parse(&["sub", "update", "1"]),
            Ok(Command::Sub(SubCommand::Update {
                id: Some("1".to_owned()),
            }))
        );
        assert_eq!(parse(&["sub", "list"]), Ok(Command::Sub(SubCommand::List)));
        assert_eq!(
            parse(&["sub", "remove", "1"]),
            Ok(Command::Sub(SubCommand::Remove { id: "1".to_owned() }))
        );
        assert_eq!(
            parse(&["nodes"]),
            Ok(Command::Nodes {
                subscription_id: None,
            })
        );
        assert_eq!(
            parse(&["nodes", "1"]),
            Ok(Command::Nodes {
                subscription_id: Some("1".to_owned()),
            })
        );
    }

    #[test]
    fn invalid_subscription_commands_are_rejected() {
        let invalid: &[&[&str]] = &[
            &["sub"],
            &["sub", "unknown"],
            &["sub", "add"],
            &["sub", "add", "https://example.com/token", "--unknown"],
            &["sub", "add", "https://example.com/token", "--name"],
            &["sub", "update", "1", "2"],
            &["sub", "list", "extra"],
            &["sub", "remove"],
            &["sub", "remove", "1", "2"],
            &["nodes", "1", "2"],
            &["nodes", "--unknown"],
        ];

        for arguments in invalid {
            assert!(parse(arguments).is_err(), "accepted {arguments:?}");
        }
    }

    #[test]
    fn command_errors_and_add_debug_do_not_expose_subscription_url() {
        let secret = "https://sub.example.com/private-token?key=query-secret";
        for arguments in [
            vec![secret],
            vec!["sub", secret],
            vec!["sub", "add", secret, secret],
        ] {
            let error = parse(&arguments).unwrap_err();
            assert!(!error.contains("private-token"));
            assert!(!error.contains("query-secret"));
        }

        let command = parse(&["sub", "add", secret]).unwrap();
        let debug = format!("{command:?}");
        assert!(debug.contains("https://sub.example.com/…"));
        assert!(!debug.contains("private-token"));
        assert!(!debug.contains("query-secret"));
    }
}
