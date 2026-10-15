#![allow(unreachable_pub)]

mod subcommands;
mod subscriptions;

use std::path::Path;
use std::process::ExitCode;

use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::prelude::*;

use rosetun_config::{
    ConnectionState, DomainMatch, FailureKind, NodeId, ProcessMatch, Rule, RuleMatcher, RuleTarget,
    Status, SubscriptionId, XrayUse,
};
use rosetun_core::{ListOperation, PreparedConnection, terminal_text};
use rosetun_ipc::{
    ClientError, ConnectRequest, ErrorCode, HelperClient, ProbeOutcome, ProbeRequest,
};

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Status,
    Temporary,
    Connect {
        request_path: Option<String>,
    },
    Apply {
        request_path: Option<String>,
    },
    Probe {
        request_path: Option<String>,
    },
    Delay,
    Select {
        subscription_id: String,
        node_id: String,
    },
    Sub(subcommands::SubCommand),
    Nodes {
        subscription_id: Option<String>,
    },
    Config,
    Xray(XrayUse),
    Lan(bool),
    Disconnect,
    Shutdown,
}

enum PreparedCliRequest {
    Raw(ConnectRequest),
    Lists(PreparedConnection),
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
        Command::Xray(setting) => local_result(set_xray(setting)),
        Command::Lan(enabled) => local_result(set_lan(enabled)),
        Command::Connect { request_path } => match prepare_list_request(request_path.as_deref()) {
            Ok(request) => with_helper(|client| connect(client, request)),
            Err(message) => local_result(Err(message)),
        },
        Command::Apply { request_path } => match request_path {
            Some(path) => match prepare_list_request(Some(&path)) {
                Ok(request) => with_helper(|client| apply(client, request)),
                Err(message) => local_result(Err(message)),
            },
            None => with_helper(|client| match prepare_apply_request(client) {
                Ok(request) => apply(client, request),
                Err(message) => local_result(Err(message)),
            }),
        },
        Command::Probe { request_path } => match prepare_connect_request(request_path.as_deref()) {
            Ok(request) => with_helper(|client| probe(client, request)),
            Err(message) => local_result(Err(message)),
        },
        Command::Delay => with_helper(delay),
        Command::Status => with_helper(status),
        Command::Temporary => with_helper(temporary),
        Command::Disconnect => with_helper(disconnect),
        Command::Shutdown => with_helper(shutdown),
    }
}

fn connect(client: &mut HelperClient, request: PreparedCliRequest) -> ExitCode {
    match send_connection(client, request, ListOperation::Connect) {
        Ok(()) => {
            println!("connected");
            ExitCode::SUCCESS
        }
        Err(error) => {
            report_helper_error(&error, "failed to connect tunnel");
            ExitCode::FAILURE
        }
    }
}

fn apply(client: &mut HelperClient, request: PreparedCliRequest) -> ExitCode {
    match send_connection(client, request, ListOperation::Apply) {
        Ok(()) => {
            println!("session changes applied");
            ExitCode::SUCCESS
        }
        Err(error) => {
            if let Some(message) = apply_error_message(&error) {
                eprintln!("{message}");
            } else {
                tracing::error!(%error, "failed to apply session changes");
            }
            ExitCode::FAILURE
        }
    }
}

fn apply_error_message(error: &ClientError) -> Option<&'static str> {
    match error {
        ClientError::Helper(helper)
            if helper.code == ErrorCode::InvalidState
                && helper.message == "reconnect to change protection settings" =>
        {
            Some("protection settings changed; run `rosetun connect`")
        }
        _ => access_denied_message(error),
    }
}

fn access_denied_message(error: &ClientError) -> Option<&'static str> {
    matches!(error, ClientError::Helper(helper) if helper.code == ErrorCode::AccessDenied)
        .then_some(
            "the tunnel is connected from another Windows account; only that account or an administrator can control it",
        )
}

fn report_helper_error(error: &ClientError, context: &str) {
    if let Some(message) = access_denied_message(error) {
        eprintln!("{message}");
    } else {
        tracing::error!(%error, "{context}");
    }
}

fn send_connection(
    client: &mut HelperClient,
    request: PreparedCliRequest,
    operation: ListOperation,
) -> Result<(), rosetun_ipc::ClientError> {
    match request {
        PreparedCliRequest::Raw(request) => match operation {
            ListOperation::Connect => client.connect_tunnel(request),
            ListOperation::Apply => client.apply_tunnel(request),
        },
        PreparedCliRequest::Lists(prepared) => {
            let cached = prepared.missing_categories.len() - prepared.skipped_categories.len();
            if cached > 0 {
                eprintln!(
                    "warning: {cached} list rules use a category that is no longer in the list; the last known version is used"
                );
            }
            if !prepared.skipped_categories.is_empty() {
                eprintln!(
                    "warning: {} list rules use a category that is no longer in the list; these rules are skipped",
                    prepared.skipped_categories.len()
                );
            }
            rosetun_core::send_prepared(client, &prepared, operation)
        }
    }
}

fn probe(client: &mut HelperClient, request: ConnectRequest) -> ExitCode {
    match client.probe_nodes(ProbeRequest {
        nodes: vec![request.node],
        settings: request.settings,
    }) {
        Ok(results) if results.len() == 1 => {
            print_probe_outcome(results[0].outcome);
            ExitCode::SUCCESS
        }
        Ok(_) => {
            tracing::error!("helper returned an unexpected number of server check results");
            ExitCode::FAILURE
        }
        Err(error) => {
            report_helper_error(&error, "failed to check server");
            ExitCode::FAILURE
        }
    }
}

fn delay(client: &mut HelperClient) -> ExitCode {
    match client.tunnel_delay().map(|delays| delays.proxy) {
        Ok(ProbeOutcome::Works { millis }) => {
            println!("works {millis} ms");
            ExitCode::SUCCESS
        }
        Ok(_) => {
            println!("fails");
            ExitCode::SUCCESS
        }
        Err(error) => {
            report_helper_error(&error, "failed to check tunnel delay");
            ExitCode::FAILURE
        }
    }
}

fn print_probe_outcome(outcome: ProbeOutcome) {
    match outcome {
        ProbeOutcome::Works { millis } => println!("works {millis} ms"),
        ProbeOutcome::Fails => println!("fails"),
        ProbeOutcome::Unresolved => println!("unresolved"),
        ProbeOutcome::Unsupported => println!("unsupported"),
    }
}

fn status_has_no_network(status: &Status) -> bool {
    match &status.state {
        ConnectionState::Failed { failure_kind, .. }
        | ConnectionState::FailedProtected { failure_kind, .. } => {
            *failure_kind == Some(FailureKind::NoNetwork)
        }
        ConnectionState::Reconnecting => {
            status.reconnect_failure_kind == Some(FailureKind::NoNetwork)
        }
        _ => false,
    }
}

fn status(client: &mut HelperClient) -> ExitCode {
    let result = client.status().and_then(|status| {
        temporary_rules_status(client.temporary_rules())
            .map(|temporary_count| (status, temporary_count))
    });
    match result {
        Ok((status, temporary_count)) => {
            println!("state: {:?}", status.state);
            if status_has_no_network(&status) {
                println!("network: no network");
            }
            println!("temporary rules: {temporary_count}");
            println!(
                "node: {}",
                terminal_text(status.node.as_ref().map(NodeId::as_str).unwrap_or("none"))
            );
            println!("engine:      {:?}", status.engine);
            println!(
                "traffic: up {} B/s down {} B/s",
                status.traffic.up_bps, status.traffic.down_bps
            );
            println!(
                "total:   up {} B down {} B",
                status.traffic.up_total, status.traffic.down_total
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            report_helper_error(&error, "failed to get status");
            ExitCode::FAILURE
        }
    }
}

fn temporary_rules_status(result: Result<Vec<Rule>, ClientError>) -> Result<String, ClientError> {
    match result {
        Ok(rules) => Ok(rules.len().to_string()),
        Err(ClientError::Helper(helper)) if helper.code == ErrorCode::Busy => {
            Ok("unavailable while the service is busy".to_owned())
        }
        Err(ClientError::Helper(helper)) if helper.code == ErrorCode::AccessDenied => {
            Ok("unavailable for another Windows account".to_owned())
        }
        Err(error) => Err(error),
    }
}

fn temporary(client: &mut HelperClient) -> ExitCode {
    match client.temporary_rules() {
        Ok(rules) if rules.is_empty() => {
            println!("none");
            ExitCode::SUCCESS
        }
        Ok(rules) => {
            for rule in &rules {
                println!("{}", temporary_rule_line(rule));
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            report_helper_error(&error, "failed to get temporary rules");
            ExitCode::FAILURE
        }
    }
}

fn temporary_rule_line(rule: &Rule) -> String {
    let target = match rule.target {
        RuleTarget::Proxy => "proxy",
        RuleTarget::Direct => "direct",
        RuleTarget::Block | RuleTarget::Exit => "block",
    };
    let value = match &rule.matcher {
        RuleMatcher::Domain(DomainMatch::Exact(value)) => format!("domain exact {value}"),
        RuleMatcher::Domain(DomainMatch::Suffix(value)) => format!("domain suffix {value}"),
        RuleMatcher::Domain(DomainMatch::Keyword(value)) => format!("domain keyword {value}"),
        RuleMatcher::Process(ProcessMatch::Name(value)) => format!("process name {value}"),
        RuleMatcher::Process(ProcessMatch::Path(value)) => {
            format!("process path {}", value.display())
        }
        RuleMatcher::IpCidr(value) => format!("ip {value}"),
        RuleMatcher::List { list, category } => category.as_ref().map_or_else(
            || format!("list {list}"),
            |category| format!("list {list}:{category}"),
        ),
        RuleMatcher::Template(_) => "template".to_owned(),
    };
    format!("{target}: {}", terminal_text(&value))
}

fn disconnect(client: &mut HelperClient) -> ExitCode {
    match client.disconnect_tunnel() {
        Ok(()) => {
            println!("tunnel disconnected");
            ExitCode::SUCCESS
        }
        Err(error) => {
            report_helper_error(&error, "failed to disconnect tunnel");
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
            report_helper_error(&error, "failed to shut down helper");
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
            if let Some(message) = access_denied_message(&error) {
                eprintln!("{message}");
            } else {
                tracing::error!(endpoint = %endpoint.display(), %error, "helper unavailable");
            }
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

    let current_store = rosetun_core::Store::open_default().map_err(|error| error.to_string())?;
    let config = current_store.load().map_err(|error| error.to_string())?;
    ConnectRequest::from_config_with_exits(&config, rosetun_ipc::ExitContext::default())
        .map_err(connect_request_error)
}

fn prepare_list_request(request_path: Option<&str>) -> Result<PreparedCliRequest, String> {
    if let Some(path) = request_path {
        return read_connect_request(Path::new(path)).map(PreparedCliRequest::Raw);
    }
    let request = prepare_connect_request(None)?;
    let store = rosetun_core::Store::open_default().map_err(|error| error.to_string())?;
    rosetun_core::prepare_lists(&store, request)
        .map(PreparedCliRequest::Lists)
        .map_err(|error| error.to_string())
}

fn prepare_apply_request(client: &mut HelperClient) -> Result<PreparedCliRequest, String> {
    let temporary = client.temporary_rules().map_err(|error| {
        access_denied_message(&error)
            .map(str::to_owned)
            .unwrap_or_else(|| error.to_string())
    })?;
    let store = rosetun_core::Store::open_default().map_err(|error| error.to_string())?;
    let config = store.load().map_err(|error| error.to_string())?;
    let request = ConnectRequest::for_apply_with_exits(
        &config,
        None,
        temporary,
        rosetun_ipc::ExitContext::default(),
    )
    .map_err(connect_request_error)?;
    rosetun_core::prepare_lists(&store, request)
        .map(PreparedCliRequest::Lists)
        .map_err(|error| error.to_string())
}

fn connect_request_error(error: rosetun_ipc::ConnectRequestError) -> String {
    match error {
        rosetun_ipc::ConnectRequestError::NodeNotFound
        | rosetun_ipc::ConnectRequestError::SelectionMissing => {
            "select an existing node with rosetun select <subscription-id> <node-id>".to_owned()
        }
        rosetun_ipc::ConnectRequestError::RuleSetNotFound => error.to_string(),
    }
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
    println!(
        "local network: {}",
        if config.settings.allow_lan {
            "on"
        } else {
            "off"
        }
    );

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

fn set_xray(setting: XrayUse) -> Result<(), String> {
    let store = rosetun_core::Store::open_default().map_err(|error| error.to_string())?;
    rosetun_core::change_setting(&store, rosetun_core::SettingChange::Xray(setting))
        .map_err(|error| error.to_string())
}

fn set_lan(enabled: bool) -> Result<(), String> {
    let store = rosetun_core::Store::open_default().map_err(|error| error.to_string())?;
    rosetun_core::change_setting(&store, rosetun_core::SettingChange::AllowLan(enabled))
        .map_err(|error| error.to_string())
}

fn parse_command() -> Result<Command, String> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    parse_command_arguments(&arguments)
}

fn parse_command_arguments(arguments: &[String]) -> Result<Command, String> {
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();

    match arguments.as_slice() {
        [] | ["status"] => Ok(Command::Status),
        ["temporary"] => Ok(Command::Temporary),
        ["connect"] => Ok(Command::Connect { request_path: None }),
        ["connect", path] => Ok(Command::Connect {
            request_path: Some((*path).to_owned()),
        }),
        ["apply"] => Ok(Command::Apply { request_path: None }),
        ["apply", path] => Ok(Command::Apply {
            request_path: Some((*path).to_owned()),
        }),
        ["probe"] => Ok(Command::Probe { request_path: None }),
        ["probe", path] => Ok(Command::Probe {
            request_path: Some((*path).to_owned()),
        }),
        ["delay"] => Ok(Command::Delay),
        ["select", subscription_id, node_id] => Ok(Command::Select {
            subscription_id: (*subscription_id).to_owned(),
            node_id: (*node_id).to_owned(),
        }),
        ["sub", arguments @ ..] => subcommands::parse(arguments).map(Command::Sub),
        ["nodes", arguments @ ..] => subcommands::parse_nodes(arguments)
            .map(|subscription_id| Command::Nodes { subscription_id }),
        ["config"] => Ok(Command::Config),
        ["xray", "auto"] => Ok(Command::Xray(XrayUse::Auto)),
        ["xray", "off"] => Ok(Command::Xray(XrayUse::Off)),
        ["xray", "always"] => Ok(Command::Xray(XrayUse::Always)),
        ["lan", "on"] => Ok(Command::Lan(true)),
        ["lan", "off"] => Ok(Command::Lan(false)),
        ["disconnect"] => Ok(Command::Disconnect),
        ["shutdown"] => Ok(Command::Shutdown),
        ["connect", ..] => Err("connect accepts zero or one request JSON path".to_owned()),
        ["apply", ..] => Err("apply accepts zero or one request JSON path".to_owned()),
        ["probe", ..] => Err("probe accepts zero or one request JSON path".to_owned()),
        ["delay", ..] => Err("delay does not accept arguments".to_owned()),
        ["select", ..] => Err("select requires exactly a subscription ID and a node ID".to_owned()),
        ["config", ..] => Err("config does not accept arguments".to_owned()),
        ["xray", ..] => Err("xray requires auto, off or always".to_owned()),
        ["lan", ..] => Err("lan requires on or off".to_owned()),
        ["status", ..] => Err("status does not accept arguments".to_owned()),
        ["temporary", ..] => Err("temporary does not accept arguments".to_owned()),
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
  rosetun temporary
  rosetun connect [request.json]
  rosetun apply [request.json]
  rosetun probe [request.json]
  rosetun delay
  rosetun select <subscription-id> <node-id>
  rosetun sub add <url> [--name <name>] [--user-agent <ua>] [--no-hwid]
  rosetun sub update [<id>]
  rosetun sub list
  rosetun sub remove <id>
  rosetun nodes [<sub-id>]
  rosetun config
  rosetun xray <auto|off|always>
  rosetun lan <on|off>
  rosetun disconnect
  rosetun shutdown

Subscription and node commands are local and do not require the helper.
Options for sub add may appear in any order after the URL."
    );
}

#[cfg(test)]
mod tests {
    use super::{
        Command, access_denied_message, apply_error_message, parse_command_arguments,
        status_has_no_network, temporary_rule_line, temporary_rules_status,
    };
    use rosetun_config::{
        ConnectionState, DomainMatch, FailureKind, ProcessMatch, Rule, RuleId, RuleMatcher,
        RuleTarget, Status, XrayUse,
    };
    use rosetun_ipc::{ClientError, ErrorCode, HelperError};

    fn parse(arguments: &[&str]) -> Result<Command, String> {
        let arguments: Vec<String> = arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect();
        parse_command_arguments(&arguments)
    }

    #[test]
    fn status_labels_missing_network_on_failure_and_while_waiting() {
        for state in [
            ConnectionState::Failed {
                reason: "no route".into(),
                failure_kind: Some(FailureKind::NoNetwork),
            },
            ConnectionState::FailedProtected {
                reason: "no route".into(),
                failure_kind: Some(FailureKind::NoNetwork),
            },
        ] {
            assert!(status_has_no_network(&Status {
                state,
                ..Status::default()
            }));
        }
        assert!(status_has_no_network(&Status {
            state: ConnectionState::Reconnecting,
            reconnect_failure_kind: Some(FailureKind::NoNetwork),
            ..Status::default()
        }));
        assert!(!status_has_no_network(&Status {
            state: ConnectionState::Failed {
                reason: "server".into(),
                failure_kind: Some(FailureKind::ServerUnreachable),
            },
            ..Status::default()
        }));
    }

    #[test]
    fn valid_commands_are_parsed() {
        assert_eq!(parse(&[]), Ok(Command::Status));
        assert_eq!(parse(&["status"]), Ok(Command::Status));
        assert_eq!(parse(&["temporary"]), Ok(Command::Temporary));
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
        assert_eq!(parse(&["apply"]), Ok(Command::Apply { request_path: None }));
        assert_eq!(
            parse(&["apply", "request.json"]),
            Ok(Command::Apply {
                request_path: Some("request.json".to_owned()),
            })
        );
        assert_eq!(parse(&["probe"]), Ok(Command::Probe { request_path: None }));
        assert_eq!(
            parse(&["probe", "request.json"]),
            Ok(Command::Probe {
                request_path: Some("request.json".to_owned()),
            })
        );
        assert_eq!(parse(&["delay"]), Ok(Command::Delay));
        assert_eq!(
            parse(&["select", "subscription", "node"]),
            Ok(Command::Select {
                subscription_id: "subscription".to_owned(),
                node_id: "node".to_owned(),
            })
        );
        assert_eq!(parse(&["config"]), Ok(Command::Config));
        assert_eq!(parse(&["xray", "auto"]), Ok(Command::Xray(XrayUse::Auto)));
        assert_eq!(parse(&["xray", "off"]), Ok(Command::Xray(XrayUse::Off)));
        assert_eq!(
            parse(&["xray", "always"]),
            Ok(Command::Xray(XrayUse::Always))
        );
        assert!(parse(&["xray", "unknown"]).is_err());
        assert_eq!(parse(&["lan", "on"]), Ok(Command::Lan(true)));
        assert_eq!(parse(&["lan", "off"]), Ok(Command::Lan(false)));
        assert!(parse(&["lan", "unknown"]).is_err());
        assert_eq!(parse(&["disconnect"]), Ok(Command::Disconnect));
        assert_eq!(parse(&["shutdown"]), Ok(Command::Shutdown));
    }

    #[test]
    fn apply_reconnect_error_has_an_actionable_message() {
        let reconnect = ClientError::Helper(HelperError::new(
            ErrorCode::InvalidState,
            "reconnect to change protection settings",
        ));
        assert_eq!(
            apply_error_message(&reconnect),
            Some("protection settings changed; run `rosetun connect`")
        );
        assert_eq!(
            apply_error_message(&ClientError::Helper(HelperError::new(
                ErrorCode::InvalidState,
                "another invalid state",
            ))),
            None
        );
        assert_eq!(apply_error_message(&ClientError::Closed), None);
    }

    #[test]
    fn denied_control_has_a_clear_message() {
        let denied = ClientError::Helper(HelperError::new(
            ErrorCode::AccessDenied,
            "the tunnel belongs to another Windows account",
        ));
        let message = "the tunnel is connected from another Windows account; only that account or an administrator can control it";
        assert_eq!(access_denied_message(&denied), Some(message));
        assert_eq!(apply_error_message(&denied), Some(message));
        assert_eq!(access_denied_message(&ClientError::Closed), None);
    }

    #[test]
    fn status_hides_temporary_rules_when_busy_or_denied() {
        assert_eq!(temporary_rules_status(Ok(Vec::new())).unwrap(), "0");
        assert_eq!(
            temporary_rules_status(Err(ClientError::Helper(HelperError::new(
                ErrorCode::Busy,
                "another tunnel operation is in progress",
            ))))
            .unwrap(),
            "unavailable while the service is busy"
        );
        assert_eq!(
            temporary_rules_status(Err(ClientError::Helper(HelperError::new(
                ErrorCode::AccessDenied,
                "another Windows account",
            ))))
            .unwrap(),
            "unavailable for another Windows account"
        );
        assert!(matches!(
            temporary_rules_status(Err(ClientError::Helper(HelperError::new(
                ErrorCode::InvalidState,
                "no session",
            )))),
            Err(ClientError::Helper(_))
        ));
        assert!(matches!(
            temporary_rules_status(Err(ClientError::Closed)),
            Err(ClientError::Closed)
        ));
    }

    #[test]
    fn temporary_rule_values_are_sanitized_for_one_line_output() {
        let mut rule = Rule {
            id: RuleId::new("temporary"),
            enabled: true,
            matcher: RuleMatcher::Domain(DomainMatch::Exact("example.com\nspoofed".into())),
            target: RuleTarget::Direct,
            exit: None,
        };
        assert_eq!(
            temporary_rule_line(&rule),
            "direct: domain exact example.com spoofed"
        );
        rule.matcher = RuleMatcher::Process(ProcessMatch::Path("C:\\apps\\foo\u{202e}.exe".into()));
        assert_eq!(
            temporary_rule_line(&rule),
            "direct: process path C:\\apps\\foo .exe"
        );
        rule.matcher = RuleMatcher::IpCidr("192.0.2.0/24".into());
        rule.target = RuleTarget::Block;
        assert_eq!(temporary_rule_line(&rule), "block: ip 192.0.2.0/24");
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
    fn apply_rejects_more_than_one_path() {
        for arguments in [
            vec!["apply", "a", "b"],
            vec!["apply", "request.json", "extra", "another"],
        ] {
            assert_eq!(
                parse(&arguments),
                Err("apply accepts zero or one request JSON path".to_owned())
            );
        }
    }

    #[test]
    fn probe_rejects_multiple_paths_and_delay_rejects_arguments() {
        assert_eq!(
            parse(&["probe", "a", "b"]),
            Err("probe accepts zero or one request JSON path".to_owned())
        );
        assert_eq!(
            parse(&["delay", "extra"]),
            Err("delay does not accept arguments".to_owned())
        );
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
        for command in ["status", "temporary", "config", "disconnect", "shutdown"] {
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
