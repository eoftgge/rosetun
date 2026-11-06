mod connections;
mod exits;
mod subcommands;
mod subscriptions;

use std::path::Path;
use std::process::ExitCode;

use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::prelude::*;

use rosetun_config::{
    ConnectionMode, ConnectionState, DomainMatch, FailureKind, InstalledProtection, NodeId,
    ProcessMatch, ProtectionCapabilities, ProtectionState, RequestedProtection, Rule, RuleMatcher,
    RuleTarget, Status, SubscriptionId, XrayUse,
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
    Exits,
    Connections,
    CloseConnection {
        id: String,
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
    Xray(XrayUse),
    Lan(bool),
    Lockdown(bool),
    /// Lockdown on with this LAN access instead of the saved one: the GUI
    /// runs the command elevated, possibly as another account with other
    /// settings.
    LockdownWithLan {
        allow_lan: bool,
        private_networks: bool,
    },
    ResetFirewall,
    OpenNetwork,
    Disconnect,
    Reconnect,
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
        Command::Sub(command) => {
            if command.uses_network() {
                follow_service_status();
            }
            local_result(subscriptions::run(command))
        }
        Command::Nodes { subscription_id } => {
            local_result(subscriptions::nodes(subscription_id.as_deref()))
        }
        Command::Config => local_result(print_config()),
        Command::Xray(setting) => local_result(set_xray(setting)),
        Command::Lan(enabled) => match set_lan(enabled).and_then(|()| saved_lan()) {
            Ok((_, private_networks)) => update_lockdown_lan(enabled, private_networks),
            Err(message) => local_result(Err(message)),
        },
        Command::Lockdown(enabled) => match saved_lan() {
            Ok((allow_lan, private_networks)) => {
                with_helper(|client| lockdown(client, enabled, allow_lan, private_networks))
            }
            Err(message) => local_result(Err(message)),
        },
        Command::LockdownWithLan {
            allow_lan,
            private_networks,
        } => with_helper(|client| lockdown(client, true, allow_lan, private_networks)),
        Command::ResetFirewall => reset_firewall(),
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
        Command::Exits => local_result(exits::run()),
        Command::Connections => with_helper(connections::run),
        Command::CloseConnection { id } => with_helper(|client| connections::close(client, &id)),
        Command::Status => with_helper(status),
        Command::Temporary => with_helper(temporary),
        Command::OpenNetwork => with_helper(open_network),
        Command::Disconnect => with_helper(disconnect),
        Command::Reconnect => with_helper(reconnect),
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
            "the tunnel is connected from another account; only that account or an administrator can control it",
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
        PreparedCliRequest::Lists(mut prepared) => {
            let (limited, warning) = limit_to_protection(prepared.request, client.protection());
            prepared.request = limited;
            if let Some(warning) = warning {
                eprintln!("{warning}");
            }
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

const KILL_SWITCH_LEFT_OUT: &str =
    "warning: the kill switch is not available on this system and is left off";

const LOCKDOWN_UNAVAILABLE: &str = "Lockdown is not available on this system";

/// Why a Lockdown change is not even sent: the helper has no Lockdown.
fn lockdown_refusal(protection: ProtectionCapabilities) -> Option<&'static str> {
    (!protection.lockdown).then_some(LOCKDOWN_UNAVAILABLE)
}

/// A request built from the saved configuration, as the helper can serve it,
/// and the warning to print when the saved kill switch is left out. The
/// setting itself is not changed. A request file given by the user is sent
/// as written and the helper refuses what it cannot give.
fn limit_to_protection(
    request: ConnectRequest,
    protection: ProtectionCapabilities,
) -> (ConnectRequest, Option<&'static str>) {
    let saved = request.settings.kill_switch;
    let request = request.limited_to(protection);
    let warning = (saved && !request.settings.kill_switch).then_some(KILL_SWITCH_LEFT_OUT);
    (request, warning)
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
    match client.tunnel_delay() {
        Ok(delays) => {
            match delays.proxy {
                ProbeOutcome::Works { millis } => println!("works {millis} ms"),
                _ => println!("fails"),
            }
            if !delays.exits.is_empty() {
                let config = rosetun_core::Store::open_default()
                    .ok()
                    .and_then(|store| store.load().ok());
                for line in exits::delay_lines(config.as_ref(), &delays.exits) {
                    println!("{line}");
                }
            }
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

/// What protects the computer now, for `rosetun status`.
fn protection_lines(protection: &ProtectionState) -> Vec<String> {
    let installed = match protection.installed {
        InstalledProtection::None => "none",
        InstalledProtection::DnsLock => "DNS lock",
        InstalledProtection::SharedProxyPort => "shared proxy port limited to local networks",
        InstalledProtection::KillSwitch => "kill switch",
        InstalledProtection::Lockdown => "Lockdown",
        InstalledProtection::HoldAfterUpgrade => "network held closed after an upgrade",
        InstalledProtection::HoldAfterCrash => "network held closed after a service crash",
    };
    let mut lines = vec![format!("protection: {installed}")];
    if let Some(unmet) = protection.unmet() {
        let requested = match protection.requested {
            RequestedProtection::KillSwitch => "kill switch",
            RequestedProtection::DnsLock | RequestedProtection::None => "DNS lock",
        };
        lines.push(format!("protection missing: {requested}: {}", unmet.reason));
    }
    if protection.connection_mode == Some(ConnectionMode::SystemProxy) {
        lines.push(
            "connection mode: system proxy (programs that ignore it are not in the tunnel)"
                .to_owned(),
        );
    }
    if protection.installed != InstalledProtection::None {
        lines.push(format!(
            "if the service crashes: {}",
            if protection.survives_service_crash {
                "this stays in place"
            } else {
                "this goes with it"
            }
        ));
    }
    lines
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
            println!("lockdown: {}", if status.lockdown { "on" } else { "off" });
            for line in protection_lines(&status.protection) {
                println!("{line}");
            }
            if status.upgrade_hold {
                println!("network: held closed (rosetun open-network opens it)");
            }
            println!(
                "node: {}",
                terminal_text(status.node.as_ref().map_or("none", NodeId::as_str))
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
            Ok("unavailable for another account".to_owned())
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

fn reconnect(client: &mut HelperClient) -> ExitCode {
    match client.reconnect_tunnel() {
        Ok(()) => {
            println!("tunnel reconnected");
            ExitCode::SUCCESS
        }
        Err(error) => {
            report_helper_error(&error, "failed to reconnect tunnel");
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
            report_helper_error(&error, "failed to disconnect tunnel");
            ExitCode::FAILURE
        }
    }
}

/// Lifts the hold an upgrade (Windows) or a crash of the service (Linux)
/// left; nothing to do is a success too.
fn open_network(client: &mut HelperClient) -> ExitCode {
    match client.open_network() {
        Ok(()) => {
            println!("network open");
            ExitCode::SUCCESS
        }
        Err(error) => {
            report_helper_error(&error, "failed to open the network");
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
    let helper_error = |error: ClientError| {
        access_denied_message(&error).map_or_else(|| error.to_string(), str::to_owned)
    };
    let temporary = client.temporary_rules().map_err(helper_error)?;
    let session = client.session_exits().map_err(helper_error)?;
    let store = rosetun_core::Store::open_default().map_err(|error| error.to_string())?;
    let config = store.load().map_err(|error| error.to_string())?;
    let request =
        apply_request(&config, temporary, exits::pinned(session)).map_err(connect_request_error)?;
    rosetun_core::prepare_lists(&store, request)
        .map(PreparedCliRequest::Lists)
        .map_err(|error| error.to_string())
}

/// Like the GUI, `apply` keeps each exit on the node the session already uses.
fn apply_request(
    config: &rosetun_config::AppConfig,
    temporary: Vec<Rule>,
    pinned: Vec<(rosetun_config::ExitId, rosetun_config::Selection)>,
) -> Result<ConnectRequest, rosetun_ipc::ConnectRequestError> {
    ConnectRequest::for_apply_with_exits(
        config,
        None,
        temporary,
        rosetun_ipc::ExitContext {
            delays: &[],
            selected: &pinned,
        },
    )
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

/// The saved "Local network" and "Private networks behind the router".
fn saved_lan() -> Result<(bool, bool), String> {
    let store = rosetun_core::Store::open_default().map_err(|error| error.to_string())?;
    let config = store.load().map_err(|error| error.to_string())?;
    Ok((config.settings.allow_lan, config.settings.private_networks))
}

fn lockdown(
    client: &mut HelperClient,
    enabled: bool,
    allow_lan: bool,
    private_networks: bool,
) -> ExitCode {
    if let Some(message) = lockdown_refusal(client.protection()) {
        eprintln!("{message}");
        return ExitCode::FAILURE;
    }
    match client.set_lockdown(enabled, allow_lan, private_networks) {
        Ok(()) => {
            println!("lockdown {}", if enabled { "on" } else { "off" });
            ExitCode::SUCCESS
        }
        Err(error) if lockdown_denied(&error) => {
            eprintln!("{LOCKDOWN_DENIED}");
            ExitCode::FAILURE
        }
        Err(error) => {
            tracing::error!(%error, "failed to change Lockdown");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
const LOCKDOWN_DENIED: &str = "only an administrator can change Lockdown; run this command in a terminal opened as administrator";
#[cfg(target_os = "linux")]
const LOCKDOWN_DENIED: &str =
    "only root can change Lockdown; run it with sudo, as `sudo rosetun lockdown on`";

/// The service refuses a Lockdown change from anyone but an administrator.
fn lockdown_denied(error: &ClientError) -> bool {
    matches!(error, ClientError::Helper(helper) if helper.code == ErrorCode::AccessDenied)
}

/// Lockdown keeps its own LAN permits; they follow the setting at once when
/// an administrator runs the command. Otherwise the setting is saved and
/// Lockdown keeps its permits. Without a running service there is nothing
/// to update: the next connect by an administrator brings Lockdown in line.
fn update_lockdown_lan(enabled: bool, private_networks: bool) -> ExitCode {
    let endpoint = rosetun_ipc::default_endpoint();
    let client_name = concat!("rosetun/", env!("CARGO_PKG_VERSION"));
    let Ok(mut client) = HelperClient::connect(&endpoint, client_name) else {
        return ExitCode::SUCCESS;
    };
    match client.status() {
        Ok(status) if status.lockdown => match client.set_lockdown(true, enabled, private_networks)
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) if lockdown_denied(&error) => {
                eprintln!("{LAN_KEPT_BY_LOCKDOWN}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                tracing::error!(%error, "failed to change Lockdown");
                ExitCode::FAILURE
            }
        },
        _ => ExitCode::SUCCESS,
    }
}

#[cfg(not(target_os = "linux"))]
const LAN_KEPT_BY_LOCKDOWN: &str = "the setting is saved, but Lockdown keeps its local network access; run `rosetun lockdown on` in a terminal opened as administrator to apply it";
#[cfg(target_os = "linux")]
const LAN_KEPT_BY_LOCKDOWN: &str = "the setting is saved, but Lockdown keeps its local network access; run `sudo rosetun lockdown on` to apply it";

/// Under Lockdown the CLI resolves names itself (`rosetun_core::follow_service_status`).
/// On Linux it also runs again in its own scope, which Lockdown permits
/// while no session runs, and connects again from there: the service
/// looks for the scope when a client says hello.
fn follow_service_status() {
    let endpoint = rosetun_ipc::default_endpoint();
    let client_name = concat!("rosetun/", env!("CARGO_PKG_VERSION"));
    let status = HelperClient::connect(&endpoint, client_name)
        .and_then(|mut client| client.status())
        .ok();
    #[cfg(target_os = "linux")]
    let status = match status {
        Some(found)
            if found.lockdown && found.state != rosetun_config::ConnectionState::Connected =>
        {
            if let rosetun_core::Scope::Outside(reason) =
                rosetun_core::enter_scope(rosetun_core::ScopeProgram::Cli)
            {
                eprintln!(
                    "warning: under Lockdown this command has no network without a connection: {reason}"
                );
            }
            HelperClient::connect(&endpoint, client_name)
                .and_then(|mut client| client.status())
                .ok()
        }
        other => other,
    };
    rosetun_core::follow_service_status(status.as_ref());
}

#[cfg(not(target_os = "linux"))]
const RESET_AS_ADMINISTRATOR: &str =
    "run `rosetun reset-firewall` from a terminal opened as administrator";
#[cfg(target_os = "linux")]
const RESET_AS_ADMINISTRATOR: &str = "run it as root: `sudo rosetun reset-firewall`";

#[cfg(not(target_os = "linux"))]
const LOCKDOWN_HELP: &str = "Only an administrator changes it.
reset-firewall removes it without the service; run it as administrator.";
#[cfg(target_os = "linux")]
const LOCKDOWN_HELP: &str = "Only root changes it (sudo rosetun lockdown on|off);
the desktop asks for an administrator password through polkit.
reset-firewall removes it without the service, also for the next boot:
sudo rosetun reset-firewall.";

/// `rosetun-helper-privileged --reset-firewall` from this program's folder.
fn reset_firewall() -> ExitCode {
    let helper = match std::env::current_exe() {
        Ok(exe) => exe.with_file_name(format!(
            "rosetun-helper-privileged{}",
            std::env::consts::EXE_SUFFIX
        )),
        Err(error) => {
            eprintln!("cannot find the Rosetun folder: {error}");
            return ExitCode::FAILURE;
        }
    };
    match std::process::Command::new(&helper)
        .arg("--reset-firewall")
        .status()
    {
        Ok(status) => match status.code() {
            Some(0) => ExitCode::SUCCESS,
            // The helper's `reset_exit::NOT_ADMINISTRATOR` (`NOT_ROOT` on Linux).
            Some(3) => {
                eprintln!("{RESET_AS_ADMINISTRATOR}");
                ExitCode::from(3)
            }
            Some(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
            None => ExitCode::FAILURE,
        },
        Err(error) => {
            eprintln!("cannot run {}: {error}", helper.display());
            ExitCode::FAILURE
        }
    }
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
        ["exits"] => Ok(Command::Exits),
        ["connections"] => Ok(Command::Connections),
        ["connections", "close", id] => Ok(Command::CloseConnection {
            id: (*id).to_owned(),
        }),
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
        ["lockdown", "on"] => Ok(Command::Lockdown(true)),
        ["lockdown", "off"] => Ok(Command::Lockdown(false)),
        ["lockdown", "on", "--lan", value] => {
            let (allow_lan, private_networks) = match *value {
                "off" => (false, false),
                "on" => (true, false),
                "private" => (true, true),
                _ => return Err("--lan takes on, off or private".to_owned()),
            };
            Ok(Command::LockdownWithLan {
                allow_lan,
                private_networks,
            })
        }
        ["reset-firewall"] => Ok(Command::ResetFirewall),
        ["open-network"] => Ok(Command::OpenNetwork),
        ["disconnect"] => Ok(Command::Disconnect),
        ["reconnect"] => Ok(Command::Reconnect),
        ["shutdown"] => Ok(Command::Shutdown),
        ["connect", ..] => Err("connect accepts zero or one request JSON path".to_owned()),
        ["apply", ..] => Err("apply accepts zero or one request JSON path".to_owned()),
        ["probe", ..] => Err("probe accepts zero or one request JSON path".to_owned()),
        ["delay", ..] => Err("delay does not accept arguments".to_owned()),
        ["exits", ..] => Err("exits does not accept arguments".to_owned()),
        ["connections", "close", ..] => {
            Err("connections close requires exactly one connection ID".to_owned())
        }
        ["connections", ..] => Err("connections accepts only close <id>".to_owned()),
        ["select", ..] => Err("select requires exactly a subscription ID and a node ID".to_owned()),
        ["config", ..] => Err("config does not accept arguments".to_owned()),
        ["xray", ..] => Err("xray requires auto, off or always".to_owned()),
        ["lan", ..] => Err("lan requires on or off".to_owned()),
        ["lockdown", ..] => Err("lockdown requires on or off".to_owned()),
        ["reset-firewall", ..] => Err("reset-firewall does not accept arguments".to_owned()),
        ["status", ..] => Err("status does not accept arguments".to_owned()),
        ["temporary", ..] => Err("temporary does not accept arguments".to_owned()),
        ["open-network", ..] => Err("open-network does not accept arguments".to_owned()),
        ["disconnect", ..] => Err("disconnect does not accept arguments".to_owned()),
        ["reconnect", ..] => Err("reconnect does not accept arguments".to_owned()),
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
  rosetun exits
  rosetun connections
  rosetun connections close <id>
  rosetun select <subscription-id> <node-id>
  rosetun sub add <url> [--name <name>] [--user-agent <ua>] [--no-hwid]
  rosetun sub update [<id>]
  rosetun sub list
  rosetun sub remove <id>
  rosetun nodes [<sub-id>]
  rosetun config
  rosetun xray <auto|off|always>
  rosetun lan <on|off>
  rosetun lockdown <on|off>    (experimental)
  rosetun lockdown on --lan <on|off|private>
  rosetun reset-firewall
  rosetun open-network
  rosetun disconnect
  rosetun reconnect
  rosetun shutdown

Subscription and node commands are local and do not require the helper.
connections lists the tunnel's connections for the account that connected it;
close ends one of them by its ID (the 8 characters shown, or the full ID).
Lockdown (experimental) blocks all traffic outside the tunnel, also when
disconnected and after a reboot. {LOCKDOWN_HELP}
open-network lifts the hold that keeps the network closed after an update
(Windows) or after the service failed (Linux).
Options for sub add may appear in any order after the URL."
    );
}

#[cfg(test)]
mod tests {
    use super::{
        Command, LAN_KEPT_BY_LOCKDOWN, LOCKDOWN_DENIED, access_denied_message, apply_error_message,
        lockdown_denied, parse_command_arguments, protection_lines, status_has_no_network,
        temporary_rule_line, temporary_rules_status,
    };
    use rosetun_config::{
        ConnectionMode, ConnectionState, DomainMatch, FailureKind, InstalledProtection,
        ProcessMatch, ProtectionShortfallCode, ProtectionState, RequestedProtection, Rule, RuleId,
        RuleMatcher, RuleTarget, Status, XrayUse,
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
    fn status_names_the_missing_protection_only_while_it_is_missing() {
        let missing = ProtectionState {
            requested: RequestedProtection::DnsLock,
            shortfall: Some(ProtectionShortfallCode::FirewallRefused.into()),
            ..ProtectionState::default()
        };
        assert_eq!(
            protection_lines(&missing),
            [
                "protection: none",
                "protection missing: DNS lock: the firewall refused the rules"
            ]
        );
        let kill_switch = ProtectionState {
            installed: InstalledProtection::KillSwitch,
            requested: RequestedProtection::DnsLock,
            shortfall: Some(ProtectionShortfallCode::FirewallRefused.into()),
            survives_service_crash: false,
            ..ProtectionState::default()
        };
        assert_eq!(
            protection_lines(&kill_switch),
            [
                "protection: kill switch",
                "if the service crashes: this goes with it"
            ]
        );
    }

    #[test]
    fn status_says_the_proxy_mode_leaves_programs_out() {
        let lines = protection_lines(&ProtectionState {
            connection_mode: Some(ConnectionMode::SystemProxy),
            ..ProtectionState::default()
        });
        assert!(lines.iter().any(|line| line.contains("system proxy")));
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
        assert_eq!(parse(&["lockdown", "on"]), Ok(Command::Lockdown(true)));
        assert_eq!(parse(&["lockdown", "off"]), Ok(Command::Lockdown(false)));
        assert_eq!(
            parse(&["lockdown", "on", "--lan", "off"]),
            Ok(Command::LockdownWithLan {
                allow_lan: false,
                private_networks: false
            })
        );
        assert_eq!(
            parse(&["lockdown", "on", "--lan", "on"]),
            Ok(Command::LockdownWithLan {
                allow_lan: true,
                private_networks: false
            })
        );
        assert_eq!(
            parse(&["lockdown", "on", "--lan", "private"]),
            Ok(Command::LockdownWithLan {
                allow_lan: true,
                private_networks: true
            })
        );
        assert!(parse(&["lockdown", "off", "--lan", "on"]).is_err());
        assert!(parse(&["lockdown"]).is_err());
        assert!(parse(&["lockdown", "on", "now"]).is_err());
        assert_eq!(parse(&["reset-firewall"]), Ok(Command::ResetFirewall));
        assert!(parse(&["reset-firewall", "now"]).is_err());
        assert_eq!(parse(&["disconnect"]), Ok(Command::Disconnect));
        assert_eq!(parse(&["reconnect"]), Ok(Command::Reconnect));
        assert_eq!(parse(&["open-network"]), Ok(Command::OpenNetwork));
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
            "the tunnel belongs to another account",
        ));
        let message = "the tunnel is connected from another account; only that account or an administrator can control it";
        assert_eq!(access_denied_message(&denied), Some(message));
        assert_eq!(apply_error_message(&denied), Some(message));
        assert_eq!(access_denied_message(&ClientError::Closed), None);
    }

    #[test]
    fn a_refused_lockdown_change_asks_for_an_administrator_terminal() {
        let denied = ClientError::Helper(HelperError::new(
            ErrorCode::AccessDenied,
            "only an administrator can change Lockdown",
        ));
        assert!(lockdown_denied(&denied));
        assert!(!lockdown_denied(&ClientError::Closed));
        assert!(!lockdown_denied(&ClientError::Helper(HelperError::new(
            ErrorCode::Busy,
            "a server check is in progress",
        ))));
        #[cfg(not(target_os = "linux"))]
        assert!(LOCKDOWN_DENIED.contains("administrator"));
        #[cfg(target_os = "linux")]
        assert!(LOCKDOWN_DENIED.contains("sudo rosetun lockdown on"));
        assert!(LAN_KEPT_BY_LOCKDOWN.contains("rosetun lockdown on"));
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
                "another account",
            ))))
            .unwrap(),
            "unavailable for another account"
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
    fn exits_takes_no_arguments() {
        assert_eq!(parse(&["exits"]), Ok(Command::Exits));
        assert_eq!(parse(&["connections"]), Ok(Command::Connections));
        assert!(parse(&["connections", "extra"]).is_err());
        assert_eq!(
            parse(&["connections", "close", "0d5c1f2e"]),
            Ok(Command::CloseConnection {
                id: "0d5c1f2e".to_owned()
            })
        );
        assert!(parse(&["connections", "close"]).is_err());
        assert!(parse(&["connections", "close", "a", "b"]).is_err());
        assert_eq!(
            parse(&["exits", "extra"]),
            Err("exits does not accept arguments".to_owned())
        );
    }

    #[test]
    fn apply_keeps_the_exit_node_the_service_reports() {
        use crate::exits::tests::{config, selection};
        use rosetun_config::ExitId;
        use rosetun_ipc::SessionExit;

        let config = config();
        let unpinned = super::apply_request(&config, Vec::new(), Vec::new()).unwrap();
        assert_eq!(unpinned.extra_nodes[0].selection, selection("nl-1"));
        let pinned = crate::exits::pinned(vec![SessionExit {
            exit: ExitId::new("nl"),
            selection: selection("nl-2"),
        }]);
        let request = super::apply_request(&config, Vec::new(), pinned).unwrap();
        assert_eq!(request.extra_nodes.len(), 1);
        assert_eq!(request.extra_nodes[0].selection, selection("nl-2"));
    }

    #[test]
    fn a_saved_kill_switch_is_left_out_with_one_warning_where_the_helper_has_none() {
        use rosetun_config::ProtectionCapabilities;

        let full = ProtectionCapabilities {
            kill_switch: true,
            lockdown: true,
        };
        let mut config = crate::exits::tests::config();
        config.settings.kill_switch = true;
        let request = super::apply_request(&config, Vec::new(), Vec::new()).unwrap();

        let (kept, warning) = super::limit_to_protection(request.clone(), full);
        assert_eq!(kept, request);
        assert_eq!(warning, None);

        let (left, warning) =
            super::limit_to_protection(request.clone(), ProtectionCapabilities::default());
        assert!(!left.settings.kill_switch);
        assert_eq!(
            warning,
            Some("warning: the kill switch is not available on this system and is left off")
        );
        assert!(config.settings.kill_switch, "the saved setting is kept");

        config.settings.kill_switch = false;
        let request = super::apply_request(&config, Vec::new(), Vec::new()).unwrap();
        let (left, warning) =
            super::limit_to_protection(request, ProtectionCapabilities::default());
        assert!(!left.settings.kill_switch);
        assert_eq!(
            warning, None,
            "nothing was asked for, so nothing is left out"
        );
    }

    #[test]
    fn lockdown_is_refused_before_the_helper_is_asked_where_there_is_none() {
        use rosetun_config::ProtectionCapabilities;

        assert_eq!(
            super::lockdown_refusal(ProtectionCapabilities {
                kill_switch: true,
                lockdown: false,
            }),
            Some("Lockdown is not available on this system")
        );
        assert_eq!(
            super::lockdown_refusal(ProtectionCapabilities {
                kill_switch: true,
                lockdown: true,
            }),
            None
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
        for command in [
            "status",
            "temporary",
            "config",
            "open-network",
            "disconnect",
            "reconnect",
            "shutdown",
        ] {
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
