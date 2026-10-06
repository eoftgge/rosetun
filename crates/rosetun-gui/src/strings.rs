pub(crate) const TITLE: &str = "Rosetun";
pub(crate) const BRAND: &str = "ROSETUN";
pub(crate) const TAGLINE: &str = "Tunnel in bloom";
pub(crate) const CONNECTION: &str = "Connection";
pub(crate) const RULES: &str = "Rules";
pub(crate) const SETTINGS: &str = "Settings";
pub(crate) const MINIMIZE: &str = "Minimize";
pub(crate) const MAXIMIZE: &str = "Maximize";
pub(crate) const RESTORE: &str = "Restore";
pub(crate) const CLOSE_WINDOW: &str = "Close";
pub(crate) const INTERFACE: &str = "Interface";
pub(crate) const SCALE: &str = "Scale";
pub(crate) const ZOOM_HINT: &str = "Ctrl+Plus and Ctrl+Minus zoom until the app closes.";
#[cfg(windows)]
pub(crate) const WINDOWS: &str = "Windows";
#[cfg(windows)]
pub(crate) const START_WITH_WINDOWS: &str = "Start with Windows";
#[cfg(windows)]
pub(crate) const START_WITH_WINDOWS_DETAIL: &str = "Opens in the tray when you sign in.";
#[cfg(windows)]
pub(crate) const KEEP_IN_TRAY: &str = "Keep running in the tray";
#[cfg(windows)]
pub(crate) const KEEP_IN_TRAY_DETAIL: &str =
    "The close button hides the window. Quit from the tray menu.";
pub(crate) const DNS_THROUGH_TUNNEL: &str = "DNS through the tunnel";
pub(crate) const DNS_EXPLANATION: &str = "Name lookups go to this DNS-over-HTTPS resolver through the server. It must be reachable from the server's exit.";
pub(crate) const RESOLVER_IP: &str = "Resolver IP";
pub(crate) const TLS_NAME: &str = "TLS name";
pub(crate) const PORT: &str = "Port";
pub(crate) const PORT_PLACEHOLDER: &str = "443";
pub(crate) const DNS_PATH: &str = "Path";
pub(crate) const DNS_PATH_PLACEHOLDER: &str = "/dns-query";
pub(crate) const SAVE: &str = "Save";
pub(crate) const RESET_TO_DEFAULT: &str = "Reset to default";
pub(crate) const ENGINE_LOG: &str = "Engine log";
pub(crate) const ENGINE_LOG_DETAIL: &str =
    "Detail of the sing-box log the helper writes. Applies on next connect.";
pub(crate) const LOG_ERROR: &str = "Error";
pub(crate) const LOG_WARN: &str = "Warn";
pub(crate) const LOG_INFO: &str = "Info";
pub(crate) const LOG_DEBUG: &str = "Debug";
pub(crate) const LOG_TRACE: &str = "Trace";
pub(crate) const ABOUT: &str = "About";
pub(crate) const HELPER_NOT_RUNNING: &str = "Helper not running";
pub(crate) const CONFIGURATION_FOLDER: &str = "Configuration folder";
pub(crate) const LOG_FILE: &str = "Log file";
pub(crate) const LOG_FILE_NAME: &str = "rosetun-gui.log";
#[cfg(windows)]
pub(crate) const TRAY_OPEN: &str = "Open Rosetun";
#[cfg(windows)]
pub(crate) const TRAY_QUIT: &str = "Quit Rosetun";
pub(crate) const OPEN_FOLDER: &str = "Open folder";
pub(crate) const CONNECT: &str = "Connect";
pub(crate) const DISCONNECT: &str = "Disconnect";
pub(crate) const RETRY: &str = "Retry";
pub(crate) const RECONNECT: &str = "Reconnect";
pub(crate) const CONNECTING_ACTION: &str = "Connecting…";
pub(crate) const RECONNECTING_ACTION: &str = "Reconnecting…";
pub(crate) const WORKING: &str = "Working…";
pub(crate) const LOADING: &str = "Loading configuration…";
pub(crate) const ERROR_MARK: &str = "!";
pub(crate) const ENGINE: &str = "Engine";
pub(crate) const ACTIVE_SERVER: &str = "Active tunnel server";
pub(crate) const UNKNOWN_SERVER: &str = "Server no longer in configuration";
pub(crate) const NO_SESSION: &str = "—";
pub(crate) const STATUS_UNKNOWN: &str = "Status unknown";
pub(crate) const DISCONNECTED: &str = "Disconnected";
pub(crate) const CONNECTING: &str = "Connecting";
pub(crate) const CONNECTED: &str = "Connected";
pub(crate) const RECONNECTING: &str = "Reconnecting";
pub(crate) const FAILED: &str = "Connection failed";
pub(crate) const FAILED_PROTECTED: &str = "Connection failed · traffic blocked";
pub(crate) const HELPER_UNAVAILABLE: &str = "Helper unavailable";
pub(crate) const HELPER_UNAVAILABLE_DETAIL: &str =
    "Start the Rosetun helper externally. Subscriptions are still available.";
pub(crate) const SELECT_SERVER: &str = "Select a server first";
pub(crate) const SELECTED_SERVER: &str = "Selected server";
pub(crate) const SESSION: &str = "Session";
pub(crate) const KILL_SWITCH: &str = "Kill switch";
pub(crate) const PROTECTION: &str = "Protection";
pub(crate) const KILL_SWITCH_DETAIL: &str = "Blocks all internet traffic if the tunnel drops.";
pub(crate) const RULE_SET: &str = "Rule set";
pub(crate) const DEFAULT_RULES: &str = "Default · proxy all";
pub(crate) const NEXT_CONNECT: &str = "Applies on next connect";
pub(crate) const TURN_OFF_PROTECTION: &str = "Turn off protection";
pub(crate) const KEEP_BLOCKED: &str = "Keep blocked";
pub(crate) const PROTECTION_WARNING: &str = "Turning off protection will allow traffic outside the tunnel and may expose your real IP address.";
pub(crate) const ADD_SUBSCRIPTION: &str = "Add subscription";
pub(crate) const ADD_SUBTITLE: &str = "Servers will be imported automatically";
pub(crate) const SUBSCRIPTION_URL: &str = "Subscription URL";
pub(crate) const URL_PLACEHOLDER: &str = "https://provider.example/subscription";
pub(crate) const PASTE: &str = "Paste";
pub(crate) const NAME: &str = "Name (optional)";
pub(crate) const NAME_PLACEHOLDER: &str = "Provider name";
pub(crate) const SEND_DEVICE_ID: &str = "Send device ID";
pub(crate) const DEVICE_ID_EXPLANATION: &str = "Some providers require a device ID to enforce device limits. Disable it only if your provider does not need it.";
pub(crate) const URL_HELP: &str = "HTTP(S) subscription URLs and supported app import links";
pub(crate) const HTTP_WARNING: &str =
    "This subscription uses HTTP; its token is transmitted without encryption.";
pub(crate) const ADD: &str = "Add";
pub(crate) const ADDING: &str = "Adding…";
pub(crate) const CANCEL: &str = "Cancel";
pub(crate) const REMOVE: &str = "Remove";
pub(crate) const REMOVING: &str = "Removing…";
pub(crate) const REMOVE_SUBSCRIPTION: &str = "Remove subscription?";
pub(crate) const REMOVE_DETAIL: &str = "The subscription and its servers will be removed.";
pub(crate) const REMOVE_SELECTED_WARNING: &str = "This subscription contains the selected server. Its selection will be cleared; an existing tunnel will not be disconnected.";
pub(crate) const UPDATE: &str = "Update";
pub(crate) const UPDATE_ALL: &str = "Update all";
pub(crate) const UPDATING: &str = "Updating…";
pub(crate) const SUBSCRIPTION_REORDER_DISABLED: &str = "Wait for the current update to finish.";
pub(crate) const NEVER_UPDATED: &str = "Not updated yet";
pub(crate) const NO_SUBSCRIPTIONS: &str = "No subscriptions yet";
pub(crate) const EMPTY_SUBSCRIPTIONS: &str =
    "Add a subscription to import servers and get connected.";
pub(crate) const NO_SERVERS: &str = "No servers available";
pub(crate) const SUPPORT: &str = "Support";
pub(crate) const WEBSITE: &str = "Website";
pub(crate) const SELECTION_CLEARED: &str = "Selected server removed · choose another server";
pub(crate) const DISMISS: &str = "Dismiss";
pub(crate) const EXPAND: &str = "+";
pub(crate) const COLLAPSE: &str = "−";
pub(crate) const RULES_TITLE: &str = "Routing rules";
pub(crate) const RULES_SUBTITLE: &str =
    "Independent of subscriptions — the active set applies to every server.";
pub(crate) const OPEN_RULES: &str = "Open rules";
pub(crate) const ACTIVE: &str = "Active";
pub(crate) const USE_FOR_CONNECTIONS: &str = "Use for connections";
pub(crate) const NEW_SET: &str = "New set";
pub(crate) const CREATE_RULE_SET: &str = "Create rule set";
pub(crate) const RENAME: &str = "Rename";
pub(crate) const DELETE: &str = "Delete";
pub(crate) const BASIC: &str = "Basic";
pub(crate) const SET_NAME: &str = "Set name";
pub(crate) const RENAME_RULE_SET: &str = "Rename rule set";
pub(crate) const DELETE_RULE_SET: &str = "Delete rule set?";
pub(crate) const DELETE_RULE_SET_DETAIL: &str = "This set and all its rules will be removed.";
pub(crate) const DELETE_ACTIVE_RULE_SET_WARNING: &str = "Connections will use Default · proxy all.";
pub(crate) const DELETE_RULE: &str = "Delete rule?";
pub(crate) const DELETE_RULE_DETAIL: &str = "This rule will be removed from the set.";
pub(crate) const SEARCH_RULES: &str = "Search rules";
pub(crate) const ALL: &str = "All";
pub(crate) const DOMAINS: &str = "Domains";
pub(crate) const PROCESSES: &str = "Processes";
pub(crate) const OTHER: &str = "Other";
pub(crate) const PROXY: &str = "Proxy";
pub(crate) const DIRECT: &str = "Direct";
pub(crate) const BLOCK: &str = "Block";
pub(crate) const DOMAIN: &str = "Domain";
pub(crate) const PROCESS: &str = "Process";
pub(crate) const KEYWORD: &str = "Keyword";
pub(crate) const IP: &str = "IP";
pub(crate) const TYPE: &str = "Type";
pub(crate) const VALUE: &str = "Value";
pub(crate) const TARGET: &str = "Target";
pub(crate) const ENABLED: &str = "Enabled";
pub(crate) const ORDER_HINT: &str = "Order from top to bottom sets priority.";
pub(crate) const REMOVE_RULE: &str = "×";
pub(crate) const REORDER_DISABLED: &str = "Clear the search and filters to reorder.";
pub(crate) const DEFAULT: &str = "Default";
pub(crate) const ALL_OTHER_TRAFFIC: &str = "All other traffic";
pub(crate) const DEFAULT_FALLBACK: &str = "Used when no rule above matches";
pub(crate) const DEFAULT_RULE_TOOLTIP: &str = "The default rule cannot be moved or removed.";
pub(crate) const NO_RULE_SETS: &str = "No rule sets yet. Connections use Default · proxy all.";
pub(crate) const NO_RULES_MATCH: &str = "No rules match the filter.";
pub(crate) const RULES_NEXT_CONNECT: &str = "Changes apply on next connect.";
pub(crate) const NEW_RULE_BUTTON: &str = "+ Rule";
pub(crate) const NEW_RULE: &str = "New rule";
pub(crate) const NEW_RULE_SUBTITLE: &str = "Applies to all subscriptions.";
pub(crate) const DOMAIN_INPUT: &str = "Domain or pattern";
pub(crate) const DOMAIN_PLACEHOLDER: &str = "example.com or *.example.com";
pub(crate) const DOMAIN_HELP: &str =
    "example.com — only this domain · *.example.com — the domain and its subdomains";
pub(crate) const PROCESS_INPUT: &str = "Process name or full path to .exe";
#[cfg(windows)]
pub(crate) const BROWSE: &str = "Browse…";
#[cfg(windows)]
pub(crate) const CHOOSE_PROGRAM: &str = "Choose a program";
#[cfg(windows)]
pub(crate) const PROGRAMS: &str = "Programs";
pub(crate) const PROCESS_PLACEHOLDER: &str = "app.exe or C:\\Apps\\app.exe";
pub(crate) const PROCESS_FILTER: &str = "Filter by name or path";
pub(crate) const REFRESH: &str = "Refresh";
pub(crate) const LOADING_PROCESSES: &str = "Loading processes…";
pub(crate) const NO_RUNNING_PROCESSES: &str = "No running processes found.";
pub(crate) const NO_PROCESSES_MATCH: &str = "No processes match the filter.";
pub(crate) const PATH_UNAVAILABLE: &str = "path unavailable";
pub(crate) const MATCH_BY_NAME: &str = "Match by name";
pub(crate) const MATCH_BY_FULL_PATH: &str = "Match by full path";
pub(crate) const RULE_PRIORITY: &str = "New rule goes to the top of the list — highest priority.";
pub(crate) const ADD_RULE: &str = "Add rule";
pub(crate) const ADDING_RULE: &str = "Adding rule…";

#[cfg(windows)]
pub(crate) fn tray_tooltip(status: &str, server: Option<&str>) -> String {
    match server {
        Some(server) => format!("{TITLE} · {status}\n{server}"),
        None => format!("{TITLE} · {status}"),
    }
}

pub(crate) fn app_version() -> String {
    format!("Rosetun {}", env!("CARGO_PKG_VERSION"))
}

pub(crate) fn scale(percent: u16) -> String {
    format!("{percent}%")
}

pub(crate) fn running_processes(count: usize) -> String {
    format!("Running processes · {count}")
}

pub(crate) fn process_copies(name: &str, count: usize) -> String {
    format!("{name} ×{count}")
}

pub(crate) fn will_match(value: &str) -> String {
    format!("Will match: {value}")
}

pub(crate) fn stored_as(ascii: &str) -> String {
    format!("Stored as {ascii}")
}

pub(crate) fn filter_count(label: &str, count: usize) -> String {
    format!("{label} {count}")
}

pub(crate) fn via_engine(engine: &str) -> String {
    format!("via {engine}")
}

pub(crate) fn engine_detail(engine: &str) -> String {
    format!("{ENGINE}: {engine}")
}

pub(crate) fn subscriptions(count: usize) -> String {
    format!("Subscriptions · {count}")
}

pub(crate) fn subscription_summary(servers: &str, updated: &str) -> String {
    format!("{servers} · {updated}")
}

pub(crate) fn servers(count: usize) -> String {
    if count == 1 {
        "1 server".to_owned()
    } else {
        format!("{count} servers")
    }
}

pub(crate) fn last_updated(age: &str) -> String {
    format!("Last updated {age}")
}

pub(crate) fn selected_pending(name: &str) -> String {
    format!("Selected {name} · reconnect to apply")
}

pub(crate) fn updated(added: usize, removed: usize, retained: usize) -> String {
    format!("Updated · {added} added, {removed} removed, {retained} retained")
}

pub(crate) fn skipped(count: usize, reason: &str) -> String {
    format!("Skipped {count}: {reason}")
}

pub(crate) fn node_details(protocol: &str, tls: &str, transport: &str) -> String {
    format!("{protocol} · {tls} · {transport}")
}

pub(crate) fn session_time(hours: u64, minutes: u64, seconds: u64) -> String {
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

pub(crate) fn plain_link(label: &str, value: &str) -> String {
    format!("{label}: {value}")
}

pub(crate) fn helper_version(version: &str) -> String {
    format!("Helper {version}")
}
