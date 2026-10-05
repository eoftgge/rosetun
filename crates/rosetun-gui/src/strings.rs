pub(crate) const TITLE: &str = "Rosetun";
pub(crate) const BRAND: &str = "ROSETUN";
pub(crate) const CONNECTION: &str = "Connection";
pub(crate) const RULES: &str = "Rules";
pub(crate) const SETTINGS: &str = "Settings";
pub(crate) const COMING_LATER: &str = "Coming later";
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
pub(crate) const DOWNLOAD: &str = "Download";
pub(crate) const UPLOAD: &str = "Upload";
pub(crate) const ACTIVE_SERVER: &str = "Active tunnel server";
pub(crate) const UNKNOWN_SERVER: &str = "Server no longer in configuration";
pub(crate) const NO_SESSION: &str = "—";
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

pub(crate) fn subscriptions(count: usize) -> String {
    format!("Subscriptions · {count}")
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

pub(crate) fn transfer_rate(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MiB/s", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} KiB/s", bytes as f64 / 1024.0)
    }
}
