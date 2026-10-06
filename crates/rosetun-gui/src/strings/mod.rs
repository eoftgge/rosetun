mod en;

/// The table of the current interface language.
pub(crate) fn t() -> &'static Strings {
    &en::EN
}

pub(crate) struct Strings {
    pub(crate) connection: &'static str,
    pub(crate) rules: &'static str,
    pub(crate) settings: &'static str,
    pub(crate) minimize: &'static str,
    pub(crate) maximize: &'static str,
    pub(crate) restore: &'static str,
    pub(crate) close_window: &'static str,
    pub(crate) interface: &'static str,
    pub(crate) scale: &'static str,
    pub(crate) zoom_hint: &'static str,
    #[cfg(windows)]
    pub(crate) windows: &'static str,
    #[cfg(windows)]
    pub(crate) start_with_windows: &'static str,
    #[cfg(windows)]
    pub(crate) start_with_windows_detail: &'static str,
    #[cfg(windows)]
    pub(crate) keep_in_tray: &'static str,
    #[cfg(windows)]
    pub(crate) keep_in_tray_detail: &'static str,
    pub(crate) dns_through_tunnel: &'static str,
    pub(crate) dns_explanation: &'static str,
    pub(crate) resolver_ip: &'static str,
    pub(crate) tls_name: &'static str,
    pub(crate) port: &'static str,
    pub(crate) dns_path: &'static str,
    pub(crate) save: &'static str,
    pub(crate) reset_to_default: &'static str,
    pub(crate) engine_log: &'static str,
    pub(crate) engine_log_detail: &'static str,
    pub(crate) log_error: &'static str,
    pub(crate) log_warn: &'static str,
    pub(crate) log_info: &'static str,
    pub(crate) log_debug: &'static str,
    pub(crate) log_trace: &'static str,
    pub(crate) about: &'static str,
    pub(crate) helper_not_running: &'static str,
    pub(crate) configuration_folder: &'static str,
    pub(crate) log_file: &'static str,
    #[cfg(windows)]
    pub(crate) tray_open: &'static str,
    #[cfg(windows)]
    pub(crate) tray_quit: &'static str,
    pub(crate) open_folder: &'static str,
    pub(crate) connect: &'static str,
    pub(crate) disconnect: &'static str,
    pub(crate) retry: &'static str,
    pub(crate) reconnect: &'static str,
    pub(crate) connecting_action: &'static str,
    pub(crate) reconnecting_action: &'static str,
    pub(crate) working: &'static str,
    pub(crate) loading: &'static str,
    pub(crate) engine: &'static str,
    pub(crate) active_server: &'static str,
    pub(crate) unknown_server: &'static str,
    pub(crate) status_unknown: &'static str,
    pub(crate) disconnected: &'static str,
    pub(crate) connecting: &'static str,
    pub(crate) connected: &'static str,
    pub(crate) reconnecting: &'static str,
    pub(crate) failed: &'static str,
    pub(crate) failed_protected: &'static str,
    pub(crate) helper_unavailable: &'static str,
    pub(crate) helper_unavailable_detail: &'static str,
    pub(crate) select_server: &'static str,
    pub(crate) selected_server: &'static str,
    pub(crate) session: &'static str,
    pub(crate) kill_switch: &'static str,
    pub(crate) protection: &'static str,
    pub(crate) kill_switch_detail: &'static str,
    pub(crate) rule_set: &'static str,
    pub(crate) default_rules: &'static str,
    pub(crate) next_connect: &'static str,
    pub(crate) turn_off_protection: &'static str,
    pub(crate) keep_blocked: &'static str,
    pub(crate) protection_warning: &'static str,
    pub(crate) add_subscription: &'static str,
    pub(crate) add_subtitle: &'static str,
    pub(crate) subscription_url: &'static str,
    pub(crate) paste: &'static str,
    pub(crate) name: &'static str,
    pub(crate) name_placeholder: &'static str,
    pub(crate) send_device_id: &'static str,
    pub(crate) device_id_explanation: &'static str,
    pub(crate) url_help: &'static str,
    pub(crate) http_warning: &'static str,
    pub(crate) add: &'static str,
    pub(crate) adding: &'static str,
    pub(crate) cancel: &'static str,
    pub(crate) remove: &'static str,
    pub(crate) removing: &'static str,
    pub(crate) remove_subscription: &'static str,
    pub(crate) remove_detail: &'static str,
    pub(crate) remove_selected_warning: &'static str,
    pub(crate) update: &'static str,
    pub(crate) update_all: &'static str,
    pub(crate) updating: &'static str,
    pub(crate) subscription_reorder_disabled: &'static str,
    pub(crate) never_updated: &'static str,
    pub(crate) no_subscriptions: &'static str,
    pub(crate) empty_subscriptions: &'static str,
    pub(crate) no_servers: &'static str,
    pub(crate) support: &'static str,
    pub(crate) website: &'static str,
    pub(crate) selection_cleared: &'static str,
    pub(crate) dismiss: &'static str,
    pub(crate) rules_title: &'static str,
    pub(crate) rules_subtitle: &'static str,
    pub(crate) open_rules: &'static str,
    pub(crate) active: &'static str,
    pub(crate) use_for_connections: &'static str,
    pub(crate) new_set: &'static str,
    pub(crate) create_rule_set: &'static str,
    pub(crate) rename: &'static str,
    pub(crate) delete: &'static str,
    pub(crate) basic: &'static str,
    pub(crate) set_name: &'static str,
    pub(crate) rename_rule_set: &'static str,
    pub(crate) delete_rule_set: &'static str,
    pub(crate) delete_rule_set_detail: &'static str,
    pub(crate) delete_active_rule_set_warning: &'static str,
    pub(crate) delete_rule: &'static str,
    pub(crate) delete_rule_detail: &'static str,
    pub(crate) search_rules: &'static str,
    pub(crate) all: &'static str,
    pub(crate) domains: &'static str,
    pub(crate) processes: &'static str,
    pub(crate) other: &'static str,
    pub(crate) proxy: &'static str,
    pub(crate) direct: &'static str,
    pub(crate) block: &'static str,
    pub(crate) domain: &'static str,
    pub(crate) process: &'static str,
    pub(crate) keyword: &'static str,
    pub(crate) r#type: &'static str,
    pub(crate) value: &'static str,
    pub(crate) target: &'static str,
    pub(crate) enabled: &'static str,
    pub(crate) order_hint: &'static str,
    pub(crate) reorder_disabled: &'static str,
    pub(crate) default: &'static str,
    pub(crate) all_other_traffic: &'static str,
    pub(crate) default_fallback: &'static str,
    pub(crate) default_rule_tooltip: &'static str,
    pub(crate) no_rule_sets: &'static str,
    pub(crate) no_rules_match: &'static str,
    pub(crate) rules_next_connect: &'static str,
    pub(crate) new_rule_button: &'static str,
    pub(crate) new_rule: &'static str,
    pub(crate) new_rule_subtitle: &'static str,
    pub(crate) domain_input: &'static str,
    pub(crate) domain_placeholder: &'static str,
    pub(crate) domain_help: &'static str,
    pub(crate) process_input: &'static str,
    #[cfg(windows)]
    pub(crate) browse: &'static str,
    #[cfg(windows)]
    pub(crate) choose_program: &'static str,
    #[cfg(windows)]
    pub(crate) programs: &'static str,
    pub(crate) process_placeholder: &'static str,
    pub(crate) process_filter: &'static str,
    pub(crate) refresh: &'static str,
    pub(crate) loading_processes: &'static str,
    pub(crate) no_running_processes: &'static str,
    pub(crate) no_processes_match: &'static str,
    pub(crate) path_unavailable: &'static str,
    pub(crate) match_by_name: &'static str,
    pub(crate) match_by_full_path: &'static str,
    pub(crate) add_rule: &'static str,
    pub(crate) adding_rule: &'static str,
}

pub(crate) const TITLE: &str = "Rosetun";
pub(crate) const BRAND: &str = "ROSETUN";
pub(crate) const TAGLINE: &str = "Tunnel in bloom";
pub(crate) const PORT_PLACEHOLDER: &str = "443";
pub(crate) const DNS_PATH_PLACEHOLDER: &str = "/dns-query";
pub(crate) const LOG_FILE_NAME: &str = "rosetun-gui.log";
pub(crate) const ERROR_MARK: &str = "!";
pub(crate) const NO_SESSION: &str = "—";
pub(crate) const URL_PLACEHOLDER: &str = "https://provider.example/subscription";
pub(crate) const EXPAND: &str = "+";
pub(crate) const COLLAPSE: &str = "−";
pub(crate) const IP: &str = "IP";
pub(crate) const REMOVE_RULE: &str = "×";

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

pub(crate) fn process_copies(name: &str, count: usize) -> String {
    format!("{name} ×{count}")
}

pub(crate) fn filter_count(label: &str, count: usize) -> String {
    format!("{label} {count}")
}

pub(crate) fn subscription_summary(servers: &str, updated: &str) -> String {
    format!("{servers} · {updated}")
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

impl Strings {
    pub(crate) fn running_processes(&self, count: usize) -> String {
        format!("Running processes · {count}")
    }

    pub(crate) fn will_match(&self, value: &str) -> String {
        format!("Will match: {value}")
    }

    pub(crate) fn stored_as(&self, ascii: &str) -> String {
        format!("Stored as {ascii}")
    }

    pub(crate) fn via_engine(&self, engine: &str) -> String {
        format!("via {engine}")
    }

    pub(crate) fn engine_detail(&self, engine: &str) -> String {
        format!("{}: {engine}", self.engine)
    }

    pub(crate) fn subscriptions(&self, count: usize) -> String {
        format!("Subscriptions · {count}")
    }

    pub(crate) fn servers(&self, count: usize) -> String {
        if count == 1 {
            "1 server".to_owned()
        } else {
            format!("{count} servers")
        }
    }

    pub(crate) fn last_updated(&self, age: &str) -> String {
        format!("Last updated {age}")
    }

    pub(crate) fn selected_pending(&self, name: &str) -> String {
        format!("Selected {name} · reconnect to apply")
    }

    pub(crate) fn updated(&self, added: usize, removed: usize, retained: usize) -> String {
        format!("Updated · {added} added, {removed} removed, {retained} retained")
    }

    pub(crate) fn skipped(&self, count: usize, reason: &str) -> String {
        format!("Skipped {count}: {reason}")
    }

    pub(crate) fn helper_version(&self, version: &str) -> String {
        format!("Helper {version}")
    }
}
