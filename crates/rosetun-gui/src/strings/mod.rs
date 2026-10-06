use std::sync::atomic::{AtomicU8, Ordering};

use rosetun_config::{LanguageSetting, SubscriptionInfo};

mod en;
mod ru;

#[cfg(test)]
pub(crate) use self::{en::EN, ru::RU};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Language {
    English,
    Russian,
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

pub(crate) fn set_language(language: Language) {
    CURRENT.store(
        match language {
            Language::English => 0,
            Language::Russian => 1,
        },
        Ordering::Relaxed,
    );
}

pub(crate) fn language() -> Language {
    match CURRENT.load(Ordering::Relaxed) {
        1 => Language::Russian,
        _ => Language::English,
    }
}

/// The table of the current interface language.
pub(crate) fn t() -> &'static Strings {
    match language() {
        Language::English => &en::EN,
        Language::Russian => &ru::RU,
    }
}

pub(crate) fn resolve_language(setting: LanguageSetting, system_russian: bool) -> Language {
    match setting {
        LanguageSetting::System if system_russian => Language::Russian,
        LanguageSetting::System | LanguageSetting::English => Language::English,
        LanguageSetting::Russian => Language::Russian,
    }
}

/// Replaces `{name}` placeholders in one pass, so a value that itself contains
/// `{…}` (a path, provider text) is never substituted again.
pub(crate) fn fill(template: &str, values: &[(&str, &str)]) -> String {
    let mut output = String::with_capacity(template.len());
    let mut remaining = template;
    while let Some(start) = remaining.find('{') {
        output.push_str(&remaining[..start]);
        let after_open = &remaining[start + 1..];
        let Some(end) = after_open.find('}') else {
            remaining = &remaining[start..];
            break;
        };
        let name = &after_open[..end];
        if let Some((_, value)) = values.iter().find(|(key, _)| *key == name) {
            output.push_str(value);
        } else {
            output.push_str(&remaining[start..start + end + 2]);
        }
        remaining = &after_open[end + 1..];
    }
    output.push_str(remaining);
    output
}

pub(crate) struct ErrorStrings {
    pub(crate) config_dir: &'static str,
    pub(crate) config_access: &'static str,
    pub(crate) config_json: &'static str,
    pub(crate) config_invalid: &'static str,
    pub(crate) config_version: &'static str,
    pub(crate) config_dangling_node: &'static str,
    pub(crate) config_dangling_rule_set: &'static str,
    pub(crate) config_inspect: &'static str,
    pub(crate) unsupported_scale: &'static str,
    pub(crate) rule_set_not_found: &'static str,
    pub(crate) rule_not_found: &'static str,
    pub(crate) rule_set_name_empty: &'static str,
    pub(crate) duplicate_rule: &'static str,
    pub(crate) selected_rule_set_missing: &'static str,
    pub(crate) invalid_domain: &'static str,
    pub(crate) domain_is_ip: &'static str,
    pub(crate) single_label_domain: &'static str,
    pub(crate) invalid_process: &'static str,
    pub(crate) relative_path: &'static str,
    pub(crate) invalid_resolver_ip: &'static str,
    pub(crate) invalid_resolver_name: &'static str,
    pub(crate) invalid_port: &'static str,
    pub(crate) invalid_dns_path: &'static str,
    pub(crate) subscription_not_found: &'static str,
    pub(crate) node_not_found: &'static str,
    pub(crate) request_settings_changed: &'static str,
    pub(crate) clock_before_epoch: &'static str,
    pub(crate) already_added: &'static str,
    pub(crate) url_already_added: &'static str,
    pub(crate) ids_exhausted: &'static str,
    pub(crate) invalid_subscription_url: &'static str,
    pub(crate) missing_host: &'static str,
    pub(crate) encrypted_happ_link: &'static str,
    pub(crate) url_scheme: &'static str,
    pub(crate) import_link_invalid: &'static str,
    pub(crate) import_link_without_url: &'static str,
    pub(crate) import_link_multiple_urls: &'static str,
    pub(crate) import_link_nested: &'static str,
    pub(crate) fetch_user_agent: &'static str,
    pub(crate) fetch_device_id: &'static str,
    pub(crate) fetch_failed: &'static str,
    pub(crate) fetch_timeout: &'static str,
    pub(crate) fetch_host_not_found: &'static str,
    pub(crate) fetch_connection: &'static str,
    pub(crate) fetch_redirects: &'static str,
    pub(crate) fetch_insecure_redirect: &'static str,
    pub(crate) fetch_tls: &'static str,
    pub(crate) fetch_too_large: &'static str,
    pub(crate) fetch_body: &'static str,
    pub(crate) fetch_not_found: &'static str,
    pub(crate) fetch_not_found_retry: &'static str,
    pub(crate) fetch_access_denied: &'static str,
    pub(crate) fetch_http_status: &'static str,
    pub(crate) parse_empty: &'static str,
    pub(crate) parse_web_page: &'static str,
    pub(crate) parse_unsupported_format: &'static str,
    pub(crate) parse_unrecognized_format: &'static str,
    pub(crate) parse_invalid_utf8: &'static str,
    pub(crate) parse_invalid_json: &'static str,
    pub(crate) device_limit_reached: &'static str,
    pub(crate) device_id_rejected: &'static str,
    pub(crate) device_policy: &'static str,
    pub(crate) no_usable_nodes: &'static str,
    pub(crate) provider_announce: &'static str,
    pub(crate) provider_notice: &'static str,
    pub(crate) skip_invalid_record: &'static str,
    pub(crate) skip_invalid_port: &'static str,
    pub(crate) skip_missing_field: &'static str,
    pub(crate) skip_invalid_json: &'static str,
    pub(crate) skip_unsupported_protocol: &'static str,
    pub(crate) skip_client_settings: &'static str,
    pub(crate) skip_vmess_format: &'static str,
    pub(crate) skip_transport: &'static str,
    pub(crate) skip_unknown_transport: &'static str,
    pub(crate) skip_tcp_header: &'static str,
    pub(crate) skip_grpc_multi_mode: &'static str,
    pub(crate) skip_encryption: &'static str,
    pub(crate) skip_flow: &'static str,
    pub(crate) skip_security: &'static str,
    pub(crate) skip_reality_key: &'static str,
    pub(crate) skip_shadowsocks_plugin: &'static str,
    pub(crate) skip_shadowsocks_method: &'static str,
    pub(crate) skip_service_record: &'static str,
    pub(crate) process_list: &'static str,
    pub(crate) helper_transport: &'static str,
    pub(crate) helper_unexpected: &'static str,
    pub(crate) helper_closed: &'static str,
    pub(crate) code_protocol_mismatch: &'static str,
    pub(crate) code_handshake_required: &'static str,
    pub(crate) code_not_privileged: &'static str,
    pub(crate) code_engine_failed: &'static str,
    pub(crate) code_routing_failed: &'static str,
    pub(crate) code_busy: &'static str,
    pub(crate) code_invalid_state: &'static str,
    pub(crate) code_unsupported_rules: &'static str,
    pub(crate) code_not_implemented: &'static str,
    pub(crate) code_internal: &'static str,
    pub(crate) autostart_read: &'static str,
    pub(crate) autostart_write: &'static str,
    pub(crate) open_folder: &'static str,
}

pub(crate) struct Strings {
    pub(crate) language: Language,
    pub(crate) errors: ErrorStrings,
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
    pub(crate) reduce_motion: &'static str,
    pub(crate) reduce_motion_detail: &'static str,
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
    pub(crate) connect_on_start: &'static str,
    pub(crate) connect_on_start_detail: &'static str,
    pub(crate) auto_reconnect: &'static str,
    pub(crate) auto_reconnect_detail: &'static str,
    pub(crate) auto_update_subscriptions: &'static str,
    pub(crate) auto_update_subscriptions_detail: &'static str,
    pub(crate) dns_through_tunnel: &'static str,
    pub(crate) dns_explanation: &'static str,
    pub(crate) resolver_ip: &'static str,
    pub(crate) tls_name: &'static str,
    pub(crate) port: &'static str,
    pub(crate) dns_path: &'static str,
    pub(crate) save: &'static str,
    pub(crate) reset_to_default: &'static str,
    pub(crate) log_title: &'static str,
    pub(crate) verbose_log: &'static str,
    pub(crate) verbose_log_off_detail: &'static str,
    pub(crate) verbose_log_on_detail: &'static str,
    pub(crate) verbose_log_hour_one: &'static str,
    pub(crate) verbose_log_hour_few: &'static str,
    pub(crate) verbose_log_hour_many: &'static str,
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
    pub(crate) unavailable: &'static str,
    pub(crate) disconnect: &'static str,
    pub(crate) retry: &'static str,
    pub(crate) reconnect: &'static str,
    pub(crate) connecting_action: &'static str,
    pub(crate) reconnecting_action: &'static str,
    pub(crate) working: &'static str,
    pub(crate) loading: &'static str,
    pub(crate) engine: &'static str,
    pub(crate) status_unknown: &'static str,
    pub(crate) disconnected: &'static str,
    pub(crate) connecting: &'static str,
    pub(crate) connected: &'static str,
    pub(crate) connected_in_template: &'static str,
    pub(crate) reconnecting: &'static str,
    pub(crate) failed: &'static str,
    pub(crate) failed_protected: &'static str,
    pub(crate) traffic_blocked: &'static str,
    pub(crate) helper_unavailable: &'static str,
    pub(crate) helper_unavailable_detail: &'static str,
    pub(crate) service_down_title: &'static str,
    pub(crate) service_down_body: &'static str,
    pub(crate) details: &'static str,
    pub(crate) hide_details: &'static str,
    pub(crate) select_server: &'static str,
    pub(crate) server_change: &'static str,
    pub(crate) subscription_label: &'static str,
    pub(crate) protocol: &'static str,
    pub(crate) external_ip: &'static str,
    pub(crate) ip_own: &'static str,
    pub(crate) ip_show: &'static str,
    pub(crate) ip_hide: &'static str,
    pub(crate) ip_unknown: &'static str,
    pub(crate) ip_pending: &'static str,
    pub(crate) session: &'static str,
    pub(crate) traffic_down: &'static str,
    pub(crate) traffic_up: &'static str,
    pub(crate) traffic_session: &'static str,
    pub(crate) traffic_empty: &'static str,
    pub(crate) no_session: &'static str,
    pub(crate) kill_switch: &'static str,
    pub(crate) protection: &'static str,
    pub(crate) kill_switch_detail: &'static str,
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
    pub(crate) ping_check: &'static str,
    pub(crate) ping_checking: &'static str,
    pub(crate) ping_ms: &'static str,
    pub(crate) ping_no_answer: &'static str,
    pub(crate) ping_pending: &'static str,
    pub(crate) ping_best: &'static str,
    pub(crate) ping_tunnel_up: &'static str,
    pub(crate) support: &'static str,
    pub(crate) website: &'static str,
    pub(crate) selection_cleared: &'static str,
    pub(crate) dismiss: &'static str,
    pub(crate) rules_title: &'static str,
    pub(crate) rules_subtitle: &'static str,
    pub(crate) open_link: &'static str,
    pub(crate) no_rules_yet: &'static str,
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
    pub(crate) language_title: &'static str,
    pub(crate) language_system: &'static str,
}

pub(crate) const TITLE: &str = "Rosetun";
pub(crate) const BRAND: &str = "ROSETUN";
pub(crate) const TAGLINE: &str = "Tunnel in bloom";
pub(crate) const PORT_PLACEHOLDER: &str = "443";
pub(crate) const DNS_PATH_PLACEHOLDER: &str = "/dns-query";
pub(crate) const LOG_FILE_NAME: &str = "rosetun-gui.log";
pub(crate) const ERROR_MARK: &str = "!";
pub(crate) const URL_PLACEHOLDER: &str = "https://provider.example/subscription";
pub(crate) const EXPAND: &str = "+";
pub(crate) const COLLAPSE: &str = "−";
pub(crate) const IP: &str = "IP";
pub(crate) const REMOVE_RULE: &str = "×";
pub(crate) const ENGLISH: &str = "English";
pub(crate) const RUSSIAN: &str = "Русский";

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

/// Russian plural: 1 сервер, 2 сервера, 5 серверов, 11 серверов, 21 сервер.
fn ru_plural<'a>(n: u64, one: &'a str, few: &'a str, many: &'a str) -> &'a str {
    if n % 10 == 1 && n % 100 != 11 {
        one
    } else if (2..=4).contains(&(n % 10)) && !(12..=14).contains(&(n % 100)) {
        few
    } else {
        many
    }
}

fn en_count(n: u64, unit: &str) -> String {
    if n == 1 {
        format!("1 {unit}")
    } else {
        format!("{n} {unit}s")
    }
}

impl Strings {
    pub(crate) fn connected_in(&self, code: &str) -> String {
        fill(self.connected_in_template, &[("code", code)])
    }

    pub(crate) fn running_processes(&self, count: usize) -> String {
        match self.language {
            Language::English => format!("Running processes · {count}"),
            Language::Russian => format!("Запущенные процессы · {count}"),
        }
    }

    pub(crate) fn will_match(&self, value: &str) -> String {
        match self.language {
            Language::English => format!("Will match: {value}"),
            Language::Russian => format!("Сработает для: {value}"),
        }
    }

    pub(crate) fn stored_as(&self, ascii: &str) -> String {
        match self.language {
            Language::English => format!("Stored as {ascii}"),
            Language::Russian => format!("Хранится как {ascii}"),
        }
    }

    pub(crate) fn engine_detail(&self, engine: &str) -> String {
        format!("{}: {engine}", self.engine)
    }

    pub(crate) fn subscriptions(&self, count: usize) -> String {
        match self.language {
            Language::English => format!("Subscriptions · {count}"),
            Language::Russian => format!("Подписки · {count}"),
        }
    }

    pub(crate) fn servers(&self, count: usize) -> String {
        match self.language {
            Language::English => en_count(count as u64, "server"),
            Language::Russian => format!(
                "{count} {}",
                ru_plural(count as u64, "сервер", "сервера", "серверов")
            ),
        }
    }

    pub(crate) fn last_updated(&self, age: &str) -> String {
        match self.language {
            Language::English => format!("Last updated {age}"),
            Language::Russian => format!("Обновлено {age}"),
        }
    }

    pub(crate) fn traffic_peak(&self, rate: &str) -> String {
        match self.language {
            Language::English => format!("peak {rate}"),
            Language::Russian => format!("пик {rate}"),
        }
    }

    pub(crate) fn more_rules(&self, count: usize) -> String {
        match self.language {
            Language::English => format!("and {count} more"),
            Language::Russian => format!("и ещё {count}"),
        }
    }

    pub(crate) fn selected_pending(&self, name: &str) -> String {
        match self.language {
            Language::English => format!("Selected {name} · reconnect to apply"),
            Language::Russian => format!("Выбран {name} · переподключитесь, чтобы применить"),
        }
    }

    pub(crate) fn updated(&self, added: usize, removed: usize, retained: usize) -> String {
        match self.language {
            Language::English => {
                format!("Updated · {added} added, {removed} removed, {retained} retained")
            }
            Language::Russian => {
                format!("Обновлено · добавлено {added}, удалено {removed}, оставлено {retained}")
            }
        }
    }

    pub(crate) fn skipped(&self, count: usize, reason: &str) -> String {
        match self.language {
            Language::English => format!("Skipped {count}: {reason}"),
            Language::Russian => format!("Пропущено {count}: {reason}"),
        }
    }

    pub(crate) fn helper_version(&self, version: &str) -> String {
        match self.language {
            Language::English => format!("Helper {version}"),
            Language::Russian => format!("Служба {version}"),
        }
    }

    pub(crate) fn verbose_log_on_detail(&self, hours: u64) -> String {
        let duration = match self.language {
            Language::English => en_count(hours, self.verbose_log_hour_one),
            Language::Russian => format!(
                "{hours} {}",
                ru_plural(
                    hours,
                    self.verbose_log_hour_one,
                    self.verbose_log_hour_few,
                    self.verbose_log_hour_many,
                )
            ),
        };
        fill(self.verbose_log_on_detail, &[("hours", &duration)])
    }

    pub(crate) fn updated_ago(&self, timestamp: u64, now: u64) -> String {
        let elapsed = now.saturating_sub(timestamp);
        match (self.language, elapsed) {
            (Language::English, 0..60) => "just now".to_owned(),
            (Language::English, 60..3600) => format!("{} ago", en_count(elapsed / 60, "minute")),
            (Language::English, 3600..86400) => {
                format!("{} ago", en_count(elapsed / 3600, "hour"))
            }
            (Language::English, _) => format!("{} ago", en_count(elapsed / 86400, "day")),
            (Language::Russian, 0..60) => "только что".to_owned(),
            (Language::Russian, 60..3600) => {
                let n = elapsed / 60;
                format!("{n} {} назад", ru_plural(n, "минуту", "минуты", "минут"))
            }
            (Language::Russian, 3600..86400) => {
                let n = elapsed / 3600;
                format!("{n} {} назад", ru_plural(n, "час", "часа", "часов"))
            }
            (Language::Russian, _) => {
                let n = elapsed / 86400;
                format!("{n} {} назад", ru_plural(n, "день", "дня", "дней"))
            }
        }
    }

    pub(crate) fn expiry(&self, expiry: u64, now: u64) -> String {
        const DAY: u64 = 24 * 60 * 60;
        let (days, future) = if expiry >= now {
            ((expiry - now) / DAY, true)
        } else {
            ((now - expiry) / DAY, false)
        };
        match (self.language, future) {
            (Language::English, true) => format!("expires in {}", en_count(days, "day")),
            (Language::English, false) => format!("expired {} ago", en_count(days, "day")),
            (Language::Russian, true) => {
                format!(
                    "истекает через {days} {}",
                    ru_plural(days, "день", "дня", "дней")
                )
            }
            (Language::Russian, false) => {
                format!(
                    "истекла {days} {} назад",
                    ru_plural(days, "день", "дня", "дней")
                )
            }
        }
    }

    pub(crate) fn bytes(&self, value: u64) -> String {
        let units = match self.language {
            Language::English => ["B", "KiB", "MiB", "GiB", "TiB"],
            Language::Russian => ["Б", "КБ", "МБ", "ГБ", "ТБ"],
        };
        let mut amount = value as f64;
        let mut unit = 0;
        while amount >= 1000.0 && unit < units.len() - 1 {
            amount /= 1024.0;
            unit += 1;
        }
        let number = if unit == 0 || amount >= 100.0 {
            format!("{amount:.0}")
        } else if amount >= 10.0 {
            format!("{amount:.1}")
        } else {
            format!("{amount:.2}")
        };
        let number = match self.language {
            Language::English => number,
            Language::Russian => number.replace('.', ","),
        };
        format!("{number} {}", units[unit])
    }

    pub(crate) fn rate(&self, bytes_per_second: u64) -> String {
        match self.language {
            Language::English => format!("{}/s", self.bytes(bytes_per_second)),
            Language::Russian => format!("{}/с", self.bytes(bytes_per_second)),
        }
    }

    pub(crate) fn traffic(&self, info: &SubscriptionInfo) -> String {
        const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
        let used = (info.upload as f64 + info.download as f64) / GIB;
        match (self.language, info.total) {
            (Language::English, Some(total)) => {
                format!("{used:.2} / {:.2} GiB", total as f64 / GIB)
            }
            (Language::English, None) => format!("{used:.2} GiB / unknown"),
            (Language::Russian, Some(total)) => format!(
                "{} / {} ГБ",
                format!("{used:.2}").replace('.', ","),
                format!("{:.2}", total as f64 / GIB).replace('.', ",")
            ),
            (Language::Russian, None) => {
                format!(
                    "{} ГБ / лимит не указан",
                    format!("{used:.2}").replace('.', ",")
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Language, en::EN, fill, resolve_language, ru::RU, ru_plural};
    use rosetun_config::{LanguageSetting, SubscriptionInfo};

    #[test]
    fn fill_does_not_expand_values_again() {
        assert_eq!(
            fill("{a} and {b}", &[("a", "{b}"), ("b", "x")]),
            "{b} and x"
        );
        assert_eq!(
            fill("{unknown} {a} {open", &[("a", "x")]),
            "{unknown} x {open"
        );
    }
    #[test]
    fn byte_counts_and_rates_use_localized_three_digit_units() {
        for (strings, zero, kib, mib_rate, mib, gib, threshold) in [
            (
                &EN,
                "0 B/s",
                "1.50 KiB",
                "11.8 MiB/s",
                "150 MiB",
                "1.82 GiB",
                "0.98 MiB",
            ),
            (
                &RU,
                "0 Б/с",
                "1,50 КБ",
                "11,8 МБ/с",
                "150 МБ",
                "1,82 ГБ",
                "0,98 МБ",
            ),
        ] {
            assert_eq!(strings.rate(0), zero);
            assert_eq!(
                strings.bytes(512),
                if strings.language == Language::English {
                    "512 B"
                } else {
                    "512 Б"
                }
            );
            assert_eq!(strings.bytes(1536), kib);
            assert_eq!(strings.rate(12_373_196), mib_rate);
            assert_eq!(strings.bytes(157_286_400), mib);
            assert_eq!(strings.bytes(1_954_210_119), gib);
            assert_eq!(strings.bytes(1_024_000), threshold);
        }
    }

    #[test]
    fn interface_copy_uses_plain_punctuation_and_a_session_word() {
        assert_eq!(EN.no_session, "not started");
        assert_eq!(RU.no_session, "не начат");
        for table in [include_str!("en.rs"), include_str!("ru.rs")] {
            assert!(!table.contains('\u{2014}'));
        }
    }

    #[test]
    fn language_resolution_covers_all_settings_and_system_languages() {
        for (setting, system_russian, expected) in [
            (LanguageSetting::System, false, Language::English),
            (LanguageSetting::System, true, Language::Russian),
            (LanguageSetting::English, false, Language::English),
            (LanguageSetting::English, true, Language::English),
            (LanguageSetting::Russian, false, Language::Russian),
            (LanguageSetting::Russian, true, Language::Russian),
        ] {
            assert_eq!(resolve_language(setting, system_russian), expected);
        }
    }

    #[test]
    fn russian_plural_handles_tens_and_hundreds() {
        for (count, expected) in [
            (0, "many"),
            (1, "one"),
            (2, "few"),
            (4, "few"),
            (5, "many"),
            (11, "many"),
            (12, "many"),
            (14, "many"),
            (21, "one"),
            (22, "few"),
            (25, "many"),
            (101, "one"),
            (111, "many"),
        ] {
            assert_eq!(ru_plural(count, "one", "few", "many"), expected, "{count}");
        }
        for (count, expected) in [
            (1, "1 сервер"),
            (3, "3 сервера"),
            (5, "5 серверов"),
            (21, "21 сервер"),
        ] {
            assert_eq!(RU.servers(count), expected);
        }
    }

    #[test]
    fn verbose_log_details_pluralize_remaining_hours() {
        for (hours, expected) in [
            (1, "1 час"),
            (2, "2 часа"),
            (5, "5 часов"),
            (21, "21 час"),
            (24, "24 часа"),
        ] {
            assert_eq!(
                RU.verbose_log_on_detail(hours),
                format!(
                    "Выключится сам через {expected}. Пока включён, записывает адреса сайтов. Применится при следующем подключении."
                )
            );
        }
        for (hours, expected) in [(1, "1 hour"), (24, "24 hours")] {
            assert_eq!(
                EN.verbose_log_on_detail(hours),
                format!(
                    "Turns itself off in {expected}. While on, it records site addresses. Applies on next connect."
                )
            );
        }
    }

    #[test]
    fn english_update_age_matches_core_at_interval_boundaries() {
        for (elapsed, expected) in [
            (0, "just now"),
            (59, "just now"),
            (60, "1 minute ago"),
            (120, "2 minutes ago"),
            (3599, "59 minutes ago"),
            (3600, "1 hour ago"),
            (7200, "2 hours ago"),
            (86399, "23 hours ago"),
            (86400, "1 day ago"),
            (172800, "2 days ago"),
        ] {
            assert_eq!(EN.updated_ago(0, elapsed), expected);
        }
        assert_eq!(EN.updated_ago(101, 100), "just now");
        assert_eq!(EN.updated_ago(u64::MAX, 0), "just now");
    }

    #[test]
    fn english_expiry_matches_core_in_both_directions() {
        for (expiry, now, expected) in [
            (86_400, 0, "expires in 1 day"),
            (0, 86_400, "expired 1 day ago"),
            (172_800, 0, "expires in 2 days"),
            (0, 172_800, "expired 2 days ago"),
            (100, 100, "expires in 0 days"),
            (99, 100, "expired 0 days ago"),
        ] {
            assert_eq!(EN.expiry(expiry, now), expected);
        }
    }

    #[test]
    fn russian_age_expiry_and_traffic() {
        assert_eq!(RU.updated_ago(0, 30), "только что");
        assert_eq!(RU.updated_ago(0, 120), "2 минуты назад");
        assert_eq!(RU.updated_ago(0, 5 * 3600), "5 часов назад");
        assert_eq!(RU.updated_ago(0, 86_400), "1 день назад");
        assert_eq!(
            RU.last_updated(&RU.updated_ago(0, 5 * 60)),
            "Обновлено 5 минут назад"
        );
        assert_eq!(RU.expiry(2 * 86_400, 0), "истекает через 2 дня");
        assert_eq!(RU.expiry(0, 5 * 86_400), "истекла 5 дней назад");
        let mut info = SubscriptionInfo {
            upload: 1 << 30,
            download: 1 << 29,
            total: Some(10 << 30),
            expire_unix: None,
        };
        assert_eq!(RU.traffic(&info), "1,50 / 10,00 ГБ");
        info.total = None;
        assert_eq!(RU.traffic(&info), "1,50 ГБ / лимит не указан");
        assert_eq!(EN.traffic(&info), "1.50 GiB / unknown");
    }
}
