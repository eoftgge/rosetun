#![forbid(unsafe_code)]

mod fetch;
mod ping;
mod rules;
mod selection;
mod settings;
pub(crate) mod store;
mod subscription_url;
mod subscriptions;
mod text;
mod update;

pub use fetch::{FetchError, Timeouts, fetch};
pub use ping::{PING_PARALLEL, PING_TIMEOUT, Ping, ping_all, tcp_ping};
pub use rosetun_subscription::{ParseError, SkipReason, Skipped, UnsupportedTransport};
pub use rules::{
    RuleInputError, RuleSetError, add_rule, create_rule_set, delete_rule_set, move_rule,
    parse_domain_input, parse_process_input, remove_rule, rename_rule_set, rule_value_ascii,
    rule_value_text, set_default_target, set_rule_enabled, set_rule_target,
};
pub use selection::{
    SelectNodeError, SelectRuleSetError, select_node, select_rule_set, set_kill_switch,
};
pub use settings::{
    DnsInputError, INTERFACE_SCALES, SettingsError, parse_dns_input, set_auto_reconnect,
    set_auto_update_subscriptions, set_close_to_tray, set_connect_on_start, set_dns,
    set_interface_scale, set_language, set_reduce_motion, set_verbose_log,
};
pub use store::{Store, StoreError};
pub use subscription_url::{
    SubscriptionUrlError, normalize as normalize_subscription_url,
    redacted as redacted_subscription_url,
};
pub use subscriptions::{
    AddFromUrlError, AddOptions, AddSubscriptionError, CommitUpdateError, MoveSubscriptionError,
    PreparedSubscription, RemoveSubscriptionError, SubscriptionUpdateResult,
    UpdateSubscriptionError, add_prepared_subscription, add_subscription,
    commit_subscription_update, move_subscription, prepare_subscription, remove_subscription,
    update_all, update_subscription,
};
pub use text::{
    expiry_text, fetch_error_message, node_address, node_protocol, node_tls, node_transport,
    provider_text, terminal_text, traffic_text, updated_text,
};
pub use update::{UpdateReport, group_skipped};

pub fn is_sensitive_log_target(target: &str) -> bool {
    ["ureq", "ureq_proto", "rustls", "rustls_platform_verifier"]
        .iter()
        .any(|prefix| {
            target == *prefix
                || target
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.starts_with("::"))
        })
}

#[cfg(test)]
mod tests {
    use super::{Store, StoreError, is_sensitive_log_target};

    #[test]
    fn sensitive_log_targets_match_only_exact_names_and_submodules() {
        for target in ["ureq", "ureq_proto", "rustls", "rustls_platform_verifier"] {
            assert!(is_sensitive_log_target(target));
            assert!(is_sensitive_log_target(&format!("{target}::run")));
            assert!(is_sensitive_log_target(&format!("{target}::run::request")));
            assert!(!is_sensitive_log_target(&format!("{target}x")));
            assert!(!is_sensitive_log_target(&format!("{target}_other")));
        }

        for target in ["", "rosetun", "other::ureq", "ureqx::run"] {
            assert!(!is_sensitive_log_target(target));
        }
    }

    #[test]
    fn store_and_store_error_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<Store>();
        assert_send_sync::<StoreError>();
    }
}
