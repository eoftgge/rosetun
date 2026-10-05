#![forbid(unsafe_code)]

mod fetch;
mod selection;
pub(crate) mod store;
mod subscription_url;
mod subscriptions;
mod text;
mod update;

pub use fetch::{FetchError, Timeouts, fetch};
pub use selection::{SelectNodeError, select_node};
pub use store::{Store, StoreError};
pub use subscription_url::{
    normalize as normalize_subscription_url, redacted as redacted_subscription_url,
};
pub use subscriptions::{
    AddSubscriptionError, CommitUpdateError, RemoveSubscriptionError, SubscriptionUpdateResult,
    UpdateSubscriptionError, add_subscription, commit_subscription_update, remove_subscription,
    update_all, update_subscription,
};
pub use text::{fetch_error_message, provider_text, terminal_text};
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
