use rosetun_config::ConfigError;
use rosetun_core::{
    AddFromUrlError, AddSubscriptionError, DnsInputError, MoveSubscriptionError,
    RemoveSubscriptionError, RuleInputError, RuleSetError, SelectNodeError, SelectRuleSetError,
    SettingsError, StoreError, UpdateSubscriptionError,
};
use rosetun_ipc::{ClientError, ConnectRequestError, ErrorCode};
use rosetun_processes::ProcessListError;

use crate::display;
use crate::strings::{Strings, fill};
use crate::worker::{ConfigWorkerError, HelperCommandError};

pub(crate) fn store(s: &Strings, error: &StoreError) -> String {
    match error {
        StoreError::NoConfigDir => s.errors.config_dir.to_owned(),
        StoreError::Io { path, source } => fill(
            s.errors.config_access,
            &[
                ("path", &path.display().to_string()),
                ("detail", &source.to_string()),
            ],
        ),
        StoreError::Parse { path, source } => fill(
            s.errors.config_json,
            &[
                ("path", &path.display().to_string()),
                ("line", &source.line().to_string()),
                ("column", &source.column().to_string()),
            ],
        ),
        StoreError::Invalid { path, source } => fill(
            s.errors.config_invalid,
            &[
                ("path", &path.display().to_string()),
                ("detail", &config(s, source)),
            ],
        ),
    }
}

fn config(s: &Strings, error: &ConfigError) -> String {
    match error {
        ConfigError::UnsupportedVersion { found, expected } => fill(
            s.errors.config_version,
            &[
                ("found", &found.to_string()),
                ("expected", &expected.to_string()),
            ],
        ),
        ConfigError::DanglingSelection { subscription, node } => fill(
            s.errors.config_dangling_node,
            &[
                ("subscription", subscription.as_str()),
                ("node", node.as_str()),
            ],
        ),
        ConfigError::DanglingRuleSet(id) => {
            fill(s.errors.config_dangling_rule_set, &[("id", id.as_str())])
        }
    }
}

pub(crate) fn config_worker(s: &Strings, error: &ConfigWorkerError) -> String {
    match error {
        ConfigWorkerError::Store(error) => store(s, error),
        ConfigWorkerError::Metadata(error) => {
            fill(s.errors.config_inspect, &[("detail", &error.to_string())])
        }
    }
}

pub(crate) fn settings(s: &Strings, error: &SettingsError) -> String {
    match error {
        SettingsError::Store(error) => store(s, error),
        SettingsError::UnsupportedScale => s.errors.unsupported_scale.to_owned(),
    }
}

pub(crate) fn rule_set(s: &Strings, error: &RuleSetError) -> String {
    match error {
        RuleSetError::Store(error) => store(s, error),
        RuleSetError::SetNotFound => s.errors.rule_set_not_found.to_owned(),
        RuleSetError::RuleNotFound => s.errors.rule_not_found.to_owned(),
        RuleSetError::EmptyName => s.errors.rule_set_name_empty.to_owned(),
        RuleSetError::DuplicateRule => s.errors.duplicate_rule.to_owned(),
    }
}

pub(crate) fn rule_input(s: &Strings, error: &RuleInputError) -> String {
    match error {
        RuleInputError::InvalidDomain => s.errors.invalid_domain.to_owned(),
        RuleInputError::IpAddress => s.errors.domain_is_ip.to_owned(),
        RuleInputError::SingleLabel => s.errors.single_label_domain.to_owned(),
        RuleInputError::InvalidProcess => s.errors.invalid_process.to_owned(),
        RuleInputError::RelativePath => s.errors.relative_path.to_owned(),
    }
}

pub(crate) fn dns_input(s: &Strings, error: &DnsInputError) -> String {
    match error {
        DnsInputError::InvalidServer => s.errors.invalid_resolver_ip.to_owned(),
        DnsInputError::InvalidServerName => s.errors.invalid_resolver_name.to_owned(),
        DnsInputError::InvalidPort => s.errors.invalid_port.to_owned(),
        DnsInputError::InvalidPath => s.errors.invalid_dns_path.to_owned(),
    }
}

pub(crate) fn select_node(s: &Strings, error: &SelectNodeError) -> String {
    match error {
        SelectNodeError::Store(error) => store(s, error),
        SelectNodeError::SubscriptionNotFound => s.errors.subscription_not_found.to_owned(),
        SelectNodeError::NodeNotFound => s.errors.node_not_found.to_owned(),
    }
}

pub(crate) fn select_rule_set(s: &Strings, error: &SelectRuleSetError) -> String {
    match error {
        SelectRuleSetError::Store(error) => store(s, error),
        SelectRuleSetError::NotFound => s.errors.rule_set_not_found.to_owned(),
    }
}

pub(crate) fn add_subscription(s: &Strings, error: &AddFromUrlError) -> String {
    match error {
        AddFromUrlError::Url(message) => message.clone(),
        AddFromUrlError::Store(error) => store(s, error),
        AddFromUrlError::AlreadyExists(id) => fill(
            s.errors.already_added,
            &[("id", &rosetun_core::terminal_text(id.as_str()))],
        ),
        AddFromUrlError::InvalidUrl(_) => s.errors.invalid_subscription_url.to_owned(),
        AddFromUrlError::MissingHost => s.errors.missing_host.to_owned(),
        AddFromUrlError::Fetch { message, .. } => message.clone(),
        AddFromUrlError::Clock(_) => s.errors.clock_before_epoch.to_owned(),
        AddFromUrlError::Commit(error) => match error {
            AddSubscriptionError::Store(error) => store(s, error),
            AddSubscriptionError::AlreadyExists => s.errors.url_already_added.to_owned(),
            AddSubscriptionError::IdExhausted => s.errors.ids_exhausted.to_owned(),
        },
    }
}

pub(crate) fn update_subscription(s: &Strings, error: &UpdateSubscriptionError) -> String {
    match error {
        UpdateSubscriptionError::Store(error) => store(s, error),
        UpdateSubscriptionError::NotFound => s.errors.subscription_not_found.to_owned(),
        UpdateSubscriptionError::Fetch { message, .. } => message.clone(),
        UpdateSubscriptionError::RequestSettingsChanged => {
            s.errors.request_settings_changed.to_owned()
        }
        UpdateSubscriptionError::Clock(_) => s.errors.clock_before_epoch.to_owned(),
    }
}

pub(crate) fn remove_subscription(s: &Strings, error: &RemoveSubscriptionError) -> String {
    match error {
        RemoveSubscriptionError::Store(error) => store(s, error),
        RemoveSubscriptionError::SubscriptionNotFound => s.errors.subscription_not_found.to_owned(),
    }
}

pub(crate) fn move_subscription(s: &Strings, error: &MoveSubscriptionError) -> String {
    match error {
        MoveSubscriptionError::Store(error) => store(s, error),
        MoveSubscriptionError::NotFound => s.errors.subscription_not_found.to_owned(),
    }
}

pub(crate) fn process_list(s: &Strings, error: &ProcessListError) -> String {
    match error {
        ProcessListError::Snapshot(error) => {
            fill(s.errors.process_list, &[("detail", &error.to_string())])
        }
    }
}

pub(crate) fn connect_request(s: &Strings, error: &ConnectRequestError) -> String {
    match error {
        ConnectRequestError::SelectionMissing | ConnectRequestError::NodeNotFound => {
            s.select_server.to_owned()
        }
        ConnectRequestError::RuleSetNotFound => s.errors.selected_rule_set_missing.to_owned(),
    }
}

pub(crate) fn client(s: &Strings, error: &ClientError) -> String {
    let message = match error {
        ClientError::Transport(detail) => fill(s.errors.helper_transport, &[("detail", detail)]),
        ClientError::Unexpected => s.errors.helper_unexpected.to_owned(),
        ClientError::Closed => s.errors.helper_closed.to_owned(),
        ClientError::Helper(error) => {
            let title = match error.code {
                ErrorCode::ProtocolMismatch => s.errors.code_protocol_mismatch,
                ErrorCode::HandshakeRequired => s.errors.code_handshake_required,
                ErrorCode::NotPrivileged => s.errors.code_not_privileged,
                ErrorCode::EngineFailed => s.errors.code_engine_failed,
                ErrorCode::RoutingFailed => s.errors.code_routing_failed,
                ErrorCode::Busy => s.errors.code_busy,
                ErrorCode::InvalidState => s.errors.code_invalid_state,
                ErrorCode::UnsupportedRules => s.errors.code_unsupported_rules,
                ErrorCode::NotImplemented => s.errors.code_not_implemented,
                ErrorCode::Internal => s.errors.code_internal,
            };
            if error.message.is_empty() {
                title.to_owned()
            } else {
                format!("{title}: {}", error.message)
            }
        }
    };
    display::safe_multiline(&message)
}

pub(crate) fn helper_command(s: &Strings, error: &HelperCommandError) -> String {
    match error {
        HelperCommandError::Store(error) => store(s, error),
        HelperCommandError::Request(error) => connect_request(s, error),
        HelperCommandError::Client(error) => client(s, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strings::{EN, RU};
    use rosetun_core::Store;
    use rosetun_ipc::HelperError;

    #[test]
    fn duplicate_rule_uses_the_selected_table() {
        let error = RuleSetError::DuplicateRule;
        assert_eq!(rule_set(&EN, &error), "this rule is already in the set");
        assert_eq!(rule_set(&RU, &error), "такое правило уже есть в наборе");
    }

    #[test]
    fn invalid_json_keeps_only_the_path_and_position() {
        let path = std::env::temp_dir().join(format!(
            "rosetun-gui-invalid-json-{}-{{detail}}.json",
            std::process::id()
        ));
        std::fs::write(&path, "{\"credential\":\"private-token\",\n\"settings\": }").unwrap();
        let error = Store::at(&path).load().unwrap_err();
        std::fs::remove_file(&path).unwrap();
        let StoreError::Parse { source, .. } = &error else {
            panic!("expected a JSON parse error");
        };
        let en = store(&EN, &error);
        let ru = store(&RU, &error);
        assert_eq!(
            en,
            format!(
                "invalid JSON in {} at line {}, column {}",
                path.display(),
                source.line(),
                source.column()
            )
        );
        assert_eq!(
            ru,
            format!(
                "ошибка JSON в {}: строка {}, столбец {}",
                path.display(),
                source.line(),
                source.column()
            )
        );
        for text in [&en, &ru] {
            assert!(!text.contains("private-token"));
            assert!(!text.contains("credential"));
            assert!(text.contains("{detail}"));
        }
    }

    #[test]
    fn helper_codes_use_localized_titles_and_preserve_details() {
        let error = ClientError::Helper(HelperError::new(ErrorCode::EngineFailed, "boom"));
        assert_eq!(client(&EN, &error), "the engine failed: boom");
        assert_eq!(client(&RU, &error), "сбой ядра: boom");
        let empty = ClientError::Helper(HelperError::new(ErrorCode::EngineFailed, ""));
        assert_eq!(client(&EN, &empty), "the engine failed");
        assert_eq!(client(&RU, &empty), "сбой ядра");
        let transport = ClientError::Transport("x".to_owned());
        assert_eq!(client(&RU, &transport), "нет связи со службой: x");
        let unsafe_detail = ClientError::Transport("socket\u{202e}failed".to_owned());
        assert_eq!(
            client(&EN, &unsafe_detail),
            "unable to contact helper: socket failed"
        );
    }

    #[test]
    fn missing_selection_uses_the_regular_interface_string() {
        assert_eq!(
            connect_request(&RU, &ConnectRequestError::SelectionMissing),
            RU.select_server
        );
        assert_eq!(
            connect_request(&EN, &ConnectRequestError::RuleSetNotFound),
            "the selected rule set does not exist"
        );
    }
}
