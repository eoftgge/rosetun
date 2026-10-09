use rosetun_config::ConfigError;
use rosetun_core::{
    AddFromUrlError, AddSubscriptionError, DnsInputError, FetchError, MoveSubscriptionError,
    ParseError, RemoveSubscriptionError, RenameSubscriptionError, RuleInputError, RuleSetError,
    SelectNodeError, SelectRuleSetError, SettingsError, SkipReason, StoreError,
    SubscriptionUrlError, UnsupportedTransport, UpdateSubscriptionError,
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
        StoreError::Format { path } => fill(
            s.errors.config_invalid,
            &[
                ("path", &path.display().to_string()),
                ("detail", s.errors.config_value),
            ],
        ),
        StoreError::Invalid {
            source: ConfigError::UnsupportedVersion { .. },
            ..
        } => s.errors.config_version.to_owned(),
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
        ConfigError::UnsupportedVersion { .. } => s.errors.config_version.to_owned(),
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

pub(crate) fn subscription_url(s: &Strings, error: &SubscriptionUrlError) -> String {
    match error {
        SubscriptionUrlError::Invalid => s.errors.invalid_subscription_url,
        SubscriptionUrlError::MissingHost => s.errors.missing_host,
        SubscriptionUrlError::EncryptedHappLink => s.errors.encrypted_happ_link,
        SubscriptionUrlError::UnsupportedScheme => s.errors.url_scheme,
        SubscriptionUrlError::InvalidImportLink => s.errors.import_link_invalid,
        SubscriptionUrlError::ImportLinkWithoutUrl => s.errors.import_link_without_url,
        SubscriptionUrlError::ImportLinkWithMultipleUrls => s.errors.import_link_multiple_urls,
        SubscriptionUrlError::TooManyNestedLinks => s.errors.import_link_nested,
    }
    .to_owned()
}

pub(crate) fn fetch(s: &Strings, error: &FetchError) -> String {
    match error {
        FetchError::InvalidUrl => s.errors.invalid_subscription_url.to_owned(),
        FetchError::InvalidUserAgent => s.errors.fetch_user_agent.to_owned(),
        FetchError::InvalidDeviceId => s.errors.fetch_device_id.to_owned(),
        FetchError::RequestFailed => s.errors.fetch_failed.to_owned(),
        FetchError::Timeout => s.errors.fetch_timeout.to_owned(),
        FetchError::HostNotFound => s.errors.fetch_host_not_found.to_owned(),
        FetchError::ConnectionFailed => s.errors.fetch_connection.to_owned(),
        FetchError::TooManyRedirects => s.errors.fetch_redirects.to_owned(),
        FetchError::InsecureRedirect => s.errors.fetch_insecure_redirect.to_owned(),
        FetchError::Tls(detail) => fill(s.errors.fetch_tls, &[("detail", detail)]),
        FetchError::ResponseTooLarge => s.errors.fetch_too_large.to_owned(),
        FetchError::BodyReadFailed => s.errors.fetch_body.to_owned(),
        FetchError::NotFound { sent_hwid: true } => s.errors.fetch_not_found.to_owned(),
        FetchError::NotFound { sent_hwid: false } => s.errors.fetch_not_found_retry.to_owned(),
        FetchError::AccessDenied => s.errors.fetch_access_denied.to_owned(),
        FetchError::HttpStatus(status) => fill(
            s.errors.fetch_http_status,
            &[("status", &status.to_string())],
        ),
        FetchError::Parse(error) => parse(s, error),
    }
}

fn parse(s: &Strings, error: &ParseError) -> String {
    match error {
        ParseError::Empty => s.errors.parse_empty.to_owned(),
        ParseError::WebPage => s.errors.parse_web_page.to_owned(),
        ParseError::UnsupportedFormat => s.errors.parse_unsupported_format.to_owned(),
        ParseError::EncryptedHappLink => s.errors.encrypted_happ_link.to_owned(),
        ParseError::UnrecognizedFormat => s.errors.parse_unrecognized_format.to_owned(),
        ParseError::InvalidUtf8 => s.errors.parse_invalid_utf8.to_owned(),
        ParseError::InvalidJson { line, column } => fill(
            s.errors.parse_invalid_json,
            &[("line", &line.to_string()), ("column", &column.to_string())],
        ),
        ParseError::DeviceLimit {
            max_devices_reached,
            not_supported,
            announce,
        } => {
            let title = if *max_devices_reached {
                s.errors.device_limit_reached
            } else if *not_supported {
                s.errors.device_id_rejected
            } else {
                s.errors.device_policy
            };
            let mut output = title.to_owned();
            if let Some(text) = announce {
                output.push('\n');
                output.push_str(&fill(s.errors.provider_announce, &[("text", text)]));
            }
            output
        }
        ParseError::NoUsableNodes { skipped, notices } => {
            let mut output = s.errors.no_usable_nodes.to_owned();
            for text in notices {
                output.push('\n');
                output.push_str(&fill(s.errors.provider_notice, &[("text", text)]));
            }
            for (reason, count) in rosetun_core::group_skipped(skipped) {
                output.push('\n');
                output.push_str(&s.skipped(count, &skip_reason(s, &reason)));
            }
            output
        }
    }
}

pub(crate) fn skip_reason(s: &Strings, reason: &SkipReason) -> String {
    match reason {
        SkipReason::InvalidRecord => s.errors.skip_invalid_record.to_owned(),
        SkipReason::InvalidPort => s.errors.skip_invalid_port.to_owned(),
        SkipReason::MissingField => s.errors.skip_missing_field.to_owned(),
        SkipReason::InvalidJson { line, column } => fill(
            s.errors.skip_invalid_json,
            &[("line", &line.to_string()), ("column", &column.to_string())],
        ),
        SkipReason::UnsupportedProtocol => s.errors.skip_unsupported_protocol.to_owned(),
        SkipReason::ClientSettings => s.errors.skip_client_settings.to_owned(),
        SkipReason::UnsupportedVmessFormat => s.errors.skip_vmess_format.to_owned(),
        SkipReason::UnsupportedTransport(UnsupportedTransport::Other) => {
            s.errors.skip_unknown_transport.to_owned()
        }
        SkipReason::UnsupportedTransport(
            transport @ (UnsupportedTransport::Xhttp
            | UnsupportedTransport::SplitHttp
            | UnsupportedTransport::Kcp
            | UnsupportedTransport::Quic
            | UnsupportedTransport::H2
            | UnsupportedTransport::Http),
        ) => fill(
            s.errors.skip_transport,
            &[("transport", &transport.to_string())],
        ),
        SkipReason::UnsupportedTcpHeader => s.errors.skip_tcp_header.to_owned(),
        SkipReason::UnsupportedGrpcMultiMode => s.errors.skip_grpc_multi_mode.to_owned(),
        SkipReason::UnsupportedEncryption => s.errors.skip_encryption.to_owned(),
        SkipReason::UnsupportedFlow => s.errors.skip_flow.to_owned(),
        SkipReason::UnsupportedSecurity => s.errors.skip_security.to_owned(),
        SkipReason::MissingRealityPublicKey => s.errors.skip_reality_key.to_owned(),
        SkipReason::ShadowsocksPlugin => s.errors.skip_shadowsocks_plugin.to_owned(),
        SkipReason::UnsupportedShadowsocksMethod => s.errors.skip_shadowsocks_method.to_owned(),
        SkipReason::UnsupportedObfs => s.errors.skip_unsupported_obfs.to_owned(),
        SkipReason::UnsupportedPin => s.errors.skip_unsupported_pin.to_owned(),
        SkipReason::ServiceRecord => s.errors.skip_service_record.to_owned(),
    }
}

pub(crate) fn add_subscription(s: &Strings, error: &AddFromUrlError) -> String {
    match error {
        AddFromUrlError::Url(error) => subscription_url(s, error),
        AddFromUrlError::Store(error) => store(s, error),
        AddFromUrlError::AlreadyExists(id) => fill(
            s.errors.already_added,
            &[("id", &rosetun_core::terminal_text(id.as_str()))],
        ),
        AddFromUrlError::InvalidUrl(_) => s.errors.invalid_subscription_url.to_owned(),
        AddFromUrlError::MissingHost => s.errors.missing_host.to_owned(),
        AddFromUrlError::Fetch { source, .. } => fetch(s, source),
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
        UpdateSubscriptionError::Fetch { source, .. } => fetch(s, source),
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

pub(crate) fn rename_subscription(s: &Strings, error: &RenameSubscriptionError) -> String {
    match error {
        RenameSubscriptionError::Store(error) => store(s, error),
        RenameSubscriptionError::NotFound => s.errors.subscription_not_found.to_owned(),
        RenameSubscriptionError::EmptyName => s.errors.subscription_name_empty.to_owned(),
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
                ErrorCode::ServerUnreachable => s.errors.code_server_unreachable,
                ErrorCode::ServerRejected => s.errors.code_server_rejected,
                ErrorCode::ServerClosed => s.errors.code_server_closed,
                ErrorCode::DnsTimeout => s.errors.code_dns_timeout,
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
    use rosetun_core::{Skipped, Store};
    use rosetun_ipc::HelperError;

    #[test]
    fn duplicate_rule_uses_the_selected_table() {
        let error = RuleSetError::DuplicateRule;
        assert_eq!(rule_set(&EN, &error), "this rule is already in the set");
        assert_eq!(rule_set(&RU, &error), "такое правило уже есть в наборе");
    }

    #[test]
    fn english_subscription_url_errors_match_core() {
        for error in [
            SubscriptionUrlError::Invalid,
            SubscriptionUrlError::MissingHost,
            SubscriptionUrlError::EncryptedHappLink,
            SubscriptionUrlError::UnsupportedScheme,
            SubscriptionUrlError::InvalidImportLink,
            SubscriptionUrlError::ImportLinkWithoutUrl,
            SubscriptionUrlError::ImportLinkWithMultipleUrls,
            SubscriptionUrlError::TooManyNestedLinks,
        ] {
            assert_eq!(subscription_url(&EN, &error), error.to_string());
        }
    }

    #[test]
    fn english_skip_reasons_match_core() {
        for reason in [
            SkipReason::InvalidRecord,
            SkipReason::InvalidPort,
            SkipReason::MissingField,
            SkipReason::InvalidJson { line: 2, column: 3 },
            SkipReason::UnsupportedProtocol,
            SkipReason::ClientSettings,
            SkipReason::UnsupportedVmessFormat,
            SkipReason::UnsupportedTcpHeader,
            SkipReason::UnsupportedGrpcMultiMode,
            SkipReason::UnsupportedEncryption,
            SkipReason::UnsupportedFlow,
            SkipReason::UnsupportedSecurity,
            SkipReason::MissingRealityPublicKey,
            SkipReason::ShadowsocksPlugin,
            SkipReason::UnsupportedShadowsocksMethod,
            SkipReason::UnsupportedObfs,
            SkipReason::UnsupportedPin,
            SkipReason::ServiceRecord,
        ] {
            assert_eq!(skip_reason(&EN, &reason), reason.to_string());
        }
        for transport in [
            UnsupportedTransport::Xhttp,
            UnsupportedTransport::SplitHttp,
            UnsupportedTransport::Kcp,
            UnsupportedTransport::Quic,
            UnsupportedTransport::H2,
            UnsupportedTransport::Http,
            UnsupportedTransport::Other,
        ] {
            let reason = SkipReason::UnsupportedTransport(transport);
            assert_eq!(skip_reason(&EN, &reason), reason.to_string());
        }
    }

    #[test]
    fn english_fetch_and_simple_parse_errors_match_core() {
        for error in [
            FetchError::InvalidUrl,
            FetchError::InvalidUserAgent,
            FetchError::InvalidDeviceId,
            FetchError::RequestFailed,
            FetchError::Timeout,
            FetchError::HostNotFound,
            FetchError::ConnectionFailed,
            FetchError::TooManyRedirects,
            FetchError::InsecureRedirect,
            FetchError::Tls("bad certificate".to_owned()),
            FetchError::ResponseTooLarge,
            FetchError::BodyReadFailed,
            FetchError::AccessDenied,
            FetchError::HttpStatus(418),
        ] {
            assert_eq!(fetch(&EN, &error), error.to_string());
        }
        for error in [
            ParseError::Empty,
            ParseError::WebPage,
            ParseError::UnsupportedFormat,
            ParseError::EncryptedHappLink,
            ParseError::UnrecognizedFormat,
            ParseError::InvalidUtf8,
            ParseError::InvalidJson { line: 2, column: 3 },
        ] {
            let expected = error.to_string();
            assert_eq!(parse(&EN, &error), expected);
            assert_eq!(fetch(&EN, &FetchError::Parse(error)), expected);
        }
    }

    #[test]
    fn russian_subscription_errors_use_the_selected_table() {
        assert_eq!(
            fetch(&RU, &FetchError::Timeout),
            "сервер подписки не ответил вовремя"
        );
        assert_eq!(
            fetch(&RU, &FetchError::NotFound { sent_hwid: false }),
            "подписка не найдена; панели с лимитом устройств отвечают так же, если ID устройства не отправлен; включите «Отправлять ID устройства» и добавьте подписку снова"
        );
        assert_eq!(
            fetch(&RU, &FetchError::NotFound { sent_hwid: true }),
            "подписка не найдена; панели с лимитом устройств отвечают так же, если ID устройства не отправлен"
        );
        assert_eq!(
            fetch(&RU, &FetchError::Tls("bad certificate".into())),
            "ошибка TLS: bad certificate; так бывает, если антивирус проверяет HTTPS-трафик или на компьютере неверное время"
        );
        assert_eq!(
            subscription_url(&RU, &SubscriptionUrlError::UnsupportedScheme),
            "адрес подписки должен начинаться с http:// или https://"
        );
        assert_eq!(
            skip_reason(
                &RU,
                &SkipReason::UnsupportedTransport(UnsupportedTransport::Other)
            ),
            "неизвестный транспорт не поддерживается"
        );
        assert_eq!(
            fetch(&EN, &FetchError::NotFound { sent_hwid: false }),
            EN.errors.fetch_not_found_retry
        );
    }

    #[test]
    fn device_limit_announcement_keeps_provider_text() {
        let error = FetchError::Parse(ParseError::DeviceLimit {
            max_devices_reached: true,
            not_supported: true,
            announce: Some("Remove an old device".into()),
        });
        assert_eq!(
            fetch(&RU, &error),
            "достигнут лимит устройств; удалите старое устройство в панели провайдера\nобъявление провайдера: Remove an old device"
        );
        assert_eq!(
            fetch(&EN, &error),
            "device limit reached for this subscription; remove an old device in your provider's panel\nannounce: Remove an old device"
        );
        assert_eq!(
            parse(
                &RU,
                &ParseError::DeviceLimit {
                    max_devices_reached: false,
                    not_supported: true,
                    announce: None,
                }
            ),
            RU.errors.device_id_rejected
        );
    }

    #[test]
    fn no_usable_nodes_localizes_notices_and_grouped_reasons() {
        let error = FetchError::Parse(ParseError::NoUsableNodes {
            skipped: vec![
                Skipped {
                    index: 1,
                    scheme: None,
                    reason: SkipReason::ServiceRecord,
                },
                Skipped {
                    index: 2,
                    scheme: None,
                    reason: SkipReason::ServiceRecord,
                },
                Skipped {
                    index: 3,
                    scheme: Some("vless".into()),
                    reason: SkipReason::UnsupportedTransport(UnsupportedTransport::Xhttp),
                },
            ],
            notices: vec!["Subscription expired".into()],
        });
        assert_eq!(
            fetch(&RU, &error),
            "в подписке нет подходящих серверов\nуведомление провайдера: Subscription expired\nПропущено 1: транспорт xhttp не поддерживается\nПропущено 2: запись содержит уведомление провайдера"
        );
        assert_eq!(
            fetch(&EN, &error),
            "subscription contains no usable nodes\nnotice: Subscription expired\nSkipped 1: xhttp transport is not supported\nSkipped 2: record contains a provider notice"
        );
    }

    #[test]
    fn fetch_errors_use_sources_instead_of_cli_messages() {
        let error = FetchError::Timeout;
        assert_eq!(
            add_subscription(
                &RU,
                &AddFromUrlError::Fetch {
                    source: error,
                    message: "CLI only".into(),
                }
            ),
            RU.errors.fetch_timeout
        );
        assert_eq!(
            update_subscription(
                &RU,
                &UpdateSubscriptionError::Fetch {
                    source: FetchError::Timeout,
                    message: "CLI only".into(),
                }
            ),
            RU.errors.fetch_timeout
        );
    }

    #[test]
    fn russian_input_errors_use_plain_wording() {
        assert_eq!(
            rule_input(&RU, &RuleInputError::SingleLabel),
            "введите полный домен, например example.com; для зоны целиком используйте *.ru"
        );
        assert_eq!(
            dns_input(&RU, &DnsInputError::InvalidPort),
            "порт должен быть числом от 1 до 65535"
        );
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
    fn future_configuration_is_left_untouched_in_both_languages() {
        let error = StoreError::Invalid {
            path: "config.json".into(),
            source: ConfigError::UnsupportedVersion {
                found: 3,
                expected: 2,
            },
        };
        assert_eq!(store(&EN, &error), EN.errors.config_version);
        assert_eq!(store(&RU, &error), RU.errors.config_version);
        for language in [&EN, &RU] {
            let message = store(language, &error);
            assert!(message.contains("Rosetun"));
            assert!(!message.contains("{found}"));
            assert!(!message.contains("{expected}"));
        }
    }

    #[test]
    fn malformed_values_do_not_reveal_their_contents() {
        let path = std::env::temp_dir().join(format!(
            "rosetun-gui-invalid-value-{}.json",
            std::process::id()
        ));
        std::fs::write(
            &path,
            r#"{"version":1,"subscriptions":"https://sub.example.com/test-secret"}"#,
        )
        .unwrap();
        let error = Store::at(&path).load().unwrap_err();
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(error, StoreError::Format { .. }));
        for language in [&EN, &RU] {
            let message = store(language, &error);
            assert!(!message.contains("test-secret"));
            assert!(!message.contains("sub.example.com"));
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
            "unable to contact the Rosetun service: socket failed"
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
