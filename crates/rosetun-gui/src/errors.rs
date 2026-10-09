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
use crate::i18n::{Language, tr_in};
use crate::worker::{ConfigWorkerError, HelperCommandError};
use fluent_bundle::FluentArgs;

fn arguments<'a>(values: &[(&'a str, &'a str)]) -> FluentArgs<'a> {
    let mut args = FluentArgs::new();
    for &(name, value) in values {
        args.set(name, value);
    }
    args
}

fn skipped_arguments<'a>(count: usize, reason: &'a str) -> FluentArgs<'a> {
    let mut args = FluentArgs::new();
    args.set("count", count.to_string());
    args.set("reason", reason);
    args
}

pub(crate) fn store(language: Language, error: &StoreError) -> String {
    match error {
        StoreError::NoConfigDir => tr_in(language, "error-config-dir", &FluentArgs::new()),
        StoreError::Io { path, source } => tr_in(
            language,
            "error-config-access",
            &arguments(&[
                ("path", &path.display().to_string()),
                ("detail", &source.to_string()),
            ]),
        ),
        StoreError::Parse { path, source } => tr_in(
            language,
            "error-config-json",
            &arguments(&[
                ("path", &path.display().to_string()),
                ("line", &source.line().to_string()),
                ("column", &source.column().to_string()),
            ]),
        ),
        StoreError::Format { path } => tr_in(
            language,
            "error-config-invalid",
            &arguments(&[
                ("path", &path.display().to_string()),
                (
                    "detail",
                    &tr_in(language, "error-config-value", &FluentArgs::new()),
                ),
            ]),
        ),
        StoreError::Invalid {
            source: ConfigError::UnsupportedVersion { .. },
            ..
        } => tr_in(language, "error-config-version", &FluentArgs::new()),
        StoreError::Invalid { path, source } => tr_in(
            language,
            "error-config-invalid",
            &arguments(&[
                ("path", &path.display().to_string()),
                ("detail", &config(language, source)),
            ]),
        ),
    }
}

fn config(language: Language, error: &ConfigError) -> String {
    match error {
        ConfigError::UnsupportedVersion { .. } => {
            tr_in(language, "error-config-version", &FluentArgs::new())
        }
        ConfigError::DanglingSelection { subscription, node } => tr_in(
            language,
            "error-config-dangling-node",
            &arguments(&[
                ("subscription", subscription.as_str()),
                ("node", node.as_str()),
            ]),
        ),
        ConfigError::DanglingRuleSet(id) => tr_in(
            language,
            "error-config-dangling-rule-set",
            &arguments(&[("id", id.as_str())]),
        ),
    }
}

pub(crate) fn config_worker(language: Language, error: &ConfigWorkerError) -> String {
    match error {
        ConfigWorkerError::Store(error) => store(language, error),
        ConfigWorkerError::Metadata(error) => tr_in(
            language,
            "error-config-inspect",
            &arguments(&[("detail", &error.to_string())]),
        ),
    }
}

pub(crate) fn settings(language: Language, error: &SettingsError) -> String {
    match error {
        SettingsError::Store(error) => store(language, error),
        SettingsError::UnsupportedScale => {
            tr_in(language, "error-unsupported-scale", &FluentArgs::new())
        }
    }
}

pub(crate) fn rule_set(language: Language, error: &RuleSetError) -> String {
    match error {
        RuleSetError::Store(error) => store(language, error),
        RuleSetError::SetNotFound => {
            tr_in(language, "error-rule-set-not-found", &FluentArgs::new())
        }
        RuleSetError::RuleNotFound => tr_in(language, "error-rule-not-found", &FluentArgs::new()),
        RuleSetError::EmptyName => tr_in(language, "error-rule-set-name-empty", &FluentArgs::new()),
        RuleSetError::DuplicateRule => tr_in(language, "error-duplicate-rule", &FluentArgs::new()),
    }
}

pub(crate) fn rule_input(language: Language, error: &RuleInputError) -> String {
    match error {
        RuleInputError::InvalidDomain => {
            tr_in(language, "error-invalid-domain", &FluentArgs::new())
        }
        RuleInputError::IpAddress => tr_in(language, "error-domain-is-ip", &FluentArgs::new()),
        RuleInputError::SingleLabel => {
            tr_in(language, "error-single-label-domain", &FluentArgs::new())
        }
        RuleInputError::InvalidProcess => {
            tr_in(language, "error-invalid-process", &FluentArgs::new())
        }
        RuleInputError::RelativePath => tr_in(language, "error-relative-path", &FluentArgs::new()),
    }
}

pub(crate) fn dns_input(language: Language, error: &DnsInputError) -> String {
    match error {
        DnsInputError::InvalidServer => {
            tr_in(language, "error-invalid-resolver-ip", &FluentArgs::new())
        }
        DnsInputError::InvalidServerName => {
            tr_in(language, "error-invalid-resolver-name", &FluentArgs::new())
        }
        DnsInputError::InvalidPort => tr_in(language, "error-invalid-port", &FluentArgs::new()),
        DnsInputError::InvalidPath => tr_in(language, "error-invalid-dns-path", &FluentArgs::new()),
    }
}

pub(crate) fn select_node(language: Language, error: &SelectNodeError) -> String {
    match error {
        SelectNodeError::Store(error) => store(language, error),
        SelectNodeError::SubscriptionNotFound => {
            tr_in(language, "error-subscription-not-found", &FluentArgs::new())
        }
        SelectNodeError::NodeNotFound => {
            tr_in(language, "error-node-not-found", &FluentArgs::new())
        }
    }
}

pub(crate) fn select_rule_set(language: Language, error: &SelectRuleSetError) -> String {
    match error {
        SelectRuleSetError::Store(error) => store(language, error),
        SelectRuleSetError::NotFound => {
            tr_in(language, "error-rule-set-not-found", &FluentArgs::new())
        }
    }
}

pub(crate) fn subscription_url(language: Language, error: &SubscriptionUrlError) -> String {
    match error {
        SubscriptionUrlError::Invalid => tr_in(
            language,
            "error-invalid-subscription-url",
            &FluentArgs::new(),
        ),
        SubscriptionUrlError::MissingHost => {
            tr_in(language, "error-missing-host", &FluentArgs::new())
        }
        SubscriptionUrlError::EncryptedHappLink => {
            tr_in(language, "error-encrypted-happ-link", &FluentArgs::new())
        }
        SubscriptionUrlError::UnsupportedScheme => {
            tr_in(language, "error-url-scheme", &FluentArgs::new())
        }
        SubscriptionUrlError::InvalidImportLink => {
            tr_in(language, "error-import-link-invalid", &FluentArgs::new())
        }
        SubscriptionUrlError::ImportLinkWithoutUrl => tr_in(
            language,
            "error-import-link-without-url",
            &FluentArgs::new(),
        ),
        SubscriptionUrlError::ImportLinkWithMultipleUrls => tr_in(
            language,
            "error-import-link-multiple-urls",
            &FluentArgs::new(),
        ),
        SubscriptionUrlError::TooManyNestedLinks => {
            tr_in(language, "error-import-link-nested", &FluentArgs::new())
        }
    }
    .to_owned()
}

pub(crate) fn fetch(language: Language, error: &FetchError) -> String {
    match error {
        FetchError::InvalidUrl => tr_in(
            language,
            "error-invalid-subscription-url",
            &FluentArgs::new(),
        ),
        FetchError::InvalidUserAgent => {
            tr_in(language, "error-fetch-user-agent", &FluentArgs::new())
        }
        FetchError::InvalidDeviceId => tr_in(language, "error-fetch-device-id", &FluentArgs::new()),
        FetchError::RequestFailed => tr_in(language, "error-fetch-failed", &FluentArgs::new()),
        FetchError::Timeout => tr_in(language, "error-fetch-timeout", &FluentArgs::new()),
        FetchError::HostNotFound => {
            tr_in(language, "error-fetch-host-not-found", &FluentArgs::new())
        }
        FetchError::ConnectionFailed => {
            tr_in(language, "error-fetch-connection", &FluentArgs::new())
        }
        FetchError::TooManyRedirects => {
            tr_in(language, "error-fetch-redirects", &FluentArgs::new())
        }
        FetchError::InsecureRedirect => tr_in(
            language,
            "error-fetch-insecure-redirect",
            &FluentArgs::new(),
        ),
        FetchError::Tls(detail) => tr_in(
            language,
            "error-fetch-tls",
            &arguments(&[("detail", detail)]),
        ),
        FetchError::ResponseTooLarge => {
            tr_in(language, "error-fetch-too-large", &FluentArgs::new())
        }
        FetchError::BodyReadFailed => tr_in(language, "error-fetch-body", &FluentArgs::new()),
        FetchError::NotFound { sent_hwid: true } => {
            tr_in(language, "error-fetch-not-found", &FluentArgs::new())
        }
        FetchError::NotFound { sent_hwid: false } => {
            tr_in(language, "error-fetch-not-found-retry", &FluentArgs::new())
        }
        FetchError::AccessDenied => {
            tr_in(language, "error-fetch-access-denied", &FluentArgs::new())
        }
        FetchError::HttpStatus(status) => tr_in(
            language,
            "error-fetch-http-status",
            &arguments(&[("status", &status.to_string())]),
        ),
        FetchError::Parse(error) => parse(language, error),
    }
}

fn parse(language: Language, error: &ParseError) -> String {
    match error {
        ParseError::Empty => tr_in(language, "error-parse-empty", &FluentArgs::new()),
        ParseError::WebPage => tr_in(language, "error-parse-web-page", &FluentArgs::new()),
        ParseError::UnsupportedFormat => tr_in(
            language,
            "error-parse-unsupported-format",
            &FluentArgs::new(),
        ),
        ParseError::EncryptedHappLink => {
            tr_in(language, "error-encrypted-happ-link", &FluentArgs::new())
        }
        ParseError::UnrecognizedFormat => tr_in(
            language,
            "error-parse-unrecognized-format",
            &FluentArgs::new(),
        ),
        ParseError::InvalidUtf8 => tr_in(language, "error-parse-invalid-utf8", &FluentArgs::new()),
        ParseError::InvalidJson { line, column } => tr_in(
            language,
            "error-parse-invalid-json",
            &arguments(&[("line", &line.to_string()), ("column", &column.to_string())]),
        ),
        ParseError::DeviceLimit {
            max_devices_reached,
            not_supported,
            announce,
        } => {
            let title = if *max_devices_reached {
                tr_in(language, "error-device-limit-reached", &FluentArgs::new())
            } else if *not_supported {
                tr_in(language, "error-device-id-rejected", &FluentArgs::new())
            } else {
                tr_in(language, "error-device-policy", &FluentArgs::new())
            };
            let mut output = title.to_owned();
            if let Some(text) = announce {
                output.push('\n');
                output.push_str(&tr_in(
                    language,
                    "error-provider-announce",
                    &arguments(&[("text", text)]),
                ));
            }
            output
        }
        ParseError::NoUsableNodes { skipped, notices } => {
            let mut output = tr_in(language, "error-no-usable-nodes", &FluentArgs::new());
            for text in notices {
                output.push('\n');
                output.push_str(&tr_in(
                    language,
                    "error-provider-notice",
                    &arguments(&[("text", text)]),
                ));
            }
            for (reason, count) in rosetun_core::group_skipped(skipped) {
                output.push('\n');
                output.push_str(&tr_in(
                    language,
                    "skipped-summary",
                    &skipped_arguments(count, &skip_reason(language, &reason)),
                ));
            }
            output
        }
    }
}

pub(crate) fn skip_reason(language: Language, reason: &SkipReason) -> String {
    match reason {
        SkipReason::InvalidRecord => {
            tr_in(language, "error-skip-invalid-record", &FluentArgs::new())
        }
        SkipReason::InvalidPort => tr_in(language, "error-skip-invalid-port", &FluentArgs::new()),
        SkipReason::MissingField => tr_in(language, "error-skip-missing-field", &FluentArgs::new()),
        SkipReason::InvalidJson { line, column } => tr_in(
            language,
            "error-skip-invalid-json",
            &arguments(&[("line", &line.to_string()), ("column", &column.to_string())]),
        ),
        SkipReason::UnsupportedProtocol => tr_in(
            language,
            "error-skip-unsupported-protocol",
            &FluentArgs::new(),
        ),
        SkipReason::ClientSettings => {
            tr_in(language, "error-skip-client-settings", &FluentArgs::new())
        }
        SkipReason::UnsupportedVmessFormat => {
            tr_in(language, "error-skip-vmess-format", &FluentArgs::new())
        }
        SkipReason::UnsupportedTransport(UnsupportedTransport::Other) => {
            tr_in(language, "error-skip-unknown-transport", &FluentArgs::new())
        }
        SkipReason::UnsupportedTransport(
            transport @ (UnsupportedTransport::Xhttp
            | UnsupportedTransport::SplitHttp
            | UnsupportedTransport::Kcp
            | UnsupportedTransport::Quic
            | UnsupportedTransport::H2
            | UnsupportedTransport::Http),
        ) => tr_in(
            language,
            "error-skip-transport",
            &arguments(&[("transport", &transport.to_string())]),
        ),
        SkipReason::UnsupportedTcpHeader => {
            tr_in(language, "error-skip-tcp-header", &FluentArgs::new())
        }
        SkipReason::UnsupportedGrpcMultiMode => {
            tr_in(language, "error-skip-grpc-multi-mode", &FluentArgs::new())
        }
        SkipReason::UnsupportedEncryption => {
            tr_in(language, "error-skip-encryption", &FluentArgs::new())
        }
        SkipReason::UnsupportedFlow => tr_in(language, "error-skip-flow", &FluentArgs::new()),
        SkipReason::UnsupportedSecurity => {
            tr_in(language, "error-skip-security", &FluentArgs::new())
        }
        SkipReason::MissingRealityPublicKey => {
            tr_in(language, "error-skip-reality-key", &FluentArgs::new())
        }
        SkipReason::ShadowsocksPlugin => tr_in(
            language,
            "error-skip-shadowsocks-plugin",
            &FluentArgs::new(),
        ),
        SkipReason::UnsupportedShadowsocksMethod => tr_in(
            language,
            "error-skip-shadowsocks-method",
            &FluentArgs::new(),
        ),
        SkipReason::UnsupportedObfs => {
            tr_in(language, "error-skip-unsupported-obfs", &FluentArgs::new())
        }
        SkipReason::UnsupportedPin => {
            tr_in(language, "error-skip-unsupported-pin", &FluentArgs::new())
        }
        SkipReason::ServiceRecord => {
            tr_in(language, "error-skip-service-record", &FluentArgs::new())
        }
    }
}

pub(crate) fn add_subscription(language: Language, error: &AddFromUrlError) -> String {
    match error {
        AddFromUrlError::Url(error) => subscription_url(language, error),
        AddFromUrlError::Store(error) => store(language, error),
        AddFromUrlError::AlreadyExists(id) => tr_in(
            language,
            "error-already-added",
            &arguments(&[("id", &rosetun_core::terminal_text(id.as_str()))]),
        ),
        AddFromUrlError::InvalidUrl(_) => tr_in(
            language,
            "error-invalid-subscription-url",
            &FluentArgs::new(),
        ),
        AddFromUrlError::MissingHost => tr_in(language, "error-missing-host", &FluentArgs::new()),
        AddFromUrlError::Fetch { source, .. } => fetch(language, source),
        AddFromUrlError::Clock(_) => {
            tr_in(language, "error-clock-before-epoch", &FluentArgs::new())
        }
        AddFromUrlError::Commit(error) => match error {
            AddSubscriptionError::Store(error) => store(language, error),
            AddSubscriptionError::AlreadyExists => {
                tr_in(language, "error-url-already-added", &FluentArgs::new())
            }
            AddSubscriptionError::IdExhausted => {
                tr_in(language, "error-ids-exhausted", &FluentArgs::new())
            }
        },
    }
}

pub(crate) fn update_subscription(language: Language, error: &UpdateSubscriptionError) -> String {
    match error {
        UpdateSubscriptionError::Store(error) => store(language, error),
        UpdateSubscriptionError::NotFound => {
            tr_in(language, "error-subscription-not-found", &FluentArgs::new())
        }
        UpdateSubscriptionError::Fetch { source, .. } => fetch(language, source),
        UpdateSubscriptionError::RequestSettingsChanged => tr_in(
            language,
            "error-request-settings-changed",
            &FluentArgs::new(),
        ),
        UpdateSubscriptionError::Clock(_) => {
            tr_in(language, "error-clock-before-epoch", &FluentArgs::new())
        }
    }
}

pub(crate) fn remove_subscription(language: Language, error: &RemoveSubscriptionError) -> String {
    match error {
        RemoveSubscriptionError::Store(error) => store(language, error),
        RemoveSubscriptionError::SubscriptionNotFound => {
            tr_in(language, "error-subscription-not-found", &FluentArgs::new())
        }
    }
}

pub(crate) fn rename_subscription(language: Language, error: &RenameSubscriptionError) -> String {
    match error {
        RenameSubscriptionError::Store(error) => store(language, error),
        RenameSubscriptionError::NotFound => {
            tr_in(language, "error-subscription-not-found", &FluentArgs::new())
        }
        RenameSubscriptionError::EmptyName => tr_in(
            language,
            "error-subscription-name-empty",
            &FluentArgs::new(),
        ),
    }
}

pub(crate) fn move_subscription(language: Language, error: &MoveSubscriptionError) -> String {
    match error {
        MoveSubscriptionError::Store(error) => store(language, error),
        MoveSubscriptionError::NotFound => {
            tr_in(language, "error-subscription-not-found", &FluentArgs::new())
        }
    }
}

pub(crate) fn process_list(language: Language, error: &ProcessListError) -> String {
    match error {
        ProcessListError::Snapshot(error) => tr_in(
            language,
            "error-process-list",
            &arguments(&[("detail", &error.to_string())]),
        ),
    }
}

pub(crate) fn connect_request(language: Language, error: &ConnectRequestError) -> String {
    match error {
        ConnectRequestError::SelectionMissing | ConnectRequestError::NodeNotFound => {
            tr_in(language, "select-server", &FluentArgs::new())
        }
        ConnectRequestError::RuleSetNotFound => tr_in(
            language,
            "error-selected-rule-set-missing",
            &FluentArgs::new(),
        ),
    }
}

pub(crate) fn client(language: Language, error: &ClientError) -> String {
    let message = match error {
        ClientError::Transport(detail) => tr_in(
            language,
            "error-helper-transport",
            &arguments(&[("detail", detail)]),
        ),
        ClientError::Unexpected => tr_in(language, "error-helper-unexpected", &FluentArgs::new()),
        ClientError::Closed => tr_in(language, "error-helper-closed", &FluentArgs::new()),
        ClientError::Helper(error) => {
            let title = match error.code {
                ErrorCode::ProtocolMismatch => {
                    tr_in(language, "error-code-protocol-mismatch", &FluentArgs::new())
                }
                ErrorCode::HandshakeRequired => tr_in(
                    language,
                    "error-code-handshake-required",
                    &FluentArgs::new(),
                ),
                ErrorCode::NotPrivileged => {
                    tr_in(language, "error-code-not-privileged", &FluentArgs::new())
                }
                ErrorCode::EngineFailed => {
                    tr_in(language, "error-code-engine-failed", &FluentArgs::new())
                }
                ErrorCode::ServerUnreachable => tr_in(
                    language,
                    "error-code-server-unreachable",
                    &FluentArgs::new(),
                ),
                ErrorCode::ServerRejected => {
                    tr_in(language, "error-code-server-rejected", &FluentArgs::new())
                }
                ErrorCode::ServerClosed => {
                    tr_in(language, "error-code-server-closed", &FluentArgs::new())
                }
                ErrorCode::DnsTimeout => {
                    tr_in(language, "error-code-dns-timeout", &FluentArgs::new())
                }
                ErrorCode::Cancelled => tr_in(language, "error-code-cancelled", &FluentArgs::new()),
                ErrorCode::EngineNotReady => {
                    tr_in(language, "error-code-engine-not-ready", &FluentArgs::new())
                }
                ErrorCode::RoutingFailed => {
                    tr_in(language, "error-code-routing-failed", &FluentArgs::new())
                }
                ErrorCode::Busy => tr_in(language, "error-code-busy", &FluentArgs::new()),
                ErrorCode::InvalidState => {
                    tr_in(language, "error-code-invalid-state", &FluentArgs::new())
                }
                ErrorCode::UnsupportedRules => {
                    tr_in(language, "error-code-unsupported-rules", &FluentArgs::new())
                }
                ErrorCode::NotImplemented => {
                    tr_in(language, "error-code-not-implemented", &FluentArgs::new())
                }
                ErrorCode::Internal => tr_in(language, "error-code-internal", &FluentArgs::new()),
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

pub(crate) fn helper_command(language: Language, error: &HelperCommandError) -> String {
    match error {
        HelperCommandError::Store(error) => store(language, error),
        HelperCommandError::Request(error) => connect_request(language, error),
        HelperCommandError::Client(error) => client(language, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rosetun_core::{Skipped, Store};
    use rosetun_ipc::HelperError;

    #[test]
    fn duplicate_rule_uses_the_selected_table() {
        let error = RuleSetError::DuplicateRule;
        assert_eq!(
            rule_set(Language::English, &error),
            "this rule is already in the set"
        );
        assert_eq!(
            rule_set(Language::Russian, &error),
            "такое правило уже есть в наборе"
        );
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
            assert_eq!(
                subscription_url(Language::English, &error),
                error.to_string()
            );
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
            assert_eq!(skip_reason(Language::English, &reason), reason.to_string());
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
            assert_eq!(skip_reason(Language::English, &reason), reason.to_string());
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
            assert_eq!(fetch(Language::English, &error), error.to_string());
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
            assert_eq!(parse(Language::English, &error), expected);
            assert_eq!(
                fetch(Language::English, &FetchError::Parse(error)),
                expected
            );
        }
    }

    #[test]
    fn russian_subscription_errors_use_the_selected_table() {
        assert_eq!(
            fetch(Language::Russian, &FetchError::Timeout),
            "сервер подписки не ответил вовремя"
        );
        assert_eq!(
            fetch(
                Language::Russian,
                &FetchError::NotFound { sent_hwid: false }
            ),
            "подписка не найдена; панели с лимитом устройств отвечают так же, если ID устройства не отправлен; включите «Отправлять ID устройства» и добавьте подписку снова"
        );
        assert_eq!(
            fetch(Language::Russian, &FetchError::NotFound { sent_hwid: true }),
            "подписка не найдена; панели с лимитом устройств отвечают так же, если ID устройства не отправлен"
        );
        assert_eq!(
            fetch(
                Language::Russian,
                &FetchError::Tls("bad certificate".into())
            ),
            "ошибка TLS: bad certificate; так бывает, если антивирус проверяет HTTPS-трафик или на компьютере неверное время"
        );
        assert_eq!(
            subscription_url(Language::Russian, &SubscriptionUrlError::UnsupportedScheme),
            "адрес подписки должен начинаться с http:// или https://"
        );
        assert_eq!(
            skip_reason(
                Language::Russian,
                &SkipReason::UnsupportedTransport(UnsupportedTransport::Other)
            ),
            "неизвестный транспорт не поддерживается"
        );
        assert_eq!(
            fetch(
                Language::English,
                &FetchError::NotFound { sent_hwid: false }
            ),
            tr_in(
                Language::English,
                "error-fetch-not-found-retry",
                &FluentArgs::new()
            )
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
            fetch(Language::Russian, &error),
            "достигнут лимит устройств; удалите старое устройство в панели провайдера\nобъявление провайдера: Remove an old device"
        );
        assert_eq!(
            fetch(Language::English, &error),
            "device limit reached for this subscription; remove an old device in your provider's panel\nannounce: Remove an old device"
        );
        assert_eq!(
            parse(
                Language::Russian,
                &ParseError::DeviceLimit {
                    max_devices_reached: false,
                    not_supported: true,
                    announce: None,
                }
            ),
            tr_in(
                Language::Russian,
                "error-device-id-rejected",
                &FluentArgs::new()
            )
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
            fetch(Language::Russian, &error),
            "в подписке нет подходящих серверов\nуведомление провайдера: Subscription expired\nПропущено 1: транспорт xhttp не поддерживается\nПропущено 2: запись содержит уведомление провайдера"
        );
        assert_eq!(
            fetch(Language::English, &error),
            "subscription contains no usable nodes\nnotice: Subscription expired\nSkipped 1: xhttp transport is not supported\nSkipped 2: record contains a provider notice"
        );
    }

    #[test]
    fn fetch_errors_use_sources_instead_of_cli_messages() {
        let error = FetchError::Timeout;
        assert_eq!(
            add_subscription(
                Language::Russian,
                &AddFromUrlError::Fetch {
                    source: error,
                    message: "CLI only".into(),
                }
            ),
            tr_in(Language::Russian, "error-fetch-timeout", &FluentArgs::new())
        );
        assert_eq!(
            update_subscription(
                Language::Russian,
                &UpdateSubscriptionError::Fetch {
                    source: FetchError::Timeout,
                    message: "CLI only".into(),
                }
            ),
            tr_in(Language::Russian, "error-fetch-timeout", &FluentArgs::new())
        );
    }

    #[test]
    fn russian_input_errors_use_plain_wording() {
        assert_eq!(
            rule_input(Language::Russian, &RuleInputError::SingleLabel),
            "введите полный домен, например example.com; для зоны целиком используйте *.ru"
        );
        assert_eq!(
            dns_input(Language::Russian, &DnsInputError::InvalidPort),
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
        let en = store(Language::English, &error);
        let ru = store(Language::Russian, &error);
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
        assert_eq!(
            store(Language::English, &error),
            tr_in(
                Language::English,
                "error-config-version",
                &FluentArgs::new()
            )
        );
        assert_eq!(
            store(Language::Russian, &error),
            tr_in(
                Language::Russian,
                "error-config-version",
                &FluentArgs::new()
            )
        );
        for language in [Language::English, Language::Russian] {
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
        for language in [Language::English, Language::Russian] {
            let message = store(language, &error);
            assert!(!message.contains("test-secret"));
            assert!(!message.contains("sub.example.com"));
        }
    }

    #[test]
    fn helper_codes_use_localized_titles_and_preserve_details() {
        let error = ClientError::Helper(HelperError::new(ErrorCode::EngineFailed, "boom"));
        assert_eq!(client(Language::English, &error), "the engine failed: boom");
        assert_eq!(client(Language::Russian, &error), "сбой ядра: boom");
        let empty = ClientError::Helper(HelperError::new(ErrorCode::EngineFailed, ""));
        assert_eq!(client(Language::English, &empty), "the engine failed");
        assert_eq!(client(Language::Russian, &empty), "сбой ядра");
        let transport = ClientError::Transport("x".to_owned());
        assert_eq!(
            client(Language::Russian, &transport),
            "нет связи со службой: x"
        );
        let unsafe_detail = ClientError::Transport("socket\u{202e}failed".to_owned());
        assert_eq!(
            client(Language::English, &unsafe_detail),
            "unable to contact the Rosetun service: socket failed"
        );
    }

    #[test]
    fn missing_selection_uses_the_regular_interface_string() {
        assert_eq!(
            connect_request(Language::Russian, &ConnectRequestError::SelectionMissing),
            tr_in(Language::Russian, "select-server", &FluentArgs::new())
        );
        assert_eq!(
            connect_request(Language::English, &ConnectRequestError::RuleSetNotFound),
            "the selected rule set does not exist"
        );
    }
}
