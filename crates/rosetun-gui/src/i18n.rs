use std::collections::HashSet;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

use fluent_bundle::concurrent::FluentBundle;
use fluent_bundle::{FluentArgs, FluentResource};
use rosetun_config::LanguageSetting;

macro_rules! tr {
    ($key:literal $(,)?) => {
        $crate::i18n::tr_in($crate::i18n::language(), $key, &fluent_bundle::FluentArgs::new())
    };
    ($key:literal, $($name:ident = $value:expr),+ $(,)?) => {{
        let mut args = fluent_bundle::FluentArgs::new();
        $(args.set(stringify!($name), $value);)+
        $crate::i18n::tr_in($crate::i18n::language(), $key, &args)
    }};
}

mod format;
#[allow(unused_imports)] // The helpers become call sites as the GUI migrates.
pub(crate) use format::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Language {
    English,
    Russian,
}

static CURRENT: AtomicU8 = AtomicU8::new(0);
static ENGLISH: OnceLock<FluentBundle<FluentResource>> = OnceLock::new();
static RUSSIAN: OnceLock<FluentBundle<FluentResource>> = OnceLock::new();
static WARNED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

#[cfg(test)]
thread_local! {
    static TEST_LANGUAGE: std::cell::Cell<Option<Language>> = const { std::cell::Cell::new(None) };
}

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
    #[cfg(test)]
    if let Some(language) = TEST_LANGUAGE.with(std::cell::Cell::get) {
        return language;
    }
    match CURRENT.load(Ordering::Relaxed) {
        1 => Language::Russian,
        _ => Language::English,
    }
}

pub(crate) fn resolve_language(setting: LanguageSetting, system_russian: bool) -> Language {
    match setting {
        LanguageSetting::System if system_russian => Language::Russian,
        LanguageSetting::System | LanguageSetting::English => Language::English,
        LanguageSetting::Russian => Language::Russian,
    }
}

fn bundle(language: Language) -> &'static FluentBundle<FluentResource> {
    let (cell, name, source) = match language {
        Language::English => (&ENGLISH, "en", include_str!("../i18n/en.ftl")),
        Language::Russian => (&RUSSIAN, "ru", include_str!("../i18n/ru.ftl")),
    };
    cell.get_or_init(|| {
        let resource = FluentResource::try_new(source.to_owned())
            .unwrap_or_else(|(_, errors)| panic!("Invalid embedded {name}.ftl: {errors:?}"));
        let locale = name.parse().expect("Valid embedded language identifier");
        let mut bundle = FluentBundle::new_concurrent(vec![locale]);
        bundle.set_use_isolating(false);
        bundle
            .add_resource(resource)
            .unwrap_or_else(|errors| panic!("Could not load embedded {name}.ftl: {errors:?}"));
        bundle
    })
}

fn format(language: Language, key: &str, args: &FluentArgs<'_>) -> Option<String> {
    let bundle = bundle(language);
    let pattern = bundle.get_message(key)?.value()?;
    let mut errors = Vec::new();
    let text = bundle.format_pattern(pattern, Some(args), &mut errors);
    errors.is_empty().then(|| text.into_owned())
}

pub(crate) fn tr_in(language: Language, key: &str, args: &FluentArgs<'_>) -> String {
    if let Some(text) = format(language, key, args) {
        return text;
    }
    debug_assert!(false, "Missing or invalid Fluent message: {key}");
    let warned = WARNED.get_or_init(|| Mutex::new(HashSet::new()));
    if warned
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .insert(key.to_owned())
    {
        tracing::warn!(key, "Could not format interface text");
    }
    format(Language::English, key, args).unwrap_or_else(|| key.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn embedded_messages_are_available_from_both_threads() {
        let worker =
            std::thread::spawn(|| tr_in(Language::Russian, "connection", &FluentArgs::new()));
        assert_eq!(
            tr_in(Language::English, "connection", &FluentArgs::new()),
            "Connection"
        );
        assert_eq!(worker.join().unwrap(), "Подключение");
    }

    #[test]
    fn old_and_fluent_helpers_match_exactly() {
        use crate::strings::{EN, RU};
        use rosetun_config::{ConnectStage, FailureKind, RuleTemplate};

        for (selected, old) in [(Language::English, &EN), (Language::Russian, &RU)] {
            TEST_LANGUAGE.with(|slot| slot.set(Some(selected)));
            for sample in ["example.com", "D:\\Example", "1,5 МБ/с", "{retry} · {name}"] {
                assert_eq!(about_version(sample, None), old.about_version(sample, None));
                assert_eq!(
                    about_version(sample, Some("0.9.1")),
                    old.about_version(sample, Some("0.9.1"))
                );
                assert_eq!(update_available(sample), old.update_available(sample));
                assert_eq!(update_skipped(sample), old.update_skipped(sample));
                assert_eq!(update_checked(sample), old.update_checked(sample));
                assert_eq!(update_last_checked(sample), old.update_last_checked(sample));
                assert_eq!(
                    update_skipped_detail(sample),
                    old.update_skipped_detail(sample)
                );
                assert_eq!(connected_in(sample), old.connected_in(sample));
                assert_eq!(stored_as(sample), old.stored_as(sample));
                assert_eq!(engine_detail(sample), old.engine_detail(sample));
                assert_eq!(last_updated(sample), old.last_updated(sample));
                assert_eq!(
                    traffic_rates(sample, sample),
                    old.traffic_rates(sample, sample)
                );
                assert_eq!(
                    traffic_chart_caption(sample, sample),
                    old.traffic_chart_caption(sample, sample)
                );
                assert_eq!(switching_to(sample), old.switching_to(sample));
                assert_eq!(
                    selected_not_applied(sample),
                    old.selected_not_applied(sample)
                );
                assert_eq!(apply_failed(sample), old.apply_failed(sample));
                assert_eq!(selected_pending(sample), old.selected_pending(sample));
                assert_eq!(skipped(2, sample), old.skipped(2, sample));
                assert_eq!(helper_version(sample), old.helper_version(sample));
                assert_eq!(other_vpn(sample), old.other_vpn(sample));
                assert_eq!(traffic_tool(sample), old.traffic_tool(sample));
                assert_eq!(line_error(2, sample), old.line_error(2, sample));
            }
            for template in [
                RuleTemplate::RussianSites,
                RuleTemplate::Messengers,
                RuleTemplate::Youtube,
                RuleTemplate::Torrents,
            ] {
                assert_eq!(template_name(template), old.template_name(template));
                assert_eq!(
                    template_description(template),
                    old.template_description(template)
                );
            }
            for count in [0, 1, 2, 3, 4, 5, 11, 12, 21, 22, 25, 101, 111, 1000, 12345] {
                assert_eq!(all_processes(count), old.all_processes(count));
                assert_eq!(found(count), old.found(count));
                assert_eq!(more_errors(count), old.more_errors(count));
                assert_eq!(selected_rule_count(count), old.selected_rule_count(count));
                assert_eq!(
                    delete_selected_rules(count),
                    old.delete_selected_rules(count)
                );
                assert_eq!(delete_rules_heading(count), old.delete_rules_heading(count));
                assert_eq!(and_more_rules(count), old.and_more_rules(count));
                assert_eq!(add_rules(count), old.add_rules(count));
                assert_eq!(servers(count), old.servers(count));
                assert_eq!(temporary_count(count), old.temporary_count(count));
                assert_eq!(more_rules(count), old.more_rules(count));
                assert_eq!(updated(count, 1, count), old.updated(count, 1, count));
                assert_eq!(
                    verbose_log_on_detail(count as u64),
                    old.verbose_log_on_detail(count as u64)
                );
                assert_eq!(
                    term_left(count as u64 * 86_400, 0),
                    old.term_left(count as u64 * 86_400, 0)
                );
                assert_eq!(bytes(count as u64 * 1024), old.bytes(count as u64 * 1024));
                assert_eq!(rate(count as u64 * 1024), old.rate(count as u64 * 1024));
                for stage in [
                    ConnectStage::WaitingForAdapter,
                    ConnectStage::StartingEngine,
                    ConnectStage::CheckingServer,
                ] {
                    assert_eq!(
                        connection_stage(stage, count as u64),
                        old.connection_stage(stage, count as u64)
                    );
                }
                assert_eq!(
                    updated_ago(0, count as u64 * 60),
                    old.updated_ago(0, count as u64 * 60)
                );
            }
            for failure in [
                FailureKind::EngineNotReady,
                FailureKind::ServerUnreachable,
                FailureKind::ServerRejected,
                FailureKind::ServerClosed,
                FailureKind::DnsTimeout,
            ] {
                let (old_title, old_hint) = old.connection_failure(failure);
                assert_eq!(
                    connection_failure(failure),
                    (old_title.to_owned(), old_hint)
                );
            }
        }
        TEST_LANGUAGE.with(|slot| slot.set(None));
    }

    #[test]
    fn old_and_fluent_plural_forms_match_exactly() {
        use crate::strings::{EN, RU};
        for count in [0, 1, 2, 3, 4, 5, 11, 12, 21, 22, 25, 101, 111, 1000, 12345] {
            let mut args = FluentArgs::new();
            args.set("count", count);
            args.set("n", count.to_string());
            for (language, old) in [(Language::English, &EN), (Language::Russian, &RU)] {
                assert_eq!(
                    tr_in(language, "servers", &args),
                    old.servers(count),
                    "servers {language:?} {count}"
                );
                assert_eq!(
                    tr_in(language, "add-rules", &args),
                    old.add_rules(count),
                    "add-rules {language:?} {count}"
                );
                assert_eq!(
                    tr_in(language, "more-rules", &args),
                    old.more_rules(count),
                    "more-rules {language:?} {count}"
                );
                let rules = tr_in(language, "rule-count", &args);
                let mut heading = FluentArgs::new();
                heading.set("n", count.to_string());
                heading.set("rules", rules);
                assert_eq!(
                    tr_in(language, "delete-rules-heading", &heading),
                    old.delete_rules_heading(count)
                );
                let hours = tr_in(language, "verbose-hours", &args);
                let mut detail = FluentArgs::new();
                detail.set("hours", hours);
                assert_eq!(
                    tr_in(language, "verbose-log-on-detail", &detail),
                    old.verbose_log_on_detail(count as u64)
                );
                let unit = tr_in(language, "term-day-unit", &args);
                let mut remaining = FluentArgs::new();
                remaining.set("days", count.to_string());
                remaining.set("unit", unit);
                if count > 0 {
                    assert_eq!(
                        tr_in(language, "term-left-template", &remaining),
                        old.term_left(count as u64 * 86_400, 0).0
                    );
                }
            }
        }
    }

    #[test]
    fn old_and_fluent_table_fields_match_exactly() {
        use crate::strings::{EN, RU};
        let mut cases = vec![
            (
                EN.errors.config_dir,
                RU.errors.config_dir,
                "error-config-dir",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.config_access,
                RU.errors.config_access,
                "error-config-access",
                &[("detail", "{detail}"), ("path", "{path}")] as &[(&str, &str)],
            ),
            (
                EN.errors.config_json,
                RU.errors.config_json,
                "error-config-json",
                &[
                    ("column", "{column}"),
                    ("line", "{line}"),
                    ("path", "{path}"),
                ] as &[(&str, &str)],
            ),
            (
                EN.errors.config_invalid,
                RU.errors.config_invalid,
                "error-config-invalid",
                &[("detail", "{detail}"), ("path", "{path}")] as &[(&str, &str)],
            ),
            (
                EN.errors.config_value,
                RU.errors.config_value,
                "error-config-value",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.config_version,
                RU.errors.config_version,
                "error-config-version",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.config_dangling_node,
                RU.errors.config_dangling_node,
                "error-config-dangling-node",
                &[("node", "{node}"), ("subscription", "{subscription}")] as &[(&str, &str)],
            ),
            (
                EN.errors.config_dangling_rule_set,
                RU.errors.config_dangling_rule_set,
                "error-config-dangling-rule-set",
                &[("id", "{id}")] as &[(&str, &str)],
            ),
            (
                EN.errors.config_inspect,
                RU.errors.config_inspect,
                "error-config-inspect",
                &[("detail", "{detail}")] as &[(&str, &str)],
            ),
            (
                EN.errors.unsupported_scale,
                RU.errors.unsupported_scale,
                "error-unsupported-scale",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.rule_set_not_found,
                RU.errors.rule_set_not_found,
                "error-rule-set-not-found",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.rule_not_found,
                RU.errors.rule_not_found,
                "error-rule-not-found",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.rule_set_name_empty,
                RU.errors.rule_set_name_empty,
                "error-rule-set-name-empty",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.duplicate_rule,
                RU.errors.duplicate_rule,
                "error-duplicate-rule",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.selected_rule_set_missing,
                RU.errors.selected_rule_set_missing,
                "error-selected-rule-set-missing",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.invalid_domain,
                RU.errors.invalid_domain,
                "error-invalid-domain",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.domain_is_ip,
                RU.errors.domain_is_ip,
                "error-domain-is-ip",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.single_label_domain,
                RU.errors.single_label_domain,
                "error-single-label-domain",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.invalid_process,
                RU.errors.invalid_process,
                "error-invalid-process",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.relative_path,
                RU.errors.relative_path,
                "error-relative-path",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.invalid_resolver_ip,
                RU.errors.invalid_resolver_ip,
                "error-invalid-resolver-ip",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.invalid_resolver_name,
                RU.errors.invalid_resolver_name,
                "error-invalid-resolver-name",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.invalid_port,
                RU.errors.invalid_port,
                "error-invalid-port",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.invalid_dns_path,
                RU.errors.invalid_dns_path,
                "error-invalid-dns-path",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.subscription_not_found,
                RU.errors.subscription_not_found,
                "error-subscription-not-found",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.subscription_name_empty,
                RU.errors.subscription_name_empty,
                "error-subscription-name-empty",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.node_not_found,
                RU.errors.node_not_found,
                "error-node-not-found",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.request_settings_changed,
                RU.errors.request_settings_changed,
                "error-request-settings-changed",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.clock_before_epoch,
                RU.errors.clock_before_epoch,
                "error-clock-before-epoch",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.already_added,
                RU.errors.already_added,
                "error-already-added",
                &[("id", "{id}")] as &[(&str, &str)],
            ),
            (
                EN.errors.url_already_added,
                RU.errors.url_already_added,
                "error-url-already-added",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.ids_exhausted,
                RU.errors.ids_exhausted,
                "error-ids-exhausted",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.invalid_subscription_url,
                RU.errors.invalid_subscription_url,
                "error-invalid-subscription-url",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.missing_host,
                RU.errors.missing_host,
                "error-missing-host",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.encrypted_happ_link,
                RU.errors.encrypted_happ_link,
                "error-encrypted-happ-link",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.url_scheme,
                RU.errors.url_scheme,
                "error-url-scheme",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.import_link_invalid,
                RU.errors.import_link_invalid,
                "error-import-link-invalid",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.import_link_without_url,
                RU.errors.import_link_without_url,
                "error-import-link-without-url",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.import_link_multiple_urls,
                RU.errors.import_link_multiple_urls,
                "error-import-link-multiple-urls",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.import_link_nested,
                RU.errors.import_link_nested,
                "error-import-link-nested",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.fetch_user_agent,
                RU.errors.fetch_user_agent,
                "error-fetch-user-agent",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.fetch_device_id,
                RU.errors.fetch_device_id,
                "error-fetch-device-id",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.fetch_failed,
                RU.errors.fetch_failed,
                "error-fetch-failed",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.fetch_timeout,
                RU.errors.fetch_timeout,
                "error-fetch-timeout",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.fetch_host_not_found,
                RU.errors.fetch_host_not_found,
                "error-fetch-host-not-found",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.fetch_connection,
                RU.errors.fetch_connection,
                "error-fetch-connection",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.fetch_redirects,
                RU.errors.fetch_redirects,
                "error-fetch-redirects",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.fetch_insecure_redirect,
                RU.errors.fetch_insecure_redirect,
                "error-fetch-insecure-redirect",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.fetch_tls,
                RU.errors.fetch_tls,
                "error-fetch-tls",
                &[("detail", "{detail}")] as &[(&str, &str)],
            ),
            (
                EN.errors.fetch_too_large,
                RU.errors.fetch_too_large,
                "error-fetch-too-large",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.fetch_body,
                RU.errors.fetch_body,
                "error-fetch-body",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.fetch_not_found,
                RU.errors.fetch_not_found,
                "error-fetch-not-found",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.fetch_not_found_retry,
                RU.errors.fetch_not_found_retry,
                "error-fetch-not-found-retry",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.fetch_access_denied,
                RU.errors.fetch_access_denied,
                "error-fetch-access-denied",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.fetch_http_status,
                RU.errors.fetch_http_status,
                "error-fetch-http-status",
                &[("status", "{status}")] as &[(&str, &str)],
            ),
            (
                EN.errors.parse_empty,
                RU.errors.parse_empty,
                "error-parse-empty",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.parse_web_page,
                RU.errors.parse_web_page,
                "error-parse-web-page",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.parse_unsupported_format,
                RU.errors.parse_unsupported_format,
                "error-parse-unsupported-format",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.parse_unrecognized_format,
                RU.errors.parse_unrecognized_format,
                "error-parse-unrecognized-format",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.parse_invalid_utf8,
                RU.errors.parse_invalid_utf8,
                "error-parse-invalid-utf8",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.parse_invalid_json,
                RU.errors.parse_invalid_json,
                "error-parse-invalid-json",
                &[("column", "{column}"), ("line", "{line}")] as &[(&str, &str)],
            ),
            (
                EN.errors.device_limit_reached,
                RU.errors.device_limit_reached,
                "error-device-limit-reached",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.device_id_rejected,
                RU.errors.device_id_rejected,
                "error-device-id-rejected",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.device_policy,
                RU.errors.device_policy,
                "error-device-policy",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.no_usable_nodes,
                RU.errors.no_usable_nodes,
                "error-no-usable-nodes",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.provider_announce,
                RU.errors.provider_announce,
                "error-provider-announce",
                &[("text", "{text}")] as &[(&str, &str)],
            ),
            (
                EN.errors.provider_notice,
                RU.errors.provider_notice,
                "error-provider-notice",
                &[("text", "{text}")] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_invalid_record,
                RU.errors.skip_invalid_record,
                "error-skip-invalid-record",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_invalid_port,
                RU.errors.skip_invalid_port,
                "error-skip-invalid-port",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_missing_field,
                RU.errors.skip_missing_field,
                "error-skip-missing-field",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_invalid_json,
                RU.errors.skip_invalid_json,
                "error-skip-invalid-json",
                &[("column", "{column}"), ("line", "{line}")] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_unsupported_protocol,
                RU.errors.skip_unsupported_protocol,
                "error-skip-unsupported-protocol",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_client_settings,
                RU.errors.skip_client_settings,
                "error-skip-client-settings",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_vmess_format,
                RU.errors.skip_vmess_format,
                "error-skip-vmess-format",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_transport,
                RU.errors.skip_transport,
                "error-skip-transport",
                &[("transport", "{transport}")] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_unknown_transport,
                RU.errors.skip_unknown_transport,
                "error-skip-unknown-transport",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_tcp_header,
                RU.errors.skip_tcp_header,
                "error-skip-tcp-header",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_grpc_multi_mode,
                RU.errors.skip_grpc_multi_mode,
                "error-skip-grpc-multi-mode",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_encryption,
                RU.errors.skip_encryption,
                "error-skip-encryption",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_flow,
                RU.errors.skip_flow,
                "error-skip-flow",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_security,
                RU.errors.skip_security,
                "error-skip-security",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_reality_key,
                RU.errors.skip_reality_key,
                "error-skip-reality-key",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_shadowsocks_plugin,
                RU.errors.skip_shadowsocks_plugin,
                "error-skip-shadowsocks-plugin",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_shadowsocks_method,
                RU.errors.skip_shadowsocks_method,
                "error-skip-shadowsocks-method",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_unsupported_obfs,
                RU.errors.skip_unsupported_obfs,
                "error-skip-unsupported-obfs",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_unsupported_pin,
                RU.errors.skip_unsupported_pin,
                "error-skip-unsupported-pin",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.skip_service_record,
                RU.errors.skip_service_record,
                "error-skip-service-record",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.process_list,
                RU.errors.process_list,
                "error-process-list",
                &[("detail", "{detail}")] as &[(&str, &str)],
            ),
            (
                EN.errors.helper_transport,
                RU.errors.helper_transport,
                "error-helper-transport",
                &[("detail", "{detail}")] as &[(&str, &str)],
            ),
            (
                EN.errors.helper_unexpected,
                RU.errors.helper_unexpected,
                "error-helper-unexpected",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.helper_closed,
                RU.errors.helper_closed,
                "error-helper-closed",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.code_protocol_mismatch,
                RU.errors.code_protocol_mismatch,
                "error-code-protocol-mismatch",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.code_handshake_required,
                RU.errors.code_handshake_required,
                "error-code-handshake-required",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.code_not_privileged,
                RU.errors.code_not_privileged,
                "error-code-not-privileged",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.code_engine_failed,
                RU.errors.code_engine_failed,
                "error-code-engine-failed",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.code_server_unreachable,
                RU.errors.code_server_unreachable,
                "error-code-server-unreachable",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.code_server_rejected,
                RU.errors.code_server_rejected,
                "error-code-server-rejected",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.code_server_closed,
                RU.errors.code_server_closed,
                "error-code-server-closed",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.code_dns_timeout,
                RU.errors.code_dns_timeout,
                "error-code-dns-timeout",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.code_cancelled,
                RU.errors.code_cancelled,
                "error-code-cancelled",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.code_engine_not_ready,
                RU.errors.code_engine_not_ready,
                "error-code-engine-not-ready",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.code_routing_failed,
                RU.errors.code_routing_failed,
                "error-code-routing-failed",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.code_busy,
                RU.errors.code_busy,
                "error-code-busy",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.code_invalid_state,
                RU.errors.code_invalid_state,
                "error-code-invalid-state",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.code_unsupported_rules,
                RU.errors.code_unsupported_rules,
                "error-code-unsupported-rules",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.code_not_implemented,
                RU.errors.code_not_implemented,
                "error-code-not-implemented",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.code_internal,
                RU.errors.code_internal,
                "error-code-internal",
                &[] as &[(&str, &str)],
            ),
            (
                EN.errors.autostart_read,
                RU.errors.autostart_read,
                "error-autostart-read",
                &[("detail", "{detail}")] as &[(&str, &str)],
            ),
            (
                EN.errors.autostart_write,
                RU.errors.autostart_write,
                "error-autostart-write",
                &[("detail", "{detail}")] as &[(&str, &str)],
            ),
            (
                EN.errors.open_folder,
                RU.errors.open_folder,
                "error-open-folder",
                &[("detail", "{detail}")] as &[(&str, &str)],
            ),
            (
                EN.connection,
                RU.connection,
                "connection",
                &[] as &[(&str, &str)],
            ),
            (EN.traffic, RU.traffic, "traffic", &[] as &[(&str, &str)]),
            (EN.rules, RU.rules, "rules", &[] as &[(&str, &str)]),
            (EN.settings, RU.settings, "settings", &[] as &[(&str, &str)]),
            (
                EN.settings_saved_instantly,
                RU.settings_saved_instantly,
                "settings-saved-instantly",
                &[] as &[(&str, &str)],
            ),
            (
                EN.section_general,
                RU.section_general,
                "section-general",
                &[] as &[(&str, &str)],
            ),
            (
                EN.section_network,
                RU.section_network,
                "section-network",
                &[] as &[(&str, &str)],
            ),
            (
                EN.section_service,
                RU.section_service,
                "section-service",
                &[] as &[(&str, &str)],
            ),
            (EN.minimize, RU.minimize, "minimize", &[] as &[(&str, &str)]),
            (EN.maximize, RU.maximize, "maximize", &[] as &[(&str, &str)]),
            (EN.restore, RU.restore, "restore", &[] as &[(&str, &str)]),
            (
                EN.close_window,
                RU.close_window,
                "close-window",
                &[] as &[(&str, &str)],
            ),
            (EN.scale, RU.scale, "scale", &[] as &[(&str, &str)]),
            (
                EN.zoom_hint,
                RU.zoom_hint,
                "zoom-hint",
                &[] as &[(&str, &str)],
            ),
            (
                EN.reduce_motion,
                RU.reduce_motion,
                "reduce-motion",
                &[] as &[(&str, &str)],
            ),
            (
                EN.reduce_motion_detail,
                RU.reduce_motion_detail,
                "reduce-motion-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.connect_on_start,
                RU.connect_on_start,
                "connect-on-start",
                &[] as &[(&str, &str)],
            ),
            (
                EN.connect_on_start_detail,
                RU.connect_on_start_detail,
                "connect-on-start-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.auto_reconnect,
                RU.auto_reconnect,
                "auto-reconnect",
                &[] as &[(&str, &str)],
            ),
            (
                EN.auto_reconnect_detail,
                RU.auto_reconnect_detail,
                "auto-reconnect-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.auto_update_subscriptions,
                RU.auto_update_subscriptions,
                "auto-update-subscriptions",
                &[] as &[(&str, &str)],
            ),
            (
                EN.auto_update_subscriptions_detail,
                RU.auto_update_subscriptions_detail,
                "auto-update-subscriptions-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.dns_through_tunnel,
                RU.dns_through_tunnel,
                "dns-through-tunnel",
                &[] as &[(&str, &str)],
            ),
            (
                EN.dns_explanation,
                RU.dns_explanation,
                "dns-explanation",
                &[] as &[(&str, &str)],
            ),
            (
                EN.dns_custom,
                RU.dns_custom,
                "dns-custom",
                &[] as &[(&str, &str)],
            ),
            (
                EN.dns_custom_detail,
                RU.dns_custom_detail,
                "dns-custom-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.dns_reachable,
                RU.dns_reachable,
                "dns-reachable",
                &[] as &[(&str, &str)],
            ),
            (
                EN.resolver_ip,
                RU.resolver_ip,
                "resolver-ip",
                &[] as &[(&str, &str)],
            ),
            (EN.tls_name, RU.tls_name, "tls-name", &[] as &[(&str, &str)]),
            (EN.port, RU.port, "port", &[] as &[(&str, &str)]),
            (EN.dns_path, RU.dns_path, "dns-path", &[] as &[(&str, &str)]),
            (EN.save, RU.save, "save", &[] as &[(&str, &str)]),
            (
                EN.reset_to_default,
                RU.reset_to_default,
                "reset-to-default",
                &[] as &[(&str, &str)],
            ),
            (
                EN.log_title,
                RU.log_title,
                "log-title",
                &[] as &[(&str, &str)],
            ),
            (
                EN.log_detail,
                RU.log_detail,
                "log-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.service_label,
                RU.service_label,
                "service-label",
                &[] as &[(&str, &str)],
            ),
            (
                EN.service_running,
                RU.service_running,
                "service-running",
                &[] as &[(&str, &str)],
            ),
            (
                EN.service_stopped,
                RU.service_stopped,
                "service-stopped",
                &[] as &[(&str, &str)],
            ),
            (
                EN.service_detail,
                RU.service_detail,
                "service-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.reset_settings,
                RU.reset_settings,
                "reset-settings",
                &[] as &[(&str, &str)],
            ),
            (
                EN.reset_settings_detail,
                RU.reset_settings_detail,
                "reset-settings-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.reset_settings_question,
                RU.reset_settings_question,
                "reset-settings-question",
                &[] as &[(&str, &str)],
            ),
            (
                EN.reset_settings_body,
                RU.reset_settings_body,
                "reset-settings-body",
                &[] as &[(&str, &str)],
            ),
            (
                EN.reset_disconnect_first,
                RU.reset_disconnect_first,
                "reset-disconnect-first",
                &[] as &[(&str, &str)],
            ),
            (
                EN.verbose_log,
                RU.verbose_log,
                "verbose-log",
                &[] as &[(&str, &str)],
            ),
            (
                EN.verbose_log_off_detail,
                RU.verbose_log_off_detail,
                "verbose-log-off-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.verbose_log_on_detail,
                RU.verbose_log_on_detail,
                "verbose-log-on-detail",
                &[("hours", "{hours}")] as &[(&str, &str)],
            ),
            (
                EN.verbose_log_hour_one,
                RU.verbose_log_hour_one,
                "verbose-log-hour-one",
                &[] as &[(&str, &str)],
            ),
            (
                EN.verbose_log_hour_few,
                RU.verbose_log_hour_few,
                "verbose-log-hour-few",
                &[] as &[(&str, &str)],
            ),
            (
                EN.verbose_log_hour_many,
                RU.verbose_log_hour_many,
                "verbose-log-hour-many",
                &[] as &[(&str, &str)],
            ),
            (EN.about, RU.about, "about", &[] as &[(&str, &str)]),
            (
                EN.about_version_with_helper,
                RU.about_version_with_helper,
                "about-version-with-helper",
                &[("app", "{app}"), ("helper", "{helper}")] as &[(&str, &str)],
            ),
            (
                EN.about_version_without_helper,
                RU.about_version_without_helper,
                "about-version-without-helper",
                &[("app", "{app}")] as &[(&str, &str)],
            ),
            (
                EN.check_updates,
                RU.check_updates,
                "check-updates",
                &[] as &[(&str, &str)],
            ),
            (
                EN.check_updates_detail,
                RU.check_updates_detail,
                "check-updates-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.check_updates_now,
                RU.check_updates_now,
                "check-updates-now",
                &[] as &[(&str, &str)],
            ),
            (
                EN.check_updates_unavailable,
                RU.check_updates_unavailable,
                "check-updates-unavailable",
                &[] as &[(&str, &str)],
            ),
            (
                EN.updates_title,
                RU.updates_title,
                "updates-title",
                &[] as &[(&str, &str)],
            ),
            (
                EN.update_available,
                RU.update_available,
                "update-available",
                &[("version", "{version}")] as &[(&str, &str)],
            ),
            (
                EN.update_prerelease,
                RU.update_prerelease,
                "update-prerelease",
                &[] as &[(&str, &str)],
            ),
            (
                EN.update_installer_detail,
                RU.update_installer_detail,
                "update-installer-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.update_open_page,
                RU.update_open_page,
                "update-open-page",
                &[] as &[(&str, &str)],
            ),
            (
                EN.update_skip,
                RU.update_skip,
                "update-skip",
                &[] as &[(&str, &str)],
            ),
            (
                EN.update_checking,
                RU.update_checking,
                "update-checking",
                &[] as &[(&str, &str)],
            ),
            (
                EN.update_checking_detail,
                RU.update_checking_detail,
                "update-checking-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.update_found,
                RU.update_found,
                "update-found",
                &[] as &[(&str, &str)],
            ),
            (
                EN.update_checked,
                RU.update_checked,
                "update-checked",
                &[("age", "{age}")] as &[(&str, &str)],
            ),
            (
                EN.update_skipped,
                RU.update_skipped,
                "update-skipped",
                &[("version", "{version}")] as &[(&str, &str)],
            ),
            (
                EN.update_skipped_next,
                RU.update_skipped_next,
                "update-skipped-next",
                &[] as &[(&str, &str)],
            ),
            (
                EN.update_skipped_detail,
                RU.update_skipped_detail,
                "update-skipped-detail",
                &[("age", "{age}")] as &[(&str, &str)],
            ),
            (
                EN.update_up_to_date,
                RU.update_up_to_date,
                "update-up-to-date",
                &[] as &[(&str, &str)],
            ),
            (
                EN.update_failed,
                RU.update_failed,
                "update-failed",
                &[] as &[(&str, &str)],
            ),
            (
                EN.update_failed_detail,
                RU.update_failed_detail,
                "update-failed-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.update_checks_off,
                RU.update_checks_off,
                "update-checks-off",
                &[] as &[(&str, &str)],
            ),
            (
                EN.update_last_checked,
                RU.update_last_checked,
                "update-last-checked",
                &[("age", "{age}")] as &[(&str, &str)],
            ),
            (
                EN.update_check_manually,
                RU.update_check_manually,
                "update-check-manually",
                &[] as &[(&str, &str)],
            ),
            (
                EN.update_not_checked,
                RU.update_not_checked,
                "update-not-checked",
                &[] as &[(&str, &str)],
            ),
            (
                EN.update_not_checked_detail,
                RU.update_not_checked_detail,
                "update-not-checked-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.license_notice,
                RU.license_notice,
                "license-notice",
                &[] as &[(&str, &str)],
            ),
            (
                EN.licenses_folder,
                RU.licenses_folder,
                "licenses-folder",
                &[] as &[(&str, &str)],
            ),
            (
                EN.configuration_folder,
                RU.configuration_folder,
                "configuration-folder",
                &[] as &[(&str, &str)],
            ),
            (EN.log_file, RU.log_file, "log-file", &[] as &[(&str, &str)]),
            (
                EN.open_folder,
                RU.open_folder,
                "open-folder",
                &[] as &[(&str, &str)],
            ),
            (EN.connect, RU.connect, "connect", &[] as &[(&str, &str)]),
            (
                EN.unavailable,
                RU.unavailable,
                "unavailable",
                &[] as &[(&str, &str)],
            ),
            (
                EN.disconnect,
                RU.disconnect,
                "disconnect",
                &[] as &[(&str, &str)],
            ),
            (EN.retry, RU.retry, "retry", &[] as &[(&str, &str)]),
            (
                EN.reconnect,
                RU.reconnect,
                "reconnect",
                &[] as &[(&str, &str)],
            ),
            (
                EN.connecting_action,
                RU.connecting_action,
                "connecting-action",
                &[] as &[(&str, &str)],
            ),
            (
                EN.cancel_connection,
                RU.cancel_connection,
                "cancel-connection",
                &[] as &[(&str, &str)],
            ),
            (
                EN.cancelling,
                RU.cancelling,
                "cancelling",
                &[] as &[(&str, &str)],
            ),
            (
                EN.stage_waiting,
                RU.stage_waiting,
                "stage-waiting",
                &[] as &[(&str, &str)],
            ),
            (
                EN.stage_starting,
                RU.stage_starting,
                "stage-starting",
                &[] as &[(&str, &str)],
            ),
            (
                EN.stage_checking,
                RU.stage_checking,
                "stage-checking",
                &[] as &[(&str, &str)],
            ),
            (
                EN.stage_elapsed,
                RU.stage_elapsed,
                "stage-elapsed",
                &[("seconds", "{seconds}"), ("stage", "{stage}")] as &[(&str, &str)],
            ),
            (
                EN.engine_not_ready_hint,
                RU.engine_not_ready_hint,
                "engine-not-ready-hint",
                &[("retry", "{retry}")] as &[(&str, &str)],
            ),
            (
                EN.server_unreachable_hint,
                RU.server_unreachable_hint,
                "server-unreachable-hint",
                &[("url_test", "{url_test}")] as &[(&str, &str)],
            ),
            (
                EN.server_rejected_hint,
                RU.server_rejected_hint,
                "server-rejected-hint",
                &[] as &[(&str, &str)],
            ),
            (
                EN.server_closed_hint,
                RU.server_closed_hint,
                "server-closed-hint",
                &[] as &[(&str, &str)],
            ),
            (
                EN.dns_timeout_hint,
                RU.dns_timeout_hint,
                "dns-timeout-hint",
                &[] as &[(&str, &str)],
            ),
            (
                EN.other_vpn_hint,
                RU.other_vpn_hint,
                "other-vpn-hint",
                &[("name", "{name}"), ("retry", "{retry}")] as &[(&str, &str)],
            ),
            (
                EN.traffic_tool_hint,
                RU.traffic_tool_hint,
                "traffic-tool-hint",
                &[("name", "{name}")] as &[(&str, &str)],
            ),
            (
                EN.reconnecting_action,
                RU.reconnecting_action,
                "reconnecting-action",
                &[] as &[(&str, &str)],
            ),
            (EN.working, RU.working, "working", &[] as &[(&str, &str)]),
            (EN.loading, RU.loading, "loading", &[] as &[(&str, &str)]),
            (EN.engine, RU.engine, "engine", &[] as &[(&str, &str)]),
            (
                EN.status_unknown,
                RU.status_unknown,
                "status-unknown",
                &[] as &[(&str, &str)],
            ),
            (
                EN.disconnected,
                RU.disconnected,
                "disconnected",
                &[] as &[(&str, &str)],
            ),
            (
                EN.connecting,
                RU.connecting,
                "connecting",
                &[] as &[(&str, &str)],
            ),
            (
                EN.connected,
                RU.connected,
                "connected",
                &[] as &[(&str, &str)],
            ),
            (
                EN.connected_in_template,
                RU.connected_in_template,
                "connected-in-template",
                &[("code", "{code}")] as &[(&str, &str)],
            ),
            (
                EN.reconnecting,
                RU.reconnecting,
                "reconnecting",
                &[] as &[(&str, &str)],
            ),
            (EN.failed, RU.failed, "failed", &[] as &[(&str, &str)]),
            (
                EN.failed_protected,
                RU.failed_protected,
                "failed-protected",
                &[] as &[(&str, &str)],
            ),
            (
                EN.traffic_blocked,
                RU.traffic_blocked,
                "traffic-blocked",
                &[] as &[(&str, &str)],
            ),
            (
                EN.helper_unavailable,
                RU.helper_unavailable,
                "helper-unavailable",
                &[] as &[(&str, &str)],
            ),
            (
                EN.helper_unavailable_detail,
                RU.helper_unavailable_detail,
                "helper-unavailable-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.service_down_title,
                RU.service_down_title,
                "service-down-title",
                &[] as &[(&str, &str)],
            ),
            (
                EN.service_down_body,
                RU.service_down_body,
                "service-down-body",
                &[] as &[(&str, &str)],
            ),
            (EN.details, RU.details, "details", &[] as &[(&str, &str)]),
            (
                EN.hide_details,
                RU.hide_details,
                "hide-details",
                &[] as &[(&str, &str)],
            ),
            (
                EN.select_server,
                RU.select_server,
                "select-server",
                &[] as &[(&str, &str)],
            ),
            (
                EN.server_change,
                RU.server_change,
                "server-change",
                &[] as &[(&str, &str)],
            ),
            (EN.protocol, RU.protocol, "protocol", &[] as &[(&str, &str)]),
            (
                EN.external_ip,
                RU.external_ip,
                "external-ip",
                &[] as &[(&str, &str)],
            ),
            (EN.delay, RU.delay, "delay", &[] as &[(&str, &str)]),
            (
                EN.delay_hint,
                RU.delay_hint,
                "delay-hint",
                &[] as &[(&str, &str)],
            ),
            (EN.ip_own, RU.ip_own, "ip-own", &[] as &[(&str, &str)]),
            (
                EN.ip_hidden,
                RU.ip_hidden,
                "ip-hidden",
                &[] as &[(&str, &str)],
            ),
            (EN.ip_show, RU.ip_show, "ip-show", &[] as &[(&str, &str)]),
            (EN.ip_hide, RU.ip_hide, "ip-hide", &[] as &[(&str, &str)]),
            (
                EN.ip_unknown,
                RU.ip_unknown,
                "ip-unknown",
                &[] as &[(&str, &str)],
            ),
            (
                EN.ip_pending,
                RU.ip_pending,
                "ip-pending",
                &[] as &[(&str, &str)],
            ),
            (EN.session, RU.session, "session", &[] as &[(&str, &str)]),
            (
                EN.traffic_down,
                RU.traffic_down,
                "traffic-down",
                &[] as &[(&str, &str)],
            ),
            (
                EN.traffic_up,
                RU.traffic_up,
                "traffic-up",
                &[] as &[(&str, &str)],
            ),
            (
                EN.traffic_open_hint,
                RU.traffic_open_hint,
                "traffic-open-hint",
                &[] as &[(&str, &str)],
            ),
            (
                EN.traffic_rates_template,
                RU.traffic_rates_template,
                "traffic-rates-template",
                &[("down", "{down}"), ("up", "{up}")] as &[(&str, &str)],
            ),
            (
                EN.traffic_range_1m,
                RU.traffic_range_1m,
                "traffic-range-1m",
                &[] as &[(&str, &str)],
            ),
            (
                EN.traffic_range_5m,
                RU.traffic_range_5m,
                "traffic-range-5m",
                &[] as &[(&str, &str)],
            ),
            (
                EN.traffic_range_15m,
                RU.traffic_range_15m,
                "traffic-range-15m",
                &[] as &[(&str, &str)],
            ),
            (
                EN.traffic_chart_caption_template,
                RU.traffic_chart_caption_template,
                "traffic-chart-caption-template",
                &[("peak", "{peak}"), ("range", "{range}")] as &[(&str, &str)],
            ),
            (
                EN.traffic_session,
                RU.traffic_session,
                "traffic-session",
                &[] as &[(&str, &str)],
            ),
            (
                EN.traffic_empty,
                RU.traffic_empty,
                "traffic-empty",
                &[] as &[(&str, &str)],
            ),
            (
                EN.no_session,
                RU.no_session,
                "no-session",
                &[] as &[(&str, &str)],
            ),
            (
                EN.kill_switch,
                RU.kill_switch,
                "kill-switch",
                &[] as &[(&str, &str)],
            ),
            (
                EN.protection,
                RU.protection,
                "protection",
                &[] as &[(&str, &str)],
            ),
            (
                EN.kill_switch_detail,
                RU.kill_switch_detail,
                "kill-switch-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.default_rules,
                RU.default_rules,
                "default-rules",
                &[] as &[(&str, &str)],
            ),
            (
                EN.next_connect,
                RU.next_connect,
                "next-connect",
                &[] as &[(&str, &str)],
            ),
            (EN.apply, RU.apply, "apply", &[] as &[(&str, &str)]),
            (
                EN.apply_now,
                RU.apply_now,
                "apply-now",
                &[] as &[(&str, &str)],
            ),
            (
                EN.apply_separator,
                RU.apply_separator,
                "apply-separator",
                &[] as &[(&str, &str)],
            ),
            (
                EN.not_applied,
                RU.not_applied,
                "not-applied",
                &[] as &[(&str, &str)],
            ),
            (
                EN.apply_on_leave,
                RU.apply_on_leave,
                "apply-on-leave",
                &[] as &[(&str, &str)],
            ),
            (
                EN.apply_hint,
                RU.apply_hint,
                "apply-hint",
                &[] as &[(&str, &str)],
            ),
            (
                EN.apply_failed_restored_template,
                RU.apply_failed_restored_template,
                "apply-failed-restored-template",
                &[("reason", "{reason}")] as &[(&str, &str)],
            ),
            (
                EN.apply_rollback_failed_template,
                RU.apply_rollback_failed_template,
                "apply-rollback-failed-template",
                &[("error", "{error}"), ("reason", "{reason}")] as &[(&str, &str)],
            ),
            (
                EN.restore_my_edits,
                RU.restore_my_edits,
                "restore-my-edits",
                &[] as &[(&str, &str)],
            ),
            (
                EN.turn_off_protection,
                RU.turn_off_protection,
                "turn-off-protection",
                &[] as &[(&str, &str)],
            ),
            (
                EN.keep_blocked,
                RU.keep_blocked,
                "keep-blocked",
                &[] as &[(&str, &str)],
            ),
            (
                EN.protection_warning,
                RU.protection_warning,
                "protection-warning",
                &[] as &[(&str, &str)],
            ),
            (
                EN.add_subscription,
                RU.add_subscription,
                "add-subscription",
                &[] as &[(&str, &str)],
            ),
            (
                EN.subscriptions_title,
                RU.subscriptions_title,
                "subscriptions-title",
                &[] as &[(&str, &str)],
            ),
            (
                EN.add_short,
                RU.add_short,
                "add-short",
                &[] as &[(&str, &str)],
            ),
            (
                EN.add_subtitle,
                RU.add_subtitle,
                "add-subtitle",
                &[] as &[(&str, &str)],
            ),
            (
                EN.subscription_url,
                RU.subscription_url,
                "subscription-url",
                &[] as &[(&str, &str)],
            ),
            (EN.paste, RU.paste, "paste", &[] as &[(&str, &str)]),
            (EN.name, RU.name, "name", &[] as &[(&str, &str)]),
            (
                EN.name_placeholder,
                RU.name_placeholder,
                "name-placeholder",
                &[] as &[(&str, &str)],
            ),
            (
                EN.send_device_id,
                RU.send_device_id,
                "send-device-id",
                &[] as &[(&str, &str)],
            ),
            (
                EN.device_id_explanation,
                RU.device_id_explanation,
                "device-id-explanation",
                &[] as &[(&str, &str)],
            ),
            (EN.url_help, RU.url_help, "url-help", &[] as &[(&str, &str)]),
            (
                EN.http_warning,
                RU.http_warning,
                "http-warning",
                &[] as &[(&str, &str)],
            ),
            (EN.add, RU.add, "add", &[] as &[(&str, &str)]),
            (EN.adding, RU.adding, "adding", &[] as &[(&str, &str)]),
            (EN.cancel, RU.cancel, "cancel", &[] as &[(&str, &str)]),
            (EN.remove, RU.remove, "remove", &[] as &[(&str, &str)]),
            (EN.removing, RU.removing, "removing", &[] as &[(&str, &str)]),
            (
                EN.remove_subscription,
                RU.remove_subscription,
                "remove-subscription",
                &[] as &[(&str, &str)],
            ),
            (
                EN.rename_subscription,
                RU.rename_subscription,
                "rename-subscription",
                &[] as &[(&str, &str)],
            ),
            (
                EN.subscription_name,
                RU.subscription_name,
                "subscription-name",
                &[] as &[(&str, &str)],
            ),
            (
                EN.more_actions,
                RU.more_actions,
                "more-actions",
                &[] as &[(&str, &str)],
            ),
            (
                EN.remove_detail,
                RU.remove_detail,
                "remove-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.remove_selected_warning,
                RU.remove_selected_warning,
                "remove-selected-warning",
                &[] as &[(&str, &str)],
            ),
            (EN.update, RU.update, "update", &[] as &[(&str, &str)]),
            (
                EN.update_all,
                RU.update_all,
                "update-all",
                &[] as &[(&str, &str)],
            ),
            (EN.updating, RU.updating, "updating", &[] as &[(&str, &str)]),
            (
                EN.auto_update_every,
                RU.auto_update_every,
                "auto-update-every",
                &[("hours", "{hours}")] as &[(&str, &str)],
            ),
            (
                EN.auto_update_on,
                RU.auto_update_on,
                "auto-update-on",
                &[] as &[(&str, &str)],
            ),
            (
                EN.servers_heading,
                RU.servers_heading,
                "servers-heading",
                &[] as &[(&str, &str)],
            ),
            (
                EN.quota_used,
                RU.quota_used,
                "quota-used",
                &[("used", "{used}")] as &[(&str, &str)],
            ),
            (
                EN.quota_used_of,
                RU.quota_used_of,
                "quota-used-of",
                &[("total", "{total}"), ("used", "{used}")] as &[(&str, &str)],
            ),
            (
                EN.last_updated_template,
                RU.last_updated_template,
                "last-updated-template",
                &[("age", "{age}")] as &[(&str, &str)],
            ),
            (
                EN.term_left_template,
                RU.term_left_template,
                "term-left-template",
                &[("days", "{days}"), ("unit", "{unit}")] as &[(&str, &str)],
            ),
            (
                EN.term_day_one,
                RU.term_day_one,
                "term-day-one",
                &[] as &[(&str, &str)],
            ),
            (
                EN.term_day_few,
                RU.term_day_few,
                "term-day-few",
                &[] as &[(&str, &str)],
            ),
            (
                EN.term_day_many,
                RU.term_day_many,
                "term-day-many",
                &[] as &[(&str, &str)],
            ),
            (
                EN.term_under_day,
                RU.term_under_day,
                "term-under-day",
                &[] as &[(&str, &str)],
            ),
            (
                EN.term_expired,
                RU.term_expired,
                "term-expired",
                &[] as &[(&str, &str)],
            ),
            (
                EN.never_updated,
                RU.never_updated,
                "never-updated",
                &[] as &[(&str, &str)],
            ),
            (
                EN.no_subscriptions,
                RU.no_subscriptions,
                "no-subscriptions",
                &[] as &[(&str, &str)],
            ),
            (
                EN.empty_subscriptions,
                RU.empty_subscriptions,
                "empty-subscriptions",
                &[] as &[(&str, &str)],
            ),
            (
                EN.no_servers,
                RU.no_servers,
                "no-servers",
                &[] as &[(&str, &str)],
            ),
            (
                EN.check_menu,
                RU.check_menu,
                "check-menu",
                &[] as &[(&str, &str)],
            ),
            (
                EN.check_quick,
                RU.check_quick,
                "check-quick",
                &[] as &[(&str, &str)],
            ),
            (
                EN.check_full,
                RU.check_full,
                "check-full",
                &[] as &[(&str, &str)],
            ),
            (
                EN.check_hint,
                RU.check_hint,
                "check-hint",
                &[] as &[(&str, &str)],
            ),
            (
                EN.ping_while_connected,
                RU.ping_while_connected,
                "ping-while-connected",
                &[] as &[(&str, &str)],
            ),
            (
                EN.ping_checking,
                RU.ping_checking,
                "ping-checking",
                &[] as &[(&str, &str)],
            ),
            (
                EN.ping_ms,
                RU.ping_ms,
                "ping-ms",
                &[("ms", "{ms}")] as &[(&str, &str)],
            ),
            (
                EN.ping_no_answer,
                RU.ping_no_answer,
                "ping-no-answer",
                &[] as &[(&str, &str)],
            ),
            (
                EN.ping_pending,
                RU.ping_pending,
                "ping-pending",
                &[] as &[(&str, &str)],
            ),
            (
                EN.ping_best,
                RU.ping_best,
                "ping-best",
                &[("ms", "{ms}")] as &[(&str, &str)],
            ),
            (
                EN.ping_tcp_hint,
                RU.ping_tcp_hint,
                "ping-tcp-hint",
                &[] as &[(&str, &str)],
            ),
            (
                EN.ping_full_hint,
                RU.ping_full_hint,
                "ping-full-hint",
                &[] as &[(&str, &str)],
            ),
            (
                EN.ping_fails,
                RU.ping_fails,
                "ping-fails",
                &[] as &[(&str, &str)],
            ),
            (
                EN.ping_fails_hint,
                RU.ping_fails_hint,
                "ping-fails-hint",
                &[] as &[(&str, &str)],
            ),
            (
                EN.ping_unresolved,
                RU.ping_unresolved,
                "ping-unresolved",
                &[] as &[(&str, &str)],
            ),
            (
                EN.ping_unresolved_hint,
                RU.ping_unresolved_hint,
                "ping-unresolved-hint",
                &[] as &[(&str, &str)],
            ),
            (
                EN.ping_unsupported,
                RU.ping_unsupported,
                "ping-unsupported",
                &[] as &[(&str, &str)],
            ),
            (
                EN.ping_udp_hint,
                RU.ping_udp_hint,
                "ping-udp-hint",
                &[] as &[(&str, &str)],
            ),
            (
                EN.full_check_busy,
                RU.full_check_busy,
                "full-check-busy",
                &[] as &[(&str, &str)],
            ),
            (EN.support, RU.support, "support", &[] as &[(&str, &str)]),
            (EN.website, RU.website, "website", &[] as &[(&str, &str)]),
            (
                EN.selection_cleared,
                RU.selection_cleared,
                "selection-cleared",
                &[] as &[(&str, &str)],
            ),
            (EN.dismiss, RU.dismiss, "dismiss", &[] as &[(&str, &str)]),
            (
                EN.rules_title,
                RU.rules_title,
                "rules-title",
                &[] as &[(&str, &str)],
            ),
            (
                EN.rules_tab_title,
                RU.rules_tab_title,
                "rules-tab-title",
                &[] as &[(&str, &str)],
            ),
            (
                EN.rules_subtitle,
                RU.rules_subtitle,
                "rules-subtitle",
                &[] as &[(&str, &str)],
            ),
            (
                EN.open_link,
                RU.open_link,
                "open-link",
                &[] as &[(&str, &str)],
            ),
            (
                EN.no_rules_yet,
                RU.no_rules_yet,
                "no-rules-yet",
                &[] as &[(&str, &str)],
            ),
            (
                EN.temporary_count,
                RU.temporary_count,
                "temporary-count",
                &[("n", "{n}")] as &[(&str, &str)],
            ),
            (EN.active, RU.active, "active", &[] as &[(&str, &str)]),
            (
                EN.make_active,
                RU.make_active,
                "make-active",
                &[] as &[(&str, &str)],
            ),
            (EN.new_set, RU.new_set, "new-set", &[] as &[(&str, &str)]),
            (
                EN.create_rule_set,
                RU.create_rule_set,
                "create-rule-set",
                &[] as &[(&str, &str)],
            ),
            (EN.rename, RU.rename, "rename", &[] as &[(&str, &str)]),
            (EN.delete, RU.delete, "delete", &[] as &[(&str, &str)]),
            (
                EN.keep_permanently,
                RU.keep_permanently,
                "keep-permanently",
                &[] as &[(&str, &str)],
            ),
            (
                EN.temporary_hint,
                RU.temporary_hint,
                "temporary-hint",
                &[] as &[(&str, &str)],
            ),
            (
                EN.temporary_needs_connection,
                RU.temporary_needs_connection,
                "temporary-needs-connection",
                &[] as &[(&str, &str)],
            ),
            (EN.basic, RU.basic, "basic", &[] as &[(&str, &str)]),
            (EN.set_name, RU.set_name, "set-name", &[] as &[(&str, &str)]),
            (
                EN.rename_rule_set,
                RU.rename_rule_set,
                "rename-rule-set",
                &[] as &[(&str, &str)],
            ),
            (
                EN.delete_rule_set,
                RU.delete_rule_set,
                "delete-rule-set",
                &[] as &[(&str, &str)],
            ),
            (
                EN.delete_rule_set_detail,
                RU.delete_rule_set_detail,
                "delete-rule-set-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.delete_active_rule_set_warning,
                RU.delete_active_rule_set_warning,
                "delete-active-rule-set-warning",
                &[] as &[(&str, &str)],
            ),
            (
                EN.delete_rule,
                RU.delete_rule,
                "delete-rule",
                &[] as &[(&str, &str)],
            ),
            (
                EN.delete_rule_detail,
                RU.delete_rule_detail,
                "delete-rule-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.delete_rules_heading,
                RU.delete_rules_heading,
                "delete-rules-heading",
                &[("n", "{n}"), ("rules", "{rules}")] as &[(&str, &str)],
            ),
            (
                EN.rule_unit,
                RU.rule_unit,
                "rule-unit",
                &[] as &[(&str, &str)],
            ),
            (
                EN.and_more_rules,
                RU.and_more_rules,
                "and-more-rules",
                &[("k", "{k}")] as &[(&str, &str)],
            ),
            (
                EN.move_to_top,
                RU.move_to_top,
                "move-to-top",
                &[] as &[(&str, &str)],
            ),
            (
                EN.move_selected_to_top,
                RU.move_selected_to_top,
                "move-selected-to-top",
                &[] as &[(&str, &str)],
            ),
            (
                EN.move_to_end,
                RU.move_to_end,
                "move-to-end",
                &[] as &[(&str, &str)],
            ),
            (
                EN.selected_rule_count,
                RU.selected_rule_count,
                "selected-rule-count",
                &[("n", "{n}")] as &[(&str, &str)],
            ),
            (
                EN.delete_selected_rules,
                RU.delete_selected_rules,
                "delete-selected-rules",
                &[("n", "{n}")] as &[(&str, &str)],
            ),
            (
                EN.search_rules,
                RU.search_rules,
                "search-rules",
                &[] as &[(&str, &str)],
            ),
            (EN.all, RU.all, "all", &[] as &[(&str, &str)]),
            (EN.domains, RU.domains, "domains", &[] as &[(&str, &str)]),
            (
                EN.processes,
                RU.processes,
                "processes",
                &[] as &[(&str, &str)],
            ),
            (EN.other, RU.other, "other", &[] as &[(&str, &str)]),
            (
                EN.any_action,
                RU.any_action,
                "any-action",
                &[] as &[(&str, &str)],
            ),
            (EN.proxy, RU.proxy, "proxy", &[] as &[(&str, &str)]),
            (EN.direct, RU.direct, "direct", &[] as &[(&str, &str)]),
            (EN.block, RU.block, "block", &[] as &[(&str, &str)]),
            (
                EN.order_hint,
                RU.order_hint,
                "order-hint",
                &[] as &[(&str, &str)],
            ),
            (
                EN.reorder_disabled,
                RU.reorder_disabled,
                "reorder-disabled",
                &[] as &[(&str, &str)],
            ),
            (
                EN.all_other_traffic,
                RU.all_other_traffic,
                "all-other-traffic",
                &[] as &[(&str, &str)],
            ),
            (
                EN.default_fallback,
                RU.default_fallback,
                "default-fallback",
                &[] as &[(&str, &str)],
            ),
            (
                EN.caption_this_address,
                RU.caption_this_address,
                "caption-this-address",
                &[] as &[(&str, &str)],
            ),
            (
                EN.caption_subdomains,
                RU.caption_subdomains,
                "caption-subdomains",
                &[] as &[(&str, &str)],
            ),
            (
                EN.caption_keyword,
                RU.caption_keyword,
                "caption-keyword",
                &[] as &[(&str, &str)],
            ),
            (
                EN.caption_any_folder,
                RU.caption_any_folder,
                "caption-any-folder",
                &[] as &[(&str, &str)],
            ),
            (
                EN.caption_addresses,
                RU.caption_addresses,
                "caption-addresses",
                &[] as &[(&str, &str)],
            ),
            (
                EN.default_rule_tooltip,
                RU.default_rule_tooltip,
                "default-rule-tooltip",
                &[] as &[(&str, &str)],
            ),
            (
                EN.no_rule_sets,
                RU.no_rule_sets,
                "no-rule-sets",
                &[] as &[(&str, &str)],
            ),
            (
                EN.no_rules_match,
                RU.no_rules_match,
                "no-rules-match",
                &[] as &[(&str, &str)],
            ),
            (
                EN.rules_templates,
                RU.rules_templates,
                "rules-templates",
                &[] as &[(&str, &str)],
            ),
            (
                EN.template_add,
                RU.template_add,
                "template-add",
                &[] as &[(&str, &str)],
            ),
            (
                EN.template_added,
                RU.template_added,
                "template-added",
                &[] as &[(&str, &str)],
            ),
            (
                EN.template_remove_hint,
                RU.template_remove_hint,
                "template-remove-hint",
                &[] as &[(&str, &str)],
            ),
            (
                EN.template_redundant,
                RU.template_redundant,
                "template-redundant",
                &[] as &[(&str, &str)],
            ),
            (
                EN.template_contents,
                RU.template_contents,
                "template-contents",
                &[("list", "{list}")] as &[(&str, &str)],
            ),
            (
                EN.caption_template,
                RU.caption_template,
                "caption-template",
                &[] as &[(&str, &str)],
            ),
            (
                EN.russian_sites_name,
                RU.russian_sites_name,
                "russian-sites-name",
                &[] as &[(&str, &str)],
            ),
            (
                EN.russian_sites_description,
                RU.russian_sites_description,
                "russian-sites-description",
                &[] as &[(&str, &str)],
            ),
            (
                EN.messengers_name,
                RU.messengers_name,
                "messengers-name",
                &[] as &[(&str, &str)],
            ),
            (
                EN.messengers_description,
                RU.messengers_description,
                "messengers-description",
                &[] as &[(&str, &str)],
            ),
            (
                EN.youtube_name,
                RU.youtube_name,
                "youtube-name",
                &[] as &[(&str, &str)],
            ),
            (
                EN.youtube_description,
                RU.youtube_description,
                "youtube-description",
                &[] as &[(&str, &str)],
            ),
            (
                EN.torrents_name,
                RU.torrents_name,
                "torrents-name",
                &[] as &[(&str, &str)],
            ),
            (
                EN.torrents_description,
                RU.torrents_description,
                "torrents-description",
                &[] as &[(&str, &str)],
            ),
            (
                EN.new_rule_button,
                RU.new_rule_button,
                "new-rule-button",
                &[] as &[(&str, &str)],
            ),
            (EN.new_rule, RU.new_rule, "new-rule", &[] as &[(&str, &str)]),
            (
                EN.new_rule_subtitle,
                RU.new_rule_subtitle,
                "new-rule-subtitle",
                &[] as &[(&str, &str)],
            ),
            (EN.edit, RU.edit, "edit", &[] as &[(&str, &str)]),
            (
                EN.edit_rule,
                RU.edit_rule,
                "edit-rule",
                &[] as &[(&str, &str)],
            ),
            (
                EN.edit_rule_subtitle,
                RU.edit_rule_subtitle,
                "edit-rule-subtitle",
                &[] as &[(&str, &str)],
            ),
            (EN.saving, RU.saving, "saving", &[] as &[(&str, &str)]),
            (
                EN.what_to_route,
                RU.what_to_route,
                "what-to-route",
                &[] as &[(&str, &str)],
            ),
            (
                EN.where_to_route,
                RU.where_to_route,
                "where-to-route",
                &[] as &[(&str, &str)],
            ),
            (
                EN.temporary_chip,
                RU.temporary_chip,
                "temporary-chip",
                &[] as &[(&str, &str)],
            ),
            (
                EN.temporary_dialog_hint,
                RU.temporary_dialog_hint,
                "temporary-dialog-hint",
                &[] as &[(&str, &str)],
            ),
            (
                EN.rule_kind_app,
                RU.rule_kind_app,
                "rule-kind-app",
                &[] as &[(&str, &str)],
            ),
            (
                EN.rule_kind_site,
                RU.rule_kind_site,
                "rule-kind-site",
                &[] as &[(&str, &str)],
            ),
            (EN.find_app, RU.find_app, "find-app", &[] as &[(&str, &str)]),
            (EN.open_tab, RU.open_tab, "open-tab", &[] as &[(&str, &str)]),
            (
                EN.all_processes,
                RU.all_processes,
                "all-processes",
                &[("n", "{n}")] as &[(&str, &str)],
            ),
            (
                EN.found,
                RU.found,
                "found",
                &[("n", "{n}")] as &[(&str, &str)],
            ),
            (
                EN.typed_process,
                RU.typed_process,
                "typed-process",
                &[] as &[(&str, &str)],
            ),
            (
                EN.sites_label,
                RU.sites_label,
                "sites-label",
                &[] as &[(&str, &str)],
            ),
            (
                EN.line_error,
                RU.line_error,
                "line-error",
                &[("error", "{error}"), ("n", "{n}")] as &[(&str, &str)],
            ),
            (
                EN.more_errors,
                RU.more_errors,
                "more-errors",
                &[("k", "{k}")] as &[(&str, &str)],
            ),
            (
                EN.add_rules_one,
                RU.add_rules_one,
                "add-rules-one",
                &[("n", "{n}")] as &[(&str, &str)],
            ),
            (
                EN.add_rules_few,
                RU.add_rules_few,
                "add-rules-few",
                &[("n", "{n}")] as &[(&str, &str)],
            ),
            (
                EN.add_rules_many,
                RU.add_rules_many,
                "add-rules-many",
                &[("n", "{n}")] as &[(&str, &str)],
            ),
            (
                EN.include_subdomains,
                RU.include_subdomains,
                "include-subdomains",
                &[] as &[(&str, &str)],
            ),
            (
                EN.include_subdomains_detail,
                RU.include_subdomains_detail,
                "include-subdomains-detail",
                &[] as &[(&str, &str)],
            ),
            (EN.advanced, RU.advanced, "advanced", &[] as &[(&str, &str)]),
            (
                EN.full_path_detail,
                RU.full_path_detail,
                "full-path-detail",
                &[] as &[(&str, &str)],
            ),
            (EN.refresh, RU.refresh, "refresh", &[] as &[(&str, &str)]),
            (
                EN.loading_processes,
                RU.loading_processes,
                "loading-processes",
                &[] as &[(&str, &str)],
            ),
            (
                EN.no_running_processes,
                RU.no_running_processes,
                "no-running-processes",
                &[] as &[(&str, &str)],
            ),
            (
                EN.no_processes_match,
                RU.no_processes_match,
                "no-processes-match",
                &[] as &[(&str, &str)],
            ),
            (
                EN.path_unavailable,
                RU.path_unavailable,
                "path-unavailable",
                &[] as &[(&str, &str)],
            ),
            (
                EN.match_by_full_path,
                RU.match_by_full_path,
                "match-by-full-path",
                &[] as &[(&str, &str)],
            ),
            (EN.add_rule, RU.add_rule, "add-rule", &[] as &[(&str, &str)]),
            (
                EN.adding_rule,
                RU.adding_rule,
                "adding-rule",
                &[] as &[(&str, &str)],
            ),
            (
                EN.language_title,
                RU.language_title,
                "language-title",
                &[] as &[(&str, &str)],
            ),
            (
                EN.language_system,
                RU.language_system,
                "language-system",
                &[] as &[(&str, &str)],
            ),
        ];
        #[cfg(windows)]
        cases.extend([
            (
                EN.start_with_windows,
                RU.start_with_windows,
                "start-with-windows",
                &[] as &[(&str, &str)],
            ),
            (
                EN.start_with_windows_detail,
                RU.start_with_windows_detail,
                "start-with-windows-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.keep_in_tray,
                RU.keep_in_tray,
                "keep-in-tray",
                &[] as &[(&str, &str)],
            ),
            (
                EN.keep_in_tray_detail,
                RU.keep_in_tray_detail,
                "keep-in-tray-detail",
                &[] as &[(&str, &str)],
            ),
            (
                EN.tray_open,
                RU.tray_open,
                "tray-open",
                &[] as &[(&str, &str)],
            ),
            (
                EN.tray_hide,
                RU.tray_hide,
                "tray-hide",
                &[] as &[(&str, &str)],
            ),
            (
                EN.tray_quit,
                RU.tray_quit,
                "tray-quit",
                &[] as &[(&str, &str)],
            ),
            (EN.browse, RU.browse, "browse", &[] as &[(&str, &str)]),
            (
                EN.choose_program,
                RU.choose_program,
                "choose-program",
                &[] as &[(&str, &str)],
            ),
            (EN.programs, RU.programs, "programs", &[] as &[(&str, &str)]),
        ]);
        for (english, russian, key, replacements) in cases {
            let mut args = FluentArgs::new();
            for (name, value) in replacements {
                args.set(*name, *value);
            }
            assert_eq!(tr_in(Language::English, key, &args), english, "{key}: en");
            assert_eq!(tr_in(Language::Russian, key, &args), russian, "{key}: ru");
        }
    }
}
