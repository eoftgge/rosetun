use super::*;
use fluent_bundle::{FluentArgs, FluentResource};
use rosetun_config::{ConnectStage, FailureKind, LanguageSetting};

fn in_language<T>(language: Language, run: impl FnOnce() -> T) -> T {
    struct Restore(Option<Language>);
    impl Drop for Restore {
        fn drop(&mut self) {
            super::TEST_LANGUAGE.with(|slot| slot.set(self.0));
        }
    }
    let previous = super::TEST_LANGUAGE.with(|slot| slot.replace(Some(language)));
    let _restore = Restore(previous);
    run()
}

fn test_bundle(source: &str, language: &str) -> FluentBundle<FluentResource> {
    let resource = FluentResource::try_new(source.to_owned()).expect("Valid test FTL");
    let mut bundle = FluentBundle::new_concurrent(vec![language.parse().unwrap()]);
    bundle.set_use_isolating(false);
    bundle.add_resource(resource).unwrap();
    bundle
}

fn test_message(bundle: &FluentBundle<FluentResource>, key: &str, args: &FluentArgs<'_>) -> String {
    let mut errors = Vec::new();
    let text = bundle.format_pattern(
        bundle.get_message(key).unwrap().value().unwrap(),
        Some(args),
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:?}");
    text.into_owned()
}

#[test]
fn fill_does_not_expand_values_again() {
    let bundle = test_bundle(
        r#"first = { $a } and { $b }
second = {"{"}unknown{"}"} { $a } {"{"}open"#,
        "en",
    );
    let mut first = FluentArgs::new();
    first.set("a", "{b}");
    first.set("b", "x");
    assert_eq!(test_message(&bundle, "first", &first), "{b} and x");
    let mut second = FluentArgs::new();
    second.set("a", "x");
    assert_eq!(
        test_message(&bundle, "second", &second),
        "{unknown} x {open"
    );
}

#[test]
fn byte_counts_and_rates_use_localized_three_digit_units() {
    for (language, zero, kib, mib_rate, mib, gib, threshold) in [
        (
            Language::English,
            "0 B/s",
            "1.50 KiB",
            "11.8 MiB/s",
            "150 MiB",
            "1.82 GiB",
            "0.98 MiB",
        ),
        (
            Language::Russian,
            "0 Б/с",
            "1,50 КБ",
            "11,8 МБ/с",
            "150 МБ",
            "1,82 ГБ",
            "0,98 МБ",
        ),
    ] {
        in_language(language, || {
            assert_eq!(rate(0), zero);
            assert_eq!(
                bytes(512),
                if language == Language::English {
                    "512 B"
                } else {
                    "512 Б"
                }
            );
            assert_eq!(bytes(1536), kib);
            assert_eq!(rate(12_373_196), mib_rate);
            assert_eq!(bytes(157_286_400), mib);
            assert_eq!(bytes(1_954_210_119), gib);
            assert_eq!(bytes(1_024_000), threshold);
        });
    }
}

#[test]
fn traffic_labels_format_both_directions_and_caption() {
    for (language, down, up, rates, caption) in [
        (
            Language::English,
            "1 MiB/s",
            "2 MiB/s",
            "↓ 1 MiB/s · ↑ 2 MiB/s",
            "Last 5 min · peak 2 MiB/s",
        ),
        (
            Language::Russian,
            "1 МБ/с",
            "2 МБ/с",
            "↓ 1 МБ/с · ↑ 2 МБ/с",
            "За 5 мин · пик 2 МБ/с",
        ),
    ] {
        in_language(language, || {
            let range = tr_in(language, "traffic-range-5m", &FluentArgs::new());
            assert_eq!(traffic_rates(down, up), rates);
            assert_eq!(traffic_chart_caption(&range, up), caption);
        });
    }
}

#[test]
fn add_rules_label_pluralizes_in_both_languages() {
    for (count, expected) in [
        (1, "Добавить правило"),
        (2, "Добавить 2 правила"),
        (5, "Добавить 5 правил"),
        (21, "Добавить 21 правило"),
    ] {
        assert_eq!(
            in_language(Language::Russian, || add_rules(count)),
            expected
        );
    }
    assert_eq!(in_language(Language::English, || add_rules(1)), "Add rule");
    assert_eq!(
        in_language(Language::English, || add_rules(2)),
        "Add 2 rules"
    );
}

#[test]
fn grouped_rule_labels_include_counts() {
    assert_eq!(
        in_language(Language::English, || delete_rules_heading(2)),
        "Delete 2 rules"
    );
    assert_eq!(
        in_language(Language::English, || delete_rules_heading(5)),
        "Delete 5 rules"
    );
    assert_eq!(
        in_language(Language::Russian, || delete_rules_heading(5)),
        "Удалить правила: 5"
    );
    assert_eq!(
        in_language(Language::Russian, || selected_rule_count(3)),
        "Выбрано: 3"
    );
    assert_eq!(
        in_language(Language::Russian, || delete_selected_rules(3)),
        "Удалить выбранные (3)"
    );
    assert_eq!(
        in_language(Language::Russian, || and_more_rules(2)),
        "и ещё 2"
    );
}

#[test]
fn interface_copy_uses_plain_punctuation_and_a_session_word() {
    assert_eq!(
        tr_in(Language::English, "no-session", &FluentArgs::new()),
        "not started"
    );
    assert_eq!(
        tr_in(Language::Russian, "no-session", &FluentArgs::new()),
        "не начат"
    );
    for table in [
        include_str!("../../i18n/en.ftl"),
        include_str!("../../i18n/ru.ftl"),
    ] {
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
fn about_version_includes_the_service_only_when_known() {
    assert_eq!(
        in_language(Language::English, || about_version("0.9.0", None)),
        "Version 0.9.0"
    );
    assert_eq!(
        in_language(Language::English, || about_version("0.9.0", Some("0.9.1"))),
        "Version 0.9.0 · service 0.9.1"
    );
    assert_eq!(
        in_language(Language::Russian, || about_version("0.9.0", None)),
        "Версия 0.9.0"
    );
    assert_eq!(
        in_language(Language::Russian, || about_version("0.9.0", Some("0.9.1"))),
        "Версия 0.9.0 · служба 0.9.1"
    );
}

#[test]
fn russian_plural_handles_tens_and_hundreds() {
    let bundle = test_bundle(
        "form = { $count ->\n    [one] one\n    [few] few\n    [many] many\n   *[other] many\n}",
        "ru",
    );
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
        let mut args = FluentArgs::new();
        args.set("count", count);
        assert_eq!(test_message(&bundle, "form", &args), expected, "{count}");
    }
    for (count, expected) in [
        (1, "1 сервер"),
        (3, "3 сервера"),
        (5, "5 серверов"),
        (21, "21 сервер"),
    ] {
        assert_eq!(in_language(Language::Russian, || servers(count)), expected);
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
            in_language(Language::Russian, || verbose_log_on_detail(hours)),
            format!(
                "Выключится сам через {expected}. Пока включён, записывает адреса сайтов. Применится при следующем подключении."
            )
        );
    }
    for (hours, expected) in [(1, "1 hour"), (24, "24 hours")] {
        assert_eq!(
            in_language(Language::English, || verbose_log_on_detail(hours)),
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
        assert_eq!(updated_ago_in(Language::English, 0, elapsed), expected);
    }
    assert_eq!(updated_ago_in(Language::English, 101, 100), "just now");
    assert_eq!(updated_ago_in(Language::English, u64::MAX, 0), "just now");
}

#[test]
fn term_left_covers_days_partial_days_and_expiry_in_both_languages() {
    for (language, one, two, five, partial, expired) in [
        (
            Language::English,
            "1 day left",
            "2 days left",
            "5 days left",
            "under a day",
            "expired",
        ),
        (
            Language::Russian,
            "ещё 1 день",
            "ещё 2 дня",
            "ещё 5 дней",
            "меньше дня",
            "истекла",
        ),
    ] {
        in_language(language, || {
            assert_eq!(term_left(86_400, 0), (one.to_owned(), false));
            assert_eq!(term_left(2 * 86_400, 0), (two.to_owned(), false));
            assert_eq!(term_left(5 * 86_400, 0), (five.to_owned(), false));
            assert_eq!(term_left(86_399, 0), (partial.to_owned(), false));
            assert_eq!(term_left(100, 100), (expired.to_owned(), true));
            assert_eq!(term_left(99, 100), (expired.to_owned(), true));
        });
    }
}

#[test]
fn russian_age_uses_lowercase_updated_summary() {
    assert_eq!(updated_ago_in(Language::Russian, 0, 30), "только что");
    assert_eq!(updated_ago_in(Language::Russian, 0, 120), "2 минуты назад");
    assert_eq!(
        updated_ago_in(Language::Russian, 0, 5 * 3600),
        "5 часов назад"
    );
    assert_eq!(updated_ago_in(Language::Russian, 0, 86_400), "1 день назад");
    assert_eq!(
        in_language(Language::Russian, || last_updated(&updated_ago(0, 5 * 60))),
        "обновлено 5 минут назад"
    );
    assert_eq!(
        in_language(Language::English, || last_updated("1 hour ago")),
        "updated 1 hour ago"
    );
    assert_eq!(
        tr_in(Language::Russian, "never-updated", &FluentArgs::new()),
        "ещё не обновлялась"
    );
    assert_eq!(
        tr_in(Language::English, "never-updated", &FluentArgs::new()),
        "not updated yet"
    );
}

#[test]
fn localized_failures_use_the_existing_action_labels() {
    for language in [Language::English, Language::Russian] {
        in_language(language, || {
            let (title, hint) = connection_failure(FailureKind::EngineNotReady);
            let retry = tr_in(language, "retry", &FluentArgs::new());
            let check_full = tr_in(language, "check-full", &FluentArgs::new());
            assert!(!title.is_empty());
            assert!(hint.contains(&retry));
            assert!(!hint.contains("{retry}"));
            let (_, hint) = connection_failure(FailureKind::ServerUnreachable);
            assert!(hint.contains(&check_full));
            assert!(!hint.contains("{url_test}"));
            assert!(connection_stage(ConnectStage::CheckingServer, 5).contains('5'));
            for kind in [
                FailureKind::ServerRejected,
                FailureKind::ServerClosed,
                FailureKind::DnsTimeout,
            ] {
                let (title, hint) = connection_failure(kind);
                assert!(!title.is_empty() && !hint.is_empty());
            }
        });
    }
    assert_eq!(
        in_language(Language::Russian, || connection_failure(
            FailureKind::ServerUnreachable
        )
        .0),
        "Сервер не отвечает"
    );
}
