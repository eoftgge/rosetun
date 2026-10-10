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
#[cfg(test)]
mod tests;
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
mod loader_tests {
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
}
