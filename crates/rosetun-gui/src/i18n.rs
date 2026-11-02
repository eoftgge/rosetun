use std::collections::HashSet;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

use fluent_bundle::concurrent::FluentBundle;
use fluent_bundle::{FluentArgs, FluentResource};
use rosetun_config::{CountryCode, LanguageSetting};

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
mod system_checks;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod validation;
pub(crate) use format::*;
pub(crate) use system_checks::{check_detail, check_hint, check_issue};

/// An interface language. Its index is its row in [`LANGUAGES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Language {
    English,
    Russian,
}

/// The writing direction of an interface language. egui lays text out left to right without
/// shaping, so a right-to-left interface language would show reversed, unjoined letters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    LeftToRight,
}

/// Everything the interface knows about one language.
pub(crate) struct LanguageInfo {
    pub(crate) language: Language,
    /// The stored choice in the settings.
    pub(crate) setting: LanguageSetting,
    /// The BCP 47 language subtag: the Fluent locale and the system language it is chosen for.
    pub(crate) code: &'static str,
    /// The name in the language itself, as the language selector shows it.
    pub(crate) native_name: &'static str,
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "egui has no right-to-left layout; a test keeps it so")
    )]
    pub(crate) direction: Direction,
    source: &'static str,
}

impl Language {
    pub(crate) fn info(self) -> &'static LanguageInfo {
        &LANGUAGES[self as usize]
    }
}

/// The interface languages, English first: it is the text of a message another language lacks.
/// Adding a language is a `.ftl` file in `i18n/` and a row here (with its `Language` variant and
/// stored `LanguageSetting`).
pub(crate) const LANGUAGES: [LanguageInfo; 2] = [
    LanguageInfo {
        language: Language::English,
        setting: LanguageSetting::English,
        code: "en",
        native_name: "English",
        direction: Direction::LeftToRight,
        source: include_str!("../i18n/en.ftl"),
    },
    LanguageInfo {
        language: Language::Russian,
        setting: LanguageSetting::Russian,
        code: "ru",
        native_name: "Русский",
        direction: Direction::LeftToRight,
        source: include_str!("../i18n/ru.ftl"),
    },
];

static CURRENT: AtomicU8 = AtomicU8::new(0);
static BUNDLES: [OnceLock<FluentBundle<FluentResource>>; LANGUAGES.len()] =
    [const { OnceLock::new() }; LANGUAGES.len()];
static WARNED: OnceLock<Mutex<HashSet<(Language, String)>>> = OnceLock::new();

#[cfg(test)]
thread_local! {
    static TEST_LANGUAGE: std::cell::Cell<Option<Language>> = const { std::cell::Cell::new(None) };
}

/// Runs `run` with the interface in `language` on this thread only, so tests in parallel
/// keep their own.
#[cfg(test)]
pub(crate) fn in_language<T>(language: Language, run: impl FnOnce() -> T) -> T {
    struct Restore(Option<Language>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_LANGUAGE.with(|slot| slot.set(self.0));
        }
    }
    let previous = TEST_LANGUAGE.with(|slot| slot.replace(Some(language)));
    let _restore = Restore(previous);
    run()
}

pub(crate) fn set_language(language: Language) {
    CURRENT.store(language as u8, Ordering::Relaxed);
}

pub(crate) fn language() -> Language {
    #[cfg(test)]
    if let Some(language) = TEST_LANGUAGE.with(std::cell::Cell::get) {
        return language;
    }
    LANGUAGES
        .get(usize::from(CURRENT.load(Ordering::Relaxed)))
        .map_or(Language::English, |info| info.language)
}

/// The language a setting shows; `system` is the system's language when the interface has it.
pub(crate) fn resolve_language(setting: LanguageSetting, system: Option<Language>) -> Language {
    match setting {
        LanguageSetting::System => system,
        chosen => LANGUAGES
            .iter()
            .find(|info| info.setting == chosen)
            .map(|info| info.language),
    }
    .unwrap_or(Language::English)
}

/// The interface language for a locale name such as `ru-RU`, `ru_RU.UTF-8` or `pt_BR@euro`.
pub(crate) fn language_of_locale(locale: &str) -> Option<Language> {
    let subtag = locale
        .split(['-', '_', '.', '@'])
        .next()
        .filter(|subtag| !subtag.is_empty())?;
    LANGUAGES
        .iter()
        .find(|info| info.code.eq_ignore_ascii_case(subtag))
        .map(|info| info.language)
}

fn bundle(language: Language) -> &'static FluentBundle<FluentResource> {
    let info = language.info();
    BUNDLES[language as usize].get_or_init(|| {
        let code = info.code;
        let resource = FluentResource::try_new(info.source.to_owned())
            .unwrap_or_else(|(_, errors)| panic!("Invalid embedded {code}.ftl: {errors:?}"));
        let locale = code.parse().expect("Valid embedded language identifier");
        let mut bundle = FluentBundle::new_concurrent(vec![locale]);
        bundle.set_use_isolating(false);
        bundle
            .add_resource(resource)
            .unwrap_or_else(|errors| panic!("Could not load embedded {code}.ftl: {errors:?}"));
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
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert((language, key.to_owned()))
    {
        tracing::warn!(
            key,
            language = language.info().code,
            "could not format interface text"
        );
    }
    format(Language::English, key, args).unwrap_or_else(|| key.to_owned())
}

/// The country's short name; every `CountryCode::all` code has a `country-XX` message.
pub(crate) fn country_name(code: &CountryCode) -> String {
    format(
        language(),
        &format!("country-{}", code.as_str()),
        &FluentArgs::new(),
    )
    .unwrap_or_else(|| code.as_str().to_owned())
}

#[cfg(test)]
mod loader_tests {
    use super::*;

    #[test]
    fn every_language_is_its_own_row_and_english_comes_first() {
        assert_eq!(LANGUAGES[0].language, Language::English);
        for (index, info) in LANGUAGES.iter().enumerate() {
            assert_eq!(info.language as usize, index, "{}", info.code);
            assert_eq!(info.language.info().code, info.code);
            assert_eq!(info.direction, Direction::LeftToRight, "{}", info.code);
            assert_ne!(info.setting, LanguageSetting::System, "{}", info.code);
            assert!(!info.native_name.is_empty(), "{}", info.code);
            let others = LANGUAGES.iter().filter(|other| other.code != info.code);
            for other in others {
                assert_ne!(info.setting, other.setting, "{}", info.code);
                assert_ne!(info.native_name, other.native_name, "{}", info.code);
            }
            assert!(!tr_in(info.language, "connection", &FluentArgs::new()).is_empty());
        }
    }

    #[test]
    fn language_resolution_covers_all_settings_and_system_languages() {
        for (setting, system, expected) in [
            (LanguageSetting::System, None, Language::English),
            (LanguageSetting::System, Some(Language::English), Language::English),
            (LanguageSetting::System, Some(Language::Russian), Language::Russian),
            (LanguageSetting::English, None, Language::English),
            (LanguageSetting::English, Some(Language::Russian), Language::English),
            (LanguageSetting::Russian, None, Language::Russian),
            (LanguageSetting::Russian, Some(Language::English), Language::Russian),
        ] {
            assert_eq!(resolve_language(setting, system), expected);
        }
    }

    #[test]
    fn locale_names_choose_a_language_by_their_language_subtag() {
        for (locale, expected) in [
            ("ru-RU", Some(Language::Russian)),
            ("ru_RU.UTF-8", Some(Language::Russian)),
            ("ru", Some(Language::Russian)),
            ("RU_ua", Some(Language::Russian)),
            ("en-GB", Some(Language::English)),
            ("en_US.UTF-8", Some(Language::English)),
            ("de_DE@euro", None),
            ("rue-SK", None),
            ("C.UTF-8", None),
            ("POSIX", None),
            ("", None),
        ] {
            assert_eq!(language_of_locale(locale), expected, "{locale}");
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
