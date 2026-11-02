# Interface translations

`en.ftl` and `ru.ftl` contain the GUI's user-facing copy. Both files are embedded in the binary with `include_str!`; no translation files are needed beside the executable.

To add a message, give it the same kebab-case key in both files and use `tr!("key")` or `tr!("key", name = value)` in the GUI. For an error or test with an explicit language, use `tr_in(language, "key", &args)`. Keep keys literal; the tests reject missing and unused messages. Preformat paths, rates, sizes, timestamps, provider text, and displayed counts as **strings**, so Fluent cannot change their punctuation or group their digits. Use a numeric `count` argument only to choose a plural branch, and a separate string such as `n = count.to_string()` to display the number. Cover `one`/`few`/`many`/`other` in Russian selects and give each select a default branch.

A message that a language lacks or cannot format shows its English text. Debug builds stop at it (`debug_assert!`); release builds log one warning per language and key, with the key and the language code only.

## Languages

`LANGUAGES` in `src/i18n.rs` is the one list of interface languages: the code (`en`, `ru`, also the Fluent locale and the system language it is chosen for), the name in the language itself for the selector, the `.ftl` file, the writing direction and the stored setting. English comes first. The language selector, the system-language choice at first start (the Windows display language, or `LC_ALL`, `LC_MESSAGES`, `LANG` on Linux) and the validation tests are built from it.

To add a language:

1. Add `xx.ftl` here with every message and term of `en.ftl`; the tests reject a missing key or variable.
2. Add a row to `LANGUAGES` and its variant to `Language` in the same position.
3. Add a variant to `LanguageSetting` in `rosetun-config`. It is stored in the settings, so it follows the repository's settings-versioning rules: an older release cannot read the new value.

Right-to-left languages (Arabic, Persian, Hebrew) are not supported as interface languages: egui lays text out left to right without shaping, so their letters would show reversed and unjoined. `Direction` has only `LeftToRight`, and a test keeps every language there. Names in these scripts, such as server names, are still shown with that limitation.

The interface bundles only Manrope (Latin and Cyrillic) and egui's fonts. Chinese, Japanese, Korean, Thai, Indic and other scripts come from system fonts found on demand (`src/system_fonts.rs`): known fonts in the Windows fonts folder, or fontconfig on Linux (the Noto fonts). A language in such a script needs those fonts on the user's system, or its text shows as squares.

Keep existing copy byte-for-byte when moving it. Do not use an em dash (`—`); separate parts with `·`, and write waiting text with `…` rather than `...`. Escape literal Fluent braces and leading/trailing spaces, and check multiline text for unintended whitespace. Nontranslated labels and placeholders live in `src/constants.rs`; punctuation-only formatting helpers remain in `src/i18n/format.rs`.

`src/i18n/validation.rs` checks message/term completeness, AST variable parity, source key usage, formatting errors, plural boundaries, punctuation, and isolation marks. Existing output assertions are in `src/i18n/tests.rs` and other GUI tests. `set_use_isolating(false)` is required because Fluent otherwise inserts invisible U+2068/U+2069 marks around arguments, which egui can render as squares and which would alter the existing strings.
