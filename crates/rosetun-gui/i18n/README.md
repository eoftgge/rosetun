# Interface translations

`en.ftl` and `ru.ftl` contain the GUI's user-facing copy. Both files are embedded in the binary with `include_str!`; no translation files are needed beside the executable.

To add a message, give it the same kebab-case key in both files and use `tr!("key")` or `tr!("key", name = value)` in the GUI. For an error or test with an explicit language, use `tr_in(language, "key", &args)`. Keep keys literal; the tests reject missing and unused messages. Preformat paths, rates, sizes, timestamps, provider text, and displayed counts as **strings**, so Fluent cannot change their punctuation or group their digits. Use a numeric `count` argument only to choose a plural branch, and a separate string such as `n = count.to_string()` to display the number. Cover `one`/`few`/`many`/`other` in Russian selects and give each select a default branch.

To add a language, add an embedded `.ftl` file and extend `Language`, its bundle initialization, the language selector, and locale detection in `src/i18n.rs` and `src/app.rs`. Also update the serialized language setting and its configuration migration as required by the repository's versioning rules, then extend the translation validation tests. The system-language setting currently chooses Russian or English.

Keep existing copy byte-for-byte when moving it. Do not use an em dash (`—`); separate parts with `·`, and write waiting text with `…` rather than `...`. Escape literal Fluent braces and leading/trailing spaces, and check multiline text for unintended whitespace. Nontranslated labels and placeholders live in `src/constants.rs`; punctuation-only formatting helpers remain in `src/i18n/format.rs`.

`src/i18n/validation.rs` checks message/term completeness, AST variable parity, source key usage, formatting errors, plural boundaries, punctuation, and isolation marks. Existing output assertions are in `src/i18n/tests.rs` and other GUI tests. `set_use_isolating(false)` is required because Fluent otherwise inserts invisible U+2068/U+2069 marks around arguments, which egui can render as squares and which would alter the existing strings.
