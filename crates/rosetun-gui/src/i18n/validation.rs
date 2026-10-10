use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use fluent_bundle::concurrent::FluentBundle;
use fluent_bundle::{FluentArgs, FluentResource};
use fluent_syntax::{ast, parser};

#[derive(Default)]
struct EntryInfo {
    variables: BTreeSet<String>,
    references: BTreeSet<String>,
}

#[derive(Default)]
struct Catalog {
    messages: BTreeMap<String, EntryInfo>,
    terms: BTreeMap<String, EntryInfo>,
}

impl Catalog {
    fn get(&self, key: &str) -> &EntryInfo {
        if key.starts_with('-') {
            self.terms.get(key)
        } else {
            self.messages.get(key)
        }
        .unwrap_or_else(|| panic!("Missing Fluent reference: {key}"))
    }

    fn variables(&self, key: &str, seen: &mut BTreeSet<String>) -> BTreeSet<String> {
        if !seen.insert(key.to_owned()) {
            return BTreeSet::new();
        }
        let entry = self.get(key);
        let mut variables = entry.variables.clone();
        for reference in &entry.references {
            variables.extend(self.variables(reference, seen));
        }
        variables
    }
}

fn collect_pattern(pattern: &ast::Pattern<&str>, entry: &mut EntryInfo) {
    for element in &pattern.elements {
        if let ast::PatternElement::Placeable { expression } = element {
            collect_expression(expression, entry);
        }
    }
}

fn collect_expression(expression: &ast::Expression<&str>, entry: &mut EntryInfo) {
    match expression {
        ast::Expression::Inline(inline) => collect_inline(inline, entry),
        ast::Expression::Select { selector, variants } => {
            collect_inline(selector, entry);
            for variant in variants {
                collect_pattern(&variant.value, entry);
            }
        }
    }
}

fn collect_arguments(arguments: &ast::CallArguments<&str>, entry: &mut EntryInfo) {
    for argument in &arguments.positional {
        collect_inline(argument, entry);
    }
    for argument in &arguments.named {
        collect_inline(&argument.value, entry);
    }
}

fn collect_inline(inline: &ast::InlineExpression<&str>, entry: &mut EntryInfo) {
    match inline {
        ast::InlineExpression::VariableReference { id } => {
            entry.variables.insert(id.name.to_owned());
        }
        ast::InlineExpression::MessageReference { id, .. } => {
            entry.references.insert(id.name.to_owned());
        }
        ast::InlineExpression::TermReference { id, arguments, .. } => {
            entry.references.insert(format!("-{}", id.name));
            if let Some(arguments) = arguments {
                collect_arguments(arguments, entry);
            }
        }
        ast::InlineExpression::FunctionReference { arguments, .. } => {
            collect_arguments(arguments, entry);
        }
        ast::InlineExpression::Placeable { expression } => collect_expression(expression, entry),
        ast::InlineExpression::StringLiteral { .. }
        | ast::InlineExpression::NumberLiteral { .. } => {}
    }
}

fn catalog(source: &str) -> Catalog {
    let resource =
        parser::parse(source).unwrap_or_else(|(_, errors)| panic!("Invalid FTL: {errors:?}"));
    let mut catalog = Catalog::default();
    for entry in resource.body {
        match entry {
            ast::Entry::Message(message) => {
                let mut info = EntryInfo::default();
                collect_pattern(
                    message.value.as_ref().expect("Message needs a value"),
                    &mut info,
                );
                for attribute in message.attributes {
                    collect_pattern(&attribute.value, &mut info);
                }
                assert!(
                    catalog
                        .messages
                        .insert(message.id.name.to_owned(), info)
                        .is_none(),
                    "Duplicate message: {}",
                    message.id.name
                );
            }
            ast::Entry::Term(term) => {
                let mut info = EntryInfo::default();
                collect_pattern(&term.value, &mut info);
                for attribute in term.attributes {
                    collect_pattern(&attribute.value, &mut info);
                }
                let key = format!("-{}", term.id.name);
                assert!(
                    catalog.terms.insert(key.clone(), info).is_none(),
                    "Duplicate term: {key}"
                );
            }
            ast::Entry::Junk { .. } => panic!("FTL contains junk"),
            ast::Entry::Comment(_)
            | ast::Entry::GroupComment(_)
            | ast::Entry::ResourceComment(_) => {}
        }
    }
    catalog
}

fn resources() -> [(super::Language, &'static str); 2] {
    [
        (super::Language::English, include_str!("../../i18n/en.ftl")),
        (super::Language::Russian, include_str!("../../i18n/ru.ftl")),
    ]
}

#[test]
fn languages_define_the_same_messages_terms_and_variables() {
    let [(.., english), (.., russian)] = resources();
    let english = catalog(english);
    let russian = catalog(russian);
    assert_eq!(
        english.messages.keys().collect::<Vec<_>>(),
        russian.messages.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        english.terms.keys().collect::<Vec<_>>(),
        russian.terms.keys().collect::<Vec<_>>()
    );
    for key in english.messages.keys().chain(english.terms.keys()) {
        assert_eq!(
            english.get(key).variables,
            russian.get(key).variables,
            "Variables for {key}"
        );
        assert_eq!(
            english.variables(key, &mut BTreeSet::new()),
            russian.variables(key, &mut BTreeSet::new()),
            "Referenced variables for {key}"
        );
    }
}

#[test]
fn plural_forms_keep_legacy_copy_at_count_boundaries() {
    use super::{Language, tr_in};

    for (count, english, russian, russian_add) in [
        (0, "0 servers", "0 серверов", "Добавить 0 правил"),
        (1, "1 server", "1 сервер", "Добавить правило"),
        (2, "2 servers", "2 сервера", "Добавить 2 правила"),
        (3, "3 servers", "3 сервера", "Добавить 3 правила"),
        (4, "4 servers", "4 сервера", "Добавить 4 правила"),
        (5, "5 servers", "5 серверов", "Добавить 5 правил"),
        (11, "11 servers", "11 серверов", "Добавить 11 правил"),
        (12, "12 servers", "12 серверов", "Добавить 12 правил"),
        (21, "21 servers", "21 сервер", "Добавить 21 правило"),
        (22, "22 servers", "22 сервера", "Добавить 22 правила"),
        (25, "25 servers", "25 серверов", "Добавить 25 правил"),
        (101, "101 servers", "101 сервер", "Добавить 101 правило"),
        (111, "111 servers", "111 серверов", "Добавить 111 правил"),
        (
            1000,
            "1000 servers",
            "1000 серверов",
            "Добавить 1000 правил",
        ),
        (
            12345,
            "12345 servers",
            "12345 серверов",
            "Добавить 12345 правил",
        ),
    ] {
        let mut args = FluentArgs::new();
        args.set("count", count);
        args.set("n", count.to_string());
        assert_eq!(
            tr_in(Language::English, "servers", &args),
            english,
            "{count}"
        );
        assert_eq!(
            tr_in(Language::Russian, "servers", &args),
            russian,
            "{count}"
        );
        assert_eq!(
            tr_in(Language::Russian, "add-rules", &args),
            russian_add,
            "{count}"
        );
        assert_eq!(
            tr_in(Language::English, "add-rules", &args),
            if count == 1 {
                "Add rule".to_owned()
            } else {
                format!("Add {count} rules")
            },
            "{count}"
        );
        assert_eq!(
            tr_in(Language::English, "delete-rules-heading", &args),
            if count == 1 {
                "Delete 1 rule".to_owned()
            } else {
                format!("Delete {count} rules")
            },
            "{count}"
        );
        assert_eq!(
            tr_in(Language::Russian, "delete-rules-heading", &args),
            format!("Удалить правила: {count}"),
            "{count}"
        );
    }
}

fn string_literal(source: &str, after: usize) -> Option<String> {
    let source = source.get(after..)?.trim_start();
    let rest = source.strip_prefix('"')?;
    let length = rest.find('"')?;
    Some(rest[..length].to_owned())
}

fn source_keys(source: &str, path: &Path) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let boundary = |position: usize| {
        position == 0
            || !matches!(source.as_bytes()[position - 1], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_')
    };
    let macro_call = concat!("tr", "!(");
    for (position, _) in source.match_indices(macro_call) {
        if !boundary(position) {
            continue;
        }
        let key = string_literal(source, position + macro_call.len())
            .unwrap_or_else(|| panic!("Dynamic tr! key in {}:{position}", path.display()));
        keys.insert(key);
    }
    let function_call = concat!("tr", "_in(");
    for (position, _) in source.match_indices(function_call) {
        if !boundary(position) {
            continue;
        }
        let mut depth = 0;
        let mut comma = None;
        for (offset, byte) in source[position + function_call.len()..].bytes().enumerate() {
            match byte {
                b'(' => depth += 1,
                b')' if depth > 0 => depth -= 1,
                b',' if depth == 0 => {
                    comma = Some(position + function_call.len() + offset + 1);
                    break;
                }
                _ => {}
            }
        }
        let after = comma.expect("tr_in must have a key argument");
        if let Some(key) = string_literal(source, after) {
            keys.insert(key);
        } else {
            let remaining = source[after..].trim_start();
            // The macro definition forwards its literal key; this signature declares the function.
            assert!(
                remaining.starts_with("$key") || remaining.starts_with("key: &str"),
                "Dynamic tr_in key in {}:{position}",
                path.display()
            );
        }
    }
    keys
}

fn source_files(directory: &Path, keys: &mut BTreeSet<String>) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            source_files(&path, keys);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            keys.extend(source_keys(&fs::read_to_string(&path).unwrap(), &path));
        }
    }
}

#[test]
fn source_uses_only_existing_messages_and_no_messages_are_orphaned() {
    let [(.., english), (.., russian)] = resources();
    let english = catalog(english);
    let russian = catalog(russian);
    let mut used = BTreeSet::new();
    source_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut used,
    );
    for key in &used {
        assert!(
            english.messages.contains_key(key),
            "Unknown English key: {key}"
        );
        assert!(
            russian.messages.contains_key(key),
            "Unknown Russian key: {key}"
        );
    }
    let mut reachable = used;
    loop {
        let mut next = reachable.clone();
        for key in &reachable {
            next.extend(english.get(key).references.iter().cloned());
            next.extend(russian.get(key).references.iter().cloned());
        }
        if next == reachable {
            break;
        }
        reachable = next;
    }
    let all: BTreeSet<_> = english
        .messages
        .keys()
        .chain(english.terms.keys())
        .cloned()
        .collect();
    assert_eq!(reachable, all, "Unused or missing Fluent messages/terms");
}

fn sample_args<'a>(variables: impl Iterator<Item = &'a String>) -> FluentArgs<'static> {
    let mut args = FluentArgs::new();
    for name in variables {
        if name == "count" {
            args.set(name.to_owned(), 21);
        } else if matches!(
            name.as_str(),
            "n" | "k"
                | "days"
                | "hours"
                | "added"
                | "removed"
                | "retained"
                | "ms"
                | "line"
                | "column"
                | "status"
        ) {
            args.set(name.to_owned(), "21");
        } else {
            args.set(name.to_owned(), "example.com");
        }
    }
    args
}

#[test]
fn every_message_formats_without_errors_or_isolation_marks() {
    for (language, source) in resources() {
        let entries = catalog(source);
        let locale = match language {
            super::Language::English => "en",
            super::Language::Russian => "ru",
        };
        let resource = FluentResource::try_new(source.to_owned()).unwrap();
        let mut bundle = FluentBundle::new_concurrent(vec![locale.parse().unwrap()]);
        bundle.set_use_isolating(false);
        bundle.add_resource(resource).unwrap();
        for key in entries.messages.keys() {
            let variables = entries.variables(key, &mut BTreeSet::new());
            let args = sample_args(variables.iter());
            let mut errors = Vec::new();
            let message = bundle.get_message(key).unwrap();
            let text = bundle.format_pattern(message.value().unwrap(), Some(&args), &mut errors);
            assert!(errors.is_empty(), "{locale} {key}: {errors:?}");
            assert!(
                !text.contains('\u{2068}') && !text.contains('\u{2069}'),
                "{locale} {key} contains isolation marks"
            );
        }
        for key in entries.terms.keys() {
            let variables = entries.variables(key, &mut BTreeSet::new());
            let passed = variables
                .iter()
                .map(|name| format!("{name}: ${name}"))
                .collect::<Vec<_>>()
                .join(", ");
            let call = if passed.is_empty() {
                key.clone()
            } else {
                format!("{key}({passed})")
            };
            let sample = format!("{source}\nvalidation-term = {{ {call} }}\n");
            let resource = FluentResource::try_new(sample).unwrap();
            let mut term_bundle = FluentBundle::new_concurrent(vec![locale.parse().unwrap()]);
            term_bundle.set_use_isolating(false);
            term_bundle.add_resource(resource).unwrap();
            let args = sample_args(variables.iter());
            let mut errors = Vec::new();
            let message = term_bundle.get_message("validation-term").unwrap();
            let text =
                term_bundle.format_pattern(message.value().unwrap(), Some(&args), &mut errors);
            assert!(errors.is_empty(), "{locale} {key}: {errors:?}");
            assert!(
                !text.contains('\u{2068}') && !text.contains('\u{2069}'),
                "{locale} {key} contains isolation marks"
            );
        }
    }
}

#[test]
fn translation_files_use_plain_punctuation() {
    for (_, source) in resources() {
        assert!(!source.contains('—'));
        assert!(!source.contains("..."));
    }
}
