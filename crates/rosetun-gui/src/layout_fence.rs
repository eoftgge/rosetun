//! Keeps spacing, type, corner and colour literals out of the views and widgets: they
//! take their values from the scales in `theme`.

use std::fs;
use std::path::{Path, PathBuf};

/// Calls whose arguments must hold no number but zero.
const WATCHED_CALLS: [&str; 8] = [
    "add_space(",
    "FontId::new(",
    "FontId::monospace(",
    "FontId::proportional(",
    ".size(",
    "CornerRadius::same(",
    "Stroke::new(",
    "item_spacing",
];

/// Calls that must not appear at all: a colour is a `Palette` field or a constant of `theme`.
const FORBIDDEN_CALLS: [&str; 3] = [
    "Color32::from_rgb(",
    "Color32::from_rgba_unmultiplied(",
    "Color32::from_rgba_premultiplied(",
];

/// A literal that may stay in a view, with the reason.
struct Allowed {
    /// Path below `src`, with `/`.
    file: &'static str,
    /// The watched call, as in `WATCHED_CALLS`.
    call: &'static str,
    /// The call's arguments without whitespace.
    arguments: &'static str,
    reason: &'static str,
}

const ALLOWED: [Allowed; 1] = [Allowed {
    file: "view/rules/table.rs",
    call: "add_space(",
    arguments: "((theme::RULE_ROW-content_height)/2.0).max(0.0)",
    reason: "half of the free height of a row, not a step",
}];

#[derive(Debug, PartialEq, Eq)]
struct Violation {
    line: usize,
    call: &'static str,
    arguments: String,
}

fn is_identifier_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn blank(c: char) -> char {
    if c == '\n' { '\n' } else { ' ' }
}

/// The source with comments and the insides of string and char literals blanked, line
/// breaks kept, so a search never matches text that is not code.
fn mask(source: &str) -> Vec<char> {
    let chars: Vec<char> = source.replace("\r\n", "\n").chars().collect();
    let mut out = chars.clone();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                out[i] = ' ';
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0;
            while i < chars.len() {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    out[i] = ' ';
                    out[i + 1] = ' ';
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    out[i] = ' ';
                    out[i + 1] = ' ';
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out[i] = blank(chars[i]);
                    i += 1;
                }
            }
        } else if c == 'r' && starts_raw_string(&chars, i) {
            let mut hashes = 0;
            let mut j = i + 1;
            while chars[j] == '#' {
                hashes += 1;
                j += 1;
            }
            // `chars[j]` is the opening quote.
            j += 1;
            while j < chars.len() {
                if chars[j] == '"' && (1..=hashes).all(|k| chars.get(j + k) == Some(&'#')) {
                    j += hashes;
                    break;
                }
                out[j] = blank(chars[j]);
                j += 1;
            }
            i = j + 1;
        } else if c == '"' {
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    out[i] = ' ';
                    i += 1;
                }
                out[i] = blank(chars[i]);
                i += 1;
            }
            i += 1;
        } else if c == '\'' {
            // A char literal, not a lifetime.
            if next == Some('\\') {
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    out[i] = blank(chars[i]);
                    i += 1;
                    if chars[i - 1] == '\\' && i < chars.len() {
                        out[i] = blank(chars[i]);
                        i += 1;
                    }
                }
                i += 1;
            } else if chars.get(i + 2) == Some(&'\'') {
                out[i + 1] = blank(chars[i + 1]);
                i += 3;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out
}

/// True when the `r` at `at` opens a raw string, such as `r"` or `r#"`.
fn starts_raw_string(chars: &[char], at: usize) -> bool {
    let before = at.checked_sub(1).map(|i| chars[i]);
    let after_byte_prefix = before == Some('b')
        && at
            .checked_sub(2)
            .is_none_or(|i| !is_identifier_char(chars[i]));
    if before.is_some_and(is_identifier_char) && !after_byte_prefix {
        return false;
    }
    let mut j = at + 1;
    while chars.get(j) == Some(&'#') {
        j += 1;
    }
    chars.get(j) == Some(&'"')
}

/// Where the item that starts at `from` ends: at a `;` outside brackets, or at the bracket
/// that closes the first one.
fn item_end(code: &[char], from: usize) -> usize {
    let mut depth = 0_i32;
    let mut i = from;
    while i < code.len() {
        match code[i] {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' => depth -= 1,
            '}' => {
                depth -= 1;
                if depth <= 0 {
                    return i;
                }
            }
            ';' if depth == 0 => return i,
            _ => {}
        }
        i += 1;
    }
    code.len().saturating_sub(1)
}

/// The code with the items marked `#[cfg(test)]` blanked.
fn without_test_items(mut code: Vec<char>) -> Vec<char> {
    let attribute: Vec<char> = "#[cfg(test)]".chars().collect();
    let mut i = 0;
    while i + attribute.len() <= code.len() {
        if code[i..i + attribute.len()] == attribute[..] {
            let end = item_end(&code, i + attribute.len());
            for c in &mut code[i..=end] {
                *c = blank(*c);
            }
            i = end + 1;
        } else {
            i += 1;
        }
    }
    code
}

fn find_all(code: &[char], needle: &str) -> Vec<usize> {
    let needle: Vec<char> = needle.chars().collect();
    (0..code.len().saturating_sub(needle.len() - 1))
        .filter(|&i| code[i..i + needle.len()] == needle[..])
        .collect()
}

/// The text from `from` to the bracket that closes the one before it.
fn call_arguments(code: &[char], from: usize) -> String {
    let mut depth = 1_i32;
    let mut end = from;
    while end < code.len() {
        match code[end] {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        end += 1;
    }
    code[from..end].iter().collect()
}

/// The text up to the first comma that is not inside brackets.
fn first_argument(arguments: &str) -> &str {
    let mut depth = 0_i32;
    for (index, c) in arguments.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => return &arguments[..index],
            _ => {}
        }
    }
    arguments
}

/// The right-hand side of `item_spacing`, `item_spacing.x` or `item_spacing.y` when the
/// text assigns to it; `None` when it only reads it.
fn spacing_assignment(code: &[char], after: usize) -> Option<String> {
    let mut i = after;
    if code.get(i) == Some(&'.') && matches!(code.get(i + 1), Some('x' | 'y')) {
        i += 2;
    }
    while code.get(i).is_some_and(|c| c.is_whitespace()) {
        i += 1;
    }
    if code.get(i) != Some(&'=') || code.get(i + 1) == Some(&'=') {
        return None;
    }
    i += 1;
    let start = i;
    while i < code.len() && code[i] != ';' {
        i += 1;
    }
    Some(code[start..i].iter().collect())
}

/// True when the text holds a number other than zero.
fn has_number(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let starts_number = chars[i].is_ascii_digit()
            && (i == 0 || !(is_identifier_char(chars[i - 1]) || chars[i - 1] == '.'));
        if !starts_number {
            i += 1;
            continue;
        }
        let mut end = i;
        while end < chars.len() && (is_identifier_char(chars[end]) || chars[end] == '.') {
            // `1.max(2)` and `0..4` are not part of the number.
            if chars[end] == '.' && !chars.get(end + 1).is_some_and(char::is_ascii_digit) {
                break;
            }
            end += 1;
        }
        let literal: String = chars[i..end].iter().collect();
        let digits: String = literal
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let zero = !literal.starts_with("0x") && digits.chars().all(|c| c == '0' || c == '.');
        if !zero {
            return true;
        }
        i = end.max(i + 1);
    }
    false
}

fn violations(source: &str) -> Vec<Violation> {
    let code = without_test_items(mask(source));
    let line_of = |offset: usize| code[..offset].iter().filter(|c| **c == '\n').count() + 1;
    let mut found = Vec::new();
    for call in WATCHED_CALLS {
        for at in find_all(&code, call) {
            let after = at + call.chars().count();
            let arguments = match call {
                "item_spacing" => spacing_assignment(&code, after),
                // The size, the width or the radius; the rest is a colour or a family.
                "FontId::new(" | "Stroke::new(" => {
                    Some(first_argument(&call_arguments(&code, after)).to_owned())
                }
                _ => Some(call_arguments(&code, after)),
            };
            if let Some(arguments) = arguments.filter(|text| has_number(text)) {
                found.push(Violation {
                    line: line_of(at),
                    call,
                    arguments: arguments.split_whitespace().collect(),
                });
            }
        }
    }
    for call in FORBIDDEN_CALLS {
        for at in find_all(&code, call) {
            found.push(Violation {
                line: line_of(at),
                call,
                arguments: String::new(),
            });
        }
    }
    found.sort_by_key(|violation| violation.line);
    found
}

fn rust_files(directory: &Path, files: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy();
        if path.is_dir() {
            if name != "tests" {
                rust_files(&path, files);
            }
        } else if name != "tests.rs" && path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}

#[test]
fn views_and_widgets_take_their_layout_from_the_theme_scales() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    for directory in ["view", "widgets"] {
        rust_files(&src.join(directory), &mut files);
    }
    assert!(
        files.len() > 20,
        "the fence found only {} files",
        files.len()
    );
    assert!(ALLOWED.iter().all(|allowed| !allowed.reason.is_empty()));
    let mut report = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(&src)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let source = fs::read_to_string(&path).unwrap();
        for violation in violations(&source) {
            let allowed = ALLOWED.iter().any(|allowed| {
                allowed.file == relative
                    && allowed.call == violation.call
                    && allowed.arguments == violation.arguments
            });
            if !allowed {
                report.push(format!(
                    "{relative}:{}: {}{}",
                    violation.line, violation.call, violation.arguments
                ));
            }
        }
    }
    assert!(
        report.is_empty(),
        "literals outside the scales in `theme` (space, font, radius, stroke, alpha, colours):\n{}",
        report.join("\n")
    );
}

#[test]
fn the_fence_catches_a_number_in_each_call_it_watches() {
    let source = "\
fn view(ui: &mut Ui) {
    ui.add_space(14.0);
    ui.spacing_mut().item_spacing.y = 6.0;
    ui.spacing_mut().item_spacing = egui::vec2(10.0, 8.0);
    let a = FontId::new(13.0, family);
    let b = FontId::monospace(11.0);
    let c = egui::FontId::proportional(13.0);
    let d = RichText::new(text).size(24.0);
    let e = CornerRadius::same(9);
    let f = Stroke::new(1.5, color);
    let g = Color32::from_rgb(1, 2, 3);
    let h = Color32::from_rgba_unmultiplied(1, 2, 3, 128);
}
";
    let found: Vec<_> = violations(source)
        .into_iter()
        .map(|violation| (violation.line, violation.call))
        .collect();
    assert_eq!(
        found,
        [
            (2, "add_space("),
            (3, "item_spacing"),
            (4, "item_spacing"),
            (5, "FontId::new("),
            (6, "FontId::monospace("),
            (7, "FontId::proportional("),
            (8, ".size("),
            (9, "CornerRadius::same("),
            (10, "Stroke::new("),
            (11, "Color32::from_rgb("),
            (12, "Color32::from_rgba_unmultiplied("),
        ]
    );
}

#[test]
fn the_fence_catches_a_number_inside_an_expression() {
    let source = "\
ui.add_space(if narrow { theme::space::M } else { 36.0 });
ui.add_space(22.0 + ui.spacing().item_spacing.x);
";
    assert_eq!(violations(source).len(), 2);
}

#[test]
fn the_fence_accepts_tokens_zero_and_reads_of_the_spacing() {
    let source = "\
fn view(ui: &mut Ui) {
    ui.add_space(theme::space::M);
    ui.add_space(0.0);
    ui.add_space(GAP2);
    ui.spacing_mut().item_spacing.x = 0.0;
    ui.spacing_mut().item_spacing.y = theme::space::XS;
    let gap = ui.spacing().item_spacing.x;
    let same = ui.spacing().item_spacing.x == other;
    let font = FontId::new(theme::font::BRAND_NAME, family);
    let size = galley.size().x;
    let radius = CornerRadius::same(theme::RADIUS);
    let stroke = Stroke::new(theme::stroke::HAIRLINE * scale, color);
}
";
    assert_eq!(violations(source), []);
}

#[test]
fn the_fence_skips_comments_strings_and_raw_strings() {
    let source = r##"
// ui.add_space(12.0);
/* ui.add_space(12.0); /* nested */ ui.add_space(12.0); */
/// `Color32::from_rgb(1, 2, 3)` in a doc comment.
fn view() {
    let text = "ui.add_space(12.0) and \" ui.add_space(8.0)";
    let raw = r#"ui.add_space(12.0) "quoted" Stroke::new(1.0, c)"#;
    let brace = '{';
    let quote = '"';
    ui.add_space(theme::space::S);
}
"##;
    assert_eq!(violations(source), []);
}

#[test]
fn the_fence_skips_test_items_and_checks_what_follows_them() {
    let source = "\
#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
fn helper() {
    ui.add_space(12.0);
}

fn view() {
    ui.add_space(theme::space::S);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spaced() {
        let braces = \"{\";
        ui.add_space(12.0);
    }
}

#[cfg(test)]
const SPACES: [f32; 2] = [1.0, 2.0];

fn after() {
    ui.add_space(14.0);
}
";
    let found = violations(source);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].line, 28);
}

#[test]
fn the_fence_reads_crlf_and_lf_sources_alike() {
    let lf = "fn view() {\n    ui.add_space(14.0);\n}\n";
    let crlf = lf.replace('\n', "\r\n");
    assert_eq!(violations(lf), violations(&crlf));
    assert_eq!(violations(&crlf).len(), 1);
}
