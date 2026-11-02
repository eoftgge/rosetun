//! Keeps spacing, margin, type, corner, opacity and colour literals out of the views and
//! widgets: they take their values from the scales in `theme`. It also keeps the views from
//! building their own inputs, drop-downs and dialogs: those come from `widgets`.

use std::fs;
use std::path::{Path, PathBuf};

/// Calls whose arguments must hold no number but zero.
const WATCHED_CALLS: [&str; 14] = [
    "add_space(",
    "FontId::new(",
    "FontId::monospace(",
    "FontId::proportional(",
    ".size(",
    "CornerRadius::same(",
    "Stroke::new(",
    "item_spacing",
    "Margin::same(",
    "Margin::symmetric(",
    "Margin {",
    "inner_margin(",
    "outer_margin(",
    "gamma_multiply(",
];

/// The label of a violation by a named constant, as in `const ICON_GAP: f32 = 12.0;`.
const NAMED_GAP: &str = "const ";

/// A constant whose name holds one of these is a spacing, so it takes a `theme::space` step.
const GAP_WORDS: [&str; 5] = ["GAP", "PADDING", "INSET", "MARGIN", "SPACING"];

/// Calls that must not appear at all: a colour is a `Palette` field or a constant of `theme`.
const FORBIDDEN_CALLS: [&str; 3] = [
    "Color32::from_rgb(",
    "Color32::from_rgba_unmultiplied(",
    "Color32::from_rgba_premultiplied(",
];

/// Calls only `widgets` may make: a view takes an input, a drop-down and a dialog from there, so
/// that every one of them looks and measures alike.
const WIDGET_ONLY_CALLS: [&str; 3] = ["TextEdit::", "ComboBox::", "Modal::new("];

/// Calls that take no number in a view: the width of a dialog is a role (`DialogWidth`), and any
/// other width is a measure of the layout, not a literal.
const VIEW_NUMBER_FREE_CALLS: [&str; 1] = ["set_width("];

/// A constant named like this in a view would carry a dialog's width around the call above.
const DIALOG_WIDTH_WORDS: [&str; 2] = ["DIALOG_WIDTH", "MODAL_WIDTH"];

/// The label of a violation by a constant that holds a dialog's width.
const NAMED_DIALOG_WIDTH: &str = "const (dialog width) ";

/// A literal that may stay in a view, with the reason.
struct Allowed {
    /// Path below `src`, with `/`.
    file: &'static str,
    /// The watched call, as in `WATCHED_CALLS`, or `NAMED_GAP`.
    call: &'static str,
    /// The function that holds the call; `None` for any.
    function: Option<&'static str>,
    /// The call's arguments without whitespace (`NAME=value` for a constant); `None` for any.
    arguments: Option<&'static str>,
    reason: &'static str,
}

const ALLOWED: [Allowed; 9] = [
    Allowed {
        file: "view/rules/table.rs",
        call: "add_space(",
        function: None,
        arguments: Some("((theme::RULE_ROW-content_height)/2.0).max(0.0)"),
        reason: "half of the free height of a row, not a step",
    },
    Allowed {
        file: "view/rose_button.rs",
        call: "gamma_multiply(",
        function: Some("params"),
        arguments: None,
        reason: "the layers of the rose per phase: an illustration, not interface elements",
    },
    Allowed {
        file: "view/connection/hero.rs",
        call: NAMED_GAP,
        function: None,
        arguments: Some("BUTTON_TEXT_GAP=36.0"),
        reason: "the layout of the hero: the connect button beside the state line",
    },
    Allowed {
        file: "view/connection/hero.rs",
        call: "set_width(",
        function: None,
        arguments: Some("96.0"),
        reason: "the label column of a row of the connection card, not a dialog",
    },
    Allowed {
        file: "view/add_subscription.rs",
        call: "set_width(",
        function: None,
        arguments: Some("230.0"),
        reason: "the width of the QR source menu, a popup beside a button, not a dialog",
    },
    Allowed {
        file: "view/exits.rs",
        call: "set_width(",
        function: Some("exit_menu"),
        arguments: Some("210.0"),
        reason: "the width of a row's menu, a popup beside a button, not a dialog",
    },
    Allowed {
        file: "view/lists.rs",
        call: "set_width(",
        function: None,
        arguments: Some("210.0"),
        reason: "the width of a row's menu, a popup beside a button, not a dialog",
    },
    Allowed {
        file: "view/subscriptions/card.rs",
        call: "set_width(",
        function: None,
        arguments: Some("180.0"),
        reason: "the width of a card's menu, a popup beside a button, not a dialog",
    },
    Allowed {
        file: "view/traffic.rs",
        call: "set_width(",
        function: None,
        arguments: Some("232.0"),
        reason: "the width of a tile of the traffic summary, not a dialog",
    },
];

#[derive(Debug, PartialEq, Eq)]
struct Violation {
    line: usize,
    call: &'static str,
    arguments: String,
    /// The innermost function that holds it.
    function: Option<String>,
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

/// The name of the innermost `fn` whose item holds `offset`.
fn enclosing_fn(code: &[char], offset: usize) -> Option<String> {
    let mut found = None;
    for at in find_all(code, "fn ") {
        if at > 0 && is_identifier_char(code[at - 1]) {
            continue;
        }
        let start = at + 3;
        let end = (start..code.len())
            .find(|&i| !is_identifier_char(code[i]))
            .unwrap_or(code.len());
        if at < offset && offset <= item_end(code, end) {
            found = Some(code[start..end].iter().collect());
        }
    }
    found
}

/// The constants named like a spacing: where each starts, its name and its value.
fn gap_constants(code: &[char]) -> Vec<(usize, String, String)> {
    constants_named(code, &GAP_WORDS)
}

/// The constants whose name holds one of `words`: where each starts, its name and its value.
fn constants_named(code: &[char], words: &[&str]) -> Vec<(usize, String, String)> {
    let mut found = Vec::new();
    for at in find_all(code, "const ") {
        if at > 0 && is_identifier_char(code[at - 1]) {
            continue;
        }
        let start = at + "const ".len();
        let mut end = start;
        while code.get(end).is_some_and(|c| is_identifier_char(*c)) {
            end += 1;
        }
        let name: String = code[start..end].iter().collect();
        while code.get(end).is_some_and(|c| c.is_whitespace()) {
            end += 1;
        }
        if code.get(end) != Some(&':') || !words.iter().any(|word| name.contains(word)) {
            continue;
        }
        let item: String = code[end..item_end(code, end)].iter().collect();
        if let Some((_, value)) = item.split_once('=') {
            found.push((at, name, value.to_owned()));
        }
    }
    found
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
                    function: enclosing_fn(&code, at),
                });
            }
        }
    }
    for (at, name, value) in gap_constants(&code) {
        if has_number(&value) {
            let value: String = value.split_whitespace().collect();
            found.push(Violation {
                line: line_of(at),
                call: NAMED_GAP,
                arguments: format!("{name}={value}"),
                function: enclosing_fn(&code, at),
            });
        }
    }
    for call in FORBIDDEN_CALLS {
        for at in find_all(&code, call) {
            found.push(Violation {
                line: line_of(at),
                call,
                arguments: String::new(),
                function: enclosing_fn(&code, at),
            });
        }
    }
    found.sort_by_key(|violation| violation.line);
    found
}

/// What a view may not build itself: a raw input, drop-down or dialog, and a dialog's width as a
/// number. `widgets` may; see `holds_widget_only_calls`.
fn view_violations(source: &str) -> Vec<Violation> {
    let code = without_test_items(mask(source));
    let line_of = |offset: usize| code[..offset].iter().filter(|c| **c == '\n').count() + 1;
    let mut found = Vec::new();
    for call in WIDGET_ONLY_CALLS {
        for at in find_all(&code, call) {
            // `MyTextEdit::` is somebody else's type.
            if at > 0 && is_identifier_char(code[at - 1]) {
                continue;
            }
            found.push(Violation {
                line: line_of(at),
                call,
                arguments: String::new(),
                function: enclosing_fn(&code, at),
            });
        }
    }
    for call in VIEW_NUMBER_FREE_CALLS {
        for at in find_all(&code, call) {
            let arguments = call_arguments(&code, at + call.chars().count());
            if has_number(&arguments) {
                found.push(Violation {
                    line: line_of(at),
                    call,
                    arguments: arguments.split_whitespace().collect(),
                    function: enclosing_fn(&code, at),
                });
            }
        }
    }
    for (at, name, value) in constants_named(&code, &DIALOG_WIDTH_WORDS) {
        found.push(Violation {
            line: line_of(at),
            call: NAMED_DIALOG_WIDTH,
            arguments: format!("{name}={}", value.split_whitespace().collect::<String>()),
            function: enclosing_fn(&code, at),
        });
    }
    found.sort_by_key(|violation| violation.line);
    found
}

/// The rules of `view_violations` hold for the views; `widgets` is where the raw calls live.
fn holds_widget_only_calls(file: &str) -> bool {
    file.starts_with("view/")
}

fn is_allowed(allowed: &[Allowed], file: &str, violation: &Violation) -> bool {
    allowed.iter().any(|rule| {
        rule.file == file
            && rule.call == violation.call
            && rule
                .function
                .is_none_or(|name| violation.function.as_deref() == Some(name))
            && rule
                .arguments
                .is_none_or(|arguments| arguments == violation.arguments)
    })
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
    let mut raw = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(&src)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let source = fs::read_to_string(&path).unwrap();
        let line = |violation: &Violation| {
            format!(
                "{relative}:{}: {}{}",
                violation.line, violation.call, violation.arguments
            )
        };
        for violation in violations(&source) {
            if !is_allowed(&ALLOWED, &relative, &violation) {
                report.push(line(&violation));
            }
        }
        if holds_widget_only_calls(&relative) {
            for violation in view_violations(&source) {
                if !is_allowed(&ALLOWED, &relative, &violation) {
                    raw.push(line(&violation));
                }
            }
        }
    }
    assert!(
        report.is_empty(),
        "literals outside the scales in `theme` (space, margin, font, radius, stroke, alpha, colours):\n{}",
        report.join("\n")
    );
    assert!(
        raw.is_empty(),
        "inputs, drop-downs and dialogs a view builds itself instead of taking them from `widgets`:\n{}",
        raw.join("\n")
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
    let frame = Frame::new()
        .inner_margin(theme::margin::same(theme::space::L))
        .inner_margin(0)
        .outer_margin(theme::margin::symmetric(theme::space::M, 0.0))
        .fill(color.gamma_multiply(theme::alpha::MUTED));
    let a = egui::Margin::same(0);
    let b = egui::Margin::symmetric(side, 0);
    let c = egui::Margin {
        left: theme::margin::side(theme::space::L),
        right: if narrow { theme::margin::side(theme::space::S) } else { 0 },
        top: 0,
        bottom: margin,
    };
    let fade = color.gamma_multiply(alpha * glow);
}
";
    assert_eq!(violations(source), []);
}

#[test]
fn the_fence_skips_comments_strings_and_raw_strings() {
    let source = r##"
// ui.add_space(12.0);
/* ui.add_space(12.0); /* nested */ ui.add_space(12.0); */
// const ICON_GAP: f32 = 12.0; and .inner_margin(12)
/// `Color32::from_rgb(1, 2, 3)` in a doc comment.
fn view() {
    let text = "ui.add_space(12.0) and \" ui.add_space(8.0)";
    let raw = r#"ui.add_space(12.0) "quoted" Stroke::new(1.0, c)"#;
    let named = "const ROW_GAP: f32 = 12.0; Margin::same(4)";
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

#[test]
fn the_fence_catches_a_number_in_a_margin_or_an_opacity() {
    let source = "\
fn view(color: Color32) {
    let a = Frame::new().inner_margin(12);
    let b = Frame::new().outer_margin(egui::Margin::same(4));
    let c = Margin::symmetric(8, 0);
    let d = color.gamma_multiply(0.5);
    let e = TextEdit::singleline(text).margin(egui::Margin::symmetric(theme::space::M, 6));
}
";
    let found: Vec<_> = violations(source)
        .into_iter()
        .map(|violation| (violation.line, violation.call))
        .collect();
    assert_eq!(
        found,
        [
            (2, "inner_margin("),
            (3, "Margin::same("),
            (3, "outer_margin("),
            (4, "Margin::symmetric("),
            (5, "gamma_multiply("),
            (6, "Margin::symmetric("),
        ]
    );
}

#[test]
fn the_fence_catches_a_number_in_a_margin_literal() {
    let source = "\
fn view(narrow: bool) {
    let a = egui::Margin {
        left: theme::margin::side(theme::space::L),
        right: 12,
        top: 0,
        bottom: theme::margin::side(theme::space::S),
    };
    let b = egui::Margin {
        left: if narrow { theme::margin::side(theme::space::L) } else { 36 },
        right: 0,
        top: 0,
        bottom: 0,
    };
}
";
    let found: Vec<_> = violations(source)
        .into_iter()
        .map(|violation| (violation.line, violation.call))
        .collect();
    assert_eq!(found, [(2, "Margin {"), (8, "Margin {")]);
}

#[test]
fn the_fence_catches_a_gap_constant_set_by_a_number() {
    let source = "\
const ICON_GAP: f32 = 12.0;
pub(crate) const ROW_PADDING: f32 = 10.0;
const ROW_INSET: f32 = theme::space::M;
const MENU_MARGIN: f32 = 2.0 * theme::space::M;
const NO_GAP: f32 = 0.0;
const ITEM_SPACING: f32 = 6.0;
const ROW_HEIGHT: f32 = 58.0;
const fn gap() -> f32 {
    4.0
}
#[cfg(test)]
const TEST_GAP: f32 = 3.0;
";
    let found: Vec<_> = violations(source)
        .into_iter()
        .map(|violation| (violation.line, violation.arguments))
        .collect();
    assert_eq!(
        found,
        [
            (1, "ICON_GAP=12.0".to_owned()),
            (2, "ROW_PADDING=10.0".to_owned()),
            (4, "MENU_MARGIN=2.0*theme::space::M".to_owned()),
            (6, "ITEM_SPACING=6.0".to_owned()),
        ]
    );
}

#[test]
fn the_fence_lets_through_only_the_listed_exceptions() {
    let rose = "\
fn params(phase: RosePhase) -> RoseParams {
    let layer = color.gamma_multiply(0.20);
}
fn paint(color: Color32) {
    let ring = color.gamma_multiply(0.6);
}
";
    let found = violations(rose);
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].function.as_deref(), Some("params"));
    assert!(is_allowed(&ALLOWED, "view/rose_button.rs", &found[0]));
    assert!(!is_allowed(&ALLOWED, "view/rose_button.rs", &found[1]));
    assert!(!is_allowed(&ALLOWED, "view/rules/mod.rs", &found[0]));

    let hero = violations("const BUTTON_TEXT_GAP: f32 = 36.0;\nconst ICON_GAP: f32 = 36.0;\n");
    assert_eq!(hero.len(), 2);
    assert!(is_allowed(&ALLOWED, "view/connection/hero.rs", &hero[0]));
    assert!(!is_allowed(&ALLOWED, "view/connection/hero.rs", &hero[1]));
    assert!(!is_allowed(&ALLOWED, "view/settings.rs", &hero[0]));
}

#[test]
fn the_fence_reads_crlf_margin_literals_and_constants_like_lf() {
    let lf = "\
const ICON_GAP: f32 = 12.0;
fn view() {
    let margin = egui::Margin {
        left: 12,
        right: 0,
        top: 0,
        bottom: 0,
    };
}
";
    let crlf = lf.replace('\n', "\r\n");
    assert_eq!(violations(lf), violations(&crlf));
    assert_eq!(violations(&crlf).len(), 2);
}

#[test]
fn the_fence_catches_a_view_that_builds_its_own_input_drop_down_or_dialog() {
    let source = "\
use eframe::egui::TextEdit;
fn view(ui: &mut Ui, ctx: &Context) {
    ui.add(egui::TextEdit::singleline(&mut text));
    ui.add(TextEdit::multiline(&mut text));
    egui::ComboBox::from_id_salt(\"language\").show_ui(ui, |ui| {});
    widgets::show_modal(ctx, egui::Modal::new(egui::Id::new(\"dialog\")), |ui| {});
    ui.set_width(520.0);
}
";
    let found: Vec<_> = view_violations(source)
        .into_iter()
        .map(|violation| (violation.line, violation.call))
        .collect();
    assert_eq!(
        found,
        [
            (3, "TextEdit::"),
            (4, "TextEdit::"),
            (5, "ComboBox::"),
            (6, "Modal::new("),
            (7, "set_width("),
        ]
    );
}

#[test]
fn the_fence_accepts_a_view_that_takes_them_from_widgets() {
    let source = "\
fn view(ui: &mut Ui, ctx: &Context, width: f32) {
    ui.add(widgets::TextField::new(&mut text).rows(4));
    widgets::drop_down(ui, \"language\", Some(width), selected, |ui| {});
    widgets::Dialog::new(\"dialog\", widgets::DialogWidth::Wide).show(ctx, |ui| {
        ui.set_width(width);
        ui.set_width(widgets::DialogWidth::Narrow.points());
        ui.set_width(0.0);
    });
    response.widget_info(|| WidgetInfo::labeled(WidgetType::ComboBox, true, name));
    let mine = MyTextEdit::new();
}
// egui::TextEdit::singleline(&mut text)
#[cfg(test)]
mod tests {
    fn test(ui: &mut Ui) {
        ui.set_width(520.0);
        egui::ComboBox::from_id_salt(\"language\");
    }
}
";
    assert_eq!(view_violations(source), []);
}

#[test]
fn the_fence_catches_a_constant_that_carries_a_dialog_width() {
    let found = view_violations(
        "const DIALOG_WIDTH: f32 = 520.0;\nconst DETAIL_LABEL_WIDTH: f32 = 96.0;\nconst MODAL_WIDTH: f32 = 400.0;\n",
    );
    let found: Vec<_> = found
        .iter()
        .map(|violation| (violation.line, violation.arguments.as_str()))
        .collect();
    assert_eq!(
        found,
        [(1, "DIALOG_WIDTH=520.0"), (3, "MODAL_WIDTH=400.0")]
    );
}

#[test]
fn only_the_views_are_kept_from_raw_inputs_and_widgets_may_hold_them() {
    assert!(holds_widget_only_calls("view/exits.rs"));
    assert!(holds_widget_only_calls("view/rules/dialogs.rs"));
    assert!(!holds_widget_only_calls("widgets/dialogs.rs"));
    assert!(!holds_widget_only_calls("widgets/text_field.rs"));
}

#[test]
fn the_fence_lets_through_only_the_listed_widths() {
    let menu = view_violations("fn exit_menu() {\n    ui.set_width(210.0);\n}\n");
    assert_eq!(menu.len(), 1);
    assert!(is_allowed(&ALLOWED, "view/exits.rs", &menu[0]));
    assert!(!is_allowed(&ALLOWED, "view/lists.rs", &view_violations("fn other() {\n    ui.set_width(520.0);\n}\n")[0]));
    assert!(!is_allowed(&ALLOWED, "view/exits.rs", &view_violations("fn exit_dialog() {\n    ui.set_width(210.0);\n}\n")[0]));
}
