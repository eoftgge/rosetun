//! Names of the programs in the connection list.

/// A longer description is a sentence, not a name.
const MAX_NAME_CHARS: usize = 64;

/// The last part of a Windows or Unix path.
pub(crate) fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// The file name without `.exe`.
pub(crate) fn file_stem(path: &str) -> &str {
    let name = file_name(path);
    match name.len().checked_sub(4) {
        Some(end) if name.is_char_boundary(end) && name[end..].eq_ignore_ascii_case(".exe") => {
            &name[..end]
        }
        _ => name,
    }
}

/// The version resource's description, or the file name when the description
/// is missing, blank or too long for a row.
pub(crate) fn display_name(path: &str, description: Option<&str>) -> String {
    description
        .map(str::trim)
        .filter(|text| !text.is_empty() && text.chars().count() <= MAX_NAME_CHARS)
        .unwrap_or_else(|| file_stem(path))
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::{display_name, file_stem};

    #[test]
    fn file_stem_drops_the_folder_and_exe_in_any_case() {
        assert_eq!(file_stem(r"C:\Program Files\Example\Browser.EXE"), "Browser");
        assert_eq!(file_stem("/usr/bin/example"), "example");
        assert_eq!(file_stem(r"C:\Tools\tool.exe.bak"), "tool.exe.bak");
        assert_eq!(file_stem(".exe"), "");
        assert_eq!(file_stem(r"C:\Игры\игра.exe"), "игра");
    }

    #[test]
    fn display_name_falls_back_to_the_file_name() {
        let path = r"C:\Program Files\Example\browser.exe";
        assert_eq!(display_name(path, Some("  Example Browser ")), "Example Browser");
        assert_eq!(display_name(path, None), "browser");
        assert_eq!(display_name(path, Some("")), "browser");
        assert_eq!(display_name(path, Some(" \t ")), "browser");
        assert_eq!(display_name(path, Some(&"я".repeat(64))), "я".repeat(64));
        assert_eq!(display_name(path, Some(&"я".repeat(65))), "browser");
    }
}
