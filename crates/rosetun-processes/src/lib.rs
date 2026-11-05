#![deny(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 FFI; every unsafe block carries a SAFETY comment"
)]
mod windows;

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningProcess {
    pub pid: u32,
    pub name: String,
    pub path: Option<PathBuf>,
    pub has_window: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessListError {
    #[error("could not list running processes: {0}")]
    Snapshot(std::io::Error),
}

#[cfg(windows)]
pub fn running_processes() -> Result<Vec<RunningProcess>, ProcessListError> {
    windows::running_processes()
}

#[cfg(target_os = "linux")]
pub fn running_processes() -> Result<Vec<RunningProcess>, ProcessListError> {
    linux::running_processes()
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn running_processes() -> Result<Vec<RunningProcess>, ProcessListError> {
    Ok(Vec::new())
}

/// The `FileDescription` of the executable's version resource, as written
/// there. Only local drive paths are read: a network path would make Windows
/// connect to that server.
#[cfg(windows)]
pub fn file_description(path: &Path, _language: &str) -> Option<String> {
    windows::file_description(path)
}

/// The name of the menu entry that starts the program, in `language` if it has one.
#[cfg(target_os = "linux")]
pub fn file_description(path: &Path, language: &str) -> Option<String> {
    linux::file_description(path, language)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn file_description(_path: &Path, _language: &str) -> Option<String> {
    None
}

/// The PNG file of the program's icon, the nearest size not below `size_px`.
#[cfg(target_os = "linux")]
pub fn program_icon_file(path: &Path, size_px: u32) -> Option<PathBuf> {
    linux::icon_file(path, size_px)
}

#[cfg(all(test, not(target_os = "linux")))]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn current_process_is_listed() {
        let current = std::env::current_exe().unwrap();
        let expected = current.file_name().unwrap().to_string_lossy();
        let processes = running_processes().unwrap();
        let process = processes
            .iter()
            .find(|process| process.pid == std::process::id())
            .expect("current process is in snapshot");
        assert_eq!(
            process
                .path
                .as_ref()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_lowercase(),
            expected.to_lowercase()
        );
    }

    #[cfg(windows)]
    #[test]
    fn system_programs_have_a_description_and_network_paths_are_not_read() {
        let windows = std::env::var_os("SystemRoot").unwrap();
        let notepad = Path::new(&windows).join(r"System32\notepad.exe");
        assert!(file_description(&notepad, "en").is_some_and(|text| !text.trim().is_empty()));
        assert_eq!(
            file_description(Path::new(r"\\server.invalid\share\app.exe"), "en"),
            None
        );
        assert_eq!(file_description(Path::new("app.exe"), "en"), None);
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    #[test]
    fn other_platforms_return_an_empty_list() {
        assert!(running_processes().unwrap().is_empty());
    }
}
