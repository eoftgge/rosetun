#![deny(unsafe_code)]

#[cfg(windows)]
#[allow(unsafe_code)]
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

#[cfg(not(windows))]
pub fn running_processes() -> Result<Vec<RunningProcess>, ProcessListError> {
    Ok(Vec::new())
}

/// The `FileDescription` of the executable's version resource, as written
/// there. Only local drive paths are read: a network path would make Windows
/// connect to that server.
#[cfg(windows)]
pub fn file_description(path: &Path) -> Option<String> {
    windows::file_description(path)
}

#[cfg(not(windows))]
pub fn file_description(_path: &Path) -> Option<String> {
    None
}

#[cfg(test)]
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
        assert!(file_description(&notepad).is_some_and(|text| !text.trim().is_empty()));
        assert_eq!(
            file_description(Path::new(r"\\server.invalid\share\app.exe")),
            None
        );
        assert_eq!(file_description(Path::new("app.exe")), None);
    }

    #[cfg(not(windows))]
    #[test]
    fn other_platforms_return_an_empty_list() {
        assert!(running_processes().unwrap().is_empty());
    }
}
