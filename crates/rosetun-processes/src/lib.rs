#![deny(unsafe_code)]

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

use std::path::PathBuf;

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

    #[cfg(not(windows))]
    #[test]
    fn other_platforms_return_an_empty_list() {
        assert!(running_processes().unwrap().is_empty());
    }
}
