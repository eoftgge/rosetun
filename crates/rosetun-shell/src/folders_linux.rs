//! Opening a folder in the file manager on Linux.
//!
//! First `org.freedesktop.FileManager1.ShowFolders` on the session bus, which Dolphin,
//! Nautilus, Nemo and Thunar answer: no process is started and nothing is looked up in
//! `PATH`. A desktop without it gets `xdg-open` by its absolute path, with the folder's
//! absolute path as the only argument, which cannot be read as an option.

use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, Stdio};

use zbus::blocking::Connection;

const FILE_MANAGER: &str = "org.freedesktop.FileManager1";
const FILE_MANAGER_PATH: &str = "/org/freedesktop/FileManager1";
const XDG_OPEN: [&str; 2] = ["/usr/bin/xdg-open", "/bin/xdg-open"];

/// Shows the folder. Blocks on the session bus: call it off the UI thread.
pub fn open_folder(folder: &Path) -> io::Result<()> {
    if !folder.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the folder path is not absolute",
        ));
    }
    match show_folder(folder) {
        Ok(()) => Ok(()),
        Err(error) => {
            tracing::debug!(%error, "the file manager did not take the folder over D-Bus");
            run_xdg_open(folder)
        }
    }
}

fn show_folder(folder: &Path) -> zbus::Result<()> {
    let connection = Connection::session()?;
    let uris = [file_uri(folder)];
    connection.call_method(
        Some(FILE_MANAGER),
        FILE_MANAGER_PATH,
        Some(FILE_MANAGER),
        "ShowFolders",
        &(uris.as_slice(), ""),
    )?;
    Ok(())
}

fn run_xdg_open(folder: &Path) -> io::Result<()> {
    let program = XDG_OPEN
        .iter()
        .find(|path| Path::new(path).is_file())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "xdg-open is not installed"))?;
    Command::new(program)
        .arg(folder)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|mut child| {
            // The launcher exits at once; reaping it keeps no zombie behind.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        })
}

/// `file:///…` with every byte but unreserved characters and `/` escaped.
fn file_uri(path: &Path) -> String {
    let mut uri = String::from("file://");
    for &byte in OsStr::as_bytes(path.as_os_str()) {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'.' | b'_' | b'~') {
            uri.push(char::from(byte));
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    uri
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_becomes_an_escaped_file_uri() {
        assert_eq!(
            file_uri(Path::new("/home/user/My lists/é#1")),
            "file:///home/user/My%20lists/%C3%A9%231"
        );
    }

    #[test]
    fn a_relative_folder_is_refused_before_anything_runs() {
        let error = open_folder(Path::new("relative/dir")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
