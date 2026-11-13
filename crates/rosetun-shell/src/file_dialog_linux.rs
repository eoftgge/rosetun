//! File dialogs through the XDG Desktop Portal (`org.freedesktop.portal.FileChooser`),
//! the desktop's own dialog with no toolkit linked in. Blocks until the user answers:
//! call it off the UI thread.
//!
//! The request object is named from the caller's bus name and a token we choose, so the
//! `Response` signal is subscribed to before the method is called and cannot be missed.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedValue, Value};

const PORTAL_NAME: &str = "org.freedesktop.portal.Desktop";
const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
const CHOOSER: &str = "org.freedesktop.portal.FileChooser";
const REQUEST: &str = "org.freedesktop.portal.Request";
const REQUEST_PATH: &str = "/org/freedesktop/portal/desktop/request";

/// A group of files the dialog offers, such as "Text files" and `["txt"]`.
#[derive(Debug, Clone, Copy)]
pub struct FileFilter<'a> {
    pub name: &'a str,
    pub extensions: &'a [&'a str],
}

/// Why no file came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileDialogError {
    /// No session bus or no portal on it: the desktop has no file dialog to ask.
    NoPortal(String),
    /// The portal was there and the request failed.
    Failed(String),
}

impl fmt::Display for FileDialogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPortal(reason) => write!(f, "no file dialog portal: {reason}"),
            Self::Failed(reason) => write!(f, "the file dialog failed: {reason}"),
        }
    }
}

impl std::error::Error for FileDialogError {}

/// Asks for one existing file. `Ok(None)` is a cancelled dialog.
pub fn pick_file(
    title: &str,
    filters: &[FileFilter<'_>],
) -> Result<Option<PathBuf>, FileDialogError> {
    ask("OpenFile", title, filters, None)
}

/// Asks where to save, proposing `file_name`. `Ok(None)` is a cancelled dialog. The
/// portal makes the file's parent folder writable for us; it does not create the file.
pub fn save_file(
    title: &str,
    file_name: &str,
    filters: &[FileFilter<'_>],
) -> Result<Option<PathBuf>, FileDialogError> {
    ask("SaveFile", title, filters, Some(file_name))
}

fn ask(
    method: &str,
    title: &str,
    filters: &[FileFilter<'_>],
    file_name: Option<&str>,
) -> Result<Option<PathBuf>, FileDialogError> {
    let connection = Connection::session().map_err(|error| no_portal(&error))?;
    let sender = connection
        .unique_name()
        .map(|name| name.as_str().to_owned())
        .ok_or_else(|| FileDialogError::NoPortal("the session bus gave no name".to_owned()))?;
    let token = format!("rosetun_{}", std::process::id());
    let path = request_path(&sender, &token);

    let request = Proxy::new(&connection, PORTAL_NAME, path.as_str(), REQUEST)
        .map_err(|error| no_portal(&error))?;
    let mut responses = request
        .receive_signal("Response")
        .map_err(|error| no_portal(&error))?;

    let mut options: HashMap<&str, Value<'_>> = HashMap::new();
    options.insert("handle_token", Value::from(token.as_str()));
    options.insert("modal", Value::from(true));
    if !filters.is_empty() {
        options.insert("filters", filters_value(filters));
    }
    if let Some(name) = file_name {
        options.insert("current_name", Value::from(name));
    }
    connection
        .call_method(
            Some(PORTAL_NAME),
            PORTAL_PATH,
            Some(CHOOSER),
            method,
            // No parent window: the portal shows the dialog as a window of its own.
            &("", title, options),
        )
        .map_err(|error| no_portal(&error))?;

    let message = responses
        .next()
        .ok_or_else(|| FileDialogError::Failed("the portal closed the request".to_owned()))?;
    let (code, results): (u32, HashMap<String, OwnedValue>) = message
        .body()
        .deserialize()
        .map_err(|error| FileDialogError::Failed(error.to_string()))?;
    match code {
        0 => {
            let uris = results
                .get("uris")
                .and_then(|value| <Vec<String>>::try_from(value.clone()).ok())
                .unwrap_or_default();
            Ok(uris.first().and_then(|uri| path_of(uri)))
        }
        1 => Ok(None),
        other => Err(FileDialogError::Failed(format!(
            "the portal answered {other}"
        ))),
    }
}

/// A bus that cannot be reached and a portal that is not there both mean there is
/// nothing to ask; whatever else goes wrong later is a failed request.
fn no_portal(error: &zbus::Error) -> FileDialogError {
    FileDialogError::NoPortal(error.to_string())
}

/// `/org/freedesktop/portal/desktop/request/<sender>/<token>`, where the sender is the
/// bus name without its colon and with dots as underscores.
fn request_path(sender: &str, token: &str) -> String {
    let sender = sender.trim_start_matches(':').replace('.', "_");
    format!("{REQUEST_PATH}/{sender}/{token}")
}

/// `a(sa(us))`: a name and its patterns, each pattern kind 0 (a glob).
fn filters_value(filters: &[FileFilter<'_>]) -> Value<'static> {
    let list: Vec<(String, Vec<(u32, String)>)> = filters
        .iter()
        .map(|filter| {
            (
                filter.name.to_owned(),
                filter
                    .extensions
                    .iter()
                    .map(|extension| (0, format!("*.{extension}")))
                    .collect(),
            )
        })
        .collect();
    Value::new(list)
}

/// A `file://` URI as a path, percent-decoded; `None` for any other scheme.
fn path_of(uri: &str) -> Option<PathBuf> {
    let rest = uri.strip_prefix("file://")?;
    // An authority, normally empty, ends at the first slash.
    let path = &rest[rest.find('/')?..];
    Some(PathBuf::from(OsString::from_vec(percent_decode(path))))
}

fn percent_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let hex = bytes
            .get(index + 1..index + 3)
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .and_then(|pair| u8::from_str_radix(pair, 16).ok());
        match (bytes[index], hex) {
            (b'%', Some(byte)) => {
                decoded.push(byte);
                index += 3;
            }
            (byte, _) => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_path_follows_the_portal_naming() {
        assert_eq!(
            request_path(":1.42", "rosetun_7"),
            "/org/freedesktop/portal/desktop/request/1_42/rosetun_7"
        );
    }

    #[test]
    fn a_file_uri_becomes_a_decoded_path() {
        assert_eq!(
            path_of("file:///home/user/My%20lists/a%C3%A9.srs"),
            Some(PathBuf::from("/home/user/My lists/aé.srs"))
        );
        assert_eq!(
            path_of("file://localhost/tmp/x"),
            Some(PathBuf::from("/tmp/x"))
        );
        assert_eq!(path_of("https://example.com/x"), None);
        assert_eq!(path_of("file://no-path"), None);
    }

    #[test]
    fn a_broken_escape_stays_as_it_is() {
        assert_eq!(percent_decode("100%"), b"100%");
        assert_eq!(percent_decode("a%zzb"), b"a%zzb");
    }

    #[test]
    fn filters_are_globs_of_the_extensions() {
        let value = filters_value(&[FileFilter {
            name: "Images",
            extensions: &["png", "jpg"],
        }]);
        assert_eq!(value.value_signature().to_string(), "a(sa(us))");
    }

    #[test]
    fn an_error_names_what_was_missing() {
        let error = FileDialogError::NoPortal("no bus".to_owned());
        assert!(error.to_string().contains("no bus"));
    }
}
