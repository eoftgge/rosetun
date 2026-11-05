//! The interface language and notifications on the Linux desktop.

use std::collections::HashMap;
use std::io;

use zbus::blocking::Connection;
use zbus::zvariant::Value;

const NOTIFICATIONS_NAME: &str = "org.freedesktop.Notifications";
const NOTIFICATIONS_PATH: &str = "/org/freedesktop/Notifications";
/// Lets the server show the program's name and icon from its menu entry.
const DESKTOP_ENTRY: &str = "rosetun";
/// The server's own time on screen.
const DEFAULT_EXPIRY: i32 = -1;

/// The locale for messages, by the precedence POSIX gives these variables,
/// such as `ru_RU.UTF-8`.
pub fn user_language() -> Option<String> {
    language_from(|name| std::env::var(name).ok())
}

fn language_from(variable: impl Fn(&str) -> Option<String>) -> Option<String> {
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .into_iter()
        .filter_map(variable)
        .find(|value| !value.trim().is_empty())
}

/// Shows a silent notification. Blocks on the session bus: call it off the UI
/// thread. Fails when the desktop has no notification server.
pub fn tray_notice(title: &str, text: &str) -> io::Result<()> {
    send_notice(
        &Connection::session().map_err(io::Error::other)?,
        title,
        text,
    )
}

fn send_notice(connection: &Connection, title: &str, text: &str) -> io::Result<()> {
    let actions: &[&str] = &[];
    let hints = HashMap::from([
        ("desktop-entry", Value::from(DESKTOP_ENTRY)),
        ("suppress-sound", Value::from(true)),
    ]);
    connection
        .call_method(
            Some(NOTIFICATIONS_NAME),
            NOTIFICATIONS_PATH,
            Some(NOTIFICATIONS_NAME),
            "Notify",
            &(
                "Rosetun",
                0u32,
                DESKTOP_ENTRY,
                title,
                text,
                actions,
                hints,
                DEFAULT_EXPIRY,
            ),
        )
        .map(|_| ())
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_message_locale_goes_by_posix_precedence() {
        let language = |set: &[(&str, &str)]| {
            language_from(|name| {
                set.iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| (*value).to_owned())
            })
        };
        assert_eq!(language(&[]), None);
        assert_eq!(language(&[("LANG", "ru_RU.UTF-8")]).unwrap(), "ru_RU.UTF-8");
        assert_eq!(
            language(&[("LANG", "en_US"), ("LC_MESSAGES", "ru_RU")]).unwrap(),
            "ru_RU"
        );
        assert_eq!(
            language(&[
                ("LANG", "en_US"),
                ("LC_MESSAGES", "ru_RU"),
                ("LC_ALL", "de_DE")
            ])
            .unwrap(),
            "de_DE"
        );
        assert_eq!(
            language(&[("LC_ALL", ""), ("LC_MESSAGES", " "), ("LANG", "ru_RU")]).unwrap(),
            "ru_RU",
            "an empty variable counts as unset"
        );
    }

    /// `dbus-run-session -- cargo test -p rosetun-shell -- --ignored` runs it.
    #[test]
    #[ignore = "needs a session bus"]
    fn a_notice_reaches_a_server_silently_with_the_programs_entry() {
        use std::sync::Mutex;
        use std::sync::mpsc::{self, Sender};
        use std::time::Duration;

        use zbus::blocking::connection::Builder;
        use zbus::zvariant::OwnedValue;

        type Seen = (String, String, String, bool);

        struct Server(Mutex<Sender<Seen>>);

        #[zbus::interface(name = "org.freedesktop.Notifications")]
        impl Server {
            #[expect(clippy::too_many_arguments, reason = "the protocol's method")]
            fn notify(
                &self,
                app_name: String,
                _replaces_id: u32,
                _app_icon: String,
                summary: String,
                body: String,
                _actions: Vec<String>,
                hints: HashMap<String, OwnedValue>,
                _expire_timeout: i32,
            ) -> u32 {
                let silent = bool::try_from(&hints["suppress-sound"]).unwrap();
                self.0
                    .lock()
                    .unwrap()
                    .send((app_name, summary, body, silent))
                    .unwrap();
                1
            }
        }

        let (seen, received) = mpsc::channel();
        let _server = Builder::session()
            .unwrap()
            .name(NOTIFICATIONS_NAME)
            .unwrap()
            .serve_at(NOTIFICATIONS_PATH, Server(Mutex::new(seen)))
            .unwrap()
            .build()
            .unwrap();
        tray_notice("Title", "Подключение восстановлено").unwrap();
        assert_eq!(
            received.recv_timeout(Duration::from_secs(5)).unwrap(),
            (
                "Rosetun".to_owned(),
                "Title".to_owned(),
                "Подключение восстановлено".to_owned(),
                true
            )
        );
    }
}
