use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use eframe::egui;
use rosetun_config::{ConnectionState, Selection};
use rosetun_core::MAX_RECENT_SERVERS;
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

use crate::actions::PrimaryAction;
use crate::app::ShellEvent;
use crate::notices::Notice;
use crate::rose_icon::{self, RoseIcon, TrayState};
use crate::state::{State, primary_label};
use crate::{constants, i18n, theme, view};

const STATUS_ID: &str = "rosetun.tray.status";
const WINDOW_ID: &str = "rosetun.tray.window";
const PRIMARY_ID: &str = "rosetun.tray.primary";
const SERVERS_ID: &str = "rosetun.tray.servers";
/// Followed by the server's place in `Tray::choices`.
const SERVER_ID_PREFIX: &str = "rosetun.tray.server.";
const ALL_SERVERS_ID: &str = "rosetun.tray.all-servers";
/// The `uID` the icon was added with: tray-icon numbers its icons from 1 in
/// the order they are made (its `COUNTER`, 0.26) and hides the number, and
/// Rosetun makes one. Were it wrong, a notice fails with a warning only.
const TRAY_ICON_ID: u32 = 1;
const QUIT_ID: &str = "rosetun.tray.quit";
/// The taskbar's icon size changes with its monitor's scale; reading it on
/// every frame would cost a window lookup per frame.
const SIZE_CHECK: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TrayView {
    pub(crate) icon: TrayState,
    pub(crate) tooltip: String,
    pub(crate) status_label: String,
    pub(crate) primary_label: String,
    pub(crate) primary_enabled: bool,
    /// The window is on screen, so the window item hides it.
    pub(crate) window_shown: bool,
    pub(crate) window_label: String,
    pub(crate) servers_label: String,
    /// Recent servers that still exist, newest first.
    pub(crate) servers: Vec<TrayServer>,
    pub(crate) all_servers_label: String,
    pub(crate) quit_label: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TrayServer {
    pub(crate) selection: Selection,
    pub(crate) label: String,
    pub(crate) current: bool,
}

pub(crate) fn tray_view(state: &State, window_shown: bool) -> TrayView {
    let (status, icon) = state.visible_status().map_or_else(
        || (tr!("helper-unavailable"), TrayState::ServiceUnavailable),
        |status| {
            let (label, _) = view::connection::state_style(&status.state);
            let icon = match status.state {
                ConnectionState::Disconnected | ConnectionState::Failed { .. }
                    if status.lockdown =>
                {
                    TrayState::Blocked
                }
                ConnectionState::Connected => TrayState::Connected,
                ConnectionState::Disconnected => TrayState::Disconnected,
                ConnectionState::Connecting | ConnectionState::Reconnecting => {
                    TrayState::Connecting
                }
                ConnectionState::FailedProtected { .. } => TrayState::Blocked,
                ConnectionState::Failed { .. } => TrayState::Failed,
            };
            (state.tray_stage_label().unwrap_or(label), icon)
        },
    );
    let server = state
        .visible_status()
        .and_then(|_| state.config.active_node())
        .map(|(_, node)| menu_text(state, &node.name));
    let menu_server = server.as_deref().map(menu_label);
    let status_label = match (icon, &menu_server) {
        (TrayState::Blocked, _) => tr!("tray-blocked"),
        (TrayState::Connected, Some(server)) => format!("{status} · {server}"),
        _ => status.clone(),
    };
    let primary_action = state.primary_action();
    let primary_label = match &menu_server {
        Some(server) if primary_action == PrimaryAction::Connect => {
            tr!("tray-connect-to", server = server.as_str())
        }
        _ => primary_label(state),
    };
    let servers = state
        .config
        .interface
        .recent_servers
        .iter()
        .filter_map(|selection| {
            let (_, node) = state.config.node_at(selection)?;
            Some(TrayServer {
                selection: selection.clone(),
                label: menu_label(&menu_text(state, &node.name)),
                current: state.config.active.as_ref() == Some(selection),
            })
        })
        .take(MAX_RECENT_SERVERS)
        .collect();
    TrayView {
        icon,
        tooltip: fit_tooltip(&i18n::tray_tooltip(&status, server.as_deref())),
        status_label,
        primary_label,
        primary_enabled: primary_action != PrimaryAction::Disabled,
        window_shown,
        window_label: if window_shown {
            tr!("tray-hide")
        } else {
            tr!("tray-open")
        },
        servers_label: tr!("tray-servers"),
        servers,
        all_servers_label: tr!("tray-all-servers"),
        quit_label: tr!("tray-quit"),
    }
}

/// Windows reads `&` in a menu item as the mark of its access key.
fn menu_label(text: &str) -> String {
    text.replace('&', "&&")
}

/// A subscription's text on one line: Windows draws a line break or a tab in
/// a tooltip or a menu item as is.
fn menu_text(state: &State, text: &str) -> String {
    state
        .text(text)
        .split(|character: char| character.is_whitespace() || character.is_control())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn fit_tooltip(text: &str) -> String {
    if text.encode_utf16().count() <= 127 {
        return text.to_owned();
    }
    let mut fitted = String::new();
    let mut units = 0;
    for character in text.chars() {
        if units + character.len_utf16() > 126 {
            break;
        }
        fitted.push(character);
        units += character.len_utf16();
    }
    fitted.push('…');
    fitted
}

fn icon_size(metric: i32) -> u32 {
    if metric <= 0 {
        return 32;
    }
    metric.clamp(16, 64) as u32
}

/// The taskbar's own icon size: Windows scales any other size with a plain
/// filter, which blurs the petals.
fn taskbar_icon_size() -> u32 {
    icon_size(rosetun_shell::taskbar_small_icon_size())
}

/// The tray icon shown, the taskbar size it was drawn for, and every icon
/// drawn so far, so switching back to a state does not rasterize it again.
struct IconSlot<I> {
    size: u32,
    checked: Instant,
    shown: Option<(TrayState, u32)>,
    icons: HashMap<(TrayState, u32), I>,
}

impl<I: Clone> IconSlot<I> {
    fn new(size: u32, now: Instant) -> Self {
        Self {
            size,
            checked: now,
            shown: None,
            icons: HashMap::new(),
        }
    }

    /// Drops every icon drawn so far, so the next update draws in the current palette.
    fn forget(&mut self) {
        self.shown = None;
        self.icons.clear();
    }

    /// The icon to set for `state`, or `None` when it is already shown.
    fn update<E>(
        &mut self,
        state: TrayState,
        now: Instant,
        probe: impl FnOnce() -> u32,
        build: impl FnOnce(TrayState, u32) -> Result<I, E>,
    ) -> Result<Option<I>, E> {
        if now.saturating_duration_since(self.checked) >= SIZE_CHECK {
            self.checked = now;
            self.size = probe();
        }
        let key = (state, self.size);
        if self.shown == Some(key) {
            return Ok(None);
        }
        // Marked before building, so a failed build is not retried every frame.
        self.shown = Some(key);
        if let Some(icon) = self.icons.get(&key) {
            return Ok(Some(icon.clone()));
        }
        let icon = build(state, self.size)?;
        self.icons.insert(key, icon.clone());
        Ok(Some(icon))
    }
}

fn rose(state: TrayState, size: u32) -> Result<Icon, tray_icon::BadIcon> {
    Icon::from_rgba(
        rose_icon::rose_icon_rgba(size, RoseIcon::Tray(state), theme::palette()),
        size,
        size,
    )
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum TrayError {
    #[error(transparent)]
    Icon(#[from] tray_icon::Error),
    #[error(transparent)]
    BadIcon(#[from] tray_icon::BadIcon),
    #[error(transparent)]
    Menu(#[from] tray_icon::menu::Error),
}

pub(crate) struct Tray {
    icon: tray_icon::TrayIcon,
    status: MenuItem,
    primary: MenuItem,
    window: MenuItem,
    /// Read by the menu handler, so the window item does what its text said.
    window_shown: Arc<AtomicBool>,
    servers: Submenu,
    /// The servers listed in `servers`, by place; read by the menu handler.
    choices: Arc<Mutex<Vec<Selection>>>,
    /// Windows flips a check item's mark on a click, so the list is rebuilt
    /// after one even when the choice did not change.
    server_clicked: Arc<AtomicBool>,
    quit: MenuItem,
    shown: Option<TrayView>,
    slot: IconSlot<Icon>,
}

impl Tray {
    pub(crate) fn new(events: Sender<ShellEvent>, ctx: egui::Context) -> Result<Self, TrayError> {
        let status = MenuItem::with_id(STATUS_ID, constants::TITLE, false, None);
        let window = MenuItem::with_id(WINDOW_ID, tr!("tray-open"), true, None);
        let primary = MenuItem::with_id(PRIMARY_ID, tr!("connect"), false, None);
        let servers = Submenu::with_id(SERVERS_ID, tr!("tray-servers"), true);
        let quit = MenuItem::with_id(QUIT_ID, tr!("tray-quit"), true, None);
        let menu = Menu::with_items(&[
            &status,
            &PredefinedMenuItem::separator(),
            &window,
            &PredefinedMenuItem::separator(),
            &primary,
            &servers,
            &PredefinedMenuItem::separator(),
            &quit,
        ])?;
        let now = Instant::now();
        let mut slot = IconSlot::new(taskbar_icon_size(), now);
        let initial_icon = slot
            .update(TrayState::Disconnected, now, || 32, rose)?
            .expect("a new slot shows nothing yet");
        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false)
            .with_tooltip(constants::TITLE)
            .with_icon(initial_icon)
            .build()?;

        let click_events = events.clone();
        let click_ctx = ctx.clone();
        TrayIconEvent::set_event_handler(Some(move |event| {
            if matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
            ) {
                let _ = click_events.send(ShellEvent::Show);
                click_ctx.request_repaint();
            }
        }));
        let window_shown = Arc::new(AtomicBool::new(false));
        let menu_window_shown = Arc::clone(&window_shown);
        let choices = Arc::new(Mutex::new(Vec::new()));
        let menu_choices = Arc::clone(&choices);
        let server_clicked = Arc::new(AtomicBool::new(false));
        let menu_server_clicked = Arc::clone(&server_clicked);
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            let shell_event = match event.id.as_ref() {
                WINDOW_ID if menu_window_shown.load(Ordering::Relaxed) => Some(ShellEvent::Hide),
                WINDOW_ID => Some(ShellEvent::Show),
                PRIMARY_ID => Some(ShellEvent::Primary),
                ALL_SERVERS_ID => Some(ShellEvent::ShowServers),
                QUIT_ID => Some(ShellEvent::Quit),
                id => id
                    .strip_prefix(SERVER_ID_PREFIX)
                    .and_then(|place| place.parse::<usize>().ok())
                    .and_then(|place| {
                        menu_server_clicked.store(true, Ordering::Relaxed);
                        menu_choices
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .get(place)
                            .cloned()
                    })
                    .map(ShellEvent::SelectServer),
            };
            if let Some(shell_event) = shell_event {
                let _ = events.send(shell_event);
                ctx.request_repaint();
            }
        }));
        Ok(Self {
            icon,
            status,
            primary,
            window,
            window_shown,
            servers,
            choices,
            server_clicked,
            quit,
            shown: None,
            slot,
        })
    }

    /// The accent preset changed: the shown icon is drawn again on the next `sync`.
    pub(crate) fn forget_icons(&mut self) {
        self.slot.forget();
    }

    pub(crate) fn sync(&mut self, view: &TrayView) {
        match self
            .slot
            .update(view.icon, Instant::now(), taskbar_icon_size, rose)
        {
            Ok(Some(icon)) => {
                if let Err(error) = self.icon.set_icon(Some(icon)) {
                    tracing::warn!(%error, "could not update tray icon");
                }
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(%error, "could not create tray icon"),
        }
        let server_clicked = self.server_clicked.swap(false, Ordering::Relaxed);
        if self.shown.as_ref() == Some(view) && !server_clicked {
            return;
        }
        let servers_changed = self.shown.as_ref().is_none_or(|shown| {
            shown.servers != view.servers || shown.all_servers_label != view.all_servers_label
        });
        if (server_clicked || servers_changed)
            && let Err(error) = self.fill_servers(view)
        {
            tracing::warn!(%error, "could not update tray servers");
        }
        if self
            .shown
            .as_ref()
            .is_none_or(|shown| shown.servers_label != view.servers_label)
        {
            self.servers.set_text(view.servers_label.as_str());
        }
        if self
            .shown
            .as_ref()
            .is_none_or(|shown| shown.tooltip != view.tooltip)
            && let Err(error) = self.icon.set_tooltip(Some(&view.tooltip))
        {
            tracing::warn!(%error, "could not update tray tooltip");
        }
        if self
            .shown
            .as_ref()
            .is_none_or(|shown| shown.primary_label != view.primary_label)
        {
            self.primary.set_text(view.primary_label.as_str());
        }
        if self
            .shown
            .as_ref()
            .is_none_or(|shown| shown.primary_enabled != view.primary_enabled)
        {
            self.primary.set_enabled(view.primary_enabled);
        }
        if self
            .shown
            .as_ref()
            .is_none_or(|shown| shown.status_label != view.status_label)
        {
            self.status.set_text(view.status_label.as_str());
        }
        self.window_shown
            .store(view.window_shown, Ordering::Relaxed);
        if self
            .shown
            .as_ref()
            .is_none_or(|shown| shown.window_label != view.window_label)
        {
            self.window.set_text(view.window_label.as_str());
        }
        if self
            .shown
            .as_ref()
            .is_none_or(|shown| shown.quit_label != view.quit_label)
        {
            self.quit.set_text(view.quit_label.as_str());
        }
        self.shown = Some(view.clone());
    }

    pub(crate) fn notify(&self, notice: Notice) {
        if let Err(error) = rosetun_shell::tray_notice(
            self.icon.window_handle(),
            TRAY_ICON_ID,
            constants::TITLE,
            &notice.text(),
        ) {
            tracing::warn!(%error, ?notice, "could not show tray notification");
        }
    }

    fn fill_servers(&self, view: &TrayView) -> Result<(), tray_icon::menu::Error> {
        while self.servers.remove_at(0).is_some() {}
        *self.choices.lock().unwrap_or_else(PoisonError::into_inner) = view
            .servers
            .iter()
            .map(|server| server.selection.clone())
            .collect();
        for (place, server) in view.servers.iter().enumerate() {
            self.servers.append(&CheckMenuItem::with_id(
                format!("{SERVER_ID_PREFIX}{place}"),
                server.label.as_str(),
                true,
                server.current,
                None,
            ))?;
        }
        if !view.servers.is_empty() {
            self.servers.append(&PredefinedMenuItem::separator())?;
        }
        self.servers.append(&MenuItem::with_id(
            ALL_SERVERS_ID,
            view.all_servers_label.as_str(),
            true,
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{IconSlot, SIZE_CHECK, fit_tooltip, icon_size, rose, tray_view};
    use crate::i18n;
    use crate::rose_icon::TrayState;
    use crate::state::State;
    use rosetun_config::{
        AppConfig, ConnectionState, Node, NodeId, Selection, Status, SubscriptionId,
    };
    use rosetun_core::Store;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    fn config_with_server(test: &str, name: &str) -> AppConfig {
        static FILES: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "rosetun-tray-test-{test}-{}-{}",
            std::process::id(),
            FILES.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(
            &path,
            format!(
                r#"{{"subscriptions":[{{"id":"provider","name":"Provider","url":"https://example.com","nodes":[{{"id":"server","name":"{name}","server":"example.com","port":443,"outbound":{{"trojan":{{"password":"test"}}}}}}]}}],"active":{{"subscription":"provider","node":"server"}}}}"#
            ),
        )
        .unwrap();
        let config = Store::at(&path).load().unwrap();
        fs::remove_file(path).unwrap();
        config
    }

    #[test]
    fn icon_size_stays_within_16_to_64() {
        for (metric, size) in [(16, 16), (20, 20), (24, 24), (8, 16), (200, 64)] {
            assert_eq!(icon_size(metric), size, "{metric}");
        }
        assert_eq!(icon_size(0), 32, "a failed lookup");
        assert_eq!(icon_size(-1), 32);
    }

    #[test]
    fn rose_is_drawn_at_the_requested_size() {
        for size in [16, 20, 24] {
            assert!(rose(TrayState::Connected, size).is_ok(), "{size} px");
        }
    }

    #[test]
    fn icon_is_rebuilt_only_for_a_new_state_or_size() {
        let start = Instant::now();
        let mut slot = IconSlot::new(20, start);
        let mut built = Vec::new();
        let mut update = |slot: &mut IconSlot<(TrayState, u32)>, state, now, size| {
            slot.update(
                state,
                now,
                || size,
                |state, size| {
                    built.push((state, size));
                    Ok::<_, ()>((state, size))
                },
            )
            .unwrap()
        };
        let connected = TrayState::Connected;
        assert_eq!(
            update(&mut slot, connected, start, 20),
            Some((connected, 20))
        );
        assert_eq!(update(&mut slot, connected, start, 24), None);
        // A changed size is noticed only once the check interval has passed.
        let later = start + Duration::from_millis(500);
        assert_eq!(update(&mut slot, connected, later, 24), None);
        let later = start + SIZE_CHECK;
        assert_eq!(
            update(&mut slot, connected, later, 24),
            Some((connected, 24))
        );
        assert_eq!(update(&mut slot, connected, later, 24), None);
        let later = later + SIZE_CHECK;
        assert_eq!(update(&mut slot, connected, later, 24), None);
        // Back to an icon drawn before: it comes from the cache.
        let later = later + SIZE_CHECK;
        assert_eq!(
            update(&mut slot, connected, later, 20),
            Some((connected, 20))
        );
        let failed = TrayState::Failed;
        assert_eq!(update(&mut slot, failed, later, 20), Some((failed, 20)));
        assert_eq!(
            update(&mut slot, connected, later, 20),
            Some((connected, 20))
        );
        // After a palette change the cached icon is drawn again.
        slot.forget();
        assert_eq!(
            update(&mut slot, connected, later, 20),
            Some((connected, 20))
        );
        assert_eq!(
            built,
            [
                (connected, 20),
                (connected, 24),
                (failed, 20),
                (connected, 20)
            ]
        );
    }

    #[test]
    fn tooltip_fits_windows_utf16_limit() {
        assert_eq!(fit_tooltip("Rosetun · Connected"), "Rosetun · Connected");
        assert_eq!(fit_tooltip(&"A".repeat(127)), "A".repeat(127));
        assert_eq!(
            fit_tooltip(&format!("{}😀X", "A".repeat(125))),
            format!("{}…", "A".repeat(125))
        );
        let fitted = fit_tooltip(&format!("{}{}", "сервер".repeat(25), "🛰️".repeat(25)));
        assert!(fitted.encode_utf16().count() <= 127);
        assert!(fitted.ends_with('…'));
        let fitted = fit_tooltip(&"😀".repeat(70));
        assert!(fitted.encode_utf16().count() <= 127);
        assert!(fitted.ends_with('…'));
    }

    #[test]
    fn status_and_primary_action_follow_visible_state() {
        let mut state = State::default();
        let unknown = tray_view(&state, true);
        assert_eq!(unknown.icon, TrayState::ServiceUnavailable);
        assert_eq!(
            unknown.tooltip,
            i18n::tray_tooltip(&tr!("helper-unavailable"), None)
        );
        assert!(!unknown.primary_enabled);
        assert_eq!(unknown.window_label, tr!("tray-hide"));

        state.helper_available = true;
        state.status = Status {
            state: ConnectionState::Connected,
            ..Status::default()
        };
        state.config = config_with_server("status", r"Server\r\n\tBlue");
        let connected = tray_view(&state, true);
        assert_eq!(connected.icon, TrayState::Connected);
        assert_eq!(connected.primary_label, tr!("disconnect"));
        assert!(connected.primary_enabled);
        assert!(connected.tooltip.contains("Server Blue"));
        assert_eq!(connected.tooltip.matches('\n').count(), 1);
        assert!(!connected.tooltip.contains('\r'));
        assert!(!connected.tooltip.contains('\t'));

        state.helper_available = false;
        let unavailable = tray_view(&state, true);
        assert_eq!(unavailable.icon, TrayState::ServiceUnavailable);
        assert_eq!(
            unavailable.tooltip,
            i18n::tray_tooltip(&tr!("helper-unavailable"), None)
        );
    }

    #[test]
    fn each_connection_state_has_the_expected_tray_shape() {
        let mut state = State::default();
        state.helper_available = true;
        for (connection, expected) in [
            (ConnectionState::Disconnected, TrayState::Disconnected),
            (ConnectionState::Connecting, TrayState::Connecting),
            (ConnectionState::Reconnecting, TrayState::Connecting),
            (ConnectionState::Connected, TrayState::Connected),
            (
                ConnectionState::FailedProtected {
                    reason: String::new(),
                    failure_kind: None,
                },
                TrayState::Blocked,
            ),
            (
                ConnectionState::Failed {
                    reason: String::new(),
                    failure_kind: None,
                },
                TrayState::Failed,
            ),
        ] {
            state.status.state = connection.clone();
            let tray = tray_view(&state, true);
            assert_eq!(tray.icon, expected, "{connection:?}");
            assert_eq!(
                tray.tooltip,
                i18n::tray_tooltip(&crate::view::connection::state_style(&connection).0, None)
            );
        }
    }

    #[test]
    fn lockdown_without_a_tunnel_shows_blocked() {
        let mut state = State::default();
        state.helper_available = true;
        state.status.lockdown = true;
        for (connection, expected) in [
            (ConnectionState::Disconnected, TrayState::Blocked),
            (
                ConnectionState::Failed {
                    reason: String::new(),
                    failure_kind: None,
                },
                TrayState::Blocked,
            ),
            (ConnectionState::Connecting, TrayState::Connecting),
            (ConnectionState::Connected, TrayState::Connected),
        ] {
            state.status.state = connection.clone();
            assert_eq!(tray_view(&state, true).icon, expected, "{connection:?}");
        }
    }

    #[test]
    fn the_status_line_names_the_state_and_the_server_when_connected() {
        let mut state = State::default();
        assert_eq!(
            tray_view(&state, true).status_label,
            tr!("helper-unavailable")
        );
        state.helper_available = true;
        state.config = config_with_server("line", r"Server\r\n\tBlue");
        let failed = || ConnectionState::Failed {
            reason: String::new(),
            failure_kind: None,
        };
        for (connection, lockdown, expected) in [
            (
                ConnectionState::Connected,
                false,
                format!("{} · Server Blue", tr!("connected")),
            ),
            (ConnectionState::Connecting, false, tr!("connecting")),
            (ConnectionState::Reconnecting, false, tr!("reconnecting")),
            (ConnectionState::Disconnected, false, tr!("disconnected")),
            (ConnectionState::Disconnected, true, tr!("tray-blocked")),
            (failed(), false, tr!("failed")),
            (failed(), true, tr!("tray-blocked")),
            (
                ConnectionState::FailedProtected {
                    reason: String::new(),
                    failure_kind: None,
                },
                false,
                tr!("tray-blocked"),
            ),
        ] {
            state.status.state = connection.clone();
            state.status.lockdown = lockdown;
            assert_eq!(
                tray_view(&state, true).status_label,
                expected,
                "{connection:?}, Lockdown {lockdown}"
            );
        }
        state.helper_available = false;
        assert_eq!(
            tray_view(&state, true).status_label,
            tr!("helper-unavailable")
        );
    }

    #[test]
    fn one_window_item_opens_a_hidden_window_and_hides_a_shown_one() {
        let state = State::default();
        let shown = tray_view(&state, true);
        assert!(shown.window_shown);
        assert_eq!(shown.window_label, tr!("tray-hide"));
        let hidden = tray_view(&state, false);
        assert!(!hidden.window_shown);
        assert_eq!(hidden.window_label, tr!("tray-open"));
        assert_ne!(shown, hidden, "a changed window item is synced");
    }

    #[test]
    fn connect_names_the_selected_server() {
        let mut state = State::default();
        state.helper_available = true;
        let tray = tray_view(&state, true);
        assert_eq!(tray.primary_label, tr!("connect"), "no server selected");
        state.config = config_with_server("connect", r"Japan\t1");
        let tray = tray_view(&state, true);
        assert_eq!(
            tray.primary_label,
            tr!("tray-connect-to", server = "Japan 1")
        );
        assert!(tray.primary_enabled);
        state.status.state = ConnectionState::Connected;
        assert_eq!(tray_view(&state, true).primary_label, tr!("disconnect"));
    }

    fn pick(node: &str) -> Selection {
        Selection {
            subscription: SubscriptionId::new("provider"),
            node: NodeId::new(node),
        }
    }

    /// A subscription with servers `a` to `g`, `a` selected.
    fn config_with_servers() -> AppConfig {
        let mut config = config_with_server("servers", "a");
        let template = config.subscriptions[0].nodes[0].clone();
        config.subscriptions[0].nodes = ["a", "b", "c", "d", "e", "f", "g"]
            .into_iter()
            .map(|id| Node {
                id: NodeId::new(id),
                name: format!("Server {id}"),
                ..template.clone()
            })
            .collect();
        config.active = Some(pick("a"));
        config
    }

    fn labels(state: &State) -> Vec<String> {
        tray_view(state, true)
            .servers
            .into_iter()
            .map(|server| server.label)
            .collect()
    }

    #[test]
    fn the_servers_menu_lists_recent_servers_newest_first_up_to_five() {
        let mut state = State::default();
        state.config = config_with_servers();
        assert!(
            tray_view(&state, true).servers.is_empty(),
            "only All servers"
        );
        state.config.interface.recent_servers = ["a", "b", "c", "d", "e", "f"].map(pick).to_vec();
        assert_eq!(
            labels(&state),
            ["Server a", "Server b", "Server c", "Server d", "Server e"]
        );
    }

    #[test]
    fn a_vanished_server_is_not_listed() {
        let mut state = State::default();
        state.config = config_with_servers();
        state.config.interface.recent_servers = vec![
            pick("b"),
            pick("gone"),
            Selection {
                subscription: SubscriptionId::new("deleted"),
                node: NodeId::new("a"),
            },
            pick("a"),
        ];
        assert_eq!(labels(&state), ["Server b", "Server a"]);
    }

    #[test]
    fn the_current_server_is_checked() {
        let mut state = State::default();
        state.config = config_with_servers();
        state.config.interface.recent_servers = vec![pick("b"), pick("a")];
        let servers = tray_view(&state, true).servers;
        assert_eq!(
            servers
                .iter()
                .map(|server| (server.selection.node.as_str(), server.current))
                .collect::<Vec<_>>(),
            [("b", false), ("a", true)]
        );
    }

    #[test]
    fn an_ampersand_in_a_name_is_not_an_access_key() {
        let mut state = State::default();
        state.helper_available = true;
        state.config = config_with_server("ampersand", "A&B");
        state.config.interface.recent_servers = vec![pick("server")];
        let tray = tray_view(&state, true);
        assert_eq!(tray.servers[0].label, "A&&B");
        assert_eq!(tray.primary_label, tr!("tray-connect-to", server = "A&&B"));
        assert!(tray.tooltip.contains("A&B") && !tray.tooltip.contains("A&&B"));
    }
}
