use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use eframe::egui;
use rosetun_config::ConnectionState;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

use crate::actions::PrimaryAction;
use crate::app::ShellEvent;
use crate::rose_icon::{self, RoseIcon, TrayState};
use crate::state::{State, primary_label};
use crate::{constants, i18n, view};

const OPEN_ID: &str = "rosetun.tray.open";
const HIDE_ID: &str = "rosetun.tray.hide";
const PRIMARY_ID: &str = "rosetun.tray.primary";
const QUIT_ID: &str = "rosetun.tray.quit";
/// The taskbar's icon size changes with its monitor's scale; reading it on
/// every frame would cost a window lookup per frame.
const SIZE_CHECK: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TrayView {
    pub(crate) icon: TrayState,
    pub(crate) tooltip: String,
    pub(crate) primary_label: String,
    pub(crate) primary_enabled: bool,
    pub(crate) open_label: String,
    pub(crate) hide_label: String,
    pub(crate) quit_label: String,
}

pub(crate) fn tray_view(state: &State) -> TrayView {
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
        .map(|(_, node)| {
            state
                .text(&node.name)
                .split(|character: char| character.is_whitespace() || character.is_control())
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        });
    TrayView {
        icon,
        tooltip: fit_tooltip(&i18n::tray_tooltip(&status, server.as_deref())),
        primary_label: primary_label(state),
        primary_enabled: state.primary_action() != PrimaryAction::Disabled,
        open_label: tr!("tray-open"),
        hide_label: tr!("tray-hide"),
        quit_label: tr!("tray-quit"),
    }
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
        rose_icon::rose_icon_rgba(size, RoseIcon::Tray(state)),
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
    primary: MenuItem,
    open: MenuItem,
    hide: MenuItem,
    quit: MenuItem,
    shown: Option<TrayView>,
    slot: IconSlot<Icon>,
}

impl Tray {
    pub(crate) fn new(events: Sender<ShellEvent>, ctx: egui::Context) -> Result<Self, TrayError> {
        let open = MenuItem::with_id(OPEN_ID, tr!("tray-open"), true, None);
        let hide = MenuItem::with_id(HIDE_ID, tr!("tray-hide"), true, None);
        let primary = MenuItem::with_id(PRIMARY_ID, tr!("connect"), false, None);
        let quit = MenuItem::with_id(QUIT_ID, tr!("tray-quit"), true, None);
        let menu = Menu::with_items(&[
            &open,
            &hide,
            &PredefinedMenuItem::separator(),
            &primary,
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
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            let shell_event = match event.id.as_ref() {
                OPEN_ID => Some(ShellEvent::Show),
                HIDE_ID => Some(ShellEvent::Hide),
                PRIMARY_ID => Some(ShellEvent::Primary),
                QUIT_ID => Some(ShellEvent::Quit),
                _ => None,
            };
            if let Some(shell_event) = shell_event {
                let _ = events.send(shell_event);
                ctx.request_repaint();
            }
        }));
        Ok(Self {
            icon,
            primary,
            open,
            hide,
            quit,
            shown: None,
            slot,
        })
    }

    pub(crate) fn sync(&mut self, view: &TrayView) {
        match self
            .slot
            .update(view.icon, Instant::now(), taskbar_icon_size, rose)
        {
            Ok(Some(icon)) => {
                if let Err(error) = self.icon.set_icon(Some(icon)) {
                    tracing::warn!(%error, "Could not update tray icon");
                }
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(%error, "Could not create tray icon"),
        }
        if self.shown.as_ref() == Some(view) {
            return;
        }
        if self
            .shown
            .as_ref()
            .is_none_or(|shown| shown.tooltip != view.tooltip)
            && let Err(error) = self.icon.set_tooltip(Some(&view.tooltip))
        {
            tracing::warn!(%error, "Could not update tray tooltip");
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
            .is_none_or(|shown| shown.open_label != view.open_label)
        {
            self.open.set_text(view.open_label.as_str());
        }
        if self
            .shown
            .as_ref()
            .is_none_or(|shown| shown.hide_label != view.hide_label)
        {
            self.hide.set_text(view.hide_label.as_str());
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
}

#[cfg(test)]
mod tests {
    use super::{IconSlot, SIZE_CHECK, fit_tooltip, icon_size, rose, tray_view};
    use crate::i18n;
    use crate::rose_icon::TrayState;
    use crate::state::State;
    use rosetun_config::{ConnectionState, Status};
    use rosetun_core::Store;
    use std::fs;
    use std::time::{Duration, Instant};

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
        assert_eq!(built, [(connected, 20), (connected, 24), (failed, 20)]);
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
        let unknown = tray_view(&state);
        assert_eq!(unknown.icon, TrayState::ServiceUnavailable);
        assert_eq!(
            unknown.tooltip,
            i18n::tray_tooltip(&tr!("helper-unavailable"), None)
        );
        assert!(!unknown.primary_enabled);
        assert_eq!(unknown.hide_label, tr!("tray-hide"));

        state.helper_available = true;
        state.status = Status {
            state: ConnectionState::Connected,
            ..Status::default()
        };
        let path = std::env::temp_dir().join(format!("rosetun-tray-test-{}", std::process::id()));
        fs::write(
            &path,
            r#"{"subscriptions":[{"id":"provider","name":"Provider","url":"https://example.com","nodes":[{"id":"server","name":"Server\r\n\tBlue","server":"example.com","port":443,"outbound":{"trojan":{"password":"test"}}}]}],"active":{"subscription":"provider","node":"server"}}"#,
        )
        .unwrap();
        state.config = Store::at(&path).load().unwrap();
        fs::remove_file(path).unwrap();
        let connected = tray_view(&state);
        assert_eq!(connected.icon, TrayState::Connected);
        assert_eq!(connected.primary_label, tr!("disconnect"));
        assert!(connected.primary_enabled);
        assert!(connected.tooltip.contains("Server Blue"));
        assert_eq!(connected.tooltip.matches('\n').count(), 1);
        assert!(!connected.tooltip.contains('\r'));
        assert!(!connected.tooltip.contains('\t'));

        state.helper_available = false;
        let unavailable = tray_view(&state);
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
            let tray = tray_view(&state);
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
            assert_eq!(tray_view(&state).icon, expected, "{connection:?}");
        }
    }
}
