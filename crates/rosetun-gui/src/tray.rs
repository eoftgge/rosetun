use std::sync::mpsc::Sender;

use eframe::egui;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

use crate::actions::PrimaryAction;
use crate::app::ShellEvent;
use crate::rose_icon::{self, RoseIcon};
use crate::state::{State, primary_label};
use crate::{constants, i18n, theme, view};

const OPEN_ID: &str = "rosetun.tray.open";
const HIDE_ID: &str = "rosetun.tray.hide";
const PRIMARY_ID: &str = "rosetun.tray.primary";
const QUIT_ID: &str = "rosetun.tray.quit";

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TrayView {
    pub(crate) color: egui::Color32,
    pub(crate) tooltip: String,
    pub(crate) primary_label: String,
    pub(crate) primary_enabled: bool,
    pub(crate) open_label: String,
    pub(crate) hide_label: String,
    pub(crate) quit_label: String,
}

pub(crate) fn tray_view(state: &State) -> TrayView {
    let (status, color) = state
        .visible_status()
        .map_or((tr!("status-unknown"), theme::DISCONNECTED), |status| {
            view::connection::state_style(&status.state)
        });
    let server = state.config.active_node().map(|(_, node)| {
        state
            .text(&node.name)
            .split(|character: char| character.is_whitespace() || character.is_control())
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    });
    TrayView {
        color,
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
        let initial_icon = Icon::from_rgba(
            rose_icon::rose_icon_rgba(32, RoseIcon::Tray(theme::DISCONNECTED)),
            32,
            32,
        )?;
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
        })
    }

    pub(crate) fn sync(&mut self, view: &TrayView) {
        if self.shown.as_ref() == Some(view) {
            return;
        }
        if self
            .shown
            .as_ref()
            .is_none_or(|shown| shown.color != view.color)
        {
            match Icon::from_rgba(
                rose_icon::rose_icon_rgba(32, RoseIcon::Tray(view.color)),
                32,
                32,
            ) {
                Ok(icon) => {
                    if let Err(error) = self.icon.set_icon(Some(icon)) {
                        tracing::warn!(%error, "Could not update tray icon");
                    }
                }
                Err(error) => tracing::warn!(%error, "Could not create tray icon"),
            }
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
    use super::{fit_tooltip, tray_view};
    use crate::state::State;
    use crate::{i18n, theme};
    use rosetun_config::{ConnectionState, Status};
    use rosetun_core::Store;
    use std::fs;

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
        assert_eq!(unknown.color, theme::DISCONNECTED);
        assert_eq!(
            unknown.tooltip,
            i18n::tray_tooltip(&tr!("status-unknown"), None)
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
        assert_eq!(connected.color, theme::CONNECTED);
        assert_eq!(connected.primary_label, tr!("disconnect"));
        assert!(connected.primary_enabled);
        assert!(connected.tooltip.contains("Server Blue"));
        assert_eq!(connected.tooltip.matches('\n').count(), 1);
        assert!(!connected.tooltip.contains('\r'));
        assert!(!connected.tooltip.contains('\t'));
    }
}
