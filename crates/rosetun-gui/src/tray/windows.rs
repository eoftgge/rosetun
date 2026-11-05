use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use eframe::egui;
use rosetun_config::Selection;
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

use super::{IconSlot, TrayView};
use crate::app::ShellEvent;
use crate::notices::Notice;
use crate::rose_icon::{self, RoseIcon, TrayState};
use crate::{constants, i18n, theme};

const STATUS_ID: &str = "rosetun.tray.status";
const WINDOW_ID: &str = "rosetun.tray.window";
const PRIMARY_ID: &str = "rosetun.tray.primary";
const RECONNECT_ID: &str = "rosetun.tray.reconnect";
/// The reconnect item's place in the menu: right after the primary item.
const RECONNECT_PLACE: usize = 3;
const SERVERS_ID: &str = "rosetun.tray.servers";
/// Followed by the server's place in `Tray::choices`.
const SERVER_ID_PREFIX: &str = "rosetun.tray.server.";
const ALL_SERVERS_ID: &str = "rosetun.tray.all-servers";
const UPDATE_ID: &str = "rosetun.tray.update";
/// The `uID` the icon was added with: tray-icon numbers its icons from 1 in
/// the order they are made (its `COUNTER`, 0.26) and hides the number, and
/// Rosetun makes one. Were it wrong, a notice fails with a warning only.
const TRAY_ICON_ID: u32 = 1;
const QUIT_ID: &str = "rosetun.tray.quit";

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
    /// In the menu only while `TrayView::reconnect_label` is set.
    reconnect: MenuItem,
    window: MenuItem,
    /// Read by the menu handler, so the window item does what its text said.
    window_shown: Arc<AtomicBool>,
    servers: Submenu,
    /// The servers listed in `servers`, by place; read by the menu handler.
    choices: Arc<Mutex<Vec<Selection>>>,
    /// Windows flips a check item's mark on a click, so the list is rebuilt
    /// after one even when the choice did not change.
    server_clicked: Arc<AtomicBool>,
    menu: Menu,
    /// In the menu only while `TrayView::update_label` is set.
    update: MenuItem,
    quit: MenuItem,
    shown: Option<TrayView>,
    slot: IconSlot<Icon>,
}

impl Tray {
    pub(crate) fn new(events: Sender<ShellEvent>, ctx: egui::Context) -> Result<Self, TrayError> {
        let status = MenuItem::with_id(STATUS_ID, constants::TITLE, false, None);
        let window = MenuItem::with_id(WINDOW_ID, tr!("tray-open"), true, None);
        let primary = MenuItem::with_id(PRIMARY_ID, tr!("connect"), false, None);
        let reconnect = MenuItem::with_id(RECONNECT_ID, tr!("reconnect"), false, None);
        let servers = Submenu::with_id(SERVERS_ID, tr!("tray-servers"), true);
        let update = MenuItem::with_id(UPDATE_ID, "", true, None);
        let quit = MenuItem::with_id(QUIT_ID, tr!("tray-quit"), true, None);
        // The connection under its state, the window and the app at the bottom;
        // the reconnect item goes in after primary (`RECONNECT_PLACE`), the update item before
        // quit.
        let menu = Menu::with_items(&[
            &status,
            &PredefinedMenuItem::separator(),
            &primary,
            &servers,
            &PredefinedMenuItem::separator(),
            &window,
            &quit,
        ])?;
        let now = Instant::now();
        let mut slot = IconSlot::new(taskbar_icon_size(), now);
        let initial_icon = slot
            .update(TrayState::Disconnected, now, || 32, rose)?
            .expect("a new slot shows nothing yet");
        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu.clone()))
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
                RECONNECT_ID => Some(ShellEvent::Reconnect),
                ALL_SERVERS_ID => Some(ShellEvent::ShowServers),
                UPDATE_ID => Some(ShellEvent::OpenUpdate),
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
            reconnect,
            window,
            window_shown,
            servers,
            choices,
            server_clicked,
            menu,
            update,
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
        let shown_reconnect = self
            .shown
            .as_ref()
            .and_then(|shown| shown.reconnect_label.as_deref());
        if shown_reconnect != view.reconnect_label.as_deref()
            && let Err(error) = self.show_reconnect(shown_reconnect.is_some(), view)
        {
            tracing::warn!(%error, "could not update the tray reconnect item");
        }
        if self
            .shown
            .as_ref()
            .is_none_or(|shown| shown.reconnect_enabled != view.reconnect_enabled)
        {
            self.reconnect.set_enabled(view.reconnect_enabled);
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
        let shown_update = self
            .shown
            .as_ref()
            .and_then(|shown| shown.update_label.as_deref());
        if shown_update != view.update_label.as_deref()
            && let Err(error) = self.show_update(shown_update.is_some(), view)
        {
            tracing::warn!(%error, "could not update the tray update item");
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

    pub(crate) fn notify_update(&self, version: &str) {
        if let Err(error) = rosetun_shell::tray_notice(
            self.icon.window_handle(),
            TRAY_ICON_ID,
            &i18n::update_offer(version),
            &tr!("notice-update-body"),
        ) {
            tracing::warn!(%error, "could not show the update notification");
        }
    }

    fn show_reconnect(&self, in_menu: bool, view: &TrayView) -> Result<(), tray_icon::menu::Error> {
        match (&view.reconnect_label, in_menu) {
            (Some(label), in_menu) => {
                self.reconnect.set_text(label.as_str());
                if !in_menu {
                    self.menu.insert(&self.reconnect, RECONNECT_PLACE)?;
                }
            }
            (None, true) => self.menu.remove(&self.reconnect)?,
            (None, false) => {}
        }
        Ok(())
    }

    fn show_update(&self, in_menu: bool, view: &TrayView) -> Result<(), tray_icon::menu::Error> {
        match (&view.update_label, in_menu) {
            (Some(label), in_menu) => {
                self.update.set_text(label.as_str());
                if !in_menu {
                    // Right before quit, wherever the reconnect item left that.
                    let place = self.menu.items().len().saturating_sub(1);
                    self.menu.insert(&self.update, place)?;
                }
            }
            (None, true) => self.menu.remove(&self.update)?,
            (None, false) => {}
        }
        Ok(())
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
    use super::{icon_size, rose};
    use crate::rose_icon::TrayState;

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
}
