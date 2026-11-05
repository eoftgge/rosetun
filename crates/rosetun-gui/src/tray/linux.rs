//! The tray on Linux: the same menu and icons as on Windows, drawn by the
//! desktop's StatusNotifierItem host.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use rosetun_config::Selection;
use rosetun_shell::{StatusItem, TrayEntry, TrayInput, TrayItem, TrayPixmap};

use super::{IconSlot, TrayView};
use crate::app::ShellEvent;
use crate::repaint::Repaint;
use crate::rose_icon::{self, RoseIcon, TrayState};
use crate::{constants, theme};

const STATUS_ID: i32 = 1;
const PRIMARY_ID: i32 = 2;
const RECONNECT_ID: i32 = 3;
const SERVERS_ID: i32 = 4;
const ALL_SERVERS_ID: i32 = 5;
const WINDOW_ID: i32 = 6;
const UPDATE_ID: i32 = 7;
const QUIT_ID: i32 = 8;
/// Followed by the server's place in `Tray::choices`.
const FIRST_SERVER_ID: i32 = 100;
/// The host scales the nearest size to its panel, so it gets a few.
const ICON_SIDES: [u32; 4] = [22, 32, 48, 64];

pub(crate) struct Tray {
    item: StatusItem,
    /// Read by the input handler, so the window item does what its text said.
    window_shown: Arc<AtomicBool>,
    /// The servers listed in the menu, by place; read by the input handler.
    choices: Arc<Mutex<Vec<Selection>>>,
    shown: Option<TrayView>,
    slot: IconSlot<Vec<TrayPixmap>>,
}

impl Tray {
    pub(crate) fn new(events: Sender<ShellEvent>, repaint: Repaint) -> Self {
        let window_shown = Arc::new(AtomicBool::new(false));
        let handler_window_shown = Arc::clone(&window_shown);
        let choices = Arc::new(Mutex::new(Vec::new()));
        let handler_choices = Arc::clone(&choices);
        let item = StatusItem::start("rosetun", constants::TITLE, move |input| {
            let event = shell_event(
                input,
                handler_window_shown.load(Ordering::Relaxed),
                &handler_choices
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner),
            );
            if let Some(event) = event {
                let _ = events.send(event);
                repaint.request();
            }
        });
        Self {
            item,
            window_shown,
            choices,
            shown: None,
            slot: IconSlot::new(0, Instant::now()),
        }
    }

    /// Whether a host shows the icon, so that a hidden window can be found again.
    pub(crate) fn available(&self) -> bool {
        self.item.has_host()
    }

    pub(crate) fn absent_reason(&self) -> Option<String> {
        self.item.absent_reason()
    }

    /// The accent preset changed: the shown icon is drawn again on the next `sync`.
    pub(crate) fn forget_icons(&mut self) {
        self.slot.forget();
    }

    pub(crate) fn sync(&mut self, view: &TrayView) {
        let icon = self.slot.update(
            view.icon,
            Instant::now(),
            || 0,
            |state, _| Ok::<_, std::convert::Infallible>(pixmaps(state)),
        );
        if let Ok(Some(icon)) = icon {
            self.item.set_icon(icon);
        }
        self.window_shown
            .store(view.window_shown, Ordering::Relaxed);
        if self.shown.as_ref() == Some(view) {
            return;
        }
        if self
            .shown
            .as_ref()
            .is_none_or(|shown| shown.tooltip != view.tooltip)
        {
            self.item.set_tooltip(constants::TITLE, &view.tooltip);
        }
        *self.choices.lock().unwrap_or_else(PoisonError::into_inner) = view
            .servers
            .iter()
            .map(|server| server.selection.clone())
            .collect();
        let menu = menu_entries(view);
        if self
            .shown
            .as_ref()
            .is_none_or(|shown| menu_entries(shown) != menu)
        {
            self.item.set_menu(menu);
        }
        self.shown = Some(view.clone());
    }
}

fn pixmaps(state: TrayState) -> Vec<TrayPixmap> {
    ICON_SIDES
        .iter()
        .map(|&side| {
            let rgba = rose_icon::rose_icon_rgba(side, RoseIcon::Tray(state), theme::palette());
            TrayPixmap::from_rgba(side as i32, &rgba)
        })
        .collect()
}

fn item(id: i32, label: &str, enabled: bool) -> TrayItem {
    TrayItem {
        id,
        label: label.to_owned(),
        enabled,
        ..TrayItem::default()
    }
}

/// The connection under its state, the window and the app at the bottom,
/// the same order as the Windows menu.
fn menu_entries(view: &TrayView) -> Vec<TrayEntry> {
    let mut servers: Vec<TrayEntry> = view
        .servers
        .iter()
        .enumerate()
        .map(|(place, server)| {
            TrayEntry::Item(TrayItem {
                checked: Some(server.current),
                ..item(
                    FIRST_SERVER_ID.saturating_add(place as i32),
                    &server.label,
                    true,
                )
            })
        })
        .collect();
    if !servers.is_empty() {
        servers.push(TrayEntry::Separator);
    }
    servers.push(TrayEntry::Item(item(
        ALL_SERVERS_ID,
        &view.all_servers_label,
        true,
    )));

    let mut entries = vec![
        TrayEntry::Item(item(STATUS_ID, &view.status_label, false)),
        TrayEntry::Separator,
        TrayEntry::Item(item(PRIMARY_ID, &view.primary_label, view.primary_enabled)),
    ];
    if let Some(label) = &view.reconnect_label {
        entries.push(TrayEntry::Item(item(
            RECONNECT_ID,
            label,
            view.reconnect_enabled,
        )));
    }
    entries.push(TrayEntry::Item(TrayItem {
        children: servers,
        ..item(SERVERS_ID, &view.servers_label, true)
    }));
    entries.push(TrayEntry::Separator);
    entries.push(TrayEntry::Item(item(WINDOW_ID, &view.window_label, true)));
    if let Some(label) = &view.update_label {
        entries.push(TrayEntry::Item(item(UPDATE_ID, label, true)));
    }
    entries.push(TrayEntry::Item(item(QUIT_ID, &view.quit_label, true)));
    entries
}

fn shell_event(input: TrayInput, window_shown: bool, choices: &[Selection]) -> Option<ShellEvent> {
    let id = match input {
        TrayInput::Activate => return Some(ShellEvent::Show),
        TrayInput::Clicked(id) => id,
    };
    match id {
        WINDOW_ID if window_shown => Some(ShellEvent::Hide),
        WINDOW_ID => Some(ShellEvent::Show),
        PRIMARY_ID => Some(ShellEvent::Primary),
        RECONNECT_ID => Some(ShellEvent::Reconnect),
        ALL_SERVERS_ID => Some(ShellEvent::ShowServers),
        UPDATE_ID => Some(ShellEvent::OpenUpdate),
        QUIT_ID => Some(ShellEvent::Quit),
        id => {
            let place = usize::try_from(id.checked_sub(FIRST_SERVER_ID)?).ok()?;
            choices.get(place).cloned().map(ShellEvent::SelectServer)
        }
    }
}

#[cfg(test)]
mod tests {
    use rosetun_config::{NodeId, SubscriptionId};

    use super::super::TrayServer;
    use super::*;

    fn selection(node: &str) -> Selection {
        Selection {
            subscription: SubscriptionId::new("provider"),
            node: NodeId::new(node),
        }
    }

    fn view() -> TrayView {
        TrayView {
            icon: TrayState::Disconnected,
            tooltip: "Rosetun".to_owned(),
            status_label: "Status".to_owned(),
            primary_label: "Connect".to_owned(),
            primary_enabled: true,
            reconnect_label: None,
            reconnect_enabled: false,
            window_shown: false,
            window_label: "Open".to_owned(),
            servers_label: "Servers".to_owned(),
            servers: Vec::new(),
            all_servers_label: "All servers".to_owned(),
            update_label: None,
            quit_label: "Quit".to_owned(),
        }
    }

    fn top_level(entries: &[TrayEntry]) -> Vec<(i32, bool)> {
        entries
            .iter()
            .filter_map(|entry| match entry {
                TrayEntry::Item(item) => Some((item.id, item.enabled)),
                TrayEntry::Separator => None,
            })
            .collect()
    }

    fn children(entries: &[TrayEntry], id: i32) -> Vec<TrayEntry> {
        entries
            .iter()
            .find_map(|entry| match entry {
                TrayEntry::Item(item) if item.id == id => Some(item.children.clone()),
                _ => None,
            })
            .unwrap()
    }

    #[test]
    fn the_menu_has_the_windows_order_and_a_disabled_status_line() {
        let entries = menu_entries(&view());
        assert_eq!(
            top_level(&entries),
            [
                (STATUS_ID, false),
                (PRIMARY_ID, true),
                (SERVERS_ID, true),
                (WINDOW_ID, true),
                (QUIT_ID, true)
            ]
        );
        assert_eq!(entries[1], TrayEntry::Separator);
    }

    #[test]
    fn reconnect_follows_primary_and_update_comes_right_before_quit() {
        let entries = menu_entries(&TrayView {
            reconnect_label: Some("Reconnect".to_owned()),
            reconnect_enabled: false,
            update_label: Some("Update".to_owned()),
            ..view()
        });
        assert_eq!(
            top_level(&entries),
            [
                (STATUS_ID, false),
                (PRIMARY_ID, true),
                (RECONNECT_ID, false),
                (SERVERS_ID, true),
                (WINDOW_ID, true),
                (UPDATE_ID, true),
                (QUIT_ID, true)
            ]
        );
    }

    #[test]
    fn servers_are_checked_items_above_all_servers() {
        let entries = menu_entries(&TrayView {
            servers: vec![
                TrayServer {
                    selection: selection("a"),
                    label: "A".to_owned(),
                    current: true,
                },
                TrayServer {
                    selection: selection("b"),
                    label: "B".to_owned(),
                    current: false,
                },
            ],
            ..view()
        });
        let servers = children(&entries, SERVERS_ID);
        let checks: Vec<_> = servers
            .iter()
            .filter_map(|entry| match entry {
                TrayEntry::Item(item) => Some((item.id, item.checked)),
                TrayEntry::Separator => None,
            })
            .collect();
        assert_eq!(
            checks,
            [
                (FIRST_SERVER_ID, Some(true)),
                (FIRST_SERVER_ID + 1, Some(false)),
                (ALL_SERVERS_ID, None)
            ]
        );
        assert_eq!(servers[2], TrayEntry::Separator);
        assert_eq!(children(&menu_entries(&view()), SERVERS_ID).len(), 1);
    }

    #[test]
    fn each_menu_item_asks_for_its_own_event() {
        let choices = [selection("a"), selection("b")];
        let event = |input, shown| format!("{:?}", shell_event(input, shown, &choices));
        for (id, shown, expected) in [
            (WINDOW_ID, true, "Hide"),
            (WINDOW_ID, false, "Show"),
            (PRIMARY_ID, false, "Primary"),
            (RECONNECT_ID, false, "Reconnect"),
            (ALL_SERVERS_ID, false, "ShowServers"),
            (UPDATE_ID, false, "OpenUpdate"),
            (QUIT_ID, false, "Quit"),
        ] {
            assert_eq!(
                event(TrayInput::Clicked(id), shown),
                format!("Some({expected})")
            );
        }
        assert_eq!(event(TrayInput::Activate, true), "Some(Show)");
        assert!(matches!(
            shell_event(TrayInput::Clicked(FIRST_SERVER_ID + 1), false, &choices),
            Some(ShellEvent::SelectServer(picked)) if picked == selection("b")
        ));
    }

    #[test]
    fn a_stale_or_inert_item_asks_for_nothing() {
        let choices = [selection("a")];
        for id in [STATUS_ID, SERVERS_ID, FIRST_SERVER_ID + 1, -1, i32::MIN] {
            assert!(
                shell_event(TrayInput::Clicked(id), false, &choices).is_none(),
                "{id}"
            );
        }
    }

    #[test]
    fn every_state_is_drawn_at_every_size_with_the_right_length() {
        for state in [
            TrayState::Connected,
            TrayState::Disconnected,
            TrayState::Connecting,
            TrayState::Blocked,
            TrayState::Failed,
            TrayState::ServiceUnavailable,
        ] {
            let icons = pixmaps(state);
            assert_eq!(icons.len(), ICON_SIDES.len());
            for icon in icons {
                let side = icon.size as usize;
                assert_eq!(icon.argb.len(), side * side * 4);
            }
        }
    }

    #[test]
    fn each_state_has_its_own_picture() {
        assert_ne!(
            pixmaps(TrayState::Connected),
            pixmaps(TrayState::Disconnected)
        );
        assert_ne!(pixmaps(TrayState::Blocked), pixmaps(TrayState::Failed));
    }
}
