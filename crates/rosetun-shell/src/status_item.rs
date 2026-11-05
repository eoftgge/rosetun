//! A tray icon on Linux: a StatusNotifierItem with its menu over dbusmenu.
//! The desktop's host draws both; without a host there is no tray, and the
//! GUI closes when its window does.
//!
//! All bus traffic runs on one thread, so a stuck session bus never stalls a
//! frame, and a missing one only leaves [`StatusItem::absent_reason`] set.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use zbus::blocking::Connection;
use zbus::blocking::connection::Builder;
use zbus::zvariant::{ObjectPath, OwnedValue, Str, Structure, StructureBuilder, Type, Value};

const ITEM_PATH: &str = "/StatusNotifierItem";
const ITEM_INTERFACE: &str = "org.kde.StatusNotifierItem";
const MENU_PATH: &str = "/MenuBar";
const MENU_INTERFACE: &str = "com.canonical.dbusmenu";
const WATCHER_NAME: &str = "org.kde.StatusNotifierWatcher";
const WATCHER_PATH: &str = "/StatusNotifierWatcher";
const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
const ROOT_ID: i32 = 0;
const DBUSMENU_VERSION: u32 = 3;
/// How often the watcher is asked after it: a restarted panel forgets the
/// item, and a host can appear later than the program at sign-in.
const WATCHER_CHECK: Duration = Duration::from_secs(3);

/// One size of the icon: `argb` holds 32-bit pixels in network byte order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayPixmap {
    pub size: i32,
    pub argb: Vec<u8>,
}

impl TrayPixmap {
    /// From straight RGBA, rows top to bottom.
    pub fn from_rgba(size: i32, rgba: &[u8]) -> Self {
        let argb = rgba
            .chunks_exact(4)
            .flat_map(|pixel| [pixel[3], pixel[0], pixel[1], pixel[2]])
            .collect();
        Self { size, argb }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayEntry {
    Separator,
    Item(TrayItem),
}

/// A menu item. `id` comes back in [`TrayInput::Clicked`]; it is never 0,
/// which names the menu's root.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrayItem {
    pub id: i32,
    pub label: String,
    pub enabled: bool,
    /// `Some` draws a check mark place.
    pub checked: Option<bool>,
    pub children: Vec<TrayEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayInput {
    /// A click on the icon itself.
    Activate,
    Clicked(i32),
}

#[derive(Debug, Default)]
struct Model {
    tooltip_title: String,
    tooltip_text: String,
    icon: Vec<TrayPixmap>,
    menu: Vec<TrayEntry>,
    revision: u32,
}

type Shared = Arc<Mutex<Model>>;
type InputHandler = Arc<dyn Fn(TrayInput) + Send + Sync>;

#[derive(Debug, Clone, Copy)]
enum Change {
    Icon,
    Tooltip,
    Menu,
}

#[derive(Debug, Default)]
struct Presence {
    host: AtomicBool,
    absent: Mutex<Option<String>>,
}

/// The icon as far as the GUI sees it. Dropping it ends the thread, and with
/// the connection the icon goes away.
pub struct StatusItem {
    model: Shared,
    changes: Sender<Change>,
    presence: Arc<Presence>,
}

impl std::fmt::Debug for StatusItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatusItem").finish_non_exhaustive()
    }
}

impl StatusItem {
    /// Starts the bus thread and returns at once. `on_input` runs on a bus
    /// thread and must not block.
    pub fn start(
        id: &str,
        title: &str,
        on_input: impl Fn(TrayInput) + Send + Sync + 'static,
    ) -> Self {
        let model = Shared::default();
        let (changes, received) = mpsc::channel();
        let presence = Arc::new(Presence::default());
        let item = Item {
            id: id.to_owned(),
            title: title.to_owned(),
            model: Arc::clone(&model),
            on_input: Arc::new(on_input),
        };
        let thread_presence = Arc::clone(&presence);
        let spawned = std::thread::Builder::new()
            .name("rosetun-tray".into())
            .spawn(move || {
                if let Err(error) = serve(item, &received, &thread_presence) {
                    thread_presence.host.store(false, Ordering::Relaxed);
                    thread_presence.set_absent(format!("the session bus failed: {error}"));
                }
            });
        if let Err(error) = spawned {
            presence.set_absent(format!("could not start the tray thread: {error}"));
        }
        Self {
            model,
            changes,
            presence,
        }
    }

    /// Whether a host shows the icon right now.
    pub fn has_host(&self) -> bool {
        self.presence.host.load(Ordering::Relaxed)
    }

    /// Why there is no icon, once that is known.
    pub fn absent_reason(&self) -> Option<String> {
        self.presence
            .absent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn set_icon(&self, icon: Vec<TrayPixmap>) {
        self.change(Change::Icon, |model| model.icon = icon);
    }

    pub fn set_tooltip(&self, title: &str, text: &str) {
        self.change(Change::Tooltip, |model| {
            title.clone_into(&mut model.tooltip_title);
            text.clone_into(&mut model.tooltip_text);
        });
    }

    pub fn set_menu(&self, menu: Vec<TrayEntry>) {
        self.change(Change::Menu, |model| {
            model.menu = menu;
            model.revision = model.revision.wrapping_add(1);
        });
    }

    fn change(&self, change: Change, apply: impl FnOnce(&mut Model)) {
        apply(&mut self.model.lock().unwrap_or_else(PoisonError::into_inner));
        // The thread is gone only when there is no bus, and then nobody is told.
        let _ = self.changes.send(change);
    }
}

impl Presence {
    fn set_absent(&self, reason: String) {
        *self.absent.lock().unwrap_or_else(PoisonError::into_inner) = Some(reason);
    }
}

fn serve(item: Item, changes: &Receiver<Change>, presence: &Presence) -> zbus::Result<()> {
    let name = format!("org.kde.StatusNotifierItem-{}-1", std::process::id());
    let menu = Menu {
        model: Arc::clone(&item.model),
        on_input: Arc::clone(&item.on_input),
    };
    let connection = Builder::session()?
        .name(name.as_str())?
        .serve_at(ITEM_PATH, item)?
        .serve_at(MENU_PATH, menu)?
        .build()?;
    let mut registered_with = None;
    loop {
        watch(&connection, &name, &mut registered_with, presence);
        let deadline = std::time::Instant::now() + WATCHER_CHECK;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match changes.recv_timeout(left) {
                Ok(change) => announce(&connection, &item_revision(change, &connection))?,
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
            }
        }
    }
}

/// Registers with a watcher this item has not met, and notes whether a host
/// is there. Trouble here is the same as no watcher: asked again later.
fn watch(
    connection: &Connection,
    name: &str,
    registered_with: &mut Option<String>,
    presence: &Presence,
) {
    let owner = connection
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "GetNameOwner",
            &WATCHER_NAME,
        )
        .ok()
        .and_then(|reply| reply.body().deserialize::<String>().ok());
    let Some(owner) = owner else {
        *registered_with = None;
        presence.host.store(false, Ordering::Relaxed);
        presence.set_absent(
            "nothing on this desktop shows tray icons (no StatusNotifierWatcher)".to_owned(),
        );
        return;
    };
    if registered_with.as_deref() != Some(owner.as_str()) {
        let registered = connection.call_method(
            Some(WATCHER_NAME),
            WATCHER_PATH,
            Some(WATCHER_NAME),
            "RegisterStatusNotifierItem",
            &name,
        );
        if registered.is_ok() {
            *registered_with = Some(owner);
        }
    }
    let host = registered_with.is_some() && host_registered(connection);
    presence.host.store(host, Ordering::Relaxed);
    if host {
        *presence
            .absent
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    } else {
        presence.set_absent(
            "nothing on this desktop shows tray icons (no StatusNotifierHost)".to_owned(),
        );
    }
}

fn host_registered(connection: &Connection) -> bool {
    connection
        .call_method(
            Some(WATCHER_NAME),
            WATCHER_PATH,
            Some(PROPERTIES_INTERFACE),
            "Get",
            &(WATCHER_NAME, "IsStatusNotifierHostRegistered"),
        )
        .ok()
        .and_then(|reply| reply.body().deserialize::<OwnedValue>().ok())
        .and_then(|value| bool::try_from(value).ok())
        .unwrap_or(false)
}

/// The signal a change takes, with the menu's revision where it needs one.
enum Signal {
    NewIcon,
    NewToolTip,
    LayoutUpdated(u32),
}

fn item_revision(change: Change, connection: &Connection) -> Signal {
    match change {
        Change::Icon => Signal::NewIcon,
        Change::Tooltip => Signal::NewToolTip,
        Change::Menu => {
            let revision = connection
                .object_server()
                .interface::<_, Menu>(MENU_PATH)
                .map_or(0, |menu| menu.get().revision());
            Signal::LayoutUpdated(revision)
        }
    }
}

fn announce(connection: &Connection, signal: &Signal) -> zbus::Result<()> {
    let none = None::<&str>;
    match signal {
        Signal::NewIcon => connection.emit_signal(none, ITEM_PATH, ITEM_INTERFACE, "NewIcon", &()),
        Signal::NewToolTip => {
            connection.emit_signal(none, ITEM_PATH, ITEM_INTERFACE, "NewToolTip", &())
        }
        Signal::LayoutUpdated(revision) => connection.emit_signal(
            none,
            MENU_PATH,
            MENU_INTERFACE,
            "LayoutUpdated",
            &(*revision, ROOT_ID),
        ),
    }
}

struct Item {
    id: String,
    title: String,
    model: Shared,
    on_input: InputHandler,
}

type DbusPixmap = (i32, i32, Vec<u8>);

fn lock(model: &Shared) -> std::sync::MutexGuard<'_, Model> {
    model.lock().unwrap_or_else(PoisonError::into_inner)
}

#[zbus::interface(name = "org.kde.StatusNotifierItem")]
impl Item {
    fn activate(&self, _x: i32, _y: i32) {
        (self.on_input)(TrayInput::Activate);
    }

    fn secondary_activate(&self, _x: i32, _y: i32) {}

    /// The host opens the menu from the `Menu` property by itself.
    fn context_menu(&self, _x: i32, _y: i32) {}

    fn scroll(&self, _delta: i32, _orientation: &str) {}

    /// Newer hosts offer this before `Activate`. The window is raised by
    /// opening it anew, which needs no token.
    fn provide_xdg_activation_token(&self, _token: &str) {}

    #[zbus(property)]
    fn category(&self) -> &str {
        "Communications"
    }

    #[zbus(property)]
    fn id(&self) -> &str {
        &self.id
    }

    #[zbus(property)]
    fn title(&self) -> &str {
        &self.title
    }

    #[zbus(property)]
    fn status(&self) -> &str {
        "Active"
    }

    #[zbus(property)]
    fn window_id(&self) -> i32 {
        0
    }

    #[zbus(property)]
    fn icon_name(&self) -> &str {
        ""
    }

    #[zbus(property)]
    fn icon_pixmap(&self) -> Vec<DbusPixmap> {
        dbus_pixmaps(&lock(&self.model).icon)
    }

    #[zbus(property)]
    fn overlay_icon_name(&self) -> &str {
        ""
    }

    #[zbus(property)]
    fn overlay_icon_pixmap(&self) -> Vec<DbusPixmap> {
        Vec::new()
    }

    #[zbus(property)]
    fn attention_icon_name(&self) -> &str {
        ""
    }

    #[zbus(property)]
    fn attention_icon_pixmap(&self) -> Vec<DbusPixmap> {
        Vec::new()
    }

    #[zbus(property)]
    fn attention_movie_name(&self) -> &str {
        ""
    }

    #[zbus(property)]
    fn tool_tip(&self) -> (String, Vec<DbusPixmap>, String, String) {
        let model = lock(&self.model);
        (
            String::new(),
            Vec::new(),
            model.tooltip_title.clone(),
            model.tooltip_text.clone(),
        )
    }

    #[zbus(property)]
    fn item_is_menu(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn menu(&self) -> ObjectPath<'static> {
        ObjectPath::from_static_str_unchecked(MENU_PATH)
    }
}

fn dbus_pixmaps(icon: &[TrayPixmap]) -> Vec<DbusPixmap> {
    icon.iter()
        .map(|pixmap| (pixmap.size, pixmap.size, pixmap.argb.clone()))
        .collect()
}

struct Menu {
    model: Shared,
    on_input: InputHandler,
}

impl Menu {
    fn revision(&self) -> u32 {
        lock(&self.model).revision
    }
}

#[zbus::interface(name = "com.canonical.dbusmenu")]
impl Menu {
    #[zbus(out_args("revision", "layout"))]
    fn get_layout(
        &self,
        parent_id: i32,
        recursion_depth: i32,
        _property_names: Vec<String>,
    ) -> zbus::fdo::Result<(u32, Layout)> {
        let model = lock(&self.model);
        let node = layout_of(&model.menu, parent_id, recursion_depth)
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs(format!("no menu item {parent_id}")))?;
        Ok((model.revision, node))
    }

    fn get_group_properties(
        &self,
        ids: Vec<i32>,
        _property_names: Vec<String>,
    ) -> Vec<(i32, HashMap<String, OwnedValue>)> {
        let model = lock(&self.model);
        ids.into_iter()
            .filter_map(|id| {
                let properties = if id == ROOT_ID {
                    root_properties()
                } else {
                    entry_properties(find_item(&model.menu, id)?)
                };
                Some((id, properties))
            })
            .collect()
    }

    fn get_property(&self, id: i32, name: &str) -> zbus::fdo::Result<OwnedValue> {
        let model = lock(&self.model);
        let properties = if id == ROOT_ID {
            root_properties()
        } else {
            find_item(&model.menu, id)
                .map(entry_properties)
                .ok_or_else(|| zbus::fdo::Error::InvalidArgs(format!("no menu item {id}")))?
        };
        properties
            .get(name)
            .and_then(|value| value.try_clone().ok())
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs(format!("no property {name}")))
    }

    fn event(&self, id: i32, event_id: &str, _data: OwnedValue, _timestamp: u32) {
        if event_id == "clicked" {
            (self.on_input)(TrayInput::Clicked(id));
        }
    }

    fn event_group(&self, events: Vec<(i32, String, OwnedValue, u32)>) -> Vec<i32> {
        for (id, event_id, _, _) in &events {
            if event_id == "clicked" {
                (self.on_input)(TrayInput::Clicked(*id));
            }
        }
        Vec::new()
    }

    /// The menu is always current, so opening it never needs a new layout.
    fn about_to_show(&self, _id: i32) -> bool {
        false
    }

    #[zbus(out_args("updates_needed", "id_errors"))]
    fn about_to_show_group(&self, _ids: Vec<i32>) -> (Vec<i32>, Vec<i32>) {
        (Vec::new(), Vec::new())
    }

    #[zbus(property)]
    fn version(&self) -> u32 {
        DBUSMENU_VERSION
    }

    #[zbus(property)]
    fn text_direction(&self) -> &str {
        "ltr"
    }

    #[zbus(property)]
    fn status(&self) -> &str {
        "normal"
    }

    #[zbus(property)]
    fn icon_theme_path(&self) -> Vec<String> {
        Vec::new()
    }
}

/// A separator has no ID of its own in the model, so it gets a stable one
/// from its place: negative, and never a real item's.
fn separator_id(place: usize, parent: i32) -> i32 {
    -1 - (parent.saturating_mul(100)).saturating_add(place as i32)
}

fn find_item(entries: &[TrayEntry], id: i32) -> Option<&TrayEntry> {
    find_entry(entries, id, ROOT_ID)
}

fn find_entry(entries: &[TrayEntry], id: i32, parent: i32) -> Option<&TrayEntry> {
    entries
        .iter()
        .enumerate()
        .find_map(|(place, entry)| match entry {
            TrayEntry::Separator => (separator_id(place, parent) == id).then_some(entry),
            TrayEntry::Item(item) if item.id == id => Some(entry),
            TrayEntry::Item(item) => find_entry(&item.children, id, item.id),
        })
}

fn root_properties() -> HashMap<String, OwnedValue> {
    HashMap::from([("children-display".to_owned(), owned(Str::from("submenu")))])
}

fn entry_properties(entry: &TrayEntry) -> HashMap<String, OwnedValue> {
    let mut properties = HashMap::new();
    match entry {
        TrayEntry::Separator => {
            properties.insert("type".to_owned(), owned(Str::from("separator")));
        }
        TrayEntry::Item(item) => {
            properties.insert("label".to_owned(), owned(Str::from(item.label.as_str())));
            properties.insert("enabled".to_owned(), owned(item.enabled));
            if let Some(checked) = item.checked {
                properties.insert("toggle-type".to_owned(), owned(Str::from("checkmark")));
                properties.insert("toggle-state".to_owned(), owned(i32::from(checked)));
            }
            if !item.children.is_empty() {
                properties.insert("children-display".to_owned(), owned(Str::from("submenu")));
            }
        }
    }
    properties
}

fn owned<'a>(value: impl Into<Value<'a>>) -> OwnedValue {
    value
        .into()
        .try_to_owned()
        .expect("a string, a number or a bool holds no file descriptor")
}

/// A dbusmenu layout node as the reply to `GetLayout`; deeper nodes travel
/// inside variants, as [`node`] builds them.
#[derive(Debug, serde::Serialize, Type)]
struct Layout(i32, HashMap<String, OwnedValue>, Vec<OwnedValue>);

/// `parent` and what is under it, as deep as `depth` says; -1 is everything.
/// `None` when no such item exists.
fn layout_of(entries: &[TrayEntry], parent: i32, depth: i32) -> Option<Layout> {
    if parent == ROOT_ID {
        return Some(Layout(
            ROOT_ID,
            root_properties(),
            child_nodes(ROOT_ID, entries, depth),
        ));
    }
    let entry = find_item(entries, parent)?;
    let children: &[TrayEntry] = match entry {
        TrayEntry::Item(item) => &item.children,
        TrayEntry::Separator => &[],
    };
    Some(Layout(
        parent,
        entry_properties(entry),
        child_nodes(parent, children, depth),
    ))
}

fn child_nodes(parent: i32, children: &[TrayEntry], depth: i32) -> Vec<OwnedValue> {
    if depth == 0 {
        return Vec::new();
    }
    children
        .iter()
        .enumerate()
        .map(|(place, entry)| {
            let (id, grandchildren): (i32, &[TrayEntry]) = match entry {
                TrayEntry::Separator => (separator_id(place, parent), &[]),
                TrayEntry::Item(item) => (item.id, &item.children),
            };
            owned(node(id, entry_properties(entry), grandchildren, depth - 1))
        })
        .collect()
}

fn node(
    id: i32,
    properties: HashMap<String, OwnedValue>,
    children: &[TrayEntry],
    depth: i32,
) -> Structure<'static> {
    StructureBuilder::new()
        .add_field(id)
        .add_field(properties)
        .add_field(child_nodes(id, children, depth))
        .build()
        .expect("a menu node has fields")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: i32, label: &str) -> TrayItem {
        TrayItem {
            id,
            label: label.to_owned(),
            enabled: true,
            ..TrayItem::default()
        }
    }

    fn menu() -> Vec<TrayEntry> {
        vec![
            TrayEntry::Item(item(1, "Status")),
            TrayEntry::Separator,
            TrayEntry::Item(TrayItem {
                children: vec![
                    TrayEntry::Item(TrayItem {
                        checked: Some(true),
                        ..item(3, "Server")
                    }),
                    TrayEntry::Separator,
                    TrayEntry::Item(item(4, "All")),
                ],
                ..item(2, "Servers")
            }),
        ]
    }

    #[test]
    fn pixels_go_to_the_bus_as_argb_in_network_order() {
        let pixmap = TrayPixmap::from_rgba(1, &[1, 2, 3, 4]);
        assert_eq!(pixmap.argb, [4, 1, 2, 3]);
    }

    #[test]
    fn a_layout_has_the_type_the_protocol_names() {
        assert_eq!(Layout::SIGNATURE.to_string(), "(ia{sv}av)");
        let child = node(5, HashMap::new(), &[], 0);
        assert_eq!(
            Value::Structure(child).value_signature().to_string(),
            "(ia{sv}av)"
        );
    }

    #[test]
    fn separators_have_ids_of_their_own_at_every_level() {
        let menu = menu();
        let top = separator_id(1, ROOT_ID);
        let nested = separator_id(1, 2);
        assert_ne!(top, nested);
        assert_eq!(find_item(&menu, top), Some(&TrayEntry::Separator));
        assert_eq!(find_item(&menu, nested), Some(&TrayEntry::Separator));
        assert!(top < 0 && nested < 0);
    }

    #[test]
    fn an_item_is_found_under_its_parent_and_an_unknown_one_is_not() {
        let menu = menu();
        assert!(matches!(
            find_item(&menu, 4),
            Some(TrayEntry::Item(found)) if found.label == "All"
        ));
        assert_eq!(find_item(&menu, 99), None);
        assert!(layout_of(&menu, 99, -1).is_none());
    }

    #[test]
    fn a_checked_item_says_so_and_a_parent_shows_a_submenu() {
        let menu = menu();
        let server = entry_properties(find_item(&menu, 3).unwrap());
        assert_eq!(i32::try_from(&server["toggle-state"]).unwrap(), 1);
        assert_eq!(
            <&str>::try_from(&server["toggle-type"]).unwrap(),
            "checkmark"
        );
        let servers = entry_properties(find_item(&menu, 2).unwrap());
        assert_eq!(
            <&str>::try_from(&servers["children-display"]).unwrap(),
            "submenu"
        );
        let plain = entry_properties(find_item(&menu, 1).unwrap());
        assert!(!plain.contains_key("toggle-type"));
        assert!(!plain.contains_key("children-display"));
    }

    /// A fake watcher and a real bus. `dbus-run-session -- cargo test -p
    /// rosetun-shell -- --ignored` runs it; CI has no session bus.
    #[test]
    #[ignore = "needs a session bus"]
    fn an_item_registers_answers_the_host_and_reports_clicks() {
        struct Watcher {
            items: Arc<Mutex<Vec<String>>>,
        }

        #[zbus::interface(name = "org.kde.StatusNotifierWatcher")]
        impl Watcher {
            fn register_status_notifier_item(&self, service: String) {
                self.items.lock().unwrap().push(service);
            }

            #[zbus(property)]
            fn is_status_notifier_host_registered(&self) -> bool {
                true
            }
        }

        let items = Arc::new(Mutex::new(Vec::new()));
        let host = Builder::session()
            .unwrap()
            .name(WATCHER_NAME)
            .unwrap()
            .serve_at(
                WATCHER_PATH,
                Watcher {
                    items: Arc::clone(&items),
                },
            )
            .unwrap()
            .build()
            .unwrap();
        let (clicks, clicked) = mpsc::channel();
        let status = StatusItem::start("rosetun", "Rosetun", move |input| {
            clicks.send(input).unwrap();
        });
        status.set_menu(menu());
        status.set_icon(vec![TrayPixmap::from_rgba(1, &[1, 2, 3, 4])]);
        status.set_tooltip("Rosetun", "Connected");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !status.has_host() {
            assert!(std::time::Instant::now() < deadline, "no registration");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(status.absent_reason(), None);
        let service = items.lock().unwrap()[0].clone();
        assert!(service.starts_with("org.kde.StatusNotifierItem-"));

        // Through another client: zbus's own signature text cannot tell two
        // reply values from one structure holding them, and a host can.
        let layout = std::process::Command::new("dbus-send")
            .args([
                "--session",
                "--print-reply",
                &format!("--dest={service}"),
                MENU_PATH,
                "com.canonical.dbusmenu.GetLayout",
                "int32:0",
                "int32:-1",
                "array:string:",
            ])
            .output()
            .unwrap();
        let layout = String::from_utf8(layout.stdout).unwrap();
        let mut replies = layout.lines().skip(1);
        assert!(
            replies.next().unwrap().trim().starts_with("uint32"),
            "{layout}"
        );
        assert_eq!(replies.next().unwrap().trim(), "struct {", "{layout}");
        assert!(layout.contains("string \"Servers\""), "{layout}");
        assert!(layout.contains("string \"All\""), "{layout}");

        let property = |path: &str, interface: &str, name: &str| {
            let reply = host
                .call_method(
                    Some(service.as_str()),
                    path,
                    Some(PROPERTIES_INTERFACE),
                    "Get",
                    &(interface, name),
                )
                .unwrap();
            reply.body().deserialize::<OwnedValue>().unwrap()
        };
        assert_eq!(
            property(ITEM_PATH, ITEM_INTERFACE, "IconPixmap")
                .value_signature()
                .to_string(),
            "a(iiay)"
        );
        assert_eq!(
            property(ITEM_PATH, ITEM_INTERFACE, "ToolTip")
                .value_signature()
                .to_string(),
            "(sa(iiay)ss)"
        );
        assert_eq!(
            u32::try_from(property(MENU_PATH, MENU_INTERFACE, "Version")).unwrap(),
            DBUSMENU_VERSION
        );

        host.call_method(
            Some(service.as_str()),
            ITEM_PATH,
            Some(ITEM_INTERFACE),
            "Activate",
            &(0, 0),
        )
        .unwrap();
        assert_eq!(
            clicked.recv_timeout(Duration::from_secs(5)).unwrap(),
            TrayInput::Activate
        );
        host.call_method(
            Some(service.as_str()),
            MENU_PATH,
            Some(MENU_INTERFACE),
            "Event",
            &(4, "clicked", Value::from(""), 0u32),
        )
        .unwrap();
        assert_eq!(
            clicked.recv_timeout(Duration::from_secs(5)).unwrap(),
            TrayInput::Clicked(4)
        );
    }
}
