//! Programs' own icons on the Traffic and Rules screens.
//!
//! One background thread reads them in request order; a row asks only while
//! it is on screen and draws its tile until the icon is ready. Neither the
//! paths nor the icons are logged: together they are the user's history.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};

use eframe::egui;
use eframe::egui::emath::GuiRounding as _;

/// Icons kept at once; the least recently shown goes first.
const MAX_ICONS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct IconKey {
    /// Lowercase, as Windows compares paths.
    path: String,
    /// A new interface scale is a new key, so icons are read again sharp.
    size_px: u32,
}

impl IconKey {
    pub(crate) fn new(path: &Path, size_px: u32) -> Self {
        Self {
            path: path.to_string_lossy().to_lowercase(),
            size_px,
        }
    }
}

enum Entry<T> {
    Loading,
    Ready(T),
    Missing,
}

struct Slot<T> {
    entry: Entry<T>,
    used: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Lookup<'a, T> {
    Ready(&'a T),
    /// Loading or no icon: the caller draws its tile.
    Tile,
    /// Not asked for yet: the caller queues it and draws its tile.
    Queue,
}

/// Path and size → icon state, at most [`MAX_ICONS`] entries.
pub(crate) struct IconCache<T> {
    slots: HashMap<IconKey, Slot<T>>,
    clock: u64,
}

impl<T> Default for IconCache<T> {
    fn default() -> Self {
        Self {
            slots: HashMap::new(),
            clock: 0,
        }
    }
}

impl<T> IconCache<T> {
    pub(crate) fn lookup(&mut self, key: &IconKey) -> Lookup<'_, T> {
        self.clock += 1;
        if !self.slots.contains_key(key) {
            if self.slots.len() >= MAX_ICONS
                && let Some(oldest) = self
                    .slots
                    .iter()
                    .min_by_key(|(_, slot)| slot.used)
                    .map(|(key, _)| key.clone())
            {
                self.slots.remove(&oldest);
            }
            self.slots.insert(
                key.clone(),
                Slot {
                    entry: Entry::Loading,
                    used: self.clock,
                },
            );
            return Lookup::Queue;
        }
        let slot = self.slots.get_mut(key).expect("checked above");
        slot.used = self.clock;
        match &slot.entry {
            Entry::Ready(icon) => Lookup::Ready(icon),
            Entry::Loading | Entry::Missing => Lookup::Tile,
        }
    }

    /// An answer for an entry evicted meanwhile is dropped.
    pub(crate) fn finish(&mut self, key: &IconKey, icon: Option<T>) {
        if let Some(slot) = self.slots.get_mut(key) {
            slot.entry = icon.map_or(Entry::Missing, Entry::Ready);
        }
    }
}

struct Loader {
    requests: Sender<(IconKey, PathBuf)>,
    results: Receiver<(IconKey, Option<egui::ColorImage>)>,
}

impl Loader {
    fn spawn(ctx: egui::Context) -> Option<Self> {
        let (requests, queue) = mpsc::channel::<(IconKey, PathBuf)>();
        let (answers, results) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("rosetun-program-icons".to_owned())
            .spawn(move || {
                #[cfg(windows)]
                let apartment = rosetun_shell::ComApartment::enter();
                for (key, path) in queue {
                    #[cfg(windows)]
                    let image = apartment
                        .as_ref()
                        .and_then(|_| rosetun_shell::program_icon(&path, key.size_px))
                        .map(|icon| {
                            egui::ColorImage::from_rgba_unmultiplied(
                                [icon.width as usize, icon.height as usize],
                                &icon.rgba,
                            )
                        });
                    #[cfg(not(windows))]
                    let image = {
                        let _ = path;
                        None
                    };
                    if answers.send((key, image)).is_err() {
                        break;
                    }
                    ctx.request_repaint();
                }
            });
        match spawned {
            Ok(_) => Some(Self { requests, results }),
            Err(error) => {
                tracing::warn!(%error, "program icon reader did not start");
                None
            }
        }
    }
}

#[derive(Default)]
struct ProgramIcons {
    cache: IconCache<egui::TextureHandle>,
    loader: Option<Loader>,
    /// The thread could not start; every program keeps its tile.
    failed: bool,
}

impl ProgramIcons {
    fn receive(&mut self, ctx: &egui::Context) {
        let Some(loader) = &self.loader else {
            return;
        };
        while let Ok((key, image)) = loader.results.try_recv() {
            let texture = image
                .map(|image| ctx.load_texture("program-icon", image, egui::TextureOptions::LINEAR));
            self.cache.finish(&key, texture);
        }
    }

    fn request(&mut self, ctx: &egui::Context, key: IconKey, path: &Path) {
        if self.loader.is_none() && !self.failed {
            self.loader = Loader::spawn(ctx.clone());
            self.failed = self.loader.is_none();
        }
        let sent = self
            .loader
            .as_ref()
            .is_some_and(|loader| loader.requests.send((key.clone(), path.to_owned())).is_ok());
        if !sent {
            self.cache.finish(&key, None);
        }
    }
}

/// Paints `path`'s icon `side` points square, centred in `rect`. `false`
/// while there is none, so the caller paints its tile instead.
pub(crate) fn paint(ui: &egui::Ui, rect: egui::Rect, side: f32, path: &Path) -> bool {
    if !ui.is_rect_visible(rect) {
        return false;
    }
    let ctx = ui.ctx();
    let pixels_per_point = ctx.pixels_per_point();
    let size_px = (side * pixels_per_point).round() as u32;
    if size_px == 0 {
        return false;
    }
    let icons = ctx.data_mut(|data| {
        data.get_temp_mut_or_default::<Arc<Mutex<ProgramIcons>>>(egui::Id::new("program_icons"))
            .clone()
    });
    let mut icons = icons.lock().unwrap_or_else(PoisonError::into_inner);
    icons.receive(ctx);
    let key = IconKey::new(path, size_px);
    let texture = match icons.cache.lookup(&key) {
        Lookup::Ready(texture) => texture.clone(),
        Lookup::Tile => return false,
        Lookup::Queue => {
            icons.request(ctx, key, path);
            return false;
        }
    };
    drop(icons);
    // Whole physical pixels, or the linear filter blurs the icon.
    let size = texture.size_vec2() / pixels_per_point;
    let min = (rect.center() - size / 2.0).round_to_pixels(pixels_per_point);
    ui.painter().image(
        texture.id(),
        egui::Rect::from_min_size(min, size),
        egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
        egui::Color32::WHITE,
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(path: &str, size_px: u32) -> IconKey {
        IconKey::new(Path::new(path), size_px)
    }

    #[test]
    fn a_path_is_queued_once_whatever_its_case() {
        let mut cache = IconCache::<u8>::default();
        assert_eq!(
            cache.lookup(&key(r"C:\Apps\Example.exe", 20)),
            Lookup::Queue
        );
        assert_eq!(cache.lookup(&key(r"c:\apps\example.EXE", 20)), Lookup::Tile);
        cache.finish(&key(r"C:\Apps\Example.exe", 20), Some(7));
        assert_eq!(
            cache.lookup(&key(r"C:\Apps\Example.exe", 20)),
            Lookup::Ready(&7)
        );
    }

    #[test]
    fn a_missing_icon_is_asked_again_only_at_another_scale() {
        let mut cache = IconCache::<u8>::default();
        let at_100 = key(r"C:\Apps\example.exe", 20);
        assert_eq!(cache.lookup(&at_100), Lookup::Queue);
        cache.finish(&at_100, None);
        assert_eq!(cache.lookup(&at_100), Lookup::Tile);
        assert_eq!(cache.lookup(&at_100), Lookup::Tile);
        assert_eq!(
            cache.lookup(&key(r"C:\Apps\example.exe", 30)),
            Lookup::Queue
        );
    }

    #[test]
    fn the_least_recently_shown_icon_is_evicted_first() {
        let mut cache = IconCache::<u8>::default();
        let paths: Vec<_> = (0..MAX_ICONS)
            .map(|n| key(&format!(r"C:\Apps\app{n}.exe"), 20))
            .collect();
        for path in &paths {
            assert_eq!(cache.lookup(path), Lookup::Queue);
            cache.finish(path, Some(1));
        }
        assert_eq!(cache.lookup(&paths[0]), Lookup::Ready(&1));
        assert_eq!(cache.lookup(&key(r"C:\Apps\new.exe", 20)), Lookup::Queue);
        assert_eq!(cache.slots.len(), MAX_ICONS);
        assert_eq!(cache.lookup(&paths[0]), Lookup::Ready(&1));
        assert_eq!(cache.lookup(&paths[1]), Lookup::Queue);
    }

    #[test]
    fn an_answer_for_an_evicted_icon_is_dropped() {
        let mut cache = IconCache::<u8>::default();
        cache.finish(&key(r"C:\Apps\example.exe", 20), Some(1));
        assert!(cache.slots.is_empty());
    }
}
