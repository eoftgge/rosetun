use std::fs;
use std::path::PathBuf;

use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use rosetun_shell::SavedWindow;

/// Remembers the main window between runs in `window.json` next to the config.
#[derive(Debug)]
pub(crate) struct WindowMemory {
    hwnd: isize,
    file: PathBuf,
    /// A hidden start keeps the window off every screen until it is first
    /// shown; that position must never be saved.
    shown: bool,
}

impl WindowMemory {
    /// `None` when the window has no Win32 handle.
    pub(crate) fn new(cc: &eframe::CreationContext<'_>, file: PathBuf) -> Option<Self> {
        let hwnd = match cc.window_handle() {
            Ok(window) => match window.as_raw() {
                RawWindowHandle::Win32(handle) => handle.hwnd.get(),
                _ => {
                    tracing::warn!("Main window does not have a Win32 handle");
                    return None;
                }
            },
            Err(error) => {
                tracing::warn!(%error, "Could not get the main window handle");
                return None;
            }
        };
        Some(Self {
            hwnd,
            file,
            shown: false,
        })
    }

    /// Places the window and returns whether it should be maximized.
    pub(crate) fn place(&mut self) -> bool {
        let saved = match fs::read(&self.file) {
            Ok(bytes) => match serde_json::from_slice::<SavedWindow>(&bytes) {
                Ok(saved) if saved.is_valid() => Some(saved),
                Ok(_) => {
                    tracing::warn!("Saved window placement has invalid dimensions");
                    None
                }
                Err(error) => {
                    tracing::warn!(%error, "Could not parse saved window placement");
                    None
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                tracing::warn!(%error, "Could not read saved window placement");
                None
            }
        };
        if let Err(error) = rosetun_shell::place_window(self.hwnd, saved) {
            tracing::warn!(%error, "Could not place the main window");
        }
        self.shown = true;
        saved.is_some_and(|window| window.maximized)
    }

    pub(crate) fn save(&self) {
        if !self.shown {
            return;
        }
        let Some(saved) = rosetun_shell::saved_window(self.hwnd) else {
            tracing::warn!("Could not read the main window placement");
            return;
        };
        if !saved.is_valid() {
            tracing::warn!("Main window placement has invalid dimensions");
            return;
        }
        let bytes = match serde_json::to_vec(&saved) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(%error, "Could not serialize the main window placement");
                return;
            }
        };
        let temporary = self.file.with_extension("json.tmp");
        if let Err(error) =
            fs::write(&temporary, bytes).and_then(|()| fs::rename(&temporary, &self.file))
        {
            tracing::warn!(%error, "Could not save the main window placement");
        }
    }
}

#[cfg(test)]
mod tests {
    use rosetun_shell::SavedWindow;

    #[test]
    fn saved_window_round_trips_through_json() {
        let saved = SavedWindow {
            left: -1650,
            top: 100,
            right: -450,
            bottom: 900,
            maximized: true,
        };
        let bytes = serde_json::to_vec(&saved).expect("serialize saved window");
        let restored = serde_json::from_slice::<SavedWindow>(&bytes).expect("parse saved window");
        assert_eq!(restored, saved);
    }
}
