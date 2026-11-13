//! The main window between runs on Linux: its size and whether it is maximized, in
//! `window.json` next to the settings, and on X11 its position too.
//!
//! Wayland lets a program choose a window's size and state but not where it goes: the
//! compositor places it, and a request to move it is ignored. So nothing is saved or
//! asked for there beyond the size. On X11 a saved position is kept only when the
//! window's title strip still lies on a monitor, so a window never comes back on a
//! screen that is gone.

use std::fs;
use std::path::Path;

use eframe::egui;
use serde_json::{Value, json};

use crate::app::host::WindowShape;

/// Far beyond any screen; a number past this is a damaged file.
const MAX_SIDE: f32 = 20_000.0;
/// How far below the window's top edge the strip that has to be on a monitor lies, in
/// physical pixels: where the title bar is.
const TITLE_STRIP: i64 = 16;

/// A monitor in physical pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Monitor {
    pub(crate) x: i32,
    pub(crate) y: i32,
    pub(crate) width: u32,
    pub(crate) height: u32,
}

/// The shape of the last run. `wayland` drops the position; `monitors` is asked only
/// when there is a position to check, and `None` from it (no X server to ask) drops it.
pub(crate) fn load(
    file: &Path,
    wayland: bool,
    monitors: impl FnOnce() -> Option<Vec<Monitor>>,
) -> Option<WindowShape> {
    let text = match fs::read_to_string(file) {
        Ok(text) => text,
        Err(error) => {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(%error, "could not read the saved window shape");
            }
            return None;
        }
    };
    let Some(mut shape) = parse(&text) else {
        tracing::warn!("the saved window shape is not usable");
        return None;
    };
    if let Some(position) = shape.position {
        let size = shape.size.unwrap_or(egui::Vec2::ZERO);
        let kept = !wayland
            && monitors()
                .is_some_and(|monitors| on_a_monitor(position, size, shape.scale, &monitors));
        if !kept {
            shape.position = None;
        }
    }
    Some(shape)
}

fn parse(text: &str) -> Option<WindowShape> {
    let value: Value = serde_json::from_str(text).ok()?;
    let number = |key: &str| value.get(key).and_then(Value::as_f64).map(|n| n as f32);
    let (width, height) = (number("width")?, number("height")?);
    let side_ok = |side: f32| side.is_finite() && (1.0..=MAX_SIDE).contains(&side);
    if !side_ok(width) || !side_ok(height) {
        return None;
    }
    let scale = number("scale")
        .filter(|scale| scale.is_finite() && (0.25..=16.0).contains(scale))
        .unwrap_or(1.0);
    let position = match (number("x"), number("y")) {
        (Some(x), Some(y)) if x.is_finite() && y.is_finite() => Some(egui::pos2(x, y)),
        _ => None,
    };
    Some(WindowShape {
        size: Some(egui::vec2(width, height)),
        maximized: value
            .get("maximized")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        position,
        scale,
    })
}

/// Writes the shape, replacing the file whole or not at all.
pub(crate) fn save(file: &Path, shape: &WindowShape) {
    let Some(size) = shape.size else {
        return;
    };
    let mut value = json!({
        "width": size.x,
        "height": size.y,
        "maximized": shape.maximized,
        "scale": shape.scale,
    });
    if let Some(position) = shape.position {
        value["x"] = json!(position.x);
        value["y"] = json!(position.y);
    }
    let temporary = file.with_extension("json.tmp");
    if let Err(error) =
        fs::write(&temporary, value.to_string()).and_then(|()| fs::rename(&temporary, file))
    {
        tracing::warn!(%error, "could not save the window shape");
    }
}

/// The shape after the window was looked at. A maximized window keeps the size and place
/// it had before, which is what comes back when it is restored. Wayland has no place.
pub(crate) fn observed(
    previous: WindowShape,
    size: Option<egui::Vec2>,
    position: Option<egui::Pos2>,
    maximized: bool,
    scale: f32,
    wayland: bool,
) -> WindowShape {
    let position = if wayland { None } else { position };
    if maximized && previous.size.is_some() {
        return WindowShape {
            maximized,
            scale: previous.scale,
            ..previous
        };
    }
    WindowShape {
        size,
        maximized,
        position,
        scale,
    }
}

/// Whether the strip under the window's top edge lies on one of the monitors.
fn on_a_monitor(position: egui::Pos2, size: egui::Vec2, scale: f32, monitors: &[Monitor]) -> bool {
    let scale = f64::from(scale);
    let centre = (
        ((f64::from(position.x) + f64::from(size.x) / 2.0) * scale).round() as i64,
        (f64::from(position.y) * scale).round() as i64 + TITLE_STRIP,
    );
    monitors.iter().any(|monitor| {
        let (left, top) = (i64::from(monitor.x), i64::from(monitor.y));
        let (right, bottom) = (
            left + i64::from(monitor.width),
            top + i64::from(monitor.height),
        );
        (left..right).contains(&centre.0) && (top..bottom).contains(&centre.1)
    })
}

/// The monitors the X server knows, or `None` without a connection to it.
pub(crate) fn x11_monitors() -> Option<Vec<Monitor>> {
    use x11rb::connection::Connection;
    use x11rb::protocol::randr::ConnectionExt;

    let (connection, screen) = x11rb::rust_connection::RustConnection::connect(None).ok()?;
    let root = connection.setup().roots.get(screen)?.root;
    let reply = connection
        .randr_get_monitors(root, true)
        .ok()?
        .reply()
        .ok()?;
    Some(
        reply
            .monitors
            .iter()
            .map(|monitor| Monitor {
                x: i32::from(monitor.x),
                y: i32::from(monitor.y),
                width: u32::from(monitor.width),
                height: u32::from(monitor.height),
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rosetun-shape-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.join("window.json")
    }

    const SCREEN: Monitor = Monitor {
        x: 0,
        y: 0,
        width: 1920,
        height: 1080,
    };
    const SECOND: Monitor = Monitor {
        x: 1920,
        y: 0,
        width: 2560,
        height: 1440,
    };

    fn shape() -> WindowShape {
        WindowShape {
            size: Some(egui::vec2(1100.0, 760.0)),
            maximized: false,
            position: Some(egui::pos2(300.0, 120.0)),
            scale: 1.0,
        }
    }

    #[test]
    fn a_saved_shape_comes_back() {
        let file = temp("round");
        save(&file, &shape());
        assert_eq!(load(&file, false, || Some(vec![SCREEN])), Some(shape()));
        fs::remove_dir_all(file.parent().unwrap()).unwrap();
    }

    #[test]
    fn wayland_keeps_the_size_and_not_the_place() {
        let file = temp("wayland");
        save(&file, &shape());
        let loaded = load(&file, true, || panic!("Wayland asks no monitors")).unwrap();
        assert_eq!(loaded.size, shape().size);
        assert_eq!(loaded.position, None);
        fs::remove_dir_all(file.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_place_on_a_monitor_that_is_gone_is_dropped() {
        let file = temp("gone");
        let mut far = shape();
        far.position = Some(egui::pos2(2500.0, 100.0));
        save(&file, &far);
        let loaded = load(&file, false, || Some(vec![SCREEN])).unwrap();
        assert_eq!(loaded.position, None);
        assert_eq!(loaded.size, far.size);
        let there = load(&file, false, || Some(vec![SCREEN, SECOND])).unwrap();
        assert_eq!(there.position, far.position);
        let unknown = load(&file, false, || None).unwrap();
        assert_eq!(unknown.position, None);
        fs::remove_dir_all(file.parent().unwrap()).unwrap();
    }

    #[test]
    fn the_title_strip_decides_not_the_corner() {
        let size = egui::vec2(1000.0, 700.0);
        // Half of the window hangs off the screen's left edge; its middle is on.
        assert!(on_a_monitor(egui::pos2(-300.0, 50.0), size, 1.0, &[SCREEN]));
        // Only its bottom corner is on the screen.
        assert!(!on_a_monitor(
            egui::pos2(-1100.0, 50.0),
            size,
            1.0,
            &[SCREEN]
        ));
        // Scaled: 1000 points at 2.0 are 2000 pixels.
        assert!(!on_a_monitor(
            egui::pos2(1000.0, 10.0),
            size,
            2.0,
            &[SCREEN]
        ));
        assert!(on_a_monitor(egui::pos2(100.0, 10.0), size, 2.0, &[SCREEN]));
    }

    #[test]
    fn a_damaged_file_gives_nothing() {
        for text in [
            "",
            "[]",
            "{}",
            r#"{"width":-5,"height":700}"#,
            r#"{"width":1e30,"height":700}"#,
            r#"{"width":"wide","height":700}"#,
        ] {
            assert_eq!(parse(text), None, "{text}");
        }
        let ok = parse(r#"{"width":1000,"height":700}"#).unwrap();
        assert!(!ok.maximized);
        assert_eq!(ok.position, None);
        assert!((ok.scale - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn a_maximized_window_keeps_the_size_it_will_return_to() {
        let kept = observed(
            shape(),
            Some(egui::vec2(1920.0, 1080.0)),
            Some(egui::pos2(0.0, 0.0)),
            true,
            1.0,
            false,
        );
        assert!(kept.maximized);
        assert_eq!(kept.size, shape().size);
        assert_eq!(kept.position, shape().position);
        let first = observed(
            WindowShape {
                size: None,
                maximized: false,
                position: None,
                scale: 1.0,
            },
            Some(egui::vec2(1920.0, 1080.0)),
            None,
            true,
            1.0,
            false,
        );
        assert_eq!(first.size, Some(egui::vec2(1920.0, 1080.0)));
    }

    #[test]
    fn wayland_never_records_a_place() {
        let seen = observed(
            shape(),
            Some(egui::vec2(900.0, 700.0)),
            Some(egui::pos2(10.0, 10.0)),
            false,
            1.0,
            true,
        );
        assert_eq!(seen.position, None);
        assert_eq!(seen.size, Some(egui::vec2(900.0, 700.0)));
    }
}
