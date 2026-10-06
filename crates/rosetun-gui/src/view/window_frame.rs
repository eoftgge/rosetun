use eframe::egui::{
    self, CursorIcon, Id, PointerButton, Rect, ResizeDirection, Sense, ViewportCommand,
};

use super::header::CUSTOM_FRAME;

const EDGE: f32 = 6.0;
const CORNER: f32 = 12.0;

/// Grab areas along the window border; corners come last so they win where they overlap edges.
fn grab_areas(window: Rect) -> [(Rect, ResizeDirection); 8] {
    let min = window.min;
    let max = window.max;
    let area = |left: f32, top: f32, right: f32, bottom: f32| {
        Rect::from_min_max(egui::pos2(left, top), egui::pos2(right, bottom))
    };
    [
        (
            area(min.x, min.y, min.x + EDGE, max.y),
            ResizeDirection::West,
        ),
        (
            area(max.x - EDGE, min.y, max.x, max.y),
            ResizeDirection::East,
        ),
        (
            area(min.x, min.y, max.x, min.y + EDGE),
            ResizeDirection::North,
        ),
        (
            area(min.x, max.y - EDGE, max.x, max.y),
            ResizeDirection::South,
        ),
        (
            area(min.x, min.y, min.x + CORNER, min.y + CORNER),
            ResizeDirection::NorthWest,
        ),
        (
            area(max.x - CORNER, min.y, max.x, min.y + CORNER),
            ResizeDirection::NorthEast,
        ),
        (
            area(min.x, max.y - CORNER, min.x + CORNER, max.y),
            ResizeDirection::SouthWest,
        ),
        (
            area(max.x - CORNER, max.y - CORNER, max.x, max.y),
            ResizeDirection::SouthEast,
        ),
    ]
}

pub(crate) fn resize_edges(ui: &mut egui::Ui) {
    if !CUSTOM_FRAME || ui.input(|input| input.viewport().maximized.unwrap_or(false)) {
        return;
    }
    for (index, (rect, direction)) in grab_areas(ui.max_rect()).into_iter().enumerate() {
        let response = ui.interact(rect, Id::new(("window_resize", index)), Sense::drag());
        if response.hovered() {
            let cursor = match direction {
                ResizeDirection::North => CursorIcon::ResizeNorth,
                ResizeDirection::South => CursorIcon::ResizeSouth,
                ResizeDirection::East => CursorIcon::ResizeEast,
                ResizeDirection::West => CursorIcon::ResizeWest,
                ResizeDirection::NorthEast => CursorIcon::ResizeNorthEast,
                ResizeDirection::NorthWest => CursorIcon::ResizeNorthWest,
                ResizeDirection::SouthEast => CursorIcon::ResizeSouthEast,
                ResizeDirection::SouthWest => CursorIcon::ResizeSouthWest,
            };
            ui.ctx().set_cursor_icon(cursor);
        }
        if response.drag_started_by(PointerButton::Primary) {
            ui.ctx()
                .send_viewport_cmd(ViewportCommand::BeginResize(direction));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CORNER, EDGE, grab_areas};
    use eframe::egui::{self, Rect, ResizeDirection};

    #[test]
    fn grab_areas_cover_edges_and_prioritize_corners() {
        let window = Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1200.0, 780.0));
        let areas = grab_areas(window);

        assert_eq!(areas.len(), 8);
        for (rect, _) in areas {
            assert!(rect.min.x >= window.min.x && rect.min.y >= window.min.y);
            assert!(rect.max.x <= window.max.x && rect.max.y <= window.max.y);
        }
        assert!(matches!(areas[0].1, ResizeDirection::West));
        assert_eq!(
            areas[0].0,
            Rect::from_min_max(window.min, egui::pos2(EDGE, 780.0))
        );
        assert!(areas[4..].iter().all(|(_, direction)| matches!(
            direction,
            ResizeDirection::NorthWest
                | ResizeDirection::NorthEast
                | ResizeDirection::SouthWest
                | ResizeDirection::SouthEast
        )));
        assert!(matches!(areas[7].1, ResizeDirection::SouthEast));
        assert_eq!(
            areas[7].0,
            Rect::from_min_max(egui::pos2(1200.0 - CORNER, 780.0 - CORNER), window.max)
        );
    }
}
