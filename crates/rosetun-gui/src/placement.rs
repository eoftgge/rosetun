use eframe::egui;

/// Share of the work area that the window takes at start, on each axis.
const SHARE: f32 = 0.75;
/// On ultra-wide monitors the window is never wider than this many heights.
const MAX_ASPECT: f32 = 2.0;
/// The smallest window the layout fits in.
const MIN_SIZE: egui::Vec2 = egui::vec2(960.0, 640.0);
/// The size when the work area is unknown.
const FALLBACK_SIZE: egui::Vec2 = egui::vec2(1200.0, 780.0);

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Placement {
    pub(crate) size: egui::Vec2,
    pub(crate) min_size: egui::Vec2,
    /// The top-left corner; `None` leaves it to the system.
    pub(crate) position: Option<egui::Pos2>,
}

impl Placement {
    /// A share of the work area, centred in it.
    #[cfg_attr(not(any(test, windows)), allow(dead_code))]
    pub(crate) fn in_work_area(area: egui::Rect) -> Self {
        let min_size = MIN_SIZE.min(area.size());
        let width = area.width() * SHARE;
        let height = area.height() * SHARE;
        let width = width.min(height * MAX_ASPECT);
        let size = egui::vec2(width, height).max(min_size).floor();
        let position = (area.min + (area.size() - size) / 2.0).floor();
        Self {
            size,
            min_size,
            position: Some(position),
        }
    }

    /// The fixed size where the system puts it.
    pub(crate) fn fallback() -> Self {
        Self {
            size: FALLBACK_SIZE,
            min_size: MIN_SIZE,
            position: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Placement;
    use eframe::egui;

    #[test]
    fn places_window_within_work_area() {
        for (origin, area_size, expected_size, expected_position) in [
            (
                egui::pos2(0.0, 0.0),
                egui::vec2(1920.0, 1032.0),
                egui::vec2(1440.0, 774.0),
                egui::pos2(240.0, 129.0),
            ),
            (
                egui::pos2(0.0, 0.0),
                egui::vec2(1536.0, 816.0),
                egui::vec2(1152.0, 640.0),
                egui::pos2(192.0, 88.0),
            ),
            (
                egui::pos2(0.0, 0.0),
                egui::vec2(1280.0, 672.0),
                egui::vec2(960.0, 640.0),
                egui::pos2(160.0, 16.0),
            ),
            (
                egui::pos2(0.0, 0.0),
                egui::vec2(3440.0, 1392.0),
                egui::vec2(2088.0, 1044.0),
                egui::pos2(676.0, 174.0),
            ),
            (
                egui::pos2(48.0, 0.0),
                egui::vec2(1872.0, 1080.0),
                egui::vec2(1404.0, 810.0),
                egui::pos2(282.0, 135.0),
            ),
            (
                egui::pos2(0.0, 0.0),
                egui::vec2(1024.0, 528.0),
                egui::vec2(960.0, 528.0),
                egui::pos2(32.0, 0.0),
            ),
        ] {
            let area = egui::Rect::from_min_size(origin, area_size);
            let placement = Placement::in_work_area(area);
            assert_eq!(placement.size, expected_size, "area: {area:?}");
            assert_eq!(
                placement.position,
                Some(expected_position),
                "area: {area:?}"
            );
            if area_size.y == 528.0 {
                assert_eq!(placement.min_size, egui::vec2(960.0, 528.0));
            }
        }
    }

    #[test]
    fn fractional_work_area_keeps_window_inside_bounds() {
        let area = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(1706.67, 1018.67));
        let placement = Placement::in_work_area(area);
        let position = placement.position.expect("work area has a position");
        assert_eq!(placement.size, placement.size.floor());
        assert_eq!(position, position.floor());
        assert!(area.contains_rect(egui::Rect::from_min_size(position, placement.size)));
    }

    #[test]
    fn falls_back_to_fixed_size_and_system_position() {
        assert_eq!(
            Placement::fallback(),
            Placement {
                size: egui::vec2(1200.0, 780.0),
                min_size: egui::vec2(960.0, 640.0),
                position: None,
            },
        );
    }
}
