use eframe::egui::{self, Shape, Stroke};

use crate::theme;

pub(crate) enum Icon {
    Grip,
    Up,
    Down,
}

pub(crate) fn icon_button(ui: &mut egui::Ui, icon: Icon, enabled: bool) -> egui::Response {
    let sense = if enabled && !matches!(icon, Icon::Grip) {
        egui::Sense::click()
    } else {
        egui::Sense::hover()
    };
    let (rect, response) = ui.allocate_exact_size(egui::vec2(22.0, 22.0), sense);
    if ui.is_rect_visible(rect) {
        let color = if !enabled {
            theme::DISABLED
        } else if response.hovered() {
            theme::TEXT
        } else {
            theme::TEXT_MUTED
        };
        let center = rect.center();
        let painter = ui.painter();
        match icon {
            Icon::Grip => {
                for x in [-2.0, 2.0] {
                    for y in [-4.0, 0.0, 4.0] {
                        painter.rect_filled(
                            egui::Rect::from_center_size(
                                center + egui::vec2(x, y),
                                egui::vec2(2.0, 2.0),
                            ),
                            0.0,
                            color,
                        );
                    }
                }
            }
            Icon::Up => {
                painter.add(Shape::convex_polygon(
                    vec![
                        center + egui::vec2(0.0, -3.0),
                        center + egui::vec2(5.0, 3.0),
                        center + egui::vec2(-5.0, 3.0),
                    ],
                    color,
                    Stroke::NONE,
                ));
            }
            Icon::Down => {
                painter.add(Shape::convex_polygon(
                    vec![
                        center + egui::vec2(-5.0, -3.0),
                        center + egui::vec2(5.0, -3.0),
                        center + egui::vec2(0.0, 3.0),
                    ],
                    color,
                    Stroke::NONE,
                ));
            }
        }
    }
    response
}
