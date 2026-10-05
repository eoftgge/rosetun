use eframe::egui;

use crate::theme;

#[derive(Clone, Copy)]
pub(crate) enum Icon {
    Grip,
    Chevron { open: bool },
    Refresh,
    Trash,
}

pub(crate) fn icon_button(ui: &mut egui::Ui, icon: Icon, enabled: bool) -> egui::Response {
    let enabled = enabled && ui.is_enabled();
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
        let stroke = egui::Stroke::new(1.5, color);
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
            Icon::Chevron { open } => {
                let points = if open {
                    [
                        center + egui::vec2(-4.0, -2.0),
                        center + egui::vec2(0.0, 2.0),
                        center + egui::vec2(4.0, -2.0),
                    ]
                } else {
                    [
                        center + egui::vec2(-2.0, -4.0),
                        center + egui::vec2(2.0, 0.0),
                        center + egui::vec2(-2.0, 4.0),
                    ]
                };
                painter.add(egui::Shape::line(points.to_vec(), stroke));
            }
            Icon::Refresh => {
                let start = -2.4;
                let end = start + std::f32::consts::FRAC_PI_2 * 3.0;
                let points = (0..=16)
                    .map(|step| {
                        let angle = start + (end - start) * step as f32 / 16.0;
                        center + egui::vec2(angle.cos(), angle.sin()) * 6.0
                    })
                    .collect();
                painter.add(egui::Shape::line(points, stroke));
                let tip = center + egui::vec2(end.cos(), end.sin()) * 6.0;
                let tangent = egui::vec2(-end.sin(), end.cos());
                let base = tip - tangent * 4.0;
                let normal = egui::vec2(-tangent.y, tangent.x) * 2.2;
                painter.add(egui::Shape::convex_polygon(
                    vec![tip, base + normal, base - normal],
                    color,
                    egui::Stroke::NONE,
                ));
            }
            Icon::Trash => {
                painter.add(egui::Shape::line(
                    vec![
                        center + egui::vec2(-4.0, -1.0),
                        center + egui::vec2(-4.0, 8.0),
                        center + egui::vec2(4.0, 8.0),
                        center + egui::vec2(4.0, -1.0),
                    ],
                    stroke,
                ));
                painter.line_segment(
                    [
                        center + egui::vec2(-6.0, -4.0),
                        center + egui::vec2(6.0, -4.0),
                    ],
                    stroke,
                );
                painter.line_segment(
                    [
                        center + egui::vec2(-2.0, -7.0),
                        center + egui::vec2(2.0, -7.0),
                    ],
                    stroke,
                );
            }
        }
    }
    if enabled && !matches!(icon, Icon::Grip) {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}
