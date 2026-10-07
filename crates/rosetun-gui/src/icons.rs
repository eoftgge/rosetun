use eframe::egui::{self, Color32};

use crate::theme;

#[derive(Clone, Copy)]
pub(crate) enum Icon {
    Grip,
    Check,
    Chevron { open: bool },
    Refresh,
    More,
    Search,
    App,
    Globe,
    Stack,
    Chat,
    Play,
    Download,
}

pub(crate) fn icon_button(ui: &mut egui::Ui, icon: Icon, enabled: bool) -> egui::Response {
    icon_button_sized(ui, icon, enabled, 22.0)
}

pub(crate) fn icon_button_sized(
    ui: &mut egui::Ui,
    icon: Icon,
    enabled: bool,
    size: f32,
) -> egui::Response {
    let enabled = enabled && ui.is_enabled();
    let sense = if enabled && !matches!(icon, Icon::Grip) {
        egui::Sense::click()
    } else {
        egui::Sense::hover()
    };
    let (rect, response) = ui.allocate_exact_size(egui::vec2(size, size), sense);
    if ui.is_rect_visible(rect) {
        if enabled && !matches!(icon, Icon::Grip) {
            if response.is_pointer_button_down_on() {
                ui.painter()
                    .rect_filled(rect, theme::RADIUS_INNER, theme::ROSE_DARK);
            } else if response.hovered() {
                ui.painter()
                    .rect_filled(rect, theme::RADIUS_INNER, theme::BORDER);
            }
        }
        let color = if !enabled {
            theme::DISABLED
        } else if response.hovered() {
            theme::TEXT
        } else {
            theme::TEXT_MUTED
        };
        paint(ui.painter(), rect.center(), icon, color);
    }
    if enabled && !matches!(icon, Icon::Grip) {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

/// A type mark: the icon on an INPUT square, not clickable.
pub(crate) fn icon_badge(ui: &mut egui::Ui, icon: Icon, size: f32) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    if ui.is_rect_visible(rect) {
        ui.painter()
            .rect_filled(rect, theme::RADIUS_INNER, theme::INPUT);
        paint(ui.painter(), rect.center(), icon, theme::TEXT_MUTED);
    }
    response
}

pub(crate) fn paint(painter: &egui::Painter, center: egui::Pos2, icon: Icon, color: Color32) {
    let stroke = egui::Stroke::new(1.5, color);
    match icon {
        Icon::Grip => {
            for x in [-2.0, 2.0] {
                for y in [-4.0, 0.0, 4.0] {
                    painter.circle_filled(center + egui::vec2(x, y), 1.0, color);
                }
            }
        }
        Icon::Check => {
            painter.line_segment(
                [
                    center + egui::vec2(-5.0, 0.0),
                    center + egui::vec2(-1.5, 3.5),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    center + egui::vec2(-1.5, 3.5),
                    center + egui::vec2(5.0, -3.5),
                ],
                stroke,
            );
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
        Icon::More => {
            for x in [-5.0, 0.0, 5.0] {
                painter.circle_filled(center + egui::vec2(x, 0.0), 1.3, color);
            }
        }
        Icon::Search => {
            painter.circle_stroke(center + egui::vec2(-1.5, -1.5), 4.5, stroke);
            painter.line_segment(
                [center + egui::vec2(1.8, 1.8), center + egui::vec2(5.5, 5.5)],
                stroke,
            );
        }
        Icon::App => {
            let rect = egui::Rect::from_center_size(center, egui::vec2(14.0, 11.0));
            painter.rect_stroke(rect, 1.0, stroke, egui::StrokeKind::Inside);
            painter.line_segment(
                [
                    egui::pos2(rect.left(), rect.top() + 3.0),
                    egui::pos2(rect.right(), rect.top() + 3.0),
                ],
                stroke,
            );
        }
        Icon::Globe => {
            painter.circle_stroke(center, 6.5, stroke);
            painter.line_segment(
                [
                    center + egui::vec2(-6.5, 0.0),
                    center + egui::vec2(6.5, 0.0),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    center + egui::vec2(0.0, -6.5),
                    center + egui::vec2(0.0, 6.5),
                ],
                stroke,
            );
            let points = (0..16)
                .map(|index| {
                    let angle = index as f32 * std::f32::consts::TAU / 16.0;
                    center + egui::vec2(3.0 * angle.cos(), 6.5 * angle.sin())
                })
                .collect();
            painter.add(egui::Shape::line(points, stroke));
        }
        Icon::Stack => {
            for y in [-4.0, 0.0, 4.0] {
                painter.rect_filled(
                    egui::Rect::from_center_size(
                        center + egui::vec2(0.0, y),
                        egui::vec2(12.0, 2.5),
                    ),
                    1.25,
                    color,
                );
            }
        }
        Icon::Chat => {
            let rect = egui::Rect::from_center_size(
                center + egui::vec2(0.0, -1.0),
                egui::vec2(14.0, 10.0),
            );
            painter.rect_stroke(rect, 2.0, stroke, egui::StrokeKind::Inside);
            painter.add(egui::Shape::convex_polygon(
                vec![
                    egui::pos2(rect.left() + 2.0, rect.bottom() - 1.0),
                    egui::pos2(rect.left() + 2.0, rect.bottom() + 3.0),
                    egui::pos2(rect.left() + 5.0, rect.bottom() - 1.0),
                ],
                color,
                egui::Stroke::NONE,
            ));
        }
        Icon::Play => {
            painter.rect_stroke(
                egui::Rect::from_center_size(center, egui::vec2(15.0, 11.0)),
                2.0,
                stroke,
                egui::StrokeKind::Inside,
            );
            painter.add(egui::Shape::convex_polygon(
                vec![
                    center + egui::vec2(-2.0, -3.0),
                    center + egui::vec2(-2.0, 3.0),
                    center + egui::vec2(3.0, 0.0),
                ],
                color,
                egui::Stroke::NONE,
            ));
        }
        Icon::Download => {
            painter.line_segment(
                [
                    center + egui::vec2(0.0, -6.0),
                    center + egui::vec2(0.0, 2.0),
                ],
                stroke,
            );
            painter.add(egui::Shape::line(
                vec![
                    center + egui::vec2(-3.5, -1.5),
                    center + egui::vec2(0.0, 2.0),
                    center + egui::vec2(3.5, -1.5),
                ],
                stroke,
            ));
            painter.line_segment(
                [
                    center + egui::vec2(-6.0, 6.0),
                    center + egui::vec2(6.0, 6.0),
                ],
                stroke,
            );
        }
    }
}
