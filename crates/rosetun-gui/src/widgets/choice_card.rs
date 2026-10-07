use std::hash::{Hash, Hasher};

use eframe::egui::{self, CornerRadius, Stroke, UiBuilder};

use crate::theme::{BORDER, INPUT, RADIUS, ROSE};

/// One of a few choices: no fill and a BORDER stroke at rest, an INPUT fill
/// and a ROSE stroke when selected.
pub(crate) fn choice_card(
    ui: &mut egui::Ui,
    id_salt: impl Hash,
    width: f32,
    selected: bool,
    enabled: bool,
    add_contents: impl FnOnce(&mut egui::Ui),
) -> egui::Response {
    let enabled = enabled && ui.is_enabled();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    id_salt.hash(&mut hasher);
    let response = ui
        .scope_builder(
            UiBuilder::new().id_salt(hasher.finish()).sense(if enabled {
                egui::Sense::click()
            } else {
                egui::Sense::hover()
            }),
            |ui| {
                ui.style_mut().interaction.selectable_labels = false;
                if !enabled {
                    ui.multiply_opacity(0.5);
                }
                let background = ui.painter().add(egui::Shape::Noop);
                ui.set_width(width);
                egui::Frame::new()
                    .inner_margin(egui::Margin::symmetric(12, 10))
                    .show(ui, |ui| {
                        ui.set_min_width(width - 24.0);
                        add_contents(ui);
                    });
                let response = ui.response();
                let fill = if selected {
                    INPUT
                } else if response.hovered() && enabled {
                    BORDER
                } else {
                    egui::Color32::TRANSPARENT
                };
                ui.painter().set(
                    background,
                    egui::Shape::rect_filled(response.rect, CornerRadius::same(RADIUS), fill),
                );
                ui.painter().rect_stroke(
                    response.rect,
                    CornerRadius::same(RADIUS),
                    Stroke::new(1.0, if selected { ROSE } else { BORDER }),
                    egui::StrokeKind::Inside,
                );
            },
        )
        .response;
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::RadioButton, enabled, selected, "")
    });
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}
