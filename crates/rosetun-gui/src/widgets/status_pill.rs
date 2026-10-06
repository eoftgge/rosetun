use eframe::egui::{self, Color32, CornerRadius, Stroke, TextStyle};

use crate::theme::{BORDER, CARD};

/// The connection state as a small clickable badge: a dot and a word.
pub(crate) fn status_pill(ui: &mut egui::Ui, text: &str, color: Color32) -> egui::Response {
    let galley =
        ui.painter()
            .layout_no_wrap(text.to_owned(), TextStyle::Small.resolve(ui.style()), color);
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(galley.size().x + 40.0, 32.0),
        egui::Sense::click(),
    );
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, text));
    if ui.is_rect_visible(rect) {
        ui.painter().rect(
            rect,
            CornerRadius::same(16),
            if response.hovered() { BORDER } else { CARD },
            Stroke::new(1.0, BORDER),
            egui::StrokeKind::Inside,
        );
        ui.painter()
            .circle_filled(egui::pos2(rect.left() + 16.0, rect.center().y), 4.0, color);
        ui.painter().galley(
            egui::pos2(rect.left() + 28.0, rect.center().y - galley.size().y / 2.0),
            galley,
            color,
        );
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}
