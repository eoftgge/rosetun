use eframe::egui;

use crate::icons::{self, Icon};
use crate::theme;

pub(crate) fn search_field(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
) -> egui::Response {
    let search = ui.add(
        egui::TextEdit::singleline(text)
            .hint_text(hint)
            .desired_width(width)
            .min_size(egui::vec2(width, 38.0))
            .margin(egui::Margin {
                left: 32,
                right: 8,
                top: 8,
                bottom: 8,
            }),
    );
    icons::paint(
        ui.painter(),
        egui::pos2(search.rect.left() + 16.0, search.rect.center().y),
        Icon::Search,
        theme::TEXT_DIM,
    );
    search
}
