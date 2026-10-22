use eframe::egui;

use crate::icons::{self, Icon};
use crate::theme;

/// Search fields over the rules and connections lists share these widths.
pub(crate) const SEARCH_WIDTH: f32 = 260.0;
pub(crate) const MIN_SEARCH_WIDTH: f32 = 120.0;

/// The search field's width on the first row of a two-row toolbar, next to
/// controls `beside` wide.
pub(crate) fn search_width_beside(ui: &egui::Ui, beside: f32) -> f32 {
    (ui.available_width() - beside - ui.spacing().item_spacing.x)
        .clamp(MIN_SEARCH_WIDTH, SEARCH_WIDTH)
}

pub(crate) fn search_field(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
) -> egui::Response {
    search_field_inner(ui, text, hint, width, None)
}

pub(crate) fn search_field_with_suffix(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    suffix: &str,
) -> egui::Response {
    search_field_inner(ui, text, hint, width, Some(suffix))
}

fn search_field_inner(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    suffix: Option<&str>,
) -> egui::Response {
    let font = egui::TextStyle::Small.resolve(ui.style());
    let right_margin = suffix.map_or(8, |suffix| {
        (ui.painter()
            .layout_no_wrap(suffix.to_owned(), font.clone(), theme::TEXT_DIM)
            .size()
            .x
            + 16.0)
            .ceil()
            .clamp(8.0, 120.0) as i8
    });
    let search = ui.add(
        egui::TextEdit::singleline(text)
            .hint_text(hint)
            .desired_width(width)
            .min_size(egui::vec2(width, 38.0))
            .margin(egui::Margin {
                left: 32,
                right: right_margin,
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
    if let Some(suffix) = suffix {
        ui.painter().text(
            egui::pos2(search.rect.right() - 10.0, search.rect.center().y),
            egui::Align2::RIGHT_CENTER,
            suffix,
            font,
            theme::TEXT_DIM,
        );
    }
    search
}
