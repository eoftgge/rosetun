use eframe::egui;

use crate::icons::{self, Icon};
use crate::theme;

use super::text_field::{field_frame, field_height, field_vertical_margin, style_field};

/// Search fields over the rules and connections lists share these widths.
pub(crate) const SEARCH_WIDTH: f32 = 260.0;
pub(crate) const MIN_SEARCH_WIDTH: f32 = 120.0;
/// Cap search inputs so an accidental multi-megabyte clipboard paste cannot
/// stall text layout while still fitting full domains, URL hosts, and paths.
const SEARCH_CHAR_LIMIT: usize = 512;

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
    let right_margin = suffix.map_or(theme::margin::side(theme::space::S), |suffix| {
        (ui.painter()
            .layout_no_wrap(suffix.to_owned(), font.clone(), theme::palette().text_dim)
            .size()
            .x
            + 16.0)
            .ceil()
            .clamp(8.0, 120.0) as i8
    });
    let height = field_height(ui);
    let vertical = field_vertical_margin(ui, height);
    let search = ui
        .scope(|ui| {
            style_field(ui, false);
            let id = ui.next_auto_id();
            ui.skip_ahead_auto_ids(1);
            let margin = egui::Margin {
                left: theme::margin::side(theme::space::XXL),
                right: right_margin,
                top: vertical,
                bottom: vertical,
            };
            ui.add(
                egui::TextEdit::singleline(text)
                    .id(id)
                    .frame(field_frame(ui, id, false, margin))
                    .hint_text(hint)
                    .char_limit(SEARCH_CHAR_LIMIT)
                    .desired_width(width)
                    .min_size(egui::vec2(width, height)),
            )
        })
        .inner;
    icons::paint(
        ui.painter(),
        egui::pos2(search.rect.left() + 16.0, search.rect.center().y),
        Icon::Search,
        theme::palette().text_dim,
    );
    if let Some(suffix) = suffix {
        ui.painter().text(
            egui::pos2(search.rect.right() - 10.0, search.rect.center().y),
            egui::Align2::RIGHT_CENTER,
            suffix,
            font,
            theme::palette().text_dim,
        );
    }
    search
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_field_caps_large_paste() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut text = String::new();
        let mut id = None;
        let pasted = "a".repeat(SEARCH_CHAR_LIMIT * 4);
        for events in [Vec::new(), vec![egui::Event::Paste(pasted)]] {
            if let Some(field_id) = id {
                ctx.memory_mut(|memory| memory.request_focus(field_id));
            }
            let mut output = ctx.run_ui(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        let response = search_field(ui, &mut text, "Search", SEARCH_WIDTH);
                        id = Some(response.id);
                    });
                },
            );
            output.textures_delta.clear();
        }
        assert_eq!(text.chars().count(), SEARCH_CHAR_LIMIT);
    }
}
