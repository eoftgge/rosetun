use eframe::egui::{self, CornerRadius, Stroke, TextStyle};

use crate::theme;

const TEXT_CHIP_HEIGHT: f32 = 24.0;
const TEXT_CHIP_PADDING: f32 = theme::space::S;

/// A compact label or choice in a wrapping row, such as a site or source host.
pub(crate) fn text_chip(
    ui: &mut egui::Ui,
    text: &str,
    color: egui::Color32,
    sense: egui::Sense,
    selected: bool,
) -> egui::Response {
    let palette = theme::palette();
    let mut job = egui::text::LayoutJob::simple_singleline(
        text.to_owned(),
        TextStyle::Body.resolve(ui.style()),
        color,
    );
    // A chip can move to the next row, so cap it at the row's full width.
    job.wrap = egui::text::TextWrapping::truncate_at_width(
        (ui.max_rect().width() - 2.0 * TEXT_CHIP_PADDING).max(0.0),
    );
    let galley = ui.painter().layout_job(job);
    let elided = galley.elided;
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(galley.size().x + 2.0 * TEXT_CHIP_PADDING, TEXT_CHIP_HEIGHT),
        sense,
    );
    let (fill, border) = if selected {
        (palette.input, palette.accent_dark)
    } else if response.hovered() && sense.senses_click() {
        (palette.border, palette.border_strong)
    } else {
        (palette.card, palette.border)
    };
    if ui.is_rect_visible(rect) {
        ui.painter().rect(
            rect,
            CornerRadius::same(theme::RADIUS_INNER),
            fill,
            Stroke::new(theme::stroke::HAIRLINE, border),
            egui::StrokeKind::Inside,
        );
        ui.painter().galley(
            egui::pos2(
                rect.left() + TEXT_CHIP_PADDING,
                rect.center().y - galley.size().y / 2.0,
            ),
            galley,
            color,
        );
    }
    if elided {
        response.on_hover_text(text)
    } else {
        response
    }
}

/// A quiet outlined word next to a title, such as "Experimental".
pub(crate) fn tag(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let galley = ui.painter().layout_no_wrap(
        text.to_owned(),
        TextStyle::Small.resolve(ui.style()),
        theme::palette().text_muted,
    );
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(galley.size().x + 14.0, galley.size().y + 4.0),
        egui::Sense::hover(),
    );
    if ui.is_rect_visible(rect) {
        ui.painter().rect_stroke(
            rect,
            CornerRadius::same(theme::capsule(rect.height())),
            Stroke::new(theme::stroke::HAIRLINE, theme::palette().border_strong),
            egui::StrokeKind::Inside,
        );
        ui.painter().galley(
            egui::pos2(rect.left() + 7.0, rect.center().y - galley.size().y / 2.0),
            galley,
            theme::palette().text_muted,
        );
    }
    response
}

/// A row title, followed by a tag when there is one. The tag moves under the
/// title when the row is too narrow for both.
pub(super) fn title_with_tag(ui: &mut egui::Ui, title: egui::WidgetText, tag_text: Option<&str>) {
    match tag_text {
        Some(tag_text) => {
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = theme::space::S;
                ui.label(title);
                tag(ui, tag_text);
            });
        }
        None => {
            ui.add(egui::Label::new(title).wrap());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::toggle_row;
    use super::*;

    #[test]
    fn a_tagged_toggle_row_stays_inside_a_narrow_card() {
        for width in [200.0, 320.0, 640.0] {
            let ctx = egui::Context::default();
            let mut row = egui::Rect::NOTHING;
            let mut panel = egui::Rect::NOTHING;
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(width, 480.0),
                    )),
                    ..egui::RawInput::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        panel = ui.max_rect();
                        row = toggle_row(
                            ui,
                            "Lockdown",
                            Some("Experimental"),
                            "No internet without the tunnel, even while disconnected.",
                            &mut false,
                            true,
                        )
                        .rect;
                    });
                },
            );
            output.textures_delta.clear();
            assert!(row.right() <= panel.right() + 0.5, "{row:?} in {panel:?}");
        }
    }
}
