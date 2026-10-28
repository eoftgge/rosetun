use eframe::egui::{self, CornerRadius, Stroke, TextStyle};

use crate::theme;

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
            CornerRadius::same(9),
            Stroke::new(1.0, theme::palette().border_strong),
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
                ui.spacing_mut().item_spacing.x = 8.0;
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
