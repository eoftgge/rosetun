use eframe::egui::{self, Color32, RichText, Stroke};

use crate::theme;

fn primary_fill(enabled: bool) -> Color32 {
    if enabled {
        theme::palette().accent_base
    } else {
        theme::palette().accent_dark.gamma_multiply(0.65)
    }
}

pub(crate) fn button_fill(
    ui: &mut egui::Ui,
    text: impl Into<egui::WidgetText>,
    enabled: bool,
) -> egui::Response {
    ui.scope(|ui| {
        if !enabled {
            ui.visuals_mut().override_text_color = Some(theme::palette().text_muted);
        }
        ui.add_enabled(enabled, egui::Button::new(text).fill(primary_fill(enabled)))
    })
    .inner
}

pub(crate) fn outline_button(
    ui: &mut egui::Ui,
    text: impl Into<egui::WidgetText>,
    enabled: bool,
) -> egui::Response {
    let button = egui::Button::new(text)
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::new(
            1.0,
            if enabled { theme::palette().border_strong } else { theme::palette().border },
        ));
    ui.scope(|ui| {
        // egui sizes a button by its state's stroke width; match hover's 1 px so it keeps its size.
        ui.visuals_mut().widgets.inactive.bg_stroke.width = 1.0;
        ui.add_enabled(enabled, button)
    })
    .inner
}

pub(crate) fn button_fill_compact(ui: &mut egui::Ui, text: &str, enabled: bool) -> egui::Response {
    compact_button(ui, text, enabled, false, false)
}

pub(crate) fn outline_button_compact(
    ui: &mut egui::Ui,
    text: &str,
    enabled: bool,
) -> egui::Response {
    compact_button(ui, text, enabled, true, false)
}

/// A compact outlined button as wide as the space; a longer text ends in `…`.
pub(crate) fn outline_button_full(ui: &mut egui::Ui, text: &str, enabled: bool) -> egui::Response {
    compact_button(ui, text, enabled, true, true)
}

fn compact_button(
    ui: &mut egui::Ui,
    text: &str,
    enabled: bool,
    outlined: bool,
    full_width: bool,
) -> egui::Response {
    let font = egui::FontId::new(12.0, egui::FontFamily::Name(theme::UI_SEMIBOLD.into()));
    let button =
        egui::Button::new(egui::RichText::new(text).font(font)).min_size(egui::vec2(0.0, 28.0));
    let button = if full_width {
        button
            .min_size(egui::vec2(ui.available_width(), 28.0))
            .truncate()
    } else {
        button
    };
    let button = if outlined {
        button.fill(Color32::TRANSPARENT).stroke(Stroke::new(
            1.0,
            if enabled { theme::palette().border_strong } else { theme::palette().border },
        ))
    } else {
        button.fill(primary_fill(enabled))
    };
    ui.scope(|ui| {
        ui.spacing_mut().button_padding = egui::vec2(12.0, 4.0);
        ui.spacing_mut().interact_size.y = 28.0;
        if outlined {
            ui.visuals_mut().widgets.inactive.bg_stroke.width = 1.0;
        } else if !enabled {
            ui.visuals_mut().override_text_color = Some(theme::palette().text_muted);
        }
        ui.add_enabled(enabled, button)
    })
    .inner
}

pub(crate) fn link(ui: &mut egui::Ui, text: &str, enabled: bool) -> egui::Response {
    let response = ui.add(
        egui::Label::new(RichText::new(text).small().color(if enabled {
            theme::palette().accent_light
        } else {
            theme::palette().text_dim
        }))
        .sense(if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        }),
    );
    if enabled && response.hovered() {
        ui.painter().line_segment(
            [
                response.rect.left_bottom() + egui::vec2(0.0, -1.0),
                response.rect.right_bottom() + egui::vec2(0.0, -1.0),
            ],
            Stroke::new(1.0, theme::palette().accent_light),
        );
    }
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_primary_keeps_its_size_and_rose_fill() {
        assert_eq!(primary_fill(true), theme::palette().accent_base);
        assert_ne!(primary_fill(false), theme::palette().card);
        assert_eq!(primary_fill(false), theme::palette().accent_dark.gamma_multiply(0.65));
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let enabled = button_fill(ui, "Add", true);
                let disabled = button_fill(ui, "Add", false);
                assert_eq!(enabled.rect.size(), disabled.rect.size());
                assert!(!disabled.enabled());
            });
        });
        output.textures_delta.clear();
    }

    #[test]
    fn compact_buttons_are_28_points_high() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let filled = button_fill_compact(ui, "Add", true);
                let outlined = outline_button_compact(ui, "Added", true);
                assert_eq!(filled.rect.height(), 28.0);
                assert_eq!(outlined.rect.height(), 28.0);
            });
        });
        output.textures_delta.clear();
    }
}
