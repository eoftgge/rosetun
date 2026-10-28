use eframe::egui::{self, Color32, Stroke};

use crate::theme;

/// A square checkbox in the brand colours: accent fill with a white tick when checked.
pub(crate) fn checkbox(
    ui: &mut egui::Ui,
    checked: &mut bool,
    label: impl Into<egui::WidgetText>,
    enabled: bool,
) -> egui::Response {
    ui.scope(|ui| {
        let fill = if *checked {
            theme::palette().accent_base
        } else {
            theme::palette().card
        };
        let border = if *checked {
            theme::palette().accent_base
        } else {
            theme::palette().border_strong
        };
        let check = if *checked {
            Color32::WHITE
        } else {
            theme::palette().text_muted
        };
        let widgets = &mut ui.visuals_mut().widgets;
        for visuals in [
            &mut widgets.noninteractive,
            &mut widgets.inactive,
            &mut widgets.hovered,
            &mut widgets.active,
        ] {
            visuals.corner_radius = egui::CornerRadius::same(0);
            visuals.bg_fill = fill;
            visuals.bg_stroke = Stroke::new(1.0, border);
            visuals.fg_stroke = Stroke::new(1.5, check);
        }
        ui.add_enabled(enabled, egui::Checkbox::new(checked, label))
    })
    .inner
}
