use eframe::egui::{self, RichText, Stroke};

use crate::theme;

/// A drop-down for a filter row: as tall as the search field, on the input
/// fill with a strong border. `menu` adds the choices.
pub(crate) fn filter_combo(
    ui: &mut egui::Ui,
    id_salt: impl std::hash::Hash + std::fmt::Debug,
    width: f32,
    selected_text: RichText,
    hover: String,
    menu: impl FnOnce(&mut egui::Ui),
) -> egui::Response {
    ui.scope(|ui| {
        ui.spacing_mut().button_padding.y = 6.0;
        ui.spacing_mut().interact_size.y = 38.0;
        let visuals = &mut ui.visuals_mut().widgets;
        visuals.inactive.weak_bg_fill = theme::palette().input;
        visuals.hovered.weak_bg_fill = theme::palette().border;
        let border = Stroke::new(1.0, theme::palette().border_strong);
        visuals.inactive.bg_stroke = border;
        visuals.hovered.bg_stroke = border;
        visuals.open.bg_stroke = border;
        ui.allocate_ui(egui::vec2(width, 38.0), |ui| {
            ui.set_width(width);
            egui::ComboBox::from_id_salt(id_salt)
                .width(width)
                .truncate()
                .selected_text(selected_text)
                .show_ui(ui, menu)
                .response
                .on_hover_text(hover)
        })
        .inner
    })
    .inner
}
