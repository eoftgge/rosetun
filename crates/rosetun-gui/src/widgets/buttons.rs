use eframe::egui::{self, Color32, Stroke};

use crate::theme::{BORDER, BORDER_STRONG, CARD, ROSE};

pub(crate) fn button_fill(
    ui: &mut egui::Ui,
    text: impl Into<egui::WidgetText>,
    enabled: bool,
) -> egui::Response {
    let button = egui::Button::new(text).fill(if enabled { ROSE } else { CARD });
    ui.add_enabled(enabled, button)
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
            if enabled { BORDER_STRONG } else { BORDER },
        ));
    ui.scope(|ui| {
        // egui sizes a button by its state's stroke width; match hover's 1 px so it keeps its size.
        ui.visuals_mut().widgets.inactive.bg_stroke.width = 1.0;
        ui.add_enabled(enabled, button)
    })
    .inner
}
