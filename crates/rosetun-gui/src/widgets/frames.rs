use eframe::egui::{self, CornerRadius, Stroke};

use crate::strings::t;
use crate::theme::{BORDER, BORDER_STRONG, CARD, ERROR, MODAL, RADIUS};

pub(crate) fn card_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(egui::Margin::same(16))
}

pub(crate) fn modal_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(MODAL)
        .stroke(Stroke::new(1.0, BORDER_STRONG))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(egui::Margin::same(24))
}

pub(crate) fn dismissible_error(ui: &mut egui::Ui, message: &str) -> bool {
    dismissible_error_with_action(ui, message, None).0
}

pub(crate) fn dismissible_error_with_action(
    ui: &mut egui::Ui,
    message: &str,
    action: Option<(&str, bool)>,
) -> (bool, bool) {
    let mut clicked = false;
    let dismissed = card_frame()
        .show(ui, |ui| {
            egui::Sides::new()
                .shrink_left()
                .wrap()
                .spacing(16.0)
                .show(
                    ui,
                    |ui| {
                        ui.colored_label(ERROR, crate::strings::ERROR_MARK);
                        ui.add(egui::Label::new(message).wrap());
                        if let Some((label, enabled)) = action {
                            clicked = crate::widgets::link(ui, label, enabled).clicked();
                        }
                    },
                    |ui| ui.button(t().dismiss).clicked(),
                )
                .1
        })
        .inner;
    (dismissed, clicked)
}
