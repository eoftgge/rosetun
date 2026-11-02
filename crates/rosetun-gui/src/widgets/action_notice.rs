use eframe::egui::{self, RichText};

use super::{link, modal_frame};
use crate::theme;

/// A short notice at the bottom of the window with one action after it, as
/// "Rule deleted · Undo". Returns whether the action was clicked.
pub(crate) fn action_notice(
    ctx: &egui::Context,
    id: &str,
    text: &str,
    action: &str,
    enabled: bool,
) -> bool {
    egui::Area::new(egui::Id::unique(id))
        .anchor(
            egui::Align2::CENTER_BOTTOM,
            egui::vec2(0.0, -theme::space::XL),
        )
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            modal_frame()
                .inner_margin(theme::margin::symmetric(theme::space::L, theme::space::M))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        let color = theme::palette().text;
                        ui.label(RichText::new(text).small().color(color));
                        ui.label(RichText::new(tr!("apply-separator")).small().color(color));
                        link(ui, action, enabled).clicked()
                    })
                    .inner
                })
                .inner
        })
        .inner
}
