use eframe::egui::{self, RichText};

use crate::state::{Action, CheckLine};
use crate::{theme, widgets};

/// Inline routing check answer shown in the slot under the rules toolbar
/// whenever the unified search field holds a recognised address or program.
pub(super) fn check_result(ui: &mut egui::Ui, line: CheckLine, actions: &mut Vec<Action>) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = theme::space::XS;
        let dot_color = line
            .target
            .map_or(theme::palette().text_dim, super::target_color);
        let (dot, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
        ui.painter().circle_filled(dot.center(), 3.0, dot_color);
        let color = if line.answer {
            theme::palette().text
        } else {
            theme::palette().text_dim
        };
        let text = ui.label(RichText::new(&line.text).small().color(color));
        if let Some(hint) = &line.hint {
            text.on_hover_text(hint);
        }
        if let Some((label, rule)) = &line.rule
            && widgets::link(ui, label, true).clicked()
        {
            actions.push(Action::ShowCheckedRule(rule.clone()));
        }
    });
}
