use eframe::egui::{self, RichText};

use crate::state::{Action, CheckLine};
use crate::{theme, widgets};

/// "Check an address or program": the field and, under it, where the active
/// rules send what was typed. The line's height is kept while the field is
/// empty, so the table below does not jump.
pub(super) fn address_check(
    ui: &mut egui::Ui,
    available: bool,
    input: &mut String,
    line: Option<CheckLine>,
    actions: &mut Vec<Action>,
) {
    let width = ui.available_width().min(widgets::CHECK_FIELD_WIDTH);
    let field = ui.add_enabled_ui(available, |ui| {
        widgets::search_field(ui, input, &tr!("rule-check-hint"), width)
    });
    field
        .response
        .on_disabled_hover_text(tr!("rule-check-other-set"));
    ui.add_space(theme::space::XS);
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = theme::space::XS;
        let Some(line) = line else {
            ui.label(RichText::new(" ").small());
            return;
        };
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
