use super::*;

pub(crate) fn name_dialog(ctx: &egui::Context, state: &mut State, actions: &mut Vec<Action>) {
    let Some(dialog) = &mut state.rules.screen.name else {
        return;
    };
    let busy = state.operations.rules_edit;
    let response = egui::Modal::new(egui::Id::new("rule_set_name"))
        .frame(widgets::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(400.0);
            ui.heading(match dialog.kind {
                NameDialogKind::Create => tr!("create-rule-set"),
                NameDialogKind::Rename(_) => tr!("rename-rule-set"),
            });
            ui.add_space(12.0);
            ui.label(tr!("set-name"));
            let input = ui.add_enabled(
                !busy,
                egui::TextEdit::singleline(&mut dialog.name).desired_width(f32::INFINITY),
            );
            if dialog.focus {
                input.request_focus();
                dialog.focus = false;
            }
            if input.changed() {
                dialog.error = None;
            }
            if let Some(error) = &dialog.error {
                ui.colored_label(theme::ERROR, error);
            }
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                if widgets::outline_button(ui, tr!("cancel"), !busy).clicked() {
                    actions.push(Action::CancelSetName);
                }
                let label = match dialog.kind {
                    NameDialogKind::Create => tr!("create-rule-set"),
                    NameDialogKind::Rename(_) => tr!("rename"),
                };
                if widgets::button_fill(ui, label, !busy && !dialog.name.trim().is_empty())
                    .clicked()
                {
                    actions.push(Action::SubmitSetName);
                }
            });
        });
    if !busy && response.should_close() {
        actions.push(Action::CancelSetName);
    }
}

fn delete_rule_value(rule: &Rule) -> String {
    if matches!(&rule.matcher, RuleMatcher::Template(_)) {
        rule_lines(&rule.matcher).0
    } else {
        rosetun_core::rule_value_text(&rule.matcher)
    }
}

pub(crate) fn delete_dialog(ctx: &egui::Context, state: &State, actions: &mut Vec<Action>) {
    let Some(dialog) = &state.rules.screen.delete else {
        return;
    };
    let busy = state.operations.rules_edit;
    let response = egui::Modal::new(egui::Id::new("delete_rules"))
        .frame(widgets::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(480.0);
            match dialog {
                DeleteDialog::Set(id) => {
                    ui.heading(tr!("delete-rule-set"));
                    if let Some(set) = state.config.rule_sets.iter().find(|set| &set.id == id) {
                        ui.label(state.text(&set.name));
                    }
                    ui.add(egui::Label::new(tr!("delete-rule-set-detail")).wrap());
                    if state.config.active_rule_set.as_ref() == Some(id) {
                        ui.add(
                            egui::Label::new(
                                RichText::new(tr!("delete-active-rule-set-warning"))
                                    .color(theme::ERROR),
                            )
                            .wrap(),
                        );
                    }
                }
                DeleteDialog::Rule { set, rule } => {
                    ui.heading(tr!("delete-rule"));
                    if let Some(rule) = state
                        .config
                        .rule_sets
                        .iter()
                        .find(|item| &item.id == set)
                        .and_then(|set| set.rules.iter().find(|item| &item.id == rule))
                    {
                        ui.label(state.text(&delete_rule_value(rule)));
                    }
                    ui.label(tr!("delete-rule-detail"));
                }
                DeleteDialog::Rules { set, rules } => {
                    ui.heading(crate::i18n::delete_rules_heading(rules.len()));
                    if let Some(set) = state.config.rule_sets.iter().find(|item| &item.id == set) {
                        for id in rules.iter().take(5) {
                            if let Some(rule) = set.rules.iter().find(|item| &item.id == id) {
                                ui.add(
                                    egui::Label::new(state.text(&delete_rule_value(rule))).wrap(),
                                );
                            }
                        }
                    }
                    if rules.len() > 5 {
                        ui.label(crate::i18n::and_more_rules(rules.len() - 5));
                    }
                    ui.label(tr!("delete-rule-detail"));
                }
            }
            ui.add_space(18.0);
            ui.horizontal(|ui| {
                if widgets::outline_button(ui, tr!("cancel"), !busy).clicked() {
                    actions.push(Action::CancelRuleDelete);
                }
                if widgets::button_fill(ui, tr!("delete"), !busy).clicked() {
                    actions.push(Action::ConfirmRuleDelete);
                }
            });
        });
    if !busy && response.should_close() {
        actions.push(Action::CancelRuleDelete);
    }
}
