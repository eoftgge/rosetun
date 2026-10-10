use super::*;

pub(crate) fn name_dialog(ctx: &egui::Context, state: &mut State, actions: &mut Vec<Action>) {
    let Some(dialog) = &mut state.rules.screen.name else {
        return;
    };
    let busy = state.operations.rules_edit;
    let (title, submit) = match dialog.kind {
        NameDialogKind::Create => (tr!("create-rule-set"), tr!("create-rule-set")),
        NameDialogKind::Rename(_) => (tr!("rename-rule-set"), tr!("rename")),
    };
    let choice = widgets::name_modal(
        ctx,
        widgets::NameModal {
            id: "rule_set_name",
            title,
            label: tr!("set-name"),
            submit,
            name: &mut dialog.name,
            focus: &mut dialog.focus,
            error: &mut dialog.error,
            busy,
            char_limit: None,
        },
    );
    match choice {
        widgets::ModalChoice::Cancel => actions.push(Action::CancelSetName),
        widgets::ModalChoice::Confirm => actions.push(Action::SubmitSetName),
        widgets::ModalChoice::None => {}
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
    let title = match dialog {
        DeleteDialog::Set(_) => tr!("delete-rule-set"),
        DeleteDialog::Rule { .. } => tr!("delete-rule"),
        DeleteDialog::Rules { rules, .. } => crate::i18n::delete_rules_heading(rules.len()),
    };
    let choice = widgets::confirm_modal(
        ctx,
        widgets::ConfirmModal {
            id: "delete_rules",
            title,
            cancel: tr!("cancel"),
            confirm: tr!("delete"),
            busy,
            confirm_enabled: !busy,
            button_gap: 18.0,
        },
        |ui| {
            match dialog {
                DeleteDialog::Set(id) => {
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
        },
    );
    match choice {
        widgets::ModalChoice::Cancel => actions.push(Action::CancelRuleDelete),
        widgets::ModalChoice::Confirm => actions.push(Action::ConfirmRuleDelete),
        widgets::ModalChoice::None => {}
    }
}
