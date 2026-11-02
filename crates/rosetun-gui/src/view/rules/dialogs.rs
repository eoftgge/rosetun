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

pub(crate) fn delete_dialog(ctx: &egui::Context, state: &State, actions: &mut Vec<Action>) {
    let Some(id) = &state.rules.screen.delete_set else {
        return;
    };
    let busy = state.operations.rules_edit;
    let choice = widgets::confirm_modal(
        ctx,
        widgets::ConfirmModal {
            id: "delete_rules",
            title: tr!("delete-rule-set"),
            cancel: tr!("cancel"),
            confirm: tr!("delete"),
            busy,
            confirm_enabled: !busy,
            width: widgets::DialogWidth::Standard,
        },
        |ui| {
            if let Some(set) = state.config.rule_sets.iter().find(|set| &set.id == id) {
                ui.label(state.text(&set.name));
            }
            ui.add(egui::Label::new(tr!("delete-rule-set-detail")).wrap());
            if state.config.active_rule_set.as_ref() == Some(id) {
                ui.add(
                    egui::Label::new(
                        RichText::new(tr!("delete-active-rule-set-warning")).color(theme::ERROR),
                    )
                    .wrap(),
                );
            }
        },
    );
    match choice {
        widgets::ModalChoice::Cancel => actions.push(Action::CancelDeleteSet),
        widgets::ModalChoice::Confirm => actions.push(Action::ConfirmDeleteSet),
        widgets::ModalChoice::None => {}
    }
}
