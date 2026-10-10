use super::*;

pub(super) fn clear_selection_on_click_away(
    ctx: &egui::Context,
    state: &State,
    selection_regions: &[egui::Rect],
    actions: &mut Vec<Action>,
) {
    if state.rules.screen.selected_rules.is_empty()
        || state.rules.screen.name.is_some()
        || state.rules.screen.add.is_some()
        || state.rules.screen.delete.is_some()
        || ctx.dragged_id().is_some()
        || actions.iter().any(|action| {
            matches!(
                action,
                Action::SelectRule { .. }
                    | Action::DropRule(_, _)
                    | Action::DropRules(_, _)
                    | Action::MoveSelectedRulesToTop
                    | Action::MoveSelectedRulesToEnd
                    | Action::RequestDeleteSelectedRules
                    | Action::ClearRuleSelection
            )
        })
    {
        return;
    }
    let click = ctx.input(|input| {
        input
            .pointer
            .primary_clicked()
            .then(|| input.pointer.interact_pos())
            .flatten()
    });
    if click.is_some_and(|pos| !selection_regions.iter().any(|rect| rect.contains(pos))) {
        actions.push(Action::ClearRuleSelection);
    }
}

pub(super) fn selection_slot(
    ui: &mut egui::Ui,
    state: &State,
    actions: &mut Vec<Action>,
) -> egui::Response {
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), 38.0),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            if state.rules.screen.selected_rules.len() >= 2 {
                selection_toolbar(ui, state, actions);
            } else {
                ui.add(
                    egui::Label::new(
                        RichText::new(tr!("order-hint"))
                            .small()
                            .color(theme::TEXT_DIM),
                    )
                    .wrap(),
                );
            }
        },
    )
    .response
}

fn selection_toolbar(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let can_edit = state.can_edit_rules();
    let can_move = can_edit && !state.rules.screen.filter.is_active();
    let count = state.rules.screen.selected_rules.len();
    ui.label(RichText::new(crate::i18n::selected_rule_count(count)).color(theme::TEXT_MUTED));
    for (label, action) in [
        (tr!("move-selected-to-top"), Action::MoveSelectedRulesToTop),
        (tr!("move-to-end"), Action::MoveSelectedRulesToEnd),
    ] {
        let button = widgets::outline_button_compact(ui, &label, can_move);
        let button = if state.rules.screen.filter.is_active() {
            button.on_hover_text(tr!("reorder-disabled"))
        } else {
            button
        };
        if button.clicked() {
            actions.push(action);
        }
    }
    let delete = ui
        .scope(|ui| {
            ui.visuals_mut().override_text_color = Some(if can_edit {
                theme::ERROR
            } else {
                theme::DISABLED
            });
            widgets::outline_button_compact(ui, &tr!("delete"), can_edit)
        })
        .inner;
    if delete.clicked() {
        actions.push(Action::RequestDeleteSelectedRules);
    }
}

pub(super) fn selection_shortcuts(
    ctx: &egui::Context,
    state: &State,
    text_edit_focused: bool,
    actions: &mut Vec<Action>,
) {
    if text_edit_focused
        || state.rules.screen.name.is_some()
        || state.rules.screen.add.is_some()
        || state.rules.screen.delete.is_some()
    {
        return;
    }
    if ctx.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, egui::Key::A)) {
        actions.push(Action::SelectVisibleRules);
    } else if !state.rules.screen.selected_rules.is_empty()
        && ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
    {
        actions.push(Action::ClearRuleSelection);
    } else if !state.rules.screen.selected_rules.is_empty()
        && state.can_edit_rules()
        && ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Delete))
    {
        actions.push(Action::RequestDeleteSelectedRules);
    }
}
