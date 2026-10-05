use eframe::egui::{self, Color32, RichText, Stroke};
use rosetun_config::{DomainMatch, ProcessMatch, Rule, RuleId, RuleMatcher, RuleSet, RuleTarget};

use crate::icons::{self, Icon};
use crate::rules::{
    RuleFilter, TypeFilter, drop_target, reorder_arrows, rule_counts, visible_rules,
};
use crate::state::{Action, DeleteDialog, NameDialogKind, State};
use crate::{strings, theme};

pub(crate) fn show(ui: &mut egui::Ui, state: &mut State, actions: &mut Vec<Action>) {
    ui.heading(strings::RULES_TITLE);
    ui.colored_label(theme::TEXT_MUTED, strings::RULES_SUBTITLE);
    ui.add_space(20.0);
    if !state.config_ready {
        ui.colored_label(theme::TEXT_DIM, strings::LOADING);
        return;
    }
    if state.config.rule_sets.is_empty() {
        ui.colored_label(theme::TEXT_MUTED, strings::NO_RULE_SETS);
        ui.add_space(12.0);
        if theme::button_fill(ui, strings::CREATE_RULE_SET, state.can_edit_rules()).clicked() {
            actions.push(Action::OpenCreateSet);
        }
        return;
    }

    set_controls(ui, state, actions);
    ui.add_space(20.0);
    let Some(set) = state
        .config
        .rule_sets
        .iter()
        .find(|item| state.rule_screen.selected_set.as_ref() == Some(&item.id))
    else {
        theme::button_fill(ui, strings::NEW_RULE_BUTTON, false);
        return;
    };
    if state
        .visible_status()
        .is_some_and(|status| status.state.is_active() || status.state.is_transitional())
        && state.config.active_rule_set.as_ref() == Some(&set.id)
    {
        theme::card_frame().show(ui, |ui| {
            ui.colored_label(theme::ROSE_LIGHT, strings::RULES_NEXT_CONNECT);
        });
        ui.add_space(16.0);
    }
    let can_add = state.can_edit_rules();
    filter_controls(ui, &mut state.rule_screen.filter, set, can_add, actions);
    ui.add_space(16.0);
    ui.colored_label(theme::TEXT_DIM, strings::ORDER_HINT);
    ui.add_space(8.0);

    let visible = visible_rules(set, &state.rule_screen.filter);
    if set.rules.is_empty() {
        ui.colored_label(
            theme::TEXT_MUTED,
            strings::no_rules(target_label(set.default_target)),
        );
    } else if visible.is_empty() {
        ui.colored_label(theme::TEXT_MUTED, strings::NO_RULES_MATCH);
    } else {
        let value_width = (ui.available_width() - 550.0).max(140.0);
        table_header(ui, value_width);
        ui.scope(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for (index, rule) in visible {
                ui.push_id((set.id.as_str(), rule.id.as_str()), |ui| {
                    rule_row(ui, state, set, rule, index, value_width, actions);
                });
            }
        });
    }
    ui.add_space(12.0);
    default_rule(ui, state, set, actions);
}

fn set_controls(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let Some(set) = state.selected_rules() else {
        return;
    };
    ui.horizontal_wrapped(|ui| {
        let mut selected = set.id.clone();
        egui::ComboBox::from_id_salt("opened_rule_set")
            .selected_text(state.text(&set.name))
            .width(260.0)
            .show_ui(ui, |ui| {
                for item in &state.config.rule_sets {
                    ui.selectable_value(&mut selected, item.id.clone(), state.text(&item.name));
                }
            });
        if selected != set.id {
            actions.push(Action::ChooseRuleSet(selected));
        }
        if state.config.active_rule_set.as_ref() == Some(&set.id) {
            ui.colored_label(theme::ROSE_LIGHT, strings::ACTIVE);
        } else if theme::outline_button(ui, strings::USE_FOR_CONNECTIONS, state.can_edit_rules())
            .clicked()
        {
            actions.push(Action::SelectRuleSet(Some(set.id.clone())));
        }
        if theme::outline_button(ui, strings::NEW_SET, state.can_edit_rules()).clicked() {
            actions.push(Action::OpenCreateSet);
        }
        if theme::outline_button(ui, strings::RENAME, state.can_edit_rules()).clicked() {
            actions.push(Action::OpenRenameSet);
        }
        if theme::outline_button(ui, strings::DELETE, state.can_edit_rules()).clicked() {
            actions.push(Action::RequestDeleteSet);
        }
    });
}

fn filter_controls(
    ui: &mut egui::Ui,
    filter: &mut RuleFilter,
    set: &RuleSet,
    can_add: bool,
    actions: &mut Vec<Action>,
) {
    ui.add(
        egui::TextEdit::singleline(&mut filter.search)
            .hint_text(strings::SEARCH_RULES)
            .desired_width(330.0),
    );
    let counts = rule_counts(set);
    ui.horizontal_wrapped(|ui| {
        for (kind, label, count) in [
            (TypeFilter::All, strings::ALL, counts.all()),
            (TypeFilter::Domains, strings::DOMAINS, counts.domains),
            (TypeFilter::Processes, strings::PROCESSES, counts.processes),
            (TypeFilter::Other, strings::OTHER, counts.other),
        ] {
            if kind == TypeFilter::Other && count == 0 {
                continue;
            }
            if ui
                .add(
                    egui::Button::new(strings::filter_count(label, count))
                        .selected(filter.kind == kind),
                )
                .clicked()
            {
                actions.push(Action::SetRuleTypeFilter(kind));
            }
        }
        ui.separator();
        for target in [RuleTarget::Proxy, RuleTarget::Direct, RuleTarget::Block] {
            let text = RichText::new(target_label(target)).color(target_color(target));
            if ui
                .add(egui::Button::new(text).selected(filter.target == Some(target)))
                .clicked()
            {
                actions.push(Action::ToggleRuleTargetFilter(target));
            }
        }
        ui.separator();
        if theme::button_fill(ui, strings::NEW_RULE_BUTTON, can_add).clicked() {
            actions.push(Action::OpenAddRule);
        }
    });
}

fn table_header(ui: &mut egui::Ui, value_width: f32) {
    ui.horizontal(|ui| {
        ui.add_space(30.0);
        ui.add_sized([90.0, 20.0], egui::Label::new(strings::TYPE));
        ui.add_sized([value_width, 20.0], egui::Label::new(strings::VALUE));
        ui.add_sized([126.0, 20.0], egui::Label::new(strings::TARGET));
        ui.add_sized([78.0, 20.0], egui::Label::new(strings::ENABLED));
        ui.label(strings::ACTIONS);
    });
}

fn rule_row(
    ui: &mut egui::Ui,
    state: &State,
    set: &RuleSet,
    rule: &Rule,
    index: usize,
    value_width: f32,
    actions: &mut Vec<Action>,
) {
    let reorder = state.can_edit_rules() && !state.rule_screen.filter.is_active();
    let dragged =
        reorder && egui::DragAndDrop::payload::<RuleId>(ui.ctx()).is_some_and(|id| *id == rule.id);
    let mut frame = theme::card_frame().inner_margin(egui::Margin::symmetric(10, 8));
    if dragged {
        frame = frame.fill(Color32::from_rgba_unmultiplied(
            theme::CARD.r(),
            theme::CARD.g(),
            theme::CARD.b(),
            128,
        ));
    } else if !rule.enabled {
        frame = frame.fill(theme::CARD.gamma_multiply(0.72));
    }
    let response = egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(0, 2))
        .show(ui, |ui| {
            frame.show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                if dragged {
                    ui.multiply_opacity(0.5);
                } else if !rule.enabled {
                    ui.multiply_opacity(0.7);
                }
                ui.horizontal(|ui| {
                    if reorder {
                        ui.dnd_drag_source(ui.id().with("handle"), rule.id.clone(), |ui| {
                            icons::icon_button(ui, Icon::Grip, true);
                        });
                    } else {
                        icons::icon_button(ui, Icon::Grip, false)
                            .on_hover_text(strings::REORDER_DISABLED);
                    }
                    ui.add_sized([90.0, 22.0], egui::Label::new(rule_type(rule)));
                    ui.vertical(|ui| {
                        ui.set_width(value_width);
                        rule_value(ui, state, rule);
                        if !rule.enabled {
                            ui.colored_label(theme::TEXT_DIM, strings::RULE_DISABLED);
                        }
                    });
                    let mut target = rule.target;
                    ui.add_enabled_ui(state.can_edit_rules(), |ui| {
                        egui::ComboBox::from_id_salt("target")
                            .selected_text(
                                RichText::new(target_label(target)).color(target_color(target)),
                            )
                            .width(108.0)
                            .show_ui(ui, |ui| {
                                for value in
                                    [RuleTarget::Proxy, RuleTarget::Direct, RuleTarget::Block]
                                {
                                    ui.selectable_value(
                                        &mut target,
                                        value,
                                        RichText::new(target_label(value))
                                            .color(target_color(value)),
                                    );
                                }
                            });
                    });
                    if target != rule.target {
                        actions.push(Action::SetRuleTarget(rule.id.clone(), target));
                    }
                    let mut enabled = rule.enabled;
                    if ui
                        .add_enabled(
                            state.can_edit_rules(),
                            egui::Checkbox::without_text(&mut enabled),
                        )
                        .changed()
                    {
                        actions.push(Action::SetRuleEnabled(rule.id.clone(), enabled));
                    }
                    ui.add_space(27.0);
                    let (up, down) = reorder_arrows(
                        index,
                        set.rules.len(),
                        &state.rule_screen.filter,
                        !state.can_edit_rules(),
                    );
                    if icons::icon_button(ui, Icon::Up, up).clicked() {
                        actions.push(Action::MoveRule(rule.id.clone(), index - 1));
                    }
                    if icons::icon_button(ui, Icon::Down, down).clicked() {
                        actions.push(Action::MoveRule(rule.id.clone(), index + 1));
                    }
                    if ui
                        .add_enabled(
                            state.can_edit_rules(),
                            egui::Button::new(strings::REMOVE_RULE),
                        )
                        .clicked()
                    {
                        actions.push(Action::RequestDeleteRule(rule.id.clone()));
                    }
                });
            });
        })
        .response;

    if reorder
        && let Some(dragged_id) = response.dnd_hover_payload::<RuleId>()
        && let Some(from) = set.rules.iter().position(|item| item.id == *dragged_id)
        && let Some(pointer) = ui.ctx().pointer_hover_pos()
    {
        let above = pointer.y < response.rect.center().y;
        let slot = index + usize::from(!above);
        if drop_target(from, slot, set.rules.len()).is_some() {
            let y = if above {
                response.rect.top()
            } else {
                response.rect.bottom()
            };
            ui.painter().line_segment(
                [
                    egui::pos2(response.rect.left(), y),
                    egui::pos2(response.rect.right(), y),
                ],
                Stroke::new(2.0, theme::ROSE),
            );
            if let Some(payload) = response.dnd_release_payload::<RuleId>() {
                actions.push(Action::DropRule((*payload).clone(), slot));
            }
        }
    }
}

fn rule_value(ui: &mut egui::Ui, state: &State, rule: &Rule) {
    if let RuleMatcher::Process(ProcessMatch::Path(path)) = &rule.matcher {
        let filename = path
            .file_name()
            .map(|name| state.text(&name.to_string_lossy()))
            .unwrap_or_else(|| state.text(&rosetun_core::rule_value_text(&rule.matcher)));
        ui.add(egui::Label::new(RichText::new(filename).size(16.0).strong()).wrap());
        if let Some(parent) = path.parent() {
            ui.add(
                egui::Label::new(
                    RichText::new(state.text(&parent.to_string_lossy()))
                        .small()
                        .color(theme::TEXT_DIM),
                )
                .wrap(),
            );
        }
    } else {
        ui.add(egui::Label::new(state.text(&rosetun_core::rule_value_text(&rule.matcher))).wrap());
    }
}

fn default_rule(ui: &mut egui::Ui, state: &State, set: &RuleSet, actions: &mut Vec<Action>) {
    theme::card_frame().show(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(strings::ALL_OTHER_TRAFFIC).strong());
            if set.default_target == RuleTarget::Block {
                ui.colored_label(target_color(RuleTarget::Block), strings::BLOCK);
            }
            for target in [RuleTarget::Proxy, RuleTarget::Direct] {
                let selected = set.default_target == target;
                let label = RichText::new(target_label(target)).color(target_color(target));
                if ui
                    .add_enabled(
                        state.can_edit_rules(),
                        egui::Button::new(label).selected(selected),
                    )
                    .clicked()
                {
                    actions.push(Action::SetDefaultTarget(target));
                }
            }
        });
        ui.colored_label(theme::TEXT_DIM, strings::DEFAULT_RULE_DETAIL);
    });
}

fn rule_type(rule: &Rule) -> &'static str {
    match &rule.matcher {
        RuleMatcher::Domain(DomainMatch::Exact(_) | DomainMatch::Suffix(_)) => strings::DOMAIN,
        RuleMatcher::Domain(DomainMatch::Keyword(_)) => strings::KEYWORD,
        RuleMatcher::Process(_) => strings::PROCESS,
        RuleMatcher::IpCidr(_) => strings::IP,
    }
}

fn target_label(target: RuleTarget) -> &'static str {
    match target {
        RuleTarget::Proxy => strings::PROXY,
        RuleTarget::Direct => strings::DIRECT,
        RuleTarget::Block => strings::BLOCK,
    }
}

fn target_color(target: RuleTarget) -> Color32 {
    match target {
        RuleTarget::Proxy => theme::ROSE_LIGHT,
        RuleTarget::Direct => theme::TEXT_MUTED,
        RuleTarget::Block => theme::ERROR,
    }
}

pub(crate) fn name_dialog(ctx: &egui::Context, state: &mut State, actions: &mut Vec<Action>) {
    let Some(dialog) = &mut state.rule_screen.name else {
        return;
    };
    let busy = state.operations.rules_edit;
    let response = egui::Modal::new(egui::Id::new("rule_set_name"))
        .frame(theme::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(400.0);
            ui.heading(match dialog.kind {
                NameDialogKind::Create => strings::CREATE_RULE_SET,
                NameDialogKind::Rename(_) => strings::RENAME_RULE_SET,
            });
            ui.add_space(12.0);
            ui.label(strings::SET_NAME);
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
                if theme::outline_button(ui, strings::CANCEL, !busy).clicked() {
                    actions.push(Action::CancelSetName);
                }
                let label = match dialog.kind {
                    NameDialogKind::Create => strings::CREATE_RULE_SET,
                    NameDialogKind::Rename(_) => strings::RENAME,
                };
                if theme::button_fill(ui, label, !busy && !dialog.name.trim().is_empty()).clicked()
                {
                    actions.push(Action::SubmitSetName);
                }
            });
        });
    if !busy && response.should_close() {
        actions.push(Action::CancelSetName);
    }
}

pub(crate) fn delete_dialog(ctx: &egui::Context, state: &State, actions: &mut Vec<Action>) {
    let Some(dialog) = &state.rule_screen.delete else {
        return;
    };
    let busy = state.operations.rules_edit;
    let response = egui::Modal::new(egui::Id::new("delete_rules"))
        .frame(theme::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(440.0);
            match dialog {
                DeleteDialog::Set(id) => {
                    ui.heading(strings::DELETE_RULE_SET);
                    if let Some(set) = state.config.rule_sets.iter().find(|set| &set.id == id) {
                        ui.label(state.text(&set.name));
                    }
                    ui.add(egui::Label::new(strings::DELETE_RULE_SET_DETAIL).wrap());
                    if state.config.active_rule_set.as_ref() == Some(id) {
                        ui.add(
                            egui::Label::new(
                                RichText::new(strings::DELETE_ACTIVE_RULE_SET_WARNING)
                                    .color(theme::ERROR),
                            )
                            .wrap(),
                        );
                    }
                }
                DeleteDialog::Rule { set, rule } => {
                    ui.heading(strings::DELETE_RULE);
                    if let Some(rule) = state
                        .config
                        .rule_sets
                        .iter()
                        .find(|item| &item.id == set)
                        .and_then(|set| set.rules.iter().find(|item| &item.id == rule))
                    {
                        ui.label(state.text(&rosetun_core::rule_value_text(&rule.matcher)));
                    }
                    ui.label(strings::DELETE_RULE_DETAIL);
                }
            }
            ui.add_space(18.0);
            ui.horizontal(|ui| {
                if theme::outline_button(ui, strings::CANCEL, !busy).clicked() {
                    actions.push(Action::CancelRuleDelete);
                }
                if theme::button_fill(ui, strings::DELETE, !busy).clicked() {
                    actions.push(Action::ConfirmRuleDelete);
                }
            });
        });
    if !busy && response.should_close() {
        actions.push(Action::CancelRuleDelete);
    }
}
