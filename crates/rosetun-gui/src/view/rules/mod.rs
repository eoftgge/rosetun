use eframe::egui::{self, Color32, RichText, Stroke};
use rosetun_config::{Rule, RuleId, RuleMatcher, RuleSet, RuleTarget, RuleTemplate};

use crate::icons::{self, Icon};
use crate::reorder::group_drop_target;
use crate::rules::{
    RuleCaption, RuleFilter, TypeFilter, rule_counts, rule_counts_slice, rule_lines, visible_rules,
    visible_rules_slice,
};
use crate::state::{Action, DeleteDialog, NameDialogKind, SessionPart, State};
use crate::{i18n, theme, widgets};

const HANDLE_WIDTH: f32 = 22.0;
const ICON_WIDTH: f32 = 34.0;
const TARGET_WIDTH: f32 = 150.0;
const TARGET_DOT_X: f32 = 14.0;
const TARGET_TEXT_X: f32 = 26.0;
const TOGGLE_WIDTH: f32 = 38.0;
const MENU_WIDTH: f32 = 32.0;
const ROW_INSET: f32 = 12.0;
const HANDLE_GAP: f32 = 10.0;
const ICON_GAP: f32 = 12.0;
const TARGET_GAP: f32 = 16.0;
const MENU_GAP: f32 = 12.0;

mod dialogs;
mod selection;
mod sets;
mod table;
mod templates;

pub(crate) use dialogs::{delete_dialog, name_dialog};
use selection::{clear_selection_on_click_away, selection_shortcuts, selection_slot};
use sets::set_controls;
use table::{default_rule, rule_row, scroll_rules_while_dragging};
#[cfg(test)]
use table::{drag_scroll_delta, drag_target, drop_action, table_cell, target_button, value_cell};
#[cfg(test)]
use templates::template_card;
use templates::template_section;

pub(crate) fn show(ui: &mut egui::Ui, state: &mut State, actions: &mut Vec<Action>) {
    let text_edit_focused = ui.ctx().text_edit_focused();
    let pending_apply = state.config_ready
        && state
            .visible_status()
            .is_some_and(|status| status.state.is_active() || status.state.is_transitional())
        && state.rules.screen.selected_set.is_some()
        && state.config.active_rule_set == state.rules.screen.selected_set
        && state.pending_reconnect(SessionPart::Rules);
    let can_apply = state.can_apply();
    let mut apply_clicked = false;
    egui::Sides::new().shrink_left().wrap().show(
        ui,
        |ui| {
            ui.vertical(|ui| {
                ui.heading(tr!("rules-tab-title"));
                ui.add(
                    egui::Label::new(RichText::new(tr!("rules-subtitle")).color(theme::TEXT_MUTED))
                        .wrap(),
                );
                if pending_apply {
                    ui.add_space(6.0);
                    let (_, link) = apply_notice(ui, can_apply);
                    apply_clicked = link.is_some_and(|link| link.clicked());
                }
            });
        },
        |ui| {
            if state.config_ready && !state.config.rule_sets.is_empty() {
                set_controls(ui, state, actions);
            }
        },
    );
    if apply_clicked {
        actions.push(Action::Apply);
    }
    ui.add_space(20.0);
    if !state.config_ready {
        ui.colored_label(theme::TEXT_DIM, tr!("loading"));
        return;
    }
    if state.config.rule_sets.is_empty() {
        ui.colored_label(theme::TEXT_MUTED, tr!("no-rule-sets"));
        ui.add_space(12.0);
        if widgets::button_fill(ui, tr!("create-rule-set"), state.can_edit_rules()).clicked() {
            actions.push(Action::OpenCreateSet);
        }
        return;
    }

    let Some(set) = state
        .config
        .rule_sets
        .iter()
        .find(|item| state.rules.screen.selected_set.as_ref() == Some(&item.id))
    else {
        widgets::button_fill(ui, tr!("new-rule-button"), false);
        return;
    };
    template_section(ui, state, set, actions);
    ui.add_space(20.0);
    let temporary = if state.config.active_rule_set.as_ref() == Some(&set.id) {
        state.session.temporary_rules.as_slice()
    } else {
        &[]
    };
    let can_add = state.can_edit_rules();
    let search_before = state.rules.screen.filter.search.clone();
    filter_controls(
        ui,
        &mut state.rules.screen.filter,
        set,
        temporary,
        can_add,
        actions,
    );
    if state.rules.screen.filter.search != search_before {
        actions.push(Action::ClearRuleSelection);
    }
    let mut selection_regions = Vec::new();
    let slot = selection_slot(ui, state, actions);
    if state.rules.screen.selected_rules.len() >= 2 {
        selection_regions.push(slot.rect);
    }

    let visible_temporary = visible_rules_slice(temporary, &state.rules.screen.filter);
    let visible = visible_rules(set, &state.rules.screen.filter);
    let value_width = (ui.available_width()
        - 2.0 * ROW_INSET
        - HANDLE_WIDTH
        - HANDLE_GAP
        - ICON_WIDTH
        - ICON_GAP
        - TARGET_WIDTH
        - TARGET_GAP
        - TOGGLE_WIDTH
        - MENU_GAP
        - MENU_WIDTH)
        .max(0.0);
    if visible.is_empty()
        && visible_temporary.is_empty()
        && (!set.rules.is_empty() || !temporary.is_empty())
    {
        ui.colored_label(theme::TEXT_MUTED, tr!("no-rules-match"));
    }
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.y = 6.0;
        for (_, rule) in visible_temporary {
            ui.push_id(("temporary", rule.id.as_str()), |ui| {
                rule_row(ui, state, set, rule, None, value_width, actions);
            });
        }
        for (index, rule) in visible {
            let row = ui.push_id((set.id.as_str(), rule.id.as_str()), |ui| {
                rule_row(ui, state, set, rule, Some(index), value_width, actions);
            });
            if state.rules.screen.selected_rules.contains(&rule.id) {
                let rect = row.response.rect;
                selection_regions.push(egui::Rect::from_min_max(
                    rect.min,
                    egui::pos2(
                        rect.left() + ROW_INSET + HANDLE_WIDTH + HANDLE_GAP,
                        rect.bottom(),
                    ),
                ));
                selection_regions.push(egui::Rect::from_min_max(
                    egui::pos2(rect.right() - ROW_INSET - MENU_WIDTH - MENU_GAP, rect.top()),
                    rect.max,
                ));
            }
        }
        default_rule(ui, state, set, value_width, actions);
    });
    scroll_rules_while_dragging(ui);
    clear_selection_on_click_away(ui.ctx(), state, &selection_regions, actions);
    selection_shortcuts(ui.ctx(), state, text_edit_focused, actions);
}

fn apply_notice(ui: &mut egui::Ui, can_apply: bool) -> (egui::Response, Option<egui::Response>) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        let (dot, _) = ui.allocate_exact_size(egui::vec2(6.0, 6.0), egui::Sense::hover());
        ui.painter()
            .circle_filled(dot.center(), 3.0, theme::ROSE_LIGHT);
        let text = if can_apply {
            tr!("apply-on-leave")
        } else {
            tr!("next-connect")
        };
        let label = ui.label(RichText::new(text).small().color(theme::TEXT_MUTED));
        let link = can_apply
            .then(|| widgets::link(ui, &tr!("apply-now"), true).on_hover_text(tr!("apply-hint")));
        (label, link)
    })
    .inner
}

fn filter_controls(
    ui: &mut egui::Ui,
    filter: &mut RuleFilter,
    set: &RuleSet,
    temporary: &[Rule],
    can_add: bool,
    actions: &mut Vec<Action>,
) {
    let mut counts = rule_counts(set);
    let extra = rule_counts_slice(temporary);
    counts.domains += extra.domains;
    counts.processes += extra.processes;
    counts.other += extra.other;
    let labels: Vec<_> = [
        (TypeFilter::All, tr!("all"), counts.all()),
        (TypeFilter::Domains, tr!("domains"), counts.domains),
        (TypeFilter::Processes, tr!("processes"), counts.processes),
        (TypeFilter::Other, tr!("other"), counts.other),
    ]
    .into_iter()
    .filter(|(kind, _, count)| *kind != TypeFilter::Other || *count != 0)
    .map(|(kind, label, count)| (kind, i18n::filter_count(&label, count)))
    .collect();
    let options: Vec<_> = labels
        .iter()
        .map(|(kind, label)| (*kind, label.as_str()))
        .collect();
    let (_, add_rule) = egui::Sides::new().shrink_left().wrap().show(
        ui,
        |ui| {
            ui.horizontal_wrapped(|ui| {
                widgets::search_field(ui, &mut filter.search, &tr!("search-rules"), 260.0);
                if let Some(kind) =
                    widgets::segmented(ui, "rule_type_filter", filter.kind, &options, false, true)
                {
                    actions.push(Action::SetRuleTypeFilter(kind));
                }
                target_filter(ui, filter, actions);
            });
        },
        |ui| widgets::button_fill(ui, tr!("new-rule-button"), can_add).clicked(),
    );
    if add_rule {
        actions.push(Action::OpenAddRule);
    }
}

fn target_filter(
    ui: &mut egui::Ui,
    filter: &RuleFilter,
    actions: &mut Vec<Action>,
) -> egui::Response {
    let mut selected = filter.target;
    let response = ui
        .scope(|ui| {
            ui.spacing_mut().button_padding.y = 6.0;
            ui.spacing_mut().interact_size.y = 38.0;
            let visuals = &mut ui.visuals_mut().widgets;
            visuals.inactive.weak_bg_fill = theme::INPUT;
            visuals.hovered.weak_bg_fill = theme::BORDER;
            let border = Stroke::new(1.0, theme::BORDER_STRONG);
            visuals.inactive.bg_stroke = border;
            visuals.hovered.bg_stroke = border;
            visuals.open.bg_stroke = border;
            let selected_text = selected
                .map(|target| RichText::new(target_label(target)).color(target_color(target)))
                .unwrap_or_else(|| RichText::new(tr!("any-action")));
            egui::ComboBox::from_id_salt("rule_target_filter")
                .width(166.0)
                .selected_text(selected_text)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut selected, None, tr!("any-action"));
                    for target in [RuleTarget::Proxy, RuleTarget::Direct, RuleTarget::Block] {
                        ui.selectable_value(
                            &mut selected,
                            Some(target),
                            RichText::new(target_label(target)).color(target_color(target)),
                        );
                    }
                })
                .response
        })
        .inner;
    if selected != filter.target {
        actions.push(Action::SetRuleTargetFilter(selected));
    }
    response
}

pub(crate) fn target_label(target: RuleTarget) -> String {
    match target {
        RuleTarget::Proxy => tr!("proxy"),
        RuleTarget::Direct => tr!("direct"),
        RuleTarget::Block => tr!("block"),
    }
}

pub(crate) fn target_color(target: RuleTarget) -> Color32 {
    match target {
        RuleTarget::Proxy => theme::ROSE_LIGHT,
        RuleTarget::Direct => theme::TEXT_MUTED,
        RuleTarget::Block => theme::ERROR,
    }
}

#[cfg(test)]
mod tests;
