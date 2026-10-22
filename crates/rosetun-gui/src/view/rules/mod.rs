use eframe::egui::{self, Color32, RichText, Stroke};
use rosetun_config::{Exit, Rule, RuleId, RuleMatcher, RuleSet, RuleTarget, RuleTemplate};
use rosetun_core::{NewExit, RuleDestination};

use crate::icons::{self, Icon};
use crate::reorder::group_drop_target;
use crate::rules::{
    RuleCaption, RuleFilter, TypeFilter, rule_counts, rule_counts_slice, rule_lines, visible_rules,
    visible_rules_slice,
};
use crate::state::{Action, DeleteDialog, NameDialogKind, RulesTab, SessionPart, State};
use crate::{i18n, theme, widgets};

const HANDLE_WIDTH: f32 = 22.0;
const ICON_WIDTH: f32 = 34.0;
const TARGET_WIDTH: f32 = 150.0;
const TARGET_DOT_X: f32 = 14.0;
const TARGET_TEXT_X: f32 = 26.0;
const TARGET_CHEVRON_SPACE: f32 = 28.0;
const TARGET_MENU_WIDTH: f32 = 240.0;
const TOGGLE_WIDTH: f32 = 38.0;
const MENU_WIDTH: f32 = 32.0;
const ROW_INSET: f32 = 12.0;
const HANDLE_GAP: f32 = 10.0;
const ICON_GAP: f32 = 12.0;
const TARGET_GAP: f32 = 16.0;
const MENU_GAP: f32 = 12.0;
const TARGET_FILTER_WIDTH: f32 = 166.0;

#[cfg_attr(not(test), expect(dead_code, reason = "some rectangles are read only by the layout tests"))]
struct ToolbarRects {
    search: egui::Rect,
    tabs: egui::Rect,
    filter: egui::Rect,
    add: egui::Rect,
    two_rows: bool,
}

mod dialogs;
mod selection;
mod sets;
mod table;
mod templates;

pub(crate) use dialogs::{delete_dialog, name_dialog};
use selection::{clear_selection_on_click_away, selection_shortcuts, selection_slot};
use sets::set_controls;
use table::{RowContext, default_rule, rule_row, scroll_rules_while_dragging};
#[cfg(test)]
use table::{
    TargetChoice, drag_scroll_delta, drag_target, drop_action, table_cell, target_button,
    value_cell,
};
#[cfg(test)]
use templates::template_card;
use templates::template_section;

fn set_controls_visible(state: &State) -> bool {
    state.lists.tab == RulesTab::Rules && state.config_ready && state.selected_rules().is_some()
}

pub(crate) fn show(ui: &mut egui::Ui, state: &mut State, actions: &mut Vec<Action>) {
    let mut selected_tab = None;
    egui::Sides::new().shrink_left().show(
        ui,
        |ui| {
            if let Some(tab) = widgets::segmented(
                ui,
                "rules_lists_tab",
                state.lists.tab,
                &[
                    (RulesTab::Rules, tr!("rules")),
                    (RulesTab::Lists, tr!("lists-title")),
                    (RulesTab::Exits, tr!("exits-title")),
                ],
                false,
                true,
            ) {
                selected_tab = Some(match tab {
                    RulesTab::Rules => Action::ShowRuleSets,
                    RulesTab::Lists => Action::ShowLists,
                    RulesTab::Exits => Action::ShowExits,
                });
            }
        },
        |ui| {
            if set_controls_visible(state) {
                set_controls(ui, state, actions);
            }
        },
    );
    if let Some(action) = selected_tab {
        actions.push(action);
    }
    ui.add_space(20.0);
    match state.lists.tab {
        RulesTab::Rules => {}
        RulesTab::Lists => return super::lists::show(ui, state, actions),
        RulesTab::Exits => return super::exits::show(ui, state, actions),
    }
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
    ui.heading(tr!("rules-tab-title"));
    ui.add(egui::Label::new(RichText::new(tr!("rules-subtitle")).color(theme::TEXT_MUTED)).wrap());
    if pending_apply {
        ui.add_space(6.0);
        let (_, link) = apply_notice(ui, can_apply);
        apply_clicked = link.is_some_and(|link| link.clicked());
    }
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
        &state.config.exits,
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
    let unresolved = crate::destinations::unresolved_exits(&state.config);
    let rows = RowContext {
        set,
        unresolved: &unresolved,
    };
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.y = 6.0;
        for (_, rule) in visible_temporary {
            ui.push_id(("temporary", rule.id.as_str()), |ui| {
                rule_row(ui, state, &rows, rule, None, value_width, actions);
            });
        }
        for (index, rule) in visible {
            let row = ui.push_id((set.id.as_str(), rule.id.as_str()), |ui| {
                rule_row(ui, state, &rows, rule, Some(index), value_width, actions);
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
    exits: &[Exit],
    set: &RuleSet,
    temporary: &[Rule],
    can_add: bool,
    actions: &mut Vec<Action>,
) -> ToolbarRects {
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
    let gap = ui.spacing().item_spacing.x;
    let add_label = tr!("new-rule-button");
    let add_width = ui
        .painter()
        .layout_no_wrap(
            add_label.clone(),
            egui::TextStyle::Button.resolve(ui.style()),
            theme::TEXT,
        )
        .size()
        .x
        + 2.0 * ui.spacing().button_padding.x
        + 16.0;
    let available = ui.available_width();
    let two_rows = widgets::SEARCH_WIDTH
        + widgets::segmented_width(ui, &options)
        + TARGET_FILTER_WIDTH
        + add_width
        + 3.0 * gap
        > available;
    let plain_labels;
    let options = if two_rows
        && widgets::segmented_width(ui, &options) + widgets::MIN_SEARCH_WIDTH + gap > available
    {
        plain_labels = labels
            .iter()
            .map(|(kind, _)| {
                (
                    *kind,
                    match kind {
                        TypeFilter::All => tr!("all"),
                        TypeFilter::Domains => tr!("domains"),
                        TypeFilter::Processes => tr!("processes"),
                        TypeFilter::Other => tr!("other"),
                    },
                )
            })
            .collect::<Vec<_>>();
        plain_labels
            .iter()
            .map(|(kind, label)| (*kind, label.as_str()))
            .collect::<Vec<_>>()
    } else {
        options
    };
    let mut rects = ToolbarRects {
        search: egui::Rect::NOTHING,
        tabs: egui::Rect::NOTHING,
        filter: egui::Rect::NOTHING,
        add: egui::Rect::NOTHING,
        two_rows,
    };
    let mut add_rule = false;
    let primary = |ui: &mut egui::Ui,
                   search_width: f32,
                   filter: &mut RuleFilter,
                   rects: &mut ToolbarRects,
                   actions: &mut Vec<Action>| {
        rects.search =
            widgets::search_field(ui, &mut filter.search, &tr!("search-rules"), search_width).rect;
        rects.tabs = ui
            .scope(|ui| {
                if let Some(kind) =
                    widgets::segmented(ui, "rule_type_filter", filter.kind, &options, false, true)
                {
                    actions.push(Action::SetRuleTypeFilter(kind));
                }
            })
            .response
            .rect;
    };
    if two_rows {
        let search_width = widgets::search_width_beside(ui, widgets::segmented_width(ui, &options));
        ui.horizontal(|ui| primary(ui, search_width, filter, &mut rects, actions));
        ui.horizontal(|ui| {
            rects.filter = target_filter(ui, filter, exits, actions).rect;
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let response = widgets::button_fill(ui, add_label, can_add);
                rects.add = response.rect;
                add_rule = response.clicked();
            });
        });
    } else {
        ui.horizontal(|ui| {
            primary(ui, widgets::SEARCH_WIDTH, filter, &mut rects, actions);
            rects.filter = target_filter(ui, filter, exits, actions).rect;
            let response = widgets::button_fill(ui, add_label, can_add);
            rects.add = response.rect;
            add_rule = response.clicked();
        });
    }
    if add_rule {
        actions.push(Action::OpenAddRule);
    }
    rects
}

fn target_filter(
    ui: &mut egui::Ui,
    filter: &RuleFilter,
    exits: &[Exit],
    actions: &mut Vec<Action>,
) -> egui::Response {
    let mut selected = filter.target;
    let mut selected_exit = filter.exit.clone();
    let exit_label =
        |id: &rosetun_config::ExitId| destination_label(&RuleDestination::Exit(id.clone()), exits);
    let selected_label = match (&selected_exit, selected) {
        (Some(id), _) => Some(exit_label(id)),
        (None, Some(target)) => Some(target_label(target)),
        (None, None) => None,
    };
    let selected_text = selected_label
        .clone()
        .zip(selected)
        .map(|(label, target)| RichText::new(label).color(target_color(target)))
        .unwrap_or_else(|| RichText::new(tr!("any-action")));
    let response = widgets::filter_combo(
        ui,
        "rule_target_filter",
        TARGET_FILTER_WIDTH,
        selected_text,
        selected_label.unwrap_or_else(|| tr!("any-action")),
        |ui| {
            if ui
                .selectable_label(selected.is_none(), tr!("any-action"))
                .clicked()
            {
                selected = None;
                selected_exit = None;
            }
            for target in [
                RuleTarget::Proxy,
                RuleTarget::Direct,
                RuleTarget::Block,
                RuleTarget::Exit,
            ] {
                let picked = selected == Some(target) && selected_exit.is_none();
                let label = RichText::new(target_label(target)).color(target_color(target));
                if ui.selectable_label(picked, label).clicked() {
                    selected = Some(target);
                    selected_exit = None;
                }
            }
            for exit in exits {
                let picked = selected_exit.as_ref() == Some(&exit.id);
                let label =
                    RichText::new(exit_label(&exit.id)).color(target_color(RuleTarget::Exit));
                if ui.selectable_label(picked, label).clicked() {
                    selected = Some(RuleTarget::Exit);
                    selected_exit = Some(exit.id.clone());
                }
            }
        },
    );
    if selected_exit != filter.exit || selected != filter.target {
        actions.push(match selected_exit {
            Some(exit) => Action::SetRuleExitFilter(exit),
            None => Action::SetRuleTargetFilter(selected),
        });
    }
    response
}

pub(crate) fn target_label(target: RuleTarget) -> String {
    match target {
        RuleTarget::Proxy => tr!("proxy"),
        RuleTarget::Direct => tr!("direct"),
        RuleTarget::Block => tr!("block"),
        RuleTarget::Exit => tr!("target-exit-any"),
    }
}

pub(crate) fn target_color(target: RuleTarget) -> Color32 {
    match target {
        RuleTarget::Proxy => theme::ROSE_LIGHT,
        RuleTarget::Direct => theme::TEXT_MUTED,
        RuleTarget::Block => theme::ERROR,
        RuleTarget::Exit => theme::EXIT,
    }
}

/// "Through VPN · <exit name>" for an exit, the plain target's word otherwise.
pub(crate) fn destination_label(destination: &RuleDestination, exits: &[Exit]) -> String {
    let name = match destination {
        RuleDestination::Proxy => return target_label(RuleTarget::Proxy),
        RuleDestination::Direct => return target_label(RuleTarget::Direct),
        RuleDestination::Block => return target_label(RuleTarget::Block),
        RuleDestination::Exit(id) => match exits.iter().find(|exit| &exit.id == id) {
            Some(exit) => &exit.name,
            None => return target_label(RuleTarget::Exit),
        },
        RuleDestination::NewExit(NewExit::Country { name, .. } | NewExit::Node { name, .. }) => {
            name
        }
    };
    tr!("target-exit", name = crate::display::safe_text(name))
}

pub(crate) fn destination_color(destination: &RuleDestination) -> Color32 {
    match destination {
        RuleDestination::Proxy => target_color(RuleTarget::Proxy),
        RuleDestination::Direct => target_color(RuleTarget::Direct),
        RuleDestination::Block => target_color(RuleTarget::Block),
        RuleDestination::Exit(_) | RuleDestination::NewExit(_) => target_color(RuleTarget::Exit),
    }
}

pub(crate) fn rule_label(rule: &Rule, exits: &[Exit]) -> String {
    destination_label(&RuleDestination::of(rule), exits)
}

#[cfg(test)]
mod tests;
