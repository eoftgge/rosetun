use eframe::egui::{self, Color32, RichText, Stroke};
use rosetun_config::{Exit, Rule, RuleId, RuleMatcher, RuleSet, RuleTarget, RuleTemplate};
use rosetun_core::{NewExit, RuleDestination};

use crate::icons::{self, Icon};
use crate::reorder::group_drop_target;
use crate::rules::{
    RuleCaption, RuleFilter, TypeFilter, rule_counts, rule_counts_slice, rule_lines, visible_rules,
    visible_rules_slice,
};
use crate::state::{Action, NameDialogKind, RulesTab, SessionPart, State, UndoNotice};
use crate::{i18n, theme, widgets};

const HANDLE_WIDTH: f32 = 22.0;
const ICON_WIDTH: f32 = 34.0;
const TARGET_WIDTH: f32 = 150.0;
const TARGET_DOT_X: f32 = 14.0;
const TARGET_DOT_RADIUS: f32 = 3.5;
const TARGET_TEXT_X: f32 = 26.0;
const TARGET_TEXT_OPTICAL_Y: f32 = 1.0;
const TARGET_CHEVRON_SPACE: f32 = 28.0;
const TARGET_MENU_WIDTH: f32 = 240.0;
const TOGGLE_WIDTH: f32 = 38.0;
const MENU_WIDTH: f32 = 32.0;
const ROW_INSET: f32 = theme::space::M;
const HANDLE_GAP: f32 = theme::space::S;
const ICON_GAP: f32 = theme::space::M;
const TARGET_GAP: f32 = theme::space::L;
const MENU_GAP: f32 = theme::space::M;
const TARGET_FILTER_WIDTH: f32 = 166.0;

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "some rectangles are read only by the layout tests"
    )
)]
struct ToolbarRects {
    search: egui::Rect,
    tabs: egui::Rect,
    filter: egui::Rect,
    templates: egui::Rect,
    add: egui::Rect,
    compact_controls: bool,
    two_rows: bool,
}

mod check;
mod dialogs;
pub(crate) mod exchange;
mod selection;
mod sets;
mod table;
mod templates;

pub(crate) use dialogs::{delete_dialog, group_editor_dialog, group_selection_dialog, name_dialog};
use selection::{clear_selection_on_click_away, selection_shortcuts, selection_slot};
use sets::set_controls;
use table::{RowContext, default_rule, rule_row, running_programs, scroll_rules_while_dragging};
#[cfg(test)]
use table::{
    TargetChoice, drag_scroll_delta, drag_target, drop_action, program_icon_path, table_cell,
    target_button, value_cell,
};
pub(crate) use templates::catalog_dialog as templates_catalog_dialog;
#[cfg(test)]
use templates::starter_card;
use templates::starter_section;

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
    ui.add_space(theme::space::XL);
    let shown = widgets::appear_progress(
        ui.ctx(),
        egui::Id::unique("rules_tab_appear"),
        state.lists.tab,
        state.config.interface.reduce_motion,
    );
    widgets::appear(ui, shown, |ui| tab_body(ui, state, actions));
    if state.rules.exchange.notice.is_none() && !undo_notice(ui.ctx(), state, actions) {
        pending_apply_notice(ui.ctx(), state, actions);
    }
}

fn undo_notice(ctx: &egui::Context, state: &State, actions: &mut Vec<Action>) -> bool {
    let Some((notice, left)) = state.rule_notice() else {
        return false;
    };
    ctx.request_repaint_after(left);
    let text = match notice {
        UndoNotice::RulesImported(count) => {
            tr!("rules-transfer-added", count = count, n = count.to_string())
        }
        UndoNotice::RulesDeleted(count) => i18n::rules_deleted(count),
        UndoNotice::SetDeleted => tr!("rule-set-deleted"),
        UndoNotice::RulesMoved(count) => i18n::rules_moved(count),
        UndoNotice::RulesGrouped(count) => i18n::rules_grouped(count),
        UndoNotice::GroupUngrouped(count) => i18n::group_ungrouped(count),
        UndoNotice::Reverted => tr!("rules-reverted"),
    };
    let undo = tr!("undo");
    let apply = tr!("apply");
    let apply_hint = if state.apply_restarts_tunnel() {
        tr!("apply-hint")
    } else {
        tr!("apply-hint-live")
    };
    let mut choices = vec![widgets::NoticeAction {
        label: &undo,
        hint: None,
        enabled: state.can_undo_rules(),
    }];
    if state.can_apply() && state.pending_reconnect(SessionPart::Rules) {
        choices.push(widgets::NoticeAction {
            label: &apply,
            hint: Some(&apply_hint),
            enabled: true,
        });
    }
    match widgets::action_notice(ctx, "rules_undo_notice", &text, &choices) {
        Some(0) => actions.push(Action::UndoRules),
        Some(_) => actions.push(Action::Apply),
        None => {}
    }
    true
}

fn pending_apply_notice(ctx: &egui::Context, state: &State, actions: &mut Vec<Action>) {
    let pending_apply = state.lists.tab == RulesTab::Rules
        && state.config_ready
        && state
            .visible_status()
            .is_some_and(|status| status.state.is_active() || status.state.is_transitional())
        && state.rules.screen.selected_set.is_some()
        && state.config.active_rule_set == state.rules.screen.selected_set
        && state.pending_reconnect(SessionPart::Rules);
    if !pending_apply {
        return;
    }
    let apply_hint = if state.apply_restarts_tunnel() {
        tr!("apply-hint")
    } else {
        tr!("apply-hint-live")
    };
    show_apply_notice(
        ctx,
        state.can_apply(),
        state.can_revert_rules(),
        &apply_hint,
        actions,
    );
}

fn show_apply_notice(
    ctx: &egui::Context,
    can_apply: bool,
    can_revert: bool,
    apply_hint: &str,
    actions: &mut Vec<Action>,
) {
    let text = if can_apply {
        tr!("apply-on-leave")
    } else {
        tr!("next-connect")
    };
    let apply_now = tr!("apply-now");
    let revert = tr!("revert-rules");
    let revert_hint = tr!("revert-rules-hint");
    let mut choices = Vec::new();
    let mut apply_index = None;
    let mut revert_index = None;
    if can_apply {
        apply_index = Some(choices.len());
        choices.push(widgets::NoticeAction {
            label: &apply_now,
            hint: Some(apply_hint),
            enabled: true,
        });
    }
    if can_revert {
        revert_index = Some(choices.len());
        choices.push(widgets::NoticeAction {
            label: &revert,
            hint: Some(&revert_hint),
            enabled: true,
        });
    }
    if let Some(clicked) = widgets::action_notice(ctx, "rules_apply_notice", &text, &choices) {
        if apply_index == Some(clicked) {
            actions.push(Action::Apply);
        } else if revert_index == Some(clicked) {
            actions.push(Action::RevertRules);
        }
    }
}

fn happ_routing_notice(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let Some((name, _)) = &state.lists.pending_happ_routing else {
        return;
    };
    let importing = state.lists.importing_happ_routing;
    widgets::card_frame()
        .stroke(Stroke::new(
            theme::stroke::HAIRLINE,
            theme::palette().accent_light,
        ))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            egui::Sides::new().shrink_left().wrap().show(
                ui,
                |ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(tr!("happ-routing-offer", name = name.as_str())).strong(),
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(tr!("happ-routing-offer-detail"))
                                    .small()
                                    .color(theme::palette().text_muted),
                            )
                            .wrap(),
                        );
                    });
                },
                |ui| {
                    ui.horizontal(|ui| {
                        let import_label = if importing {
                            tr!("happ-routing-importing")
                        } else {
                            tr!("happ-routing-import")
                        };
                        if widgets::button_fill(ui, import_label, !importing).clicked() {
                            actions.push(Action::ImportHappRouting);
                        }
                        if widgets::outline_button(ui, tr!("hide-details"), !importing).clicked() {
                            actions.push(Action::DismissHappRouting);
                        }
                    });
                },
            );
        });
    ui.add_space(theme::space::M);
}

fn tab_body(ui: &mut egui::Ui, state: &mut State, actions: &mut Vec<Action>) {
    match state.lists.tab {
        RulesTab::Rules => {}
        RulesTab::Lists => return super::lists::show(ui, state, actions),
        RulesTab::Exits => return super::exits::show(ui, state, actions),
    }
    let text_edit_focused = ui.ctx().text_edit_focused();
    let reveal = std::mem::take(&mut state.rules.screen.reveal_selection);
    ui.heading(tr!("rules-tab-title"));
    ui.add(
        egui::Label::new(RichText::new(tr!("rules-subtitle")).color(theme::palette().text_muted))
            .wrap(),
    );
    ui.add_space(theme::space::XL);
    if !state.config_ready {
        ui.colored_label(theme::palette().text_dim, tr!("loading"));
        return;
    }
    happ_routing_notice(ui, state, actions);
    if state.config.rule_sets.is_empty() {
        ui.colored_label(theme::palette().text_muted, tr!("no-rule-sets"));
        ui.add_space(theme::space::M);
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
    let check_line = state.rule_check();
    let mut selection_regions = Vec::new();
    let slot = selection_slot(ui, state, check_line, actions);
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
        ui.colored_label(theme::palette().text_muted, tr!("no-rules-match"));
    }
    let unresolved = crate::destinations::unresolved_exits(&state.config);
    let rows = RowContext {
        set,
        target_choices: table::rule_target_choices(&state.config),
        unresolved: &unresolved,
        running: running_programs(state),
    };
    let reduce_motion = state.config.interface.reduce_motion;
    let filter_active = state.rules.screen.filter.is_active();
    let rule_ids: Vec<RuleId> = visible.iter().map(|(_, rule)| rule.id.clone()).collect();
    let motion_id = ui.scope_id().with(("rules_list_motion", set.id.as_str()));
    let frame_nr = ui.ctx().cumulative_frame_nr();
    let now = ui.ctx().input(|input| input.time);
    let mut list_motion = ui
        .ctx()
        .data_mut(|data| data.get_temp::<RulesListMotion>(motion_id))
        .unwrap_or_default();
    list_motion.sync(frame_nr, now, &rule_ids, filter_active, reduce_motion);
    let mut any_motion = false;
    let mut measured_pitch: Option<f32> = None;
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.y = theme::space::S;
        for (_, rule) in visible_temporary {
            ui.push_id(("temporary", rule.id.as_str()), |ui| {
                rule_row(ui, state, &rows, rule, None, value_width, actions);
            });
        }
        for (index, rule) in visible {
            let (slide_dy, sliding) = list_motion.slide_offset(&rule.id, now, reduce_motion);
            any_motion |= sliding;
            let layer = ui.layer_id();
            let start_shape = (slide_dy.abs() > 0.25).then(|| {
                ui.ctx().graphics(|graphics| {
                    graphics
                        .get(layer)
                        .map_or(egui::layers::ShapeIdx(0), egui::layers::PaintList::next_idx)
                })
            });
            let row = ui.push_id((set.id.as_str(), rule.id.as_str()), |ui| {
                rule_row(ui, state, &rows, rule, Some(index), value_width, actions);
            });
            let group_expanded = matches!(rule.matcher, RuleMatcher::Group { .. })
                && state.rules.screen.expanded_groups.contains(&rule.id);
            if !group_expanded && row.response.rect.height() > 0.0 {
                measured_pitch = Some(row.response.rect.height() + theme::space::S);
            }
            if let Some(start_shape) = start_shape {
                let shift = egui::emath::TSTransform::from_translation(egui::vec2(0.0, slide_dy));
                ui.ctx().graphics_mut(|graphics| {
                    let list = graphics.entry(layer);
                    let end_shape = list.next_idx();
                    list.transform_range(start_shape, end_shape, shift);
                });
            }
            if reveal && state.rules.screen.selection_anchor.as_ref() == Some(&rule.id) {
                row.response.scroll_to_me(None);
            }
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
        if set.rules.is_empty() && temporary.is_empty() {
            starter_section(ui, state, set, actions);
        }
        default_rule(ui, state, set, value_width, actions);
    });
    if let Some(pitch) = measured_pitch {
        list_motion.row_pitch = pitch;
    }
    ui.ctx()
        .data_mut(|data| data.insert_temp(motion_id, list_motion));
    if any_motion {
        ui.ctx().request_repaint();
    }
    scroll_rules_while_dragging(ui);
    clear_selection_on_click_away(ui.ctx(), state, &selection_regions, actions);
    selection_shortcuts(ui.ctx(), state, text_edit_focused, actions);
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
    let side = widgets::field_height(ui);
    let add_label = tr!("new-rule-button");
    let add_icon_label = tr!("new-rule");
    let templates_label = tr!("templates-button");
    let button_width = |label: &str| {
        ui.painter()
            .layout_no_wrap(
                label.to_owned(),
                egui::TextStyle::Button.resolve(ui.style()),
                theme::palette().text,
            )
            .size()
            .x
            + 2.0 * ui.spacing().button_padding.x
            + 16.0
    };
    let add_width = button_width(&add_label);
    let templates_width = button_width(&templates_label);
    let available = ui.available_width();
    let tabs_width = widgets::segmented_width(ui, &options);
    let compact_controls = widgets::SEARCH_WIDTH
        + tabs_width
        + TARGET_FILTER_WIDTH
        + templates_width
        + add_width
        + 4.0 * gap
        > available;
    let compact_beside = tabs_width + 3.0 * side + 4.0 * gap;
    let two_rows = compact_controls && widgets::MIN_SEARCH_WIDTH + compact_beside > available;
    let plain_labels;
    let options = if two_rows && tabs_width + widgets::MIN_SEARCH_WIDTH + gap > available {
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
        templates: egui::Rect::NOTHING,
        add: egui::Rect::NOTHING,
        compact_controls,
        two_rows,
    };
    let mut open_templates = false;
    let mut add_rule = false;
    let templates_button = |ui: &mut egui::Ui| {
        if compact_controls {
            widgets::outline_button_icon(ui, Icon::Sparkle, &templates_label, true)
        } else {
            widgets::outline_button(ui, templates_label.as_str(), true)
        }
    };
    let add_button = |ui: &mut egui::Ui| {
        if compact_controls {
            widgets::button_fill_icon(ui, Icon::Plus, &add_icon_label, can_add)
        } else {
            widgets::button_fill(ui, add_label.as_str(), can_add)
        }
    };
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
            rects.filter = target_filter(ui, filter, exits, compact_controls, actions).rect;
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let response = add_button(ui);
                rects.add = response.rect;
                add_rule = response.clicked();
                let response = templates_button(ui);
                rects.templates = response.rect;
                open_templates = response.clicked();
            });
        });
    } else {
        let search_width = if compact_controls {
            (available - compact_beside).clamp(widgets::MIN_SEARCH_WIDTH, widgets::SEARCH_WIDTH)
        } else {
            widgets::SEARCH_WIDTH
        };
        ui.horizontal(|ui| {
            primary(ui, search_width, filter, &mut rects, actions);
            rects.filter = target_filter(ui, filter, exits, compact_controls, actions).rect;
            let response = templates_button(ui);
            rects.templates = response.rect;
            open_templates = response.clicked();
            let response = add_button(ui);
            rects.add = response.rect;
            add_rule = response.clicked();
        });
    }
    if open_templates {
        actions.push(Action::OpenTemplatesCatalog);
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
    compact: bool,
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
    let active_color = selected.map(target_color);
    let selected_text = selected_label.clone().zip(selected).map_or_else(
        || RichText::new(tr!("any-action")),
        |(label, target)| RichText::new(label).color(target_color(target)),
    );
    let hover = selected_label.unwrap_or_else(|| tr!("any-action"));
    let mut menu = |ui: &mut egui::Ui| {
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
            let label = RichText::new(exit_label(&exit.id)).color(target_color(RuleTarget::Exit));
            if ui.selectable_label(picked, label).clicked() {
                selected = Some(RuleTarget::Exit);
                selected_exit = Some(exit.id.clone());
            }
        }
    };
    let response = if compact {
        widgets::filter_combo_icon(
            ui,
            "rule_target_filter",
            TARGET_FILTER_WIDTH,
            active_color,
            hover,
            &mut menu,
        )
    } else {
        widgets::filter_combo(
            ui,
            "rule_target_filter",
            TARGET_FILTER_WIDTH,
            selected_text,
            hover,
            &mut menu,
        )
    };
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
        RuleTarget::Proxy => theme::palette().accent_light,
        RuleTarget::Direct => theme::palette().text_muted,
        RuleTarget::Block => theme::error(),
        RuleTarget::Exit => theme::exit(),
    }
}

/// "Through VPN • <exit name>" for an exit, the plain target's word otherwise.
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

const MAX_RULE_SLIDE_ROWS: f32 = 4.0;

#[derive(Clone, Default)]
struct RulesListMotion {
    last_frame: u64,
    row_pitch: f32,
    indices: std::collections::HashMap<RuleId, usize>,
    slides: std::collections::HashMap<RuleId, (f32, f64)>,
}

impl RulesListMotion {
    fn sync(
        &mut self,
        frame: u64,
        now: f64,
        keys: &[RuleId],
        filter_active: bool,
        reduce_motion: bool,
    ) {
        if self.last_frame == frame {
            return;
        }
        if self.last_frame == 0 || self.last_frame + 1 < frame || filter_active || reduce_motion {
            self.slides.clear();
            self.indices.clear();
            self.indices
                .extend(keys.iter().enumerate().map(|(i, k)| (k.clone(), i)));
            self.last_frame = frame;
            return;
        }

        let pitch = if self.row_pitch > 0.0 {
            self.row_pitch
        } else {
            theme::RULE_ROW + theme::space::S
        };
        let max_slide = pitch * MAX_RULE_SLIDE_ROWS;
        let present: std::collections::HashSet<&RuleId> = keys.iter().collect();
        self.slides.retain(|k, (_, started)| {
            present.contains(k) && now - *started < f64::from(crate::motion::FAST)
        });

        for (idx, key) in keys.iter().enumerate() {
            if let Some(&prev_idx) = self.indices.get(key)
                && prev_idx != idx
            {
                let current_dy = self.slide_offset(key, now, false).0;
                let delta = (prev_idx as f32 - idx as f32) * pitch;
                let start_dy = (current_dy + delta).clamp(-max_slide, max_slide);
                self.slides.insert(key.clone(), (start_dy, now));
            }
        }

        self.indices.clear();
        self.indices
            .extend(keys.iter().enumerate().map(|(i, k)| (k.clone(), i)));
        self.last_frame = frame;
    }

    fn slide_offset(&self, key: &RuleId, now: f64, reduce_motion: bool) -> (f32, bool) {
        if reduce_motion {
            return (0.0, false);
        }
        if let Some(&(start_dy, started)) = self.slides.get(key) {
            let t = ((now - started).max(0.0) / f64::from(crate::motion::FAST)) as f32;
            if t < 1.0 {
                let dy = start_dy * (1.0 - crate::motion::ease_out(t));
                return (dy, true);
            }
        }
        (0.0, false)
    }
}

#[cfg(test)]
mod tests;
