use eframe::egui::{self, Color32, RichText, Stroke};
use rosetun_config::{Rule, RuleId, RuleMatcher, RuleSet, RuleTarget, RuleTemplate};

use crate::icons::{self, Icon};
use crate::reorder::group_drop_target;
use crate::rules::{
    RuleCaption, RuleFilter, TypeFilter, rule_counts, rule_counts_slice, rule_lines, visible_rules,
    visible_rules_slice,
};
use crate::state::{Action, DeleteDialog, NameDialogKind, SessionPart, State};
use crate::strings::t;
use crate::{strings, theme, widgets};

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

pub(crate) fn show(ui: &mut egui::Ui, state: &mut State, actions: &mut Vec<Action>) {
    let text_edit_focused = ui.ctx().text_edit_focused();
    egui::Sides::new().shrink_left().wrap().show(
        ui,
        |ui| {
            ui.vertical(|ui| {
                ui.heading(t().rules_tab_title);
                ui.add(
                    egui::Label::new(RichText::new(t().rules_subtitle).color(theme::TEXT_MUTED))
                        .wrap(),
                );
            });
        },
        |ui| {
            if state.config_ready && !state.config.rule_sets.is_empty() {
                set_controls(ui, state, actions);
            }
        },
    );
    ui.add_space(20.0);
    if !state.config_ready {
        ui.colored_label(theme::TEXT_DIM, t().loading);
        return;
    }
    if state.config.rule_sets.is_empty() {
        ui.colored_label(theme::TEXT_MUTED, t().no_rule_sets);
        ui.add_space(12.0);
        if widgets::button_fill(ui, t().create_rule_set, state.can_edit_rules()).clicked() {
            actions.push(Action::OpenCreateSet);
        }
        return;
    }

    let Some(set) = state
        .config
        .rule_sets
        .iter()
        .find(|item| state.rule_screen.selected_set.as_ref() == Some(&item.id))
    else {
        widgets::button_fill(ui, t().new_rule_button, false);
        return;
    };
    if state
        .visible_status()
        .is_some_and(|status| status.state.is_active() || status.state.is_transitional())
        && state.config.active_rule_set.as_ref() == Some(&set.id)
        && state.pending_reconnect(SessionPart::Rules)
    {
        widgets::card_frame()
            .inner_margin(egui::Margin::symmetric(16, 8))
            .show(ui, |ui| {
                if state.can_apply() {
                    apply_notice(ui, actions);
                } else {
                    ui.colored_label(theme::ROSE_LIGHT, t().next_connect);
                }
            });
        ui.add_space(20.0);
    }
    template_section(ui, state, set, actions);
    ui.add_space(20.0);
    let temporary = if state.config.active_rule_set.as_ref() == Some(&set.id) {
        state.temporary_rules.as_slice()
    } else {
        &[]
    };
    let can_add = state.can_edit_rules();
    let search_before = state.rule_screen.filter.search.clone();
    filter_controls(
        ui,
        &mut state.rule_screen.filter,
        set,
        temporary,
        can_add,
        actions,
    );
    if state.rule_screen.filter.search != search_before {
        actions.push(Action::ClearRuleSelection);
    }
    let mut selection_regions = Vec::new();
    let slot = selection_slot(ui, state, actions);
    if state.rule_screen.selected_rules.len() >= 2 {
        selection_regions.push(slot.rect);
    }

    let visible_temporary = visible_rules_slice(temporary, &state.rule_screen.filter);
    let visible = visible_rules(set, &state.rule_screen.filter);
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
        ui.colored_label(theme::TEXT_MUTED, t().no_rules_match);
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
            if state.rule_screen.selected_rules.contains(&rule.id) {
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

fn clear_selection_on_click_away(
    ctx: &egui::Context,
    state: &State,
    selection_regions: &[egui::Rect],
    actions: &mut Vec<Action>,
) {
    if state.rule_screen.selected_rules.is_empty()
        || state.rule_screen.name.is_some()
        || state.rule_screen.add.is_some()
        || state.rule_screen.delete.is_some()
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

fn scroll_rules_while_dragging(ui: &mut egui::Ui) {
    if egui::DragAndDrop::payload::<RuleId>(ui.ctx()).is_none() {
        return;
    }
    let Some(pointer) = ui.ctx().pointer_hover_pos() else {
        return;
    };
    let viewport = ui.clip_rect();
    if pointer.x < viewport.left()
        || pointer.x > viewport.right()
        || pointer.y < viewport.top() - 24.0
        || pointer.y > viewport.bottom() + 24.0
    {
        return;
    }
    let (wheel, dt) = ui.input(|input| (input.smooth_scroll_delta().y, input.stable_dt.min(0.1)));
    if wheel != 0.0 {
        ui.input_mut(|input| input.smooth_scroll_delta.y = 0.0);
    }
    let delta = drag_scroll_delta(viewport, pointer.y, wheel, dt);
    if delta != 0.0 {
        ui.scroll_with_delta_animation(
            egui::vec2(0.0, delta),
            egui::style::ScrollAnimation::none(),
        );
    }
}

fn drag_scroll_delta(viewport: egui::Rect, pointer_y: f32, wheel: f32, dt: f32) -> f32 {
    let edge = 48.0;
    let speed = 640.0;
    let proximity = if pointer_y < viewport.top() + edge {
        ((viewport.top() + edge - pointer_y) / edge).clamp(0.0, 1.0)
    } else if pointer_y > viewport.bottom() - edge {
        -((pointer_y - viewport.bottom() + edge) / edge).clamp(0.0, 1.0)
    } else {
        0.0
    };
    wheel + proximity * proximity.abs() * speed * dt
}

fn selection_slot(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) -> egui::Response {
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), 38.0),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            if state.rule_screen.selected_rules.len() >= 2 {
                selection_toolbar(ui, state, actions);
            } else {
                ui.add(
                    egui::Label::new(RichText::new(t().order_hint).small().color(theme::TEXT_DIM))
                        .wrap(),
                );
            }
        },
    )
    .response
}

fn selection_toolbar(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let can_edit = state.can_edit_rules();
    let can_move = can_edit && !state.rule_screen.filter.is_active();
    let count = state.rule_screen.selected_rules.len();
    ui.label(RichText::new(t().selected_rule_count(count)).color(theme::TEXT_MUTED));
    for (label, action) in [
        (t().move_selected_to_top, Action::MoveSelectedRulesToTop),
        (t().move_to_end, Action::MoveSelectedRulesToEnd),
    ] {
        let button = widgets::outline_button_compact(ui, label, can_move);
        let button = if state.rule_screen.filter.is_active() {
            button.on_hover_text(t().reorder_disabled)
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
            widgets::outline_button_compact(ui, t().delete, can_edit)
        })
        .inner;
    if delete.clicked() {
        actions.push(Action::RequestDeleteSelectedRules);
    }
}

fn selection_shortcuts(
    ctx: &egui::Context,
    state: &State,
    text_edit_focused: bool,
    actions: &mut Vec<Action>,
) {
    if text_edit_focused
        || state.rule_screen.name.is_some()
        || state.rule_screen.add.is_some()
        || state.rule_screen.delete.is_some()
    {
        return;
    }
    if ctx.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, egui::Key::A)) {
        actions.push(Action::SelectVisibleRules);
    } else if !state.rule_screen.selected_rules.is_empty()
        && ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
    {
        actions.push(Action::ClearRuleSelection);
    } else if !state.rule_screen.selected_rules.is_empty()
        && state.can_edit_rules()
        && ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Delete))
    {
        actions.push(Action::RequestDeleteSelectedRules);
    }
}

fn apply_notice(ui: &mut egui::Ui, actions: &mut Vec<Action>) -> (egui::Response, egui::Response) {
    ui.spacing_mut().interact_size.y = 28.0;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 12.0;
        let label = ui.colored_label(theme::ROSE_LIGHT, t().apply_on_leave);
        let button =
            widgets::button_fill_compact(ui, t().apply_now, true).on_hover_text(t().apply_hint);
        if button.clicked() {
            actions.push(Action::Apply);
        }
        (label, button)
    })
    .inner
}

fn template_icon(template: RuleTemplate) -> Icon {
    match template {
        RuleTemplate::RussianSites => Icon::Globe,
        RuleTemplate::Messengers => Icon::Chat,
        RuleTemplate::Youtube => Icon::Play,
        RuleTemplate::Torrents => Icon::Download,
    }
}

fn template_section(ui: &mut egui::Ui, state: &State, set: &RuleSet, actions: &mut Vec<Action>) {
    let font = egui::FontId::new(
        egui::TextStyle::Body.resolve(ui.style()).size,
        egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
    );
    ui.label(
        RichText::new(t().rules_templates)
            .font(font)
            .color(theme::TEXT_MUTED),
    );
    ui.add_space(8.0);
    let width = ((ui.available_width() - 3.0 * 12.0) / 4.0).max(0.0);
    ui.with_layout(egui::Layout::left_to_right(egui::Align::Min), |ui| {
        ui.spacing_mut().item_spacing.x = 12.0;
        for template in RuleTemplate::ALL {
            ui.push_id(template.key(), |ui| {
                template_card(ui, state, set, template, width, actions);
            });
        }
    });
}

fn template_card(
    ui: &mut egui::Ui,
    state: &State,
    set: &RuleSet,
    template: RuleTemplate,
    width: f32,
    actions: &mut Vec<Action>,
) {
    let rule = set.rules.iter().find(
        |rule| matches!(&rule.matcher, RuleMatcher::Template(current) if *current == template),
    );
    let target = rule.map_or_else(|| template.default_target(), |rule| rule.target);
    let redundant = rule.is_none() && target == set.default_target;
    ui.allocate_ui_with_layout(
        egui::vec2(width, 0.0),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            ui.set_width(width);
            ui.set_max_width(width);
            let frame = widgets::card_frame().inner_margin(14).stroke(Stroke::new(
                1.0,
                if rule.is_some() {
                    theme::ROSE_DARK
                } else {
                    theme::BORDER
                },
            ));
            let response = frame
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 10.0;
                        let badge = icons::icon_badge(ui, template_icon(template), 30.0);
                        if redundant {
                            badge.on_hover_text(t().template_redundant);
                        }
                        let font = egui::FontId::new(
                            egui::TextStyle::Body.resolve(ui.style()).size,
                            egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(state.text(t().template_name(template)))
                                    .font(font)
                                    .color(theme::TEXT),
                            )
                            .truncate(),
                        )
                        .on_hover_text(if redundant {
                            t().template_redundant
                        } else {
                            t().template_name(template)
                        });
                    });
                    ui.add_space(8.0);
                    let description = state.text(t().template_description(template));
                    let height = 2.0 * ui.text_style_height(&egui::TextStyle::Small);
                    let mut job = egui::text::LayoutJob::simple(
                        description.clone(),
                        egui::TextStyle::Small.resolve(ui.style()),
                        theme::TEXT_DIM,
                        ui.available_width(),
                    );
                    job.wrap.max_rows = 2;
                    job.wrap.overflow_character = Some('…');
                    ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.set_min_height(height);
                            ui.add(egui::Label::new(job).wrap())
                                .on_hover_text(if redundant {
                                    t().template_redundant.to_owned()
                                } else {
                                    description
                                });
                        },
                    );
                    ui.add_space(10.0);
                    egui::Sides::new().shrink_left().height(30.0).show(
                        ui,
                        |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 6.0;
                                let (rect, dot) = ui.allocate_exact_size(
                                    egui::vec2(7.0, 7.0),
                                    egui::Sense::hover(),
                                );
                                if redundant {
                                    dot.on_hover_text(t().template_redundant);
                                }
                                ui.painter().circle_filled(
                                    rect.center(),
                                    3.5,
                                    target_color(target),
                                );
                                let label = ui.add(
                                    egui::Label::new(
                                        RichText::new(target_label(target))
                                            .small()
                                            .color(target_color(target)),
                                    )
                                    .truncate(),
                                );
                                if redundant {
                                    label.on_hover_text(t().template_redundant);
                                }
                            });
                        },
                        |ui| {
                            let button = if rule.is_some() {
                                widgets::outline_button_compact(
                                    ui,
                                    t().template_added,
                                    state.can_edit_rules(),
                                )
                                .on_hover_text(t().template_remove_hint)
                            } else {
                                widgets::button_fill_compact(
                                    ui,
                                    t().template_add,
                                    state.can_edit_rules(),
                                )
                            };
                            let button = if redundant {
                                button.on_hover_text(t().template_redundant)
                            } else {
                                button
                            };
                            if button.clicked() {
                                actions.push(if rule.is_some() {
                                    Action::RemoveTemplate(template)
                                } else {
                                    Action::AddTemplate(template)
                                });
                            }
                        },
                    );
                })
                .response;
            if redundant {
                response.on_hover_text(t().template_redundant);
            }
        },
    );
}

fn set_controls(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let Some(set) = state.selected_rules() else {
        return;
    };
    let active = state.config.active_rule_set.as_ref() == Some(&set.id);
    ui.horizontal(|ui| {
        set_picker(ui, state, set, actions);
        let menu =
            icons::icon_button_sized(ui, Icon::More, true, 40.0).on_hover_text(t().more_actions);
        widgets::menu_popup(&menu).show(|ui| {
            ui.set_min_width(180.0);
            if !active
                && widgets::menu_item(
                    ui,
                    widgets::MenuItem {
                        label: t().make_active,
                        enabled: state.can_edit_rules(),
                        selected: false,
                        danger: false,
                        note: None,
                    },
                )
                .clicked()
            {
                actions.push(Action::SelectRuleSet(Some(set.id.clone())));
                ui.close();
            }
            if widgets::menu_item(
                ui,
                widgets::MenuItem {
                    label: t().new_set,
                    enabled: state.can_edit_rules(),
                    selected: false,
                    danger: false,
                    note: None,
                },
            )
            .clicked()
            {
                actions.push(Action::OpenCreateSet);
                ui.close();
            }
            if widgets::menu_item(
                ui,
                widgets::MenuItem {
                    label: t().rename,
                    enabled: state.can_edit_rules(),
                    selected: false,
                    danger: false,
                    note: None,
                },
            )
            .clicked()
            {
                actions.push(Action::OpenRenameSet);
                ui.close();
            }
            ui.separator();
            if widgets::menu_item(
                ui,
                widgets::MenuItem {
                    label: t().delete,
                    enabled: state.can_edit_rules(),
                    selected: false,
                    danger: true,
                    note: None,
                },
            )
            .clicked()
            {
                actions.push(Action::RequestDeleteSet);
                ui.close();
            }
        });
    });
}

fn set_picker(ui: &mut egui::Ui, state: &State, set: &RuleSet, actions: &mut Vec<Action>) {
    let name = state.text(&set.name);
    let font = egui::FontId::new(
        egui::TextStyle::Body.resolve(ui.style()).size,
        egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
    );
    let name_width = ui
        .painter()
        .layout_no_wrap(name.clone(), font.clone(), theme::TEXT)
        .size()
        .x
        .min(260.0);
    let active = state.config.active_rule_set.as_ref() == Some(&set.id);
    let active_width = if active {
        ui.painter()
            .layout_no_wrap(
                t().active.to_owned(),
                egui::TextStyle::Small.resolve(ui.style()),
                theme::ROSE_LIGHT,
            )
            .size()
            .x
            + 12.0
    } else {
        0.0
    };
    let width = (12.0 + name_width + active_width + 36.0).max(220.0);
    let response = ui
        .scope_builder(egui::UiBuilder::new().sense(egui::Sense::click()), |ui| {
            ui.style_mut().interaction.selectable_labels = false;
            let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 40.0), egui::Sense::hover());
            let painter = ui.painter();
            painter.rect_filled(
                rect,
                theme::RADIUS,
                if ui.response().hovered() {
                    theme::BORDER
                } else {
                    theme::INPUT
                },
            );
            painter.rect_stroke(
                rect,
                theme::RADIUS,
                Stroke::new(1.0, theme::BORDER_STRONG),
                egui::StrokeKind::Inside,
            );
            let center_y = rect.center().y;
            let left = rect.left() + 12.0;
            let name_left = left;
            let galley = egui::WidgetText::from(RichText::new(name).font(font).color(theme::TEXT))
                .into_galley(
                    ui,
                    Some(egui::TextWrapMode::Truncate),
                    name_width,
                    egui::TextStyle::Body,
                );
            painter.galley(
                egui::pos2(name_left, center_y - galley.size().y / 2.0),
                galley,
                theme::TEXT,
            );
            let icon_right = 18.0;
            if active {
                painter.text(
                    egui::pos2(rect.right() - 10.0 - icon_right, center_y),
                    egui::Align2::RIGHT_CENTER,
                    t().active,
                    egui::TextStyle::Small.resolve(ui.style()),
                    theme::ROSE_LIGHT,
                );
            }
            icons::paint(
                painter,
                egui::pos2(rect.right() - icon_right, center_y),
                Icon::Chevron { open: true },
                theme::TEXT_DIM,
            );
        })
        .response
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    widgets::menu_popup(&response).show(|ui| {
        ui.set_min_width(width);
        for item in &state.config.rule_sets {
            let selected = item.id == set.id;
            let is_active = state.config.active_rule_set.as_ref() == Some(&item.id);
            if widgets::menu_item(
                ui,
                widgets::MenuItem {
                    label: &state.text(&item.name),
                    enabled: true,
                    selected,
                    danger: false,
                    note: is_active.then_some(t().active),
                },
            )
            .clicked()
            {
                actions.push(Action::ChooseRuleSet(item.id.clone()));
                ui.close();
            }
        }
    });
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
        (TypeFilter::All, t().all, counts.all()),
        (TypeFilter::Domains, t().domains, counts.domains),
        (TypeFilter::Processes, t().processes, counts.processes),
        (TypeFilter::Other, t().other, counts.other),
    ]
    .into_iter()
    .filter(|(kind, _, count)| *kind != TypeFilter::Other || *count != 0)
    .map(|(kind, label, count)| (kind, strings::filter_count(label, count)))
    .collect();
    let options: Vec<_> = labels
        .iter()
        .map(|(kind, label)| (*kind, label.as_str()))
        .collect();
    let (_, add_rule) = egui::Sides::new().shrink_left().wrap().show(
        ui,
        |ui| {
            ui.horizontal_wrapped(|ui| {
                widgets::search_field(ui, &mut filter.search, t().search_rules, 260.0);
                if let Some(kind) =
                    widgets::segmented(ui, "rule_type_filter", filter.kind, &options, false, true)
                {
                    actions.push(Action::SetRuleTypeFilter(kind));
                }
                target_filter(ui, filter, actions);
            });
        },
        |ui| widgets::button_fill(ui, t().new_rule_button, can_add).clicked(),
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
                .unwrap_or_else(|| RichText::new(t().any_action));
            egui::ComboBox::from_id_salt("rule_target_filter")
                .width(166.0)
                .selected_text(selected_text)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut selected, None, t().any_action);
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

fn table_cell(
    ui: &mut egui::Ui,
    width: f32,
    height: f32,
    content: impl FnOnce(&mut egui::Ui),
) -> egui::Response {
    ui.allocate_ui_with_layout(
        egui::vec2(width, height),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.set_width(width);
            ui.set_min_height(height);
            content(ui);
        },
    )
    .response
}

fn value_cell(
    ui: &mut egui::Ui,
    width: f32,
    content_height: f32,
    content: impl FnOnce(&mut egui::Ui),
) -> egui::Response {
    table_cell(ui, width, theme::RULE_ROW, |ui| {
        ui.vertical(|ui| {
            ui.set_width(width);
            ui.spacing_mut().item_spacing.y = 0.0;
            ui.add_space(((theme::RULE_ROW - content_height) / 2.0).max(0.0));
            content(ui);
        });
    })
}

/// A target picker: a dot and a word in the target's colour; a click opens the choices.
fn target_button(
    ui: &mut egui::Ui,
    id_salt: impl std::hash::Hash + std::fmt::Debug,
    target: RuleTarget,
    choices: &[RuleTarget],
    enabled: bool,
) -> Option<RuleTarget> {
    ui.push_id(egui::Id::new(id_salt), |ui| {
        let enabled = enabled && ui.is_enabled();
        let sense = if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        };
        let (rect, response) = ui.allocate_exact_size(egui::vec2(TARGET_WIDTH, 34.0), sense);
        if ui.is_rect_visible(rect) {
            if response.hovered() && enabled {
                ui.painter().rect_filled(rect, theme::RADIUS, theme::BORDER);
            }
            ui.painter().rect_stroke(
                rect,
                theme::RADIUS,
                Stroke::new(1.0, theme::BORDER_STRONG),
                egui::StrokeKind::Inside,
            );
            let color = if enabled {
                target_color(target)
            } else {
                theme::DISABLED
            };
            ui.painter().circle_filled(
                egui::pos2(rect.left() + TARGET_DOT_X, rect.center().y),
                3.5,
                color,
            );
            ui.painter().text(
                egui::pos2(rect.left() + TARGET_TEXT_X, rect.center().y),
                egui::Align2::LEFT_CENTER,
                target_label(target),
                egui::TextStyle::Button.resolve(ui.style()),
                color,
            );
            icons::paint(
                ui.painter(),
                egui::pos2(rect.right() - 14.0, rect.center().y),
                Icon::Chevron { open: true },
                if enabled {
                    theme::TEXT_DIM
                } else {
                    theme::DISABLED
                },
            );
        }
        if !enabled {
            return None;
        }
        let response = response.on_hover_cursor(egui::CursorIcon::PointingHand);
        let mut selected = None;
        widgets::menu_popup(&response).show(|ui| {
            ui.set_min_width(TARGET_WIDTH);
            for &choice in choices {
                let item = ui
                    .scope(|ui| {
                        ui.set_min_width(TARGET_WIDTH);
                        ui.spacing_mut().button_padding.x = TARGET_TEXT_X;
                        ui.visuals_mut().override_text_color = Some(target_color(choice));
                        widgets::menu_item(
                            ui,
                            widgets::MenuItem {
                                label: target_label(choice),
                                enabled: true,
                                selected: choice == target,
                                danger: false,
                                note: None,
                            },
                        )
                    })
                    .inner;
                if ui.is_rect_visible(item.rect) {
                    ui.painter().circle_filled(
                        egui::pos2(item.rect.left() + TARGET_DOT_X, item.rect.center().y),
                        3.5,
                        target_color(choice),
                    );
                }
                if item.clicked() {
                    selected = (choice != target).then_some(choice);
                    ui.close();
                }
            }
        });
        selected
    })
    .inner
}

fn dragged_rules(state: &State, set: &RuleSet, dragged: &RuleId) -> Option<Vec<RuleId>> {
    if !set.rules.iter().any(|rule| &rule.id == dragged) {
        return None;
    }
    Some(if state.rule_screen.selected_rules.contains(dragged) {
        set.rules
            .iter()
            .filter(|rule| state.rule_screen.selected_rules.contains(&rule.id))
            .map(|rule| rule.id.clone())
            .collect()
    } else {
        vec![dragged.clone()]
    })
}

fn drag_target(
    state: &State,
    set: &RuleSet,
    dragged: &RuleId,
    full_slot: usize,
) -> Option<(Vec<RuleId>, usize)> {
    let rules = dragged_rules(state, set, dragged)?;
    let positions: Vec<_> = set
        .rules
        .iter()
        .enumerate()
        .filter_map(|(index, rule)| rules.contains(&rule.id).then_some(index))
        .collect();
    let target = group_drop_target(&positions, full_slot, set.rules.len())?;
    Some((rules, target))
}

fn drop_action(rules: Vec<RuleId>, full_slot: usize, target: usize) -> Action {
    if rules.len() == 1 {
        Action::DropRule(rules[0].clone(), full_slot)
    } else {
        Action::DropRules(rules, target)
    }
}

fn rule_icon(matcher: &RuleMatcher) -> Icon {
    match matcher {
        RuleMatcher::Domain(_) => Icon::Globe,
        RuleMatcher::Process(_) => Icon::App,
        RuleMatcher::IpCidr(_) => Icon::Stack,
        RuleMatcher::Template(template) => template_icon(*template),
    }
}

fn rule_row(
    ui: &mut egui::Ui,
    state: &State,
    set: &RuleSet,
    rule: &Rule,
    index: Option<usize>,
    value_width: f32,
    actions: &mut Vec<Action>,
) {
    let temporary = index.is_none();
    let selected = !temporary && state.rule_screen.selected_rules.contains(&rule.id);
    let reorder = !temporary && state.can_edit_rules() && !state.rule_screen.filter.is_active();
    let dragged = reorder
        && egui::DragAndDrop::payload::<RuleId>(ui.ctx()).is_some_and(|id| {
            *id == rule.id || (selected && state.rule_screen.selected_rules.contains(&*id))
        });
    let mut frame = widgets::card_frame().inner_margin(egui::Margin::symmetric(12, 0));
    let fill = if selected { theme::INPUT } else { theme::CARD };
    if dragged {
        frame = frame.fill(Color32::from_rgba_unmultiplied(
            fill.r(),
            fill.g(),
            fill.b(),
            128,
        ));
    } else if !rule.enabled {
        frame = frame.fill(fill.gamma_multiply(0.72));
    } else {
        frame = frame.fill(fill);
    }
    let response = frame
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            if dragged {
                ui.multiply_opacity(0.5);
            } else if !rule.enabled {
                ui.multiply_opacity(0.7);
            }
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                table_cell(ui, HANDLE_WIDTH, theme::RULE_ROW, |ui| {
                    if reorder {
                        ui.dnd_drag_source(ui.id().with("handle"), rule.id.clone(), |ui| {
                            icons::icon_button(ui, Icon::Grip, true);
                        });
                    } else if !temporary {
                        icons::icon_button(ui, Icon::Grip, false)
                            .on_hover_text(t().reorder_disabled);
                    }
                });
                ui.add_space(HANDLE_GAP);
                table_cell(ui, ICON_WIDTH, theme::RULE_ROW, |ui| {
                    if temporary {
                        icons::icon_badge_colored(ui, Icon::Clock, ICON_WIDTH, theme::TEXT_DIM)
                            .on_hover_text(t().temporary_hint);
                    } else {
                        icons::icon_badge(ui, rule_icon(&rule.matcher), ICON_WIDTH);
                    }
                });
                ui.add_space(ICON_GAP);
                let value_height = ui.text_style_height(&egui::TextStyle::Body)
                    + ui.text_style_height(&egui::TextStyle::Small);
                value_cell(ui, value_width, value_height, |ui| {
                    rule_value(ui, state, rule);
                });
                table_cell(ui, TARGET_WIDTH, theme::RULE_ROW, |ui| {
                    if let Some(target) = target_button(
                        ui,
                        "target",
                        rule.target,
                        &[RuleTarget::Proxy, RuleTarget::Direct, RuleTarget::Block],
                        !temporary && state.can_edit_rules(),
                    ) {
                        actions.push(Action::SetRuleTarget(rule.id.clone(), target));
                    }
                });
                ui.add_space(TARGET_GAP);
                table_cell(ui, TOGGLE_WIDTH, theme::RULE_ROW, |ui| {
                    let mut enabled = rule.enabled;
                    if widgets::toggle(ui, &mut enabled, !temporary && state.can_edit_rules())
                        .changed()
                    {
                        actions.push(Action::SetRuleEnabled(rule.id.clone(), enabled));
                    }
                });
                ui.add_space(MENU_GAP);
                table_cell(ui, MENU_WIDTH, theme::RULE_ROW, |ui| {
                    let can_open = if temporary {
                        state.can_change_temporary() && !state.operations.rules_edit
                    } else {
                        state.can_edit_rules()
                    };
                    let menu = icons::icon_button_sized(ui, Icon::More, can_open, MENU_WIDTH)
                        .on_hover_text(t().more_actions);
                    if can_open {
                        let group = selected && state.rule_screen.selected_rules.len() >= 2;
                        let menu_width = if group {
                            ui.painter()
                                .layout_no_wrap(
                                    t().delete_selected_rules(
                                        state.rule_screen.selected_rules.len(),
                                    ),
                                    egui::TextStyle::Button.resolve(ui.style()),
                                    theme::ERROR,
                                )
                                .size()
                                .x
                                + 40.0
                        } else {
                            160.0
                        };
                        widgets::menu_popup(&menu).show(|ui| {
                            ui.set_min_width(menu_width.max(160.0));
                            if group {
                                widgets::menu_item(
                                    ui,
                                    widgets::MenuItem {
                                        label: t().edit,
                                        enabled: false,
                                        selected: false,
                                        danger: false,
                                        note: None,
                                    },
                                );
                                for (label, action) in [
                                    (t().move_selected_to_top, Action::MoveSelectedRulesToTop),
                                    (t().move_to_end, Action::MoveSelectedRulesToEnd),
                                ] {
                                    let item = widgets::menu_item(
                                        ui,
                                        widgets::MenuItem {
                                            label,
                                            enabled: !state.rule_screen.filter.is_active(),
                                            selected: false,
                                            danger: false,
                                            note: None,
                                        },
                                    );
                                    let item = if state.rule_screen.filter.is_active() {
                                        item.on_hover_text(t().reorder_disabled)
                                    } else {
                                        item
                                    };
                                    if item.clicked() {
                                        actions.push(action);
                                        ui.close();
                                    }
                                }
                                if widgets::menu_item(
                                    ui,
                                    widgets::MenuItem {
                                        label: &t().delete_selected_rules(
                                            state.rule_screen.selected_rules.len(),
                                        ),
                                        enabled: true,
                                        selected: false,
                                        danger: true,
                                        note: None,
                                    },
                                )
                                .clicked()
                                {
                                    actions.push(Action::RequestDeleteSelectedRules);
                                    ui.close();
                                }
                            } else {
                                if temporary {
                                    if widgets::menu_item(
                                        ui,
                                        widgets::MenuItem {
                                            label: t().keep_permanently,
                                            enabled: state.can_edit_rules(),
                                            selected: false,
                                            danger: false,
                                            note: None,
                                        },
                                    )
                                    .clicked()
                                    {
                                        actions.push(Action::KeepTemporary(rule.id.clone()));
                                        ui.close();
                                    }
                                } else {
                                    if crate::rules::editable(&rule.matcher)
                                        && widgets::menu_item(
                                            ui,
                                            widgets::MenuItem {
                                                label: t().edit,
                                                enabled: true,
                                                selected: false,
                                                danger: false,
                                                note: None,
                                            },
                                        )
                                        .clicked()
                                    {
                                        actions.push(Action::OpenEditRule(rule.id.clone()));
                                        ui.close();
                                    }
                                    if widgets::menu_item(
                                        ui,
                                        widgets::MenuItem {
                                            label: t().move_to_top,
                                            enabled: index.is_some_and(|index| index > 0),
                                            selected: false,
                                            danger: false,
                                            note: None,
                                        },
                                    )
                                    .clicked()
                                    {
                                        actions.push(Action::MoveRuleToTop(rule.id.clone()));
                                        ui.close();
                                    }
                                }
                                if widgets::menu_item(
                                    ui,
                                    widgets::MenuItem {
                                        label: t().delete,
                                        enabled: true,
                                        selected: false,
                                        danger: true,
                                        note: None,
                                    },
                                )
                                .clicked()
                                {
                                    actions.push(if temporary {
                                        Action::RemoveTemporary(rule.id.clone())
                                    } else {
                                        Action::RequestDeleteRule(rule.id.clone())
                                    });
                                    ui.close();
                                }
                            }
                        });
                    }
                });
            });
        })
        .response;

    if selected {
        ui.painter().rect_filled(
            egui::Rect::from_min_size(
                egui::pos2(response.rect.left(), response.rect.top() + 10.0),
                egui::vec2(3.0, response.rect.height() - 20.0),
            ),
            0.0,
            theme::ROSE,
        );
    }
    if !temporary {
        let left = response.rect.left() + ROW_INSET + HANDLE_WIDTH + HANDLE_GAP;
        let right = response.rect.right()
            - ROW_INSET
            - MENU_WIDTH
            - MENU_GAP
            - TOGGLE_WIDTH
            - TARGET_GAP
            - TARGET_WIDTH;
        let body = egui::Rect::from_min_max(
            egui::pos2(left, response.rect.top()),
            egui::pos2(right.max(left), response.rect.bottom()),
        );
        let click = ui.interact(body, ui.id().with("select_rule"), egui::Sense::click());
        if click.clicked() {
            let modifiers = ui.input(|input| input.modifiers);
            actions.push(Action::SelectRule {
                rule: rule.id.clone(),
                additive: modifiers.command,
                range: modifiers.shift,
            });
        }
    }

    if reorder
        && let Some(index) = index
        && let Some(dragged_id) = response.dnd_hover_payload::<RuleId>()
        && let Some(pointer) = ui.ctx().pointer_hover_pos()
    {
        let above = pointer.y < response.rect.center().y;
        let slot = index + usize::from(!above);
        if drag_target(state, set, &dragged_id, slot).is_some() {
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
            if let Some(payload) = response.dnd_release_payload::<RuleId>()
                && let Some((rules, target)) = drag_target(state, set, &payload, slot)
            {
                actions.push(drop_action(rules, slot, target));
            }
        }
    }
}

fn rule_value(ui: &mut egui::Ui, state: &State, rule: &Rule) {
    let (value, caption) = rule_lines(&rule.matcher);
    let value = state.text(&value);
    let caption = match caption {
        RuleCaption::ThisAddress => t().caption_this_address.to_owned(),
        RuleCaption::WithSubdomains => t().caption_subdomains.to_owned(),
        RuleCaption::Keyword => t().caption_keyword.to_owned(),
        RuleCaption::AnyFolder => t().caption_any_folder.to_owned(),
        RuleCaption::Path(path) => path,
        RuleCaption::Addresses => t().caption_addresses.to_owned(),
        RuleCaption::Template => t().caption_template.to_owned(),
    };
    let caption = state.text(&caption);
    let tooltip = if let RuleMatcher::Template(template) = &rule.matcher {
        let list = template
            .matchers()
            .iter()
            .map(rosetun_core::rule_value_text)
            .collect::<Vec<_>>()
            .join(", ");
        state.text(&strings::fill(t().template_contents, &[("list", &list)]))
    } else {
        let full_value = state.text(&rosetun_core::rule_value_text(&rule.matcher));
        rosetun_core::rule_value_ascii(&rule.matcher)
            .map(|ascii| format!("{full_value}\n{}", t().stored_as(&state.text(&ascii))))
            .unwrap_or(full_value)
    };
    let font = egui::FontId::new(
        egui::TextStyle::Body.resolve(ui.style()).size,
        egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
    );
    ui.add(egui::Label::new(RichText::new(value).font(font).color(theme::TEXT)).truncate())
        .on_hover_text(&tooltip);
    ui.add(egui::Label::new(RichText::new(caption).small().color(theme::TEXT_DIM)).truncate())
        .on_hover_text(tooltip);
}

fn default_rule(
    ui: &mut egui::Ui,
    state: &State,
    set: &RuleSet,
    value_width: f32,
    actions: &mut Vec<Action>,
) {
    let response = ui.push_id("default_rule", |ui| {
        widgets::card_frame()
            .fill(theme::PANEL)
            .inner_margin(egui::Margin::symmetric(12, 0))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    table_cell(ui, HANDLE_WIDTH, theme::RULE_ROW, |_| {});
                    ui.add_space(HANDLE_GAP);
                    table_cell(ui, ICON_WIDTH, theme::RULE_ROW, |ui| {
                        icons::icon_badge(ui, Icon::Globe, ICON_WIDTH);
                    });
                    ui.add_space(ICON_GAP);
                    let value_height = ui.text_style_height(&egui::TextStyle::Body)
                        + ui.text_style_height(&egui::TextStyle::Small);
                    value_cell(ui, value_width, value_height, |ui| {
                        let font = egui::FontId::new(
                            egui::TextStyle::Body.resolve(ui.style()).size,
                            egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(state.text(t().all_other_traffic))
                                    .font(font)
                                    .color(theme::TEXT),
                            )
                            .truncate(),
                        )
                        .on_hover_text(t().default_rule_tooltip);
                        ui.add(
                            egui::Label::new(
                                RichText::new(state.text(t().default_fallback))
                                    .small()
                                    .color(theme::TEXT_DIM),
                            )
                            .truncate(),
                        )
                        .on_hover_text(t().default_rule_tooltip);
                    });
                    table_cell(ui, TARGET_WIDTH, theme::RULE_ROW, |ui| {
                        let choices = if set.default_target == RuleTarget::Block {
                            &[RuleTarget::Proxy, RuleTarget::Direct, RuleTarget::Block][..]
                        } else {
                            &[RuleTarget::Proxy, RuleTarget::Direct][..]
                        };
                        if let Some(target) = target_button(
                            ui,
                            "target",
                            set.default_target,
                            choices,
                            state.can_edit_rules(),
                        ) {
                            actions.push(Action::SetDefaultTarget(target));
                        }
                    });
                    ui.add_space(TARGET_GAP);
                    table_cell(ui, TOGGLE_WIDTH, theme::RULE_ROW, |_| {});
                    ui.add_space(MENU_GAP);
                    table_cell(ui, MENU_WIDTH, theme::RULE_ROW, |_| {});
                });
            })
            .response
    });
    let rect = response.inner.rect;
    ui.painter().line_segment(
        [
            egui::pos2(rect.left(), rect.top()),
            egui::pos2(rect.right(), rect.top()),
        ],
        Stroke::new(1.0, theme::BORDER_STRONG),
    );
    if state.can_edit_rules()
        && !state.rule_screen.filter.is_active()
        && let Some(dragged_id) = response.inner.dnd_hover_payload::<RuleId>()
        && drag_target(state, set, &dragged_id, set.rules.len()).is_some()
    {
        ui.painter().line_segment(
            [
                egui::pos2(rect.left(), rect.top()),
                egui::pos2(rect.right(), rect.top()),
            ],
            Stroke::new(2.0, theme::ROSE),
        );
        if let Some(payload) = response.inner.dnd_release_payload::<RuleId>()
            && let Some((rules, target)) = drag_target(state, set, &payload, set.rules.len())
        {
            actions.push(drop_action(rules, set.rules.len(), target));
        }
    }
}

pub(crate) fn target_label(target: RuleTarget) -> &'static str {
    match target {
        RuleTarget::Proxy => t().proxy,
        RuleTarget::Direct => t().direct,
        RuleTarget::Block => t().block,
    }
}

pub(crate) fn target_color(target: RuleTarget) -> Color32 {
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
        .frame(widgets::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(400.0);
            ui.heading(match dialog.kind {
                NameDialogKind::Create => t().create_rule_set,
                NameDialogKind::Rename(_) => t().rename_rule_set,
            });
            ui.add_space(12.0);
            ui.label(t().set_name);
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
                if widgets::outline_button(ui, t().cancel, !busy).clicked() {
                    actions.push(Action::CancelSetName);
                }
                let label = match dialog.kind {
                    NameDialogKind::Create => t().create_rule_set,
                    NameDialogKind::Rename(_) => t().rename,
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
    let Some(dialog) = &state.rule_screen.delete else {
        return;
    };
    let busy = state.operations.rules_edit;
    let response = egui::Modal::new(egui::Id::new("delete_rules"))
        .frame(widgets::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(480.0);
            match dialog {
                DeleteDialog::Set(id) => {
                    ui.heading(t().delete_rule_set);
                    if let Some(set) = state.config.rule_sets.iter().find(|set| &set.id == id) {
                        ui.label(state.text(&set.name));
                    }
                    ui.add(egui::Label::new(t().delete_rule_set_detail).wrap());
                    if state.config.active_rule_set.as_ref() == Some(id) {
                        ui.add(
                            egui::Label::new(
                                RichText::new(t().delete_active_rule_set_warning)
                                    .color(theme::ERROR),
                            )
                            .wrap(),
                        );
                    }
                }
                DeleteDialog::Rule { set, rule } => {
                    ui.heading(t().delete_rule);
                    if let Some(rule) = state
                        .config
                        .rule_sets
                        .iter()
                        .find(|item| &item.id == set)
                        .and_then(|set| set.rules.iter().find(|item| &item.id == rule))
                    {
                        ui.label(state.text(&delete_rule_value(rule)));
                    }
                    ui.label(t().delete_rule_detail);
                }
                DeleteDialog::Rules { set, rules } => {
                    ui.heading(t().delete_rules_heading(rules.len()));
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
                        ui.label(t().and_more_rules(rules.len() - 5));
                    }
                    ui.label(t().delete_rule_detail);
                }
            }
            ui.add_space(18.0);
            ui.horizontal(|ui| {
                if widgets::outline_button(ui, t().cancel, !busy).clicked() {
                    actions.push(Action::CancelRuleDelete);
                }
                if widgets::button_fill(ui, t().delete, !busy).clicked() {
                    actions.push(Action::ConfirmRuleDelete);
                }
            });
        });
    if !busy && response.should_close() {
        actions.push(Action::CancelRuleDelete);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drag_set() -> RuleSet {
        let mut set = RuleSet::new(
            rosetun_config::RuleSetId::new("set"),
            "Test",
            RuleTarget::Proxy,
        );
        set.rules = (0..5)
            .map(|index| Rule {
                id: RuleId::new(index.to_string()),
                enabled: true,
                matcher: RuleMatcher::Domain(rosetun_config::DomainMatch::Exact(format!(
                    "{index}.example"
                ))),
                target: RuleTarget::Proxy,
            })
            .collect();
        set
    }

    #[test]
    fn selected_drag_targets_use_the_list_without_selected_rules() {
        let set = drag_set();
        let mut state = State::default();
        state.rule_screen.selected_rules = [RuleId::new("1"), RuleId::new("3")].into();
        assert!(matches!(
            drag_target(&state, &set, &RuleId::new("1"), 0),
            Some((rules, 0)) if rules == [RuleId::new("1"), RuleId::new("3")]
        ));
        assert!(matches!(
            drag_target(&state, &set, &RuleId::new("3"), 2),
            Some((_, 1))
        ));
        assert!(matches!(
            drag_target(&state, &set, &RuleId::new("1"), 4),
            Some((_, 2))
        ));
        state.rule_screen.selected_rules = [RuleId::new("1"), RuleId::new("2")].into();
        assert!(drag_target(&state, &set, &RuleId::new("1"), 2).is_none());
        state.rule_screen.selected_rules = [RuleId::new("1"), RuleId::new("3")].into();
        let (rules, target) = drag_target(&state, &set, &RuleId::new("3"), 5).unwrap();
        assert_eq!(target, 3);
        assert!(matches!(
            drop_action(rules, 5, target),
            Action::DropRules(_, 3)
        ));
        let (rules, target) = drag_target(&state, &set, &RuleId::new("2"), 0).unwrap();
        assert_eq!(rules, vec![RuleId::new("2")]);
        assert!(matches!(
            drop_action(rules, 0, target),
            Action::DropRule(_, 0)
        ));
        assert_eq!(state.rule_screen.selected_rules.len(), 2);
    }

    fn row_input_actions(
        ctx: &egui::Context,
        state: &State,
        set: &RuleSet,
        events: Vec<egui::Event>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(800.0, 200.0),
                )),
                events,
                ..egui::RawInput::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.push_id((set.id.as_str(), set.rules[0].id.as_str()), |ui| {
                        rule_row(
                            ui,
                            state,
                            set,
                            &set.rules[0],
                            Some(0),
                            (ui.available_width() - 350.0).max(0.0),
                            &mut actions,
                        );
                    });
                });
            },
        );
        output.textures_delta.clear();
        actions
    }

    #[test]
    fn row_body_selects_without_selecting_from_the_handle_or_controls() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let set = drag_set();
        let mut state = State::default();
        state.config_ready = true;
        row_input_actions(&ctx, &state, &set, Vec::new());
        for (x, select) in [(150.0, true), (30.0, false), (600.0, false)] {
            let pos = egui::pos2(x, 38.0);
            row_input_actions(
                &ctx,
                &state,
                &set,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed: true,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
            let actions = row_input_actions(
                &ctx,
                &state,
                &set,
                vec![egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::NONE,
                }],
            );
            assert_eq!(
                actions
                    .iter()
                    .any(|action| matches!(action, Action::SelectRule { .. })),
                select,
                "click at {pos:?}"
            );
        }
        assert!(state.rule_screen.selected_rules.is_empty());
    }

    #[test]
    fn row_click_forwards_ctrl_and_shift_modifiers() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let set = drag_set();
        let state = State::default();
        row_input_actions(&ctx, &state, &set, Vec::new());
        let pos = egui::pos2(150.0, 38.0);
        for (modifiers, additive, range) in [
            (
                egui::Modifiers {
                    ctrl: true,
                    command: true,
                    ..egui::Modifiers::NONE
                },
                true,
                false,
            ),
            (egui::Modifiers::SHIFT, false, true),
        ] {
            row_input_actions(
                &ctx,
                &state,
                &set,
                vec![
                    egui::Event::ModifiersChanged(modifiers),
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed: true,
                        modifiers,
                    },
                ],
            );
            let actions = row_input_actions(
                &ctx,
                &state,
                &set,
                vec![egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers,
                }],
            );
            assert!(matches!(
                actions.as_slice(),
                [Action::SelectRule {
                    additive: actual_additive,
                    range: actual_range,
                    ..
                }] if *actual_additive == additive && *actual_range == range
            ));
        }
    }

    #[test]
    fn clicking_away_clears_selection_but_selected_rows_and_actions_keep_it() {
        let ctx = egui::Context::default();
        let mut state = State::default();
        state.rule_screen.selected_rules.insert(RuleId::new("1"));
        let handle = egui::Rect::from_min_size(egui::pos2(100.0, 20.0), egui::vec2(40.0, 60.0));
        let menu = egui::Rect::from_min_size(egui::pos2(270.0, 20.0), egui::vec2(30.0, 60.0));
        let frame = |events, mut actions: Vec<Action>| {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(800.0, 200.0),
                    )),
                    events,
                    ..egui::RawInput::default()
                },
                |ctx| clear_selection_on_click_away(ctx, &state, &[handle, menu], &mut actions),
            );
            output.textures_delta.clear();
            actions
        };
        frame(Vec::new(), Vec::new());
        for (pos, clear) in [
            (egui::pos2(150.0, 150.0), true),
            (egui::pos2(110.0, 50.0), false),
            (egui::pos2(285.0, 50.0), false),
            (egui::pos2(150.0, 50.0), true),
            (egui::pos2(500.0, 50.0), true),
        ] {
            frame(
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed: true,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                Vec::new(),
            );
            let actions = frame(
                vec![egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::NONE,
                }],
                Vec::new(),
            );
            assert_eq!(
                matches!(actions.as_slice(), [Action::ClearRuleSelection]),
                clear,
                "click at {pos:?}"
            );
        }
    }

    #[test]
    fn dragging_near_edges_or_wheeling_scrolls_in_the_expected_direction() {
        let viewport = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 600.0));
        assert!(drag_scroll_delta(viewport, 10.0, 0.0, 1.0 / 60.0) > 0.0);
        assert!(drag_scroll_delta(viewport, 590.0, 0.0, 1.0 / 60.0) < 0.0);
        assert_eq!(drag_scroll_delta(viewport, 300.0, 0.0, 1.0 / 60.0), 0.0);
        assert_eq!(drag_scroll_delta(viewport, 300.0, -72.0, 1.0 / 60.0), -72.0);
        assert!(
            drag_scroll_delta(viewport, 580.0, 0.0, 1.0 / 60.0).abs()
                < drag_scroll_delta(viewport, 595.0, 0.0, 1.0 / 60.0).abs()
        );
    }

    #[test]
    fn dragging_a_rule_scrolls_the_enclosing_area_with_a_wheel() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let frame = |events| {
            let mut offset = 0.0;
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(400.0, 200.0),
                    )),
                    events,
                    ..egui::RawInput::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        let result = egui::ScrollArea::vertical()
                            .id_salt("rule_drag_wheel")
                            .scroll_source(egui::scroll_area::ScrollSource {
                                mouse_wheel: false,
                                ..Default::default()
                            })
                            .show(ui, |ui| {
                                ui.ctx().set_dragged_id(egui::Id::new("rule_drag"));
                                ui.allocate_space(egui::vec2(200.0, 600.0));
                                scroll_rules_while_dragging(ui);
                            });
                        offset = result.state.offset.y;
                    });
                },
            );
            output.textures_delta.clear();
            offset
        };
        frame(Vec::new());
        egui::DragAndDrop::set_payload(&ctx, RuleId::new("1"));
        let offset = frame(vec![
            egui::Event::PointerMoved(egui::pos2(100.0, 100.0)),
            egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(0.0, -72.0),
                phase: egui::TouchPhase::Move,
                modifiers: egui::Modifiers::NONE,
            },
        ]);
        let after = frame(vec![egui::Event::PointerMoved(egui::pos2(100.0, 100.0))]);
        assert!(
            offset > 0.0 || after > 0.0,
            "offset after drag wheel: {offset}, {after}"
        );
        let edge = frame(vec![egui::Event::PointerMoved(egui::pos2(100.0, 189.0))]);
        let edge_after = frame(vec![egui::Event::PointerMoved(egui::pos2(100.0, 189.0))]);
        assert!(
            edge > after || edge_after > after,
            "offset after edge drag: {after}, {edge}, {edge_after}"
        );
        egui::DragAndDrop::clear_payload(&ctx);
    }

    #[test]
    fn toolbar_and_hint_reserve_the_same_height() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut state = State::default();
        state.config_ready = true;
        for selected in [false, true] {
            state.rule_screen.selected_rules.clear();
            if selected {
                state.rule_screen.selected_rules = [RuleId::new("1"), RuleId::new("2")].into();
            }
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(888.0, 640.0),
                    )),
                    ..egui::RawInput::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        let slot = selection_slot(ui, &state, &mut Vec::new());
                        assert!((slot.rect.height() - 38.0).abs() < 1.0, "{slot:?}");
                    });
                },
            );
            output.textures_delta.clear();
        }
    }

    #[test]
    fn table_shortcuts_select_visible_clear_and_ignore_text_focus() {
        let ctx = egui::Context::default();
        let mut state = State::default();
        state.config_ready = true;
        state.rule_screen.selected_rules.insert(RuleId::new("1"));
        for (key, modifiers, focused, expected) in [
            (egui::Key::A, egui::Modifiers::COMMAND, false, true),
            (egui::Key::Escape, egui::Modifiers::NONE, false, true),
            (egui::Key::Delete, egui::Modifiers::NONE, false, true),
            (egui::Key::Escape, egui::Modifiers::NONE, true, false),
            (egui::Key::Delete, egui::Modifiers::NONE, true, false),
        ] {
            let mut actions = Vec::new();
            let mut output = ctx.run_ui(
                egui::RawInput {
                    events: vec![egui::Event::Key {
                        key,
                        physical_key: None,
                        pressed: true,
                        repeat: false,
                        modifiers,
                    }],
                    ..egui::RawInput::default()
                },
                |ctx| selection_shortcuts(ctx, &state, focused, &mut actions),
            );
            output.textures_delta.clear();
            assert_eq!(!actions.is_empty(), expected);
            if expected {
                assert!(matches!(
                    actions.as_slice(),
                    [Action::SelectVisibleRules
                        | Action::ClearRuleSelection
                        | Action::RequestDeleteSelectedRules]
                ));
            }
        }
        state.rule_screen.delete = Some(DeleteDialog::Set(rosetun_config::RuleSetId::new("1")));
        let mut actions = Vec::new();
        let mut output = ctx.run_ui(
            egui::RawInput {
                events: vec![egui::Event::Key {
                    key: egui::Key::Delete,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                }],
                ..egui::RawInput::default()
            },
            |ctx| selection_shortcuts(ctx, &state, false, &mut actions),
        );
        output.textures_delta.clear();
        assert!(actions.is_empty());
    }

    #[test]
    fn apply_notice_centers_text_against_the_button() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let (label, button) = widgets::card_frame()
                    .inner_margin(egui::Margin::symmetric(16, 8))
                    .show(ui, |ui| apply_notice(ui, &mut Vec::new()))
                    .inner;
                assert!(
                    (label.rect.center().y - button.rect.center().y).abs() < 1.0,
                    "text: {:?}, button: {:?}",
                    label.rect,
                    button.rect
                );
            });
        });
        output.textures_delta.clear();
    }

    #[test]
    fn action_filter_button_matches_the_search_field_height() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let response = target_filter(ui, &RuleFilter::default(), &mut Vec::new());
                assert!(
                    (response.rect.height() - 38.0).abs() < 1.0,
                    "action filter: {:?}",
                    response.rect
                );
            });
        });
        output.textures_delta.clear();
    }

    #[test]
    fn template_cards_keep_a_row_of_equal_sized_non_overlapping_cards() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut state = State::default();
        state.config_ready = true;
        for installed in [false, true] {
            let mut set = RuleSet::new(
                rosetun_config::RuleSetId::new("set"),
                "Test",
                RuleTarget::Proxy,
            );
            if installed {
                set.rules = RuleTemplate::ALL
                    .into_iter()
                    .enumerate()
                    .map(|(index, template)| Rule {
                        id: RuleId::new(index.to_string()),
                        enabled: true,
                        matcher: RuleMatcher::Template(template),
                        target: template.default_target(),
                    })
                    .collect();
            }
            for available in [440.0, 760.0] {
                let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.set_width(available);
                        let width = (available - 36.0) / 4.0;
                        let mut rects = Vec::new();
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Min), |ui| {
                            ui.spacing_mut().item_spacing.x = 12.0;
                            for template in RuleTemplate::ALL {
                                let rect = ui
                                    .scope(|ui| {
                                        template_card(
                                            ui,
                                            &state,
                                            &set,
                                            template,
                                            width,
                                            &mut Vec::new(),
                                        );
                                    })
                                    .response
                                    .rect;
                                rects.push(rect);
                            }
                        });
                        for rect in &rects {
                            assert!(rect.width() <= width + 1.0, "{rect:?} vs {width}");
                            assert!((rect.height() - rects[0].height()).abs() < 1.0);
                            assert!(
                                (rect.top() - rects[0].top()).abs() < 1.0,
                                "cards are staggered: {rect:?} vs {:?}",
                                rects[0]
                            );
                        }
                        for pair in rects.windows(2) {
                            assert!(pair[0].right() + 11.0 <= pair[1].left(), "{pair:?}");
                        }
                    });
                });
                output.textures_delta.clear();
            }
        }
    }

    #[test]
    fn table_cells_keep_columns_and_center_contents() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.set_width(800.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    let handle = table_cell(ui, HANDLE_WIDTH, theme::RULE_ROW, |_| {});
                    ui.add_space(HANDLE_GAP);
                    let badge = table_cell(ui, ICON_WIDTH, theme::RULE_ROW, |ui| {
                        icons::icon_badge(ui, Icon::App, ICON_WIDTH);
                    });
                    ui.add_space(ICON_GAP);
                    let body_height = ui.text_style_height(&egui::TextStyle::Body);
                    let small_height = ui.text_style_height(&egui::TextStyle::Small);
                    let mut first_line = egui::Rect::NOTHING;
                    let mut second_line = egui::Rect::NOTHING;
                    let value = value_cell(ui, 160.0, body_height + small_height, |ui| {
                        first_line = ui.add(egui::Label::new("app.exe").truncate()).rect;
                        second_line = ui
                            .add(
                                egui::Label::new(RichText::new("C:\\Apps\\app.exe").small())
                                    .truncate(),
                            )
                            .rect;
                    });
                    let mut button_rect = egui::Rect::NOTHING;
                    let target_cell = table_cell(ui, TARGET_WIDTH, theme::RULE_ROW, |ui| {
                        button_rect = ui
                            .scope(|ui| {
                                target_button(
                                    ui,
                                    "test_target",
                                    RuleTarget::Proxy,
                                    &[RuleTarget::Proxy, RuleTarget::Direct],
                                    true,
                                );
                            })
                            .response
                            .rect;
                    });
                    ui.add_space(TARGET_GAP);
                    let mut checked = true;
                    let mut toggle_rect = egui::Rect::NOTHING;
                    let toggle_cell = table_cell(ui, TOGGLE_WIDTH, theme::RULE_ROW, |ui| {
                        toggle_rect = widgets::toggle(ui, &mut checked, true).rect;
                    });
                    ui.add_space(MENU_GAP);
                    let menu_cell = table_cell(ui, MENU_WIDTH, theme::RULE_ROW, |ui| {
                        icons::icon_button_sized(ui, Icon::More, true, MENU_WIDTH);
                    });
                    assert!((badge.rect.left() - handle.rect.right() - HANDLE_GAP).abs() < 1.0);
                    assert!((value.rect.left() - badge.rect.right() - ICON_GAP).abs() < 1.0);
                    assert!((target_cell.rect.left() - value.rect.right()).abs() < 1.0);
                    assert!(
                        (toggle_cell.rect.left() - target_cell.rect.right() - TARGET_GAP).abs()
                            < 1.0
                    );
                    assert!(
                        (menu_cell.rect.left() - toggle_cell.rect.right() - MENU_GAP).abs() < 1.0
                    );
                    assert!((value.rect.height() - theme::RULE_ROW).abs() < 1.0);
                    assert!(
                        ((first_line.top() + second_line.bottom()) / 2.0 - value.rect.center().y)
                            .abs()
                            < 3.0
                    );
                    assert!(
                        (button_rect.center().y - target_cell.rect.center().y).abs() < 3.0,
                        "button: {button_rect:?} vs {:?}",
                        target_cell.rect
                    );
                    assert!((button_rect.center().x - target_cell.rect.center().x).abs() < 3.0);
                    assert!(
                        (toggle_rect.center().y - toggle_cell.rect.center().y).abs() < 3.0,
                        "toggle: {toggle_rect:?} vs {:?}",
                        toggle_cell.rect
                    );
                    assert!((toggle_rect.center().x - toggle_cell.rect.center().x).abs() < 3.0);
                });
            });
        });
        output.textures_delta.clear();
    }
}
