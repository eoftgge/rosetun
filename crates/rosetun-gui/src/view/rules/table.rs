use std::collections::BTreeSet;

use rosetun_config::ExitId;

use super::templates::template_icon;
use super::*;

pub(super) fn scroll_rules_while_dragging(ui: &mut egui::Ui) {
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

pub(super) fn drag_scroll_delta(viewport: egui::Rect, pointer_y: f32, wheel: f32, dt: f32) -> f32 {
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

pub(super) fn table_cell(
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

pub(super) fn value_cell(
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

/// One entry of a target menu.
pub(super) struct TargetChoice {
    pub(super) destination: RuleDestination,
    pub(super) label: String,
    pub(super) color: Color32,
    /// A section title drawn above this entry.
    pub(super) section: Option<String>,
}

impl TargetChoice {
    pub(super) fn plain(target: RuleTarget) -> Self {
        Self {
            destination: target.into(),
            label: target_label(target),
            color: target_color(target),
            section: None,
        }
    }

    pub(super) fn of(destination: RuleDestination, exits: &[Exit]) -> Self {
        Self {
            label: destination_label(&destination, exits),
            color: destination_color(&destination),
            destination,
            section: None,
        }
    }
}

/// A rule row's choices: the plain targets, then "Your exits". New exits are made in the dialog.
pub(super) fn rule_target_choices(exits: &[Exit]) -> Vec<TargetChoice> {
    let mut choices: Vec<_> = [RuleTarget::Proxy, RuleTarget::Direct, RuleTarget::Block]
        .into_iter()
        .map(TargetChoice::plain)
        .collect();
    for (index, exit) in exits.iter().enumerate() {
        let mut choice = TargetChoice::of(RuleDestination::Exit(exit.id.clone()), exits);
        let name = crate::display::safe_text(&exit.name);
        choice.label = match crate::destinations::exit_country(exit) {
            Some(code) => format!("{name} · {}", code.as_str()),
            None => name,
        };
        if index == 0 {
            choice.section = Some(tr!("where-section-exits"));
        }
        choices.push(choice);
    }
    choices
}

/// A target picker: a dot and a word in the target's colour; a click opens the choices.
pub(super) fn target_button(
    ui: &mut egui::Ui,
    id_salt: impl std::hash::Hash + std::fmt::Debug,
    current: &TargetChoice,
    choices: &[TargetChoice],
    enabled: bool,
) -> Option<RuleDestination> {
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
                current.color
            } else {
                theme::DISABLED
            };
            ui.painter().circle_filled(
                egui::pos2(rect.left() + TARGET_DOT_X, rect.center().y),
                3.5,
                color,
            );
            let mut job = egui::text::LayoutJob::simple_singleline(
                current.label.clone(),
                egui::TextStyle::Button.resolve(ui.style()),
                color,
            );
            job.wrap = egui::text::TextWrapping::truncate_at_width(
                rect.width() - TARGET_TEXT_X - TARGET_CHEVRON_SPACE,
            );
            let galley = ui.painter().layout_job(job);
            ui.painter().galley(
                egui::pos2(
                    rect.left() + TARGET_TEXT_X,
                    rect.center().y - galley.size().y / 2.0,
                ),
                galley,
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
        let response = response
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .on_hover_text(&current.label);
        let width = if choices.len() > 3 {
            TARGET_MENU_WIDTH
        } else {
            TARGET_WIDTH
        };
        let mut selected = None;
        widgets::menu_popup(&response).show(|ui| {
            ui.set_min_width(width);
            for choice in choices {
                if let Some(section) = &choice.section {
                    ui.separator();
                    ui.label(RichText::new(section).small().color(theme::TEXT_DIM));
                }
                let item = ui
                    .scope(|ui| {
                        ui.set_min_width(width);
                        ui.spacing_mut().button_padding.x = TARGET_TEXT_X;
                        ui.visuals_mut().override_text_color = Some(choice.color);
                        widgets::menu_item(
                            ui,
                            widgets::MenuItem {
                                label: &choice.label,
                                enabled: true,
                                selected: choice.destination == current.destination,
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
                        choice.color,
                    );
                }
                if item.clicked() {
                    selected = (choice.destination != current.destination)
                        .then(|| choice.destination.clone());
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
    Some(if state.rules.screen.selected_rules.contains(dragged) {
        set.rules
            .iter()
            .filter(|rule| state.rules.screen.selected_rules.contains(&rule.id))
            .map(|rule| rule.id.clone())
            .collect()
    } else {
        vec![dragged.clone()]
    })
}

pub(super) fn drag_target(
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

pub(super) fn drop_action(rules: Vec<RuleId>, full_slot: usize, target: usize) -> Action {
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
        RuleMatcher::List { .. } => Icon::List,
        RuleMatcher::Template(template) => template_icon(*template),
    }
}

/// What every row of one table shares, computed once per frame.
pub(super) struct RowContext<'a> {
    pub(super) set: &'a RuleSet,
    /// `destinations::unresolved_exits`, which resolves every exit.
    pub(super) unresolved: &'a BTreeSet<ExitId>,
}

pub(super) fn rule_row(
    ui: &mut egui::Ui,
    state: &State,
    rows: &RowContext<'_>,
    rule: &Rule,
    index: Option<usize>,
    value_width: f32,
    actions: &mut Vec<Action>,
) {
    let set = rows.set;
    let temporary = index.is_none();
    let selected = !temporary && state.rules.screen.selected_rules.contains(&rule.id);
    let reorder = !temporary && state.can_edit_rules() && !state.rules.screen.filter.is_active();
    let dragged = reorder
        && egui::DragAndDrop::payload::<RuleId>(ui.ctx()).is_some_and(|id| {
            *id == rule.id || (selected && state.rules.screen.selected_rules.contains(&*id))
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
                            .on_hover_text(tr!("reorder-disabled"));
                    }
                });
                ui.add_space(HANDLE_GAP);
                table_cell(ui, ICON_WIDTH, theme::RULE_ROW, |ui| {
                    if temporary {
                        icons::icon_badge_colored(ui, Icon::Clock, ICON_WIDTH, theme::TEXT_DIM)
                            .on_hover_text(tr!("temporary-hint"));
                    } else {
                        icons::icon_badge(ui, rule_icon(&rule.matcher), ICON_WIDTH);
                    }
                });
                ui.add_space(ICON_GAP);
                let value_height = ui.text_style_height(&egui::TextStyle::Body)
                    + ui.text_style_height(&egui::TextStyle::Small);
                value_cell(ui, value_width, value_height, |ui| {
                    rule_value(ui, state, rule, index.map(|_| &set.id), rows.unresolved);
                });
                table_cell(ui, TARGET_WIDTH, theme::RULE_ROW, |ui| {
                    let exits = &state.config.exits;
                    if let Some(target) = target_button(
                        ui,
                        "target",
                        &TargetChoice::of(RuleDestination::of(rule), exits),
                        &rule_target_choices(exits),
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
                        .on_hover_text(tr!("more-actions"));
                    if can_open {
                        let group = selected && state.rules.screen.selected_rules.len() >= 2;
                        let menu_width = if group {
                            ui.painter()
                                .layout_no_wrap(
                                    crate::i18n::delete_selected_rules(
                                        state.rules.screen.selected_rules.len(),
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
                                        label: &tr!("edit"),
                                        enabled: false,
                                        selected: false,
                                        danger: false,
                                        note: None,
                                    },
                                );
                                for (label, action) in [
                                    (tr!("move-selected-to-top"), Action::MoveSelectedRulesToTop),
                                    (tr!("move-to-end"), Action::MoveSelectedRulesToEnd),
                                ] {
                                    let item = widgets::menu_item(
                                        ui,
                                        widgets::MenuItem {
                                            label: &label,
                                            enabled: !state.rules.screen.filter.is_active(),
                                            selected: false,
                                            danger: false,
                                            note: None,
                                        },
                                    );
                                    let item = if state.rules.screen.filter.is_active() {
                                        item.on_hover_text(tr!("reorder-disabled"))
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
                                        label: &crate::i18n::delete_selected_rules(
                                            state.rules.screen.selected_rules.len(),
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
                                            label: &tr!("keep-permanently"),
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
                                                label: &tr!("edit"),
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
                                            label: &tr!("move-to-top"),
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
                                        label: &tr!("delete"),
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

fn rule_value(
    ui: &mut egui::Ui,
    state: &State,
    rule: &Rule,
    set: Option<&rosetun_config::RuleSetId>,
    unresolved: &BTreeSet<ExitId>,
) {
    let (value, caption) = match &rule.matcher {
        RuleMatcher::List { list, category } => (
            state.list_rule_name(list, category.as_deref()),
            RuleCaption::Template,
        ),
        _ => rule_lines(&rule.matcher),
    };
    let value = state.text(&value);
    let caption = match caption {
        RuleCaption::ThisAddress => tr!("caption-this-address"),
        RuleCaption::WithSubdomains => tr!("caption-subdomains"),
        RuleCaption::Keyword => tr!("caption-keyword"),
        RuleCaption::AnyFolder => tr!("caption-any-folder"),
        RuleCaption::Path(path) => path,
        RuleCaption::Addresses => tr!("caption-addresses"),
        RuleCaption::Template if matches!(&rule.matcher, RuleMatcher::List { .. }) => {
            tr!("caption-list")
        }
        RuleCaption::Template => tr!("caption-template"),
    };
    let missing = state.missing_list_rule(set, &rule.id);
    let exit_missing = rule.target == RuleTarget::Exit
        && rule.exit.as_ref().is_none_or(|id| unresolved.contains(id));
    let tooltip = if let RuleMatcher::Template(template) = &rule.matcher {
        let list = template
            .matchers()
            .iter()
            .map(rosetun_core::rule_value_text)
            .collect::<Vec<_>>()
            .join(", ");
        state.text(&tr!("template-contents", list = &list))
    } else if matches!(&rule.matcher, RuleMatcher::List { .. }) {
        value.clone()
    } else {
        let full_value = state.text(&rosetun_core::rule_value_text(&rule.matcher));
        rosetun_core::rule_value_ascii(&rule.matcher)
            .map(|ascii| {
                format!(
                    "{full_value}\n{}",
                    crate::i18n::stored_as(&state.text(&ascii))
                )
            })
            .unwrap_or(full_value)
    };
    let font = egui::FontId::new(
        egui::TextStyle::Body.resolve(ui.style()).size,
        egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
    );
    ui.add(egui::Label::new(RichText::new(value).font(font).color(theme::TEXT)).truncate())
        .on_hover_text(&tooltip);
    if let Some(missing) = missing {
        let warning = if missing.last_good {
            tr!("rule-category-last-good")
        } else {
            tr!("rule-category-disabled")
        };
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            icons::icon_badge_colored(ui, Icon::Warning, 16.0, theme::ERROR)
                .on_hover_text(tr!("rule-category-hint"));
            ui.add(egui::Label::new(RichText::new(warning).small().color(theme::ERROR)).truncate())
                .on_hover_text(tr!("rule-category-hint"));
        });
    } else if exit_missing {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            icons::icon_badge_colored(ui, Icon::Warning, 16.0, theme::ERROR);
            ui.add(
                egui::Label::new(
                    RichText::new(tr!("exit-node-missing"))
                        .small()
                        .color(theme::ERROR),
                )
                .truncate(),
            );
        });
    } else {
        ui.add(
            egui::Label::new(
                RichText::new(state.text(&caption))
                    .small()
                    .color(theme::TEXT_DIM),
            )
            .truncate(),
        )
        .on_hover_text(tooltip);
    }
}

pub(super) fn default_rule(
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
                                RichText::new(state.text(&tr!("all-other-traffic")))
                                    .font(font)
                                    .color(theme::TEXT),
                            )
                            .truncate(),
                        )
                        .on_hover_text(tr!("default-rule-tooltip"));
                        ui.add(
                            egui::Label::new(
                                RichText::new(state.text(&tr!("default-fallback")))
                                    .small()
                                    .color(theme::TEXT_DIM),
                            )
                            .truncate(),
                        )
                        .on_hover_text(tr!("default-rule-tooltip"));
                    });
                    table_cell(ui, TARGET_WIDTH, theme::RULE_ROW, |ui| {
                        let choices: &[RuleTarget] = if set.default_target == RuleTarget::Block {
                            &[RuleTarget::Proxy, RuleTarget::Direct, RuleTarget::Block]
                        } else {
                            &[RuleTarget::Proxy, RuleTarget::Direct]
                        };
                        let choices: Vec<_> =
                            choices.iter().copied().map(TargetChoice::plain).collect();
                        if let Some((target, _)) = target_button(
                            ui,
                            "target",
                            &TargetChoice::plain(set.default_target),
                            &choices,
                            state.can_edit_rules(),
                        )
                        .as_ref()
                        .and_then(RuleDestination::settled)
                        {
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
        && !state.rules.screen.filter.is_active()
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
