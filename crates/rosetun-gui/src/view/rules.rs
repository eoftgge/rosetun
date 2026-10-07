use eframe::egui::{self, Color32, RichText, Stroke};
use rosetun_config::{Rule, RuleId, RuleMatcher, RuleSet, RuleTarget, RuleTemplate};

use crate::icons::{self, Icon};
use crate::reorder::drop_target;
use crate::rules::{RuleCaption, RuleFilter, TypeFilter, rule_counts, rule_lines, visible_rules};
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
        widgets::card_frame().show(ui, |ui| {
            ui.colored_label(theme::ROSE_LIGHT, t().rules_next_connect);
        });
        ui.add_space(20.0);
    }
    template_section(ui, state, set, actions);
    ui.add_space(20.0);
    let can_add = state.can_edit_rules();
    filter_controls(ui, &mut state.rule_screen.filter, set, can_add, actions);
    ui.add_space(8.0);
    ui.add(egui::Label::new(RichText::new(t().order_hint).small().color(theme::TEXT_DIM)).wrap());
    ui.add_space(12.0);

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
    if visible.is_empty() && !set.rules.is_empty() {
        ui.colored_label(theme::TEXT_MUTED, t().no_rules_match);
    }
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.y = 6.0;
        for (index, rule) in visible {
            ui.push_id((set.id.as_str(), rule.id.as_str()), |ui| {
                rule_row(ui, state, set, rule, index, value_width, actions);
            });
        }
        default_rule(ui, state, set, value_width, actions);
    });
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
    can_add: bool,
    actions: &mut Vec<Action>,
) {
    let counts = rule_counts(set);
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
    index: usize,
    value_width: f32,
    actions: &mut Vec<Action>,
) {
    let reorder = state.can_edit_rules() && !state.rule_screen.filter.is_active();
    let dragged =
        reorder && egui::DragAndDrop::payload::<RuleId>(ui.ctx()).is_some_and(|id| *id == rule.id);
    let mut frame = widgets::card_frame().inner_margin(egui::Margin::symmetric(12, 0));
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
                    } else {
                        icons::icon_button(ui, Icon::Grip, false)
                            .on_hover_text(t().reorder_disabled);
                    }
                });
                ui.add_space(HANDLE_GAP);
                table_cell(ui, ICON_WIDTH, theme::RULE_ROW, |ui| {
                    icons::icon_badge(ui, rule_icon(&rule.matcher), ICON_WIDTH);
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
                        state.can_edit_rules(),
                    ) {
                        actions.push(Action::SetRuleTarget(rule.id.clone(), target));
                    }
                });
                ui.add_space(TARGET_GAP);
                table_cell(ui, TOGGLE_WIDTH, theme::RULE_ROW, |ui| {
                    let mut enabled = rule.enabled;
                    if widgets::toggle(ui, &mut enabled, state.can_edit_rules()).changed() {
                        actions.push(Action::SetRuleEnabled(rule.id.clone(), enabled));
                    }
                });
                ui.add_space(MENU_GAP);
                table_cell(ui, MENU_WIDTH, theme::RULE_ROW, |ui| {
                    let menu = icons::icon_button_sized(
                        ui,
                        Icon::More,
                        state.can_edit_rules(),
                        MENU_WIDTH,
                    )
                    .on_hover_text(t().more_actions);
                    if state.can_edit_rules() {
                        widgets::menu_popup(&menu).show(|ui| {
                            ui.set_min_width(160.0);
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
                                    enabled: index > 0,
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
                                actions.push(Action::RequestDeleteRule(rule.id.clone()));
                                ui.close();
                            }
                        });
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
        && let Some(from) = set.rules.iter().position(|rule| rule.id == *dragged_id)
        && drop_target(from, set.rules.len(), set.rules.len()).is_some()
    {
        ui.painter().line_segment(
            [
                egui::pos2(rect.left(), rect.top()),
                egui::pos2(rect.right(), rect.top()),
            ],
            Stroke::new(2.0, theme::ROSE),
        );
        if let Some(payload) = response.inner.dnd_release_payload::<RuleId>() {
            actions.push(Action::DropRule((*payload).clone(), set.rules.len()));
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
                        let value = if matches!(&rule.matcher, RuleMatcher::Template(_)) {
                            rule_lines(&rule.matcher).0
                        } else {
                            rosetun_core::rule_value_text(&rule.matcher)
                        };
                        ui.label(state.text(&value));
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
