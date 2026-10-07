use eframe::egui::{self, Color32, RichText, Stroke};
use rosetun_config::{DomainMatch, ProcessMatch, Rule, RuleId, RuleMatcher, RuleSet, RuleTarget};

use crate::icons::{self, Icon};
use crate::reorder::drop_target;
use crate::rules::{RuleFilter, TypeFilter, rule_counts, visible_rules};
use crate::state::{Action, DeleteDialog, NameDialogKind, State};
use crate::strings::t;
use crate::{strings, theme, widgets};

const HANDLE_WIDTH: f32 = 28.0;
const MIN_TYPE_WIDTH: f32 = 100.0;
/// Gap between the type label and the value column.
const TYPE_PADDING: f32 = 16.0;
const TARGET_WIDTH: f32 = 172.0;
const TARGET_COMBO_WIDTH: f32 = 140.0;
// With the app theme, the visible ComboBox sits below the center of its allocated area.
const TARGET_COMBO_TOP_OFFSET: f32 = 8.0;
const ENABLED_WIDTH: f32 = 100.0;
const REMOVE_WIDTH: f32 = 44.0;
const TABLE_INSET: f32 = 10.0;
const ROW_HEIGHT: f32 = 52.0;
const HEADER_HEIGHT: f32 = 24.0;

#[derive(Clone, Copy)]
struct TableWidths {
    rule_type: f32,
    value: f32,
}

/// Wide enough for the longest rule type label in the current language.
fn type_width(ui: &egui::Ui) -> f32 {
    let font_id = egui::TextStyle::Body.resolve(ui.style());
    [
        t().domain,
        t().keyword,
        t().process,
        strings::IP,
        t().default,
    ]
    .into_iter()
    .map(|label| {
        ui.painter()
            .layout_no_wrap(label.to_owned(), font_id.clone(), theme::TEXT)
            .size()
            .x
    })
    .fold(MIN_TYPE_WIDTH, |width, label_width| {
        width.max(label_width + TYPE_PADDING)
    })
}

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
    {
        widgets::card_frame().show(ui, |ui| {
            ui.colored_label(theme::ROSE_LIGHT, t().rules_next_connect);
        });
        ui.add_space(16.0);
    }
    let can_add = state.can_edit_rules();
    filter_controls(ui, &mut state.rule_screen.filter, set, can_add, actions);
    ui.add_space(8.0);
    ui.add(egui::Label::new(RichText::new(t().order_hint).small().color(theme::TEXT_DIM)).wrap());
    ui.add_space(12.0);

    let visible = visible_rules(set, &state.rule_screen.filter);
    let rule_type = type_width(ui);
    let widths = TableWidths {
        rule_type,
        value: (ui.available_width()
            - 2.0 * TABLE_INSET
            - HANDLE_WIDTH
            - rule_type
            - TARGET_WIDTH
            - ENABLED_WIDTH
            - REMOVE_WIDTH)
            .max(140.0),
    };
    table_header(ui, widths);
    if visible.is_empty() && !set.rules.is_empty() {
        ui.colored_label(theme::TEXT_MUTED, t().no_rules_match);
    }
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.y = 0.0;
        for (index, rule) in visible {
            ui.push_id((set.id.as_str(), rule.id.as_str()), |ui| {
                rule_row(ui, state, set, rule, index, widths, actions);
            });
        }
        default_rule(ui, state, set, widths, actions);
    });
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
        egui::Popup::menu(&menu).show(|ui| {
            ui.set_min_width(180.0);
            if !active
                && ui
                    .add_enabled(state.can_edit_rules(), egui::Button::new(t().make_active))
                    .clicked()
            {
                actions.push(Action::SelectRuleSet(Some(set.id.clone())));
                ui.close();
            }
            if ui
                .add_enabled(state.can_edit_rules(), egui::Button::new(t().new_set))
                .clicked()
            {
                actions.push(Action::OpenCreateSet);
                ui.close();
            }
            if ui
                .add_enabled(state.can_edit_rules(), egui::Button::new(t().rename))
                .clicked()
            {
                actions.push(Action::OpenRenameSet);
                ui.close();
            }
            ui.separator();
            if ui
                .add_enabled(
                    state.can_edit_rules(),
                    egui::Button::new(RichText::new(t().delete).color(theme::ERROR)),
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
    let label_width = ui
        .painter()
        .layout_no_wrap(
            t().rule_set_label.to_owned(),
            egui::TextStyle::Small.resolve(ui.style()),
            theme::TEXT_DIM,
        )
        .size()
        .x;
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
    let width = (12.0 + label_width + 10.0 + name_width + active_width + 36.0).max(220.0);
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
            painter.text(
                egui::pos2(left, center_y),
                egui::Align2::LEFT_CENTER,
                t().rule_set_label,
                egui::TextStyle::Small.resolve(ui.style()),
                theme::TEXT_DIM,
            );
            let name_left = left + label_width + 10.0;
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
            if active {
                painter.text(
                    egui::pos2(name_left + name_width + 12.0, center_y),
                    egui::Align2::LEFT_CENTER,
                    t().active,
                    egui::TextStyle::Small.resolve(ui.style()),
                    theme::ROSE_LIGHT,
                );
            }
            icons::paint(
                painter,
                egui::pos2(rect.right() - 18.0, center_y),
                Icon::Chevron { open: true },
                theme::TEXT_DIM,
            );
        })
        .response
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    egui::Popup::menu(&response).show(|ui| {
        ui.set_min_width(width);
        for item in &state.config.rule_sets {
            let selected = item.id == set.id;
            let is_active = state.config.active_rule_set.as_ref() == Some(&item.id);
            ui.horizontal(|ui| {
                if ui
                    .selectable_label(selected, state.text(&item.name))
                    .clicked()
                {
                    actions.push(Action::ChooseRuleSet(item.id.clone()));
                    ui.close();
                }
                if is_active {
                    ui.label(RichText::new(t().active).small().color(theme::ROSE_LIGHT));
                }
            });
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
                let search = ui.add(
                    egui::TextEdit::singleline(&mut filter.search)
                        .hint_text(t().search_rules)
                        .desired_width(260.0)
                        .min_size(egui::vec2(260.0, 38.0))
                        .margin(egui::Margin {
                            left: 32,
                            right: 8,
                            top: 8,
                            bottom: 8,
                        }),
                );
                icons::paint(
                    ui.painter(),
                    egui::pos2(search.rect.left() + 16.0, search.rect.center().y),
                    Icon::Search,
                    theme::TEXT_DIM,
                );
                if let Some(kind) =
                    widgets::segmented(ui, "rule_type_filter", filter.kind, &options, false, true)
                {
                    actions.push(Action::SetRuleTypeFilter(kind));
                }
                let mut selected = filter.target;
                egui::ComboBox::from_id_salt("rule_target_filter")
                    .selected_text(selected.map(target_label).unwrap_or(t().any_action))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut selected, None, t().any_action);
                        for target in [RuleTarget::Proxy, RuleTarget::Direct, RuleTarget::Block] {
                            ui.selectable_value(
                                &mut selected,
                                Some(target),
                                RichText::new(target_label(target)).color(target_color(target)),
                            );
                        }
                    });
                if selected != filter.target {
                    actions.push(Action::SetRuleTargetFilter(selected));
                }
            });
        },
        |ui| widgets::button_fill(ui, t().new_rule_button, can_add).clicked(),
    );
    if add_rule {
        actions.push(Action::OpenAddRule);
    }
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
    table_cell(ui, width, ROW_HEIGHT, |ui| {
        ui.vertical(|ui| {
            ui.set_width(width);
            ui.spacing_mut().item_spacing.y = 0.0;
            ui.add_space(((ROW_HEIGHT - content_height) / 2.0).max(0.0));
            content(ui);
        });
    })
}

fn target_cell(ui: &mut egui::Ui, content: impl FnOnce(&mut egui::Ui)) -> egui::Response {
    table_cell(ui, TARGET_WIDTH, ROW_HEIGHT, |ui| {
        ui.add_space((TARGET_WIDTH - TARGET_COMBO_WIDTH) / 2.0);
        ui.vertical(|ui| {
            ui.set_width(TARGET_COMBO_WIDTH);
            ui.spacing_mut().item_spacing.y = 0.0;
            ui.add_space(
                ((ROW_HEIGHT - ui.spacing().interact_size.y) / 2.0 - TARGET_COMBO_TOP_OFFSET)
                    .max(0.0),
            );
            content(ui);
        });
    })
}

fn table_header(ui: &mut egui::Ui, widths: TableWidths) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.add_space(TABLE_INSET);
        table_cell(ui, HANDLE_WIDTH, HEADER_HEIGHT, |_| {});
        table_cell(ui, widths.rule_type, HEADER_HEIGHT, |ui| {
            ui.label(t().r#type);
        });
        table_cell(ui, widths.value, HEADER_HEIGHT, |ui| {
            ui.label(t().value);
        });
        table_cell(ui, TARGET_WIDTH, HEADER_HEIGHT, |ui| {
            ui.add_sized(
                [TARGET_WIDTH, HEADER_HEIGHT],
                egui::Label::new(t().target).halign(egui::Align::Center),
            );
        });
        table_cell(ui, ENABLED_WIDTH, HEADER_HEIGHT, |ui| {
            ui.add_sized(
                [ENABLED_WIDTH, HEADER_HEIGHT],
                egui::Label::new(t().enabled).halign(egui::Align::Center),
            );
        });
    });
}

fn rule_row(
    ui: &mut egui::Ui,
    state: &State,
    set: &RuleSet,
    rule: &Rule,
    index: usize,
    widths: TableWidths,
    actions: &mut Vec<Action>,
) {
    let reorder = state.can_edit_rules() && !state.rule_screen.filter.is_active();
    let dragged =
        reorder && egui::DragAndDrop::payload::<RuleId>(ui.ctx()).is_some_and(|id| *id == rule.id);
    let mut frame = widgets::card_frame().inner_margin(egui::Margin::symmetric(10, 0));
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
                    ui.spacing_mut().item_spacing.x = 0.0;
                    table_cell(ui, HANDLE_WIDTH, ROW_HEIGHT, |ui| {
                        if reorder {
                            ui.dnd_drag_source(ui.id().with("handle"), rule.id.clone(), |ui| {
                                icons::icon_button(ui, Icon::Grip, true);
                            });
                        } else {
                            icons::icon_button(ui, Icon::Grip, false)
                                .on_hover_text(t().reorder_disabled);
                        }
                    });
                    table_cell(ui, widths.rule_type, ROW_HEIGHT, |ui| {
                        ui.label(rule_type(rule));
                    });
                    let value_height = match &rule.matcher {
                        RuleMatcher::Process(ProcessMatch::Path(path))
                            if path.parent().is_some() =>
                        {
                            ui.text_style_height(&egui::TextStyle::Body)
                                + ui.text_style_height(&egui::TextStyle::Small)
                        }
                        _ => ui.text_style_height(&egui::TextStyle::Body),
                    };
                    value_cell(ui, widths.value, value_height, |ui| {
                        rule_value(ui, state, rule);
                    });
                    target_cell(ui, |ui| {
                        let mut target = rule.target;
                        if !state.can_edit_rules() {
                            ui.disable();
                        }
                        egui::ComboBox::from_id_salt("target")
                            .selected_text(
                                RichText::new(target_label(target)).color(target_color(target)),
                            )
                            .width(TARGET_COMBO_WIDTH)
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
                        if target != rule.target {
                            actions.push(Action::SetRuleTarget(rule.id.clone(), target));
                        }
                    });
                    table_cell(ui, ENABLED_WIDTH, ROW_HEIGHT, |ui| {
                        ui.add_space((ENABLED_WIDTH - 38.0) / 2.0);
                        let mut enabled = rule.enabled;
                        if widgets::toggle(ui, &mut enabled, state.can_edit_rules()).changed() {
                            actions.push(Action::SetRuleEnabled(rule.id.clone(), enabled));
                        }
                    });
                    table_cell(ui, REMOVE_WIDTH, ROW_HEIGHT, |ui| {
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
        ui.add(egui::Label::new(RichText::new(&filename).size(16.0).strong()).truncate())
            .on_hover_text(filename);
        if let Some(parent) = path.parent() {
            let folder = state.text(&parent.to_string_lossy());
            ui.add(
                egui::Label::new(RichText::new(&folder).small().color(theme::TEXT_DIM)).truncate(),
            )
            .on_hover_text(folder);
        }
    } else {
        let value = state.text(&rosetun_core::rule_value_text(&rule.matcher));
        let tooltip = rosetun_core::rule_value_ascii(&rule.matcher)
            .map(|ascii| format!("{value}\n{}", t().stored_as(&state.text(&ascii))))
            .unwrap_or_else(|| value.clone());
        ui.add(egui::Label::new(&value).truncate())
            .on_hover_text(tooltip);
    }
}

fn default_rule(
    ui: &mut egui::Ui,
    state: &State,
    set: &RuleSet,
    widths: TableWidths,
    actions: &mut Vec<Action>,
) {
    let response = ui.push_id("default_rule", |ui| {
        egui::Frame::new()
            .inner_margin(egui::Margin::symmetric(0, 2))
            .show(ui, |ui| {
                widgets::card_frame()
                    .fill(theme::PANEL)
                    .inner_margin(egui::Margin::symmetric(10, 0))
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 0.0;
                            table_cell(ui, HANDLE_WIDTH, ROW_HEIGHT, |_| {});
                            table_cell(ui, widths.rule_type, ROW_HEIGHT, |ui| {
                                ui.label(t().default)
                                    .on_hover_text(t().default_rule_tooltip);
                            })
                            .on_hover_text(t().default_rule_tooltip);
                            let value_height = ui.text_style_height(&egui::TextStyle::Body)
                                + ui.text_style_height(&egui::TextStyle::Small);
                            value_cell(ui, widths.value, value_height, |ui| {
                                ui.add(
                                    egui::Label::new(RichText::new(t().all_other_traffic).strong())
                                        .truncate(),
                                );
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(t().default_fallback)
                                            .small()
                                            .color(theme::TEXT_DIM),
                                    )
                                    .truncate(),
                                )
                                .on_hover_text(t().default_fallback);
                            });
                            target_cell(ui, |ui| {
                                let mut target = set.default_target;
                                if !state.can_edit_rules() {
                                    ui.disable();
                                }
                                ui.visuals_mut().widgets.inactive.bg_fill = theme::PANEL;
                                ui.visuals_mut().widgets.noninteractive.bg_fill = theme::PANEL;
                                egui::ComboBox::from_id_salt("target")
                                    .selected_text(
                                        RichText::new(target_label(target))
                                            .color(target_color(target)),
                                    )
                                    .width(TARGET_COMBO_WIDTH)
                                    .show_ui(ui, |ui| {
                                        for value in [RuleTarget::Proxy, RuleTarget::Direct] {
                                            ui.selectable_value(
                                                &mut target,
                                                value,
                                                RichText::new(target_label(value))
                                                    .color(target_color(value)),
                                            );
                                        }
                                        if set.default_target == RuleTarget::Block {
                                            ui.selectable_value(
                                                &mut target,
                                                RuleTarget::Block,
                                                RichText::new(t().block)
                                                    .color(target_color(RuleTarget::Block)),
                                            );
                                        }
                                    });
                                if target != set.default_target {
                                    actions.push(Action::SetDefaultTarget(target));
                                }
                            });
                            table_cell(ui, ENABLED_WIDTH, ROW_HEIGHT, |_| {});
                            table_cell(ui, REMOVE_WIDTH, ROW_HEIGHT, |_| {});
                        });
                    });
            })
            .response
    });
    let rect = response.inner.rect;
    ui.painter().line_segment(
        [
            egui::pos2(rect.left(), rect.top() + 2.0),
            egui::pos2(rect.right(), rect.top() + 2.0),
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

fn rule_type(rule: &Rule) -> &'static str {
    match &rule.matcher {
        RuleMatcher::Domain(DomainMatch::Exact(_) | DomainMatch::Suffix(_)) => t().domain,
        RuleMatcher::Domain(DomainMatch::Keyword(_)) => t().keyword,
        RuleMatcher::Process(_) => t().process,
        RuleMatcher::IpCidr(_) => strings::IP,
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
                        ui.label(state.text(&rosetun_core::rule_value_text(&rule.matcher)));
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
    fn table_cells_keep_columns_and_center_contents() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.set_width(800.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    let type_cell = table_cell(ui, MIN_TYPE_WIDTH, ROW_HEIGHT, |ui| {
                        ui.label("Process");
                    });
                    let body_height = ui.text_style_height(&egui::TextStyle::Body);
                    let small_height = ui.text_style_height(&egui::TextStyle::Small);
                    let mut single_label = egui::Rect::NOTHING;
                    let single = value_cell(ui, 160.0, body_height, |ui| {
                        single_label = ui.add(egui::Label::new("app.exe").truncate()).rect;
                    });
                    let mut first_line = egui::Rect::NOTHING;
                    let mut second_line = egui::Rect::NOTHING;
                    let double = value_cell(ui, 160.0, body_height + small_height, |ui| {
                        first_line = ui.add(egui::Label::new("app.exe").truncate()).rect;
                        second_line = ui
                            .add(egui::Label::new(RichText::new("C:\\Apps").small()).truncate())
                            .rect;
                    });
                    assert!((single.rect.left() - type_cell.rect.right()).abs() < 1.0);
                    assert!((double.rect.left() - single.rect.right()).abs() < 1.0);
                    assert!((single.rect.width() - 160.0).abs() < 1.0);
                    assert!((single_label.center().y - single.rect.center().y).abs() < 3.0);
                    assert!(
                        ((first_line.top() + second_line.bottom()) / 2.0 - double.rect.center().y)
                            .abs()
                            < 3.0
                    );
                    let mut combo_rect = egui::Rect::NOTHING;
                    let target_cell = target_cell(ui, |ui| {
                        combo_rect = egui::ComboBox::from_id_salt("target")
                            .selected_text("Proxy")
                            .width(TARGET_COMBO_WIDTH)
                            .show_ui(ui, |_| {})
                            .response
                            .rect;
                    });
                    let mut checked = true;
                    let mut toggle_rect = egui::Rect::NOTHING;
                    let enabled_cell = table_cell(ui, ENABLED_WIDTH, ROW_HEIGHT, |ui| {
                        ui.add_space((ENABLED_WIDTH - 38.0) / 2.0);
                        toggle_rect = widgets::toggle(ui, &mut checked, true).rect;
                    });
                    assert!(
                        (combo_rect.center().x - target_cell.rect.center().x).abs() < 3.0,
                        "combo horizontal: {:?} vs {:?}",
                        combo_rect,
                        target_cell.rect
                    );
                    assert!(
                        (combo_rect.center().y - target_cell.rect.center().y).abs() < 3.0,
                        "combo vertical: {:?} vs {:?}",
                        combo_rect,
                        target_cell.rect
                    );
                    assert!(
                        (toggle_rect.center().x - enabled_cell.rect.center().x).abs() < 3.0,
                        "checkbox horizontal: {:?} vs {:?}",
                        toggle_rect,
                        enabled_cell.rect
                    );
                });
            });
        });
        output.textures_delta.clear();
    }
}
