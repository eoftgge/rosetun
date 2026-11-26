use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use rosetun_config::{ExitId, ProcessMatch};

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
    /// What the closed button shows. An exit drops "Through VPN": its colour already says it.
    pub(super) button: String,
    pub(super) color: Color32,
    pub(super) country: Option<(String, bool)>,
    /// A section title drawn above this entry.
    pub(super) section: Option<String>,
}

impl TargetChoice {
    pub(super) fn plain(target: RuleTarget) -> Self {
        let label = target_label(target);
        Self {
            destination: target.into(),
            button: label.clone(),
            label,
            color: target_color(target),
            country: None,
            section: None,
        }
    }

    pub(super) fn of(destination: RuleDestination, exits: &[Exit]) -> Self {
        let label = destination_label(&destination, exits);
        let button = match &destination {
            RuleDestination::Exit(id) => exits
                .iter()
                .find(|exit| &exit.id == id)
                .map(|exit| crate::display::safe_text(&exit.name)),
            _ => None,
        };
        Self {
            button: button.unwrap_or_else(|| label.clone()),
            label,
            color: destination_color(&destination),
            country: None,
            destination,
            section: None,
        }
    }
}

/// A rule row's choices: the plain targets, then "Your exits". New exits are made in the dialog.
pub(super) fn rule_target_choices(config: &rosetun_config::AppConfig) -> Vec<TargetChoice> {
    let exits = &config.exits;
    let mut choices: Vec<_> = [RuleTarget::Proxy, RuleTarget::Direct, RuleTarget::Block]
        .into_iter()
        .map(TargetChoice::plain)
        .collect();
    for (index, exit) in exits.iter().enumerate() {
        let mut choice = TargetChoice::of(RuleDestination::Exit(exit.id.clone()), exits);
        choice.label = crate::display::safe_text(&exit.name);
        choice.country = crate::destinations::exit_display_country(config, exit)
            .map(|code| (code, config.interface.show_country_flags));
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
    target_picker(ui, id_salt, current, choices, enabled, false)
}

/// Full-width form-styled target picker matching TextField height, fill, and border.
pub(super) fn target_field(
    ui: &mut egui::Ui,
    id_salt: impl std::hash::Hash + std::fmt::Debug,
    current: &TargetChoice,
    choices: &[TargetChoice],
    enabled: bool,
) -> Option<RuleDestination> {
    target_picker(ui, id_salt, current, choices, enabled, true)
}

fn target_picker(
    ui: &mut egui::Ui,
    id_salt: impl std::hash::Hash + std::fmt::Debug,
    current: &TargetChoice,
    choices: &[TargetChoice],
    enabled: bool,
    full_field: bool,
) -> Option<RuleDestination> {
    ui.push_id(egui::Id::unique(id_salt), |ui| {
        let enabled = enabled && ui.is_enabled();
        let sense = if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        };
        let size = if full_field {
            egui::vec2(ui.available_width().floor(), widgets::field_height(ui))
        } else {
            egui::vec2(TARGET_WIDTH, 34.0)
        };
        let (rect, response) = ui.allocate_exact_size(size, sense);
        let open = egui::Popup::is_id_open(ui.ctx(), egui::Popup::default_response_id(&response));
        if ui.is_rect_visible(rect) {
            if full_field {
                let border = if open {
                    theme::palette().accent_base
                } else if response.hovered() && enabled {
                    theme::palette().border_strong
                } else {
                    theme::palette().border
                };
                ui.painter().rect(
                    rect,
                    theme::RADIUS,
                    theme::palette().input,
                    Stroke::new(theme::stroke::HAIRLINE, border),
                    egui::StrokeKind::Inside,
                );
            } else {
                if response.hovered() && enabled {
                    ui.painter()
                        .rect_filled(rect, theme::RADIUS, theme::palette().border);
                }
                ui.painter().rect_stroke(
                    rect,
                    theme::RADIUS,
                    Stroke::new(theme::stroke::HAIRLINE, theme::palette().border_strong),
                    egui::StrokeKind::Inside,
                );
            }
            let color = if enabled {
                current.color
            } else {
                theme::disabled()
            };
            ui.painter().circle_filled(
                egui::pos2(rect.left() + TARGET_DOT_X, rect.center().y),
                3.5,
                color,
            );
            let text = if full_field {
                &current.label
            } else {
                &current.button
            };
            let mut job = egui::text::LayoutJob::simple_singleline(
                text.clone(),
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
                Icon::Chevron { open: 1.0 },
                if enabled {
                    theme::palette().text_dim
                } else {
                    theme::disabled()
                },
            );
        }
        if !enabled {
            return None;
        }
        let response = response
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .on_hover_text(&current.label);
        let mut selected = None;
        widgets::menu_popup(&response).show(|ui| {
            let trigger_inner = (rect.width() - ui.spacing().menu_margin.sum().x).max(0.0);
            let font = egui::TextStyle::Button.resolve(ui.style());
            let section_font = egui::TextStyle::Small.resolve(ui.style());
            let mut needed = trigger_inner;
            for choice in choices {
                let label_w = ui
                    .painter()
                    .layout_no_wrap(choice.label.clone(), font.clone(), choice.color)
                    .size()
                    .x;
                needed = needed.max(TARGET_TEXT_X + label_w + 34.0);
                if let Some(section) = &choice.section {
                    let section_w = ui
                        .painter()
                        .layout_no_wrap(
                            section.clone(),
                            section_font.clone(),
                            theme::palette().text_dim,
                        )
                        .size()
                        .x;
                    needed = needed.max(section_w + 16.0);
                }
            }
            let width = if full_field {
                needed.max(trigger_inner)
            } else {
                needed.min(TARGET_MENU_WIDTH)
            };
            ui.set_min_width(width);
            for choice in choices {
                if let Some(section) = &choice.section {
                    ui.separator();
                    ui.label(
                        RichText::new(section)
                            .small()
                            .color(theme::palette().text_dim),
                    );
                }
                let item = ui
                    .scope(|ui| {
                        ui.set_min_width(width);
                        ui.spacing_mut().button_padding.x = TARGET_TEXT_X;
                        ui.visuals_mut().override_text_color = Some(choice.color);
                        widgets::menu_item_with_country(
                            ui,
                            widgets::MenuItem {
                                label: &choice.label,
                                enabled: true,
                                selected: choice.destination == current.destination,
                                danger: false,
                                note: None,
                            },
                            choice
                                .country
                                .as_ref()
                                .map(|(code, flags)| (code.as_str(), *flags)),
                        )
                    })
                    .inner;
                if choice.country.is_none() && ui.is_rect_visible(item.rect) {
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

pub(super) fn rule_icon(matcher: &RuleMatcher) -> Icon {
    match matcher {
        RuleMatcher::Domain(_) => Icon::Globe,
        RuleMatcher::Process(_) => Icon::App,
        RuleMatcher::IpCidr(_) => Icon::Stack,
        RuleMatcher::List { .. } => Icon::List,
        RuleMatcher::Group { .. } => Icon::Group,
    }
}

/// What every row of one table shares, computed once per frame.
pub(super) struct RowContext<'a> {
    pub(super) set: &'a RuleSet,
    pub(super) target_choices: Vec<TargetChoice>,
    /// `destinations::unresolved_exits`, which resolves every exit.
    pub(super) unresolved: &'a BTreeSet<ExitId>,
    /// `running_programs`, for the icons of rules by file name.
    pub(super) running: HashMap<String, &'a Path>,
}

/// Paths of programs already listed elsewhere (the add-rule dialog, the
/// Traffic tab), by lowercase file name. Nothing is read for the table.
pub(super) fn running_programs(state: &State) -> HashMap<String, &Path> {
    let dialog = state
        .rules
        .screen
        .add
        .iter()
        .flat_map(|dialog| &dialog.processes)
        .filter_map(|group| group.path.as_deref());
    let traffic = state.traffic.connections.programs.paths().map(Path::new);
    dialog
        .chain(traffic)
        .map(|path| {
            let name = crate::programs::file_name(&path.to_string_lossy()).to_lowercase();
            (name, path)
        })
        .collect()
}

/// The executable whose icon a rule shows: its own full path, or a running
/// program with the rule's file name.
pub(super) fn program_icon_path<'a>(
    matcher: &'a RuleMatcher,
    running: &HashMap<String, &'a Path>,
) -> Option<&'a Path> {
    match matcher {
        RuleMatcher::Process(ProcessMatch::Path(path)) => Some(path),
        RuleMatcher::Process(ProcessMatch::Name(name)) => {
            running.get(&name.to_lowercase()).copied()
        }
        _ => None,
    }
}

/// A program rule's badge with the program's own icon when there is one.
fn program_badge(ui: &mut egui::Ui, path: &Path) {
    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(ICON_WIDTH, ICON_WIDTH), egui::Sense::hover());
    if !ui.is_rect_visible(rect) || crate::program_icons::paint(ui, rect, ICON_WIDTH, path) {
        return;
    }
    ui.painter()
        .rect_filled(rect, theme::RADIUS_INNER, theme::palette().input);
    icons::paint(
        ui.painter(),
        rect.center(),
        Icon::App,
        theme::palette().text_muted,
    );
}

const EXPAND_WIDTH: f32 = 28.0;
const EXPAND_GAP: f32 = theme::space::XS;

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
    let is_group = matches!(rule.matcher, RuleMatcher::Group { .. });
    let group_expanded = is_group && state.rules.screen.expanded_groups.contains(&rule.id);
    let expand_progress = if is_group {
        widgets::reveal_progress(
            ui.ctx(),
            ui.scope_id().with("group_open"),
            group_expanded,
            state.config.interface.reduce_motion,
        )
    } else {
        0.0
    };
    let selected = !temporary && state.rules.screen.selected_rules.contains(&rule.id);
    let reorder = !temporary && state.can_edit_rules() && !state.rules.screen.filter.is_active();
    let dragged = reorder
        && egui::DragAndDrop::payload::<RuleId>(ui.ctx()).is_some_and(|id| {
            *id == rule.id || (selected && state.rules.screen.selected_rules.contains(&*id))
        });
    let mut frame =
        widgets::card_frame().inner_margin(theme::margin::symmetric(theme::space::M, 0.0));
    let fill = if selected {
        theme::palette().input
    } else {
        theme::palette().card
    };
    if dragged {
        frame = frame.fill(theme::alpha::fade(fill, theme::alpha::DISABLED_ALPHA));
    } else if !rule.enabled {
        frame = frame.fill(fill.gamma_multiply(theme::alpha::MUTED));
    } else {
        frame = frame.fill(fill);
    }
    let row_value_width = if is_group {
        (value_width - EXPAND_WIDTH - EXPAND_GAP).max(0.0)
    } else {
        value_width
    };
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
                        ui.dnd_drag_source(ui.scope_id().with("handle"), rule.id.clone(), |ui| {
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
                        icons::icon_badge_colored(
                            ui,
                            Icon::Clock,
                            ICON_WIDTH,
                            theme::palette().text_dim,
                        )
                        .on_hover_text(tr!("temporary-hint"));
                    } else if let Some(path) = program_icon_path(&rule.matcher, &rows.running) {
                        program_badge(ui, path);
                    } else {
                        icons::icon_badge(ui, rule_icon(&rule.matcher), ICON_WIDTH);
                    }
                });
                ui.add_space(ICON_GAP);
                let value_height = ui.text_style_height(&egui::TextStyle::Body)
                    + ui.text_style_height(&egui::TextStyle::Small);
                value_cell(ui, row_value_width, value_height, |ui| {
                    rule_value(ui, state, rule, index.map(|_| &set.id), rows.unresolved);
                });
                if is_group {
                    table_cell(ui, EXPAND_WIDTH, theme::RULE_ROW, |ui| {
                        let btn = icons::icon_button_sized(
                            ui,
                            Icon::Chevron {
                                open: expand_progress,
                            },
                            true,
                            EXPAND_WIDTH,
                        )
                        .on_hover_text(tr!("group-expand-hint"));
                        if btn.clicked() {
                            actions.push(Action::ToggleGroupExpanded(rule.id.clone()));
                        }
                    });
                    ui.add_space(EXPAND_GAP);
                }
                table_cell(ui, TARGET_WIDTH, theme::RULE_ROW, |ui| {
                    let exits = &state.config.exits;
                    if let Some(target) = target_button(
                        ui,
                        "target",
                        &TargetChoice::of(RuleDestination::of(rule), exits),
                        &rows.target_choices,
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
                let can_open_menu = if temporary {
                    state.can_change_temporary() && !state.operations.rules_edit
                } else {
                    state.can_edit_rules()
                };
                table_cell(ui, MENU_WIDTH, theme::RULE_ROW, |ui| {
                    let menu = icons::icon_button_sized(ui, Icon::More, can_open_menu, MENU_WIDTH)
                        .on_hover_text(tr!("more-actions"));
                    if can_open_menu {
                        widgets::menu_popup(&menu).show(|ui| {
                            rule_row_menu(
                                ui, state, set, rule, index, temporary, selected, actions,
                            );
                        });
                    }
                });
            });
            if let RuleMatcher::Group { items, .. } = &rule.matcher {
                widgets::reveal(
                    ui,
                    ui.scope_id().with("group_drawer"),
                    expand_progress,
                    |ui| {
                        group_drawer(ui, state, rule, items, temporary, actions);
                    },
                );
            }
        })
        .response;

    if selected {
        ui.painter().rect_filled(
            egui::Rect::from_min_size(
                egui::pos2(response.rect.left(), response.rect.top() + 10.0),
                egui::vec2(3.0, response.rect.height() - 20.0),
            ),
            0.0,
            theme::palette().accent_base,
        );
    }
    if !temporary
        && !state.config.interface.reduce_motion
        && let Some((highlighted, generation)) = &state.rules.screen.highlight_rule
        && highlighted == &rule.id
    {
        let pulse_id = ui.scope_id().with(("rule_highlight_pulse", *generation));
        let now = ui.ctx().input(|input| input.time);
        let started = ui
            .ctx()
            .data_mut(|data| *data.get_temp_mut_or_insert_with(pulse_id, || now));
        let duration = f64::from(crate::motion::NORMAL) * 2.0;
        let t = ((now - started) / duration) as f32;
        if t < 1.0 {
            let strength = 1.0 - crate::motion::ease_out(t);
            let accent = theme::palette().accent_base;
            ui.painter().rect(
                response.rect,
                egui::CornerRadius::same(theme::RADIUS),
                accent.gamma_multiply(theme::alpha::TINT * strength),
                Stroke::new(theme::stroke::HAIRLINE, accent.gamma_multiply(strength)),
                egui::StrokeKind::Inside,
            );
            ui.ctx().request_repaint();
        }
    }
    let can_open_menu = if temporary {
        state.can_change_temporary() && !state.operations.rules_edit
    } else {
        state.can_edit_rules()
    };
    let left = response.rect.left() + ROW_INSET + HANDLE_WIDTH + HANDLE_GAP;
    let expand_space = if is_group {
        EXPAND_WIDTH + EXPAND_GAP
    } else {
        0.0
    };
    let right = response.rect.right()
        - ROW_INSET
        - MENU_WIDTH
        - MENU_GAP
        - TOGGLE_WIDTH
        - TARGET_GAP
        - TARGET_WIDTH
        - expand_space;
    let top_bottom = (response.rect.top() + theme::RULE_ROW).min(response.rect.bottom());
    let body = egui::Rect::from_min_max(
        egui::pos2(left, response.rect.top()),
        egui::pos2(right.max(left), top_bottom),
    );
    let click = ui.interact(
        body,
        ui.scope_id().with("select_rule"),
        egui::Sense::click(),
    );
    if !temporary {
        if is_group && click.double_clicked() {
            actions.push(Action::ToggleGroupExpanded(rule.id.clone()));
        } else if click.clicked() {
            let modifiers = ui.input(|input| input.modifiers);
            actions.push(Action::SelectRule {
                rule: rule.id.clone(),
                additive: modifiers.command,
                range: modifiers.shift,
            });
        } else if click.secondary_clicked() && !selected {
            actions.push(Action::SelectRule {
                rule: rule.id.clone(),
                additive: false,
                range: false,
            });
        }
    }
    if can_open_menu {
        widgets::context_menu_popup(&click).show(|ui| {
            rule_row_menu(ui, state, set, rule, index, temporary, selected, actions);
        });
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
                Stroke::new(theme::stroke::MARK, theme::palette().accent_base),
            );
            if let Some(payload) = response.dnd_release_payload::<RuleId>()
                && let Some((rules, target)) = drag_target(state, set, &payload, slot)
            {
                actions.push(drop_action(rules, slot, target));
            }
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "context menu mirrors the rule row inputs without allocating an intermediate struct"
)]
fn rule_row_menu(
    ui: &mut egui::Ui,
    state: &State,
    set: &RuleSet,
    rule: &Rule,
    index: Option<usize>,
    temporary: bool,
    selected: bool,
    actions: &mut Vec<Action>,
) {
    let is_group = matches!(rule.matcher, RuleMatcher::Group { .. });
    let multi = selected && state.rules.screen.selected_rules.len() >= 2;
    let source_ids = if multi {
        state.selected_rule_ids()
    } else {
        vec![rule.id.clone()]
    };
    let target_groups: Vec<(&RuleId, String)> = if temporary {
        Vec::new()
    } else {
        set.rules
            .iter()
            .filter_map(|entry| {
                let RuleMatcher::Group { name, .. } = &entry.matcher else {
                    return None;
                };
                source_ids
                    .iter()
                    .any(|id| id != &entry.id)
                    .then(|| (&entry.id, crate::display::safe_text(name)))
            })
            .collect()
    };
    let has_target_groups = !target_groups.is_empty();
    let delete_group = crate::i18n::delete_selected_rules(state.rules.screen.selected_rules.len());
    let add_to_group_label = tr!("group-add-to");
    let mut labels = if multi {
        vec![
            tr!("group-selected"),
            tr!("move-selected-to-top"),
            tr!("move-to-end"),
            delete_group.clone(),
        ]
    } else {
        vec![
            tr!("keep-permanently"),
            tr!("edit"),
            tr!("group-ungroup"),
            tr!("move-to-top"),
            tr!("delete"),
        ]
    };
    if has_target_groups {
        labels.push(add_to_group_label.clone());
    }
    let label_refs: Vec<&str> = labels.iter().map(String::as_str).collect();
    if has_target_groups {
        widgets::menu_choice_width(ui, &label_refs, widgets::MenuWidth::Compact.points());
    } else {
        widgets::menu_content_width(ui, &label_refs, widgets::MenuWidth::Compact.points());
    }
    if multi {
        if widgets::menu_item(
            ui,
            widgets::MenuItem {
                label: &tr!("group-selected"),
                enabled: true,
                selected: false,
                danger: false,
                note: None,
            },
        )
        .clicked()
        {
            actions.push(Action::OpenGroupSelection);
            ui.close();
        }
        if has_target_groups {
            add_to_group_submenu(
                ui,
                &add_to_group_label,
                &target_groups,
                &source_ids,
                actions,
            );
        }
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
                label: &delete_group,
                enabled: true,
                selected: false,
                danger: true,
                note: None,
            },
        )
        .clicked()
        {
            actions.push(Action::DeleteSelectedRules);
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
            if has_target_groups {
                add_to_group_submenu(
                    ui,
                    &add_to_group_label,
                    &target_groups,
                    &source_ids,
                    actions,
                );
            }
            if is_group
                && widgets::menu_item(
                    ui,
                    widgets::MenuItem {
                        label: &tr!("group-ungroup"),
                        enabled: true,
                        selected: false,
                        danger: false,
                        note: None,
                    },
                )
                .clicked()
            {
                actions.push(Action::UngroupRule(rule.id.clone()));
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
                Action::DeleteRule(rule.id.clone())
            });
            ui.close();
        }
    }
}

fn add_to_group_submenu(
    ui: &mut egui::Ui,
    label: &str,
    target_groups: &[(&RuleId, String)],
    source_ids: &[RuleId],
    actions: &mut Vec<Action>,
) {
    widgets::menu_submenu(ui, label, |ui| {
        let names: Vec<&str> = target_groups
            .iter()
            .map(|(_, name)| name.as_str())
            .collect();
        widgets::menu_content_width(ui, &names, widgets::MenuWidth::Compact.points());
        let width = ui.min_rect().width().min(280.0);
        ui.set_width(width);
        let mut picked = false;
        let mut draw_items = |ui: &mut egui::Ui| {
            ui.set_width(ui.available_width().min(width));
            for (group_id, group_name) in target_groups {
                if widgets::menu_item(
                    ui,
                    widgets::MenuItem {
                        label: group_name,
                        enabled: true,
                        selected: false,
                        danger: false,
                        note: None,
                    },
                )
                .clicked()
                {
                    actions.push(Action::AddRulesToGroup(
                        source_ids.to_vec(),
                        (*group_id).clone(),
                    ));
                    picked = true;
                }
            }
        };
        if target_groups.len() > 8 {
            egui::ScrollArea::vertical()
                .id_salt("add_to_group_submenu")
                .max_height(260.0)
                .auto_shrink([false, true])
                .show(ui, draw_items);
        } else {
            draw_items(ui);
        }
        if picked {
            ui.close();
        }
    });
}

fn group_drawer(
    ui: &mut egui::Ui,
    state: &State,
    rule: &Rule,
    items: &[RuleMatcher],
    temporary: bool,
    actions: &mut Vec<Action>,
) {
    let rect = ui.available_rect_before_wrap();
    ui.painter().line_segment(
        [
            egui::pos2(rect.left(), rect.top()),
            egui::pos2(rect.right(), rect.top()),
        ],
        Stroke::new(theme::stroke::HAIRLINE, theme::palette().border),
    );
    ui.add_space(theme::space::S);
    let indent = HANDLE_WIDTH + HANDLE_GAP;
    let can_remove = !temporary && state.can_edit_rules() && items.len() > 1;
    ui.horizontal(|ui| {
        ui.add_space(indent);
        ui.vertical(|ui| {
            ui.set_min_width((ui.available_width() - theme::space::XS).max(0.0));
            ui.spacing_mut().item_spacing.y = theme::space::XS;
            for (item_idx, item) in items.iter().enumerate() {
                ui.push_id(item_idx, |ui| {
                    let (label, caption) = match item {
                        RuleMatcher::List { list, category } => (
                            state.list_rule_name(list, category.as_deref()),
                            tr!("caption-list"),
                        ),
                        _ => {
                            let (val, cap) = rule_lines(item);
                            (state.text(&val), caption_text(&cap))
                        }
                    };
                    egui::Sides::new().shrink_left().height(26.0).show(
                        ui,
                        |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = theme::space::S;
                                icons::icon_badge(ui, rule_icon(item), 22.0);
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&label).color(theme::palette().text),
                                    )
                                    .truncate(),
                                );
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&caption)
                                            .small()
                                            .color(theme::palette().text_dim),
                                    )
                                    .truncate(),
                                );
                            });
                        },
                        |ui| {
                            if !temporary {
                                let hint = if items.len() <= 1 {
                                    tr!("group-last-item-hint")
                                } else {
                                    tr!("group-remove-item-hint")
                                };
                                let btn =
                                    icons::icon_button_sized(ui, Icon::Close, can_remove, 24.0)
                                        .on_hover_text(hint.clone())
                                        .on_disabled_hover_text(hint);
                                if btn.clicked() {
                                    actions
                                        .push(Action::RemoveGroupItem(rule.id.clone(), item_idx));
                                }
                            }
                        },
                    );
                });
            }
            if !temporary {
                ui.add_space(theme::space::XS);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = theme::space::L;
                    if widgets::link(ui, &tr!("edit"), state.can_edit_rules()).clicked() {
                        actions.push(Action::OpenEditRule(rule.id.clone()));
                    }
                    if widgets::link(ui, &tr!("group-ungroup"), state.can_edit_rules()).clicked() {
                        actions.push(Action::UngroupRule(rule.id.clone()));
                    }
                });
            }
        });
    });
    ui.add_space(theme::space::M);
}

pub(super) fn caption_text(caption: &RuleCaption) -> String {
    match caption {
        RuleCaption::ThisAddress => tr!("caption-this-address"),
        RuleCaption::WithSubdomains => tr!("caption-subdomains"),
        RuleCaption::Keyword => tr!("caption-keyword"),
        RuleCaption::AnyFolder => tr!("caption-any-folder"),
        RuleCaption::Path(path) => path.clone(),
        RuleCaption::Addresses => tr!("caption-addresses"),
        RuleCaption::List => tr!("caption-list"),
        RuleCaption::Group { count, preview } => {
            let count_text = i18n::group_items_count(*count);
            if preview.is_empty() {
                count_text
            } else {
                format!("{count_text} • {preview}")
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
            RuleCaption::List,
        ),
        _ => rule_lines(&rule.matcher),
    };
    let value = state.text(&value);
    let caption = caption_text(&caption);
    let caption = if rule.enabled {
        caption
    } else {
        match &rule.matcher {
            RuleMatcher::Process(value)
                if rosetun_config::rules_exchange::translate_process(
                    value,
                    rosetun_config::rules_exchange::System::current(),
                    rosetun_config::rules_exchange::System::current(),
                )
                .1 =>
            {
                tr!("rules-transfer-other-system")
            }
            RuleMatcher::List { list, .. } => state
                .config
                .lists
                .iter()
                .find(|entry| &entry.id == list)
                .map_or_else(
                    || caption.clone(),
                    |entry| match &entry.source {
                        rosetun_config::ListSource::File { original_name }
                            if entry.sha256.is_none() =>
                        {
                            if original_name == "list-required" {
                                tr!("rules-transfer-needs-list")
                            } else {
                                format!("{}: {original_name}", tr!("rules-transfer-needs-file"))
                            }
                        }
                        _ => caption.clone(),
                    },
                ),
            _ => caption,
        }
    };
    let missing = state.missing_list_rule(set, &rule.id);
    let exit_missing = rule.target == RuleTarget::Exit
        && rule.exit.as_ref().is_none_or(|id| unresolved.contains(id));
    let tooltip = if let RuleMatcher::Group { items, .. } = &rule.matcher {
        const MAX_TOOLTIP_ITEMS: usize = 12;
        let mut parts: Vec<String> = items
            .iter()
            .take(MAX_TOOLTIP_ITEMS)
            .map(|item| match item {
                RuleMatcher::List { list, category } => {
                    state.list_rule_name(list, category.as_deref())
                }
                _ => rosetun_core::rule_value_text(item),
            })
            .collect();
        if items.len() > MAX_TOOLTIP_ITEMS {
            parts.push("…".to_owned());
        }
        let list = parts.join(", ");
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
    ui.add(
        egui::Label::new(RichText::new(value).font(font).color(theme::palette().text)).truncate(),
    )
    .on_hover_text(&tooltip);
    if let Some(missing) = missing {
        let warning = if missing.last_good {
            tr!("rule-category-last-good")
        } else {
            tr!("rule-category-disabled")
        };
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = theme::space::XS;
            icons::icon_badge_colored(ui, Icon::Warning, 16.0, theme::error())
                .on_hover_text(tr!("rule-category-hint"));
            ui.add(
                egui::Label::new(RichText::new(warning).small().color(theme::error())).truncate(),
            )
            .on_hover_text(tr!("rule-category-hint"));
        });
    } else if exit_missing {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = theme::space::XS;
            icons::icon_badge_colored(ui, Icon::Warning, 16.0, theme::error());
            ui.add(
                egui::Label::new(
                    RichText::new(tr!("exit-node-missing"))
                        .small()
                        .color(theme::error()),
                )
                .truncate(),
            );
        });
    } else {
        ui.add(
            egui::Label::new(
                RichText::new(state.text(&caption))
                    .small()
                    .color(theme::palette().text_dim),
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
            .fill(theme::palette().panel)
            .inner_margin(theme::margin::symmetric(theme::space::M, 0.0))
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
                                    .color(theme::palette().text),
                            )
                            .truncate(),
                        )
                        .on_hover_text(tr!("default-rule-tooltip"));
                        ui.add(
                            egui::Label::new(
                                RichText::new(state.text(&tr!("default-fallback")))
                                    .small()
                                    .color(theme::palette().text_dim),
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
        Stroke::new(theme::stroke::HAIRLINE, theme::palette().border_strong),
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
            Stroke::new(theme::stroke::MARK, theme::palette().accent_base),
        );
        if let Some(payload) = response.inner.dnd_release_payload::<RuleId>()
            && let Some((rules, target)) = drag_target(state, set, &payload, set.rules.len())
        {
            actions.push(drop_action(rules, set.rules.len(), target));
        }
    }
}
