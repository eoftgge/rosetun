use std::collections::VecDeque;

use eframe::egui::{self, Color32, RichText};
use rosetun_config::ConnectionState;

use crate::actions::{PrimaryAction, ProtectionAction, protection_action};
use crate::errors;
use crate::state::{Action, State, primary_label};
use crate::strings::t;
use crate::{display, strings, theme, widgets};

use super::rose_button::{self, RosePhase};
use super::rules::{target_color, target_label};

pub(crate) fn show(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    if !state.config_ready {
        ui.colored_label(theme::TEXT_DIM, t().loading);
    }
    if !state.helper_available {
        service_banner(ui, state);
        ui.add_space(theme::SECTION_GAP);
    }
    hero_card(ui, state, actions);
    ui.add_space(theme::SECTION_GAP);
    traffic_card(ui, state);
    ui.add_space(theme::SECTION_GAP);
    control_cards(ui, state, actions);
}

fn service_banner(ui: &mut egui::Ui, state: &State) {
    let id = egui::Id::new("service_down_details");
    let expanded = ui.data(|data| data.get_temp::<bool>(id)).unwrap_or(false);
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        egui::Sides::new().shrink_left().wrap().spacing(16.0).show(
            ui,
            |ui| {
                ui.horizontal_top(|ui| {
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(28.0, 28.0), egui::Sense::hover());
                    ui.painter().circle_stroke(
                        rect.center(),
                        13.0,
                        egui::Stroke::new(1.5, theme::ERROR),
                    );
                    ui.painter().text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        "!",
                        egui::FontId::new(18.0, egui::FontFamily::Name(theme::UI_SEMIBOLD.into())),
                        theme::ERROR,
                    );
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(t().service_down_title)
                                .strong()
                                .color(theme::TEXT),
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(t().service_down_body)
                                    .small()
                                    .color(theme::TEXT_DIM),
                            )
                            .wrap(),
                        );
                    });
                });
            },
            |ui| {
                if widgets::outline_button(
                    ui,
                    if expanded {
                        t().hide_details
                    } else {
                        t().details
                    },
                    true,
                )
                .clicked()
                {
                    ui.data_mut(|data| data.insert_temp(id, !expanded));
                }
            },
        );
        if expanded && let Some(error) = &state.helper_error {
            ui.add_space(10.0);
            ui.add(
                egui::Label::new(
                    RichText::new(state.text(&errors::client(t(), error)))
                        .small()
                        .color(theme::TEXT_DIM),
                )
                .wrap(),
            );
        }
    });
}

fn hero_card(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    widgets::card_frame()
        .inner_margin(egui::Margin::symmetric(28, 20))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            let visible_status = state.visible_status();
            let (label, color) = visible_status
                .map_or((t().status_unknown, theme::DISCONNECTED), |status| {
                    state_style(&status.state)
                });
            let selection_changed = visible_status.filter(|status| {
                (status.state.is_active() || status.state.is_transitional())
                    && state
                        .config
                        .active
                        .as_ref()
                        .is_none_or(|selection| status.node.as_ref() != Some(&selection.node))
            });
            ui.horizontal_top(|ui| {
                ui.allocate_ui_with_layout(
                    egui::vec2(240.0, 260.0),
                    egui::Layout::top_down(egui::Align::Center),
                    |ui| {
                        let action = state.primary_action();
                        let phase = rose_button::rose_phase(
                            state.helper_available,
                            visible_status.map(|status| &status.state),
                        );
                        let button_label = if phase == RosePhase::Unavailable {
                            t().unavailable
                        } else {
                            primary_label(state)
                        };
                        if rose_button::rose_button(
                            ui,
                            phase,
                            button_label,
                            action != PrimaryAction::Disabled,
                            state.config.interface.reduce_motion,
                        ) {
                            actions.push(Action::Primary);
                        }
                    },
                );
                ui.add_space(36.0);
                ui.vertical(|ui| {
                    ui.set_min_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 14.0;
                    ui.label(RichText::new(label).size(26.0).color(color));
                    let session = visible_status
                        .and_then(|status| status.since_unix)
                        .map_or_else(
                            || t().no_session.to_owned(),
                            |since| display::session_text(Some(since), display::now_unix()),
                        );
                    ui.colored_label(
                        theme::TEXT_MUTED,
                        strings::plain_link(t().session, &session),
                    );
                    if let Some(status) = visible_status {
                        if let ConnectionState::Failed { reason }
                        | ConnectionState::FailedProtected { reason } = &status.state
                        {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(state.text(reason))
                                        .small()
                                        .color(theme::ERROR),
                                )
                                .wrap(),
                            );
                        }
                        if protection_action(status, state.operations.helper)
                            == ProtectionAction::ConfirmDisconnect
                            && widgets::outline_button(ui, t().turn_off_protection, true).clicked()
                        {
                            actions.push(Action::RequestProtectionOff);
                        }
                    }
                    if server_button(ui, state) {
                        actions.push(Action::RevealServer);
                    }
                    if selection_changed.is_some() {
                        let message = state.config.active_node().map_or_else(
                            || t().selection_cleared.to_owned(),
                            |(_, node)| {
                                let name = display::drop_missing_glyphs(
                                    ui.ctx(),
                                    &egui::TextStyle::Body.resolve(ui.style()),
                                    &state.text(&node.name),
                                );
                                t().selected_pending(&name)
                            },
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(message).small().color(theme::ROSE_LIGHT),
                            )
                            .wrap(),
                        );
                    }
                    let protocol = state.config.active_node().map_or_else(
                        || t().ping_pending.to_owned(),
                        |(_, node)| {
                            strings::node_details(
                                rosetun_core::node_protocol(node),
                                rosetun_core::node_tls(node),
                                rosetun_core::node_transport(node),
                            )
                        },
                    );
                    let engine = visible_status
                        .and_then(|status| status.engine)
                        .unwrap_or(state.config.settings.engine);
                    let protocol_width = (ui.available_width() - 100.0).max(0.0);
                    egui::Grid::new("connection_details")
                        .num_columns(2)
                        .spacing(egui::vec2(20.0, 4.0))
                        .show(ui, |ui| {
                            ui.label(RichText::new(t().protocol).small().color(theme::TEXT_DIM));
                            ui.label(RichText::new(t().engine).small().color(theme::TEXT_DIM));
                            ui.end_row();
                            ui.add_sized(
                                [protocol_width, 0.0],
                                egui::Label::new(protocol).truncate(),
                            );
                            ui.label(engine.as_str())
                                .on_hover_text(t().engine_detail(engine.as_str()));
                            ui.end_row();
                        });
                });
            });
        });
}

/// The selected server as a wide button; returns true when clicked.
fn server_button(ui: &mut egui::Ui, state: &State) -> bool {
    let width = ui.available_width();
    let response = egui::Frame::new()
        .fill(theme::INPUT)
        .stroke(egui::Stroke::new(1.0, theme::BORDER_STRONG))
        .corner_radius(theme::RADIUS)
        .inner_margin(egui::Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.set_min_width(width - 28.0);
            ui.horizontal(|ui| {
                let name_width = (ui.available_width() - 100.0).max(0.0);
                ui.allocate_ui_with_layout(
                    egui::vec2(name_width, 0.0),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.set_width(name_width);
                        if let Some((subscription, node)) = state.config.active_node() {
                            let name = display::drop_missing_glyphs(
                                ui.ctx(),
                                &egui::FontId::new(
                                    17.0,
                                    egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
                                ),
                                &state.text(&node.name),
                            );
                            ui.add(
                                egui::Label::new(
                                    RichText::new(name)
                                        .font(egui::FontId::new(
                                            17.0,
                                            egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
                                        ))
                                        .color(theme::TEXT),
                                )
                                .truncate(),
                            );
                            let subscription = state.text(&subscription.name);
                            let address = state.text(&rosetun_core::node_address(node));
                            let detail =
                                format!("{} · {subscription} · {address}", t().subscription_label);
                            ui.add(
                                egui::Label::new(
                                    RichText::new(detail).small().color(theme::TEXT_DIM),
                                )
                                .truncate(),
                            );
                        } else {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(t().select_server)
                                        .size(17.0)
                                        .strong()
                                        .color(theme::TEXT),
                                )
                                .truncate(),
                            );
                        }
                    },
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(t().server_change).color(theme::ROSE_LIGHT));
                });
            });
        })
        .response;
    let response = ui
        .interact(
            response.rect,
            response.id.with("server_button"),
            egui::Sense::click(),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    if response.hovered() {
        ui.painter().rect_stroke(
            response.rect,
            theme::RADIUS,
            egui::Stroke::new(1.0, theme::ROSE_DARK),
            egui::StrokeKind::Inside,
        );
    }
    response.clicked()
}

fn traffic_card(ui: &mut egui::Ui, state: &State) {
    let traffic = state.visible_status().and_then(|status| {
        matches!(
            status.state,
            ConnectionState::Connected | ConnectionState::Reconnecting
        )
        .then_some(&status.traffic)
    });
    let (down, up, total) = traffic.map_or((0, 0, 0), |traffic| {
        (
            traffic.down_bps,
            traffic.up_bps,
            traffic.down_total.saturating_add(traffic.up_total),
        )
    });
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(180.0, 96.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.set_width(180.0);
                    traffic_row(
                        ui,
                        theme::ROSE_LIGHT,
                        t().traffic_down,
                        &t().rate(down),
                        traffic.is_some(),
                    );
                    traffic_row(
                        ui,
                        theme::ROSE_DARK,
                        t().traffic_up,
                        &t().rate(up),
                        traffic.is_some(),
                    );
                    ui.add_space(4.0);
                    let (line, _) =
                        ui.allocate_exact_size(egui::vec2(180.0, 1.0), egui::Sense::hover());
                    ui.painter().hline(
                        line.x_range(),
                        line.center().y,
                        egui::Stroke::new(1.0, theme::BORDER),
                    );
                    ui.add_space(4.0);
                    egui::Sides::new().shrink_left().show(
                        ui,
                        |ui| {
                            ui.label(
                                RichText::new(t().traffic_session)
                                    .small()
                                    .color(theme::TEXT_DIM),
                            );
                        },
                        |ui| {
                            ui.label(RichText::new(t().bytes(total)).strong().color(
                                if traffic.is_some() {
                                    theme::TEXT
                                } else {
                                    theme::TEXT_DIM
                                },
                            ));
                        },
                    );
                },
            );
            traffic_chart(ui, &state.traffic_history);
        });
    });
}

fn traffic_row(ui: &mut egui::Ui, color: Color32, label: &str, value: &str, connected: bool) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
        ui.painter().rect_filled(rect, 0.0, color);
        ui.label(RichText::new(label).small().color(theme::TEXT_DIM));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(RichText::new(value).strong().color(if connected {
                theme::TEXT
            } else {
                theme::TEXT_DIM
            }));
        });
    });
}

fn chart_scale(history: &VecDeque<(u64, u64)>) -> u64 {
    history
        .iter()
        .map(|&(down, up)| down.max(up))
        .max()
        .unwrap_or(1)
        .max(1)
}

/// Pixel heights above and below the baseline.
fn bar_heights(down: u64, up: u64, scale: u64) -> (f32, f32) {
    let scale = scale.max(1) as f64;
    let height = |value: u64, maximum: f64| {
        if value == 0 {
            0.0
        } else {
            (maximum * value as f64 / scale).clamp(1.0, maximum) as f32
        }
    };
    (height(down, 58.0), height(up, 37.0))
}

fn traffic_chart(ui: &mut egui::Ui, history: &VecDeque<(u64, u64)>) {
    let width = ui.available_width().max(0.0);
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 96.0), egui::Sense::hover());
    let baseline = rect.top() + 58.0;
    ui.painter().hline(
        rect.x_range(),
        baseline,
        egui::Stroke::new(1.0, theme::BORDER),
    );
    if history.is_empty() {
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            t().traffic_empty,
            egui::TextStyle::Small.resolve(ui.style()),
            theme::TEXT_DIM,
        );
        return;
    }
    let scale = chart_scale(history);
    let bar_width = ((width - 2.0 * 59.0) / 60.0).max(0.0);
    for (index, &(down, up)) in history.iter().enumerate() {
        let x = rect.right() - bar_width - (history.len() - 1 - index) as f32 * (bar_width + 2.0);
        let (down_height, up_height) = bar_heights(down, up, scale);
        if bar_width > 0.0 && down_height > 0.0 {
            ui.painter().rect_filled(
                egui::Rect::from_min_size(
                    egui::pos2(x, baseline - down_height),
                    egui::vec2(bar_width, down_height),
                ),
                0.0,
                theme::ROSE_LIGHT,
            );
        }
        if bar_width > 0.0 && up_height > 0.0 {
            ui.painter().rect_filled(
                egui::Rect::from_min_size(
                    egui::pos2(x, baseline + 1.0),
                    egui::vec2(bar_width, up_height),
                ),
                0.0,
                theme::ROSE_DARK,
            );
        }
    }
    ui.painter().text(
        rect.right_top(),
        egui::Align2::RIGHT_TOP,
        t().traffic_peak(&t().rate(scale)),
        egui::TextStyle::Small.resolve(ui.style()),
        theme::TEXT_DIM,
    );
    if let Some(pos) = response.hover_pos()
        && bar_width > 0.0
    {
        let slot = ((rect.right() - pos.x) / (bar_width + 2.0)).floor() as usize;
        if slot < history.len() {
            let (down, up) = history[history.len() - 1 - slot];
            response.on_hover_text(format!(
                "{}: {}\n{}: {}",
                t().traffic_down,
                t().rate(down),
                t().traffic_up,
                t().rate(up),
            ));
        }
    }
}

fn control_cards(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.x = theme::SECTION_GAP;
        ui.columns(2, |columns| {
            let mut left = columns[0].new_child(
                egui::UiBuilder::new()
                    .max_rect(columns[0].available_rect_before_wrap())
                    .sizing_pass(),
            );
            protection_card(&mut left, state, &mut Vec::new(), 0.0);
            let left_height = left.min_rect().height();
            let mut right = columns[1].new_child(
                egui::UiBuilder::new()
                    .max_rect(columns[1].available_rect_before_wrap())
                    .sizing_pass(),
            );
            rules_card(&mut right, state, &mut Vec::new(), 0.0);
            let right_height = right.min_rect().height();
            let height = left_height.max(right_height);
            protection_card(&mut columns[0], state, actions, height);
            rules_card(&mut columns[1], state, actions, height);
        });
    });
}

fn protection_card(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>, height: f32) {
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.set_min_height((height - 34.0).max(0.0));
        ui.colored_label(theme::TEXT_DIM, t().protection);
        let mut kill_switch = state.config.settings.kill_switch;
        if widgets::toggle_row(
            ui,
            t().kill_switch,
            t().kill_switch_detail,
            &mut kill_switch,
            state.config_ready && !state.operations.kill_switch && !state.operations.helper,
        )
        .changed()
        {
            actions.push(Action::SetKillSwitch(kill_switch));
        }
        let mut connect_on_start = state.config.interface.connect_on_start;
        if widgets::toggle_row(
            ui,
            t().connect_on_start,
            t().connect_on_start_detail,
            &mut connect_on_start,
            state.can_edit_settings(),
        )
        .changed()
        {
            actions.push(Action::SetConnectOnStart(connect_on_start));
        }
        if tunnel_up(state) {
            ui.label(
                RichText::new(t().next_connect)
                    .small()
                    .color(theme::ROSE_LIGHT),
            );
        }
    });
}

fn rules_card(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>, height: f32) {
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.set_min_height((height - 34.0).max(0.0));
        egui::Sides::new().shrink_left().show(
            ui,
            |ui| {
                ui.label(
                    RichText::new(t().rules_title)
                        .small()
                        .color(theme::TEXT_DIM),
                );
            },
            |ui| {
                if ui
                    .add(
                        egui::Label::new(RichText::new(t().open_link).color(theme::ROSE_LIGHT))
                            .sense(egui::Sense::click()),
                    )
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .clicked()
                {
                    actions.push(Action::OpenActiveRules);
                }
            },
        );
        let mut selected = state.config.active_rule_set.clone();
        let previous = selected.clone();
        let current_name = state
            .config
            .active_rules()
            .map(|rules| state.text(&rules.name))
            .unwrap_or_else(|| t().default_rules.to_owned());
        ui.add_enabled_ui(state.can_edit_rules(), |ui| {
            egui::ComboBox::from_id_salt("active_rule_set")
                .selected_text(current_name)
                .width(ui.available_width())
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut selected, None, t().default_rules);
                    for rules in &state.config.rule_sets {
                        ui.selectable_value(
                            &mut selected,
                            Some(rules.id.clone()),
                            state.text(&rules.name),
                        );
                    }
                });
        });
        if selected != previous {
            actions.push(Action::SelectRuleSet(selected));
        }
        if let Some(rules) = state.config.active_rules() {
            let mut enabled = rules.rules.iter().filter(|rule| rule.enabled);
            let mut shown = 0;
            for rule in enabled.by_ref().take(2) {
                shown += 1;
                ui.horizontal(|ui| {
                    let width = (ui.available_width() - 90.0).max(0.0);
                    ui.add_sized(
                        [width, 0.0],
                        egui::Label::new(state.text(&rosetun_core::rule_value_text(&rule.matcher)))
                            .truncate(),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.colored_label(target_color(rule.target), target_label(rule.target));
                    });
                });
            }
            if shown == 0 {
                ui.add(
                    egui::Label::new(
                        RichText::new(t().no_rules_yet)
                            .small()
                            .color(theme::TEXT_DIM),
                    )
                    .wrap(),
                );
            }
            let remaining = enabled.count();
            if remaining > 0 {
                ui.label(
                    RichText::new(t().more_rules(remaining))
                        .small()
                        .color(theme::TEXT_DIM),
                );
            }
        } else {
            ui.add(
                egui::Label::new(
                    RichText::new(t().no_rules_yet)
                        .small()
                        .color(theme::TEXT_DIM),
                )
                .wrap(),
            );
        }
        if tunnel_up(state) {
            ui.label(
                RichText::new(t().next_connect)
                    .small()
                    .color(theme::TEXT_DIM),
            );
        }
    });
}

fn tunnel_up(state: &State) -> bool {
    state
        .visible_status()
        .is_some_and(|status| status.state.is_active() || status.state.is_transitional())
}

pub(crate) fn state_style(state: &ConnectionState) -> (&'static str, Color32) {
    match state {
        ConnectionState::Disconnected => (t().disconnected, theme::DISCONNECTED),
        ConnectionState::Connecting => (t().connecting, theme::ROSE_BRIGHT),
        ConnectionState::Connected => (t().connected, theme::CONNECTED),
        ConnectionState::Reconnecting => (t().reconnecting, theme::ROSE_BRIGHT),
        ConnectionState::Failed { .. } => (t().failed, theme::ERROR),
        ConnectionState::FailedProtected { .. } => (t().failed_protected, theme::ERROR),
    }
}

pub(crate) fn protection_dialog(ctx: &egui::Context, state: &State, actions: &mut Vec<Action>) {
    let response = egui::Modal::new(egui::Id::new("turn_off_protection"))
        .frame(widgets::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(480.0);
            ui.heading(t().turn_off_protection);
            ui.add_space(12.0);
            ui.add(
                egui::Label::new(RichText::new(t().protection_warning).color(theme::ERROR)).wrap(),
            );
            if let Some(error) = &state.operation_error {
                ui.add(egui::Label::new(state.text(error)).wrap());
            }
            ui.add_space(20.0);
            ui.horizontal(|ui| {
                if widgets::outline_button(ui, t().keep_blocked, !state.operations.helper).clicked()
                {
                    actions.push(Action::KeepBlocked);
                }
                if widgets::button_fill(
                    ui,
                    t().turn_off_protection,
                    state.helper_available && !state.operations.helper,
                )
                .clicked()
                {
                    actions.push(Action::ConfirmProtectionOff);
                }
            });
        });
    if !state.operations.helper && response.should_close() {
        actions.push(Action::KeepBlocked);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::{bar_heights, chart_scale};

    #[test]
    fn chart_scale_uses_largest_rate_or_one() {
        assert_eq!(chart_scale(&VecDeque::new()), 1);
        assert_eq!(chart_scale(&VecDeque::from([(12, 5), (3, 20)])), 20);
        assert_eq!(chart_scale(&VecDeque::from([(0, 0)])), 1);
    }

    #[test]
    fn bar_heights_scale_both_sides_and_keep_tiny_samples_visible() {
        assert_eq!(bar_heights(100, 0, 100), (58.0, 0.0));
        assert_eq!(bar_heights(0, 100, 100), (0.0, 37.0));
        assert_eq!(bar_heights(1, 1, 10_000), (1.0, 1.0));
        assert_eq!(bar_heights(0, 0, 1), (0.0, 0.0));
    }
}
