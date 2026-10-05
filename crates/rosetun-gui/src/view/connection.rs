use eframe::egui::{self, Color32, RichText, Stroke};
use rosetun_config::ConnectionState;

use crate::actions::{PrimaryAction, ProtectionAction, protection_action};
use crate::state::{Action, State, primary_label};
use crate::{display, strings, theme};

pub(crate) fn show(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    if !state.config_ready {
        ui.colored_label(theme::TEXT_DIM, strings::LOADING);
    }
    if !state.helper_available {
        theme::card_frame().show(ui, |ui| {
            ui.colored_label(theme::ERROR, strings::HELPER_UNAVAILABLE_DETAIL);
            if let Some(error) = &state.helper_error {
                ui.add(egui::Label::new(state.text(&error.to_string())).wrap());
            }
        });
        ui.add_space(16.0);
    }

    let (label, color) = state_style(&state.status.state);
    ui.columns(2, |columns| {
        columns[0].vertical_centered(|ui| {
            ui.add_space(12.0);
            let enabled = state.primary_action() != PrimaryAction::Disabled;
            let response = ui.add_enabled(
                enabled,
                egui::Button::new(RichText::new(primary_label(state)).size(19.0).strong())
                    .min_size(egui::vec2(216.0, 200.0))
                    .fill(theme::MODAL)
                    .stroke(Stroke::new(
                        2.0,
                        if enabled { color } else { theme::DISABLED },
                    )),
            );
            if response.clicked() {
                actions.push(Action::Primary);
            }
            ui.add_space(20.0);
            ui.label(RichText::new(label).size(26.0).color(color));
            ui.add_space(6.0);
            let session = if state.status.since_unix.is_some() {
                display::session_text(state.status.since_unix, display::now_unix())
            } else {
                strings::NO_SESSION.to_owned()
            };
            ui.colored_label(
                theme::TEXT_MUTED,
                strings::plain_link(strings::SESSION, &session),
            );
        });
        columns[1].vertical(|ui| {
            theme::card_frame().show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.colored_label(theme::TEXT_DIM, strings::SELECTED_SERVER);
                if let Some((subscription, node)) = state.config.active_node() {
                    ui.add(
                        egui::Label::new(RichText::new(state.text(&node.name)).size(17.0).strong())
                            .wrap(),
                    );
                    ui.colored_label(theme::TEXT_MUTED, state.text(&subscription.name));
                    ui.add(egui::Label::new(state.text(&rosetun_core::node_address(node))).wrap());
                    ui.colored_label(
                        theme::TEXT_DIM,
                        strings::node_details(
                            rosetun_core::node_protocol(node),
                            rosetun_core::node_tls(node),
                            rosetun_core::node_transport(node),
                        ),
                    );
                } else {
                    ui.colored_label(theme::TEXT_MUTED, strings::SELECT_SERVER);
                }
            });
            if let Some(id) = &state.status.node
                && state
                    .config
                    .active
                    .as_ref()
                    .is_none_or(|selection| &selection.node != id)
                && (state.status.state.is_active() || state.status.state.is_transitional())
            {
                theme::card_frame().show(ui, |ui| {
                    ui.colored_label(theme::TEXT_DIM, strings::ACTIVE_SERVER);
                    let name = state
                        .config
                        .subscriptions
                        .iter()
                        .find_map(|sub| sub.node(id).map(|node| state.text(&node.name)));
                    ui.add(
                        egui::Label::new(name.as_deref().unwrap_or(strings::UNKNOWN_SERVER)).wrap(),
                    );
                });
            }
            theme::card_frame().show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                let mut enabled = state.config.settings.kill_switch;
                if ui
                    .add_enabled(
                        state.config_ready
                            && !state.operations.kill_switch
                            && !state.operations.helper,
                        egui::Checkbox::new(&mut enabled, strings::KILL_SWITCH),
                    )
                    .changed()
                {
                    actions.push(Action::SetKillSwitch(enabled));
                }
                ui.colored_label(theme::TEXT_DIM, strings::NEXT_CONNECT);
                ui.add_space(10.0);
                ui.colored_label(theme::TEXT_DIM, strings::ENGINE);
                let engine = state.status.engine.unwrap_or(state.config.settings.engine);
                ui.label(engine.as_str());
            });
        });
    });
    ui.add_space(20.0);
    if let Some(name) = &state.selection_pending {
        ui.add(
            egui::Label::new(
                RichText::new(strings::selected_pending(&state.text(name)))
                    .color(theme::ROSE_LIGHT),
            )
            .wrap(),
        );
    }
    match &state.status.state {
        ConnectionState::Failed { reason } | ConnectionState::FailedProtected { reason } => {
            theme::card_frame().show(ui, |ui| {
                ui.add(
                    egui::Label::new(RichText::new(state.text(reason)).color(theme::ERROR)).wrap(),
                );
            });
        }
        _ => {}
    }
    if protection_action(&state.status, state.operations.helper)
        == ProtectionAction::ConfirmDisconnect
        && theme::outline_button(ui, strings::TURN_OFF_PROTECTION, state.helper_available).clicked()
    {
        actions.push(Action::RequestProtectionOff);
    }
    ui.add_space(12.0);
    theme::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.columns(2, |columns| {
            columns[0].colored_label(theme::TEXT_DIM, strings::UPLOAD);
            columns[0].label(
                RichText::new(strings::transfer_rate(state.status.traffic.up_bps))
                    .size(20.0)
                    .color(theme::CONNECTED),
            );
            columns[1].colored_label(theme::TEXT_DIM, strings::DOWNLOAD);
            columns[1].label(
                RichText::new(strings::transfer_rate(state.status.traffic.down_bps))
                    .size(20.0)
                    .color(theme::ROSE_LIGHT),
            );
        });
    });
    ui.add_space(12.0);
    theme::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.colored_label(theme::TEXT_DIM, strings::RULE_SET);
        let mut selected = state.config.active_rule_set.clone();
        let previous = selected.clone();
        let current_name = state
            .config
            .active_rules()
            .map(|rules| state.text(&rules.name))
            .unwrap_or_else(|| strings::DEFAULT_RULES.to_owned());
        ui.add_enabled_ui(
            state.config_ready && !state.operations.rules && !state.operations.helper,
            |ui| {
                egui::ComboBox::from_id_salt("active_rule_set")
                    .selected_text(current_name)
                    .width(ui.available_width())
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut selected, None, strings::DEFAULT_RULES);
                        for rules in &state.config.rule_sets {
                            ui.selectable_value(
                                &mut selected,
                                Some(rules.id.clone()),
                                state.text(&rules.name),
                            );
                        }
                    });
            },
        );
        if selected != previous {
            actions.push(Action::SelectRuleSet(selected));
        }
        ui.colored_label(theme::TEXT_DIM, strings::NEXT_CONNECT);
    });
}

fn state_style(state: &ConnectionState) -> (&'static str, Color32) {
    match state {
        ConnectionState::Disconnected => (strings::DISCONNECTED, theme::DISCONNECTED),
        ConnectionState::Connecting => (strings::CONNECTING, theme::ROSE_BRIGHT),
        ConnectionState::Connected => (strings::CONNECTED, theme::CONNECTED),
        ConnectionState::Reconnecting => (strings::RECONNECTING, theme::ROSE_BRIGHT),
        ConnectionState::Failed { .. } => (strings::FAILED, theme::ERROR),
        ConnectionState::FailedProtected { .. } => (strings::FAILED_PROTECTED, theme::ERROR),
    }
}

pub(crate) fn protection_dialog(ctx: &egui::Context, state: &State, actions: &mut Vec<Action>) {
    let response = egui::Modal::new(egui::Id::new("turn_off_protection"))
        .frame(theme::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(480.0);
            ui.heading(strings::TURN_OFF_PROTECTION);
            ui.add_space(12.0);
            ui.add(
                egui::Label::new(RichText::new(strings::PROTECTION_WARNING).color(theme::ERROR))
                    .wrap(),
            );
            if let Some(error) = &state.operation_error {
                ui.add(egui::Label::new(state.text(error)).wrap());
            }
            ui.add_space(20.0);
            ui.horizontal(|ui| {
                if theme::outline_button(ui, strings::KEEP_BLOCKED, !state.operations.helper)
                    .clicked()
                {
                    actions.push(Action::KeepBlocked);
                }
                if theme::button_fill(
                    ui,
                    strings::TURN_OFF_PROTECTION,
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
