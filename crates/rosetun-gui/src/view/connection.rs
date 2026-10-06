use eframe::egui::{self, Color32, RichText, Stroke};
use rosetun_config::ConnectionState;

use crate::actions::{PrimaryAction, ProtectionAction, protection_action};
use crate::state::{Action, State, primary_label};
use crate::strings::t;
use crate::{display, strings, theme};

pub(crate) fn show(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    if !state.config_ready {
        ui.colored_label(theme::TEXT_DIM, t().loading);
    }
    if !state.helper_available {
        theme::card_frame().show(ui, |ui| {
            ui.colored_label(theme::ERROR, t().helper_unavailable_detail);
            if let Some(error) = &state.helper_error {
                ui.add(egui::Label::new(state.text(&error.to_string())).wrap());
            }
        });
        ui.add_space(16.0);
    }

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
    ui.columns(2, |columns| {
        columns[0].vertical_centered(|ui| {
            ui.add_space(12.0);
            let action = state.primary_action();
            let enabled = action != PrimaryAction::Disabled;
            let mut text = RichText::new(primary_label(state)).size(19.0).strong();
            let (fill, stroke) = match action {
                PrimaryAction::Connect | PrimaryAction::Retry | PrimaryAction::Reconnect => {
                    text = text.color(Color32::WHITE);
                    (theme::ROSE, Stroke::NONE)
                }
                PrimaryAction::Disconnect => (
                    Color32::from_rgba_unmultiplied(
                        theme::CONNECTED.r(),
                        theme::CONNECTED.g(),
                        theme::CONNECTED.b(),
                        36,
                    ),
                    Stroke::new(2.0, theme::CONNECTED),
                ),
                PrimaryAction::Disabled => (theme::MODAL, Stroke::new(2.0, theme::DISABLED)),
            };
            let response = ui.add_enabled(
                enabled,
                egui::Button::new(text)
                    .min_size(egui::vec2(216.0, 200.0))
                    .fill(fill)
                    .stroke(stroke),
            );
            if response.clicked() {
                actions.push(Action::Primary);
            }
            ui.add_space(20.0);
            ui.label(RichText::new(label).size(26.0).color(color));
            ui.add_space(6.0);
            let session = visible_status
                .and_then(|status| status.since_unix)
                .map_or_else(
                    || strings::NO_SESSION.to_owned(),
                    |since| display::session_text(Some(since), display::now_unix()),
                );
            ui.colored_label(
                theme::TEXT_MUTED,
                strings::plain_link(t().session, &session),
            );
        });
        columns[1].vertical(|ui| {
            theme::card_frame().show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.colored_label(theme::TEXT_DIM, t().selected_server);
                if let Some((subscription, node)) = state.config.active_node() {
                    let name = display::drop_missing_glyphs(
                        ui.ctx(),
                        &egui::FontId::proportional(17.0),
                        &state.text(&node.name),
                    );
                    ui.add(egui::Label::new(RichText::new(name).size(17.0).strong()).wrap());
                    let subscription_name = display::drop_missing_glyphs(
                        ui.ctx(),
                        &egui::TextStyle::Body.resolve(ui.style()),
                        &state.text(&subscription.name),
                    );
                    ui.colored_label(theme::TEXT_MUTED, subscription_name);
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
                    ui.colored_label(theme::TEXT_MUTED, t().select_server);
                }
                let engine = visible_status
                    .and_then(|status| status.engine)
                    .unwrap_or(state.config.settings.engine);
                ui.label(
                    RichText::new(t().via_engine(engine.as_str()))
                        .small()
                        .color(theme::TEXT_DIM),
                )
                .on_hover_text(t().engine_detail(engine.as_str()));
            });
            if let Some(id) = selection_changed.and_then(|status| status.node.as_ref()) {
                theme::card_frame().show(ui, |ui| {
                    ui.colored_label(theme::TEXT_DIM, t().active_server);
                    let name = state
                        .config
                        .subscriptions
                        .iter()
                        .find_map(|sub| sub.node(id).map(|node| state.text(&node.name)));
                    let name = name.map(|name| {
                        display::drop_missing_glyphs(
                            ui.ctx(),
                            &egui::TextStyle::Body.resolve(ui.style()),
                            &name,
                        )
                    });
                    ui.add(egui::Label::new(name.as_deref().unwrap_or(t().unknown_server)).wrap());
                });
            }
            theme::card_frame().show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.colored_label(theme::TEXT_DIM, t().protection);
                let mut enabled = state.config.settings.kill_switch;
                if theme::switch_row(
                    ui,
                    t().kill_switch,
                    t().kill_switch_detail,
                    &mut enabled,
                    state.config_ready && !state.operations.kill_switch && !state.operations.helper,
                )
                .changed()
                {
                    actions.push(Action::SetKillSwitch(enabled));
                }
                if visible_status.is_some_and(|status| {
                    status.state.is_active() || status.state.is_transitional()
                }) {
                    ui.label(
                        RichText::new(t().next_connect)
                            .small()
                            .color(theme::ROSE_LIGHT),
                    );
                }
            });
        });
    });
    ui.add_space(20.0);
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
        ui.add(egui::Label::new(RichText::new(message).color(theme::ROSE_LIGHT)).wrap());
    }
    if let Some(ConnectionState::Failed { reason } | ConnectionState::FailedProtected { reason }) =
        visible_status.map(|status| &status.state)
    {
        theme::card_frame().show(ui, |ui| {
            ui.add(egui::Label::new(RichText::new(state.text(reason)).color(theme::ERROR)).wrap());
        });
    }
    if let Some(status) = visible_status
        && protection_action(status, state.operations.helper) == ProtectionAction::ConfirmDisconnect
        && theme::outline_button(ui, t().turn_off_protection, true).clicked()
    {
        actions.push(Action::RequestProtectionOff);
    }
    ui.add_space(12.0);
    theme::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.colored_label(theme::TEXT_DIM, t().rule_set);
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
        ui.colored_label(theme::TEXT_DIM, t().next_connect);
        if theme::outline_button(ui, t().open_rules, true).clicked() {
            actions.push(Action::OpenActiveRules);
        }
    });
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
        .frame(theme::modal_frame())
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
                if theme::outline_button(ui, t().keep_blocked, !state.operations.helper).clicked() {
                    actions.push(Action::KeepBlocked);
                }
                if theme::button_fill(
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
