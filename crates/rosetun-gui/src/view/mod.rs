pub(crate) mod add_rule;
pub(crate) mod add_subscription;
pub(crate) mod connection;
pub(crate) mod rules;
pub(crate) mod settings;
pub(crate) mod subscriptions;

use eframe::egui::{self, RichText, Stroke};

use crate::state::{Action, Screen, State};
use crate::{strings, theme};

pub(crate) fn show(ui: &mut egui::Ui, state: &mut State) -> Vec<Action> {
    let mut actions = Vec::new();
    egui::Panel::top("header")
        .exact_size(76.0)
        .frame(
            egui::Frame::new()
                .fill(theme::PANEL)
                .inner_margin(egui::Margin::symmetric(24, 20)),
        )
        .show(ui, |ui| {
            ui.horizontal_centered(|ui| {
                ui.label(RichText::new(strings::BRAND).size(23.0).strong());
                ui.add_space(32.0);
                if state.screen == Screen::Connection {
                    ui.colored_label(theme::ROSE_LIGHT, strings::CONNECTION);
                } else if ui.button(strings::CONNECTION).clicked() {
                    actions.push(Action::ShowConnection);
                }
                if state.screen == Screen::Rules {
                    ui.colored_label(theme::ROSE_LIGHT, strings::RULES);
                } else if ui.button(strings::RULES).clicked() {
                    actions.push(Action::OpenRules);
                }
                if state.screen == Screen::Settings {
                    ui.colored_label(theme::ROSE_LIGHT, strings::SETTINGS);
                } else if ui.button(strings::SETTINGS).clicked() {
                    actions.push(Action::OpenSettings);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if !state.helper_available {
                        ui.colored_label(theme::ERROR, strings::HELPER_UNAVAILABLE);
                    } else if let Some(version) = &state.helper_version {
                        ui.colored_label(
                            theme::TEXT_DIM,
                            strings::helper_version(&state.text(version)),
                        );
                    }
                });
            });
        });
    if state.screen == Screen::Connection {
        egui::Panel::left("subscriptions")
            .exact_size(316.0)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(theme::PANEL)
                    .stroke(Stroke::new(1.0, theme::BORDER))
                    .inner_margin(16),
            )
            .show(ui, |ui| subscriptions::show(ui, state, &mut actions));
    }
    egui::CentralPanel::default()
        .frame(
            egui::Frame::new()
                .fill(theme::BG)
                .inner_margin(egui::Margin::symmetric(36, 32)),
        )
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("connection_scroll")
                .show(ui, |ui| {
                    if let Some(error) = &state.config_error
                        && theme::dismissible_error(ui, &state.text(&error.to_string()))
                    {
                        actions.push(Action::DismissConfigError);
                    }
                    if let Some(error) = &state.operation_error
                        && theme::dismissible_error(ui, &state.text(error))
                    {
                        actions.push(Action::DismissOperationError);
                    }
                    match state.screen {
                        Screen::Connection => connection::show(ui, state, &mut actions),
                        Screen::Rules => rules::show(ui, state, &mut actions),
                        Screen::Settings => settings::show(ui, state, &mut actions),
                    }
                });
        });

    let ctx = ui.ctx();
    if let Some(dialog) = &mut state.add {
        add_subscription::show(ctx, &state.config, dialog, &mut actions);
    }
    if state.remove.is_some() {
        subscriptions::remove_dialog(ctx, state, &mut actions);
    }
    if state.protection_confirmation && state.screen == Screen::Connection {
        connection::protection_dialog(ctx, state, &mut actions);
    }
    if state.screen == Screen::Rules {
        rules::name_dialog(ctx, state, &mut actions);
        rules::delete_dialog(ctx, state, &mut actions);
        if let Some(dialog) = &mut state.rule_screen.add {
            add_rule::show(ctx, dialog, &mut actions);
        }
    }
    actions
}
