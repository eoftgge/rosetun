pub(crate) mod add_rule;
pub(crate) mod add_subscription;
pub(crate) mod connection;
pub(crate) mod header;
pub(crate) mod rules;
pub(crate) mod settings;
pub(crate) mod subscriptions;

use eframe::egui::{self, Stroke};

use crate::state::{Action, Screen, State};
use crate::theme;

pub(crate) fn show(ui: &mut egui::Ui, state: &mut State) -> Vec<Action> {
    let mut actions = Vec::new();
    egui::Panel::top("header")
        .exact_size(76.0)
        .show_separator_line(false)
        .frame(egui::Frame::new().fill(theme::PANEL).inner_margin(0))
        .show(ui, |ui| header::show(ui, state, &mut actions));
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
