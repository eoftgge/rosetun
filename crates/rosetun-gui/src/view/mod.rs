pub(crate) mod add_subscription;
pub(crate) mod connection;
pub(crate) mod subscriptions;

use eframe::egui::{self, RichText, Stroke};

use crate::state::{Action, State};
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
                ui.colored_label(theme::ROSE_LIGHT, strings::CONNECTION);
                ui.add_enabled(false, egui::Button::new(strings::RULES).frame(false))
                    .on_disabled_hover_text(strings::COMING_LATER);
                ui.add_enabled(false, egui::Button::new(strings::SETTINGS).frame(false))
                    .on_disabled_hover_text(strings::COMING_LATER);
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
                    connection::show(ui, state, &mut actions);
                });
        });

    let ctx = ui.ctx();
    if let Some(dialog) = &mut state.add {
        add_subscription::show(ctx, &state.config, dialog, &mut actions);
    }
    if state.remove.is_some() {
        subscriptions::remove_dialog(ctx, state, &mut actions);
    }
    if state.protection_confirmation {
        connection::protection_dialog(ctx, state, &mut actions);
    }
    actions
}
