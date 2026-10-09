pub(crate) mod add_rule;
pub(crate) mod add_subscription;
pub(crate) mod connection;
pub(crate) mod header;
pub(crate) mod rose_button;
pub(crate) mod rules;
pub(crate) mod settings;
pub(crate) mod subscriptions;
pub(crate) mod traffic;
mod window_frame;

use eframe::egui::{self, Align, RichText, Stroke};

use crate::errors;
use crate::state::{Action, Screen, SettingsSection, State};
use crate::strings::t;
use crate::{theme, widgets};

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
                    .inner_margin(egui::Margin {
                        left: 16,
                        right: 16,
                        top: 16,
                        bottom: 0,
                    }),
            )
            .show(ui, |ui| subscriptions::show(ui, state, &mut actions));
    }
    if state.screen == Screen::Settings {
        egui::Panel::left("settings_nav")
            .exact_size(240.0)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(theme::PANEL)
                    .stroke(Stroke::new(1.0, theme::BORDER))
                    .inner_margin(egui::Margin {
                        left: 16,
                        right: 16,
                        top: 28,
                        bottom: 28,
                    }),
            )
            .show(ui, |ui| settings_nav(ui, state, &mut actions));
    }
    egui::CentralPanel::default()
        .frame(
            egui::Frame::new()
                .fill(theme::BG)
                .inner_margin(egui::Margin {
                    left: 36,
                    right: 36,
                    top: 28,
                    bottom: 32,
                }),
        )
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("connection_scroll")
                .show(ui, |ui| {
                    if let Some(error) = &state.config_error
                        && widgets::dismissible_error(
                            ui,
                            &state.text(&errors::config_worker(t(), error)),
                        )
                    {
                        actions.push(Action::DismissConfigError);
                    }
                    if let Some(error) = &state.operation_error
                        && widgets::dismissible_error(ui, &state.text(error))
                    {
                        actions.push(Action::DismissOperationError);
                    }
                    match state.screen {
                        Screen::Connection => connection::show(ui, state, &mut actions),
                        Screen::Traffic => traffic::show(ui, state, &mut actions),
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
    if state.rename.is_some() {
        subscriptions::rename_dialog(ctx, state, &mut actions);
    }
    if state.protection_confirmation && state.screen == Screen::Connection {
        connection::protection_dialog(ctx, state, &mut actions);
    }
    if state.screen == Screen::Rules {
        rules::name_dialog(ctx, state, &mut actions);
        rules::delete_dialog(ctx, state, &mut actions);
        let can_temporary = state.can_change_temporary();
        if let Some(dialog) = &mut state.rule_screen.add {
            if !can_temporary {
                dialog.temporary_only = false;
            }
            add_rule::show(ctx, dialog, can_temporary, &mut actions);
        }
    }
    if state.settings_screen.reset_open {
        settings::reset_dialog(ctx, state, &mut actions);
    }
    window_frame::resize_edges(ui);
    actions
}

fn settings_nav(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    ui.horizontal(|ui| {
        ui.add_space(12.0);
        ui.heading(t().settings);
    });
    ui.add_space(10.0);
    for (section, title) in [
        (SettingsSection::General, t().section_general),
        (SettingsSection::Connection, t().connection),
        (SettingsSection::Network, t().section_network),
        (SettingsSection::Service, t().section_service),
        (SettingsSection::About, t().about),
    ] {
        if settings_nav_item(
            ui,
            title,
            state.settings_screen.section == section,
            section == SettingsSection::Service && service_warning(state),
            section == SettingsSection::About && state.available_update().is_some(),
        ) {
            actions.push(Action::OpenSettingsSection(section));
        }
    }
    let size = ui.available_size();
    ui.allocate_ui_with_layout(size, egui::Layout::bottom_up(Align::Min), |ui| {
        ui.add(egui::Label::new(
            RichText::new(t().settings_saved_instantly)
                .small()
                .color(theme::TEXT_DIM),
        ));
    });
}

fn service_warning(state: &State) -> bool {
    state.helper_error.is_some()
}

fn settings_nav_item(
    ui: &mut egui::Ui,
    label: &str,
    selected: bool,
    warning: bool,
    update: bool,
) -> bool {
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 42.0), egui::Sense::click());
    let fill = if selected {
        theme::INPUT
    } else if response.hovered() {
        theme::BORDER
    } else {
        egui::Color32::TRANSPARENT
    };
    ui.painter().rect_filled(rect, theme::RADIUS, fill);
    if selected {
        ui.painter().rect_filled(
            egui::Rect::from_min_size(
                egui::pos2(rect.left(), rect.top() + 10.0),
                egui::vec2(3.0, 22.0),
            ),
            0,
            theme::ROSE,
        );
    }
    ui.painter().text(
        egui::pos2(rect.left() + 12.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        egui::TextStyle::Body.resolve(ui.style()),
        if selected {
            theme::TEXT
        } else {
            theme::TEXT_MUTED
        },
    );
    if warning {
        ui.painter().text(
            egui::pos2(rect.right() - 12.0, rect.center().y),
            egui::Align2::RIGHT_CENTER,
            crate::strings::ERROR_MARK,
            egui::TextStyle::Body.resolve(ui.style()),
            theme::ERROR,
        );
    }
    if update {
        ui.painter().circle_filled(
            egui::pos2(rect.right() - 14.0, rect.center().y),
            3.0,
            theme::ROSE_LIGHT,
        );
    }
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::SelectableLabel, true, selected, label)
    });
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

#[cfg(test)]
mod settings_nav_tests {
    use super::service_warning;
    use crate::state::State;
    use crate::worker::WorkerEvent;
    use rosetun_ipc::ClientError;

    #[test]
    fn service_warning_waits_for_a_failed_response() {
        let mut state = State::default();
        assert!(!service_warning(&state));
        state.reduce(WorkerEvent::HelperUnavailable(ClientError::Closed));
        assert!(service_warning(&state));
        state.reduce(WorkerEvent::HelperAvailable {
            version: "0.9.0".into(),
        });
        assert!(!service_warning(&state));
    }
}
