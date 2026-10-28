pub(crate) mod add_rule;
pub(crate) mod add_subscription;
pub(crate) mod connection;
mod connections;
pub(crate) mod exits;
pub(crate) mod header;
pub(crate) mod lists;
pub(crate) mod rose_button;
pub(crate) mod rules;
pub(crate) mod settings;
pub(crate) mod subscriptions;
pub(crate) mod traffic;
mod window_frame;

use eframe::egui::{self, Align, RichText, Stroke};
use rosetun_config::ConnectionState;

use crate::errors;
use crate::state::{Action, Screen, SettingsSection, State};
use crate::{theme, widgets};

pub(crate) fn show(ui: &mut egui::Ui, state: &mut State) -> Vec<Action> {
    let mut actions = Vec::new();
    let narrow = ui.available_width() < 800.0;
    egui::Panel::top("header")
        .exact_size(76.0)
        .show_separator_line(false)
        .frame(
            egui::Frame::new()
                .fill(theme::palette().panel)
                .inner_margin(0),
        )
        .show(ui, |ui| header::show(ui, state, &mut actions));
    if state.screen == Screen::Connection {
        egui::Panel::left("subscriptions")
            .exact_size(if narrow { 240.0 } else { 316.0 })
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(theme::palette().panel)
                    .stroke(Stroke::new(1.0, theme::palette().border))
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
            .exact_size(if narrow { 200.0 } else { 240.0 })
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(theme::palette().panel)
                    .stroke(Stroke::new(1.0, theme::palette().border))
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
                .fill(theme::palette().bg)
                .inner_margin(egui::Margin {
                    left: if narrow { 16 } else { 36 },
                    right: if narrow { 16 } else { 36 },
                    top: 28,
                    bottom: 32,
                }),
        )
        .show(ui, |ui| {
            let dragging_rule = state.screen == Screen::Rules
                && egui::DragAndDrop::payload::<rosetun_config::RuleId>(ui.ctx()).is_some();
            egui::ScrollArea::vertical()
                .id_salt("connection_scroll")
                .scroll_source(egui::scroll_area::ScrollSource {
                    mouse_wheel: !dragging_rule,
                    ..Default::default()
                })
                .show(ui, |ui| {
                    if state.config_unreadable() {
                        config_unreadable_banner(ui, state, &mut actions);
                    } else if let Some(error) = &state.config_error
                        && widgets::dismissible_error(
                            ui,
                            &state.text(&errors::config_worker(crate::i18n::language(), error)),
                        )
                    {
                        actions.push(Action::DismissConfigError);
                    }
                    if let Some(error) = &state.operation_error
                        && widgets::dismissible_error(ui, &state.text(error))
                    {
                        actions.push(Action::DismissOperationError);
                    }
                    if let Some(error) = state.session.apply_failure() {
                        let (dismissed, restore) = widgets::dismissible_error_with_action(
                            ui,
                            error,
                            Some((&tr!("restore-my-edits"), state.can_restore_edits())),
                        );
                        if dismissed {
                            actions.push(Action::DismissApplyFailure);
                        }
                        if restore {
                            actions.push(Action::RestoreMyEdits);
                        }
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
    if let Some(dialog) = &mut state.subscriptions.add {
        add_subscription::show(ctx, &state.config, dialog, &mut actions);
    }
    if let Some(dialog) = &mut state.lists.add {
        lists::add_dialog(ctx, dialog, &mut actions);
    }
    if state.lists.rename.is_some() {
        lists::rename_dialog(ctx, state, &mut actions);
    }
    if state.lists.remove.is_some() {
        lists::remove_dialog(ctx, state, &mut actions);
    }
    if state.subscriptions.remove.is_some() {
        subscriptions::remove_dialog(ctx, state, &mut actions);
    }
    if state.subscriptions.rename.is_some() {
        subscriptions::rename_dialog(ctx, state, &mut actions);
    }
    if state.protection_confirmation && state.screen == Screen::Connection {
        connection::protection_dialog(ctx, state, &mut actions);
    }
    if state.lockdown_confirmation.is_some() {
        connection::lockdown_dialog(ctx, state, &mut actions);
    }
    if state.screen == Screen::Rules {
        rules::name_dialog(ctx, state, &mut actions);
        rules::delete_dialog(ctx, state, &mut actions);
        exits::exit_dialog(ctx, state, &mut actions);
        exits::rename_dialog(ctx, state, &mut actions);
        exits::delete_dialog(ctx, state, &mut actions);
        let can_temporary = state.can_change_temporary();
        let existing_list_rules = state.selected_list_rule_count();
        if let Some(dialog) = &mut state.rules.screen.add {
            if !can_temporary {
                dialog.temporary_only = false;
            }
            add_rule::show(
                ctx,
                dialog,
                &state.config,
                can_temporary,
                existing_list_rules,
                &mut actions,
            );
        }
    }
    if state.settings.screen.reset_open {
        settings::reset_dialog(ctx, state, &mut actions);
    }
    window_frame::resize_edges(ui);
    actions
}

/// Shown instead of a dismissible error while the settings cannot be read: the
/// rest of the window has nothing to work with, so the way out stays in view.
fn config_unreadable_banner(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let mut message = tr!("config-unreadable");
    if let Some(error) = &state.config_error {
        message.push('\n');
        message.push_str(&errors::config_worker(crate::i18n::language(), error));
    }
    #[cfg(windows)]
    {
        let buttons = [
            (tr!("open-settings-folder"), state.can_open_folders()),
            (
                if state.settings.screen.report_running {
                    tr!("report-collecting")
                } else {
                    tr!("report-save")
                },
                state.can_save_report(),
            ),
        ];
        let buttons = buttons
            .iter()
            .map(|(label, enabled)| (label.as_ref(), *enabled))
            .collect::<Vec<_>>();
        match widgets::error_with_actions(ui, &state.text(&message), &buttons) {
            Some(0) => actions.push(Action::OpenFolder(crate::state::AboutFolder::Config)),
            Some(_) => actions.push(Action::SaveReport),
            None => {}
        }
    }
    #[cfg(not(windows))]
    {
        let _ = actions;
        widgets::error_with_actions(ui, &state.text(&message), &[]);
    }
}

fn settings_nav(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    ui.horizontal(|ui| {
        ui.add_space(12.0);
        ui.heading(tr!("settings"));
    });
    ui.add_space(10.0);
    for (section, title) in [
        (SettingsSection::General, tr!("section-general")),
        (SettingsSection::Connection, tr!("connection")),
        (SettingsSection::Network, tr!("section-network")),
        (SettingsSection::Advanced, tr!("section-advanced")),
        (SettingsSection::Service, tr!("section-service")),
        (SettingsSection::About, tr!("about")),
    ] {
        if settings_nav_item(
            ui,
            &title,
            state.settings.screen.section == section,
            section == SettingsSection::Service && service_warning(state),
            section == SettingsSection::About && state.available_update().is_some(),
        ) {
            actions.push(Action::OpenSettingsSection(section));
        }
    }
    let size = ui.available_size();
    ui.allocate_ui_with_layout(size, egui::Layout::bottom_up(Align::Min), |ui| {
        ui.add(egui::Label::new(
            RichText::new(tr!("settings-saved-instantly"))
                .small()
                .color(theme::palette().text_dim),
        ));
    });
}

/// Whether the screen shows something that changes every second without an event.
pub(crate) fn shows_clock(state: &State) -> bool {
    let Some(status) = state.visible_status() else {
        return false;
    };
    match state.screen {
        Screen::Connection => status.since_unix.is_some() || status.state.is_transitional(),
        Screen::Traffic => matches!(
            status.state,
            ConnectionState::Connected | ConnectionState::Reconnecting
        ),
        Screen::Rules | Screen::Settings => false,
    }
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
        theme::palette().input
    } else if response.hovered() {
        theme::palette().border
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
            theme::palette().accent_base,
        );
    }
    ui.painter().text(
        egui::pos2(rect.left() + 12.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        egui::TextStyle::Body.resolve(ui.style()),
        if selected {
            theme::palette().text
        } else {
            theme::palette().text_muted
        },
    );
    if warning {
        ui.painter().text(
            egui::pos2(rect.right() - 12.0, rect.center().y),
            egui::Align2::RIGHT_CENTER,
            crate::constants::ERROR_MARK,
            egui::TextStyle::Body.resolve(ui.style()),
            theme::ERROR,
        );
    }
    if update {
        ui.painter().circle_filled(
            egui::pos2(rect.right() - 14.0, rect.center().y),
            3.0,
            theme::palette().accent_light,
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
