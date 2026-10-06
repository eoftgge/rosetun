use eframe::egui::{self, RichText};
use rosetun_config::LogLevel;

use crate::state::{Action, State};
use crate::strings::t;
use crate::{strings, theme};

pub(crate) fn show(ui: &mut egui::Ui, state: &mut State, actions: &mut Vec<Action>) {
    ui.heading(t().settings);
    ui.add_space(20.0);
    if !state.config_ready {
        ui.colored_label(theme::TEXT_DIM, t().loading);
        return;
    }

    interface(ui, state, actions);
    #[cfg(windows)]
    {
        ui.add_space(16.0);
        windows(ui, state, actions);
    }
    ui.add_space(16.0);
    dns(ui, state, actions);
    ui.add_space(16.0);
    engine_log(ui, state, actions);
    ui.add_space(16.0);
    about(ui, state, actions);
}

fn interface(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    theme::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.heading(t().interface);
        ui.add_space(8.0);
        ui.label(t().scale);
        ui.horizontal_wrapped(|ui| {
            for percent in rosetun_core::INTERFACE_SCALES {
                if ui
                    .add_enabled(
                        state.can_edit_settings(),
                        egui::Button::new(strings::scale(percent))
                            .selected(state.config.interface.scale_percent == percent),
                    )
                    .clicked()
                {
                    actions.push(Action::SetInterfaceScale(percent));
                }
            }
        });
        ui.label(RichText::new(t().zoom_hint).small().color(theme::TEXT_DIM));
    });
}

#[cfg(windows)]
fn windows(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    theme::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.heading(t().windows);
        ui.add_space(8.0);
        let editable = state.can_edit_settings();
        let mut autostart = state.settings_screen.autostart.unwrap_or(false);
        if theme::switch_row(
            ui,
            t().start_with_windows,
            t().start_with_windows_detail,
            &mut autostart,
            editable && state.settings_screen.autostart.is_some(),
        )
        .changed()
        {
            actions.push(Action::SetAutostart(autostart));
        }
        ui.add_space(12.0);
        let mut close_to_tray = state.config.interface.close_to_tray;
        if theme::switch_row(
            ui,
            t().keep_in_tray,
            t().keep_in_tray_detail,
            &mut close_to_tray,
            editable,
        )
        .changed()
        {
            actions.push(Action::SetCloseToTray(close_to_tray));
        }
    });
}

fn dns(ui: &mut egui::Ui, state: &mut State, actions: &mut Vec<Action>) {
    theme::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.heading(t().dns_through_tunnel);
        ui.add(
            egui::Label::new(
                RichText::new(t().dns_explanation)
                    .small()
                    .color(theme::TEXT_MUTED),
            )
            .wrap(),
        );
        ui.add_space(12.0);
        let editable = state.can_edit_settings();
        let form = &mut state.settings_screen;
        egui::Grid::new("dns_settings_fields")
            .num_columns(2)
            .spacing([16.0, 10.0])
            .show(ui, |ui| {
                for (label, value, hint) in [
                    (t().resolver_ip, &mut form.server, ""),
                    (t().tls_name, &mut form.server_name, ""),
                    (t().port, &mut form.port, strings::PORT_PLACEHOLDER),
                    (t().dns_path, &mut form.path, strings::DNS_PATH_PLACEHOLDER),
                ] {
                    ui.label(label);
                    if ui
                        .add_enabled(
                            editable,
                            egui::TextEdit::singleline(value)
                                .hint_text(hint)
                                .desired_width(300.0),
                        )
                        .changed()
                    {
                        form.dirty = true;
                    }
                    ui.end_row();
                }
            });
        let parsed = form.parsed_dns();
        if let Err(error) = &parsed {
            ui.colored_label(theme::ERROR, error.to_string());
        }
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            if theme::button_fill(
                ui,
                t().save,
                editable && parsed.is_ok_and(|dns| dns != state.config.settings.dns),
            )
            .clicked()
            {
                actions.push(Action::SaveDns);
            }
            if theme::outline_button(ui, t().reset_to_default, editable).clicked() {
                actions.push(Action::ResetDns);
            }
        });
        if state
            .visible_status()
            .is_some_and(|status| status.state.is_active() || status.state.is_transitional())
        {
            ui.label(
                RichText::new(t().next_connect)
                    .small()
                    .color(theme::ROSE_LIGHT),
            );
        }
    });
}

fn engine_log(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    theme::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.heading(t().engine_log);
        ui.label(
            RichText::new(t().engine_log_detail)
                .small()
                .color(theme::TEXT_MUTED),
        );
        let saved = state.config.settings.log_level;
        let mut selected = saved;
        ui.add_enabled_ui(state.can_edit_settings(), |ui| {
            egui::ComboBox::from_id_salt("engine_log_level")
                .selected_text(log_label(selected))
                .show_ui(ui, |ui| {
                    for level in [
                        LogLevel::Error,
                        LogLevel::Warn,
                        LogLevel::Info,
                        LogLevel::Debug,
                        LogLevel::Trace,
                    ] {
                        ui.selectable_value(&mut selected, level, log_label(level));
                    }
                });
        });
        if selected != saved {
            actions.push(Action::SetEngineLogLevel(selected));
        }
    });
}

fn log_label(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Error => t().log_error,
        LogLevel::Warn => t().log_warn,
        LogLevel::Info => t().log_info,
        LogLevel::Debug => t().log_debug,
        LogLevel::Trace => t().log_trace,
    }
}

fn about(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    theme::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.heading(t().about);
        ui.label(strings::app_version());
        if state.helper_available {
            if let Some(version) = &state.helper_version {
                ui.label(t().helper_version(&state.text(version)));
            }
        } else {
            ui.label(t().helper_not_running);
        }
        if let Some(folder) = &state.settings_screen.config_folder {
            ui.add_space(12.0);
            about_path(
                ui,
                state,
                t().configuration_folder,
                folder.to_string_lossy().as_ref(),
                actions,
            );
            ui.add_space(8.0);
            let log = folder.join(strings::LOG_FILE_NAME);
            about_path(
                ui,
                state,
                t().log_file,
                log.to_string_lossy().as_ref(),
                actions,
            );
        }
    });
}

fn about_path(
    ui: &mut egui::Ui,
    state: &State,
    label: &str,
    path: &str,
    actions: &mut Vec<Action>,
) {
    ui.label(label);
    ui.horizontal(|ui| {
        let path = state.text(path);
        ui.add_sized(
            [
                ui.available_width() - if cfg!(windows) { 130.0 } else { 0.0 },
                20.0,
            ],
            egui::Label::new(RichText::new(&path).small().color(theme::TEXT_DIM)).truncate(),
        )
        .on_hover_text(&path);
        #[cfg(windows)]
        if theme::outline_button(ui, t().open_folder, state.can_edit_settings()).clicked() {
            actions.push(Action::OpenConfigFolder);
        }
        #[cfg(not(windows))]
        let _ = actions;
    });
}
