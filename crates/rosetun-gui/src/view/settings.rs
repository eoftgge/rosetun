use eframe::egui::{self, RichText};
use rosetun_config::LanguageSetting;

use crate::errors;
use crate::state::{Action, State, now_unix};
use crate::strings::t;
use crate::{strings, theme, widgets};

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
    connection(ui, state, actions);
    ui.add_space(16.0);
    dns(ui, state, actions);
    ui.add_space(16.0);
    engine_log(ui, state, actions);
    ui.add_space(16.0);
    about(ui, state, actions);
}

fn interface(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.heading(t().interface);
        ui.add_space(8.0);
        ui.label(t().scale);
        let scales: Vec<_> = rosetun_core::INTERFACE_SCALES
            .into_iter()
            .map(|percent| (percent, strings::scale(percent)))
            .collect();
        let options: Vec<_> = scales
            .iter()
            .map(|(percent, label)| (*percent, label.as_str()))
            .collect();
        if let Some(percent) = widgets::segmented(
            ui,
            state.config.interface.scale_percent,
            &options,
            false,
            state.can_edit_settings(),
        ) {
            actions.push(Action::SetInterfaceScale(percent));
        }
        ui.label(RichText::new(t().zoom_hint).small().color(theme::TEXT_DIM));
        ui.add_space(12.0);
        ui.label(t().language_title);
        let saved = state.config.interface.language;
        let mut selected = saved;
        ui.add_enabled_ui(state.can_edit_settings(), |ui| {
            egui::ComboBox::from_id_salt("interface_language")
                .selected_text(language_label(selected))
                .show_ui(ui, |ui| {
                    for language in [
                        LanguageSetting::System,
                        LanguageSetting::English,
                        LanguageSetting::Russian,
                    ] {
                        ui.selectable_value(&mut selected, language, language_label(language));
                    }
                });
        });
        if selected != saved && state.can_edit_settings() {
            actions.push(Action::SetLanguage(selected));
        }
    });
}

fn language_label(setting: LanguageSetting) -> &'static str {
    match setting {
        LanguageSetting::System => t().language_system,
        LanguageSetting::English => strings::ENGLISH,
        LanguageSetting::Russian => strings::RUSSIAN,
    }
}

#[cfg(windows)]
fn windows(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.heading(t().windows);
        ui.add_space(8.0);
        let editable = state.can_edit_settings();
        let mut autostart = state.settings_screen.autostart.unwrap_or(false);
        if widgets::toggle_row(
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
        if widgets::toggle_row(
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

fn connection(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.heading(t().connection);
        ui.add_space(8.0);
        let editable = state.can_edit_settings();
        let mut connect_on_start = state.config.interface.connect_on_start;
        if widgets::toggle_row(
            ui,
            t().connect_on_start,
            t().connect_on_start_detail,
            &mut connect_on_start,
            editable,
        )
        .changed()
        {
            actions.push(Action::SetConnectOnStart(connect_on_start));
        }
        ui.add_space(12.0);
        let mut auto_reconnect = state.config.settings.auto_reconnect;
        if widgets::toggle_row(
            ui,
            t().auto_reconnect,
            t().auto_reconnect_detail,
            &mut auto_reconnect,
            editable,
        )
        .changed()
        {
            actions.push(Action::SetAutoReconnect(auto_reconnect));
        }
        ui.add_space(12.0);
        let mut auto_update_subscriptions = state.config.interface.auto_update_subscriptions;
        if widgets::toggle_row(
            ui,
            t().auto_update_subscriptions,
            t().auto_update_subscriptions_detail,
            &mut auto_update_subscriptions,
            editable,
        )
        .changed()
        {
            actions.push(Action::SetAutoUpdateSubscriptions(
                auto_update_subscriptions,
            ));
        }
    });
}

fn dns(ui: &mut egui::Ui, state: &mut State, actions: &mut Vec<Action>) {
    widgets::card_frame().show(ui, |ui| {
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
            ui.colored_label(theme::ERROR, errors::dns_input(t(), error));
        }
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            if widgets::button_fill(
                ui,
                t().save,
                editable && parsed.is_ok_and(|dns| dns != state.config.settings.dns),
            )
            .clicked()
            {
                actions.push(Action::SaveDns);
            }
            if widgets::outline_button(ui, t().reset_to_default, editable).clicked() {
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
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.heading(t().log_title);
        ui.add_space(8.0);
        let settings = &state.config.settings;
        let now = now_unix();
        let mut on = settings.verbose_log_active(now);
        let detail = if on {
            let hours = settings
                .verbose_log_until
                .unwrap_or(now)
                .saturating_sub(now)
                .div_ceil(3600);
            t().verbose_log_on_detail(hours)
        } else {
            t().verbose_log_off_detail.to_owned()
        };
        if widgets::toggle_row(
            ui,
            t().verbose_log,
            &detail,
            &mut on,
            state.can_edit_settings(),
        )
        .changed()
        {
            actions.push(Action::SetVerboseLog(on));
        }
    });
}

fn about(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    widgets::card_frame().show(ui, |ui| {
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
                ui.available_width() - if cfg!(windows) { 180.0 } else { 0.0 },
                20.0,
            ],
            egui::Label::new(RichText::new(&path).small().color(theme::TEXT_DIM)).truncate(),
        )
        .on_hover_text(&path);
        #[cfg(windows)]
        if widgets::outline_button(ui, t().open_folder, state.can_edit_settings()).clicked() {
            actions.push(Action::OpenConfigFolder);
        }
        #[cfg(not(windows))]
        let _ = actions;
    });
}
