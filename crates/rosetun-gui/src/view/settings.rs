use eframe::egui::{self, RichText};
use rosetun_config::LanguageSetting;
use rosetun_core::DnsPreset;

use crate::brand;
use crate::display;
use crate::errors;
use crate::state::{AboutFolder, Action, SessionPart, SettingsSection, State, now_unix};
use crate::strings::t;
use crate::{strings, theme, widgets};

pub(crate) fn show(ui: &mut egui::Ui, state: &mut State, actions: &mut Vec<Action>) {
    if !state.config_ready {
        ui.colored_label(theme::TEXT_DIM, t().loading);
        return;
    }
    match state.settings_screen.section {
        SettingsSection::General => general(ui, state, actions),
        SettingsSection::Connection => connection(ui, state, actions),
        SettingsSection::Network => dns(ui, state, actions),
        SettingsSection::Service => service(ui, state, actions),
        SettingsSection::About => about(ui, state, actions),
    }
}

fn general(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    widgets::settings_card(ui, |card| {
        card.row(t().scale, Some(t().zoom_hint), |ui| {
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
                "interface_scale",
                state.config.interface.scale_percent,
                &options,
                false,
                state.can_edit_settings(),
            ) {
                actions.push(Action::SetInterfaceScale(percent));
            }
        });
        card.row(t().language_title, None, |ui| {
            let saved = state.config.interface.language;
            let mut selected = saved;
            ui.add_enabled_ui(state.can_edit_settings(), |ui| {
                egui::ComboBox::from_id_salt("interface_language")
                    .width(200.0)
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
        let mut reduce_motion = state.config.interface.reduce_motion;
        if card
            .toggle(
                t().reduce_motion,
                t().reduce_motion_detail,
                &mut reduce_motion,
                state.can_edit_settings(),
            )
            .changed()
        {
            actions.push(Action::SetReduceMotion(reduce_motion));
        }
    });
    #[cfg(windows)]
    {
        ui.add_space(16.0);
        windows(ui, state, actions);
    }
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
    widgets::settings_card(ui, |card| {
        let editable = state.can_edit_settings();
        let mut autostart = state.settings_screen.autostart.unwrap_or(false);
        if card
            .toggle(
                t().start_with_windows,
                t().start_with_windows_detail,
                &mut autostart,
                editable && state.settings_screen.autostart.is_some(),
            )
            .changed()
        {
            actions.push(Action::SetAutostart(autostart));
        }
        let mut close_to_tray = state.config.interface.close_to_tray;
        if card
            .toggle(
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
    widgets::settings_card(ui, |card| {
        let editable = state.can_edit_settings();
        let mut connect_on_start = state.config.interface.connect_on_start;
        if card
            .toggle(
                t().connect_on_start,
                t().connect_on_start_detail,
                &mut connect_on_start,
                editable,
            )
            .changed()
        {
            actions.push(Action::SetConnectOnStart(connect_on_start));
        }
        let mut kill_switch = state.config.settings.kill_switch;
        if card
            .toggle(
                t().kill_switch,
                t().kill_switch_detail,
                &mut kill_switch,
                state.config_ready && !state.operations.kill_switch && !state.operations.helper,
            )
            .changed()
        {
            actions.push(Action::SetKillSwitch(kill_switch));
        }
        let mut auto_reconnect = state.config.settings.auto_reconnect;
        if card
            .toggle(
                t().auto_reconnect,
                t().auto_reconnect_detail,
                &mut auto_reconnect,
                editable,
            )
            .changed()
        {
            actions.push(Action::SetAutoReconnect(auto_reconnect));
        }
        let mut auto_update_subscriptions = state.config.interface.auto_update_subscriptions;
        if card
            .toggle(
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
    widgets::settings_card(ui, |card| {
        card.row(t().dns_through_tunnel, Some(t().dns_explanation), |_| {});
        card.body(|ui| {
            let editable = state.can_edit_settings();
            let saved = DnsPreset::matching(&state.config.settings.dns);
            let custom = state.settings_screen.custom_dns;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                let width = (ui.available_width() - 3.0 * 8.0) / 4.0;
                for (index, (preset, (name, address))) in DnsPreset::ALL
                    .into_iter()
                    .zip(strings::DNS_PRESETS)
                    .enumerate()
                {
                    if dns_choice(
                        ui,
                        index,
                        width,
                        saved == Some(preset) && !custom,
                        editable,
                        name,
                        address,
                    )
                    .clicked()
                    {
                        actions.push(Action::SetDnsPreset(preset));
                    }
                }
                if dns_choice(
                    ui,
                    "custom",
                    width,
                    custom,
                    editable,
                    t().dns_custom,
                    t().dns_custom_detail,
                )
                .clicked()
                {
                    actions.push(Action::SelectCustomDns);
                }
            });
            if custom {
                ui.add_space(16.0);
                dns_form(ui, state, actions);
            }
            ui.add_space(12.0);
            ui.label(
                RichText::new(t().dns_reachable)
                    .small()
                    .color(theme::TEXT_DIM),
            );
            if state
                .visible_status()
                .is_some_and(|status| status.state.is_active() || status.state.is_transitional())
                && state.pending_reconnect(SessionPart::Dns)
            {
                if state.can_apply() {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        ui.label(
                            RichText::new(t().not_applied)
                                .small()
                                .color(theme::ROSE_LIGHT),
                        );
                        ui.label(
                            RichText::new(t().apply_separator)
                                .small()
                                .color(theme::ROSE_LIGHT),
                        );
                        if widgets::link(ui, t().apply, true)
                            .on_hover_text(t().apply_hint)
                            .clicked()
                        {
                            actions.push(Action::Apply);
                        }
                    });
                } else {
                    ui.label(
                        RichText::new(t().next_connect)
                            .small()
                            .color(theme::ROSE_LIGHT),
                    );
                }
            }
        });
    });
}

fn dns_choice(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash,
    width: f32,
    selected: bool,
    enabled: bool,
    title: &str,
    detail: &str,
) -> egui::Response {
    widgets::choice_card(ui, id, width, selected, enabled, title, |ui| {
        ui.set_min_height(44.0);
        ui.vertical_centered(|ui| {
            ui.label(
                RichText::new(title)
                    .font(egui::FontId::new(
                        13.0,
                        egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
                    ))
                    .color(theme::TEXT),
            );
            ui.add(egui::Label::new(RichText::new(detail).small().color(theme::TEXT_DIM)).wrap());
        });
    })
}

fn dns_form(ui: &mut egui::Ui, state: &mut State, actions: &mut Vec<Action>) {
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
    if widgets::button_fill(
        ui,
        t().save,
        editable && parsed.is_ok_and(|dns| dns != state.config.settings.dns),
    )
    .clicked()
    {
        actions.push(Action::SaveDns);
    }
}

fn service(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let running = state.helper_available;
    let color = if running {
        theme::CONNECTED
    } else {
        theme::ERROR
    };
    let mut detail = t().service_detail.to_owned();
    if running && let Some(version) = &state.helper_version {
        detail.push('\n');
        detail.push_str(&t().helper_version(&state.text(version)));
    }
    widgets::settings_card(ui, |card| {
        card.row_with_title(
            |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    let (dot, _) =
                        ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                    ui.painter().circle_filled(dot.center(), 5.0, color);
                    ui.colored_label(color, t().service_label);
                    ui.colored_label(
                        color,
                        if running {
                            t().service_running
                        } else {
                            t().service_stopped
                        },
                    );
                });
            },
            Some(&detail),
            |_| {},
        );
    });
    ui.add_space(16.0);
    widgets::settings_card(ui, |card| {
        card.row(t().log_title, Some(t().log_detail), |ui| {
            #[cfg(windows)]
            if widgets::outline_button(ui, t().open_folder, state.can_edit_settings()).clicked() {
                actions.push(Action::OpenFolder(AboutFolder::Config));
            }
            #[cfg(not(windows))]
            let _ = ui;
        });
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
        if card
            .toggle(t().verbose_log, &detail, &mut on, state.can_edit_settings())
            .changed()
        {
            actions.push(Action::SetVerboseLog(on));
        }
    });
    ui.add_space(16.0);
    widgets::settings_card(ui, |card| {
        card.row(t().reset_settings, Some(t().reset_settings_detail), |ui| {
            let allowed = state.can_reset_settings();
            let response = widgets::outline_button(
                ui,
                RichText::new(t().reset_to_default).color(theme::ERROR),
                allowed,
            );
            if response.clicked() {
                actions.push(Action::RequestResetSettings);
            }
            if !allowed {
                response.on_disabled_hover_text(t().reset_disconnect_first);
            }
        });
    });
}

pub(crate) fn reset_dialog(ctx: &egui::Context, state: &State, actions: &mut Vec<Action>) {
    let response = egui::Modal::new(egui::Id::new("reset_settings"))
        .frame(widgets::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(480.0);
            ui.heading(t().reset_settings_question);
            ui.add_space(12.0);
            ui.add(egui::Label::new(t().reset_settings_body).wrap());
            ui.add_space(20.0);
            ui.horizontal(|ui| {
                if widgets::outline_button(ui, t().cancel, !state.operations.settings).clicked() {
                    actions.push(Action::CancelResetSettings);
                }
                if widgets::button_fill(ui, t().reset_to_default, state.can_reset_settings())
                    .clicked()
                {
                    actions.push(Action::ConfirmResetSettings);
                }
            });
        });
    if !state.operations.settings && response.should_close() {
        actions.push(Action::CancelResetSettings);
    }
}

fn about(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    widgets::settings_card(ui, |card| {
        card.body(|ui| {
            ui.horizontal(|ui| {
                let (emblem, _) =
                    ui.allocate_exact_size(egui::vec2(56.0, 56.0), egui::Sense::hover());
                brand::paint_emblem(ui.painter(), emblem, 1.0);
                ui.add_space(16.0);
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(strings::BRAND)
                            .font(egui::FontId::new(
                                28.0,
                                egui::FontFamily::Name(theme::BRAND_FONT.into()),
                            ))
                            .color(theme::TEXT),
                    );
                    let version = t().about_version(
                        env!("CARGO_PKG_VERSION"),
                        state
                            .helper_available
                            .then_some(state.helper_version.as_deref())
                            .flatten(),
                    );
                    ui.label(RichText::new(version).small().color(theme::TEXT_MUTED));
                });
            });
        });
    });
    ui.add_space(theme::SECTION_GAP);
    widgets::settings_card(ui, |card| {
        card.body(|ui| {
            ui.label(
                RichText::new(t().updates_title)
                    .font(egui::FontId::new(
                        17.0,
                        egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
                    ))
                    .color(theme::TEXT),
            );
            if let Some(release) = state.available_update() {
                ui.add_space(14.0);
                let width = ui.available_width();
                egui::Frame::new()
                    .fill(theme::INPUT)
                    .stroke(egui::Stroke::new(1.0, theme::ROSE_DARK))
                    .corner_radius(theme::RADIUS)
                    .inner_margin(16)
                    .show(ui, |ui| {
                        ui.set_min_width((width - 32.0).max(0.0));
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 14.0;
                            let (icon, _) = ui
                                .allocate_exact_size(egui::vec2(32.0, 32.0), egui::Sense::hover());
                            let center = icon.center();
                            let painter = ui.painter();
                            painter.circle_stroke(
                                center,
                                15.5,
                                egui::Stroke::new(1.0, theme::ROSE),
                            );
                            for (start, end) in [
                                (
                                    egui::pos2(center.x, center.y + 7.0),
                                    egui::pos2(center.x, center.y - 7.0),
                                ),
                                (
                                    egui::pos2(center.x - 5.0, center.y - 2.0),
                                    egui::pos2(center.x, center.y - 7.0),
                                ),
                                (
                                    egui::pos2(center.x + 5.0, center.y - 2.0),
                                    egui::pos2(center.x, center.y - 7.0),
                                ),
                            ] {
                                painter.line_segment(
                                    [start, end],
                                    egui::Stroke::new(1.5, theme::ROSE_LIGHT),
                                );
                            }
                            ui.vertical(|ui| {
                                ui.label(
                                    RichText::new(t().update_available(&release.version))
                                        .font(egui::FontId::new(
                                            16.0,
                                            egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
                                        ))
                                        .color(theme::TEXT),
                                );
                                let detail = format!(
                                    "{}{}",
                                    if release.prerelease {
                                        t().update_prerelease
                                    } else {
                                        ""
                                    },
                                    t().update_installer_detail,
                                );
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(detail).small().color(theme::TEXT_MUTED),
                                    )
                                    .wrap(),
                                );
                                ui.add_space(8.0);
                                ui.horizontal_wrapped(|ui| {
                                    if widgets::button_fill(ui, t().update_open_page, true)
                                        .clicked()
                                    {
                                        display::open_web_link(ui.ctx(), &release.url);
                                    }
                                    if widgets::outline_button(
                                        ui,
                                        t().update_skip,
                                        state.can_edit_settings(),
                                    )
                                    .clicked()
                                    {
                                        actions.push(Action::SkipVersion);
                                    }
                                });
                            });
                        });
                    });
            }
        });
        let (status, detail) = update_status(state, now_unix(), t());
        card.row(&status, Some(&detail), |ui| {
            let response =
                widgets::outline_button(ui, t().check_updates_now, state.can_check_updates());
            if response.clicked() {
                actions.push(Action::CheckUpdatesNow);
            }
            if state.update_check_blocked_by_connection() {
                response.on_disabled_hover_text(t().check_updates_unavailable);
            }
        });
        let mut check_updates = state.config.interface.check_updates;
        if card
            .toggle(
                t().check_updates,
                t().check_updates_detail,
                &mut check_updates,
                state.can_edit_settings(),
            )
            .changed()
        {
            actions.push(Action::SetCheckUpdates(check_updates));
        }
    });
    ui.add_space(theme::SECTION_GAP);
    widgets::settings_card(ui, |card| {
        card.body(|ui| {
            if let Some(folder) = &state.settings_screen.config_folder {
                about_path(
                    ui,
                    state,
                    t().configuration_folder,
                    folder.to_string_lossy().as_ref(),
                    AboutFolder::Config,
                    actions,
                );
                ui.add_space(8.0);
                let log = folder.join(strings::LOG_FILE_NAME);
                about_path(
                    ui,
                    state,
                    t().log_file,
                    log.to_string_lossy().as_ref(),
                    AboutFolder::Config,
                    actions,
                );
            }
            if let Some(folder) = &state.settings_screen.licenses_folder {
                ui.add_space(8.0);
                about_path(
                    ui,
                    state,
                    t().licenses_folder,
                    folder.to_string_lossy().as_ref(),
                    AboutFolder::Licenses,
                    actions,
                );
            }
        });
    });
    ui.add_space(theme::SECTION_GAP);
    ui.add(
        egui::Label::new(
            RichText::new(t().license_notice)
                .small()
                .color(theme::TEXT_DIM),
        )
        .wrap(),
    );
}

fn update_status(state: &State, now: u64, s: &strings::Strings) -> (String, String) {
    let age = state
        .config
        .interface
        .last_update_check
        .map(|timestamp| s.updated_ago(timestamp, now));
    if state.update_check_pending {
        return (
            s.update_checking.to_owned(),
            s.update_checking_detail.to_owned(),
        );
    }
    if state.update_check_failed {
        let detail = if state.config.interface.check_updates {
            s.update_failed_detail
        } else {
            s.update_check_manually
        };
        return (s.update_failed.to_owned(), detail.to_owned());
    }
    if !state.config.interface.check_updates {
        let detail = age.as_ref().map_or_else(
            || s.update_check_manually.to_owned(),
            |age| s.update_last_checked(age),
        );
        return (s.update_checks_off.to_owned(), detail);
    }
    if let Some(release) = &state.newest_release {
        if state.available_update().is_none() {
            let detail = age.as_ref().map_or_else(
                || s.update_skipped_next.to_owned(),
                |age| s.update_skipped_detail(age),
            );
            return (s.update_skipped(&release.version), detail);
        }
        let detail = age.as_ref().map_or_else(
            || s.update_not_checked_detail.to_owned(),
            |age| s.update_checked(age),
        );
        return (s.update_found.to_owned(), detail);
    }
    match age {
        Some(age) => (s.update_up_to_date.to_owned(), s.update_checked(&age)),
        None => (
            s.update_not_checked.to_owned(),
            s.update_not_checked_detail.to_owned(),
        ),
    }
}

fn about_path(
    ui: &mut egui::Ui,
    state: &State,
    label: &str,
    path: &str,
    folder: AboutFolder,
    actions: &mut Vec<Action>,
) {
    ui.label(label);
    ui.horizontal(|ui| {
        let path = state.text(path);
        let width = (ui.available_width() - if cfg!(windows) { 180.0 } else { 0.0 }).max(0.0);
        ui.allocate_ui_with_layout(
            egui::vec2(width, ui.text_style_height(&egui::TextStyle::Small)),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.set_width(width);
                ui.add(
                    egui::Label::new(RichText::new(&path).small().color(theme::TEXT_DIM))
                        .truncate(),
                )
                .on_hover_text(&path);
            },
        );
        #[cfg(windows)]
        if widgets::outline_button(ui, t().open_folder, state.can_edit_settings()).clicked() {
            actions.push(Action::OpenFolder(folder));
        }
        #[cfg(not(windows))]
        let _ = (actions, folder);
    });
}

#[cfg(test)]
mod update_status_tests {
    use super::{State, update_status};
    use crate::strings::{EN, RU};
    use rosetun_core::Release;

    #[test]
    fn status_prioritizes_checking_failure_and_disabled_checks() {
        let mut state = State::default();
        state.config_ready = true;
        assert_eq!(update_status(&state, 200, &EN).0, "Not checked yet");
        state.config.interface.last_update_check = Some(80);
        assert_eq!(update_status(&state, 200, &EN).1, "Checked 2 minutes ago.");
        state.newest_release = Some(Release {
            version: "999.0.0-alpha.4".into(),
            url: "https://example.com/release".into(),
            prerelease: true,
        });
        assert_eq!(update_status(&state, 200, &EN).0, "New version available");
        state.config.interface.skipped_version = Some("999.0.0-alpha.4".into());
        assert_eq!(
            update_status(&state, 200, &EN),
            (
                "Version 999.0.0-alpha.4 skipped".into(),
                "We'll tell you about the next one. Checked 2 minutes ago.".into(),
            )
        );
        state.config.interface.check_updates = false;
        assert_eq!(
            update_status(&state, 200, &EN).0,
            "Automatic checks are off"
        );
        state.update_check_failed = true;
        assert_eq!(
            update_status(&state, 200, &EN),
            ("Couldn't check".into(), "You can check manually.".into(),)
        );
        state.update_check_pending = true;
        assert_eq!(update_status(&state, 200, &EN).0, "Checking…");
    }

    #[test]
    fn russian_status_uses_the_same_age_and_skipped_version() {
        let mut state = State::default();
        state.config_ready = true;
        state.config.interface.last_update_check = Some(80);
        state.config.interface.skipped_version = Some("999.0.0-alpha.4".into());
        state.newest_release = Some(Release {
            version: "999.0.0-alpha.4".into(),
            url: "https://example.com/release".into(),
            prerelease: true,
        });
        assert_eq!(
            update_status(&state, 200, &RU),
            (
                "Версия 999.0.0-alpha.4 пропущена".into(),
                "Напомним, когда выйдет следующая. Проверено 2 минуты назад.".into(),
            )
        );
    }
}
