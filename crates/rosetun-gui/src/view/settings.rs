use eframe::egui::{self, RichText};
use rosetun_config::LanguageSetting;
use rosetun_core::DnsPreset;

use crate::brand;
use crate::display;
use crate::errors;
use crate::state::{AboutFolder, Action, SessionPart, SettingsSection, State, now_unix};
use crate::{constants, i18n, theme, widgets};

pub(crate) fn show(ui: &mut egui::Ui, state: &mut State, actions: &mut Vec<Action>) {
    if !state.config_ready {
        ui.colored_label(theme::TEXT_DIM, tr!("loading"));
        return;
    }
    match state.settings.screen.section {
        SettingsSection::General => general(ui, state, actions),
        SettingsSection::Connection => connection(ui, state, actions),
        SettingsSection::Network => dns(ui, state, actions),
        SettingsSection::Service => service(ui, state, actions),
        SettingsSection::About => about(ui, state, actions),
    }
}

fn general(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    widgets::settings_card(ui, |card| {
        card.row(tr!("scale"), Some(&tr!("zoom-hint")), |ui| {
            let scales: Vec<_> = rosetun_core::INTERFACE_SCALES
                .into_iter()
                .map(|percent| (percent, i18n::scale(percent)))
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
        card.row(tr!("language-title"), None, |ui| {
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
                tr!("reduce-motion"),
                tr!("reduce-motion-detail"),
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

fn language_label(setting: LanguageSetting) -> String {
    match setting {
        LanguageSetting::System => tr!("language-system"),
        LanguageSetting::English => constants::ENGLISH.to_owned(),
        LanguageSetting::Russian => constants::RUSSIAN.to_owned(),
    }
}

#[cfg(windows)]
fn windows(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    widgets::settings_card(ui, |card| {
        let editable = state.can_edit_settings();
        let mut autostart = state.settings.screen.autostart.unwrap_or(false);
        if card
            .toggle(
                tr!("start-with-windows"),
                tr!("start-with-windows-detail"),
                &mut autostart,
                editable && state.settings.screen.autostart.is_some(),
            )
            .changed()
        {
            actions.push(Action::SetAutostart(autostart));
        }
        let mut close_to_tray = state.config.interface.close_to_tray;
        if card
            .toggle(
                tr!("keep-in-tray"),
                tr!("keep-in-tray-detail"),
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
                tr!("connect-on-start"),
                tr!("connect-on-start-detail"),
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
                tr!("kill-switch"),
                tr!("kill-switch-detail"),
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
                tr!("auto-reconnect"),
                tr!("auto-reconnect-detail"),
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
                tr!("auto-update-subscriptions"),
                tr!("auto-update-subscriptions-detail"),
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
        card.row(
            tr!("dns-through-tunnel"),
            Some(&tr!("dns-explanation")),
            |_| {},
        );
        card.body(|ui| {
            let editable = state.can_edit_settings();
            let saved = DnsPreset::matching(&state.config.settings.dns);
            let custom = state.settings.screen.custom_dns;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                let width = (ui.available_width() - 3.0 * 8.0) / 4.0;
                for (index, (preset, (name, address))) in DnsPreset::ALL
                    .into_iter()
                    .zip(constants::DNS_PRESETS)
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
                    &tr!("dns-custom"),
                    &tr!("dns-custom-detail"),
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
                RichText::new(tr!("dns-reachable"))
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
                            RichText::new(tr!("apply-on-leave"))
                                .small()
                                .color(theme::ROSE_LIGHT),
                        );
                        ui.label(
                            RichText::new(tr!("apply-separator"))
                                .small()
                                .color(theme::ROSE_LIGHT),
                        );
                        if widgets::link(ui, &tr!("apply-now"), true)
                            .on_hover_text(tr!("apply-hint"))
                            .clicked()
                        {
                            actions.push(Action::Apply);
                        }
                    });
                } else {
                    ui.label(
                        RichText::new(tr!("next-connect"))
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
    let form = &mut state.settings.screen;
    egui::Grid::new("dns_settings_fields")
        .num_columns(2)
        .spacing([16.0, 10.0])
        .show(ui, |ui| {
            for (label, value, hint) in [
                (tr!("resolver-ip"), &mut form.server, ""),
                (tr!("tls-name"), &mut form.server_name, ""),
                (tr!("port"), &mut form.port, constants::PORT_PLACEHOLDER),
                (
                    tr!("dns-path"),
                    &mut form.path,
                    constants::DNS_PATH_PLACEHOLDER,
                ),
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
        ui.colored_label(
            theme::ERROR,
            errors::dns_input(crate::i18n::language(), error),
        );
    }
    ui.add_space(8.0);
    if widgets::button_fill(
        ui,
        tr!("save"),
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
    let mut detail = tr!("service-detail").to_owned();
    if running && let Some(version) = &state.helper_version {
        detail.push('\n');
        detail.push_str(&crate::i18n::helper_version(&state.text(version)));
    }
    widgets::settings_card(ui, |card| {
        card.row_with_title(
            |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    let (dot, _) =
                        ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                    ui.painter().circle_filled(dot.center(), 5.0, color);
                    ui.colored_label(color, tr!("service-label"));
                    ui.colored_label(
                        color,
                        if running {
                            tr!("service-running")
                        } else {
                            tr!("service-stopped")
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
        card.row(tr!("log-title"), Some(&tr!("log-detail")), |ui| {
            #[cfg(windows)]
            if widgets::outline_button(ui, tr!("open-folder"), state.can_edit_settings()).clicked()
            {
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
            crate::i18n::verbose_log_on_detail(hours)
        } else {
            tr!("verbose-log-off-detail").to_owned()
        };
        if card
            .toggle(
                tr!("verbose-log"),
                &detail,
                &mut on,
                state.can_edit_settings(),
            )
            .changed()
        {
            actions.push(Action::SetVerboseLog(on));
        }
    });
    ui.add_space(16.0);
    widgets::settings_card(ui, |card| {
        card.row(
            tr!("reset-settings"),
            Some(&tr!("reset-settings-detail")),
            |ui| {
                let allowed = state.can_reset_settings();
                let response = widgets::outline_button(
                    ui,
                    RichText::new(tr!("reset-to-default")).color(theme::ERROR),
                    allowed,
                );
                if response.clicked() {
                    actions.push(Action::RequestResetSettings);
                }
                if !allowed {
                    response.on_disabled_hover_text(tr!("reset-disconnect-first"));
                }
            },
        );
    });
}

pub(crate) fn reset_dialog(ctx: &egui::Context, state: &State, actions: &mut Vec<Action>) {
    let response = egui::Modal::new(egui::Id::new("reset_settings"))
        .frame(widgets::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(480.0);
            ui.heading(tr!("reset-settings-question"));
            ui.add_space(12.0);
            ui.add(egui::Label::new(tr!("reset-settings-body")).wrap());
            ui.add_space(20.0);
            ui.horizontal(|ui| {
                if widgets::outline_button(ui, tr!("cancel"), !state.operations.settings).clicked()
                {
                    actions.push(Action::CancelResetSettings);
                }
                if widgets::button_fill(ui, tr!("reset-to-default"), state.can_reset_settings())
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
                        RichText::new(constants::BRAND)
                            .font(egui::FontId::new(
                                28.0,
                                egui::FontFamily::Name(theme::BRAND_FONT.into()),
                            ))
                            .color(theme::TEXT),
                    );
                    let version = crate::i18n::about_version(
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
                RichText::new(tr!("updates-title"))
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
                                    RichText::new(crate::i18n::update_available(&release.version))
                                        .font(egui::FontId::new(
                                            16.0,
                                            egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
                                        ))
                                        .color(theme::TEXT),
                                );
                                let detail = format!(
                                    "{}{}",
                                    if release.prerelease {
                                        tr!("update-prerelease")
                                    } else {
                                        String::new()
                                    },
                                    tr!("update-installer-detail"),
                                );
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(detail).small().color(theme::TEXT_MUTED),
                                    )
                                    .wrap(),
                                );
                                ui.add_space(8.0);
                                ui.horizontal_wrapped(|ui| {
                                    if widgets::button_fill(ui, tr!("update-open-page"), true)
                                        .clicked()
                                    {
                                        display::open_web_link(ui.ctx(), &release.url);
                                    }
                                    if widgets::outline_button(
                                        ui,
                                        tr!("update-skip"),
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
        let (status, detail) = update_status(state, now_unix(), crate::i18n::language());
        card.row(&status, Some(&detail), |ui| {
            let response =
                widgets::outline_button(ui, tr!("check-updates-now"), state.can_check_updates());
            if response.clicked() {
                actions.push(Action::CheckUpdatesNow);
            }
            if state.update_check_blocked_by_connection() {
                response.on_disabled_hover_text(tr!("check-updates-unavailable"));
            }
        });
        let mut check_updates = state.config.interface.check_updates;
        if card
            .toggle(
                tr!("check-updates"),
                tr!("check-updates-detail"),
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
            if let Some(folder) = &state.settings.screen.config_folder {
                about_path(
                    ui,
                    state,
                    &tr!("configuration-folder"),
                    folder.to_string_lossy().as_ref(),
                    AboutFolder::Config,
                    actions,
                );
                ui.add_space(8.0);
                let log = folder.join(constants::LOG_FILE_NAME);
                about_path(
                    ui,
                    state,
                    &tr!("log-file"),
                    log.to_string_lossy().as_ref(),
                    AboutFolder::Config,
                    actions,
                );
            }
            if let Some(folder) = &state.settings.screen.licenses_folder {
                ui.add_space(8.0);
                about_path(
                    ui,
                    state,
                    &tr!("licenses-folder"),
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
            RichText::new(tr!("license-notice"))
                .small()
                .color(theme::TEXT_DIM),
        )
        .wrap(),
    );
}

fn status_argument<'a>(name: &'static str, value: &'a str) -> fluent_bundle::FluentArgs<'a> {
    let mut args = fluent_bundle::FluentArgs::new();
    args.set(name, value);
    args
}

fn update_status(state: &State, now: u64, language: crate::i18n::Language) -> (String, String) {
    use crate::i18n::tr_in;
    let empty = fluent_bundle::FluentArgs::new();
    let age = state
        .config
        .interface
        .last_update_check
        .map(|timestamp| crate::i18n::updated_ago_in(language, timestamp, now));
    if state.updates.update_check_pending {
        return (
            tr_in(language, "update-checking", &empty),
            tr_in(language, "update-checking-detail", &empty),
        );
    }
    if state.updates.update_check_failed {
        let detail = if state.config.interface.check_updates {
            tr_in(language, "update-failed-detail", &empty)
        } else {
            tr_in(language, "update-check-manually", &empty)
        };
        return (tr_in(language, "update-failed", &empty), detail);
    }
    if !state.config.interface.check_updates {
        let detail = age.as_ref().map_or_else(
            || tr_in(language, "update-check-manually", &empty),
            |age| {
                tr_in(
                    language,
                    "update-last-checked",
                    &status_argument("age", age),
                )
            },
        );
        return (tr_in(language, "update-checks-off", &empty), detail);
    }
    if let Some(release) = &state.updates.newest_release {
        if state.available_update().is_none() {
            let detail = age.as_ref().map_or_else(
                || tr_in(language, "update-skipped-next", &empty),
                |age| {
                    tr_in(
                        language,
                        "update-skipped-detail",
                        &status_argument("age", age),
                    )
                },
            );
            return (
                tr_in(
                    language,
                    "update-skipped",
                    &status_argument("version", &release.version),
                ),
                detail,
            );
        }
        let detail = age.as_ref().map_or_else(
            || tr_in(language, "update-not-checked-detail", &empty),
            |age| tr_in(language, "update-checked", &status_argument("age", age)),
        );
        return (tr_in(language, "update-found", &empty), detail);
    }
    match age {
        Some(age) => (
            tr_in(language, "update-up-to-date", &empty),
            tr_in(language, "update-checked", &status_argument("age", &age)),
        ),
        None => (
            tr_in(language, "update-not-checked", &empty),
            tr_in(language, "update-not-checked-detail", &empty),
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
        if widgets::outline_button(ui, tr!("open-folder"), state.can_edit_settings()).clicked() {
            actions.push(Action::OpenFolder(folder));
        }
        #[cfg(not(windows))]
        let _ = (actions, folder);
    });
}

#[cfg(test)]
mod update_status_tests {
    use super::{State, update_status};
    use crate::i18n::Language;
    use rosetun_core::Release;

    #[test]
    fn status_prioritizes_checking_failure_and_disabled_checks() {
        let mut state = State::default();
        state.config_ready = true;
        assert_eq!(
            update_status(&state, 200, Language::English).0,
            "Not checked yet"
        );
        state.config.interface.last_update_check = Some(80);
        assert_eq!(
            update_status(&state, 200, Language::English).1,
            "Checked 2 minutes ago."
        );
        state.updates.newest_release = Some(Release {
            version: "999.0.0-alpha.4".into(),
            url: "https://example.com/release".into(),
            prerelease: true,
        });
        assert_eq!(
            update_status(&state, 200, Language::English).0,
            "New version available"
        );
        state.config.interface.skipped_version = Some("999.0.0-alpha.4".into());
        assert_eq!(
            update_status(&state, 200, Language::English),
            (
                "Version 999.0.0-alpha.4 skipped".into(),
                "We'll tell you about the next one. Checked 2 minutes ago.".into(),
            )
        );
        state.config.interface.check_updates = false;
        assert_eq!(
            update_status(&state, 200, Language::English).0,
            "Automatic checks are off"
        );
        state.updates.update_check_failed = true;
        assert_eq!(
            update_status(&state, 200, Language::English),
            ("Couldn't check".into(), "You can check manually.".into(),)
        );
        state.updates.update_check_pending = true;
        assert_eq!(update_status(&state, 200, Language::English).0, "Checking…");
    }

    #[test]
    fn russian_status_uses_the_same_age_and_skipped_version() {
        let mut state = State::default();
        state.config_ready = true;
        state.config.interface.last_update_check = Some(80);
        state.config.interface.skipped_version = Some("999.0.0-alpha.4".into());
        state.updates.newest_release = Some(Release {
            version: "999.0.0-alpha.4".into(),
            url: "https://example.com/release".into(),
            prerelease: true,
        });
        assert_eq!(
            update_status(&state, 200, Language::Russian),
            (
                "Версия 999.0.0-alpha.4 пропущена".into(),
                "Напомним, когда выйдет следующая. Проверено 2 минуты назад.".into(),
            )
        );
    }
}
