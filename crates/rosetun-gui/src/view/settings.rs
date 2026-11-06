use eframe::egui::{self, RichText};
#[cfg(any(windows, target_os = "linux"))]
use rosetun_config::QuitAction;
use rosetun_config::{
    AccentPreset, ConnectionMode, ConnectionState, LanguageSetting, LocalProxySettings, TlsMode,
    XrayUse,
};
use rosetun_core::{CheckKind, CheckStatus, DnsPreset};

use crate::brand;
use crate::display;
use crate::errors;
use crate::icons::{self, Icon};
use crate::state::{AboutFolder, Action, SessionPart, SettingsSection, State, now_unix};
use crate::{constants, i18n, theme, widgets};

pub(crate) fn show(ui: &mut egui::Ui, state: &mut State, actions: &mut Vec<Action>) {
    if !state.config_ready {
        ui.colored_label(theme::palette().text_dim, tr!("loading"));
        return;
    }
    let shown = widgets::appear_progress(
        ui.ctx(),
        egui::Id::unique("settings_section_appear"),
        state.settings.screen.section,
        state.config.interface.reduce_motion,
    );
    widgets::appear(ui, shown, |ui| match state.settings.screen.section {
        SettingsSection::General => general(ui, state, actions),
        SettingsSection::Connection => {
            connection_mode(ui, state, actions);
            ui.add_space(theme::space::M);
            connection(ui, state, actions);
        }
        SettingsSection::Network => dns(ui, state, actions),
        SettingsSection::Advanced => advanced(ui, state, actions),
        SettingsSection::Service => service(ui, state, actions),
        SettingsSection::About => about(ui, state, actions),
    });
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
                widgets::drop_down(
                    ui,
                    "interface_language",
                    Some(200.0),
                    language_label(selected),
                    |ui| {
                        let languages = i18n::LANGUAGES.iter().map(|info| info.setting);
                        for language in std::iter::once(LanguageSetting::System).chain(languages) {
                            ui.selectable_value(&mut selected, language, language_label(language));
                        }
                    },
                );
            });
            if selected != saved && state.can_edit_settings() {
                actions.push(Action::SetLanguage(selected));
            }
        });
        card.row(tr!("accent-title"), None, |ui| {
            let options: Vec<_> = AccentPreset::ALL
                .into_iter()
                .map(|accent| {
                    let palette = theme::palette_of(accent);
                    widgets::Swatch {
                        value: accent,
                        label: accent_label(accent),
                        fill: palette.accent_base,
                        ring: palette.card,
                    }
                })
                .collect();
            ui.horizontal(|ui| {
                if let Some(accent) = widgets::swatches(
                    ui,
                    "interface_accent",
                    state.config.interface.accent,
                    &options,
                    state.can_edit_settings(),
                ) {
                    actions.push(Action::SetAccent(accent));
                }
                // Rose and Graphite rose share the accent; the name tells them apart.
                ui.label(
                    RichText::new(accent_label(state.config.interface.accent))
                        .color(theme::palette().text_muted),
                );
            });
        });
        let mut reduce_motion = state.config.interface.reduce_motion;
        if card
            .toggle(
                tr!("reduce-motion"),
                None,
                tr!("reduce-motion-detail"),
                &mut reduce_motion,
                state.can_edit_settings(),
            )
            .changed()
        {
            actions.push(Action::SetReduceMotion(reduce_motion));
        }
    });
    #[cfg(any(windows, target_os = "linux"))]
    {
        ui.add_space(theme::space::L);
        desktop(ui, state, actions);
    }
}

fn language_label(setting: LanguageSetting) -> String {
    i18n::LANGUAGES
        .iter()
        .find(|info| info.setting == setting)
        .map_or_else(
            || tr!("language-system"),
            |info| info.native_name.to_owned(),
        )
}

fn accent_label(accent: AccentPreset) -> String {
    match accent {
        AccentPreset::Rose => tr!("accent-rose"),
        AccentPreset::Graphite => tr!("accent-graphite-rose"),
        AccentPreset::Cocoa => tr!("accent-cocoa"),
        AccentPreset::Lilac => tr!("accent-lilac"),
        AccentPreset::Teal => tr!("accent-teal"),
        AccentPreset::Amber => tr!("accent-amber"),
    }
}

#[cfg(any(windows, target_os = "linux"))]
fn quit_action_label(action: QuitAction) -> String {
    match action {
        QuitAction::Ask => tr!("quit-action-ask"),
        QuitAction::Disconnect => tr!("quit-action-disconnect"),
        QuitAction::KeepConnected => tr!("quit-action-keep"),
    }
}

#[cfg(any(windows, target_os = "linux"))]
fn desktop(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    widgets::settings_card(ui, |card| {
        let editable = state.can_edit_settings();
        let mut autostart = state.settings.screen.autostart.unwrap_or(false);
        if card
            .toggle(
                if cfg!(windows) {
                    tr!("start-with-windows")
                } else {
                    tr!("start-at-sign-in")
                },
                None,
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
                None,
                tr!("keep-in-tray-detail"),
                &mut close_to_tray,
                editable,
            )
            .changed()
        {
            actions.push(Action::SetCloseToTray(close_to_tray));
        }
        card.row(tr!("quit-action"), None, |ui| {
            let saved = state.config.interface.quit_action;
            let mut selected = saved;
            ui.add_enabled_ui(editable, |ui| {
                widgets::drop_down(
                    ui,
                    "quit_action",
                    Some(240.0),
                    quit_action_label(selected),
                    |ui| {
                        for action in [
                            QuitAction::Ask,
                            QuitAction::Disconnect,
                            QuitAction::KeepConnected,
                        ] {
                            ui.selectable_value(&mut selected, action, quit_action_label(action));
                        }
                    },
                );
            });
            if selected != saved && editable {
                actions.push(Action::SetOnQuit(selected));
            }
        });
        let mut notifications = state.config.interface.notifications;
        if card
            .toggle(
                tr!("notifications"),
                None,
                tr!("notifications-detail"),
                &mut notifications,
                editable,
            )
            .changed()
        {
            actions.push(Action::SetNotifications(notifications));
        }
    });
}

fn pending(pending: bool) -> widgets::RowOptions {
    widgets::RowOptions {
        pending,
        ..widgets::RowOptions::default()
    }
}

/// Wide enough for five digits.
const LOCAL_PROXY_PORT_WIDTH: f32 = 96.0;

/// TUN or the system proxy, and in the proxy mode its port and who may use it.
fn connection_mode(ui: &mut egui::Ui, state: &mut State, actions: &mut Vec<Action>) {
    let editable = state.can_edit_settings();
    let mode = state.config.settings.connection_mode;
    let proxy = mode == ConnectionMode::SystemProxy;
    let waits = state.waits_for_next_connect(SessionPart::LocalProxy);
    widgets::settings_card(ui, |card| {
        card.row_with(
            tr!("connection-mode"),
            Some(&state.connection_mode_detail()),
            pending(waits),
            |ui| {
                let options = [
                    (ConnectionMode::Tun, tr!("connection-mode-tun")),
                    (ConnectionMode::SystemProxy, tr!("connection-mode-proxy")),
                ];
                if let Some(chosen) =
                    widgets::segmented(ui, "connection_mode", mode, &options, false, editable)
                {
                    actions.push(Action::SetConnectionMode(chosen));
                }
            },
        );
        if !proxy {
            return;
        }
        let saved = state.config.settings.local_proxy;
        let form = &mut state.settings.screen;
        if !form.local_proxy_port_dirty {
            form.local_proxy_port = saved.port.to_string();
        }
        let parsed = parse_local_proxy_port(&form.local_proxy_port);
        let invalid = parsed.is_none().then(|| tr!("local-proxy-port-invalid"));
        card.field_row(tr!("local-proxy-port"), invalid.as_deref(), |ui| {
            let response = ui.add(
                widgets::TextField::new(&mut form.local_proxy_port)
                    .width(LOCAL_PROXY_PORT_WIDTH)
                    .enabled(editable)
                    .invalid(parsed.is_none()),
            );
            if response.changed() {
                form.local_proxy_port_dirty = true;
            }
            if response.lost_focus()
                && let Some(port) = parsed
            {
                form.local_proxy_port_dirty = false;
                actions.push(Action::SetLocalProxyPort(port));
            }
        });
        let mut share = saved.share_on_lan;
        if card
            .toggle(
                tr!("share-on-lan"),
                None,
                tr!("share-on-lan-detail"),
                &mut share,
                editable,
            )
            .changed()
        {
            actions.push(Action::SetShareOnLan(share));
        }
        if let Some(note) = local_proxy_note(state, saved) {
            card.body(|ui| {
                ui.add(
                    egui::Label::new(RichText::new(note).small().color(theme::palette().text_dim))
                        .wrap(),
                );
            });
        }
    });
}

/// `None` for what the port field holds and cannot be saved.
fn parse_local_proxy_port(text: &str) -> Option<u16> {
    text.trim()
        .parse()
        .ok()
        .filter(|port| LocalProxySettings::port_is_valid(*port))
}

/// What the user has to know or do about the proxy right now: where other devices
/// find it, or that the desktop's settings are theirs to set.
fn local_proxy_note(state: &State, saved: LocalProxySettings) -> Option<String> {
    let local = format!("127.0.0.1:{}", saved.port);
    if state.system_proxy.failed {
        return Some(tr!("system-proxy-failed", address = local));
    }
    if state.system_proxy.manual {
        return Some(tr!("system-proxy-manual", address = local));
    }
    if !saved.share_on_lan {
        return None;
    }
    if state.lockdown_active() && !state.lockdown_lan_open() {
        return Some(tr!("share-on-lan-lockdown"));
    }
    Some(match state.system_proxy.lan_address {
        Some(address) => tr!(
            "share-on-lan-address",
            address = std::net::SocketAddr::new(address, saved.port).to_string()
        ),
        None => tr!("share-on-lan-no-address"),
    })
}

fn connection(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    widgets::settings_card(ui, |card| {
        let editable = state.can_edit_settings();
        let mut connect_on_start = state.config.interface.connect_on_start;
        if card
            .toggle(
                tr!("connect-on-start"),
                None,
                tr!("connect-on-start-detail"),
                &mut connect_on_start,
                editable,
            )
            .changed()
        {
            actions.push(Action::SetConnectOnStart(connect_on_start));
        }
        let lockdown = state.lockdown_active();
        let kill_switch_unavailable = state.kill_switch_unavailable();
        let mut kill_switch =
            !kill_switch_unavailable && (state.config.settings.kill_switch || lockdown);
        if card
            .toggle_with(
                tr!("kill-switch"),
                None,
                if kill_switch_unavailable {
                    tr!("kill-switch-unavailable")
                } else if lockdown {
                    tr!("kill-switch-lockdown")
                } else {
                    state.kill_switch_detail()
                },
                pending(state.waits_for_next_connect(SessionPart::Protection)),
                &mut kill_switch,
                state.config_ready
                    && !kill_switch_unavailable
                    && !state.operations.kill_switch
                    && !state.operations.helper
                    && !lockdown,
            )
            .changed()
        {
            actions.push(Action::SetKillSwitch(kill_switch));
        }
        let mut lockdown_on = lockdown;
        if card
            .toggle(
                tr!("lockdown"),
                Some(&tr!("experimental")),
                if state.lockdown_unavailable() {
                    tr!("lockdown-unavailable")
                } else {
                    tr!("lockdown-detail")
                },
                &mut lockdown_on,
                state.can_change_lockdown(),
            )
            .changed()
        {
            actions.push(Action::RequestLockdown(lockdown_on));
        }
        let mut allow_lan = state.config.settings.allow_lan;
        if card
            .toggle_with(
                tr!("allow-lan"),
                None,
                tr!("allow-lan-detail"),
                pending(state.allow_lan_next_connect()),
                &mut allow_lan,
                editable,
            )
            .on_hover_text(tr!("allow-lan-hint"))
            .changed()
        {
            actions.push(Action::SetAllowLan(allow_lan));
        }
        let lan_on = state.config.settings.allow_lan;
        let mut private_networks = state.config.settings.private_networks;
        if card
            .toggle_with(
                tr!("private-networks"),
                None,
                tr!("private-networks-detail"),
                widgets::RowOptions {
                    pending: state.private_networks_next_connect(),
                    nested: true,
                    ..widgets::RowOptions::default()
                },
                &mut private_networks,
                editable && lan_on,
            )
            .on_hover_text(if lan_on {
                tr!("private-networks-hint")
            } else {
                tr!("private-networks-needs-lan")
            })
            .changed()
        {
            actions.push(Action::SetPrivateNetworks(private_networks));
        }
        if state.outside_scope && state.lockdown_active() {
            card.body(|ui| {
                ui.label(
                    RichText::new(tr!("lockdown-outside-scope"))
                        .small()
                        .color(theme::palette().accent_light),
                );
            });
        }
        if state.lockdown_lan_kept && state.lockdown_active() {
            card.body(|ui| {
                ui.label(
                    RichText::new(tr!("lockdown-lan-kept"))
                        .small()
                        .color(theme::palette().accent_light),
                );
            });
        }
        let mut auto_reconnect = state.config.settings.auto_reconnect;
        if card
            .toggle_with(
                tr!("auto-reconnect"),
                None,
                tr!("auto-reconnect-detail"),
                pending(state.auto_reconnect_next_connect()),
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
                None,
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
        card.row_with(
            tr!("dns-through-tunnel"),
            Some(&tr!("dns-explanation")),
            pending(state.waits_for_next_connect(SessionPart::Dns)),
            |_| {},
        );
        card.body(|ui| {
            let editable = state.can_edit_settings();
            let saved = DnsPreset::matching(&state.config.settings.dns);
            let custom = state.settings.screen.custom_dns;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = theme::space::S;
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
                ui.add_space(theme::space::L);
                dns_form(ui, state, actions);
            }
            ui.add_space(theme::space::M);
            ui.label(
                RichText::new(tr!("dns-reachable"))
                    .small()
                    .color(theme::palette().text_dim),
            );
            apply_note(ui, state, SessionPart::Dns, actions);
        });
    });
}

/// "Not applied · Apply" under a setting that a running session can pick up right away.
fn apply_note(ui: &mut egui::Ui, state: &State, part: SessionPart, actions: &mut Vec<Action>) {
    if !state.session_up() || !state.pending_reconnect(part) || !state.can_apply() {
        return;
    }
    let muted = theme::palette().text_muted;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.label(RichText::new(tr!("apply-on-leave")).small().color(muted));
        ui.label(RichText::new(tr!("apply-separator")).small().color(muted));
        if widgets::link(ui, &tr!("apply-now"), true)
            .on_hover_text(tr!("apply-hint"))
            .clicked()
        {
            actions.push(Action::Apply);
        }
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
                    .font(theme::font::semibold(theme::font::CAPTION))
                    .color(theme::palette().text),
            );
            ui.add(
                egui::Label::new(
                    RichText::new(detail)
                        .small()
                        .color(theme::palette().text_dim),
                )
                .wrap(),
            );
        });
    })
}

fn dns_form(ui: &mut egui::Ui, state: &mut State, actions: &mut Vec<Action>) {
    let editable = state.can_edit_settings();
    let form = &mut state.settings.screen;
    let label_width = [
        tr!("resolver-ip"),
        tr!("tls-name"),
        tr!("port"),
        tr!("dns-path"),
    ]
    .into_iter()
    .map(|label| {
        ui.painter()
            .layout_no_wrap(
                label,
                egui::TextStyle::Body.resolve(ui.style()),
                theme::palette().text,
            )
            .size()
            .x
    })
    .fold(0.0, f32::max);
    let input_width = (ui.available_width() - label_width - 16.0).clamp(120.0, 300.0);
    let parsed = form.parsed_dns();
    egui::Grid::new("dns_settings_fields")
        .num_columns(2)
        .spacing([16.0, 10.0])
        .show(ui, |ui| {
            for (label, value, hint, failure) in [
                (
                    tr!("resolver-ip"),
                    &mut form.server,
                    "",
                    rosetun_core::DnsInputError::InvalidServer,
                ),
                (
                    tr!("tls-name"),
                    &mut form.server_name,
                    "",
                    rosetun_core::DnsInputError::InvalidServerName,
                ),
                (
                    tr!("port"),
                    &mut form.port,
                    constants::PORT_PLACEHOLDER,
                    rosetun_core::DnsInputError::InvalidPort,
                ),
                (
                    tr!("dns-path"),
                    &mut form.path,
                    constants::DNS_PATH_PLACEHOLDER,
                    rosetun_core::DnsInputError::InvalidPath,
                ),
            ] {
                ui.label(label);
                let field = widgets::TextField::new(value)
                    .hint(hint)
                    .width(input_width)
                    .enabled(editable)
                    .invalid(parsed.as_ref().err() == Some(&failure));
                if ui.add(field).changed() {
                    form.dirty = true;
                }
                ui.end_row();
            }
        });
    if let Err(error) = &parsed {
        ui.colored_label(
            theme::ERROR,
            errors::dns_input(crate::i18n::language(), error),
        );
    }
    ui.add_space(theme::space::S);
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

fn advanced(ui: &mut egui::Ui, state: &mut State, actions: &mut Vec<Action>) {
    xray(ui, state, actions);
    ui.add_space(theme::space::M);
    fragment(ui, state, actions);
}

fn fragment(ui: &mut egui::Ui, state: &mut State, actions: &mut Vec<Action>) {
    let xray_off = state.config.settings.xray == XrayUse::Off;
    let editable = state.can_edit_settings() && !xray_off;
    let enabled = state.config.settings.tls_fragment.enabled;
    widgets::settings_card(ui, |card| {
        let mut on = enabled;
        let detail = if xray_off {
            tr!("fragment-needs-xray")
        } else {
            tr!("fragment-detail")
        };
        if card
            .toggle_with(
                tr!("fragment-title"),
                None,
                detail,
                pending(state.waits_for_next_connect(SessionPart::Fragment)),
                &mut on,
                editable,
            )
            .changed()
        {
            actions.push(Action::SetTlsFragment(on));
        }
        if enabled {
            card.body(|ui| {
                fragment_form(ui, state, editable, actions);
                apply_note(ui, state, SessionPart::Fragment, actions);
            });
        }
    });
}

fn fragment_form(ui: &mut egui::Ui, state: &mut State, editable: bool, actions: &mut Vec<Action>) {
    let saved = state.config.settings.tls_fragment;
    let form = &mut state.settings.screen;
    let parsed = form.parsed_fragment(saved.enabled);
    let labels = [
        tr!("fragment-packets"),
        tr!("fragment-length"),
        tr!("fragment-interval"),
    ];
    let label_width = labels
        .iter()
        .map(|label| {
            ui.painter()
                .layout_no_wrap(
                    label.to_string(),
                    egui::TextStyle::Body.resolve(ui.style()),
                    theme::palette().text,
                )
                .size()
                .x
        })
        .fold(0.0, f32::max);
    let input_width = (ui.available_width() - label_width - 16.0).clamp(120.0, 300.0);
    egui::Grid::new("fragment_settings_fields")
        .num_columns(2)
        .spacing([16.0, 10.0])
        .show(ui, |ui| {
            for (label, value, hint, tooltip, failure) in [
                (
                    &labels[0],
                    &mut form.fragment_packets,
                    constants::FRAGMENT_PACKETS_PLACEHOLDER,
                    tr!("fragment-packets-hint"),
                    rosetun_core::FragmentInputError::InvalidPackets,
                ),
                (
                    &labels[1],
                    &mut form.fragment_length,
                    constants::FRAGMENT_LENGTH_PLACEHOLDER,
                    tr!("fragment-length-hint"),
                    rosetun_core::FragmentInputError::InvalidLength,
                ),
                (
                    &labels[2],
                    &mut form.fragment_interval,
                    constants::FRAGMENT_INTERVAL_PLACEHOLDER,
                    tr!("fragment-interval-hint"),
                    rosetun_core::FragmentInputError::InvalidInterval,
                ),
            ] {
                ui.label(label.as_str());
                let field = widgets::TextField::new(value)
                    .hint(hint)
                    .width(input_width)
                    .enabled(editable)
                    .invalid(parsed.as_ref().err() == Some(&failure));
                if ui.add(field).on_hover_text(tooltip).changed() {
                    form.fragment_dirty = true;
                }
                ui.end_row();
            }
        });
    if let Err(error) = &parsed {
        ui.colored_label(
            theme::ERROR,
            errors::fragment_input(crate::i18n::language(), error),
        );
    }
    ui.add_space(theme::space::S);
    if widgets::button_fill(
        ui,
        tr!("save"),
        editable && parsed.is_ok_and(|fragment| fragment != saved),
    )
    .clicked()
    {
        actions.push(Action::SaveTlsFragment);
    }
    ui.add_space(theme::space::S);
}

fn xray(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    widgets::settings_card(ui, |card| {
        card.row_with(
            tr!("xray-title"),
            Some(&tr!("xray-detail")),
            pending(state.xray_next_connect()),
            |_| {},
        );
        card.body(|ui| {
            let selected = state.config.settings.xray;
            for (index, setting, title, detail) in [
                (0, XrayUse::Auto, tr!("xray-auto"), tr!("xray-auto-detail")),
                (1, XrayUse::Off, tr!("xray-off"), tr!("xray-off-detail")),
                (
                    2,
                    XrayUse::Always,
                    tr!("xray-always"),
                    tr!("xray-always-detail"),
                ),
            ] {
                let width = ui.available_width();
                let response = widgets::choice_card(
                    ui,
                    ("xray-setting", index),
                    width,
                    selected == setting,
                    state.can_edit_settings(),
                    &title,
                    |ui| {
                        ui.horizontal(|ui| {
                            let (radio, _) = ui
                                .allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
                            ui.painter().circle_stroke(
                                radio.center(),
                                7.0,
                                egui::Stroke::new(
                                    theme::stroke::GLYPH,
                                    if selected == setting {
                                        theme::palette().accent_light
                                    } else {
                                        theme::palette().text_dim
                                    },
                                ),
                            );
                            if selected == setting {
                                ui.painter().circle_filled(
                                    radio.center(),
                                    3.5,
                                    theme::palette().accent_light,
                                );
                            }
                            ui.vertical(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(&title).strong());
                                    if setting == XrayUse::Auto {
                                        ui.colored_label(
                                            theme::palette().accent_light,
                                            tr!("xray-recommended"),
                                        );
                                    }
                                });
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&detail)
                                            .small()
                                            .color(theme::palette().text_dim),
                                    )
                                    .wrap(),
                                );
                            });
                        });
                    },
                );
                if response.clicked() && selected != setting {
                    actions.push(Action::SetXray(setting));
                }
                ui.add_space(theme::space::S);
            }
            if selected == XrayUse::Off {
                let count = state.xray_reality_count();
                if count > 0 {
                    ui.add(
                        egui::Label::new(
                            RichText::new(crate::i18n::xray_off_warning(count))
                                .small()
                                .color(theme::ERROR),
                        )
                        .wrap(),
                    );
                    ui.add_space(theme::space::S);
                }
            }
            if let Some(status) = state.visible_status().filter(|status| {
                matches!(
                    status.state,
                    ConnectionState::Connected | ConnectionState::Reconnecting
                )
            }) {
                let node = state.running_node();
                // No server name here: providers often name nodes by their address,
                // and this screen ends up in screenshots.
                let current = if status.xray {
                    match node {
                        Some(node)
                            if matches!(
                                &node.stream.transport,
                                rosetun_config::Transport::Xhttp { .. }
                            ) =>
                        {
                            tr!("xray-current-xhttp")
                        }
                        Some(node) if matches!(&node.stream.tls, TlsMode::Reality(_)) => {
                            tr!("xray-current-reality")
                        }
                        _ => tr!("xray-current-chained"),
                    }
                } else {
                    tr!("xray-current-singbox")
                };
                ui.add(
                    egui::Label::new(
                        RichText::new(current)
                            .small()
                            .color(theme::palette().text_dim),
                    )
                    .wrap(),
                );
            }
        });
    });
}

fn service(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let running = state.helper_available;
    let color = if running {
        theme::connected()
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
                    ui.spacing_mut().item_spacing.x = theme::space::XS;
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
    ui.add_space(theme::space::L);
    widgets::settings_card(ui, |card| {
        let checked = state.system_checks.checked_at.map_or_else(
            || tr!("system-check-never"),
            |at| {
                tr!(
                    "system-check-last",
                    when = i18n::updated_ago(at, now_unix())
                )
            },
        );
        card.row(tr!("system-check-title"), Some(&checked), |ui| {
            if widgets::outline_button(
                ui,
                if state.system_checks.checking {
                    tr!("system-check-running")
                } else {
                    tr!("system-check-run")
                },
                !state.system_checks.checking,
            )
            .clicked()
            {
                actions.push(Action::CheckSystem);
            }
        });
        if let Some(results) = &state.system_checks.results {
            for result in results {
                let title = match result.kind {
                    CheckKind::Clock => tr!("system-check-clock"),
                    CheckKind::Proxy => tr!("system-check-proxy"),
                    CheckKind::PacketInterceptor => tr!("system-check-packet"),
                    CheckKind::OtherVpn => tr!("system-check-vpn"),
                    CheckKind::DnsSubstitution => tr!("system-check-dns"),
                };
                let (icon, color) = match result.status {
                    CheckStatus::Ok => (Icon::Check, theme::connected()),
                    CheckStatus::Warning => (Icon::Warning, theme::WARNING),
                    CheckStatus::Unavailable | CheckStatus::Skipped => {
                        (Icon::Unknown, theme::palette().text_dim)
                    }
                };
                let detail = i18n::check_detail(result);
                let rect = card.row_with_title(
                    |ui| {
                        ui.horizontal(|ui| {
                            let size = ui.text_style_height(&egui::TextStyle::Body);
                            let (rect, _) = ui
                                .allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
                            if ui.is_rect_visible(rect) {
                                icons::paint(ui.painter(), rect.center(), icon, color);
                            }
                            ui.label(title);
                        });
                    },
                    Some(&detail),
                    |_| {},
                );
                if let Some(hint) = i18n::check_hint(result) {
                    card.hover_hint(rect, &hint);
                }
            }
        } else {
            card.row(tr!("system-check-intro"), None, |_| {});
        }
    });
    ui.add_space(theme::space::L);
    widgets::settings_card(ui, |card| {
        card.row(tr!("log-title"), Some(&tr!("log-detail")), |ui| {
            #[cfg(windows)]
            ui.horizontal(|ui| {
                if widgets::outline_button(
                    ui,
                    if state.settings.screen.report_running {
                        tr!("report-collecting")
                    } else {
                        tr!("report-save")
                    },
                    state.can_save_report(),
                )
                .clicked()
                {
                    actions.push(Action::SaveReport);
                }
                if widgets::outline_button(ui, tr!("open-folder"), state.can_edit_settings())
                    .clicked()
                {
                    actions.push(Action::OpenFolder(AboutFolder::Config));
                }
            });
            #[cfg(not(windows))]
            let _ = ui;
        });
        #[cfg(windows)]
        if state.settings.screen.report_saved.is_some() {
            card.row(tr!("report-saved"), None, |ui| {
                if widgets::outline_button(ui, tr!("report-show-in-folder"), true).clicked() {
                    actions.push(Action::ShowReportFolder);
                }
            });
        }
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
                None,
                &detail,
                &mut on,
                state.can_edit_settings(),
            )
            .changed()
        {
            actions.push(Action::SetVerboseLog(on));
        }
    });
    ui.add_space(theme::space::L);
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

/// One line under a failed lookup that points to the DNS check.
pub(crate) fn dns_hint(ui: &mut egui::Ui, actions: &mut Vec<Action>) {
    ui.horizontal_wrapped(|ui| {
        ui.colored_label(theme::WARNING, tr!("system-check-dns-hint"));
        if ui.link(tr!("system-check-more")).clicked() {
            actions.push(Action::ShowSystemChecks);
        }
    });
}

pub(crate) fn reset_dialog(ctx: &egui::Context, state: &State, actions: &mut Vec<Action>) {
    let choice = widgets::confirm_modal(
        ctx,
        widgets::ConfirmModal {
            id: "reset_settings",
            title: tr!("reset-settings-question"),
            cancel: tr!("cancel"),
            confirm: tr!("reset-to-default"),
            busy: state.settings_busy_shown(state.frame_time()),
            confirm_enabled: state.can_reset_settings(),
            width: widgets::DialogWidth::Standard,
        },
        |ui| {
            ui.add_space(theme::space::M);
            ui.add(egui::Label::new(tr!("reset-settings-body")).wrap());
        },
    );
    match choice {
        widgets::ModalChoice::Cancel => actions.push(Action::CancelResetSettings),
        widgets::ModalChoice::Confirm => actions.push(Action::ConfirmResetSettings),
        widgets::ModalChoice::None => {}
    }
}

fn about(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    widgets::settings_card(ui, |card| {
        card.body(|ui| {
            ui.horizontal(|ui| {
                let (emblem, _) =
                    ui.allocate_exact_size(egui::vec2(56.0, 56.0), egui::Sense::hover());
                brand::paint_emblem(ui.painter(), emblem);
                ui.add_space(theme::space::L);
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(constants::BRAND)
                            .font(egui::FontId::new(
                                theme::font::BRAND_ABOUT,
                                egui::FontFamily::Name(theme::BRAND_FONT.into()),
                            ))
                            .color(theme::palette().text),
                    );
                    let version = crate::i18n::about_version(
                        env!("CARGO_PKG_VERSION"),
                        state
                            .helper_available
                            .then_some(state.helper_version.as_deref())
                            .flatten(),
                    );
                    ui.label(
                        RichText::new(version)
                            .small()
                            .color(theme::palette().text_muted),
                    );
                });
            });
        });
    });
    ui.add_space(theme::SECTION_GAP);
    widgets::settings_card(ui, |card| {
        card.body(|ui| {
            ui.label(
                RichText::new(tr!("updates-title"))
                    .font(theme::font::title())
                    .color(theme::palette().text),
            );
            if let Some(release) = state.available_update() {
                ui.add_space(theme::space::L);
                let width = ui.available_width();
                egui::Frame::new()
                    .fill(theme::palette().input)
                    .stroke(egui::Stroke::new(
                        theme::stroke::HAIRLINE,
                        theme::palette().accent_dark,
                    ))
                    .corner_radius(theme::RADIUS)
                    .inner_margin(theme::margin::same(theme::space::L))
                    .show(ui, |ui| {
                        ui.set_min_width((width - 32.0).max(0.0));
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = theme::space::M;
                            let (icon, _) = ui
                                .allocate_exact_size(egui::vec2(32.0, 32.0), egui::Sense::hover());
                            let center = icon.center();
                            let painter = ui.painter();
                            painter.circle_stroke(
                                center,
                                15.5,
                                egui::Stroke::new(
                                    theme::stroke::HAIRLINE,
                                    theme::palette().accent_base,
                                ),
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
                                    egui::Stroke::new(
                                        theme::stroke::GLYPH,
                                        theme::palette().accent_light,
                                    ),
                                );
                            }
                            ui.vertical(|ui| {
                                ui.label(
                                    RichText::new(crate::i18n::update_available(&release.version))
                                        .font(theme::font::title())
                                        .color(theme::palette().text),
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
                                        RichText::new(detail)
                                            .small()
                                            .color(theme::palette().text_muted),
                                    )
                                    .wrap(),
                                );
                                ui.add_space(theme::space::S);
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
                None,
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
        if let Some(folder) = &state.settings.screen.config_folder {
            about_path(
                card,
                state,
                &tr!("configuration-folder"),
                folder.to_string_lossy().as_ref(),
                AboutFolder::Config,
                actions,
            );
            let log = folder.join(constants::LOG_FILE_NAME);
            about_path(
                card,
                state,
                &tr!("log-file"),
                log.to_string_lossy().as_ref(),
                AboutFolder::Config,
                actions,
            );
        }
        if let Some(folder) = &state.settings.screen.licenses_folder {
            about_path(
                card,
                state,
                &tr!("licenses-folder"),
                folder.to_string_lossy().as_ref(),
                AboutFolder::Licenses,
                actions,
            );
        }
    });
    ui.add_space(theme::SECTION_GAP);
    ui.add(
        egui::Label::new(
            RichText::new(tr!("license-notice"))
                .small()
                .color(theme::palette().text_dim),
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
    card: &mut widgets::SettingsCard<'_>,
    state: &State,
    label: &str,
    path: &str,
    folder: AboutFolder,
    actions: &mut Vec<Action>,
) {
    let path = state.text(path);
    card.row_with_title(
        |ui| {
            ui.label(RichText::new(label).color(theme::palette().text));
            ui.add(
                egui::Label::new(
                    RichText::new(&path)
                        .small()
                        .color(theme::palette().text_dim),
                )
                .truncate(),
            )
            .on_hover_text(&path);
        },
        None,
        |ui| {
            #[cfg(windows)]
            if widgets::outline_button(ui, tr!("open-folder"), state.can_open_folders()).clicked() {
                actions.push(Action::OpenFolder(folder));
            }
            #[cfg(not(windows))]
            let _ = (ui, actions, folder);
        },
    );
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

#[cfg(test)]
mod lockdown_switch_tests {
    use super::*;
    use crate::i18n::Language;
    use crate::worker::WorkerEvent;

    fn state(lockdown: bool) -> State {
        let mut state = State::default();
        state.config_ready = true;
        state.reduce(WorkerEvent::HelperAvailable {
            version: "0.9.0".into(),
            protection: crate::worker::FULL_PROTECTION,
        });
        state.reduce(WorkerEvent::Status(rosetun_config::Status {
            lockdown,
            ..rosetun_config::Status::default()
        }));
        state
    }

    /// Draws the Connection section, then clicks the row of the setting titled `title` beside
    /// that title: a click on the title's text itself goes to the selectable label.
    fn click_row(state: &State, title: &str) -> Vec<Action> {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let run = |events: Vec<egui::Event>| {
            let mut actions = Vec::new();
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(960.0, 640.0),
                    )),
                    events,
                    ..egui::RawInput::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        connection(ui, state, &mut actions);
                    });
                },
            );
            output.textures_delta.clear();
            let title = output.shapes.iter().find_map(|shape| match &shape.shape {
                egui::Shape::Text(text) if text.galley.text() == title => {
                    let rect = text.galley.rect.translate(text.pos.to_vec2());
                    Some(egui::pos2(rect.right() + 200.0, rect.center().y))
                }
                _ => None,
            });
            (actions, title)
        };
        // The first frame lays the card out before it knows its own size.
        run(Vec::new());
        let pos = run(Vec::new()).1.expect("the switch is drawn");
        let button = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        run(vec![egui::Event::PointerMoved(pos), button(true)]);
        run(vec![button(false)]).0
    }

    fn click_lockdown(state: &State) -> Vec<Action> {
        click_row(state, &tr!("lockdown"))
    }

    /// Every text the Connection section draws.
    fn texts(state: &State) -> Vec<String> {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut shown = Vec::new();
        for _ in 0..2 {
            let mut actions = Vec::new();
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(960.0, 640.0),
                    )),
                    ..egui::RawInput::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        connection(ui, state, &mut actions);
                    });
                },
            );
            output.textures_delta.clear();
            shown = output
                .shapes
                .iter()
                .filter_map(|shape| match &shape.shape {
                    egui::Shape::Text(text) => Some(text.galley.text().to_owned()),
                    _ => None,
                })
                .collect();
        }
        shown
    }

    fn with_protection(protection: Option<rosetun_config::ProtectionCapabilities>) -> State {
        let mut state = state(false);
        state.config.settings.kill_switch = true;
        state.protection = protection;
        state
    }

    #[test]
    fn a_system_without_protection_shows_both_switches_as_unavailable_and_inert() {
        let none = Some(rosetun_config::ProtectionCapabilities::default());
        for language in [Language::English, Language::Russian] {
            crate::i18n::in_language(language, || {
                let state = with_protection(none);
                let shown = texts(&state);
                assert!(
                    shown.contains(&tr!("kill-switch-unavailable")),
                    "{language:?}"
                );
                assert!(shown.contains(&tr!("lockdown-unavailable")), "{language:?}");
                assert!(!shown.contains(&tr!("kill-switch-detail")), "{language:?}");
                assert!(!shown.contains(&tr!("lockdown-detail")), "{language:?}");
                assert!(click_lockdown(&state).is_empty(), "{language:?}");
                assert!(
                    click_row(&state, &tr!("kill-switch")).is_empty(),
                    "{language:?}"
                );
            });
        }
    }

    #[test]
    fn until_the_helper_answers_the_switches_look_and_work_as_before() {
        for protection in [None, Some(crate::worker::FULL_PROTECTION)] {
            let state = with_protection(protection);
            let shown = texts(&state);
            assert!(shown.contains(&tr!("kill-switch-detail")), "{protection:?}");
            assert!(shown.contains(&tr!("lockdown-detail")), "{protection:?}");
            assert!(
                !shown.contains(&tr!("kill-switch-unavailable")),
                "{protection:?}"
            );
            assert!(
                !shown.contains(&tr!("lockdown-unavailable")),
                "{protection:?}"
            );
            assert!(
                matches!(
                    click_row(&state, &tr!("kill-switch")).as_slice(),
                    [Action::SetKillSwitch(false)]
                ),
                "{protection:?}"
            );
            assert!(
                matches!(
                    click_lockdown(&state).as_slice(),
                    [Action::RequestLockdown(true)]
                ),
                "{protection:?}"
            );
        }
    }

    #[test]
    fn the_settings_keep_the_lockdown_switch_and_ask_to_confirm() {
        for (lockdown, expected) in [(false, true), (true, false)] {
            let actions = click_lockdown(&state(lockdown));
            assert!(
                matches!(actions.as_slice(), [Action::RequestLockdown(asked)] if *asked == expected),
                "lockdown {lockdown}: {} actions",
                actions.len()
            );
        }
    }
}

#[cfg(test)]
mod drop_down_tests {
    use super::*;
    use crate::i18n::{self, Language};
    use crate::test_ui::TestScreen;

    fn screen() -> TestScreen {
        TestScreen::new(egui::vec2(960.0, 640.0))
    }

    #[test]
    fn choosing_a_language_asks_for_that_language() {
        i18n::in_language(Language::English, || {
            let mut state = State::default();
            state.config_ready = true;
            let mut actions = Vec::new();
            let mut screen = screen();
            let mut show = |ui: &mut egui::Ui| {
                egui::CentralPanel::default().show(ui, |ui| general(ui, &state, &mut actions));
            };
            screen.click_text(&tr!("language-system"), &mut show);
            screen.click_text(Language::Russian.info().native_name, &mut show);
            assert!(
                actions
                    .iter()
                    .any(|action| matches!(action, Action::SetLanguage(LanguageSetting::Russian))),
                "{}",
                actions.len()
            );
        });
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn choosing_what_quitting_does_asks_for_that_action() {
        i18n::in_language(Language::English, || {
            let mut state = State::default();
            state.config_ready = true;
            let mut actions = Vec::new();
            let mut screen = screen();
            let mut show = |ui: &mut egui::Ui| {
                egui::CentralPanel::default().show(ui, |ui| desktop(ui, &state, &mut actions));
            };
            screen.click_text(&tr!("quit-action-ask"), &mut show);
            screen.click_text(&tr!("quit-action-keep"), &mut show);
            assert!(
                actions
                    .iter()
                    .any(|action| matches!(action, Action::SetOnQuit(QuitAction::KeepConnected)))
            );
        });
    }
}

#[cfg(test)]
mod fragment_tests {
    use super::*;
    use crate::i18n::{self, Language};
    use crate::test_ui::TestScreen;

    fn shown(state: &mut State, actions: &mut Vec<Action>) -> Vec<String> {
        let mut screen = TestScreen::new(egui::vec2(960.0, 900.0));
        screen
            .settle(|ui| {
                egui::CentralPanel::default().show(ui, |ui| advanced(ui, state, actions));
            })
            .into_iter()
            .map(|(text, _)| text)
            .collect()
    }

    fn state(xray: XrayUse, enabled: bool) -> State {
        let mut state = State::default();
        state.config_ready = true;
        state.config.settings.xray = xray;
        state.config.settings.tls_fragment.enabled = enabled;
        let fragment = state.config.settings.tls_fragment;
        state.settings.screen.sync_fragment(&fragment);
        state
    }

    #[test]
    fn the_switch_is_unavailable_with_its_reason_while_xray_is_off_in_both_languages() {
        for language in [Language::English, Language::Russian] {
            i18n::in_language(language, || {
                let mut state = state(XrayUse::Off, false);
                let mut actions = Vec::new();
                let texts = shown(&mut state, &mut actions);
                assert!(texts.contains(&tr!("fragment-needs-xray")));
                assert!(!texts.contains(&tr!("fragment-detail")));

                let mut screen = TestScreen::new(egui::vec2(960.0, 900.0));
                let mut show = |ui: &mut egui::Ui| {
                    egui::CentralPanel::default()
                        .show(ui, |ui| advanced(ui, &mut state, &mut actions));
                };
                screen.click_text(&tr!("fragment-title"), &mut show);
                assert!(
                    !actions
                        .iter()
                        .any(|action| matches!(action, Action::SetTlsFragment(_)))
                );
            });
        }
    }

    #[test]
    fn the_switch_asks_for_fragmentation_and_shows_its_caption_in_both_languages() {
        for language in [Language::English, Language::Russian] {
            i18n::in_language(language, || {
                let mut state = state(XrayUse::Auto, false);
                let mut actions = Vec::new();
                let mut screen = TestScreen::new(egui::vec2(960.0, 900.0));
                let mut show = |ui: &mut egui::Ui| {
                    egui::CentralPanel::default()
                        .show(ui, |ui| advanced(ui, &mut state, &mut actions));
                };
                let texts = screen.click_text(&tr!("fragment-title"), &mut show);
                assert!(
                    texts
                        .iter()
                        .any(|(text, _)| *text == tr!("fragment-detail"))
                );
                assert!(
                    actions
                        .iter()
                        .any(|action| matches!(action, Action::SetTlsFragment(true)))
                );
            });
        }
    }

    #[test]
    fn a_wrong_value_shows_its_caption_and_blocks_saving_in_both_languages() {
        for language in [Language::English, Language::Russian] {
            i18n::in_language(language, || {
                let mut state = state(XrayUse::Auto, true);
                let mut actions = Vec::new();
                let texts = shown(&mut state, &mut actions);
                assert!(texts.contains(&tr!("fragment-packets")));
                assert!(
                    !texts.contains(&tr!("error-fragment-length")),
                    "valid values show no error"
                );

                state.settings.screen.fragment_length = "9999".into();
                let texts = shown(&mut state, &mut actions);
                assert!(texts.contains(&tr!("error-fragment-length")));
                let mut screen = TestScreen::new(egui::vec2(960.0, 900.0));
                let mut show = |ui: &mut egui::Ui| {
                    egui::CentralPanel::default()
                        .show(ui, |ui| advanced(ui, &mut state, &mut actions));
                };
                screen.click_text(&tr!("save"), &mut show);
                assert!(
                    !actions
                        .iter()
                        .any(|action| matches!(action, Action::SaveTlsFragment))
                );
            });
        }
    }

    #[test]
    fn a_changed_valid_value_can_be_saved() {
        i18n::in_language(Language::English, || {
            let mut state = state(XrayUse::Auto, true);
            state.settings.screen.fragment_length = "100-200".into();
            let mut actions = Vec::new();
            let mut screen = TestScreen::new(egui::vec2(960.0, 900.0));
            let mut show = |ui: &mut egui::Ui| {
                egui::CentralPanel::default().show(ui, |ui| advanced(ui, &mut state, &mut actions));
            };
            screen.click_text(&tr!("save"), &mut show);
            assert!(
                actions
                    .iter()
                    .any(|action| matches!(action, Action::SaveTlsFragment))
            );
        });
    }
}

#[cfg(test)]
mod pending_notice_tests {
    use rosetun_config::{
        AppConfig, Node, NodeId, Outbound, Selection, Status, Subscription, SubscriptionId,
        VlessParams,
    };
    use rosetun_ipc::ConnectRequest;

    use super::*;
    use crate::i18n::{self, Language};
    use crate::test_ui::{TestScreen, Texts};
    use crate::worker::WorkerEvent;

    const WINDOWS: [(egui::Vec2, f32); 2] = [
        (egui::vec2(960.0, 640.0), 200.0),
        (egui::vec2(1200.0, 780.0), 240.0),
    ];
    const LANGUAGES: [Language; 2] = [Language::English, Language::Russian];

    fn connected(status: ConnectionState) -> State {
        let mut config = AppConfig::default();
        config.subscriptions.push(Subscription {
            id: SubscriptionId::new("1"),
            name: "Provider".into(),
            url: "https://example.com/secret-path".into(),
            nodes: vec![Node {
                id: NodeId::new("node"),
                name: "Test".into(),
                server: "127.0.0.1".into(),
                port: 443,
                outbound: Outbound::Vless(VlessParams {
                    uuid: "00000000-0000-0000-0000-000000000000".into(),
                    flow: None,
                }),
                stream: Default::default(),
                raw: None,
            }],
            auto_update: false,
            updated_at_unix: None,
            user_agent: None,
            send_hwid: true,
            hwid_scope: rosetun_config::HwidScope::Machine,
            info: None,
            update_interval_hours: None,
            support_url: None,
            web_page_url: None,
            announce: None,
            notices: vec![],
        });
        config.active = Some(Selection {
            subscription: SubscriptionId::new("1"),
            node: NodeId::new("node"),
        });
        config.settings.allow_lan = true;
        let request = ConnectRequest::from_config(&config).unwrap();
        let mut state = State::default();
        state.config = config;
        state.config_ready = true;
        state.reduce(WorkerEvent::HelperAvailable {
            version: "0.9.0".into(),
            protection: crate::worker::FULL_PROTECTION,
        });
        state.reduce(WorkerEvent::Connect(Ok(request)));
        state.reduce(WorkerEvent::Status(Status {
            state: status,
            ..Status::default()
        }));
        state
    }

    /// Draws the section where the settings screen draws it: beside the navigation, with the
    /// screen's own margins.
    fn page(ui: &mut egui::Ui, nav: f32, content: impl FnOnce(&mut egui::Ui)) {
        egui::Panel::left("nav").exact_size(nav).show(ui, |_| {});
        egui::CentralPanel::default()
            .frame(egui::Frame::new().inner_margin(theme::margin::same(theme::space::XXL)))
            .show(ui, content);
    }

    fn drawn(state: &State, size: egui::Vec2, nav: f32) -> Texts {
        let mut screen = TestScreen::new(size);
        screen.settle(|ui| page(ui, nav, |ui| connection(ui, state, &mut Vec::new())))
    }

    fn with_note(shown: &Texts) -> Vec<String> {
        let note = tr!("next-connect-note");
        shown
            .iter()
            .filter(|(text, _)| text.contains(&note))
            .map(|(text, _)| text.clone())
            .collect()
    }

    fn top_of(shown: &Texts, title: &str) -> f32 {
        shown
            .iter()
            .find(|(text, _)| text == title)
            .unwrap_or_else(|| panic!("no {title:?} on the screen"))
            .1
            .top()
    }

    /// How high a row with a caption of two lines is at this window size.
    fn two_line_row(size: egui::Vec2, nav: f32) -> f32 {
        let mut height = 0.0;
        let mut screen = TestScreen::new(size);
        screen.settle(|ui| {
            page(ui, nav, |ui| {
                widgets::settings_card(ui, |card| {
                    let mut on = false;
                    height = card
                        .toggle("Title", None, "First line\nSecond line", &mut on, true)
                        .rect
                        .height();
                });
            });
        });
        height
    }

    #[test]
    fn a_row_with_the_note_is_no_higher_than_one_with_a_two_line_caption() {
        for language in LANGUAGES {
            i18n::in_language(language, || {
                for (size, nav) in WINDOWS {
                    let mut state = connected(ConnectionState::Connected);
                    state.config.settings.allow_lan = true;
                    state.config.settings.private_networks = true;
                    state.config.settings.auto_reconnect = false;
                    let limit = two_line_row(size, nav);
                    let shown = drawn(&state, size, nav);
                    let row = |from: String, to: String| {
                        top_of(&shown, &to) - top_of(&shown, &from) - 1.0
                    };
                    let private = row(tr!("private-networks"), tr!("auto-reconnect"));
                    let reconnect = row(tr!("auto-reconnect"), tr!("auto-update-subscriptions"));
                    assert!(
                        private <= limit,
                        "{language:?} {size:?}: {private} > {limit}"
                    );
                    assert!(
                        reconnect <= limit,
                        "{language:?} {size:?}: {reconnect} > {limit}"
                    );

                    state.config.settings.allow_lan = false;
                    let shown = drawn(&state, size, nav);
                    // No line under this row, and the nested title stands at the top of its own.
                    let lan = top_of(&shown, &tr!("private-networks"))
                        - top_of(&shown, &tr!("allow-lan"))
                        + theme::space::L;
                    assert!(lan <= limit, "{language:?} {size:?}: {lan} > {limit}");
                }
            });
        }
    }

    #[test]
    fn the_mode_card_shows_the_proxy_settings_only_in_the_proxy_mode() {
        for language in LANGUAGES {
            i18n::in_language(language, || {
                let (size, _) = WINDOWS[0];
                let shown = |state: &mut State| {
                    let mut screen = TestScreen::new(size);
                    screen
                        .settle(|ui| connection_mode(ui, state, &mut Vec::new()))
                        .into_iter()
                        .map(|(text, _)| text)
                        .collect::<Vec<_>>()
                };
                let mut state = connected(ConnectionState::Disconnected);
                let texts = shown(&mut state);
                assert!(texts.contains(&tr!("connection-mode-tun-detail")));
                assert!(!texts.contains(&tr!("share-on-lan")));

                state.config.settings.connection_mode = ConnectionMode::SystemProxy;
                let texts = shown(&mut state);
                assert!(texts.contains(&tr!("connection-mode-proxy-detail")));
                assert!(texts.contains(&tr!("local-proxy-port")));
                assert!(texts.contains(&tr!("share-on-lan")));

                state.config.settings.local_proxy.share_on_lan = true;
                state.system_proxy.lan_address = Some("192.0.2.5".parse().unwrap());
                let address = tr!("share-on-lan-address", address = "192.0.2.5:10808");
                assert!(shown(&mut state).contains(&address));

                state.system_proxy.lan_address = None;
                assert!(shown(&mut state).contains(&tr!("share-on-lan-no-address")));

                state.settings.screen.local_proxy_port = "80".into();
                state.settings.screen.local_proxy_port_dirty = true;
                assert!(shown(&mut state).contains(&tr!("local-proxy-port-invalid")));
            });
        }
    }

    #[test]
    fn the_port_sits_in_a_row_like_the_other_settings() {
        let (size, _) = WINDOWS[0];
        let mut state = connected(ConnectionState::Disconnected);
        state.config.settings.connection_mode = ConnectionMode::SystemProxy;
        let mut screen = TestScreen::new(size);
        let texts = screen.settle(|ui| connection_mode(ui, &mut state, &mut Vec::new()));
        let rect = |wanted: &str| {
            texts
                .iter()
                .find(|(text, _)| text == wanted)
                .map_or_else(|| panic!("{wanted} is not shown"), |(_, rect)| *rect)
        };
        let label = rect(&tr!("local-proxy-port"));
        let value = rect("10808");
        // Level with its title, and in the column of the controls.
        assert!(
            (label.center().y - value.center().y).abs() < 2.0,
            "{label:?} {value:?}"
        );
        assert!(value.left() > size.x / 2.0, "{value:?}");
        // Under the switch between the modes, at the right as well.
        let proxy = rect(&tr!("connection-mode-proxy"));
        assert!(proxy.left() > size.x / 2.0, "{proxy:?}");
        assert!(rect(&tr!("connection-mode")).left() < label.left() + 1.0);
    }

    #[test]
    fn a_desktop_without_automatic_settings_gets_the_address_to_enter() {
        let saved = LocalProxySettings::default();
        let mut state = connected(ConnectionState::Connected);
        assert_eq!(local_proxy_note(&state, saved), None);
        state.system_proxy.manual = true;
        assert_eq!(
            local_proxy_note(&state, saved),
            Some(tr!("system-proxy-manual", address = "127.0.0.1:10808"))
        );
    }

    #[test]
    fn only_a_port_in_range_can_be_saved() {
        assert_eq!(parse_local_proxy_port(" 20808 "), Some(20808));
        for text in ["", "80", "1023", "65536", "a", "-1"] {
            assert_eq!(parse_local_proxy_port(text), None, "{text:?}");
        }
    }

    #[test]
    fn the_note_follows_the_caption_of_the_changed_setting_only() {
        for language in LANGUAGES {
            i18n::in_language(language, || {
                let (size, nav) = WINDOWS[0];
                let note = tr!("next-connect-note");
                let mut state = connected(ConnectionState::Connected);
                assert_eq!(with_note(&drawn(&state, size, nav)), Vec::<String>::new());
                assert!(
                    drawn(&state, size, nav)
                        .iter()
                        .any(|(text, _)| *text == tr!("auto-reconnect-detail")),
                    "the caption of the reconnect setting stands alone"
                );

                state.config.settings.private_networks = true;
                assert_eq!(
                    with_note(&drawn(&state, size, nav)),
                    [format!("{} {note}", tr!("private-networks-detail"))]
                );

                state.config.settings.private_networks = false;
                state.config.settings.auto_reconnect = false;
                assert_eq!(
                    with_note(&drawn(&state, size, nav)),
                    [format!("{} {note}", tr!("auto-reconnect-detail"))]
                );

                state.config.settings.auto_reconnect = true;
                state.config.settings.allow_lan = false;
                assert_eq!(
                    with_note(&drawn(&state, size, nav)),
                    [format!("{} {note}", tr!("allow-lan-detail"))]
                );
            });
        }
    }

    #[test]
    fn nothing_waits_without_a_connection() {
        let (size, nav) = WINDOWS[0];
        let mut state = connected(ConnectionState::Disconnected);
        state.config.settings.private_networks = true;
        state.config.settings.auto_reconnect = false;
        assert_eq!(with_note(&drawn(&state, size, nav)), Vec::<String>::new());
    }

    #[test]
    fn the_xray_note_shows_only_while_the_session_runs_another_mode() {
        let mut state = connected(ConnectionState::Connected);
        state.status.xray_use = Some(state.config.settings.xray);
        let shown = |state: &State| {
            TestScreen::new(egui::vec2(960.0, 900.0))
                .settle(|ui| page(ui, 200.0, |ui| xray(ui, state, &mut Vec::new())))
        };
        assert_eq!(with_note(&shown(&state)), Vec::<String>::new());
        state.config.settings.xray = XrayUse::Off;
        assert_eq!(
            with_note(&shown(&state)),
            [format!(
                "{} {}",
                tr!("xray-detail"),
                tr!("next-connect-note")
            )]
        );
    }

    #[test]
    fn private_networks_step_in_under_the_local_network() {
        let (size, nav) = WINDOWS[0];
        let state = connected(ConnectionState::Disconnected);
        let shown = drawn(&state, size, nav);
        let left = |title: String| {
            shown
                .iter()
                .find(|(text, _)| *text == title)
                .expect("the title is drawn")
                .1
                .left()
        };
        assert_eq!(
            left(tr!("private-networks")) - left(tr!("allow-lan")),
            theme::space::XL
        );
    }

    /// Presses the row beside its title: a click on the title's text goes to the selectable label.
    fn click_private_networks(state: &State) -> Vec<Action> {
        let (size, nav) = WINDOWS[0];
        let mut actions = Vec::new();
        let mut screen = TestScreen::new(size);
        let mut show = |ui: &mut egui::Ui| {
            page(ui, nav, |ui| connection(ui, state, &mut actions));
        };
        let title = tr!("private-networks");
        let rect = screen
            .settle(&mut show)
            .into_iter()
            .find(|(text, _)| *text == title)
            .expect("the row stays on the screen")
            .1;
        let pos = egui::pos2(rect.right() + 100.0, rect.center().y);
        let button = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        screen.run(
            vec![egui::Event::PointerMoved(pos), button(true)],
            &mut show,
        );
        screen.run(vec![button(false)], &mut show);
        actions
    }

    #[test]
    fn private_networks_are_unavailable_without_the_local_network_and_say_why() {
        for language in LANGUAGES {
            i18n::in_language(language, || {
                let (size, nav) = WINDOWS[0];
                let mut state = connected(ConnectionState::Disconnected);
                assert!(matches!(
                    click_private_networks(&state).as_slice(),
                    [Action::SetPrivateNetworks(true)]
                ));

                state.config.settings.allow_lan = false;
                assert!(click_private_networks(&state).is_empty());

                let mut screen = TestScreen::new(size);
                let mut show = |ui: &mut egui::Ui| {
                    page(ui, nav, |ui| connection(ui, &state, &mut Vec::new()));
                };
                let title = tr!("private-networks");
                let rect = screen
                    .settle(&mut show)
                    .into_iter()
                    .find(|(text, _)| *text == title)
                    .expect("the row stays on the screen")
                    .1;
                screen.run(
                    vec![egui::Event::PointerMoved(egui::pos2(
                        rect.right() + 100.0,
                        rect.center().y,
                    ))],
                    &mut show,
                );
                let shown = screen.settle(&mut show);
                assert!(
                    shown
                        .iter()
                        .any(|(text, _)| *text == tr!("private-networks-needs-lan")),
                    "{language:?}: {shown:?}"
                );
            });
        }
    }
}
