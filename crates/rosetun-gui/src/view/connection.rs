use eframe::egui::{self, Color32, RichText};
use rosetun_config::{ConnectionState, RuleMatcher};
use rosetun_ipc::ProbeOutcome;

use crate::actions::{PrimaryAction, ProtectionAction, protection_action};
use crate::errors;
use crate::icons::{self, Icon};
use crate::state::{Action, ExitLookup, ExitRoute, SessionPart, State, TunnelDelay, primary_label};
use crate::strings::t;
use crate::{display, strings, theme, widgets};

use super::rose_button::{self, RosePhase};
use super::rules::{target_color, target_label};

pub(crate) fn show(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    if !state.config_ready {
        ui.colored_label(theme::TEXT_DIM, tr!("loading"));
    }
    if !state.helper_available {
        service_banner(ui, state);
        ui.add_space(theme::SECTION_GAP);
    }
    hero_card(ui, state, actions);
    ui.add_space(theme::SECTION_GAP);
    control_cards(ui, state, actions);
}

fn service_banner(ui: &mut egui::Ui, state: &State) {
    let id = egui::Id::new("service_down_details");
    let expanded = ui.data(|data| data.get_temp::<bool>(id)).unwrap_or(false);
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        egui::Sides::new().shrink_left().wrap().spacing(16.0).show(
            ui,
            |ui| {
                ui.horizontal_top(|ui| {
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(28.0, 28.0), egui::Sense::hover());
                    ui.painter().circle_stroke(
                        rect.center(),
                        13.0,
                        egui::Stroke::new(1.5, theme::ERROR),
                    );
                    ui.painter().text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        "!",
                        egui::FontId::new(18.0, egui::FontFamily::Name(theme::UI_SEMIBOLD.into())),
                        theme::ERROR,
                    );
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(tr!("service-down-title"))
                                .strong()
                                .color(theme::TEXT),
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(tr!("service-down-body"))
                                    .small()
                                    .color(theme::TEXT_DIM),
                            )
                            .wrap(),
                        );
                    });
                });
            },
            |ui| {
                if widgets::outline_button(
                    ui,
                    if expanded {
                        tr!("hide-details")
                    } else {
                        tr!("details")
                    },
                    true,
                )
                .clicked()
                {
                    ui.data_mut(|data| data.insert_temp(id, !expanded));
                }
            },
        );
        if expanded && let Some(error) = &state.helper_error {
            ui.add_space(10.0);
            ui.add(
                egui::Label::new(
                    RichText::new(state.text(&errors::client(t(), error)))
                        .small()
                        .color(theme::TEXT_DIM),
                )
                .wrap(),
            );
        }
    });
}

fn hero_card(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    widgets::card_frame()
        .inner_margin(egui::Margin::symmetric(28, 20))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            let visible_status = state.visible_status();
            let (label, color) = visible_status
                .map_or((tr!("status-unknown"), theme::DISCONNECTED), |status| {
                    state_style(&status.state)
                });
            let server_pending = state.pending_reconnect(SessionPart::Server);
            let selection_changed =
                visible_status.filter(|status| {
                    (status.state.is_active() || status.state.is_transitional())
                        && (server_pending
                            || state.config.active.as_ref().is_none_or(|selection| {
                                status.node.as_ref() != Some(&selection.node)
                            }))
                });
            ui.horizontal_top(|ui| {
                ui.allocate_ui_with_layout(
                    egui::vec2(240.0, 260.0),
                    egui::Layout::top_down(egui::Align::Center),
                    |ui| {
                        let action = state.primary_action();
                        let phase = rose_button::rose_phase(
                            state.helper_available,
                            visible_status.map(|status| &status.state),
                        );
                        let button_label = if phase == RosePhase::Unavailable {
                            tr!("unavailable").to_owned()
                        } else {
                            primary_label(state)
                        };
                        if rose_button::rose_button(
                            ui,
                            phase,
                            &button_label,
                            action != PrimaryAction::Disabled,
                            state.config.interface.reduce_motion,
                        ) {
                            actions.push(Action::Primary);
                        }
                    },
                );
                ui.add_space(36.0);
                ui.vertical(|ui| {
                    ui.set_min_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 14.0;
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 4.0;
                        ui.label(RichText::new(label).size(26.0).color(color));
                        let session = visible_status
                            .and_then(|status| status.since_unix)
                            .map_or_else(
                                || tr!("no-session").to_owned(),
                                |since| display::session_text(Some(since), display::now_unix()),
                            );
                        ui.colored_label(
                            theme::TEXT_MUTED,
                            strings::plain_link(&tr!("session"), &session),
                        );
                    });
                    if let Some(status) = visible_status {
                        if status.state.is_transitional() {
                            if let Some(stage) = status.connect_stage {
                                let seconds = display::now_unix().saturating_sub(
                                    status.stage_since_unix.unwrap_or_else(display::now_unix),
                                );
                                ui.label(
                                    RichText::new(crate::i18n::connection_stage(stage, seconds))
                                        .small()
                                        .color(theme::TEXT_MUTED),
                                );
                                ui.ctx()
                                    .request_repaint_after(std::time::Duration::from_secs(1));
                            }
                            if widgets::outline_button(
                                ui,
                                if state.cancel_in_flight {
                                    tr!("cancelling")
                                } else {
                                    tr!("cancel-connection")
                                },
                                !state.cancel_in_flight,
                            )
                            .clicked()
                            {
                                actions.push(Action::CancelConnection);
                            }
                        }
                        if let ConnectionState::Failed {
                            reason,
                            failure_kind,
                        }
                        | ConnectionState::FailedProtected {
                            reason,
                            failure_kind,
                        } = &status.state
                        {
                            if let Some(kind) = failure_kind {
                                let (title, hint) = crate::i18n::connection_failure(*kind);
                                ui.colored_label(theme::ERROR, title)
                                    .on_hover_text(state.text(reason));
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(hint).small().color(theme::TEXT_MUTED),
                                    )
                                    .wrap(),
                                );
                                if let Some(conflicts) = &state.failure_interference {
                                    if !conflicts.other_vpns.is_empty() {
                                        ui.add(
                                            egui::Label::new(crate::i18n::other_vpn(
                                                &conflict_names(state, &conflicts.other_vpns),
                                            ))
                                            .wrap(),
                                        );
                                    }
                                    if !conflicts.traffic_tools.is_empty() {
                                        ui.add(
                                            egui::Label::new(crate::i18n::traffic_tool(
                                                &conflict_names(state, &conflicts.traffic_tools),
                                            ))
                                            .wrap(),
                                        );
                                    }
                                }
                                if let Some(selection) = &state.config.active
                                    && widgets::outline_button(
                                        ui,
                                        tr!("check-full"),
                                        !state.operations.helper,
                                    )
                                    .clicked()
                                {
                                    actions.push(Action::FullCheckNode(
                                        selection.subscription.clone(),
                                        selection.node.clone(),
                                    ));
                                }
                            } else {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(state.text(reason))
                                            .small()
                                            .color(theme::ERROR),
                                    )
                                    .wrap(),
                                );
                            }
                        }
                        if protection_action(status, state.operations.helper)
                            == ProtectionAction::ConfirmDisconnect
                            && widgets::outline_button(ui, tr!("turn-off-protection"), true)
                                .clicked()
                        {
                            actions.push(Action::RequestProtectionOff);
                        }
                    }
                    if server_button(ui, state) {
                        actions.push(Action::RevealServer);
                    }
                    if selection_changed.is_some() {
                        let applying = server_pending && state.operations.helper;
                        let can_apply = server_pending && state.can_apply();
                        let message = state.config.active_node().map_or_else(
                            || tr!("selection-cleared").to_owned(),
                            |(_, node)| {
                                let name = display::drop_missing_glyphs(
                                    ui.ctx(),
                                    &egui::TextStyle::Body.resolve(ui.style()),
                                    &state.text(&node.name),
                                );
                                if applying {
                                    crate::i18n::switching_to(&name)
                                } else if can_apply {
                                    crate::i18n::selected_not_applied(&name)
                                } else {
                                    crate::i18n::selected_pending(&name)
                                }
                            },
                        );
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing.x = 0.0;
                            ui.label(RichText::new(message).small().color(theme::ROSE_LIGHT));
                            if can_apply {
                                ui.label(
                                    RichText::new(tr!("apply-separator"))
                                        .small()
                                        .color(theme::ROSE_LIGHT),
                                );
                                if widgets::link(ui, &tr!("apply"), true)
                                    .on_hover_text(tr!("apply-hint"))
                                    .clicked()
                                {
                                    actions.push(Action::Apply);
                                }
                            }
                        });
                    }
                    let protocol = state.config.active_node().map_or_else(
                        || tr!("ping-pending").to_owned(),
                        |(_, node)| {
                            strings::node_details(
                                rosetun_core::node_protocol(node),
                                rosetun_core::node_tls(node),
                                rosetun_core::node_transport(node),
                            )
                        },
                    );
                    let engine = visible_status
                        .and_then(|status| status.engine)
                        .unwrap_or(state.config.settings.engine);
                    let (ip, ip_color, toggle) = exit_line(&state.exit, state.exit_revealed);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 8.0;
                        ui.add_space(2.0);
                        detail_row(ui, tr!("external-ip"), |ui| {
                            ui.spacing_mut().item_spacing.x = 0.0;
                            let row_height = ui.text_style_height(&egui::TextStyle::Body);
                            let toggle_width = toggle.as_ref().map_or(0.0, |text| {
                                ui.painter()
                                    .layout_no_wrap(
                                        text.to_owned(),
                                        egui::TextStyle::Body.resolve(ui.style()),
                                        theme::ROSE_LIGHT,
                                    )
                                    .size()
                                    .x
                                    + 12.0
                            });
                            let address_width = (ui.available_width() - toggle_width).max(0.0);
                            ui.allocate_ui_with_layout(
                                egui::vec2(address_width, row_height),
                                egui::Layout::left_to_right(egui::Align::Center),
                                |ui| {
                                    ui.set_width(address_width);
                                    ui.add(
                                        egui::Label::new(RichText::new(ip).color(ip_color))
                                            .truncate(),
                                    );
                                },
                            );
                            if let Some(toggle) = toggle {
                                ui.add_space(12.0);
                                if ui
                                    .add(
                                        egui::Label::new(
                                            RichText::new(toggle).color(theme::ROSE_LIGHT),
                                        )
                                        .sense(egui::Sense::click()),
                                    )
                                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                                    .clicked()
                                {
                                    actions.push(Action::ToggleExitReveal);
                                }
                            }
                        });
                        if visible_status.is_some_and(|status| {
                            matches!(status.state, ConnectionState::Connected)
                        }) {
                            detail_row(ui, tr!("delay"), |ui| {
                                ui.spacing_mut().item_spacing.x = 6.0;
                                let (text, color) = match state.tunnel_delay {
                                    TunnelDelay::Done(ProbeOutcome::Works { millis }) => (
                                        tr!("ping-ms", ms = millis.max(1).to_string()),
                                        theme::TEXT,
                                    ),
                                    TunnelDelay::Done(_) => {
                                        (tr!("ping-no-answer").to_owned(), theme::ERROR)
                                    }
                                    TunnelDelay::Idle | TunnelDelay::Measuring => {
                                        (tr!("ping-pending").to_owned(), theme::TEXT_DIM)
                                    }
                                };
                                let enabled = !matches!(state.tunnel_delay, TunnelDelay::Measuring);
                                let response = ui
                                    .add(egui::Label::new(RichText::new(text).color(color)).sense(
                                        if enabled {
                                            egui::Sense::click()
                                        } else {
                                            egui::Sense::hover()
                                        },
                                    ))
                                    .on_hover_text(tr!("delay-hint"));
                                let refresh = if matches!(state.tunnel_delay, TunnelDelay::Done(_))
                                {
                                    icons::icon_button_sized(ui, Icon::Refresh, enabled, 18.0)
                                        .on_hover_text(tr!("delay-hint"))
                                        .clicked()
                                } else {
                                    false
                                };
                                if response.clicked() || refresh {
                                    actions.push(Action::MeasureDelay);
                                }
                            });
                        }
                        if let Some(status) = visible_status.filter(|status| {
                            matches!(
                                status.state,
                                ConnectionState::Connected | ConnectionState::Reconnecting
                            )
                        }) {
                            detail_row(ui, tr!("traffic"), |ui| {
                                let rates = crate::i18n::traffic_rates(
                                    &crate::i18n::rate(status.traffic.down_bps),
                                    &crate::i18n::rate(status.traffic.up_bps),
                                );
                                if ui
                                    .add(
                                        egui::Label::new(rates)
                                            .truncate()
                                            .sense(egui::Sense::click()),
                                    )
                                    .on_hover_text(tr!("traffic-open-hint"))
                                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                                    .clicked()
                                {
                                    actions.push(Action::OpenTraffic);
                                }
                            });
                        }
                        detail_row(ui, tr!("protocol"), |ui| {
                            ui.add(egui::Label::new(&protocol).truncate())
                                .on_hover_text(&protocol);
                        });
                        detail_row(ui, tr!("engine"), |ui| {
                            ui.add(egui::Label::new(engine.as_str()).truncate())
                                .on_hover_text(crate::i18n::engine_detail(engine.as_str()));
                        });
                    });
                });
            });
        });
}

/// What the external IP line shows: the value, its colour and the reveal link,
/// if any. A hidden address shows neither its digits nor its length.
fn exit_line(exit: &ExitLookup, revealed: bool) -> (String, Color32, Option<String>) {
    match exit {
        ExitLookup::Known { .. } if !revealed => (
            tr!("ip-hidden").to_owned(),
            theme::TEXT_MUTED,
            Some(tr!("ip-show")),
        ),
        ExitLookup::Known { route, info } => {
            let address = info.ip.to_string();
            let address = if *route == ExitRoute::Direct {
                format!("{address} {}", tr!("ip-own"))
            } else {
                address
            };
            (address, theme::TEXT, Some(tr!("ip-hide")))
        }
        ExitLookup::Failed(_) => (tr!("ip-unknown").to_owned(), theme::TEXT_DIM, None),
        ExitLookup::None | ExitLookup::Pending(_) => {
            (tr!("ip-pending").to_owned(), theme::TEXT_DIM, None)
        }
    }
}

/// One line of the details list: a small label in a 96 px column, then the
/// value, both centred on one row height.
fn detail_row<R>(
    ui: &mut egui::Ui,
    label: impl AsRef<str>,
    value: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    let row_height = ui.text_style_height(&egui::TextStyle::Body);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 12.0;
        ui.allocate_ui_with_layout(
            egui::vec2(96.0, row_height),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.set_width(96.0);
                ui.label(RichText::new(label.as_ref()).small().color(theme::TEXT_DIM));
            },
        );
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), row_height),
            egui::Layout::left_to_right(egui::Align::Center),
            value,
        )
        .inner
    })
    .inner
}

/// The selected server as a wide button; returns true when clicked.
fn server_button(ui: &mut egui::Ui, state: &State) -> bool {
    let country = match (state.visible_status(), &state.exit) {
        (
            Some(status),
            ExitLookup::Known {
                route: ExitRoute::Tunnel,
                info,
            },
        ) if matches!(status.state, ConnectionState::Connected)
            && state
                .config
                .active
                .as_ref()
                .is_some_and(|selected| status.node.as_ref() == Some(&selected.node)) =>
        {
            info.country.as_deref()
        }
        _ => None,
    };
    let flag = state
        .config
        .active_node()
        .and_then(|(_, node)| display::leading_flag(&node.name).0);
    let width = ui.available_width();
    let response = egui::Frame::new()
        .fill(theme::INPUT)
        .stroke(egui::Stroke::new(1.0, theme::BORDER_STRONG))
        .corner_radius(theme::RADIUS)
        .inner_margin(egui::Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.set_min_width(width - 28.0);
            ui.horizontal(|ui| {
                let badge_height = 26.0;
                let name_font =
                    egui::FontId::new(17.0, egui::FontFamily::Name(theme::UI_SEMIBOLD.into()));
                let badge = country
                    .map(|code| (code, true))
                    .or_else(|| flag.as_deref().map(|code| (code, false)));
                let block_height =
                    badge_height + 2.0 + ui.text_style_height(&egui::TextStyle::Small);
                if let Some((code, verified)) = badge {
                    let (area, _) = ui
                        .allocate_exact_size(egui::vec2(36.0, block_height), egui::Sense::hover());
                    let rect =
                        egui::Rect::from_center_size(area.center(), egui::vec2(36.0, badge_height));
                    ui.painter().rect_stroke(
                        rect,
                        theme::RADIUS_INNER,
                        egui::Stroke::new(
                            1.0,
                            if verified {
                                theme::ROSE_DARK
                            } else {
                                theme::BORDER_STRONG
                            },
                        ),
                        egui::StrokeKind::Inside,
                    );
                    ui.painter().text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        code,
                        egui::FontId::monospace(13.0),
                        if verified {
                            theme::ROSE_LIGHT
                        } else {
                            theme::TEXT_MUTED
                        },
                    );
                }
                let text_width = (ui.available_width() - 100.0).max(0.0);
                ui.allocate_ui_with_layout(
                    egui::vec2(text_width, block_height),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.set_width(text_width);
                        ui.spacing_mut().item_spacing.y = 0.0;
                        ui.allocate_ui_with_layout(
                            egui::vec2(text_width, badge_height),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.set_width(text_width);
                                ui.set_min_height(badge_height);
                                let name = state.config.active_node().map_or_else(
                                    || tr!("select-server").to_owned(),
                                    |(_, node)| {
                                        display::drop_missing_glyphs(
                                            ui.ctx(),
                                            &name_font,
                                            &state.text(display::leading_flag(&node.name).1),
                                        )
                                    },
                                );
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(name)
                                            .font(name_font.clone())
                                            .color(theme::TEXT),
                                    )
                                    .truncate(),
                                );
                            },
                        );
                        ui.add_space(2.0);
                        ui.allocate_ui_with_layout(
                            egui::vec2(text_width, ui.text_style_height(&egui::TextStyle::Small)),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.set_width(text_width);
                                if let Some((subscription, node)) = state.config.active_node() {
                                    let subscription = state.text(&subscription.name);
                                    let address = state.text(&rosetun_core::node_address(node));
                                    let detail = format!("{subscription} · {address}");
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(detail).small().color(theme::TEXT_DIM),
                                        )
                                        .truncate(),
                                    );
                                }
                            },
                        );
                    },
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(tr!("server-change")).color(theme::ROSE_LIGHT));
                });
            });
        })
        .response;
    let response = ui
        .interact(
            response.rect,
            response.id.with("server_button"),
            egui::Sense::click(),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    if response.hovered() {
        ui.painter().rect_stroke(
            response.rect,
            theme::RADIUS,
            egui::Stroke::new(1.0, theme::ROSE_DARK),
            egui::StrokeKind::Inside,
        );
    }
    response.clicked()
}

fn control_cards(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.x = theme::SECTION_GAP;
        ui.columns(2, |columns| {
            let mut left = columns[0].new_child(
                egui::UiBuilder::new()
                    .max_rect(columns[0].available_rect_before_wrap())
                    .sizing_pass(),
            );
            protection_card(&mut left, state, &mut Vec::new(), 0.0);
            let left_height = left.min_rect().height();
            let mut right = columns[1].new_child(
                egui::UiBuilder::new()
                    .max_rect(columns[1].available_rect_before_wrap())
                    .sizing_pass(),
            );
            rules_card(&mut right, state, &mut Vec::new(), 0.0);
            let right_height = right.min_rect().height();
            let height = left_height.max(right_height);
            protection_card(&mut columns[0], state, actions, height);
            rules_card(&mut columns[1], state, actions, height);
        });
    });
}

fn protection_card(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>, height: f32) {
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.set_min_height((height - 34.0).max(0.0));
        ui.colored_label(theme::TEXT_DIM, tr!("protection"));
        let mut kill_switch = state.config.settings.kill_switch;
        if widgets::toggle_row(
            ui,
            tr!("kill-switch"),
            tr!("kill-switch-detail"),
            &mut kill_switch,
            state.config_ready && !state.operations.kill_switch && !state.operations.helper,
        )
        .changed()
        {
            actions.push(Action::SetKillSwitch(kill_switch));
        }
        let mut connect_on_start = state.config.interface.connect_on_start;
        if widgets::toggle_row(
            ui,
            tr!("connect-on-start"),
            tr!("connect-on-start-detail"),
            &mut connect_on_start,
            state.can_edit_settings(),
        )
        .changed()
        {
            actions.push(Action::SetConnectOnStart(connect_on_start));
        }
        if tunnel_up(state) && state.pending_reconnect(SessionPart::Protection) {
            ui.label(
                RichText::new(tr!("next-connect"))
                    .small()
                    .color(theme::ROSE_LIGHT),
            );
        }
    });
}

fn rules_card(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>, height: f32) {
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.set_min_height((height - 34.0).max(0.0));
        egui::Sides::new().shrink_left().show(
            ui,
            |ui| {
                ui.label(
                    RichText::new(tr!("rules-title"))
                        .small()
                        .color(theme::TEXT_DIM),
                );
            },
            |ui| {
                if ui
                    .add(
                        egui::Label::new(RichText::new(tr!("open-link")).color(theme::ROSE_LIGHT))
                            .sense(egui::Sense::click()),
                    )
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .clicked()
                {
                    actions.push(Action::OpenActiveRules);
                }
            },
        );
        rule_set_picker(ui, state, actions);
        if !state.temporary_rules.is_empty() {
            ui.label(
                RichText::new(crate::i18n::temporary_count(state.temporary_rules.len()))
                    .small()
                    .color(theme::TEXT_DIM),
            );
        }
        if let Some(rules) = state.config.active_rules() {
            let mut enabled = rules.rules.iter().filter(|rule| rule.enabled);
            let mut shown = 0;
            for rule in enabled.by_ref().take(2) {
                shown += 1;
                ui.horizontal(|ui| {
                    let width = (ui.available_width() - 90.0).max(0.0);
                    let value = if matches!(&rule.matcher, RuleMatcher::Template(_)) {
                        crate::rules::rule_lines(&rule.matcher).0
                    } else {
                        rosetun_core::rule_value_text(&rule.matcher)
                    };
                    ui.allocate_ui_with_layout(
                        egui::vec2(width, ui.text_style_height(&egui::TextStyle::Body)),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            ui.set_width(width);
                            ui.add(egui::Label::new(state.text(&value)).truncate());
                        },
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.colored_label(target_color(rule.target), target_label(rule.target));
                    });
                });
            }
            if shown == 0 {
                ui.add(
                    egui::Label::new(
                        RichText::new(tr!("no-rules-yet"))
                            .small()
                            .color(theme::TEXT_DIM),
                    )
                    .wrap(),
                );
            }
            let remaining = enabled.count();
            if remaining > 0 {
                ui.label(
                    RichText::new(crate::i18n::more_rules(remaining))
                        .small()
                        .color(theme::TEXT_DIM),
                );
            }
        } else {
            ui.add(
                egui::Label::new(
                    RichText::new(tr!("no-rules-yet"))
                        .small()
                        .color(theme::TEXT_DIM),
                )
                .wrap(),
            );
        }
        if tunnel_up(state) && state.pending_reconnect(SessionPart::Rules) {
            if state.can_apply() {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    ui.label(
                        RichText::new(tr!("not-applied"))
                            .small()
                            .color(theme::TEXT_DIM),
                    );
                    ui.label(
                        RichText::new(tr!("apply-separator"))
                            .small()
                            .color(theme::TEXT_DIM),
                    );
                    if widgets::link(ui, &tr!("apply"), true)
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
                        .color(theme::TEXT_DIM),
                );
            }
        }
    });
}

fn rule_set_picker(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let name = state
        .config
        .active_rules()
        .map(|rules| state.text(&rules.name))
        .unwrap_or_else(|| tr!("default-rules").to_owned());
    let font = egui::FontId::new(
        egui::TextStyle::Body.resolve(ui.style()).size,
        egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
    );
    let available = ui.available_width();
    let name_width = ui
        .painter()
        .layout_no_wrap(name.clone(), font.clone(), theme::TEXT)
        .size()
        .x;
    let text_width = name_width.min((available - 22.0).max(0.0));
    let enabled = state.can_edit_rules();
    let sense = if enabled {
        egui::Sense::click()
    } else {
        egui::Sense::hover()
    };
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(
            text_width + 22.0,
            ui.text_style_height(&egui::TextStyle::Body) + 8.0,
        ),
        sense,
    );
    if ui.is_rect_visible(rect) {
        if enabled && response.hovered() {
            ui.painter().rect_filled(
                rect.expand2(egui::vec2(6.0, 0.0)),
                theme::RADIUS_INNER,
                theme::BORDER,
            );
        }
        let color = if enabled {
            theme::TEXT
        } else {
            theme::TEXT_DIM
        };
        let galley = egui::WidgetText::from(RichText::new(name).font(font).color(color))
            .into_galley(
                ui,
                Some(egui::TextWrapMode::Truncate),
                text_width,
                egui::TextStyle::Body,
            );
        ui.painter().galley(
            egui::pos2(rect.left(), rect.center().y - galley.size().y / 2.0),
            galley,
            color,
        );
        icons::paint(
            ui.painter(),
            egui::pos2(rect.left() + text_width + 12.0, rect.center().y),
            Icon::Chevron { open: true },
            theme::TEXT_DIM,
        );
    }
    if !enabled {
        return;
    }
    let response = response.on_hover_cursor(egui::CursorIcon::PointingHand);
    widgets::menu_popup(&response).show(|ui| {
        ui.set_min_width(response.rect.width().max(180.0));
        if widgets::menu_item(
            ui,
            widgets::MenuItem {
                label: &tr!("default-rules"),
                enabled: true,
                selected: state.config.active_rule_set.is_none(),
                danger: false,
                note: None,
            },
        )
        .clicked()
        {
            if state.config.active_rule_set.is_some() {
                actions.push(Action::SelectRuleSet(None));
            }
            ui.close();
        }
        for rules in &state.config.rule_sets {
            if widgets::menu_item(
                ui,
                widgets::MenuItem {
                    label: &state.text(&rules.name),
                    enabled: true,
                    selected: state.config.active_rule_set.as_ref() == Some(&rules.id),
                    danger: false,
                    note: None,
                },
            )
            .clicked()
            {
                if state.config.active_rule_set.as_ref() != Some(&rules.id) {
                    actions.push(Action::SelectRuleSet(Some(rules.id.clone())));
                }
                ui.close();
            }
        }
    });
}

fn tunnel_up(state: &State) -> bool {
    state
        .visible_status()
        .is_some_and(|status| status.state.is_active() || status.state.is_transitional())
}

pub(crate) fn state_style(state: &ConnectionState) -> (String, Color32) {
    match state {
        ConnectionState::Disconnected => (tr!("disconnected"), theme::DISCONNECTED),
        ConnectionState::Connecting => (tr!("connecting"), theme::ROSE_BRIGHT),
        ConnectionState::Connected => (tr!("connected"), theme::CONNECTED),
        ConnectionState::Reconnecting => (tr!("reconnecting"), theme::ROSE_BRIGHT),
        ConnectionState::Failed { .. } => (tr!("failed"), theme::ERROR),
        ConnectionState::FailedProtected { .. } => (tr!("failed-protected"), theme::ERROR),
    }
}

pub(crate) fn protection_dialog(ctx: &egui::Context, state: &State, actions: &mut Vec<Action>) {
    let response = egui::Modal::new(egui::Id::new("turn_off_protection"))
        .frame(widgets::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(480.0);
            ui.heading(tr!("turn-off-protection"));
            ui.add_space(12.0);
            ui.add(
                egui::Label::new(RichText::new(tr!("protection-warning")).color(theme::ERROR))
                    .wrap(),
            );
            if let Some(error) = &state.operation_error {
                ui.add(egui::Label::new(state.text(error)).wrap());
            }
            ui.add_space(20.0);
            ui.horizontal(|ui| {
                if widgets::outline_button(ui, tr!("keep-blocked"), !state.operations.helper)
                    .clicked()
                {
                    actions.push(Action::KeepBlocked);
                }
                if widgets::button_fill(
                    ui,
                    tr!("turn-off-protection"),
                    state.helper_available && !state.operations.helper,
                )
                .clicked()
                {
                    actions.push(Action::ConfirmProtectionOff);
                }
            });
        });
    if !state.operations.helper && response.should_close() {
        actions.push(Action::KeepBlocked);
    }
}

fn conflict_names(state: &State, names: &[String]) -> String {
    let mut visible = names
        .iter()
        .take(2)
        .map(|name| {
            let safe = display::safe_text(&state.text(name));
            let short: String = safe.chars().take(48).collect();
            if safe.chars().count() > 48 {
                format!("{short}…")
            } else {
                short
            }
        })
        .collect::<Vec<_>>();
    if names.len() > 2 {
        visible.push("…".to_owned());
    }
    visible.join(", ")
}

#[cfg(test)]
mod conflict_names_tests {
    use super::*;

    #[test]
    fn limits_conflict_names_and_individual_name_lengths() {
        let state = State::default();
        assert_eq!(
            conflict_names(
                &state,
                &[
                    "Example VPN".into(),
                    "Example tunnel".into(),
                    "Third".into()
                ]
            ),
            "Example VPN, Example tunnel, …"
        );
        let long = "A".repeat(80);
        let clipped = conflict_names(&state, &[long]);
        assert_eq!(clipped.chars().count(), 49);
        assert!(clipped.ends_with('…'));
    }
}

#[cfg(test)]
mod hero_details_tests {
    use super::*;

    fn known(route: ExitRoute) -> ExitLookup {
        ExitLookup::Known {
            route,
            info: rosetun_core::ExitInfo {
                ip: "203.0.113.7".parse().unwrap(),
                country: None,
            },
        }
    }

    #[test]
    fn external_ip_line_covers_routes_and_reveal_states() {
        let cases = [
            (
                known(ExitRoute::Direct),
                false,
                tr!("ip-hidden").to_owned(),
                theme::TEXT_MUTED,
                Some(tr!("ip-show")),
            ),
            (
                known(ExitRoute::Tunnel),
                false,
                tr!("ip-hidden").to_owned(),
                theme::TEXT_MUTED,
                Some(tr!("ip-show")),
            ),
            (
                known(ExitRoute::Direct),
                true,
                format!("203.0.113.7 {}", tr!("ip-own")),
                theme::TEXT,
                Some(tr!("ip-hide")),
            ),
            (
                known(ExitRoute::Tunnel),
                true,
                "203.0.113.7".to_owned(),
                theme::TEXT,
                Some(tr!("ip-hide")),
            ),
        ];
        for (exit, revealed, value, color, toggle) in cases {
            assert_eq!(exit_line(&exit, revealed), (value, color, toggle));
        }
        let (hidden, _, _) = exit_line(&known(ExitRoute::Direct), false);
        assert!(!hidden.contains("203"));
        assert!(!hidden.contains(".7"));
    }

    #[test]
    fn external_ip_line_without_an_address_has_no_toggle() {
        for exit in [
            ExitLookup::Failed(ExitRoute::Direct),
            ExitLookup::None,
            ExitLookup::Pending(ExitRoute::Tunnel),
        ] {
            for revealed in [false, true] {
                let expected = if matches!(exit, ExitLookup::Failed(_)) {
                    tr!("ip-unknown")
                } else {
                    tr!("ip-pending")
                };
                assert_eq!(
                    exit_line(&exit, revealed),
                    (expected.to_owned(), theme::TEXT_DIM, None)
                );
            }
        }
    }
}
