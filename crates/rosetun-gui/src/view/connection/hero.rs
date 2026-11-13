use super::*;

/// Between the connect button and the state line when the window is wide.
const BUTTON_TEXT_GAP: f32 = 36.0;

fn server_check_available(kind: FailureKind) -> bool {
    kind != FailureKind::NoNetwork
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed_state(kind: Option<FailureKind>, protected: bool) -> State {
        use rosetun_config::{HwidScope, Selection, Subscription, SubscriptionId};

        let node = rosetun_config::Node {
            id: rosetun_config::NodeId::new("server"),
            name: "Server".into(),
            server: "server.example.com".into(),
            port: 443,
            outbound: Outbound::Vless(rosetun_config::VlessParams {
                uuid: "00000000-0000-0000-0000-000000000000".into(),
                flow: None,
            }),
            stream: rosetun_config::StreamSettings {
                tls: TlsMode::Reality(rosetun_config::RealityParams {
                    sni: Some("example.com".into()),
                    public_key: "test-public-key".into(),
                    short_id: None,
                    fingerprint: None,
                }),
                ..Default::default()
            },
            raw: None,
        };
        let subscription = SubscriptionId::new("provider");
        let mut state = State::default();
        state.config_ready = true;
        state.helper_available = true;
        state.failure_details_open = true;
        state.config.settings.xray = XrayUse::Off;
        state.config.active = Some(Selection {
            subscription: subscription.clone(),
            node: node.id.clone(),
        });
        state.config.subscriptions.push(Subscription {
            id: subscription,
            name: "Provider".into(),
            url: "https://example.com/subscription".into(),
            nodes: vec![node],
            auto_update: false,
            updated_at_unix: None,
            user_agent: None,
            send_hwid: true,
            hwid_scope: HwidScope::Machine,
            info: None,
            update_interval_hours: None,
            support_url: None,
            web_page_url: None,
            announce: None,
            notices: vec![],
        });
        state.status.state = if protected {
            ConnectionState::FailedProtected {
                reason: "connection failed".into(),
                failure_kind: kind,
            }
        } else {
            ConnectionState::Failed {
                reason: "connection failed".into(),
                failure_kind: kind,
            }
        };
        state
    }

    #[test]
    fn recovery_actions_keep_their_order_and_availability() {
        use FailureAction::{Check, OtherServer, ProtectionOff, XrayAuto, XrayRelease};
        for protected in [false, true] {
            for (kind, expected) in [
                (None, vec![]),
                (Some(FailureKind::NoNetwork), vec![]),
                (Some(FailureKind::ServerUnreachable), vec![Check]),
                (Some(FailureKind::XrayStartFailed), vec![Check, XrayRelease]),
                (
                    Some(FailureKind::ServerRejected),
                    vec![Check, XrayAuto, OtherServer],
                ),
            ] {
                let mut state = failed_state(kind, protected);
                let mut wanted: Vec<_> = expected.iter().map(|item| (*item, true)).collect();
                if protected {
                    wanted.push((ProtectionOff, true));
                }
                assert_eq!(available_failure_actions(&state), wanted);
                state.operations.helper = true;
                let busy: Vec<_> = expected
                    .iter()
                    .map(|item| (*item, *item == XrayRelease))
                    .collect();
                assert_eq!(available_failure_actions(&state), busy);
                state.operations.helper = false;
                state.config.active = None;
                assert!(
                    !available_failure_actions(&state)
                        .iter()
                        .any(|(item, _)| matches!(item, Check | XrayAuto | OtherServer))
                );
            }
        }
        let mut state = failed_state(Some(FailureKind::ServerRejected), true);
        state.status.xray_use = Some(XrayUse::Auto);
        assert_eq!(
            available_failure_actions(&state),
            vec![(Check, true), (ProtectionOff, true)]
        );
    }

    fn text_rect(texts: &crate::test_ui::Texts, label: &str) -> egui::Rect {
        texts
            .iter()
            .find(|(text, _)| text == label)
            .unwrap_or_else(|| panic!("missing {label:?}"))
            .1
    }

    #[test]
    fn failure_details_and_actions_share_rows_in_both_languages() {
        for language in [i18n::Language::English, i18n::Language::Russian] {
            i18n::in_language(language, || {
                for size in [egui::vec2(960.0, 640.0), egui::vec2(1200.0, 900.0)] {
                    for kind in [
                        None,
                        Some(FailureKind::ServerUnreachable),
                        Some(FailureKind::XrayStartFailed),
                        Some(FailureKind::ServerRejected),
                    ] {
                        let state = failed_state(kind, true);
                        let mut screen = crate::test_ui::TestScreen::new(size);
                        let mut actions = Vec::new();
                        let texts = screen.settle(|ui| {
                            egui::CentralPanel::default()
                                .show(ui, |ui| hero_card(ui, &state, &mut actions));
                        });
                        let hide = text_rect(&texts, &tr!("hide-details"));
                        let copy = text_rect(&texts, &tr!("copy"));
                        assert!((hide.center().y - copy.center().y).abs() < 1.0);
                        assert!(copy.left() > hide.right());
                        let items = available_failure_actions(&state);
                        let rects: Vec<_> = items
                            .iter()
                            .map(|(item, _)| text_rect(&texts, &item.label()))
                            .collect();
                        for pair in rects.windows(2) {
                            assert!(pair[1].center().y >= pair[0].center().y);
                            if (pair[1].center().y - pair[0].center().y).abs() < 1.0 {
                                assert!(pair[1].left() > pair[0].right());
                            }
                        }
                        if kind == Some(FailureKind::ServerUnreachable) {
                            assert!((rects[0].center().y - rects[1].center().y).abs() < 1.0);
                        }
                        assert!(rects[0].top() > copy.bottom());
                    }
                }
            });
        }
    }

    #[test]
    fn recovery_buttons_wrap_only_when_the_row_runs_out_of_room() {
        for language in [i18n::Language::English, i18n::Language::Russian] {
            i18n::in_language(language, || {
                let state = failed_state(Some(FailureKind::XrayStartFailed), true);
                for width in [280.0, 1000.0] {
                    let mut screen = crate::test_ui::TestScreen::new(egui::vec2(width, 640.0));
                    let texts = screen.settle(|ui| {
                        egui::CentralPanel::default()
                            .show(ui, |ui| failure_actions(ui, &state, &mut Vec::new()));
                    });
                    let check = text_rect(&texts, &tr!("check-full"));
                    let release = text_rect(&texts, &tr!("xray-open-release"));
                    let protection = text_rect(&texts, &tr!("turn-off-protection"));
                    if width > 900.0 {
                        assert!((check.center().y - release.center().y).abs() < 1.0);
                        assert!((check.center().y - protection.center().y).abs() < 1.0);
                    } else {
                        assert!(protection.center().y > check.center().y);
                    }
                }
            });
        }
    }

    #[test]
    fn copied_details_show_feedback_then_restore_the_copy_link() {
        let state = failed_state(Some(FailureKind::ServerUnreachable), true);
        let mut screen = crate::test_ui::TestScreen::new(egui::vec2(960.0, 640.0));
        let mut actions = Vec::new();
        let mut show = |ui: &mut egui::Ui| {
            egui::CentralPanel::default().show(ui, |ui| failure_details(ui, &state, &mut actions));
        };
        let copied = screen.click_text(&tr!("copy"), &mut show);
        text_rect(&copied, &tr!("copied"));
        screen.settle(&mut show);
        let expired = screen.settle(&mut show);
        text_rect(&expired, &tr!("copy"));
    }

    #[test]
    fn hero_title_tells_an_unavailable_service_from_one_not_answered_yet() {
        let mut state = State::default();
        assert_eq!(hero_title(&state), (tr!("checking"), theme::DISCONNECTED));
        state.helper_error = Some(rosetun_ipc::ClientError::Closed);
        assert_eq!(
            hero_title(&state),
            (tr!("connection-unavailable"), theme::ERROR)
        );
        state.helper_available = true;
        state.helper_error = None;
        assert_eq!(hero_title(&state), state_style(&state.status.state));
    }

    #[test]
    fn missing_network_does_not_offer_a_server_check() {
        assert!(!server_check_available(FailureKind::NoNetwork));
        assert!(server_check_available(FailureKind::ServerUnreachable));
    }

    fn engine_row(xray: bool, fragmented: bool, requested: bool, xray_use: XrayUse) -> Vec<String> {
        let mut state = State::default();
        state.config_ready = true;
        state.helper_available = true;
        state.status = rosetun_config::Status {
            state: ConnectionState::Connected,
            xray,
            xray_use: Some(xray_use),
            fragmented,
            fragment_requested: requested,
            ..rosetun_config::Status::default()
        };
        let mut actions = Vec::new();
        let mut screen = crate::test_ui::TestScreen::new(egui::vec2(1200.0, 900.0));
        screen
            .settle(|ui| {
                egui::CentralPanel::default().show(ui, |ui| hero_card(ui, &state, &mut actions));
            })
            .into_iter()
            .map(|(text, _)| text)
            .collect()
    }

    #[test]
    fn the_engine_row_tells_applied_and_unapplied_fragmentation_in_both_languages() {
        use crate::i18n::{self, Language};
        for language in [Language::English, Language::Russian] {
            i18n::in_language(language, || {
                let applied = engine_row(true, true, true, XrayUse::Auto);
                assert!(applied.contains(&tr!("fragment-engine-active")));
                assert!(!applied.contains(&tr!("fragment-engine-none")));

                let unsupported = engine_row(false, false, true, XrayUse::Auto);
                assert!(unsupported.contains(&tr!("fragment-engine-none")));
                assert!(!unsupported.contains(&tr!("fragment-engine-active")));

                let off = engine_row(false, false, false, XrayUse::Auto);
                assert!(!off.contains(&tr!("fragment-engine-none")));
                assert!(!off.contains(&tr!("fragment-engine-active")));

                let plain = engine_row(true, false, false, XrayUse::Auto);
                assert!(plain.contains(&tr!("xray-engine")));
            });
        }
    }
}

/// Without a status the service either has not answered yet (start-up) or
/// is unreachable; only the second is an error.
fn hero_title(state: &State) -> (String, Color32) {
    let Some(status) = state.visible_status() else {
        return if state.helper_error.is_some() {
            (tr!("connection-unavailable"), theme::ERROR)
        } else {
            (tr!("checking"), theme::DISCONNECTED)
        };
    };
    if matches!(status.state, ConnectionState::Reconnecting)
        && status.reconnect_failure_kind == Some(FailureKind::NoNetwork)
    {
        (tr!("error-code-no-network"), theme::ERROR)
    } else if status.xray_stopped && matches!(status.state, ConnectionState::Reconnecting) {
        (tr!("xray-reconnecting-title"), theme::ERROR)
    } else {
        state_style(&status.state)
    }
}

pub(super) fn hero_card(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let narrow = ui.available_width() < 560.0;
    widgets::card_frame()
        .inner_margin(theme::margin::symmetric(
            if narrow {
                theme::space::M
            } else {
                theme::space::XXL
            },
            theme::space::L,
        ))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            let visible_status = state.visible_status();
            let (label, color) = hero_title(state);
            let server_pending = state.pending_reconnect(SessionPart::Server);
            let selection_changed =
                visible_status.filter(|status| {
                    (status.state.is_active() || status.state.is_transitional())
                        && (server_pending
                            || state.config.active.as_ref().is_none_or(|selection| {
                                status.node.as_ref() != Some(&selection.node)
                            }))
                });
            ui.with_layout(
                if narrow {
                    egui::Layout::top_down(egui::Align::Center)
                } else {
                    egui::Layout::left_to_right(egui::Align::Min)
                },
                |ui| {
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
                                motion::continuous_frames(
                                    motion::WindowView::of(ui.ctx(), state.window_hidden()),
                                    state.config.interface.reduce_motion,
                                ),
                            ) {
                                actions.push(Action::Primary);
                            }
                        },
                    );
                    ui.add_space(if narrow {
                        theme::space::M
                    } else {
                        BUTTON_TEXT_GAP
                    });
                    ui.vertical(|ui| {
                        ui.set_min_width(ui.available_width());
                        ui.spacing_mut().item_spacing.y = theme::space::L;
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = theme::space::XS;
                            ui.label(
                                RichText::new(label)
                                    .size(theme::font::STATE_LINE)
                                    .color(color),
                            );
                            let session = visible_status
                                .and_then(|status| status.since_unix)
                                .map_or_else(
                                    || tr!("no-session").to_owned(),
                                    |since| display::session_text(Some(since), display::now_unix()),
                                );
                            ui.colored_label(
                                theme::palette().text_muted,
                                i18n::plain_link(&tr!("session"), &session),
                            );
                        });
                        if state.xhttp_without_xray() {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(tr!("xhttp-needs-xray")).color(theme::ERROR),
                                )
                                .wrap(),
                            );
                            if widgets::button_fill(
                                ui,
                                tr!("xhttp-connect-through-xray"),
                                state.can_edit_settings()
                                    && state.helper_available
                                    && !state.operations.helper,
                            )
                            .clicked()
                            {
                                actions.push(Action::EnableXrayAutoAndConnect);
                            }
                        }
                        if let Some(status) = visible_status {
                            if matches!(status.state, ConnectionState::Reconnecting)
                                && status.reconnect_failure_kind == Some(FailureKind::NoNetwork)
                            {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(tr!("no-network-waiting-hint"))
                                            .small()
                                            .color(theme::palette().text_muted),
                                    )
                                    .wrap(),
                                );
                                if state.running_session_protected() {
                                    ui.colored_label(theme::ERROR, tr!("no-network-protected"));
                                }
                            } else if status.xray_stopped
                                && matches!(status.state, ConnectionState::Reconnecting)
                            {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(tr!("xray-reconnecting-detail"))
                                            .small()
                                            .color(theme::palette().text_muted),
                                    )
                                    .wrap(),
                                );
                            }
                            if status.state.is_transitional() {
                                if let Some(stage) = state.stage_line(display::now_unix()) {
                                    ui.label(
                                        RichText::new(stage.text)
                                            .small()
                                            .color(theme::palette().text_muted),
                                    );
                                    if let Some(hint) = stage.hint {
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(hint)
                                                    .small()
                                                    .color(theme::palette().text_muted),
                                            )
                                            .wrap(),
                                        );
                                    }
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
                            if let ConnectionState::Failed { failure_kind, .. }
                            | ConnectionState::FailedProtected { failure_kind, .. } =
                                &status.state
                            {
                                ui.vertical(|ui| {
                                    ui.spacing_mut().item_spacing.y = theme::space::M;
                                    if let Some(kind) = failure_kind {
                                        let (title, hint) = crate::i18n::connection_failure(
                                            *kind,
                                            state.config.active_node().map(|(_, node)| node),
                                            status.xray_use.unwrap_or(state.config.settings.xray),
                                            state.lockdown_active(),
                                        );
                                        let response = ui.colored_label(theme::ERROR, title);
                                        if let Some(details) = state.failure_details() {
                                            response.on_hover_text(details);
                                        }
                                        if *kind == FailureKind::NoNetwork
                                            && matches!(
                                                status.state,
                                                ConnectionState::FailedProtected { .. }
                                            )
                                        {
                                            ui.colored_label(
                                                theme::ERROR,
                                                tr!("no-network-protected"),
                                            );
                                        }
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(hint)
                                                    .small()
                                                    .color(theme::palette().text_muted),
                                            )
                                            .wrap(),
                                        );
                                        failure_details(ui, state, actions);
                                        if let Some(conflicts) = &state.failure_interference {
                                            if !conflicts.other_vpns.is_empty() {
                                                ui.add(
                                                    egui::Label::new(crate::i18n::other_vpn(
                                                        &conflict_names(
                                                            state,
                                                            &conflicts.other_vpns,
                                                        ),
                                                    ))
                                                    .wrap(),
                                                );
                                            }
                                            if !conflicts.traffic_tools.is_empty() {
                                                ui.add(
                                                    egui::Label::new(crate::i18n::traffic_tool(
                                                        &conflict_names(
                                                            state,
                                                            &conflicts.traffic_tools,
                                                        ),
                                                    ))
                                                    .wrap(),
                                                );
                                            }
                                        }
                                    } else {
                                        let text = if state.tunnel_held_by_windows() {
                                            tr!("error-tunnel-held-by-windows")
                                        } else {
                                            state.failure_details().unwrap_or_default()
                                        };
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(text).small().color(theme::ERROR),
                                            )
                                            .wrap(),
                                        );
                                        failure_details(ui, state, actions);
                                    }
                                    if let Some(warning) = &state.system_checks.failure_warning {
                                        ui.horizontal_wrapped(|ui| {
                                            ui.colored_label(
                                                theme::WARNING,
                                                tr!(
                                                    "system-check-found",
                                                    issue = i18n::check_issue(warning)
                                                ),
                                            );
                                            if ui.link(tr!("system-check-more")).clicked() {
                                                actions.push(Action::ShowSystemChecks);
                                            }
                                        });
                                    }
                                    if state.dns_hint_for_failure() {
                                        crate::view::settings::dns_hint(ui, actions);
                                    }
                                    failure_actions(ui, state, actions);
                                });
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
                                ui.label(
                                    RichText::new(message)
                                        .small()
                                        .color(theme::palette().accent_light),
                                );
                                if can_apply {
                                    ui.label(
                                        RichText::new(tr!("apply-separator"))
                                            .small()
                                            .color(theme::palette().accent_light),
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
                                i18n::node_details(
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
                            ui.spacing_mut().item_spacing.y = theme::space::S;
                            ui.add_space(theme::space::XXS);
                            detail_row(ui, tr!("external-ip"), |ui| {
                                ui.spacing_mut().item_spacing.x = 0.0;
                                let row_height = ui.text_style_height(&egui::TextStyle::Body);
                                let toggle_width = toggle.as_ref().map_or(0.0, |text| {
                                    ui.painter()
                                        .layout_no_wrap(
                                            text.to_owned(),
                                            egui::TextStyle::Body.resolve(ui.style()),
                                            theme::palette().accent_light,
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
                                    ui.add_space(theme::space::M);
                                    if ui
                                        .add(
                                            egui::Label::new(
                                                RichText::new(toggle)
                                                    .color(theme::palette().accent_light),
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
                                    ui.spacing_mut().item_spacing.x = theme::space::XS;
                                    let (text, color) = match state.tunnel_delay.proxy() {
                                        Some(ProbeOutcome::Works { millis }) => (
                                            tr!("ping-ms", ms = millis.max(1).to_string()),
                                            theme::palette().text,
                                        ),
                                        Some(_) => (tr!("ping-no-answer").to_owned(), theme::ERROR),
                                        None => (
                                            tr!("ping-pending").to_owned(),
                                            theme::palette().text_dim,
                                        ),
                                    };
                                    let enabled =
                                        !matches!(state.tunnel_delay, TunnelDelay::Measuring);
                                    let response = ui
                                        .add(
                                            egui::Label::new(RichText::new(text).color(color))
                                                .sense(if enabled {
                                                    egui::Sense::click()
                                                } else {
                                                    egui::Sense::hover()
                                                }),
                                        )
                                        .on_hover_text(tr!("delay-hint"));
                                    let refresh =
                                        if matches!(state.tunnel_delay, TunnelDelay::Done(_)) {
                                            icons::icon_button_sized(
                                                ui,
                                                Icon::Refresh,
                                                enabled,
                                                18.0,
                                            )
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
                                if visible_status.is_some_and(|status| status.xray) {
                                    ui.vertical(|ui| {
                                        if visible_status.is_some_and(|status| status.fragmented) {
                                            ui.label(tr!("fragment-engine-active"));
                                        } else {
                                            ui.label(tr!("xray-engine"));
                                        }
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(tr!("xray-engine-detail"))
                                                    .small()
                                                    .color(theme::palette().text_dim),
                                            )
                                            .wrap(),
                                        );
                                        if let Some(status) = visible_status {
                                            unfragmented_note(ui, status);
                                        }
                                    });
                                } else {
                                    ui.vertical(|ui| {
                                        ui.add(egui::Label::new(engine.as_str()).truncate())
                                            .on_hover_text(crate::i18n::engine_detail(
                                                engine.as_str(),
                                            ));
                                        if let Some(status) = visible_status {
                                            unfragmented_note(ui, status);
                                        }
                                    });
                                }
                            });
                        });
                    });
                },
            );
        });
}

const COPIED_FOR: f64 = 2.0;

/// Fragmentation was on when this session started but the server's connection is not split.
fn unfragmented_note(ui: &mut egui::Ui, status: &rosetun_config::Status) {
    if !status.fragment_requested || status.fragmented {
        return;
    }
    let hint = if status.xray_use == Some(XrayUse::Off) {
        tr!("fragment-none-xray-hint")
    } else {
        tr!("fragment-none-hint")
    };
    ui.add(
        egui::Label::new(
            RichText::new(tr!("fragment-engine-none"))
                .small()
                .color(theme::palette().text_dim),
        )
        .sense(egui::Sense::hover()),
    )
    .on_hover_text(hint);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailureAction {
    Check,
    XrayRelease,
    XrayAuto,
    OtherServer,
    ProtectionOff,
}

impl FailureAction {
    fn label(self) -> String {
        match self {
            Self::Check => tr!("check-full"),
            Self::XrayRelease => tr!("xray-open-release"),
            Self::XrayAuto => tr!("xray-auto-connect"),
            Self::OtherServer => tr!("xray-other-server"),
            Self::ProtectionOff => tr!("turn-off-protection"),
        }
    }
}

fn available_failure_actions(state: &State) -> Vec<(FailureAction, bool)> {
    let Some(status) = state.visible_status() else {
        return Vec::new();
    };
    let mut items = Vec::new();
    if let ConnectionState::Failed {
        failure_kind: Some(kind),
        ..
    }
    | ConnectionState::FailedProtected {
        failure_kind: Some(kind),
        ..
    } = &status.state
    {
        if server_check_available(*kind) && state.config.active.is_some() {
            items.push((FailureAction::Check, !state.operations.helper));
        }
        if *kind == FailureKind::XrayStartFailed {
            items.push((FailureAction::XrayRelease, true));
        }
        let reality_off = *kind == FailureKind::ServerRejected
            && status.xray_use.unwrap_or(state.config.settings.xray) == XrayUse::Off
            && state.config.active_node().is_some_and(|(_, node)| {
                matches!(&node.outbound, Outbound::Vless(_))
                    && matches!(&node.stream.tls, TlsMode::Reality(_))
            });
        if reality_off {
            items.push((
                FailureAction::XrayAuto,
                state.can_edit_settings() && !state.operations.helper,
            ));
            items.push((FailureAction::OtherServer, !state.operations.helper));
        }
    }
    if protection_action(status, state.operations.helper) == ProtectionAction::ConfirmDisconnect {
        items.push((FailureAction::ProtectionOff, true));
    }
    items
}

fn failure_actions(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let items = available_failure_actions(state);
    if items.is_empty() {
        return;
    }
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = egui::vec2(theme::space::S, theme::space::S);
        for (item, enabled) in items {
            let response = if item == FailureAction::XrayAuto {
                widgets::button_fill(ui, item.label(), enabled)
            } else {
                widgets::outline_button(ui, item.label(), enabled)
            };
            if response.clicked() {
                match item {
                    FailureAction::Check => {
                        if let Some(selection) = &state.config.active {
                            actions.push(Action::FullCheckNode(
                                selection.subscription.clone(),
                                selection.node.clone(),
                            ));
                        }
                    }
                    FailureAction::XrayRelease => {
                        display::open_web_link(
                            ui.ctx(),
                            "https://github.com/eoftgge/rosetun/releases",
                        );
                    }
                    FailureAction::XrayAuto => actions.push(Action::EnableXrayAutoAndConnect),
                    FailureAction::OtherServer => actions.push(Action::RevealServer),
                    FailureAction::ProtectionOff => actions.push(Action::RequestProtectionOff),
                }
            }
        }
    });
}

fn failure_details(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let Some(details) = state.failure_details() else {
        return;
    };
    let open = state.failure_details_open;
    ui.horizontal(|ui| {
        if ui
            .link(if open {
                tr!("hide-details")
            } else {
                tr!("details")
            })
            .clicked()
        {
            actions.push(Action::ToggleFailureDetails);
        }
        if open {
            let id = egui::Id::unique("failure_details_copied");
            let now = ui.input(|input| input.time);
            let copied = ui
                .data(|data| data.get_temp::<f64>(id))
                .is_some_and(|at| now - at < COPIED_FOR);
            if ui
                .link(if copied { tr!("copied") } else { tr!("copy") })
                .clicked()
            {
                ui.ctx().copy_text(details.clone());
                ui.data_mut(|data| data.insert_temp(id, now));
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_secs_f64(COPIED_FOR));
            }
        }
    });
    if !open {
        return;
    }
    ui.add(
        egui::Label::new(
            RichText::new(&details)
                .small()
                .color(theme::palette().text_muted),
        )
        .selectable(true)
        .wrap(),
    );
}

/// What the external IP line shows: the value, its colour and the reveal link,
/// if any. A hidden address shows neither its digits nor its length.
fn exit_line(exit: &ExitLookup, revealed: bool) -> (String, Color32, Option<String>) {
    match exit {
        ExitLookup::Known { .. } if !revealed => (
            tr!("ip-hidden").to_owned(),
            theme::palette().text_muted,
            Some(tr!("ip-show")),
        ),
        ExitLookup::Known { route, info } => {
            let address = info.ip.to_string();
            let address = if *route == ExitRoute::Direct {
                format!("{address} {}", tr!("ip-own"))
            } else {
                address
            };
            (address, theme::palette().text, Some(tr!("ip-hide")))
        }
        ExitLookup::Failed(_) => (
            tr!("ip-unknown").to_owned(),
            theme::palette().text_dim,
            None,
        ),
        ExitLookup::None | ExitLookup::Pending(_) => (
            tr!("ip-pending").to_owned(),
            theme::palette().text_dim,
            None,
        ),
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
        ui.spacing_mut().item_spacing.x = theme::space::M;
        ui.allocate_ui_with_layout(
            egui::vec2(96.0, row_height),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.set_width(96.0);
                ui.label(
                    RichText::new(label.as_ref())
                        .small()
                        .color(theme::palette().text_dim),
                );
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
        .fill(theme::palette().input)
        .stroke(egui::Stroke::new(
            theme::stroke::HAIRLINE,
            theme::palette().border_strong,
        ))
        .corner_radius(theme::RADIUS)
        .inner_margin(theme::margin::same(theme::space::M))
        .show(ui, |ui| {
            ui.set_min_width(width - 2.0 * theme::space::M);
            ui.horizontal(|ui| {
                let badge_height = 26.0;
                let name_font = theme::font::title();
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
                            theme::stroke::HAIRLINE,
                            if verified {
                                theme::palette().accent_dark
                            } else {
                                theme::palette().border_strong
                            },
                        ),
                        egui::StrokeKind::Inside,
                    );
                    ui.painter().text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        code,
                        theme::font::mono_small(),
                        if verified {
                            theme::palette().accent_light
                        } else {
                            theme::palette().text_muted
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
                                            .color(theme::palette().text),
                                    )
                                    .truncate(),
                                );
                            },
                        );
                        ui.add_space(theme::space::XXS);
                        ui.allocate_ui_with_layout(
                            egui::vec2(text_width, ui.text_style_height(&egui::TextStyle::Small)),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.set_width(text_width);
                                // No node address here: this screen ends up in screenshots.
                                if let Some((subscription, _)) = state.config.active_node() {
                                    let detail = state.text(&subscription.name);
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(detail)
                                                .small()
                                                .color(theme::palette().text_dim),
                                        )
                                        .truncate(),
                                    );
                                }
                            },
                        );
                    },
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(tr!("server-change")).color(theme::palette().accent_light),
                    );
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
            egui::Stroke::new(theme::stroke::HAIRLINE, theme::palette().accent_dark),
            egui::StrokeKind::Inside,
        );
    }
    response.clicked()
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
                theme::palette().text_muted,
                Some(tr!("ip-show")),
            ),
            (
                known(ExitRoute::Tunnel),
                false,
                tr!("ip-hidden").to_owned(),
                theme::palette().text_muted,
                Some(tr!("ip-show")),
            ),
            (
                known(ExitRoute::Direct),
                true,
                format!("203.0.113.7 {}", tr!("ip-own")),
                theme::palette().text,
                Some(tr!("ip-hide")),
            ),
            (
                known(ExitRoute::Tunnel),
                true,
                "203.0.113.7".to_owned(),
                theme::palette().text,
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
                    (expected.to_owned(), theme::palette().text_dim, None)
                );
            }
        }
    }
}
