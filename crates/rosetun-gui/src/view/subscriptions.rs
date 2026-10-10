use std::time::Duration;

use eframe::egui::{self, Color32, RichText, Stroke};
use rosetun_config::{
    ConnectionState, Node, NodeId, Outbound, Subscription, SubscriptionId, SubscriptionInfo,
};

use crate::errors;
use crate::icons::{self, Icon};
use crate::reorder::drop_target;
use crate::state::{Action, PingResult, State, UpdateOutcome, shared_auto_update_hours};
use crate::{constants, display, i18n, theme, widgets};

pub(crate) fn show(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    const FOOTER_HEIGHT: f32 = 92.0;

    ui.style_mut().interaction.selectable_labels = false;
    egui::Panel::bottom("subscriptions_footer")
        .exact_size(FOOTER_HEIGHT)
        .frame(egui::Frame::new())
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            ui.add_space(24.0);
            let (update_all, add) = egui::Sides::new()
                .height(36.0)
                .shrink_left()
                .truncate()
                .show(
                    ui,
                    |ui| {
                        let enabled = state.config_ready
                            && !state.config.subscriptions.is_empty()
                            && !state.operations.update_all
                            && state.operations.updating.is_empty()
                            && !state.operations.removing;
                        widgets::outline_button(
                            ui,
                            if state.operations.update_all {
                                tr!("updating")
                            } else {
                                tr!("update-all")
                            },
                            enabled,
                        )
                        .clicked()
                    },
                    |ui| {
                        widgets::button_fill(
                            ui,
                            tr!("add-short"),
                            state.subscriptions.add.is_none(),
                        )
                        .clicked()
                    },
                );
            if update_all {
                actions.push(Action::UpdateAll);
            }
            if add {
                actions.push(Action::OpenAdd);
            }
            ui.add_space(6.0);
            let width = ui.available_width();
            ui.allocate_ui_with_layout(
                egui::vec2(width, 18.0),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    if state.config.interface.auto_update_subscriptions
                        && !state.config.subscriptions.is_empty()
                    {
                        let text = shared_auto_update_hours(&state.config.subscriptions)
                            .map(|hours| tr!("auto-update-every", hours = hours.to_string()))
                            .unwrap_or_else(|| tr!("auto-update-on"));
                        ui.add(
                            egui::Label::new(RichText::new(text).small().color(theme::TEXT_DIM))
                                .truncate(),
                        );
                    }
                },
            );
        });
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        ui.label(
            RichText::new(tr!("subscriptions-title"))
                .color(theme::TEXT)
                .font(egui::FontId::new(
                    15.0,
                    egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
                )),
        );
        ui.label(
            RichText::new(format!("· {}", state.config.subscriptions.len())).color(theme::TEXT_DIM),
        );
    });
    ui.add_space(12.0);
    egui::ScrollArea::vertical()
        .id_salt("subscription_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if state.config.subscriptions.is_empty() {
                ui.colored_label(theme::TEXT_MUTED, tr!("no-subscriptions"));
                ui.add_space(8.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(tr!("empty-subscriptions")).color(theme::TEXT_DIM),
                    )
                    .wrap(),
                );
            }
            ui.scope(|ui| {
                let item_spacing = ui.spacing().item_spacing.y;
                ui.spacing_mut().item_spacing.y = 0.0;
                for (index, subscription) in state.config.subscriptions.iter().enumerate() {
                    ui.push_id(subscription.id.as_str(), |ui| {
                        let response = egui::Frame::new()
                            .inner_margin(egui::Margin::symmetric(0, 4))
                            .show(ui, |ui| {
                                ui.spacing_mut().item_spacing.y = item_spacing;
                                subscription_card(ui, state, subscription, actions)
                            });
                        if state.can_reorder_subscriptions()
                            && let Some(dragged_id) =
                                response.response.dnd_hover_payload::<SubscriptionId>()
                            && let Some(from) = state
                                .config
                                .subscriptions
                                .iter()
                                .position(|item| item.id == *dragged_id)
                            && let Some(pointer) = ui.ctx().pointer_hover_pos()
                        {
                            let above = pointer.y < response.inner.rect.center().y;
                            let slot = index + usize::from(!above);
                            if drop_target(from, slot, state.config.subscriptions.len()).is_some() {
                                let rect = response.response.rect;
                                let y = if above { rect.top() } else { rect.bottom() };
                                ui.painter().line_segment(
                                    [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
                                    Stroke::new(2.0, theme::ROSE),
                                );
                                if let Some(payload) =
                                    response.response.dnd_release_payload::<SubscriptionId>()
                                {
                                    actions
                                        .push(Action::DropSubscription((*payload).clone(), slot));
                                }
                            }
                        }
                    });
                }
            });
        });
}

fn subscription_card(
    ui: &mut egui::Ui,
    state: &State,
    subscription: &Subscription,
    actions: &mut Vec<Action>,
) -> egui::Response {
    let reorder = state.can_reorder_subscriptions();
    let dragged = reorder
        && egui::DragAndDrop::payload::<SubscriptionId>(ui.ctx())
            .is_some_and(|id| *id == subscription.id);
    let expanded = state.subscriptions.expanded.contains(&subscription.id);
    let selected = state
        .config
        .active
        .as_ref()
        .is_some_and(|selection| selection.subscription == subscription.id);
    let now = display::now_unix();
    let updated = subscription
        .updated_at_unix
        .map(|timestamp| crate::i18n::last_updated(&crate::i18n::updated_ago(timestamp, now)))
        .unwrap_or_else(|| tr!("never-updated").to_owned());
    let mut frame = widgets::card_frame()
        .inner_margin(12)
        .stroke(Stroke::new(1.0, theme::BORDER));
    if dragged {
        frame = frame.fill(Color32::from_rgba_unmultiplied(
            theme::CARD.r(),
            theme::CARD.g(),
            theme::CARD.b(),
            128,
        ));
    }
    ui.scope_builder(
        egui::UiBuilder::new()
            .id_salt("card")
            .sense(egui::Sense::hover()),
        |ui| {
            let response = frame.show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                if dragged {
                    ui.multiply_opacity(0.5);
                }
                let header_rect = egui::Rect::from_min_size(
                    ui.next_widget_position(),
                    egui::vec2(ui.available_width(), 28.0),
                );
                if reorder {
                    ui.interact(
                        header_rect,
                        ui.id().with("header_drag"),
                        egui::Sense::drag(),
                    )
                    .dnd_set_drag_payload(subscription.id.clone());
                }
                ui.horizontal(|ui| {
                    if icons::icon_button(ui, Icon::Chevron { open: expanded }, true)
                        .on_hover_text(if expanded {
                            constants::COLLAPSE
                        } else {
                            constants::EXPAND
                        })
                        .clicked()
                    {
                        actions.push(Action::ToggleExpanded(subscription.id.clone()));
                    }
                    let name_width =
                        (ui.available_width() - 2.0 * 28.0 - 2.0 * ui.spacing().item_spacing.x)
                            .max(0.0);
                    let name = provider_text(ui, state, &subscription.name, egui::TextStyle::Body);
                    ui.allocate_ui_with_layout(
                        egui::vec2(name_width, 22.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            ui.set_width(name_width);
                            if ui
                                .add(
                                    egui::Label::new(RichText::new(&name).color(theme::TEXT).font(
                                        egui::FontId::new(
                                            egui::TextStyle::Body.resolve(ui.style()).size,
                                            egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
                                        ),
                                    ))
                                    .truncate()
                                    .sense(egui::Sense::click()),
                                )
                                .on_hover_text(name)
                                .clicked()
                            {
                                actions.push(Action::ToggleExpanded(subscription.id.clone()));
                            }
                        },
                    );
                    if state.operations.update_all
                        || state.operations.updating.contains(&subscription.id)
                    {
                        ui.allocate_ui_with_layout(
                            egui::vec2(28.0, 28.0),
                            egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                            |ui| {
                                ui.add(egui::Spinner::new().size(18.0));
                            },
                        )
                        .response
                        .on_hover_text(format!("{}\n{updated}", tr!("updating")));
                    } else if icons::icon_button_sized(
                        ui,
                        Icon::Refresh,
                        !state.subscription_busy(&subscription.id),
                        28.0,
                    )
                    .on_hover_text(format!("{}\n{updated}", tr!("update")))
                    .clicked()
                    {
                        actions.push(Action::Update(subscription.id.clone()));
                    }
                    let menu = icons::icon_button_sized(ui, Icon::More, true, 28.0)
                        .on_hover_text(tr!("more-actions"));
                    widgets::menu_popup(&menu).show(|ui| {
                        ui.set_width(180.0);
                        ui.add(
                            egui::Label::new(
                                RichText::new(display::safe_text(
                                    &rosetun_core::redacted_subscription_url(&subscription.url),
                                ))
                                .small()
                                .color(theme::TEXT_DIM),
                            )
                            .wrap(),
                        );
                        ui.separator();
                        if widgets::menu_item(
                            ui,
                            widgets::MenuItem {
                                label: &tr!("rename"),
                                enabled: state.config_ready
                                    && !state.operations.renaming
                                    && state.subscriptions.rename.is_none()
                                    && state.subscriptions.remove.is_none(),
                                selected: false,
                                danger: false,
                                note: None,
                            },
                        )
                        .clicked()
                        {
                            actions.push(Action::RequestRename(subscription.id.clone()));
                            ui.close();
                        }
                        if widgets::menu_item(
                            ui,
                            widgets::MenuItem {
                                label: &tr!("remove"),
                                enabled: !state.subscription_busy(&subscription.id)
                                    && !state.operations.removing,
                                selected: false,
                                danger: true,
                                note: None,
                            },
                        )
                        .clicked()
                        {
                            actions.push(Action::RequestRemove(subscription.id.clone()));
                            ui.close();
                        }
                    });
                });
                ui.horizontal(|ui| {
                    ui.add_space(22.0 + ui.spacing().item_spacing.x);
                    egui::Sides::new().shrink_left().show(
                        ui,
                        |ui| {
                            let muted = egui::TextFormat {
                                font_id: egui::TextStyle::Small.resolve(ui.style()),
                                color: theme::TEXT_DIM,
                                ..Default::default()
                            };
                            let mut summary = egui::text::LayoutJob::default();
                            summary.append(
                                &crate::i18n::servers(subscription.nodes.len()),
                                0.0,
                                muted.clone(),
                            );
                            if let Some(expire) =
                                subscription.info.as_ref().and_then(|info| info.expire_unix)
                            {
                                summary.append(" · ", 0.0, muted.clone());
                                let (term, _) = crate::i18n::term_left(expire, now);
                                summary.append(
                                    &term,
                                    0.0,
                                    egui::TextFormat {
                                        color: expiry_color(expire, now),
                                        ..muted
                                    },
                                );
                            }
                            ui.add(egui::Label::new(summary).truncate());
                        },
                        |ui| {
                            if !expanded && let Some(best) = state.best_ping(subscription) {
                                ui.label(
                                    RichText::new(tr!(
                                        "ping-best",
                                        ms = ping_millis(best).to_string()
                                    ))
                                    .small()
                                    .color(theme::TEXT_DIM),
                                );
                            }
                        },
                    );
                });
                if let Some(UpdateOutcome::Error(error)) =
                    state.subscriptions.outcomes.get(&subscription.id)
                    && widgets::dismissible_error(
                        ui,
                        &state.text(&errors::update_subscription(crate::i18n::language(), error)),
                    )
                {
                    actions.push(Action::DismissOutcome(subscription.id.clone()));
                }
                if !expanded {
                    return;
                }
                ui.add_space(6.0);
                if let Some(info) = &subscription.info {
                    let used = crate::i18n::bytes(info.upload.saturating_add(info.download));
                    let traffic = info.total.map_or_else(
                        || tr!("quota-used", used = &used),
                        |total| {
                            tr!(
                                "quota-used-of",
                                used = &used,
                                total = crate::i18n::bytes(total)
                            )
                        },
                    );
                    egui::Sides::new().shrink_left().show(
                        ui,
                        |ui| {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(traffic).small().color(theme::TEXT_MUTED),
                                )
                                .truncate(),
                            );
                        },
                        |ui| {
                            if let Some(expire) = info.expire_unix {
                                let (term, _) = crate::i18n::term_left(expire, now);
                                ui.label(
                                    RichText::new(term).small().color(expiry_color(expire, now)),
                                );
                            }
                        },
                    );
                    if let Some(fraction) = quota_fraction(info, now) {
                        let (bar, _) = ui.allocate_exact_size(
                            egui::vec2(ui.available_width(), 4.0),
                            egui::Sense::hover(),
                        );
                        ui.painter().rect_filled(bar, 2.0, theme::INPUT);
                        if fraction > 0.0 {
                            ui.painter().rect_filled(
                                egui::Rect::from_min_size(
                                    bar.min,
                                    egui::vec2(bar.width() * fraction, 4.0),
                                ),
                                2.0,
                                if fraction >= 1.0 {
                                    theme::ERROR
                                } else {
                                    theme::ROSE_DARK
                                },
                            );
                        }
                    }
                }
                if subscription.announce.is_some() || !subscription.notices.is_empty() {
                    widgets::card_frame()
                        .fill(theme::BG)
                        .stroke(Stroke::new(1.0, theme::BORDER))
                        .corner_radius(theme::RADIUS)
                        .inner_margin(10)
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.style_mut().interaction.selectable_labels = true;
                            if let Some(announce) = &subscription.announce {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(provider_text(
                                            ui,
                                            state,
                                            announce,
                                            egui::TextStyle::Small,
                                        ))
                                        .small()
                                        .color(theme::TEXT_MUTED),
                                    )
                                    .wrap(),
                                );
                            }
                            for notice in &subscription.notices {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(provider_text(
                                            ui,
                                            state,
                                            notice,
                                            egui::TextStyle::Small,
                                        ))
                                        .small()
                                        .color(theme::TEXT_MUTED),
                                    )
                                    .wrap(),
                                );
                            }
                        });
                }
                if subscription.support_url.is_some() || subscription.web_page_url.is_some() {
                    ui.horizontal(|ui| {
                        if let Some(value) = &subscription.support_url {
                            provider_link(ui, state, &tr!("support"), value);
                        }
                        if let Some(value) = &subscription.web_page_url {
                            provider_link(ui, state, &tr!("website"), value);
                        }
                    });
                }
                if let Some(UpdateOutcome::Success(report)) =
                    state.subscriptions.outcomes.get(&subscription.id)
                {
                    ui.add(
                        egui::Label::new(
                            RichText::new(crate::i18n::updated(
                                report.added,
                                report.removed,
                                report.retained,
                            ))
                            .color(theme::ROSE_LIGHT),
                        )
                        .wrap(),
                    );
                    if report.selection_cleared {
                        ui.add(
                            egui::Label::new(
                                RichText::new(tr!("selection-cleared")).color(theme::ERROR),
                            )
                            .wrap(),
                        );
                    }
                    for (reason, count) in &report.skipped {
                        ui.add(
                            egui::Label::new(state.text(&crate::i18n::skipped(
                                *count,
                                &errors::skip_reason(crate::i18n::language(), reason),
                            )))
                            .wrap(),
                        );
                    }
                }
                egui::Sides::new().shrink_left().show(
                    ui,
                    |ui| {
                        ui.label(
                            RichText::new(tr!("servers-heading"))
                                .small()
                                .color(theme::TEXT_DIM),
                        );
                    },
                    |ui| {
                        let checking = state.operations.pinging.contains(&subscription.id);
                        if checking {
                            ui.label(
                                RichText::new(tr!("ping-checking"))
                                    .small()
                                    .color(theme::TEXT_DIM),
                            );
                        } else {
                            let enabled = state.config_ready
                                && !subscription.nodes.is_empty()
                                && !state.subscription_busy(&subscription.id);
                            let menu = menu_link(ui, &tr!("check-menu"), enabled)
                                .on_hover_text(tr!("check-hint"));
                            widgets::menu_popup(&menu).show(|ui| {
                                check_menu_items(ui, state, subscription, None, enabled, actions);
                            });
                        }
                    },
                );
                if subscription.nodes.is_empty() {
                    ui.colored_label(theme::TEXT_DIM, tr!("no-servers"));
                }
                let show_flags = subscription
                    .nodes
                    .iter()
                    .any(|node| display::leading_flag(&node.name).0.is_some());
                let font = egui::TextStyle::Small.resolve(ui.style());
                let ping_width = subscription
                    .nodes
                    .iter()
                    .filter_map(|node| {
                        state
                            .subscriptions
                            .pings
                            .get(&(subscription.id.clone(), node.id.clone()))
                            .map(|&result| (node, result))
                    })
                    .map(|(node, result)| {
                        let (label, _, _) =
                            ping_label(result, matches!(&node.outbound, Outbound::Hysteria2(_)));
                        ui.painter()
                            .layout_no_wrap(label, font.clone(), theme::TEXT_DIM)
                            .size()
                            .x
                    })
                    .reduce(f32::max)
                    .map(|width| width.max(70.0));
                ui.scope(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    for node in &subscription.nodes {
                        ui.push_id(node.id.as_str(), |ui| {
                            server_row(
                                ui,
                                state,
                                subscription,
                                node,
                                show_flags,
                                ping_width,
                                actions,
                            );
                        });
                    }
                });
            });
            if reorder
                && ui
                    .ctx()
                    .pointer_hover_pos()
                    .is_some_and(|pointer| response.response.rect.contains(pointer))
            {
                icons::paint(
                    ui.painter(),
                    egui::pos2(
                        response.response.rect.left() + 6.0,
                        response.response.rect.top() + 26.0,
                    ),
                    Icon::Grip,
                    theme::TEXT_DIM,
                );
            }
            if selected {
                let rect = response.response.rect;
                ui.painter().rect_filled(
                    egui::Rect::from_min_max(
                        egui::pos2(rect.left(), rect.top() + f32::from(theme::RADIUS)),
                        egui::pos2(rect.left() + 3.0, rect.bottom() - f32::from(theme::RADIUS)),
                    ),
                    0.0,
                    theme::ROSE,
                );
            }
        },
    )
    .response
}

fn expiry_color(expire: u64, now: u64) -> Color32 {
    if expire <= now {
        theme::EXPIRED
    } else if expire - now < 7 * 86_400 {
        theme::WARNING
    } else {
        theme::TEXT_DIM
    }
}

/// How much of the plan is used up, 0.0..=1.0: traffic against the limit, or
/// without a limit, the last 30 days before expiry.
fn quota_fraction(info: &SubscriptionInfo, now: u64) -> Option<f32> {
    if let Some(total) = info.total {
        let used = info.upload.saturating_add(info.download);
        return Some(if total == 0 {
            1.0
        } else {
            (used as f64 / total as f64).clamp(0.0, 1.0) as f32
        });
    }
    const THIRTY_DAYS: u64 = 30 * 86_400;
    info.expire_unix
        .map(|expire| 1.0 - expire.saturating_sub(now).min(THIRTY_DAYS) as f32 / THIRTY_DAYS as f32)
}

/// Signal bars for a ping: 3 under 80 ms, 2 up to 150 ms, 1 above, 0 without an answer.
fn ping_quality(result: PingResult) -> u8 {
    match result {
        PingResult::Answered(elapsed) | PingResult::Works(elapsed) => match ping_millis(elapsed) {
            0..80 => 3,
            80..=150 => 2,
            _ => 1,
        },
        PingResult::NoAnswer
        | PingResult::Fails
        | PingResult::Unresolved
        | PingResult::Unsupported
        | PingResult::Pending => 0,
    }
}

fn ping_label(result: PingResult, is_hysteria2: bool) -> (String, Color32, Option<String>) {
    match result {
        PingResult::Answered(elapsed) => (
            tr!("ping-ms", ms = ping_millis(elapsed).to_string()),
            theme::TEXT_DIM,
            Some(tr!("ping-tcp-hint")),
        ),
        PingResult::Works(elapsed) => (
            tr!("ping-ms", ms = ping_millis(elapsed).to_string()),
            theme::TEXT_DIM,
            Some(tr!("ping-full-hint")),
        ),
        PingResult::NoAnswer => (tr!("ping-no-answer"), theme::ERROR, None),
        PingResult::Fails => (
            tr!("ping-fails"),
            theme::ERROR,
            Some(tr!("ping-fails-hint")),
        ),
        PingResult::Unresolved => (
            tr!("ping-unresolved"),
            theme::TEXT_DIM,
            Some(tr!("ping-unresolved-hint")),
        ),
        PingResult::Unsupported => (
            tr!("ping-unsupported"),
            theme::TEXT_DIM,
            is_hysteria2.then(|| tr!("ping-udp-hint")),
        ),
        PingResult::Pending => (tr!("ping-pending"), theme::TEXT_DIM, None),
    }
}

fn hover_ping_hint(
    result: Option<PingResult>,
    pointer: Option<egui::Pos2>,
    region: Option<egui::Rect>,
    is_hysteria2: bool,
) -> Option<String> {
    if !pointer
        .zip(region)
        .is_some_and(|(point, rect)| rect.contains(point))
    {
        return None;
    }
    ping_label(result?, is_hysteria2).2
}

fn check_menu_items(
    ui: &mut egui::Ui,
    state: &State,
    subscription: &Subscription,
    node: Option<&NodeId>,
    available: bool,
    actions: &mut Vec<Action>,
) {
    ui.set_min_width(200.0);
    let can_ping = state.can_ping();
    let ping = widgets::menu_item(
        ui,
        widgets::MenuItem {
            label: &tr!("check-quick"),
            enabled: available && can_ping,
            selected: false,
            danger: false,
            note: None,
        },
    );
    let ping = if matches!(state.status.state, ConnectionState::Connected) {
        ping.on_disabled_hover_text(tr!("ping-while-connected"))
    } else {
        ping
    };
    if ping.clicked() {
        actions.push(match node {
            Some(node) => Action::PingNode(subscription.id.clone(), node.clone()),
            None => Action::Ping(subscription.id.clone()),
        });
        ui.close();
    }
    if widgets::menu_item(
        ui,
        widgets::MenuItem {
            label: &tr!("check-full"),
            enabled: available && state.can_full_check(),
            selected: false,
            danger: false,
            note: None,
        },
    )
    .clicked()
    {
        actions.push(match node {
            Some(node) => Action::FullCheckNode(subscription.id.clone(), node.clone()),
            None => Action::FullCheck(subscription.id.clone()),
        });
        ui.close();
    }
}

fn server_row(
    ui: &mut egui::Ui,
    state: &State,
    subscription: &Subscription,
    node: &Node,
    show_flags: bool,
    ping_width: Option<f32>,
    actions: &mut Vec<Action>,
) {
    let enabled = state.config_ready && !state.operations.selection && !state.operations.helper;
    let selected = state.config.active.as_ref().is_some_and(|selection| {
        selection.subscription == subscription.id && selection.node == node.id
    });
    let sense = if state.config_ready {
        egui::Sense::click()
    } else {
        egui::Sense::hover()
    };
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), theme::SERVER_ROW), sense);
    let (code, remainder) = display::leading_flag(&node.name);
    let name = provider_text(ui, state, remainder, egui::TextStyle::Body);
    let full_name = state.text(&node.name);
    let ping_result = state
        .subscriptions
        .pings
        .get(&(subscription.id.clone(), node.id.clone()))
        .copied();
    let right = rect.right() - 10.0;
    let ping_left = ping_width.map(|width| right - width);
    let ping_region = ping_left.map(|left| {
        egui::Rect::from_min_max(
            egui::pos2(left, rect.top()),
            egui::pos2(right, rect.bottom()),
        )
    });
    let response = if let Some(hint) = hover_ping_hint(
        ping_result,
        ui.ctx().pointer_hover_pos(),
        ping_region,
        matches!(&node.outbound, Outbound::Hysteria2(_)),
    ) {
        response.on_hover_text(hint)
    } else {
        response.on_hover_text(i18n::server_tooltip(
            &full_name,
            &i18n::node_details(
                rosetun_core::node_protocol(node),
                rosetun_core::node_tls(node),
                rosetun_core::node_transport(node),
            ),
            &state.text(&rosetun_core::node_address(node)),
        ))
    };
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::SelectableLabel,
            enabled,
            selected,
            &full_name,
        )
    });
    let response = if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    };
    if state
        .subscriptions
        .reveal
        .as_ref()
        .is_some_and(|(id, selected)| id == &subscription.id && selected == &node.id)
    {
        response.scroll_to_me(Some(egui::Align::Center));
        actions.push(Action::RevealDone);
    }
    if enabled && response.clicked() {
        actions.push(Action::SelectNode(subscription.id.clone(), node.id.clone()));
    }
    let available = state.config_ready
        && !state.operations.pinging.contains(&subscription.id)
        && !state.subscription_busy(&subscription.id);
    widgets::context_menu_popup(&response).show(|ui| {
        check_menu_items(ui, state, subscription, Some(&node.id), available, actions);
    });
    if !ui.is_rect_visible(rect) {
        return;
    }
    let painter = ui.painter();
    let background = if enabled && response.is_pointer_button_down_on() {
        Some(theme::ROSE_DARK)
    } else if enabled && response.hovered() {
        Some(theme::BORDER)
    } else if selected {
        Some(theme::INPUT)
    } else {
        None
    };
    if let Some(color) = background {
        painter.rect_filled(rect, theme::RADIUS_INNER, color);
    }
    let mut name_left = rect.left() + 10.0;
    if show_flags {
        if let Some(code) = code {
            let badge = egui::Rect::from_min_size(
                egui::pos2(name_left, rect.center().y - 10.0),
                egui::vec2(28.0, 20.0),
            );
            painter.rect_stroke(
                badge,
                theme::RADIUS_INNER,
                Stroke::new(1.0, theme::BORDER_STRONG),
                egui::StrokeKind::Inside,
            );
            painter.text(
                badge.center(),
                egui::Align2::CENTER_CENTER,
                code,
                egui::FontId::monospace(11.0),
                theme::TEXT_MUTED,
            );
        }
        name_left += 38.0;
    }
    let mut name_right = right;
    if let Some(ping_left) = ping_left {
        let bars_left = ping_left - 8.0 - 13.0;
        name_right = bars_left - 10.0;
        if let Some(result) = ping_result {
            let quality = ping_quality(result);
            let bottom = rect.center().y + 5.5;
            for (index, height) in [4.0, 7.0, 11.0].into_iter().enumerate() {
                painter.rect_filled(
                    egui::Rect::from_min_size(
                        egui::pos2(bars_left + index as f32 * 5.0, bottom - height),
                        egui::vec2(3.0, height),
                    ),
                    1.0,
                    if index < quality as usize {
                        theme::TEXT_MUTED
                    } else {
                        theme::BORDER_STRONG
                    },
                );
            }
            let (ping_text, color, _) =
                ping_label(result, matches!(&node.outbound, Outbound::Hysteria2(_)));
            painter.text(
                egui::pos2(right, rect.center().y),
                egui::Align2::RIGHT_CENTER,
                ping_text,
                egui::TextStyle::Small.resolve(ui.style()),
                color,
            );
        }
    }
    let name_color = if selected {
        theme::ROSE_LIGHT
    } else {
        theme::TEXT
    };
    let text = RichText::new(name).color(name_color).font(if selected {
        egui::FontId::new(
            egui::TextStyle::Body.resolve(ui.style()).size,
            egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
        )
    } else {
        egui::TextStyle::Body.resolve(ui.style())
    });
    let galley = egui::WidgetText::from(text).into_galley(
        ui,
        Some(egui::TextWrapMode::Truncate),
        (name_right - name_left).max(0.0),
        egui::TextStyle::Body,
    );
    painter.galley(
        egui::pos2(name_left, rect.center().y - galley.size().y / 2.0),
        galley,
        name_color,
    );
}

fn ping_millis(elapsed: Duration) -> u128 {
    elapsed
        .as_millis()
        .saturating_add(u128::from(
            !elapsed.subsec_nanos().is_multiple_of(1_000_000),
        ))
        .max(1)
}

fn provider_text(ui: &egui::Ui, state: &State, value: &str, style: egui::TextStyle) -> String {
    display::drop_missing_glyphs(ui.ctx(), &style.resolve(ui.style()), &state.text(value))
}

fn menu_link(ui: &mut egui::Ui, text: &str, enabled: bool) -> egui::Response {
    let font = egui::TextStyle::Small.resolve(ui.style());
    let text_width = ui
        .painter()
        .layout_no_wrap(text.to_owned(), font.clone(), theme::ROSE_LIGHT)
        .size()
        .x;
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(
            text_width + 20.0,
            ui.text_style_height(&egui::TextStyle::Small),
        ),
        if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        },
    );
    if ui.is_rect_visible(rect) {
        let color = if enabled {
            theme::ROSE_LIGHT
        } else {
            theme::TEXT_DIM
        };
        ui.painter().text(
            rect.left_center(),
            egui::Align2::LEFT_CENTER,
            text,
            font,
            color,
        );
        icons::paint(
            ui.painter(),
            egui::pos2(rect.right() - 7.0, rect.center().y),
            Icon::Chevron { open: true },
            color,
        );
        if enabled && response.hovered() {
            ui.painter().line_segment(
                [
                    rect.left_bottom() + egui::vec2(0.0, -1.0),
                    egui::pos2(rect.left() + text_width, rect.bottom() - 1.0),
                ],
                Stroke::new(1.0, theme::ROSE_LIGHT),
            );
        }
    }
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

fn provider_link(ui: &mut egui::Ui, state: &State, label: &str, value: &str) {
    if display::safe_web_url(value).is_some() {
        let response = widgets::link(ui, label, true);
        if response.clicked() {
            display::open_web_link(ui.ctx(), value);
        }
        response.on_hover_text(rosetun_core::terminal_text(&state.text(value)));
    } else {
        ui.add(
            egui::Label::new(
                RichText::new(state.text(&i18n::plain_link(label, value))).color(theme::TEXT_DIM),
            )
            .truncate(),
        );
    }
}

pub(crate) fn rename_dialog(ctx: &egui::Context, state: &mut State, actions: &mut Vec<Action>) {
    let Some(dialog) = &mut state.subscriptions.rename else {
        return;
    };
    let busy = state.operations.renaming;
    let response = egui::Modal::new(egui::Id::new("rename_subscription"))
        .frame(widgets::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(400.0);
            ui.heading(tr!("rename-subscription"));
            ui.add_space(12.0);
            ui.label(tr!("subscription-name"));
            let input = ui.add_enabled(
                !busy,
                egui::TextEdit::singleline(&mut dialog.name)
                    .char_limit(rosetun_core::SUBSCRIPTION_NAME_LIMIT)
                    .desired_width(f32::INFINITY),
            );
            if dialog.focus {
                input.request_focus();
                dialog.focus = false;
            }
            if input.changed() {
                dialog.error = None;
            }
            if !busy
                && !dialog.name.trim().is_empty()
                && (input.has_focus() || input.lost_focus())
                && ui.input(|input| input.key_pressed(egui::Key::Enter))
            {
                actions.push(Action::SubmitRename);
            }
            if let Some(error) = &dialog.error {
                ui.colored_label(theme::ERROR, error);
            }
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                if widgets::outline_button(ui, tr!("cancel"), !busy).clicked() {
                    actions.push(Action::CancelRename);
                }
                if widgets::button_fill(ui, tr!("rename"), !busy && !dialog.name.trim().is_empty())
                    .clicked()
                {
                    actions.push(Action::SubmitRename);
                }
            });
        });
    if !busy && response.should_close() {
        actions.push(Action::CancelRename);
    }
}

pub(crate) fn remove_dialog(ctx: &egui::Context, state: &State, actions: &mut Vec<Action>) {
    let Some(dialog) = &state.subscriptions.remove else {
        return;
    };
    let response = egui::Modal::new(egui::Id::new("remove_subscription"))
        .frame(widgets::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(480.0);
            ui.heading(tr!("remove-subscription"));
            if let Some(subscription) = state
                .config
                .subscriptions
                .iter()
                .find(|sub| sub.id == dialog.id)
            {
                ui.label(provider_text(
                    ui,
                    state,
                    &subscription.name,
                    egui::TextStyle::Body,
                ));
            }
            ui.add_space(12.0);
            ui.add(egui::Label::new(tr!("remove-detail")).wrap());
            if state
                .config
                .active
                .as_ref()
                .is_some_and(|selection| selection.subscription == dialog.id)
            {
                ui.add(
                    egui::Label::new(
                        RichText::new(tr!("remove-selected-warning")).color(theme::ERROR),
                    )
                    .wrap(),
                );
            }
            if let Some(error) = &dialog.error {
                ui.add(
                    egui::Label::new(RichText::new(state.text(error)).color(theme::ERROR)).wrap(),
                );
            }
            ui.add_space(20.0);
            ui.horizontal(|ui| {
                if widgets::outline_button(ui, tr!("cancel"), !state.operations.removing).clicked()
                {
                    actions.push(Action::CancelRemove);
                }
                if widgets::button_fill(
                    ui,
                    if state.operations.removing {
                        tr!("removing")
                    } else {
                        tr!("remove")
                    },
                    !state.operations.removing,
                )
                .clicked()
                {
                    actions.push(Action::ConfirmRemove);
                }
            });
        });
    if !state.operations.removing && response.should_close() {
        actions.push(Action::CancelRemove);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_colors_change_within_seven_days_and_after_expiry() {
        let now = 1_000_000;
        let week = 7 * 86_400;
        assert_eq!(expiry_color(now + week, now), theme::TEXT_DIM);
        assert_eq!(expiry_color(now + week - 1, now), theme::WARNING);
        assert_eq!(expiry_color(now + 1, now), theme::WARNING);
        assert_eq!(expiry_color(now, now), theme::EXPIRED);
        assert_eq!(expiry_color(now - 1, now), theme::EXPIRED);
    }

    #[test]
    fn ping_milliseconds_round_up_and_never_show_zero() {
        assert_eq!(ping_millis(Duration::ZERO), 1);
        assert_eq!(ping_millis(Duration::from_nanos(1)), 1);
        assert_eq!(ping_millis(Duration::from_millis(1)), 1);
        assert_eq!(ping_millis(Duration::from_micros(1_001)), 2);
        assert_eq!(ping_millis(Duration::from_millis(118)), 118);
    }

    #[test]
    fn result_hint_replaces_server_tooltip_only_over_the_result() {
        let rect = egui::Rect::from_min_max(egui::pos2(80.0, 0.0), egui::pos2(150.0, 30.0));
        let latency = Some(PingResult::Answered(Duration::from_millis(85)));
        let works = Some(PingResult::Works(Duration::from_millis(85)));
        let inside = Some(egui::pos2(100.0, 15.0));
        assert_eq!(
            hover_ping_hint(latency, inside, Some(rect), false),
            Some(tr!("ping-tcp-hint"))
        );
        assert_eq!(
            hover_ping_hint(works, inside, Some(rect), false),
            Some(tr!("ping-full-hint"))
        );
        assert_eq!(
            hover_ping_hint(Some(PingResult::Fails), inside, Some(rect), false),
            Some(tr!("ping-fails-hint"))
        );
        assert_eq!(
            hover_ping_hint(Some(PingResult::Unresolved), inside, Some(rect), false),
            Some(tr!("ping-unresolved-hint"))
        );
        assert_eq!(
            hover_ping_hint(latency, Some(egui::pos2(30.0, 15.0)), Some(rect), false),
            None
        );
        assert_eq!(hover_ping_hint(latency, inside, None, false), None);
        assert_eq!(hover_ping_hint(latency, None, Some(rect), false), None);
        assert_eq!(
            hover_ping_hint(Some(PingResult::Pending), inside, Some(rect), false),
            None
        );
        assert_eq!(
            hover_ping_hint(Some(PingResult::Unsupported), inside, Some(rect), true),
            Some(tr!("ping-udp-hint"))
        );
        assert_eq!(
            hover_ping_hint(Some(PingResult::Unsupported), inside, Some(rect), false),
            None
        );
    }

    #[test]
    fn ping_bars_reflect_latency_and_missing_answers() {
        for (result, expected) in [
            (PingResult::Answered(Duration::from_millis(79)), 3),
            (PingResult::Answered(Duration::from_millis(80)), 2),
            (PingResult::Answered(Duration::from_millis(150)), 2),
            (PingResult::Answered(Duration::from_millis(151)), 1),
            (PingResult::Works(Duration::from_millis(79)), 3),
            (PingResult::Works(Duration::from_millis(150)), 2),
            (PingResult::Works(Duration::from_millis(151)), 1),
            (PingResult::Fails, 0),
            (PingResult::Unresolved, 0),
            (PingResult::Unsupported, 0),
            (PingResult::NoAnswer, 0),
            (PingResult::Pending, 0),
        ] {
            assert_eq!(ping_quality(result), expected);
        }
    }

    #[test]
    fn ping_labels_match_results_and_hints() {
        let elapsed = Duration::from_millis(85);
        let ms = tr!("ping-ms", ms = "85");
        for (result, label, color, hint) in [
            (
                PingResult::Answered(elapsed),
                ms.clone(),
                theme::TEXT_DIM,
                Some(tr!("ping-tcp-hint")),
            ),
            (
                PingResult::Works(elapsed),
                ms,
                theme::TEXT_DIM,
                Some(tr!("ping-full-hint")),
            ),
            (
                PingResult::NoAnswer,
                tr!("ping-no-answer").to_owned(),
                theme::ERROR,
                None,
            ),
            (
                PingResult::Fails,
                tr!("ping-fails").to_owned(),
                theme::ERROR,
                Some(tr!("ping-fails-hint")),
            ),
            (
                PingResult::Unresolved,
                tr!("ping-unresolved").to_owned(),
                theme::TEXT_DIM,
                Some(tr!("ping-unresolved-hint")),
            ),
            (
                PingResult::Unsupported,
                tr!("ping-unsupported").to_owned(),
                theme::TEXT_DIM,
                None,
            ),
            (
                PingResult::Pending,
                tr!("ping-pending").to_owned(),
                theme::TEXT_DIM,
                None,
            ),
        ] {
            assert_eq!(ping_label(result, false), (label, color, hint));
        }
    }

    #[test]
    fn quota_progress_clamps_usage_and_counts_down_to_expiry() {
        let mut info = SubscriptionInfo {
            upload: 10,
            download: 15,
            total: Some(100),
            expire_unix: None,
        };
        assert_eq!(quota_fraction(&info, 0), Some(0.25));
        info.upload = 75;
        info.download = 75;
        assert_eq!(quota_fraction(&info, 0), Some(1.0));
        info.upload = u64::MAX;
        info.download = u64::MAX;
        assert_eq!(quota_fraction(&info, 0), Some(1.0));
        info.total = None;
        info.expire_unix = Some(15 * 86_400);
        assert_eq!(quota_fraction(&info, 0), Some(0.5));
        info.expire_unix = Some(60 * 86_400);
        assert_eq!(quota_fraction(&info, 0), Some(0.0));
        info.expire_unix = Some(10);
        assert_eq!(quota_fraction(&info, 11), Some(1.0));
        info.expire_unix = None;
        assert_eq!(quota_fraction(&info, 0), None);
    }
}
