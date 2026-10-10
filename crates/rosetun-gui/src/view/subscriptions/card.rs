use super::servers::{check_menu_items, ping_label, ping_millis, server_row};
use super::*;

pub(super) fn subscription_card(
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
