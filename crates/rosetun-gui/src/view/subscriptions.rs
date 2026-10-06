use std::time::Duration;

use eframe::egui::{self, Color32, RichText, Stroke};
use rosetun_config::{Subscription, SubscriptionId};

use crate::errors;
use crate::icons::{self, Icon};
use crate::reorder::drop_target;
use crate::state::{Action, PingResult, State, UpdateOutcome, shared_auto_update_hours};
use crate::strings::t;
use crate::{display, strings, theme, widgets};

pub(crate) fn show(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    const FOOTER_HEIGHT: f32 = 72.0;

    ui.style_mut().interaction.selectable_labels = false;
    egui::Panel::bottom("subscriptions_footer")
        .exact_size(FOOTER_HEIGHT)
        .frame(egui::Frame::new())
        .show(ui, |ui| {
            egui::Sides::new()
                .height(FOOTER_HEIGHT)
                .shrink_right()
                .show(
                    ui,
                    |ui| {
                        ui.scope(|ui| {
                            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
                            let enabled = state.config_ready
                                && !state.config.subscriptions.is_empty()
                                && !state.operations.update_all
                                && state.operations.updating.is_empty()
                                && !state.operations.removing;
                            if widgets::outline_button(
                                ui,
                                if state.operations.update_all {
                                    t().updating
                                } else {
                                    t().update_all
                                },
                                enabled,
                            )
                            .clicked()
                            {
                                actions.push(Action::UpdateAll);
                            }
                        });
                    },
                    |ui| {
                        if state.config.interface.auto_update_subscriptions
                            && !state.config.subscriptions.is_empty()
                        {
                            let text = shared_auto_update_hours(&state.config.subscriptions)
                                .map(|hours| {
                                    strings::fill(
                                        t().auto_update_every,
                                        &[("hours", &hours.to_string())],
                                    )
                                })
                                .unwrap_or_else(|| t().auto_update_on.to_owned());
                            ui.add(
                                egui::Label::new(
                                    RichText::new(text).small().color(theme::TEXT_DIM),
                                )
                                .truncate(),
                            );
                        }
                    },
                );
        });
    egui::Sides::new().shrink_left().show(
        ui,
        |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                ui.label(
                    RichText::new(t().subscriptions_title)
                        .color(theme::TEXT)
                        .font(egui::FontId::new(
                            15.0,
                            egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
                        )),
                );
                ui.label(
                    RichText::new(format!("· {}", state.config.subscriptions.len()))
                        .color(theme::TEXT_DIM),
                );
            });
        },
        |ui| {
            ui.scope(|ui| {
                ui.spacing_mut().button_padding.y = 6.0;
                if widgets::button_fill(ui, t().add_short, state.add.is_none()).clicked() {
                    actions.push(Action::OpenAdd);
                }
            });
        },
    );
    ui.add_space(12.0);
    egui::ScrollArea::vertical()
        .id_salt("subscription_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if state.config.subscriptions.is_empty() {
                ui.colored_label(theme::TEXT_MUTED, t().no_subscriptions);
                ui.add_space(8.0);
                ui.add(
                    egui::Label::new(RichText::new(t().empty_subscriptions).color(theme::TEXT_DIM))
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
    let expanded = state.expanded.contains(&subscription.id);
    let selected = state
        .config
        .active
        .as_ref()
        .is_some_and(|selection| selection.subscription == subscription.id);
    let mut frame = widgets::card_frame().inner_margin(12).stroke(Stroke::new(
        1.0,
        if selected {
            theme::ROSE_DARK
        } else {
            theme::BORDER
        },
    ));
    if dragged {
        frame = frame.fill(Color32::from_rgba_unmultiplied(
            theme::CARD.r(),
            theme::CARD.g(),
            theme::CARD.b(),
            128,
        ));
    }
    ui.scope_builder(
        egui::UiBuilder::new().id_salt("card").sense(if reorder {
            egui::Sense::drag()
        } else {
            egui::Sense::hover()
        }),
        |ui| {
            if reorder {
                ui.response().dnd_set_drag_payload(subscription.id.clone());
            }
            let response = frame.show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                if dragged {
                    ui.multiply_opacity(0.5);
                }
                ui.horizontal(|ui| {
                    if icons::icon_button(ui, Icon::Chevron { open: expanded }, true)
                        .on_hover_text(if expanded {
                            strings::COLLAPSE
                        } else {
                            strings::EXPAND
                        })
                        .clicked()
                    {
                        actions.push(Action::ToggleExpanded(subscription.id.clone()));
                    }
                    let name_width =
                        (ui.available_width() - 2.0 * 28.0 - 2.0 * ui.spacing().item_spacing.x)
                            .max(0.0);
                    let name = provider_text(ui, state, &subscription.name, egui::TextStyle::Body);
                    if ui
                        .add_sized(
                            [name_width, 22.0],
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
                        .on_hover_text(t().updating);
                    } else if icons::icon_button_sized(
                        ui,
                        Icon::Refresh,
                        !state.subscription_busy(&subscription.id),
                        28.0,
                    )
                    .on_hover_text(t().update)
                    .clicked()
                    {
                        actions.push(Action::Update(subscription.id.clone()));
                    }
                    let menu = icons::icon_button_sized(ui, Icon::More, true, 28.0)
                        .on_hover_text(t().more_actions);
                    egui::Popup::menu(&menu).show(|ui| {
                        ui.set_min_width(180.0);
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
                        if ui
                            .add_enabled(
                                state.config_ready
                                    && !state.operations.renaming
                                    && state.rename.is_none()
                                    && state.remove.is_none(),
                                egui::Button::new(t().rename),
                            )
                            .clicked()
                        {
                            actions.push(Action::RequestRename(subscription.id.clone()));
                            ui.close();
                        }
                        if ui
                            .add_enabled(
                                !state.subscription_busy(&subscription.id)
                                    && !state.operations.removing,
                                egui::Button::new(RichText::new(t().remove).color(theme::ERROR)),
                            )
                            .clicked()
                        {
                            actions.push(Action::RequestRemove(subscription.id.clone()));
                            ui.close();
                        }
                    });
                });
                let age = subscription
                    .updated_at_unix
                    .map(|timestamp| {
                        t().last_updated(&t().updated_ago(timestamp, display::now_unix()))
                    })
                    .unwrap_or_else(|| t().never_updated.to_owned());
                let summary =
                    strings::subscription_summary(&t().servers(subscription.nodes.len()), &age);
                ui.horizontal(|ui| {
                    ui.add_space(22.0);
                    egui::Sides::new().shrink_left().show(
                        ui,
                        |ui| {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(summary).small().color(theme::TEXT_DIM),
                                )
                                .truncate(),
                            );
                        },
                        |ui| {
                            if !expanded && let Some(best) = state.best_ping(subscription) {
                                ui.label(
                                    RichText::new(strings::fill(
                                        t().ping_best,
                                        &[("ms", &ping_millis(best).to_string())],
                                    ))
                                    .small()
                                    .color(theme::TEXT_DIM),
                                );
                            }
                        },
                    );
                });
                if let Some(UpdateOutcome::Error(error)) = state.outcomes.get(&subscription.id)
                    && widgets::dismissible_error(
                        ui,
                        &state.text(&errors::update_subscription(t(), error)),
                    )
                {
                    actions.push(Action::DismissOutcome(subscription.id.clone()));
                }
                if !expanded {
                    return;
                }
                ui.add_space(6.0);
                if let Some(info) = &subscription.info {
                    let mut details = t().traffic(info);
                    if let Some(expiry) = info.expire_unix {
                        details.push_str(" · ");
                        details.push_str(&t().expiry(expiry, display::now_unix()));
                    }
                    ui.add(
                        egui::Label::new(RichText::new(details).small().color(theme::TEXT_MUTED))
                            .truncate(),
                    );
                }
                if subscription.announce.is_some() || !subscription.notices.is_empty() {
                    widgets::card_frame()
                        .fill(theme::INPUT)
                        .inner_margin(10)
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            if let Some(announce) = &subscription.announce {
                                ui.add(
                                    egui::Label::new(provider_text(
                                        ui,
                                        state,
                                        announce,
                                        egui::TextStyle::Body,
                                    ))
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
                                            egui::TextStyle::Body,
                                        ))
                                        .color(theme::TEXT_MUTED),
                                    )
                                    .wrap(),
                                );
                            }
                        });
                }
                if let Some(UpdateOutcome::Success(report)) = state.outcomes.get(&subscription.id) {
                    ui.add(
                        egui::Label::new(
                            RichText::new(t().updated(
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
                                RichText::new(t().selection_cleared).color(theme::ERROR),
                            )
                            .wrap(),
                        );
                    }
                    for (reason, count) in &report.skipped {
                        ui.add(
                            egui::Label::new(
                                state.text(&t().skipped(*count, &errors::skip_reason(t(), reason))),
                            )
                            .wrap(),
                        );
                    }
                }
                if subscription.support_url.is_some() || subscription.web_page_url.is_some() {
                    ui.horizontal(|ui| {
                        if let Some(value) = &subscription.support_url {
                            provider_link(ui, state, t().support, value);
                        }
                        if let Some(value) = &subscription.web_page_url {
                            provider_link(ui, state, t().website, value);
                        }
                    });
                }
                ui.separator();
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let checking = state.operations.pinging.contains(&subscription.id);
                    let enabled = state.config_ready
                        && !subscription.nodes.is_empty()
                        && !checking
                        && !state.subscription_busy(&subscription.id)
                        && state.can_ping();
                    let button = widgets::outline_button(
                        ui,
                        if checking {
                            t().ping_checking
                        } else {
                            t().ping_check
                        },
                        enabled,
                    );
                    let button = if state.can_ping() {
                        button
                    } else {
                        button.on_disabled_hover_text(t().ping_tunnel_up)
                    };
                    if button.clicked() {
                        actions.push(Action::Ping(subscription.id.clone()));
                    }
                });
                if subscription.nodes.is_empty() {
                    ui.colored_label(theme::TEXT_DIM, t().no_servers);
                }
                for node in &subscription.nodes {
                    let selected = state.config.active.as_ref().is_some_and(|selection| {
                        selection.subscription == subscription.id && selection.node == node.id
                    });
                    ui.push_id(node.id.as_str(), |ui| {
                        let name = provider_text(ui, state, &node.name, egui::TextStyle::Body);
                        let text = if selected {
                            RichText::new(name).color(theme::ROSE_LIGHT).strong()
                        } else {
                            RichText::new(name).color(theme::TEXT)
                        };
                        let ping = state.pings.get(&(subscription.id.clone(), node.id.clone()));
                        ui.horizontal(|ui| {
                            let ping_width = if ping.is_some() {
                                108.0 + ui.spacing().item_spacing.x
                            } else {
                                0.0
                            };
                            let name_width = (ui.available_width() - ping_width).max(0.0);
                            let response = ui
                                .add_enabled_ui(
                                    state.config_ready
                                        && !state.operations.selection
                                        && !state.operations.helper,
                                    |ui| {
                                        ui.add_sized(
                                            [name_width, 0.0],
                                            egui::Button::new(text).selected(selected).wrap(),
                                        )
                                    },
                                )
                                .inner;
                            if state.reveal.as_ref().is_some_and(|(id, selected)| {
                                id == &subscription.id && selected == &node.id
                            }) {
                                response.scroll_to_me(Some(egui::Align::Center));
                                actions.push(Action::RevealDone);
                            }
                            if response.clicked() {
                                actions.push(Action::SelectNode(
                                    subscription.id.clone(),
                                    node.id.clone(),
                                ));
                            }
                            if let Some(result) = ping {
                                let (label, color) = match result {
                                    PingResult::Answered(elapsed) => (
                                        strings::fill(
                                            t().ping_ms,
                                            &[("ms", &ping_millis(*elapsed).to_string())],
                                        ),
                                        theme::TEXT_DIM,
                                    ),
                                    PingResult::NoAnswer => {
                                        (t().ping_no_answer.to_owned(), theme::ERROR)
                                    }
                                    PingResult::Pending => {
                                        (t().ping_pending.to_owned(), theme::TEXT_DIM)
                                    }
                                };
                                ui.colored_label(color, label);
                            }
                        });
                        ui.add(
                            egui::Label::new(
                                RichText::new(strings::node_details(
                                    rosetun_core::node_protocol(node),
                                    rosetun_core::node_tls(node),
                                    rosetun_core::node_transport(node),
                                ))
                                .small()
                                .color(theme::TEXT_DIM),
                            )
                            .wrap(),
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(state.text(&rosetun_core::node_address(node)))
                                    .small()
                                    .color(theme::TEXT_DIM),
                            )
                            .wrap(),
                        );
                        ui.add_space(6.0);
                    });
                }
            });
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

fn provider_link(ui: &mut egui::Ui, state: &State, label: &str, value: &str) {
    if display::safe_web_url(value).is_some() {
        let response = ui
            .add(
                egui::Label::new(RichText::new(label).color(theme::ROSE_LIGHT))
                    .sense(egui::Sense::click()),
            )
            .on_hover_cursor(egui::CursorIcon::PointingHand);
        if response.hovered() {
            ui.painter().line_segment(
                [
                    response.rect.left_bottom() + egui::vec2(0.0, -1.0),
                    response.rect.right_bottom() + egui::vec2(0.0, -1.0),
                ],
                Stroke::new(1.0, theme::ROSE_LIGHT),
            );
        }
        if response.clicked() {
            display::open_web_link(ui.ctx(), value);
        }
        response.on_hover_text(rosetun_core::terminal_text(&state.text(value)));
    } else {
        ui.add(
            egui::Label::new(
                RichText::new(state.text(&strings::plain_link(label, value)))
                    .color(theme::TEXT_DIM),
            )
            .truncate(),
        );
    }
}

pub(crate) fn rename_dialog(ctx: &egui::Context, state: &mut State, actions: &mut Vec<Action>) {
    let Some(dialog) = &mut state.rename else {
        return;
    };
    let busy = state.operations.renaming;
    let response = egui::Modal::new(egui::Id::new("rename_subscription"))
        .frame(widgets::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(400.0);
            ui.heading(t().rename_subscription);
            ui.add_space(12.0);
            ui.label(t().subscription_name);
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
                if widgets::outline_button(ui, t().cancel, !busy).clicked() {
                    actions.push(Action::CancelRename);
                }
                if widgets::button_fill(ui, t().rename, !busy && !dialog.name.trim().is_empty())
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
    let Some(dialog) = &state.remove else {
        return;
    };
    let response = egui::Modal::new(egui::Id::new("remove_subscription"))
        .frame(widgets::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(480.0);
            ui.heading(t().remove_subscription);
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
            ui.add(egui::Label::new(t().remove_detail).wrap());
            if state
                .config
                .active
                .as_ref()
                .is_some_and(|selection| selection.subscription == dialog.id)
            {
                ui.add(
                    egui::Label::new(
                        RichText::new(t().remove_selected_warning).color(theme::ERROR),
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
                if widgets::outline_button(ui, t().cancel, !state.operations.removing).clicked() {
                    actions.push(Action::CancelRemove);
                }
                if widgets::button_fill(
                    ui,
                    if state.operations.removing {
                        t().removing
                    } else {
                        t().remove
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
    fn ping_milliseconds_round_up_and_never_show_zero() {
        assert_eq!(ping_millis(Duration::ZERO), 1);
        assert_eq!(ping_millis(Duration::from_nanos(1)), 1);
        assert_eq!(ping_millis(Duration::from_millis(1)), 1);
        assert_eq!(ping_millis(Duration::from_micros(1_001)), 2);
        assert_eq!(ping_millis(Duration::from_millis(118)), 118);
    }
}
