use eframe::egui::{self, Color32, RichText, Stroke};
use rosetun_config::{Subscription, SubscriptionId};

use crate::icons::{self, Icon};
use crate::reorder::drop_target;
use crate::state::{Action, State, UpdateOutcome};
use crate::strings::t;
use crate::{display, strings, theme};

pub(crate) fn show(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    ui.label(
        RichText::new(t().subscriptions(state.config.subscriptions.len()))
            .color(theme::TEXT_DIM)
            .strong(),
    );
    ui.add_space(6.0);
    if theme::button_fill(ui, t().add_subscription, state.add.is_none()).clicked() {
        actions.push(Action::OpenAdd);
    }
    ui.add_space(12.0);
    let height = (ui.available_height() - 48.0).max(120.0);
    egui::ScrollArea::vertical()
        .id_salt("subscription_scroll")
        .max_height(height)
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
    ui.separator();
    let enabled = state.config_ready
        && !state.config.subscriptions.is_empty()
        && !state.operations.update_all
        && state.operations.updating.is_empty()
        && !state.operations.removing;
    if theme::outline_button(
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
    let mut frame = theme::card_frame().inner_margin(12).stroke(Stroke::new(
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
                (ui.available_width() - 3.0 * 22.0 - 3.0 * ui.spacing().item_spacing.x).max(0.0);
            ui.allocate_ui_with_layout(
                egui::vec2(name_width, 22.0),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    ui.set_width(name_width);
                    let name = provider_text(ui, state, &subscription.name, egui::TextStyle::Body);
                    let label = ui
                        .add(
                            egui::Label::new(RichText::new(&name).strong())
                                .truncate()
                                .sense(egui::Sense::click()),
                        )
                        .on_hover_text(name);
                    if label.clicked() {
                        actions.push(Action::ToggleExpanded(subscription.id.clone()));
                    }
                },
            );
            if state.operations.update_all || state.operations.updating.contains(&subscription.id) {
                ui.allocate_ui_with_layout(
                    egui::vec2(22.0, 22.0),
                    egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                    |ui| {
                        ui.add(egui::Spinner::new().size(18.0));
                    },
                )
                .response
                .on_hover_text(t().updating);
            } else if icons::icon_button(
                ui,
                Icon::Refresh,
                !state.subscription_busy(&subscription.id),
            )
            .on_hover_text(t().update)
            .clicked()
            {
                actions.push(Action::Update(subscription.id.clone()));
            }
            if icons::icon_button(
                ui,
                Icon::Trash,
                !state.subscription_busy(&subscription.id) && !state.operations.removing,
            )
            .on_hover_text(t().remove)
            .clicked()
            {
                actions.push(Action::RequestRemove(subscription.id.clone()));
            }
            if reorder {
                ui.dnd_drag_source(ui.id().with("handle"), subscription.id.clone(), |ui| {
                    icons::icon_button(ui, Icon::Grip, true);
                });
            } else {
                icons::icon_button(ui, Icon::Grip, false)
                    .on_hover_text(t().subscription_reorder_disabled);
            }
        });
        let age = subscription
            .updated_at_unix
            .map(|timestamp| {
                t().last_updated(&rosetun_core::updated_text(timestamp, display::now_unix()))
            })
            .unwrap_or_else(|| t().never_updated.to_owned());
        ui.add(
            egui::Label::new(
                RichText::new(strings::subscription_summary(
                    &t().servers(subscription.nodes.len()),
                    &age,
                ))
                .small()
                .color(theme::TEXT_DIM),
            )
            .truncate(),
        );
        if let Some(UpdateOutcome::Error(error)) = state.outcomes.get(&subscription.id)
            && theme::dismissible_error(ui, &state.text(&error.to_string()))
        {
            actions.push(Action::DismissOutcome(subscription.id.clone()));
        }
        if !expanded {
            return;
        }
        ui.add_space(6.0);
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
        if let Some(info) = &subscription.info {
            let mut details = rosetun_core::traffic_text(info);
            if let Some(expiry) = info.expire_unix {
                details.push_str(" · ");
                details.push_str(&rosetun_core::expiry_text(expiry, display::now_unix()));
            }
            ui.add(
                egui::Label::new(RichText::new(details).small().color(theme::TEXT_MUTED))
                    .truncate(),
            );
        }
        if subscription.announce.is_some() || !subscription.notices.is_empty() {
            theme::card_frame()
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
                    RichText::new(t().updated(report.added, report.removed, report.retained))
                        .color(theme::ROSE_LIGHT),
                )
                .wrap(),
            );
            if report.selection_cleared {
                ui.add(
                    egui::Label::new(RichText::new(t().selection_cleared).color(theme::ERROR))
                        .wrap(),
                );
            }
            for (reason, count) in &report.skipped {
                ui.add(egui::Label::new(state.text(&t().skipped(*count, reason))).wrap());
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
                let response = ui.add_enabled(
                    state.config_ready && !state.operations.selection && !state.operations.helper,
                    egui::Button::new(text).selected(selected).wrap(),
                );
                if response.clicked() {
                    actions.push(Action::SelectNode(subscription.id.clone(), node.id.clone()));
                }
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
            egui::Rect::from_min_max(rect.min, egui::pos2(rect.left() + 3.0, rect.bottom())),
            0.0,
            theme::ROSE,
        );
    }
    response.response
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

pub(crate) fn remove_dialog(ctx: &egui::Context, state: &State, actions: &mut Vec<Action>) {
    let Some(dialog) = &state.remove else {
        return;
    };
    let response = egui::Modal::new(egui::Id::new("remove_subscription"))
        .frame(theme::modal_frame())
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
                if theme::outline_button(ui, t().cancel, !state.operations.removing).clicked() {
                    actions.push(Action::CancelRemove);
                }
                if theme::button_fill(
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
