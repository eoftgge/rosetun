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

mod card;
mod servers;

use card::subscription_card;

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
