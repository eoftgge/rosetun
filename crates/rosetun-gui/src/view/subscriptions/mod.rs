use std::time::Duration;

use eframe::egui::{self, Color32, RichText, Stroke};
use rosetun_config::{
    ConnectionState, ListSource, Node, NodeId, Outbound, Subscription, SubscriptionId,
    SubscriptionInfo,
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
                            && (!state.config.subscriptions.is_empty()
                                || state
                                    .config
                                    .lists
                                    .iter()
                                    .any(|list| matches!(&list.source, ListSource::Url(_))))
                            && !state.operations.update_all
                            && state.operations.updating.is_empty()
                            && state.operations.updating_lists.is_empty()
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
                            .map_or_else(
                                || tr!("auto-update-on"),
                                |hours| tr!("auto-update-every", hours = hours.to_string()),
                            );
                        ui.add(
                            egui::Label::new(RichText::new(text).small().color(theme::palette().text_dim))
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
                .color(theme::palette().text)
                .font(egui::FontId::new(
                    15.0,
                    egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
                )),
        );
        ui.label(
            RichText::new(format!("· {}", state.config.subscriptions.len())).color(theme::palette().text_dim),
        );
    });
    ui.add_space(12.0);
    egui::ScrollArea::vertical()
        .id_salt("subscription_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if state.config.subscriptions.is_empty() {
                ui.colored_label(theme::palette().text_muted, tr!("no-subscriptions"));
                ui.add_space(8.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(tr!("empty-subscriptions")).color(theme::palette().text_dim),
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
                        if state.subscriptions.reveal_card.as_ref() == Some(&subscription.id) {
                            response.response.scroll_to_me(Some(egui::Align::Min));
                            actions.push(Action::RevealDone);
                        }
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
                                    Stroke::new(2.0, theme::palette().accent_base),
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
        .layout_no_wrap(text.to_owned(), font.clone(), theme::palette().accent_light)
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
            theme::palette().accent_light
        } else {
            theme::palette().text_dim
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
                Stroke::new(1.0, theme::palette().accent_light),
            );
        }
    }
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

/// `shown` is the link as `rosetun_core::provider_link` cleaned it; `link`
/// itself only goes to the browser.
fn provider_link(ui: &mut egui::Ui, state: &State, label: &str, link: &str, shown: &str) {
    if display::safe_web_url(link).is_some() {
        let response = widgets::link(ui, label, true);
        if response.clicked() {
            display::open_web_link(ui.ctx(), link);
        }
        response.on_hover_text(state.text(shown));
    } else {
        ui.add(
            egui::Label::new(
                RichText::new(state.text(&i18n::plain_link(label, shown))).color(theme::palette().text_dim),
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
    let choice = widgets::name_modal(
        ctx,
        widgets::NameModal {
            id: "rename_subscription",
            title: tr!("rename-subscription"),
            label: tr!("subscription-name"),
            submit: tr!("rename"),
            name: &mut dialog.name,
            focus: &mut dialog.focus,
            error: &mut dialog.error,
            busy,
            char_limit: Some(rosetun_core::SUBSCRIPTION_NAME_LIMIT),
        },
    );
    match choice {
        widgets::ModalChoice::Cancel => actions.push(Action::CancelRename),
        widgets::ModalChoice::Confirm => actions.push(Action::SubmitRename),
        widgets::ModalChoice::None => {}
    }
}

pub(crate) fn remove_dialog(ctx: &egui::Context, state: &State, actions: &mut Vec<Action>) {
    let Some(dialog) = &state.subscriptions.remove else {
        return;
    };
    let choice = widgets::confirm_modal(
        ctx,
        widgets::ConfirmModal {
            id: "remove_subscription",
            title: tr!("remove-subscription"),
            cancel: tr!("cancel"),
            confirm: if state.operations.removing {
                tr!("removing")
            } else {
                tr!("remove")
            },
            busy: state.operations.removing,
            confirm_enabled: !state.operations.removing,
            button_gap: 20.0,
        },
        |ui| {
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
        },
    );
    match choice {
        widgets::ModalChoice::Cancel => actions.push(Action::CancelRemove),
        widgets::ModalChoice::Confirm => actions.push(Action::ConfirmRemove),
        widgets::ModalChoice::None => {}
    }
}
