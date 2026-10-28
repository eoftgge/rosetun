use eframe::egui::{self, Color32, RichText};
use rosetun_config::{ConnectionState, FailureKind, Outbound, RuleMatcher, TlsMode, XrayUse};
use rosetun_ipc::ProbeOutcome;

use crate::actions::{PrimaryAction, ProtectionAction, protection_action};
use crate::errors;
use crate::icons::{self, Icon};
use crate::state::{Action, ExitLookup, ExitRoute, SessionPart, State, TunnelDelay, primary_label};
use crate::{display, i18n, theme, widgets};

use super::rose_button::{self, RosePhase};
use super::rules::{rule_label, target_color};

mod controls;
mod exits;
mod hero;

use controls::control_cards;
use exits::exits_card;
use hero::hero_card;

pub(crate) fn show(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    if !state.config_ready {
        ui.colored_label(theme::palette().text_dim, tr!("loading"));
    }
    if !state.helper_available {
        service_banner(ui, state);
        ui.add_space(theme::SECTION_GAP);
    }
    hero_card(ui, state, actions);
    ui.add_space(theme::SECTION_GAP);
    // Protection right under the hero, so a 960 px window shows it without
    // scrolling; the exits card only reports and comes last.
    control_cards(ui, state, actions);
    exits_card(ui, state);
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
                                .color(theme::palette().text),
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(tr!("service-down-body"))
                                    .small()
                                    .color(theme::palette().text_dim),
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
                    RichText::new(state.text(&errors::client(crate::i18n::language(), error)))
                        .small()
                        .color(theme::palette().text_dim),
                )
                .wrap(),
            );
        }
    });
}

pub(crate) fn state_style(state: &ConnectionState) -> (String, Color32) {
    match state {
        ConnectionState::Disconnected => (tr!("disconnected"), theme::DISCONNECTED),
        ConnectionState::Connecting => (tr!("connecting"), theme::palette().accent_bright),
        ConnectionState::Connected => (tr!("connected"), theme::CONNECTED),
        ConnectionState::Reconnecting => (tr!("reconnecting"), theme::palette().accent_bright),
        ConnectionState::Failed { .. } => (tr!("failed"), theme::ERROR),
        ConnectionState::FailedProtected { .. } => (tr!("failed-protected"), theme::ERROR),
    }
}

pub(crate) fn protection_dialog(ctx: &egui::Context, state: &State, actions: &mut Vec<Action>) {
    let choice = widgets::confirm_modal(
        ctx,
        widgets::ConfirmModal {
            id: "turn_off_protection",
            title: tr!("turn-off-protection"),
            cancel: tr!("keep-blocked"),
            confirm: tr!("turn-off-protection"),
            busy: state.operations.helper,
            confirm_enabled: state.helper_available && !state.operations.helper,
            button_gap: 20.0,
        },
        |ui| {
            ui.add_space(12.0);
            ui.add(
                egui::Label::new(RichText::new(tr!("protection-warning")).color(theme::ERROR))
                    .wrap(),
            );
            if let Some(error) = &state.operation_error {
                ui.add(egui::Label::new(state.text(error)).wrap());
            }
        },
    );
    match choice {
        widgets::ModalChoice::Cancel => actions.push(Action::KeepBlocked),
        widgets::ModalChoice::Confirm => actions.push(Action::ConfirmProtectionOff),
        widgets::ModalChoice::None => {}
    }
}

pub(crate) fn lockdown_dialog(ctx: &egui::Context, state: &State, actions: &mut Vec<Action>) {
    let enabling = state.lockdown_confirmation == Some(true);
    let (title, confirm, body) = if enabling {
        (
            tr!("lockdown-on-question"),
            tr!("lockdown-turn-on"),
            tr!("lockdown-on-body"),
        )
    } else {
        (
            tr!("lockdown-off-question"),
            tr!("lockdown-turn-off"),
            tr!("lockdown-off-body"),
        )
    };
    let choice = widgets::confirm_modal(
        ctx,
        widgets::ConfirmModal {
            id: "lockdown",
            title,
            cancel: tr!("cancel"),
            confirm,
            busy: state.operations.lockdown,
            confirm_enabled: state.can_change_lockdown(),
            button_gap: 20.0,
        },
        |ui| {
            ui.add_space(12.0);
            if enabling {
                ui.add(
                    egui::Label::new(
                        RichText::new(tr!("lockdown-experimental"))
                            .color(theme::palette().text_muted),
                    )
                    .wrap(),
                );
                ui.add_space(8.0);
            }
            ui.add(egui::Label::new(body).wrap());
            if enabling {
                ui.add_space(8.0);
                ui.add(egui::Label::new(tr!("lockdown-virtual-machines")).wrap());
                ui.add_space(8.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(tr!("lockdown-way-out"))
                            .small()
                            .color(theme::palette().text_dim),
                    )
                    .wrap(),
                );
            }
            if let Some(error) = &state.operation_error {
                ui.add(
                    egui::Label::new(RichText::new(state.text(error)).color(theme::ERROR)).wrap(),
                );
            }
        },
    );
    match choice {
        widgets::ModalChoice::Cancel => actions.push(Action::CancelLockdown),
        widgets::ModalChoice::Confirm => actions.push(Action::ConfirmLockdown),
        widgets::ModalChoice::None => {}
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
