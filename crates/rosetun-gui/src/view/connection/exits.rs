use rosetun_ipc::ExitOutcome;

use super::*;
use crate::state::SessionExitRow;
use crate::view::exits::exit_title;

/// "Rules through other servers", with the gap above it: one row per exit of
/// the running session. Returns whether the card was shown.
pub(super) fn exits_card(ui: &mut egui::Ui, state: &State) -> bool {
    let rows = state.session_exit_rows();
    if rows.is_empty() {
        return false;
    }
    ui.add_space(theme::SECTION_GAP);
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.colored_label(theme::palette().text_dim, tr!("connection-exits"));
        ui.add_space(4.0);
        ui.spacing_mut().item_spacing.y = 8.0;
        for row in &rows {
            exit_row(ui, state, row);
        }
    });
    true
}

fn exit_row(ui: &mut egui::Ui, state: &State, row: &SessionExitRow<'_>) {
    let (status, color) = exit_status(row.outcome);
    egui::Sides::new().shrink_left().spacing(16.0).show(
        ui,
        |ui| {
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                let title = row
                    .exit
                    .map_or_else(|| tr!("connection-exit-removed"), exit_title);
                ui.add(egui::Label::new(RichText::new(title).color(theme::palette().text)).truncate());
                ui.add(
                    egui::Label::new(
                        RichText::new(display::safe_text(&state.text(row.node)))
                            .small()
                            .color(theme::palette().text_dim),
                    )
                    .truncate(),
                );
            });
        },
        |ui| {
            ui.label(RichText::new(status).color(color));
        },
    );
}

/// The delay column of a row and its colour.
fn exit_status(outcome: Option<ExitOutcome>) -> (String, Color32) {
    match outcome {
        Some(ExitOutcome::Probed(ProbeOutcome::Works { millis })) => {
            (tr!("ping-ms", ms = millis.max(1).to_string()), theme::palette().text)
        }
        Some(ExitOutcome::Probed(_)) => (tr!("connection-exit-no-answer"), theme::WARNING),
        Some(ExitOutcome::NoAddress) => (tr!("connection-exit-no-address"), theme::WARNING),
        None => (tr!("ping-pending").to_owned(), theme::palette().text_dim),
    }
}

#[cfg(test)]
mod tests {
    use rosetun_config::{
        CountryCode, ExitId, ExitTarget, RuleSet, RuleSetId, RuleTarget, Selection, Settings,
        SubscriptionId,
    };
    use rosetun_ipc::{ConnectRequest, ExitDelay, ExtraNode, TunnelDelays};

    use super::*;
    use crate::destinations::tests::{config, exit};

    fn selection(node: &str) -> Selection {
        Selection {
            subscription: SubscriptionId::new("sub"),
            node: rosetun_config::NodeId::new(node),
        }
    }

    /// Connected with three exits; `delays` is what the service answered.
    fn state(with_exits: bool, delays: Option<Vec<ExitDelay>>) -> State {
        let mut state = State::default();
        state.helper_available = true;
        state.config_ready = true;
        state.config = config(
            &[("main", "Main node"), ("nl", "NL One"), ("de", "DE One")],
            vec![
                exit("a", ExitTarget::Country(CountryCode::parse("NL").unwrap())),
                exit("b", ExitTarget::Country(CountryCode::parse("DE").unwrap())),
                exit("c", ExitTarget::Country(CountryCode::parse("FR").unwrap())),
            ],
        );
        state.status.state = ConnectionState::Connected;
        let nodes = &state.config.subscriptions[0].nodes;
        let extra = |id: &str, node: usize| ExtraNode {
            exit: ExitId::new(id),
            selection: selection(nodes[node].id.as_str()),
            node: nodes[node].clone(),
        };
        let request = ConnectRequest {
            selection: selection("main"),
            node: nodes[0].clone(),
            rule_set: RuleSet::new(RuleSetId::new("set"), "Set", RuleTarget::Proxy),
            extra_nodes: if with_exits {
                vec![extra("a", 1), extra("b", 2), extra("c", 2)]
            } else {
                Vec::new()
            },
            temporary_rules: Vec::new(),
            lists: Vec::new(),
            settings: Settings::default(),
            rule_templates: Vec::new(),
        };
        state.set_session_request_for_test(request);
        if let Some(exits) = delays {
            state.tunnel_delay = TunnelDelay::Done(TunnelDelays {
                proxy: ProbeOutcome::Works { millis: 30 },
                exits,
            });
        }
        state
    }

    fn delays() -> Vec<ExitDelay> {
        vec![
            ExitDelay {
                exit: ExitId::new("a"),
                outcome: ExitOutcome::Probed(ProbeOutcome::Works { millis: 84 }),
            },
            ExitDelay {
                exit: ExitId::new("b"),
                outcome: ExitOutcome::Probed(ProbeOutcome::Fails),
            },
            ExitDelay {
                exit: ExitId::new("c"),
                outcome: ExitOutcome::NoAddress,
            },
        ]
    }

    fn input(width: f32, height: f32) -> egui::RawInput {
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(width, height),
            )),
            ..egui::RawInput::default()
        }
    }

    fn render(state: &State, width: f32) -> (bool, Vec<(String, Color32)>, egui::Rect) {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut shown = false;
        let mut rect = egui::Rect::NOTHING;
        let mut output = ctx.run_ui(input(width, 640.0), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                shown = exits_card(ui, state);
                rect = ui.min_rect();
            });
        });
        output.textures_delta.clear();
        let texts = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Text(text) => Some((
                    text.galley.text().to_owned(),
                    text.galley.job.sections[0].format.color,
                )),
                _ => None,
            })
            .collect();
        (shown, texts, rect)
    }

    #[test]
    fn card_appears_only_with_exits_in_the_session() {
        let (shown, texts, _) = render(&state(false, None), 960.0);
        assert!(!shown);
        assert!(texts.is_empty());
        let (shown, texts, _) = render(&state(true, None), 960.0);
        assert!(shown);
        assert!(
            texts
                .iter()
                .any(|(text, _)| text == &tr!("connection-exits"))
        );
        assert!(
            texts
                .iter()
                .filter(|(text, color)| text == &tr!("ping-pending") && *color == theme::palette().text_dim)
                .count()
                == 3
        );
    }

    #[test]
    fn rows_show_delay_no_answer_and_no_address() {
        let (_, texts, _) = render(&state(true, Some(delays())), 960.0);
        for (expected, color) in [
            ("Example exit · NL".to_owned(), theme::palette().text),
            ("NL One".to_owned(), theme::palette().text_dim),
            ("DE One".to_owned(), theme::palette().text_dim),
            (tr!("ping-ms", ms = "84"), theme::palette().text),
            (tr!("connection-exit-no-answer"), theme::WARNING),
            (tr!("connection-exit-no-address"), theme::WARNING),
        ] {
            assert!(
                texts
                    .iter()
                    .any(|(text, found)| text == &expected && *found == color),
                "{expected} in {texts:?}"
            );
        }
    }

    #[test]
    fn card_fits_a_small_window() {
        let mut state = state(true, Some(delays()));
        state.config.exits[2].name = "A very long exit name that cannot fit a narrow card".into();
        for width in [360.0, 520.0] {
            let (_, texts, rect) = render(&state, width);
            assert!(rect.right() <= width + 0.5, "{rect:?} in {width}");
            assert!(
                texts
                    .iter()
                    .any(|(text, _)| text == &tr!("connection-exit-no-address"))
            );
        }
    }
}
