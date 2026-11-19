use rosetun_ipc::ExitOutcome;

use super::*;
use crate::destinations::exit_country;
use crate::state::SessionExitRow;
use crate::view::settings::delay_mode_hint;

/// "Rules through other servers", with the gap above it: one row per exit of
/// the running session. Returns whether the card was shown.
pub(super) fn exits_card(ui: &mut egui::Ui, state: &State) -> bool {
    let rows = state.session_exit_rows();
    if rows.is_empty() {
        return false;
    }
    let country_column = rows.iter().any(|row| {
        row.exit.and_then(exit_country).is_some() || display::leading_flag(row.node).0.is_some()
    });
    ui.add_space(theme::SECTION_GAP);
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.colored_label(theme::palette().text_dim, tr!("connection-exits"));
        ui.add_space(theme::space::XS);
        ui.spacing_mut().item_spacing.y = theme::space::S;
        for row in &rows {
            exit_row(ui, state, row, country_column);
        }
    });
    true
}

fn exit_row(ui: &mut egui::Ui, state: &State, row: &SessionExitRow<'_>, country_column: bool) {
    let (status, color) = exit_status(row.outcome);
    let (node_country, node_name) = display::leading_flag(row.node);
    let country = row
        .exit
        .and_then(exit_country)
        .map(rosetun_config::CountryCode::as_str)
        .or(node_country.as_deref());
    let actual_country = node_country
        .as_deref()
        .filter(|&code| Some(code) != country);
    egui::Sides::new().shrink_left().spacing(16.0).show(
        ui,
        |ui| {
            ui.horizontal(|ui| {
                let badge_size = egui::Vec2::from(theme::country_badge::ROW_SIZE);
                let slot = country_column.then(|| ui.allocate_space(egui::vec2(badge_size.x, 0.0)));
                let text = ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    let title = row.exit.map_or_else(
                        || tr!("connection-exit-removed"),
                        |exit| state.text(&exit.name),
                    );
                    ui.add(
                        egui::Label::new(RichText::new(title).color(theme::palette().text))
                            .truncate(),
                    );
                    let flags = state.config.interface.show_country_flags;
                    let detail_text =
                        |name| RichText::new(name).small().color(theme::palette().text_dim);
                    let node = widgets::country_label(
                        detail_text(state.text(node_name)),
                        actual_country,
                        flags,
                        false,
                    );
                    let (parent_country, parent_name) =
                        row.via_node.map_or((None, None), |parent| {
                            let (code, name) = display::leading_flag(parent);
                            (code, Some(name))
                        });
                    let detail = if let Some(parent) = parent_name {
                        let mut path = widgets::country_label(
                            detail_text(format!("{} →", state.text(parent))),
                            parent_country.as_deref(),
                            flags,
                            false,
                        );
                        path.extend_right(node);
                        path
                    } else {
                        node
                    };
                    ui.add(egui::WidgetAtom::new(detail).wrap_mode(egui::TextWrapMode::Truncate));
                });
                if let (Some((id, slot)), Some(code)) = (slot, country) {
                    let badge = egui::Rect::from_center_size(
                        egui::pos2(slot.center().x, text.response.rect.center().y),
                        badge_size,
                    );
                    widgets::country_badge(
                        ui,
                        badge,
                        code,
                        state.config.interface.show_country_flags,
                        false,
                    );
                    ui.interact(badge, id, egui::Sense::hover())
                        .on_hover_text(code);
                }
            });
        },
        |ui| {
            ui.label(RichText::new(status).color(color))
                .on_hover_text(delay_mode_hint(state.config.interface.delay_mode));
        },
    );
}

/// The delay column of a row and its colour.
fn exit_status(outcome: Option<ExitOutcome>) -> (String, Color32) {
    match outcome {
        Some(ExitOutcome::Probed(ProbeOutcome::Works { millis })) => (
            tr!("ping-ms", ms = millis.max(1).to_string()),
            theme::palette().text,
        ),
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
            &[("main", "Main node"), ("nl", "🇳🇱 One"), ("de", "DE One")],
            vec![
                exit("a", ExitTarget::Country(CountryCode::parse("NL").unwrap())),
                exit("b", ExitTarget::Country(CountryCode::parse("DE").unwrap())),
                exit("c", ExitTarget::Country(CountryCode::parse("FR").unwrap())),
            ],
        );
        state.status.state = ConnectionState::Connected;
        let nodes = &state.config.subscriptions[0].nodes;
        let extra = |id: &str, node: usize| ExtraNode {
            via: None,
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
                .filter(|(text, color)| text == &tr!("ping-pending")
                    && *color == theme::palette().text_dim)
                .count()
                == 3
        );
    }

    #[test]
    fn rows_show_delay_no_answer_and_no_address() {
        let (_, texts, _) = render(&state(true, Some(delays())), 960.0);
        for (expected, color) in [
            ("Example exit".to_owned(), theme::palette().text),
            ("One".to_owned(), theme::palette().text_dim),
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
        assert!(!texts.iter().any(|(text, _)| text.contains("[NL]")));
        let mut codes = state(true, Some(delays()));
        codes.config.interface.show_country_flags = false;
        let (_, texts, _) = render(&codes, 960.0);
        assert!(texts.iter().any(|(text, _)| text == "NL"));
        assert!(!texts.iter().any(|(text, _)| text.contains("[NL]")));
    }

    #[test]
    fn country_badge_is_centered_on_both_lines() {
        for show_flags in [true, false] {
            let mut state = state(true, Some(delays()));
            state.config.interface.show_country_flags = show_flags;
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            let mut output = ctx.run_ui(input(960.0, 640.0), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| exits_card(ui, &state));
            });
            output.textures_delta.clear();
            let line = |name: &str| {
                output
                    .shapes
                    .iter()
                    .find_map(|shape| match &shape.shape {
                        egui::Shape::Text(text) if text.galley.text() == name => {
                            Some(text.galley.rect.translate(text.pos.to_vec2()))
                        }
                        _ => None,
                    })
                    .unwrap()
            };
            let text = line("Example exit").union(line("One"));
            let badge = output
                .shapes
                .iter()
                .find_map(|shape| match &shape.shape {
                    egui::Shape::Rect(badge)
                        if badge.rect.size() == theme::country_badge::ROW_SIZE.into()
                            && badge.brush.is_some() == show_flags
                            && badge.stroke.color == theme::palette().border_strong =>
                    {
                        Some(badge.rect)
                    }
                    _ => None,
                })
                .unwrap();
            assert!(
                (badge.center().y - text.center().y).abs() <= 0.5,
                "{badge:?} {text:?}"
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
