use super::*;

fn drag_set() -> RuleSet {
    let mut set = RuleSet::new(
        rosetun_config::RuleSetId::new("set"),
        "Test",
        RuleTarget::Proxy,
    );
    set.rules = (0..5)
        .map(|index| Rule {
            id: RuleId::new(index.to_string()),
            enabled: true,
            matcher: RuleMatcher::Domain(rosetun_config::DomainMatch::Exact(format!(
                "{index}.example"
            ))),
            target: RuleTarget::Proxy,
        })
        .collect();
    set
}

#[test]
fn selected_drag_targets_use_the_list_without_selected_rules() {
    let set = drag_set();
    let mut state = State::default();
    state.rules.screen.selected_rules = [RuleId::new("1"), RuleId::new("3")].into();
    assert!(matches!(
        drag_target(&state, &set, &RuleId::new("1"), 0),
        Some((rules, 0)) if rules == [RuleId::new("1"), RuleId::new("3")]
    ));
    assert!(matches!(
        drag_target(&state, &set, &RuleId::new("3"), 2),
        Some((_, 1))
    ));
    assert!(matches!(
        drag_target(&state, &set, &RuleId::new("1"), 4),
        Some((_, 2))
    ));
    state.rules.screen.selected_rules = [RuleId::new("1"), RuleId::new("2")].into();
    assert!(drag_target(&state, &set, &RuleId::new("1"), 2).is_none());
    state.rules.screen.selected_rules = [RuleId::new("1"), RuleId::new("3")].into();
    let (rules, target) = drag_target(&state, &set, &RuleId::new("3"), 5).unwrap();
    assert_eq!(target, 3);
    assert!(matches!(
        drop_action(rules, 5, target),
        Action::DropRules(_, 3)
    ));
    let (rules, target) = drag_target(&state, &set, &RuleId::new("2"), 0).unwrap();
    assert_eq!(rules, vec![RuleId::new("2")]);
    assert!(matches!(
        drop_action(rules, 0, target),
        Action::DropRule(_, 0)
    ));
    assert_eq!(state.rules.screen.selected_rules.len(), 2);
}

fn row_input_actions(
    ctx: &egui::Context,
    state: &State,
    set: &RuleSet,
    events: Vec<egui::Event>,
) -> Vec<Action> {
    let mut actions = Vec::new();
    let mut output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(800.0, 200.0),
            )),
            events,
            ..egui::RawInput::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.push_id((set.id.as_str(), set.rules[0].id.as_str()), |ui| {
                    rule_row(
                        ui,
                        state,
                        set,
                        &set.rules[0],
                        Some(0),
                        (ui.available_width() - 350.0).max(0.0),
                        &mut actions,
                    );
                });
            });
        },
    );
    output.textures_delta.clear();
    actions
}

#[test]
fn row_body_selects_without_selecting_from_the_handle_or_controls() {
    let ctx = egui::Context::default();
    theme::apply(&ctx);
    let set = drag_set();
    let mut state = State::default();
    state.config_ready = true;
    row_input_actions(&ctx, &state, &set, Vec::new());
    for (x, select) in [(150.0, true), (30.0, false), (600.0, false)] {
        let pos = egui::pos2(x, 38.0);
        row_input_actions(
            &ctx,
            &state,
            &set,
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        );
        let actions = row_input_actions(
            &ctx,
            &state,
            &set,
            vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        assert_eq!(
            actions
                .iter()
                .any(|action| matches!(action, Action::SelectRule { .. })),
            select,
            "click at {pos:?}"
        );
    }
    assert!(state.rules.screen.selected_rules.is_empty());
}

#[test]
fn row_click_forwards_ctrl_and_shift_modifiers() {
    let ctx = egui::Context::default();
    theme::apply(&ctx);
    let set = drag_set();
    let state = State::default();
    row_input_actions(&ctx, &state, &set, Vec::new());
    let pos = egui::pos2(150.0, 38.0);
    for (modifiers, additive, range) in [
        (
            egui::Modifiers {
                ctrl: true,
                command: true,
                ..egui::Modifiers::NONE
            },
            true,
            false,
        ),
        (egui::Modifiers::SHIFT, false, true),
    ] {
        row_input_actions(
            &ctx,
            &state,
            &set,
            vec![
                egui::Event::ModifiersChanged(modifiers),
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers,
                },
            ],
        );
        let actions = row_input_actions(
            &ctx,
            &state,
            &set,
            vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers,
            }],
        );
        assert!(matches!(
            actions.as_slice(),
            [Action::SelectRule {
                additive: actual_additive,
                range: actual_range,
                ..
            }] if *actual_additive == additive && *actual_range == range
        ));
    }
}

#[test]
fn clicking_away_clears_selection_but_selected_rows_and_actions_keep_it() {
    let ctx = egui::Context::default();
    let mut state = State::default();
    state.rules.screen.selected_rules.insert(RuleId::new("1"));
    let handle = egui::Rect::from_min_size(egui::pos2(100.0, 20.0), egui::vec2(40.0, 60.0));
    let menu = egui::Rect::from_min_size(egui::pos2(270.0, 20.0), egui::vec2(30.0, 60.0));
    let frame = |events, mut actions: Vec<Action>| {
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(800.0, 200.0),
                )),
                events,
                ..egui::RawInput::default()
            },
            |ctx| clear_selection_on_click_away(ctx, &state, &[handle, menu], &mut actions),
        );
        output.textures_delta.clear();
        actions
    };
    frame(Vec::new(), Vec::new());
    for (pos, clear) in [
        (egui::pos2(150.0, 150.0), true),
        (egui::pos2(110.0, 50.0), false),
        (egui::pos2(285.0, 50.0), false),
        (egui::pos2(150.0, 50.0), true),
        (egui::pos2(500.0, 50.0), true),
    ] {
        frame(
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
            Vec::new(),
        );
        let actions = frame(
            vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }],
            Vec::new(),
        );
        assert_eq!(
            matches!(actions.as_slice(), [Action::ClearRuleSelection]),
            clear,
            "click at {pos:?}"
        );
    }
}

#[test]
fn dragging_near_edges_or_wheeling_scrolls_in_the_expected_direction() {
    let viewport = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 600.0));
    assert!(drag_scroll_delta(viewport, 10.0, 0.0, 1.0 / 60.0) > 0.0);
    assert!(drag_scroll_delta(viewport, 590.0, 0.0, 1.0 / 60.0) < 0.0);
    assert_eq!(drag_scroll_delta(viewport, 300.0, 0.0, 1.0 / 60.0), 0.0);
    assert_eq!(drag_scroll_delta(viewport, 300.0, -72.0, 1.0 / 60.0), -72.0);
    assert!(
        drag_scroll_delta(viewport, 580.0, 0.0, 1.0 / 60.0).abs()
            < drag_scroll_delta(viewport, 595.0, 0.0, 1.0 / 60.0).abs()
    );
}

#[test]
fn dragging_a_rule_scrolls_the_enclosing_area_with_a_wheel() {
    let ctx = egui::Context::default();
    theme::apply(&ctx);
    let frame = |events| {
        let mut offset = 0.0;
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(400.0, 200.0),
                )),
                events,
                ..egui::RawInput::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let result = egui::ScrollArea::vertical()
                        .id_salt("rule_drag_wheel")
                        .scroll_source(egui::scroll_area::ScrollSource {
                            mouse_wheel: false,
                            ..Default::default()
                        })
                        .show(ui, |ui| {
                            ui.ctx().set_dragged_id(egui::Id::new("rule_drag"));
                            ui.allocate_space(egui::vec2(200.0, 600.0));
                            scroll_rules_while_dragging(ui);
                        });
                    offset = result.state.offset.y;
                });
            },
        );
        output.textures_delta.clear();
        offset
    };
    frame(Vec::new());
    egui::DragAndDrop::set_payload(&ctx, RuleId::new("1"));
    let offset = frame(vec![
        egui::Event::PointerMoved(egui::pos2(100.0, 100.0)),
        egui::Event::MouseWheel {
            unit: egui::MouseWheelUnit::Point,
            delta: egui::vec2(0.0, -72.0),
            phase: egui::TouchPhase::Move,
            modifiers: egui::Modifiers::NONE,
        },
    ]);
    let after = frame(vec![egui::Event::PointerMoved(egui::pos2(100.0, 100.0))]);
    assert!(
        offset > 0.0 || after > 0.0,
        "offset after drag wheel: {offset}, {after}"
    );
    let edge = frame(vec![egui::Event::PointerMoved(egui::pos2(100.0, 189.0))]);
    let edge_after = frame(vec![egui::Event::PointerMoved(egui::pos2(100.0, 189.0))]);
    assert!(
        edge > after || edge_after > after,
        "offset after edge drag: {after}, {edge}, {edge_after}"
    );
    egui::DragAndDrop::clear_payload(&ctx);
}

#[test]
fn toolbar_and_hint_reserve_the_same_height() {
    let ctx = egui::Context::default();
    theme::apply(&ctx);
    let mut state = State::default();
    state.config_ready = true;
    for selected in [false, true] {
        state.rules.screen.selected_rules.clear();
        if selected {
            state.rules.screen.selected_rules = [RuleId::new("1"), RuleId::new("2")].into();
        }
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(888.0, 640.0),
                )),
                ..egui::RawInput::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let slot = selection_slot(ui, &state, &mut Vec::new());
                    assert!((slot.rect.height() - 38.0).abs() < 1.0, "{slot:?}");
                });
            },
        );
        output.textures_delta.clear();
    }
}

#[test]
fn table_shortcuts_select_visible_clear_and_ignore_text_focus() {
    let ctx = egui::Context::default();
    let mut state = State::default();
    state.config_ready = true;
    state.rules.screen.selected_rules.insert(RuleId::new("1"));
    for (key, modifiers, focused, expected) in [
        (egui::Key::A, egui::Modifiers::COMMAND, false, true),
        (egui::Key::Escape, egui::Modifiers::NONE, false, true),
        (egui::Key::Delete, egui::Modifiers::NONE, false, true),
        (egui::Key::Escape, egui::Modifiers::NONE, true, false),
        (egui::Key::Delete, egui::Modifiers::NONE, true, false),
    ] {
        let mut actions = Vec::new();
        let mut output = ctx.run_ui(
            egui::RawInput {
                events: vec![egui::Event::Key {
                    key,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers,
                }],
                ..egui::RawInput::default()
            },
            |ctx| selection_shortcuts(ctx, &state, focused, &mut actions),
        );
        output.textures_delta.clear();
        assert_eq!(!actions.is_empty(), expected);
        if expected {
            assert!(matches!(
                actions.as_slice(),
                [Action::SelectVisibleRules
                    | Action::ClearRuleSelection
                    | Action::RequestDeleteSelectedRules]
            ));
        }
    }
    state.rules.screen.delete = Some(DeleteDialog::Set(rosetun_config::RuleSetId::new("1")));
    let mut actions = Vec::new();
    let mut output = ctx.run_ui(
        egui::RawInput {
            events: vec![egui::Event::Key {
                key: egui::Key::Delete,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
            ..egui::RawInput::default()
        },
        |ctx| selection_shortcuts(ctx, &state, false, &mut actions),
    );
    output.textures_delta.clear();
    assert!(actions.is_empty());
}

#[test]
fn apply_notice_centers_text_against_the_link() {
    let ctx = egui::Context::default();
    theme::apply(&ctx);
    let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| {
            let (label, link) = apply_notice(ui, true);
            let link = link.expect("an applicable change shows the link");
            assert!(
                (label.rect.center().y - link.rect.center().y).abs() < 1.0,
                "text: {:?}, link: {:?}",
                label.rect,
                link.rect
            );
        });
    });
    output.textures_delta.clear();
}

#[test]
fn apply_notice_has_no_link_when_the_change_waits_for_reconnect() {
    let ctx = egui::Context::default();
    theme::apply(&ctx);
    let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| {
            let (_, link) = apply_notice(ui, false);
            assert!(link.is_none());
        });
    });
    output.textures_delta.clear();
}

#[test]
fn action_filter_button_matches_the_search_field_height() {
    let ctx = egui::Context::default();
    theme::apply(&ctx);
    let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| {
            let response = target_filter(ui, &RuleFilter::default(), &mut Vec::new());
            assert!(
                (response.rect.height() - 38.0).abs() < 1.0,
                "action filter: {:?}",
                response.rect
            );
        });
    });
    output.textures_delta.clear();
}

#[test]
fn template_cards_keep_a_row_of_equal_sized_non_overlapping_cards() {
    let ctx = egui::Context::default();
    theme::apply(&ctx);
    let mut state = State::default();
    state.config_ready = true;
    for installed in [false, true] {
        let mut set = RuleSet::new(
            rosetun_config::RuleSetId::new("set"),
            "Test",
            RuleTarget::Proxy,
        );
        if installed {
            set.rules = RuleTemplate::ALL
                .into_iter()
                .enumerate()
                .map(|(index, template)| Rule {
                    id: RuleId::new(index.to_string()),
                    enabled: true,
                    matcher: RuleMatcher::Template(template),
                    target: template.default_target(),
                })
                .collect();
        }
        for available in [440.0, 760.0] {
            let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.set_width(available);
                    let width = (available - 36.0) / 4.0;
                    let mut rects = Vec::new();
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Min), |ui| {
                        ui.spacing_mut().item_spacing.x = 12.0;
                        for template in RuleTemplate::ALL {
                            let rect = ui
                                .scope(|ui| {
                                    template_card(
                                        ui,
                                        &state,
                                        &set,
                                        template,
                                        width,
                                        &mut Vec::new(),
                                    );
                                })
                                .response
                                .rect;
                            rects.push(rect);
                        }
                    });
                    for rect in &rects {
                        assert!(rect.width() <= width + 1.0, "{rect:?} vs {width}");
                        assert!((rect.height() - rects[0].height()).abs() < 1.0);
                        assert!(
                            (rect.top() - rects[0].top()).abs() < 1.0,
                            "cards are staggered: {rect:?} vs {:?}",
                            rects[0]
                        );
                    }
                    for pair in rects.windows(2) {
                        assert!(pair[0].right() + 11.0 <= pair[1].left(), "{pair:?}");
                    }
                });
            });
            output.textures_delta.clear();
        }
    }
}

#[test]
fn table_cells_keep_columns_and_center_contents() {
    let ctx = egui::Context::default();
    theme::apply(&ctx);
    let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.set_width(800.0);
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                let handle = table_cell(ui, HANDLE_WIDTH, theme::RULE_ROW, |_| {});
                ui.add_space(HANDLE_GAP);
                let badge = table_cell(ui, ICON_WIDTH, theme::RULE_ROW, |ui| {
                    icons::icon_badge(ui, Icon::App, ICON_WIDTH);
                });
                ui.add_space(ICON_GAP);
                let body_height = ui.text_style_height(&egui::TextStyle::Body);
                let small_height = ui.text_style_height(&egui::TextStyle::Small);
                let mut first_line = egui::Rect::NOTHING;
                let mut second_line = egui::Rect::NOTHING;
                let value = value_cell(ui, 160.0, body_height + small_height, |ui| {
                    first_line = ui.add(egui::Label::new("app.exe").truncate()).rect;
                    second_line = ui
                        .add(
                            egui::Label::new(RichText::new("C:\\Apps\\app.exe").small()).truncate(),
                        )
                        .rect;
                });
                let mut button_rect = egui::Rect::NOTHING;
                let target_cell = table_cell(ui, TARGET_WIDTH, theme::RULE_ROW, |ui| {
                    button_rect = ui
                        .scope(|ui| {
                            target_button(
                                ui,
                                "test_target",
                                RuleTarget::Proxy,
                                &[RuleTarget::Proxy, RuleTarget::Direct],
                                true,
                            );
                        })
                        .response
                        .rect;
                });
                ui.add_space(TARGET_GAP);
                let mut checked = true;
                let mut toggle_rect = egui::Rect::NOTHING;
                let toggle_cell = table_cell(ui, TOGGLE_WIDTH, theme::RULE_ROW, |ui| {
                    toggle_rect = widgets::toggle(ui, &mut checked, true).rect;
                });
                ui.add_space(MENU_GAP);
                let menu_cell = table_cell(ui, MENU_WIDTH, theme::RULE_ROW, |ui| {
                    icons::icon_button_sized(ui, Icon::More, true, MENU_WIDTH);
                });
                assert!((badge.rect.left() - handle.rect.right() - HANDLE_GAP).abs() < 1.0);
                assert!((value.rect.left() - badge.rect.right() - ICON_GAP).abs() < 1.0);
                assert!((target_cell.rect.left() - value.rect.right()).abs() < 1.0);
                assert!(
                    (toggle_cell.rect.left() - target_cell.rect.right() - TARGET_GAP).abs() < 1.0
                );
                assert!((menu_cell.rect.left() - toggle_cell.rect.right() - MENU_GAP).abs() < 1.0);
                assert!((value.rect.height() - theme::RULE_ROW).abs() < 1.0);
                assert!(
                    ((first_line.top() + second_line.bottom()) / 2.0 - value.rect.center().y).abs()
                        < 3.0
                );
                assert!(
                    (button_rect.center().y - target_cell.rect.center().y).abs() < 3.0,
                    "button: {button_rect:?} vs {:?}",
                    target_cell.rect
                );
                assert!((button_rect.center().x - target_cell.rect.center().x).abs() < 3.0);
                assert!(
                    (toggle_rect.center().y - toggle_cell.rect.center().y).abs() < 3.0,
                    "toggle: {toggle_rect:?} vs {:?}",
                    toggle_cell.rect
                );
                assert!((toggle_rect.center().x - toggle_cell.rect.center().x).abs() < 3.0);
            });
        });
    });
    output.textures_delta.clear();
}
