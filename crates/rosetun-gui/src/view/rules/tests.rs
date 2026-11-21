use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rosetun_config::{DomainMatch, ProcessMatch};

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
            exit: None,
        })
        .collect();
    set
}

#[test]
fn a_program_rule_shows_the_icon_of_its_path_or_of_a_running_program_by_name() {
    let running = HashMap::from([(
        "example.exe".to_owned(),
        Path::new(r"C:\Apps\Example\Example.exe"),
    )]);
    let by_path = RuleMatcher::Process(ProcessMatch::Path(PathBuf::from(r"D:\Tools\other.exe")));
    assert_eq!(
        program_icon_path(&by_path, &running),
        Some(Path::new(r"D:\Tools\other.exe"))
    );
    let by_name = RuleMatcher::Process(ProcessMatch::Name("EXAMPLE.exe".to_owned()));
    assert_eq!(
        program_icon_path(&by_name, &running),
        Some(Path::new(r"C:\Apps\Example\Example.exe"))
    );
    let not_running = RuleMatcher::Process(ProcessMatch::Name("absent.exe".to_owned()));
    assert_eq!(program_icon_path(&not_running, &running), None);
    let site = RuleMatcher::Domain(DomainMatch::Exact("example.com".to_owned()));
    assert_eq!(program_icon_path(&site, &running), None);
}

fn render_toolbar(
    set: &RuleSet,
    width: f32,
    scale: f32,
    language: crate::i18n::Language,
) -> (ToolbarRects, f32) {
    crate::i18n::in_language(language, || {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut filter = RuleFilter::default();
        let mut rects = None;
        let mut field_height = 0.0;
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(width / scale, 640.0 / scale),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default()
                    .frame(egui::Frame::new().inner_margin(theme::margin::same(theme::space::XXL)))
                    .show(ctx, |ui| {
                        field_height = widgets::field_height(ui);
                        rects = Some(filter_controls(
                            ui,
                            &mut filter,
                            &[],
                            set,
                            &[],
                            true,
                            &mut Vec::new(),
                        ));
                    });
            },
        );
        output.textures_delta.clear();
        (rects.unwrap(), field_height)
    })
}

#[test]
fn toolbar_controls_do_not_overlap_at_minimum_window_scales() {
    let mut set = drag_set();
    set.rules.push(Rule {
        id: RuleId::new("other"),
        enabled: true,
        matcher: RuleMatcher::IpCidr("192.0.2.0/24".to_owned()),
        target: RuleTarget::Direct,
        exit: None,
    });
    for language in [
        crate::i18n::Language::English,
        crate::i18n::Language::Russian,
    ] {
        for (width, scale) in [(960.0, 1.0), (960.0, 1.25), (960.0, 1.5), (1920.0, 1.0)] {
            let (rects, field_height) = render_toolbar(&set, width, scale, language);
            let right = width / scale - theme::space::XXL;
            assert!(
                rects.search.right() <= rects.tabs.left(),
                "{language:?} {width} {scale}"
            );
            assert!(
                rects.filter.right() <= rects.templates.left(),
                "{language:?} {width} {scale}"
            );
            assert!(
                rects.templates.right() <= rects.add.left(),
                "{language:?} {width} {scale}"
            );
            assert!(
                rects.add.right() <= right,
                "{language:?} {width} {scale}: {:?} vs {right}",
                rects.add
            );
            if rects.compact_controls {
                assert_eq!(
                    rects.filter.size(),
                    egui::vec2(field_height, field_height),
                    "{language:?} {width} {scale}"
                );
                assert_eq!(
                    rects.templates.size(),
                    egui::vec2(field_height, field_height),
                    "{language:?} {width} {scale}"
                );
                assert_eq!(
                    rects.add.size(),
                    egui::vec2(field_height, field_height),
                    "{language:?} {width} {scale}"
                );
            } else {
                assert!(
                    rects.filter.width() >= TARGET_FILTER_WIDTH,
                    "{language:?} {width} {scale}"
                );
                assert!(
                    rects.templates.width() > field_height,
                    "{language:?} {width} {scale}"
                );
                assert!(
                    rects.add.width() > field_height,
                    "{language:?} {width} {scale}"
                );
            }
            if rects.two_rows {
                assert!(
                    rects.tabs.bottom() <= rects.filter.top(),
                    "{language:?} {width} {scale}"
                );
                assert!(
                    rects.tabs.bottom() <= rects.templates.top(),
                    "{language:?} {width} {scale}"
                );
                assert!(
                    rects.tabs.bottom() <= rects.add.top(),
                    "{language:?} {width} {scale}"
                );
            } else {
                assert!(
                    rects.tabs.right() <= rects.filter.left(),
                    "{language:?} {width} {scale}"
                );
            }
        }
        let (wide, _) = render_toolbar(&set, 1920.0, 1.0, language);
        assert!(!wide.compact_controls && !wide.two_rows, "{language:?}");
        let (narrow, _) = render_toolbar(&set, 960.0, 1.25, language);
        assert!(narrow.compact_controls, "{language:?}");
    }
}

#[test]
fn rule_set_controls_only_appear_on_rules_tab() {
    let mut state = State::default();
    state.config_ready = true;
    state.config.rule_sets.push(drag_set());
    state.rules.screen.selected_set = Some(rosetun_config::RuleSetId::new("set"));
    state.lists.tab = RulesTab::Rules;
    assert!(set_controls_visible(&state));
    state.lists.tab = RulesTab::Lists;
    assert!(!set_controls_visible(&state));
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
                        &RowContext {
                            set,
                            target_choices: table::rule_target_choices(&state.config),
                            unresolved: &crate::destinations::unresolved_exits(&state.config),
                            running: HashMap::new(),
                        },
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
fn dragging_near_an_edge_scrolls_as_far_at_60_as_at_300_frames_per_second() {
    let viewport = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 600.0));
    let one_second = |frames_per_second: u16| -> f32 {
        let dt = 1.0 / f32::from(frames_per_second);
        (0..frames_per_second)
            .map(|_| drag_scroll_delta(viewport, 10.0, 0.0, dt))
            .sum()
    };
    let at_60 = one_second(60);
    assert!(at_60 > 100.0);
    assert!((at_60 - one_second(300)).abs() < 0.01, "{at_60}");
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
                            ui.ctx().set_dragged_id(egui::Id::unique("rule_drag"));
                            ui.allocate_space(egui::vec2(200.0, 600.0));
                            scroll_rules_while_dragging(ui);
                        });
                    offset = result.state.unclamped_offset().y;
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
        crate::test_ui::wheel(egui::vec2(0.0, -72.0)),
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
    for (selected, line) in [(false, None), (false, Some(check_line(None))), (true, None)] {
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
                    let slot = selection_slot(ui, &state, line.clone(), &mut Vec::new());
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
        (egui::Key::ArrowDown, egui::Modifiers::NONE, false, true),
        (egui::Key::ArrowUp, egui::Modifiers::NONE, false, true),
        (egui::Key::Z, egui::Modifiers::COMMAND, false, true),
        (
            egui::Key::Z,
            egui::Modifiers::COMMAND | egui::Modifiers::SHIFT,
            false,
            true,
        ),
        (egui::Key::Y, egui::Modifiers::COMMAND, false, true),
        (egui::Key::Backspace, egui::Modifiers::NONE, false, false),
        (egui::Key::Escape, egui::Modifiers::NONE, true, false),
        (egui::Key::Delete, egui::Modifiers::NONE, true, false),
        (egui::Key::Z, egui::Modifiers::COMMAND, true, false),
        (egui::Key::ArrowDown, egui::Modifiers::NONE, true, false),
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
                    | Action::DeleteSelectedRules
                    | Action::StepRuleSelection { .. }
                    | Action::UndoRules
                    | Action::RedoRules]
            ));
        }
    }
    state.rules.screen.delete_set = Some(rosetun_config::RuleSetId::new("1"));
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
fn ctrl_z_undoes_and_ctrl_shift_z_or_ctrl_y_redo() {
    let ctx = egui::Context::default();
    let mut state = State::default();
    state.config_ready = true;
    for (key, modifiers, redo) in [
        (egui::Key::Z, egui::Modifiers::COMMAND, false),
        (
            egui::Key::Z,
            egui::Modifiers::COMMAND | egui::Modifiers::SHIFT,
            true,
        ),
        (egui::Key::Y, egui::Modifiers::COMMAND, true),
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
            |ctx| selection_shortcuts(ctx, &state, false, &mut actions),
        );
        output.textures_delta.clear();
        if redo {
            assert!(matches!(actions.as_slice(), [Action::RedoRules]));
        } else {
            assert!(matches!(actions.as_slice(), [Action::UndoRules]));
        }
    }
}

#[test]
fn apply_notice_centers_text_against_the_link() {
    let ctx = egui::Context::default();
    theme::apply(&ctx);
    let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| {
            let (label, link, revert) = apply_notice(ui, true, true);
            let link = link.expect("an applicable change shows the link");
            let revert = revert.expect("a revertible change shows the revert link");
            assert!(
                (label.rect.center().y - link.rect.center().y).abs() < 1.0,
                "text: {:?}, link: {:?}",
                label.rect,
                link.rect
            );
            assert!(revert.rect.left() > link.rect.right());
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
            let (_, link, revert) = apply_notice(ui, false, false);
            assert!(link.is_none());
            assert!(revert.is_none());
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
            let full = target_filter(ui, &RuleFilter::default(), &[], false, &mut Vec::new());
            let compact = target_filter(ui, &RuleFilter::default(), &[], true, &mut Vec::new());
            let mut query = String::new();
            let search = widgets::search_field(ui, &mut query, "", widgets::SEARCH_WIDTH);
            let height = widgets::field_height(ui);
            assert_eq!(full.rect.height(), search.rect.height());
            assert_eq!(full.rect.height(), height);
            assert_eq!(compact.rect.size(), egui::vec2(height, height));
        });
    });
    output.textures_delta.clear();
}

#[test]
fn starter_cards_keep_a_row_of_equal_sized_non_overlapping_cards() {
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
            set.rules = RuleTemplate::STARTER
                .into_iter()
                .enumerate()
                .map(|(index, template)| Rule {
                    id: RuleId::new(index.to_string()),
                    enabled: true,
                    matcher: template.to_group(crate::i18n::template_name(template)),
                    target: template.default_target(),
                    exit: None,
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
                        for template in RuleTemplate::STARTER {
                            let rect = ui
                                .scope(|ui| {
                                    starter_card(
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
fn group_row_expands_drawer_and_renders_items_inline() {
    let mut state = State::default();
    state.config_ready = true;
    state.config.interface.reduce_motion = true;
    let mut set = RuleSet::new(
        rosetun_config::RuleSetId::new("set"),
        "Test",
        RuleTarget::Proxy,
    );
    let group_id = RuleId::new("grp");
    set.rules.push(Rule {
        id: group_id.clone(),
        enabled: true,
        matcher: RuleMatcher::Group {
            name: "Video".into(),
            items: vec![
                RuleMatcher::Domain(DomainMatch::Suffix("youtube.com".into())),
                RuleMatcher::Domain(DomainMatch::Suffix("googlevideo.com".into())),
            ],
        },
        target: RuleTarget::Proxy,
        exit: None,
    });
    let mut screen = crate::test_ui::TestScreen::new(egui::vec2(800.0, 400.0));
    let render = |state: &State, ui: &mut egui::Ui, actions: &mut Vec<Action>| {
        ui.push_id((set.id.as_str(), set.rules[0].id.as_str()), |ui| {
            rule_row(
                ui,
                state,
                &RowContext {
                    set: &set,
                    target_choices: table::rule_target_choices(&state.config),
                    unresolved: &crate::destinations::unresolved_exits(&state.config),
                    running: HashMap::new(),
                },
                &set.rules[0],
                Some(0),
                (ui.available_width() - 350.0).max(0.0),
                actions,
            );
        });
    };

    let collapsed = screen.settle(|ui| render(&state, ui, &mut Vec::new()));
    assert!(collapsed.iter().any(|(text, _)| text == "Video"));
    assert!(!collapsed.iter().any(|(text, _)| text == "googlevideo.com"));

    state.rules.screen.expanded_groups.insert(group_id);
    let expanded = screen.settle(|ui| render(&state, ui, &mut Vec::new()));
    assert!(expanded.iter().any(|(text, _)| text == "youtube.com"));
    assert!(expanded.iter().any(|(text, _)| text == "googlevideo.com"));
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
                                &TargetChoice::plain(RuleTarget::Proxy),
                                &[RuleTarget::Proxy, RuleTarget::Direct].map(TargetChoice::plain),
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

#[test]
fn exit_rules_read_through_their_exit_in_their_own_colour() {
    let exit = crate::destinations::tests::exit(
        "1",
        rosetun_config::ExitTarget::Country(rosetun_config::CountryCode::parse("NL").unwrap()),
    );
    let rule = Rule {
        id: RuleId::new("1"),
        enabled: true,
        matcher: RuleMatcher::Domain(rosetun_config::DomainMatch::Exact("example.com".into())),
        target: RuleTarget::Exit,
        exit: Some(exit.id.clone()),
    };
    assert_eq!(
        rule_label(&rule, std::slice::from_ref(&exit)),
        "Through VPN · Example exit"
    );
    assert_eq!(rule_label(&rule, &[]), "Through an exit");
    let destination = RuleDestination::of(&rule);
    assert_eq!(destination_color(&destination), theme::EXIT);
    assert_ne!(
        destination_color(&destination),
        target_color(RuleTarget::Block)
    );
    let config = crate::destinations::tests::config(&[("a", "🇩🇪 Example")], vec![exit.clone()]);
    let choices = table::rule_target_choices(&config);
    assert_eq!(choices.len(), 4);
    assert_eq!(choices[3].label, "Example exit");
    assert_eq!(choices[3].country, Some(("NL".to_owned(), true)));
    assert!(choices[3].section.is_some());

    assert!(crate::destinations::unresolved_exits(&config).contains(&exit.id));
}

#[test]
fn exit_button_shows_the_exit_name_without_truncation() {
    let mut exit = crate::destinations::tests::exit(
        "1",
        rosetun_config::ExitTarget::Country(rosetun_config::CountryCode::parse("NL").unwrap()),
    );
    exit.name = "Нидерланды".into();
    let exits = std::slice::from_ref(&exit);
    let current = TargetChoice::of(RuleDestination::Exit(exit.id.clone()), exits);
    assert_eq!(current.button, "Нидерланды");
    assert_eq!(current.label, "Through VPN · Нидерланды");
    assert_eq!(
        TargetChoice::plain(RuleTarget::Direct).button,
        tr!("direct")
    );
    let ctx = egui::Context::default();
    theme::apply(&ctx);
    let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| {
            target_button(ui, "exit_target", &current, &[], true);
        });
    });
    output.textures_delta.clear();
    let texts: Vec<_> = output
        .shapes
        .iter()
        .filter_map(|shape| match &shape.shape {
            egui::Shape::Text(text) => Some(text.galley.text().to_owned()),
            _ => None,
        })
        .collect();
    assert_eq!(texts, ["Нидерланды"]);
}

fn check_line(rule: Option<(String, RuleId)>) -> crate::state::CheckLine {
    crate::state::CheckLine {
        text: tr!(
            "rule-check-lead-basis",
            head = "video.example.com → Direct".to_owned(),
            basis = tr!(
                "rule-check-list",
                list = "A long list name for the check".to_owned()
            )
        ),
        rule,
        hint: None,
        target: Some(RuleTarget::Direct),
        answer: true,
    }
}

#[test]
fn the_check_shows_its_answer_and_a_link_that_asks_for_the_rule() {
    for language in [i18n::Language::English, i18n::Language::Russian] {
        i18n::in_language(language, || {
            let mut screen = crate::test_ui::TestScreen::new(egui::vec2(960.0, 640.0));
            let label = tr!("rule-check-number", number = "13".to_owned());
            let mut actions = Vec::new();
            let mut show = |ui: &mut egui::Ui| {
                check::check_result(
                    ui,
                    check_line(Some((label.clone(), RuleId::new("one")))),
                    &mut actions,
                );
            };

            let texts = screen.settle(&mut show);
            let (_, link) = texts.iter().find(|(text, _)| *text == label).unwrap();
            // The link's text starts after the answer, so its middle is not on it.
            let pos = egui::pos2(link.right() - 4.0, link.center().y);
            let button = |pressed| egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            };
            screen.run(
                vec![egui::Event::PointerMoved(pos), button(true)],
                &mut show,
            );
            screen.run(vec![button(false)], &mut show);

            let (_, answer) = texts
                .iter()
                .find(|(text, _)| text.starts_with("video.example.com →"))
                .unwrap();
            assert!(link.right() <= 960.0, "{language:?}: {link:?}");
            // The link follows the answer on its row.
            assert!(
                link.right() > answer.right(),
                "{language:?}: {answer:?} {link:?}"
            );
            assert!(
                (link.center().y - answer.center().y).abs() < 1.0,
                "{language:?}: {answer:?} {link:?}"
            );
            assert!(
                matches!(actions.as_slice(), [Action::ShowCheckedRule(rule)] if rule.as_str() == "one"),
                "{language:?}: one click asks for the rule once"
            );
        });
    }
}

#[test]
fn catalog_dialog_places_destination_picker_to_the_left_of_add_button() {
    for language in [i18n::Language::English, i18n::Language::Russian] {
        i18n::in_language(language, || {
            let mut state = State::default();
            state.config_ready = true;
            state.config.rule_sets.push(drag_set());
            state.rules.screen.selected_set = Some(rosetun_config::RuleSetId::new("set"));
            state.act(Action::OpenTemplatesCatalog);

            let ctx = egui::Context::default();
            theme::apply(&ctx);
            let mut texts = Vec::new();
            for _ in 0..3 {
                let mut actions = Vec::new();
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(1200.0, 800.0),
                        )),
                        ..Default::default()
                    },
                    |ctx| {
                        templates::catalog_dialog(ctx, &mut state, &mut actions);
                    },
                );
                output.textures_delta.clear();
                texts = output
                    .shapes
                    .iter()
                    .filter_map(|shape| match &shape.shape {
                        egui::Shape::Text(text) => Some((
                            text.galley.text().to_owned(),
                            egui::Rect::from_min_size(text.pos, text.galley.size()),
                        )),
                        _ => None,
                    })
                    .collect();
            }

            let add_label = tr!("template-add");
            let direct_label = target_label(RuleTarget::Direct);
            let proxy_label = target_label(RuleTarget::Proxy);
            let show_label = tr!("templates-show-items");
            let add_rects: Vec<_> = texts
                .iter()
                .filter(|(t, _)| t == &add_label)
                .map(|(_, r)| *r)
                .collect();
            assert!(!add_rects.is_empty(), "{language:?}: expected Add buttons");
            for add_rect in add_rects {
                let same_row_target = texts.iter().find(|(t, r)| {
                    (t == &direct_label || t == &proxy_label)
                        && (r.center().y - add_rect.center().y).abs() < 6.0
                });
                let (_, target_rect) = same_row_target.unwrap_or_else(|| {
                    panic!("{language:?}: missing destination picker on row of {add_rect:?}")
                });
                assert!(
                    target_rect.right() < add_rect.left(),
                    "{language:?}: target {target_rect:?} should sit left of Add {add_rect:?}"
                );
                let same_row_toggle = texts.iter().find(|(t, r)| {
                    t == &show_label && (r.center().y - add_rect.center().y).abs() < 6.0
                });
                let (_, toggle_rect) = same_row_toggle.unwrap_or_else(|| {
                    panic!("{language:?}: missing show-items toggle on row of {add_rect:?}")
                });
                assert!(
                    toggle_rect.right() < target_rect.left(),
                    "{language:?}: toggle {toggle_rect:?} should sit left of target {target_rect:?}"
                );
            }
        });
    }
}

#[test]
fn group_editor_dialog_renders_all_item_kinds_in_both_languages() {
    for language in [i18n::Language::English, i18n::Language::Russian] {
        i18n::in_language(language, || {
            let mut state = State::default();
            state.config_ready = true;
            state.config.rule_sets.push(drag_set());
            state.config.lists.push(rosetun_config::List {
                id: rosetun_config::ListId::new("geosite"),
                name: "GeoSite".into(),
                format: rosetun_config::ListFormat::GeoSite,
                source: rosetun_config::ListSource::File {
                    original_name: "geosite.dat".into(),
                },
                categories: vec!["youtube".into(), "ru".into()],
                size: Some(100),
                updated_at: None,
                sha256: Some("abc".into()),
            });
            state.rules.screen.selected_set = Some(rosetun_config::RuleSetId::new("set"));
            state.act(Action::OpenNewGroup);

            let ctx = egui::Context::default();
            theme::apply(&ctx);
            for kind in [
                crate::state::GroupItemKind::Address,
                crate::state::GroupItemKind::Process,
                crate::state::GroupItemKind::List,
            ] {
                state
                    .rules
                    .screen
                    .group_editor
                    .as_mut()
                    .unwrap()
                    .set_item_kind(kind);
                let mut texts = Vec::new();
                for _ in 0..3 {
                    let mut actions = Vec::new();
                    let mut output = ctx.run_ui(
                        egui::RawInput {
                            screen_rect: Some(egui::Rect::from_min_size(
                                egui::Pos2::ZERO,
                                egui::vec2(1200.0, 800.0),
                            )),
                            ..Default::default()
                        },
                        |ctx| {
                            dialogs::group_editor_dialog(ctx, &mut state, &mut actions);
                        },
                    );
                    output.textures_delta.clear();
                    texts = output
                        .shapes
                        .iter()
                        .filter_map(|shape| match &shape.shape {
                            egui::Shape::Text(text) => Some(text.galley.text().to_owned()),
                            _ => None,
                        })
                        .collect();
                }
                assert!(
                    texts.contains(&tr!("rule-kind-address")),
                    "{language:?} {kind:?}: {texts:?}"
                );
                assert!(
                    texts.contains(&tr!("rule-kind-app")),
                    "{language:?} {kind:?}: {texts:?}"
                );
                assert!(
                    texts.contains(&tr!("rule-kind-list")),
                    "{language:?} {kind:?}: {texts:?}"
                );
                if kind == crate::state::GroupItemKind::Address {
                    assert!(
                        texts.contains(&tr!("include-subdomains")),
                        "{language:?}: expected subdomains checkbox"
                    );
                }
                if kind == crate::state::GroupItemKind::List {
                    assert!(
                        texts.iter().any(|t| t == "youtube"),
                        "{language:?}: expected category suggestion chips"
                    );
                }
            }
        });
    }
}

#[test]
fn right_clicking_selected_rules_opens_context_menu_with_group_and_delete() {
    for language in [i18n::Language::English, i18n::Language::Russian] {
        i18n::in_language(language, || {
            let set = drag_set();
            let mut state = State::default();
            state.config_ready = true;
            state.config.rule_sets.push(set.clone());
            state.rules.screen.selected_set = Some(set.id.clone());
            state.rules.screen.selected_rules = [RuleId::new("0"), RuleId::new("1")].into();

            let mut screen = crate::test_ui::TestScreen::new(egui::vec2(960.0, 480.0));
            let render = |ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>| {
                let unresolved = crate::destinations::unresolved_exits(&state.config);
                let choices = table::rule_target_choices(&state.config);
                let row_ctx = RowContext {
                    set: &set,
                    target_choices: choices,
                    unresolved: &unresolved,
                    running: HashMap::new(),
                };
                for idx in 0..3 {
                    ui.push_id(&set.rules[idx].id, |ui| {
                        rule_row(
                            ui,
                            state,
                            &row_ctx,
                            &set.rules[idx],
                            Some(idx),
                            (ui.available_width() - 350.0).max(0.0),
                            actions,
                        );
                    });
                }
            };

            let mut actions = Vec::new();
            let texts = screen.settle(|ui| render(ui, &state, &mut actions));
            let (_, row0_rect) = texts.iter().find(|(text, _)| text == "0.example").unwrap();
            let row0_pos = row0_rect.center();

            // Right-click on a selected row keeps selection and opens multi-selection menu.
            let right_click =
                |screen: &mut crate::test_ui::TestScreen, state: &State, pos: egui::Pos2| {
                    let mut actions = Vec::new();
                    let btn = |pressed| egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Secondary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    };
                    screen.run(vec![egui::Event::PointerMoved(pos), btn(true)], |ui| {
                        render(ui, state, &mut actions);
                    });
                    screen.run(vec![btn(false)], |ui| {
                        render(ui, state, &mut actions);
                    });
                    let texts = screen.run(Vec::new(), |ui| {
                        render(ui, state, &mut actions);
                    });
                    (texts, actions)
                };

            let (menu_texts, menu_actions) = right_click(&mut screen, &state, row0_pos);
            assert!(
                menu_actions.is_empty(),
                "{language:?}: right-clicking an already selected row must not alter selection"
            );
            let group_label = tr!("group-selected");
            let delete_label = crate::i18n::delete_selected_rules(2);
            assert!(
                menu_texts.iter().any(|(t, _)| t == &group_label),
                "{language:?}: expected {group_label:?} in {menu_texts:?}"
            );
            assert!(
                menu_texts.iter().any(|(t, _)| t == &delete_label),
                "{language:?}: expected {delete_label:?} in {menu_texts:?}"
            );

            // Clicking "Group" in the context menu emits OpenGroupSelection.
            let mut actions = Vec::new();
            screen.click_text(&group_label, |ui| render(ui, &state, &mut actions));
            assert!(
                actions
                    .iter()
                    .any(|a| matches!(a, Action::OpenGroupSelection)),
                "{language:?}: expected OpenGroupSelection (got {} actions)",
                actions.len()
            );

            // Right-clicking again and clicking "Delete 2 rules" emits DeleteSelectedRules.
            right_click(&mut screen, &state, row0_pos);
            let mut actions = Vec::new();
            screen.click_text(&delete_label, |ui| render(ui, &state, &mut actions));
            assert!(
                actions
                    .iter()
                    .any(|a| matches!(a, Action::DeleteSelectedRules)),
                "{language:?}: expected DeleteSelectedRules (got {} actions)",
                actions.len()
            );

            // Right-clicking an unselected row selects it cleanly.
            let (_, row2_rect) = texts.iter().find(|(text, _)| text == "2.example").unwrap();
            let (_, row2_actions) = right_click(&mut screen, &state, row2_rect.center());
            assert!(
                row2_actions.iter().any(|a| matches!(
                    a,
                    Action::SelectRule {
                        rule,
                        additive: false,
                        range: false
                    } if rule == &RuleId::new("2")
                )),
                "{language:?}: expected SelectRule for unselected row (got {} actions)",
                row2_actions.len()
            );
        });
    }
}

#[test]
fn context_menu_add_to_group_submenu_emits_add_rules_to_group() {
    for language in [i18n::Language::English, i18n::Language::Russian] {
        i18n::in_language(language, || {
            let group_id = RuleId::new("g0");
            let mut rules = vec![
                Rule {
                    id: RuleId::new("0"),
                    enabled: true,
                    matcher: RuleMatcher::Domain(DomainMatch::Suffix("0.example".into())),
                    target: RuleTarget::Proxy,
                    exit: None,
                },
                Rule {
                    id: RuleId::new("1"),
                    enabled: true,
                    matcher: RuleMatcher::Domain(DomainMatch::Suffix("1.example".into())),
                    target: RuleTarget::Proxy,
                    exit: None,
                },
                Rule {
                    id: group_id.clone(),
                    enabled: true,
                    matcher: RuleMatcher::Group {
                        name: "Games".into(),
                        items: vec![RuleMatcher::Domain(DomainMatch::Suffix(
                            "steam.example".into(),
                        ))],
                    },
                    target: RuleTarget::Direct,
                    exit: None,
                },
            ];
            // Add enough groups (> 8) to exercise the ScrollArea submenu path too,
            // ensuring the very first group ("Games") is never truncated to "...".
            for extra in 1..=9 {
                rules.push(Rule {
                    id: RuleId::new(format!("g{extra}")),
                    enabled: true,
                    matcher: RuleMatcher::Group {
                        name: format!("Group {extra}"),
                        items: vec![RuleMatcher::Domain(DomainMatch::Suffix(format!(
                            "group{extra}.example"
                        )))],
                    },
                    target: RuleTarget::Direct,
                    exit: None,
                });
            }
            let set = RuleSet {
                id: rosetun_config::RuleSetId::new("set"),
                name: "Main".into(),
                default_target: RuleTarget::Direct,
                rules,
            };
            let mut state = State::default();
            state.config_ready = true;
            state.config.rule_sets.push(set.clone());
            state.config.active_rule_set = Some(set.id.clone());
            state.rules.screen.selected_set = Some(set.id.clone());
            state.rules.screen.selected_rules.insert(RuleId::new("0"));
            state.rules.screen.selected_rules.insert(RuleId::new("1"));

            let mut screen = crate::test_ui::TestScreen::new(egui::vec2(960.0, 480.0));
            let render = |ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>| {
                let unresolved = crate::destinations::unresolved_exits(&state.config);
                let choices = table::rule_target_choices(&state.config);
                let row_ctx = RowContext {
                    set: &set,
                    target_choices: choices,
                    unresolved: &unresolved,
                    running: HashMap::new(),
                };
                for idx in 0..3 {
                    ui.push_id(&set.rules[idx].id, |ui| {
                        rule_row(
                            ui,
                            state,
                            &row_ctx,
                            &set.rules[idx],
                            Some(idx),
                            (ui.available_width() - 350.0).max(0.0),
                            actions,
                        );
                    });
                }
            };

            let mut actions = Vec::new();
            let texts = screen.settle(|ui| render(ui, &state, &mut actions));
            let (_, row0_rect) = texts.iter().find(|(text, _)| text == "0.example").unwrap();
            let row0_pos = row0_rect.center();

            // Right-click a selected row to open the context menu.
            let btn = |pressed| egui::Event::PointerButton {
                pos: row0_pos,
                button: egui::PointerButton::Secondary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            };
            screen.run(vec![egui::Event::PointerMoved(row0_pos), btn(true)], |ui| {
                render(ui, &state, &mut actions);
            });
            screen.run(vec![btn(false)], |ui| {
                render(ui, &state, &mut actions);
            });
            let menu_texts = screen.run(Vec::new(), |ui| {
                render(ui, &state, &mut actions);
            });
            let add_to_group = tr!("group-add-to");
            let (_, submenu_rect) = menu_texts
                .iter()
                .find(|(text, _)| text == &add_to_group)
                .unwrap_or_else(|| {
                    panic!("{language:?}: expected {add_to_group:?} in {menu_texts:?}")
                });

            // Hover the "Add to group" submenu trigger to open the target group list.
            let submenu_pos = submenu_rect.center();
            screen.run(vec![egui::Event::PointerMoved(submenu_pos)], |ui| {
                render(ui, &state, &mut actions);
            });
            let submenu_texts = screen.run(Vec::new(), |ui| {
                render(ui, &state, &mut actions);
            });
            // Find the first "Games" item painted inside the scrolled submenu (to the right of the trigger).
            let (_, group_rect) = submenu_texts
                .iter()
                .find(|(text, rect)| text == "Games" && rect.left() > submenu_rect.left())
                .unwrap_or_else(|| {
                    panic!(
                        "{language:?}: expected submenu item 'Games' right of {submenu_rect:?} in {submenu_texts:?}"
                    )
                });

            // Click the target group inside the submenu.
            let target_pos = group_rect.center();
            let primary = |pressed| egui::Event::PointerButton {
                pos: target_pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            };
            let mut click_actions = Vec::new();
            screen.run(
                vec![egui::Event::PointerMoved(target_pos), primary(true)],
                |ui| {
                    render(ui, &state, &mut click_actions);
                },
            );
            screen.run(vec![primary(false)], |ui| {
                render(ui, &state, &mut click_actions);
            });
            assert!(
                click_actions.iter().any(|action| matches!(
                    action,
                    Action::AddRulesToGroup(sources, target)
                        if sources == &vec![RuleId::new("0"), RuleId::new("1")]
                            && target == &group_id
                )),
                "{language:?}: expected AddRulesToGroup([0, 1], g0), got {} actions",
                click_actions.len()
            );
        });
    }
}

#[test]
fn group_editor_dialog_reorders_items_and_renders_reorder_controls() {
    for language in [i18n::Language::English, i18n::Language::Russian] {
        i18n::in_language(language, || {
            let mut state = State::default();
            state.config_ready = true;
            let set_id = rosetun_config::RuleSetId::new("set");
            state.config.rule_sets.push(RuleSet {
                id: set_id.clone(),
                name: "Main".into(),
                default_target: RuleTarget::Direct,
                rules: Vec::new(),
            });
            state.rules.screen.selected_set = Some(set_id);
            state.act(Action::OpenNewGroup);
            let dialog = state.rules.screen.group_editor.as_mut().unwrap();
            dialog.name = "Bundle".into();
            dialog.items = vec![
                RuleMatcher::Domain(DomainMatch::Suffix("first.example".into())),
                RuleMatcher::Domain(DomainMatch::Suffix("second.example".into())),
                RuleMatcher::Domain(DomainMatch::Suffix("third.example".into())),
            ];

            let mut screen = crate::test_ui::TestScreen::new(egui::vec2(760.0, 680.0));
            let mut actions = Vec::new();
            let texts = screen.settle(|ui| {
                dialogs::group_editor_dialog(ui.ctx(), &mut state, &mut actions);
            });
            let first_y = texts
                .iter()
                .find(|(text, _)| text == "first.example")
                .unwrap()
                .1
                .center()
                .y;
            let second_y = texts
                .iter()
                .find(|(text, _)| text == "second.example")
                .unwrap()
                .1
                .center()
                .y;
            let third_y = texts
                .iter()
                .find(|(text, _)| text == "third.example")
                .unwrap()
                .1
                .center()
                .y;
            assert!(first_y < second_y && second_y < third_y);

            // Confirm the 6-dot grip handle on the first row is vertically centered with its text.
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            let mut grip_ys = Vec::new();
            let mut label_y = None;
            for _ in 0..3 {
                let mut frame_actions = Vec::new();
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(760.0, 680.0),
                        )),
                        ..Default::default()
                    },
                    |ctx| {
                        dialogs::group_editor_dialog(ctx, &mut state, &mut frame_actions);
                    },
                );
                output.textures_delta.clear();
                grip_ys.clear();
                label_y = None;
                for clipped in &output.shapes {
                    match &clipped.shape {
                        egui::Shape::Text(text) if text.galley.text() == "first.example" => {
                            let rect = text.galley.rect.translate(text.pos.to_vec2());
                            label_y = Some(rect.center().y);
                        }
                        egui::Shape::Circle(circle) if (circle.radius - 1.0).abs() < 0.05 => {
                            grip_ys.push(circle.center.y);
                        }
                        _ => {}
                    }
                }
            }
            let label_y = label_y.expect("first.example label");
            let first_row_dots: Vec<f32> = grip_ys
                .into_iter()
                .filter(|y| (*y - label_y).abs() < 12.0)
                .collect();
            assert_eq!(first_row_dots.len(), 6, "expected 6 grip dots on first row");
            let grip_center_y = first_row_dots.iter().sum::<f32>() / first_row_dots.len() as f32;
            assert!(
                (grip_center_y - label_y).abs() <= 1.0,
                "{language:?}: grip center {grip_center_y} must align with row label center {label_y}"
            );

            // Reorder via state method and confirm painted vertical order follows.
            state
                .rules
                .screen
                .group_editor
                .as_mut()
                .unwrap()
                .move_item(2, 0);
            let texts_after = screen.settle(|ui| {
                dialogs::group_editor_dialog(ui.ctx(), &mut state, &mut actions);
            });
            let first_y = texts_after
                .iter()
                .find(|(text, _)| text == "first.example")
                .unwrap()
                .1
                .center()
                .y;
            let third_y = texts_after
                .iter()
                .find(|(text, _)| text == "third.example")
                .unwrap()
                .1
                .center()
                .y;
            assert!(
                third_y < first_y,
                "{language:?}: expected third.example above first.example after reorder"
            );
        });
    }
}
