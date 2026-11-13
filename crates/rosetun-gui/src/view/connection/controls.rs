use rosetun_config::Rule;

use super::*;
use crate::rules::RuleCaption;
use crate::state::SettingsSection;

pub(super) fn control_cards(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    if ui.available_width() < 520.0 {
        protection_card(ui, state, actions, 0.0);
        ui.add_space(theme::SECTION_GAP);
        rules_card(ui, state, actions, 0.0);
        return;
    }
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.x = theme::SECTION_GAP;
        ui.columns(2, |columns| {
            let mut left = columns[0].new_child(
                egui::UiBuilder::new()
                    .max_rect(columns[0].available_rect_before_wrap())
                    .sizing_pass(),
            );
            protection_card(&mut left, state, &mut Vec::new(), 0.0);
            let left_height = left.min_rect().height();
            let mut right = columns[1].new_child(
                egui::UiBuilder::new()
                    .max_rect(columns[1].available_rect_before_wrap())
                    .sizing_pass(),
            );
            rules_card(&mut right, state, &mut Vec::new(), 0.0);
            let right_height = right.min_rect().height();
            let height = left_height.max(right_height);
            protection_card(&mut columns[0], state, actions, height);
            rules_card(&mut columns[1], state, actions, height);
        });
    });
}

fn protection_card(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>, height: f32) {
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.set_min_height((height - widgets::card_chrome_height()).max(0.0));
        ui.colored_label(theme::palette().text_dim, tr!("protection"));
        let lockdown = state.lockdown_active();
        let unavailable = state.kill_switch_unavailable();
        let mut kill_switch = !unavailable && (state.config.settings.kill_switch || lockdown);
        let dim = theme::palette().text_dim;
        let waits = state.waits_for_next_connect(SessionPart::Protection);
        if widgets::toggle_row_with_detail(
            ui,
            tr!("kill-switch"),
            None,
            |ui| {
                if unavailable {
                    ui.add(
                        egui::Label::new(
                            RichText::new(tr!("kill-switch-unavailable"))
                                .small()
                                .color(dim),
                        )
                        .wrap(),
                    );
                    return;
                }
                if !lockdown {
                    widgets::row_detail(ui, &state.session_kill_switch_detail(), waits);
                    return;
                }
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    ui.label(
                        RichText::new(tr!("kill-switch-lockdown"))
                            .small()
                            .color(dim),
                    );
                    ui.label(RichText::new(tr!("apply-separator")).small().color(dim));
                    if widgets::link(ui, &tr!("settings"), true).clicked() {
                        actions.push(Action::OpenSettingsSection(SettingsSection::Connection));
                    }
                    if waits {
                        let muted = theme::palette().text_muted;
                        ui.label(RichText::new(tr!("apply-separator")).small().color(dim));
                        ui.label(RichText::new(tr!("next-connect")).small().color(muted));
                    }
                });
            },
            &mut kill_switch,
            state.config_ready
                && !unavailable
                && !state.operations.kill_switch
                && !state.operations.helper
                && !lockdown,
        )
        .changed()
        {
            actions.push(Action::SetKillSwitch(kill_switch));
        }
        row_divider(ui);
        let mut connect_on_start = state.config.interface.connect_on_start;
        if widgets::toggle_row(
            ui,
            tr!("connect-on-start"),
            None,
            tr!("connect-on-start-detail"),
            &mut connect_on_start,
            state.can_edit_settings(),
        )
        .changed()
        {
            actions.push(Action::SetConnectOnStart(connect_on_start));
        }
    });
}

/// The 1 px BORDER line `widgets::settings_card` draws between its rows.
fn row_divider(ui: &mut egui::Ui) {
    let (line, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 1.0), egui::Sense::hover());
    ui.painter().hline(
        line.x_range(),
        line.center().y,
        (1.0, theme::palette().border),
    );
}

fn rules_card(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>, height: f32) {
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.set_min_height((height - widgets::card_chrome_height()).max(0.0));
        egui::Sides::new().shrink_left().show(
            ui,
            |ui| {
                ui.label(
                    RichText::new(tr!("rules-title"))
                        .small()
                        .color(theme::palette().text_dim),
                );
            },
            |ui| {
                if ui
                    .add(
                        egui::Label::new(
                            RichText::new(tr!("open-link")).color(theme::palette().accent_light),
                        )
                        .sense(egui::Sense::click()),
                    )
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .clicked()
                {
                    actions.push(Action::OpenActiveRules);
                }
            },
        );
        rule_set_picker(ui, state, actions);
        if !state.session.temporary_rules.is_empty() {
            ui.label(
                RichText::new(crate::i18n::temporary_count(
                    state.session.temporary_rules.len(),
                ))
                .small()
                .color(theme::palette().text_dim),
            );
        }
        if let Some(rules) = state.config.active_rules() {
            let mut enabled = rules.rules.iter().filter(|rule| rule.enabled);
            let mut shown = 0;
            for rule in enabled.by_ref().take(2) {
                shown += 1;
                rule_row(ui, state, rule);
            }
            if shown == 0 {
                ui.add(
                    egui::Label::new(
                        RichText::new(tr!("no-rules-yet"))
                            .small()
                            .color(theme::palette().text_dim),
                    )
                    .wrap(),
                );
            }
            let remaining = enabled.count();
            if remaining > 0 {
                ui.label(
                    RichText::new(crate::i18n::more_rules(remaining))
                        .small()
                        .color(theme::palette().text_dim),
                );
            }
        } else {
            ui.add(
                egui::Label::new(
                    RichText::new(tr!("no-rules-yet"))
                        .small()
                        .color(theme::palette().text_dim),
                )
                .wrap(),
            );
        }
        let missing = state.active_missing_categories();
        if missing > 0 {
            ui.horizontal(|ui| {
                ui.colored_label(
                    theme::ERROR,
                    tr!("list-missing-summary", n = missing.to_string()),
                );
                if widgets::link(ui, &tr!("rules"), true).clicked() {
                    actions.push(Action::OpenActiveRules);
                }
            });
        }
        if tunnel_up(state) && state.pending_reconnect(SessionPart::Rules) {
            if state.can_apply() {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    ui.label(
                        RichText::new(tr!("not-applied"))
                            .small()
                            .color(theme::palette().text_dim),
                    );
                    ui.label(
                        RichText::new(tr!("apply-separator"))
                            .small()
                            .color(theme::palette().text_dim),
                    );
                    if widgets::link(ui, &tr!("apply"), true)
                        .on_hover_text(tr!("apply-hint"))
                        .clicked()
                    {
                        actions.push(Action::Apply);
                    }
                });
            } else {
                ui.label(
                    RichText::new(tr!("next-connect"))
                        .small()
                        .color(theme::palette().text_dim),
                );
            }
        }
    });
}

/// Fewest characters of a rule's value kept before its target gives way.
const MIN_VALUE_CHARS: usize = 4;

/// One rule: the value on the left, cut with "…" when short of room, and the target on the
/// right. The target is measured first, so the value gets what it leaves; only when even
/// a few characters of the value would not fit does the target give way too. Returns the
/// rectangles of the value and of the target.
fn rule_row(ui: &mut egui::Ui, state: &State, rule: &Rule) -> (egui::Rect, egui::Rect) {
    let (value, path) = match &rule.matcher {
        RuleMatcher::List { list, category } => {
            (state.list_rule_name(list, category.as_deref()), None)
        }
        matcher => match crate::rules::rule_lines(matcher) {
            (name, RuleCaption::Path(path)) => (name, Some(state.text(&path))),
            (value, _) => (value, None),
        },
    };
    let value = state.text(&value);
    let target = rule_label(rule, &state.config.exits);
    ui.horizontal(|ui| {
        let font = egui::TextStyle::Body.resolve(ui.style());
        let measure = |text: &str| {
            ui.painter()
                .layout_no_wrap(text.to_owned(), font.clone(), Color32::PLACEHOLDER)
                .size()
                .x
                .ceil()
        };
        let total = ui.available_width();
        let gap = ui.spacing().item_spacing.x;
        let kept: String = value.chars().take(MIN_VALUE_CHARS).collect();
        let kept = if kept == value {
            value.clone()
        } else {
            format!("{kept}…")
        };
        let value_width = (total - gap - measure(&target))
            .max(measure(&kept))
            .min((total - gap).max(0.0));
        let target_width = (total - gap - value_width).max(0.0);
        let height = ui.text_style_height(&egui::TextStyle::Body);
        let value_rect = ui
            .allocate_ui_with_layout(
                egui::vec2(value_width, height),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    ui.set_width(value_width);
                    let label = egui::Label::new(value).truncate();
                    match path {
                        Some(path) => ui
                            .add(label.show_tooltip_when_elided(false))
                            .on_hover_text(path),
                        None => ui.add(label),
                    }
                    .rect
                },
            )
            .inner;
        let target_rect = ui
            .allocate_ui_with_layout(
                egui::vec2(target_width, height),
                egui::Layout::right_to_left(egui::Align::Center),
                |ui| {
                    ui.set_width(target_width);
                    ui.add(
                        egui::Label::new(RichText::new(target).color(target_color(rule.target)))
                            .truncate(),
                    )
                    .rect
                },
            )
            .inner;
        (value_rect, target_rect)
    })
    .inner
}

fn rule_set_picker(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let name = state.config.active_rules().map_or_else(
        || tr!("default-rules").to_owned(),
        |rules| state.text(&rules.name),
    );
    let font = egui::FontId::new(
        egui::TextStyle::Body.resolve(ui.style()).size,
        egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
    );
    let available = ui.available_width();
    let name_width = ui
        .painter()
        .layout_no_wrap(name.clone(), font.clone(), theme::palette().text)
        .size()
        .x;
    let text_width = name_width.min((available - 22.0).max(0.0));
    let enabled = state.can_edit_rules();
    let sense = if enabled {
        egui::Sense::click()
    } else {
        egui::Sense::hover()
    };
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(
            text_width + 22.0,
            ui.text_style_height(&egui::TextStyle::Body) + 8.0,
        ),
        sense,
    );
    if ui.is_rect_visible(rect) {
        if enabled && response.hovered() {
            ui.painter().rect_filled(
                rect.expand2(egui::vec2(6.0, 0.0)),
                theme::RADIUS_INNER,
                theme::palette().border,
            );
        }
        let color = if enabled {
            theme::palette().text
        } else {
            theme::palette().text_dim
        };
        let galley = egui::WidgetText::from(RichText::new(name).font(font).color(color))
            .into_galley(
                ui,
                Some(egui::TextWrapMode::Truncate),
                text_width,
                egui::TextStyle::Body,
            );
        ui.painter().galley(
            egui::pos2(rect.left(), rect.center().y - galley.size().y / 2.0),
            galley,
            color,
        );
        icons::paint(
            ui.painter(),
            egui::pos2(rect.left() + text_width + 12.0, rect.center().y),
            Icon::Chevron { open: 1.0 },
            theme::palette().text_dim,
        );
    }
    if !enabled {
        return;
    }
    let response = response.on_hover_cursor(egui::CursorIcon::PointingHand);
    widgets::menu_popup(&response).show(|ui| {
        ui.set_min_width(
            response
                .rect
                .width()
                .max(widgets::MenuWidth::Compact.points()),
        );
        if widgets::menu_item(
            ui,
            widgets::MenuItem {
                label: &tr!("default-rules"),
                enabled: true,
                selected: state.config.active_rule_set.is_none(),
                danger: false,
                note: None,
            },
        )
        .clicked()
        {
            if state.config.active_rule_set.is_some() {
                actions.push(Action::SelectRuleSet(None));
            }
            ui.close();
        }
        for rules in &state.config.rule_sets {
            if widgets::menu_item(
                ui,
                widgets::MenuItem {
                    label: &state.text(&rules.name),
                    enabled: true,
                    selected: state.config.active_rule_set.as_ref() == Some(&rules.id),
                    danger: false,
                    note: None,
                },
            )
            .clicked()
            {
                if state.config.active_rule_set.as_ref() != Some(&rules.id) {
                    actions.push(Action::SelectRuleSet(Some(rules.id.clone())));
                }
                ui.close();
            }
        }
    });
}

fn tunnel_up(state: &State) -> bool {
    state
        .visible_status()
        .is_some_and(|status| status.state.is_active() || status.state.is_transitional())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rosetun_config::{
        CountryCode, DomainMatch, ExitTarget, ProcessMatch, RuleId, RuleSet, RuleSetId, RuleTarget,
    };

    use super::*;
    use crate::destinations::tests::{config, exit};
    use crate::i18n::{self, Language};

    const LONG_PATH: &str = r"E:\Games\Example Games\Example Client\ExampleClientServices.exe";
    const FILE_NAME: &str = "ExampleClientServices.exe";
    /// As long as a target can be and still leave a few characters of the value in the
    /// narrowest two-column card.
    const EXIT_NAME: &str = "Berlin 2";

    /// The first column's width where `control_cards` still uses two columns.
    const TWO_COLUMN_WIDTH: f32 = 520.0;

    struct Shown {
        text: String,
        rect: egui::Rect,
        elided: bool,
    }

    struct Frame {
        shown: Vec<Shown>,
        /// The cards' outlines in drawing order; the last two are the visible ones.
        cards: Vec<egui::Rect>,
        actions: Vec<Action>,
    }

    impl Frame {
        fn find(&self, text: &str) -> &Shown {
            self.shown
                .iter()
                .find(|found| found.text == text)
                .unwrap_or_else(|| panic!("{text:?} not drawn"))
        }

        fn has(&self, text: &str) -> bool {
            self.shown.iter().any(|found| found.text == text)
        }
    }

    fn rule(id: &str, matcher: RuleMatcher, target: RuleTarget, exit: Option<&str>) -> Rule {
        Rule {
            id: RuleId::new(id),
            enabled: true,
            matcher,
            target,
            exit: exit.map(rosetun_config::ExitId::new),
        }
    }

    fn state(exit_name: &str) -> State {
        let mut state = State::default();
        state.helper_available = true;
        state.config_ready = true;
        let mut long_exit = exit("a", ExitTarget::Country(CountryCode::parse("NL").unwrap()));
        long_exit.name = exit_name.to_owned();
        state.config = config(&[("main", "Main node")], vec![long_exit]);
        let mut set = RuleSet::new(RuleSetId::new("set"), "Example set", RuleTarget::Proxy);
        set.rules = vec![
            rule(
                "path",
                RuleMatcher::Process(ProcessMatch::Path(PathBuf::from(LONG_PATH))),
                RuleTarget::Exit,
                Some("a"),
            ),
            rule(
                "domain",
                RuleMatcher::Domain(DomainMatch::Exact("example.com".into())),
                RuleTarget::Direct,
                None,
            ),
        ];
        state.config.rule_sets = vec![set];
        state.config.active_rule_set = Some(RuleSetId::new("set"));
        state
    }

    fn with_lockdown(lockdown: bool) -> State {
        let mut state = state(EXIT_NAME);
        state.status.lockdown = lockdown;
        state
    }

    fn run(
        ctx: &egui::Context,
        state: &State,
        window: egui::Vec2,
        column: f32,
        events: Vec<egui::Event>,
    ) -> Frame {
        let mut actions = Vec::new();
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, window)),
                events,
                ..egui::RawInput::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.scope(|ui| {
                        ui.set_max_width(column);
                        control_cards(ui, state, &mut actions);
                    });
                });
            },
        );
        output.textures_delta.clear();
        let mut shown = Vec::new();
        let mut cards = Vec::new();
        for shape in &output.shapes {
            match &shape.shape {
                egui::Shape::Text(text) => shown.push(Shown {
                    text: text.galley.text().to_owned(),
                    rect: text.galley.rect.translate(text.pos.to_vec2()),
                    elided: text.galley.elided,
                }),
                egui::Shape::Rect(rect) if rect.fill == theme::palette().card => {
                    cards.push(rect.rect);
                }
                _ => {}
            }
        }
        Frame {
            shown,
            cards,
            actions,
        }
    }

    fn themed(state: &State, window: egui::Vec2, column: f32) -> Frame {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        run(&ctx, state, window, column, Vec::new())
    }

    /// Draws the screen, then presses and releases the pointer on the end of `text`.
    fn click(state: &State, window: egui::Vec2, text: &str) -> Vec<Action> {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        // The first frame lays the card out before it knows its own size.
        run(&ctx, state, window, 944.0, Vec::new());
        // Text wrapped after other text has the space before it in its rectangle, so aim at
        // the end of it.
        let rect = run(&ctx, state, window, 944.0, Vec::new()).find(text).rect;
        let pos = egui::pos2(rect.right() - 4.0, rect.center().y);
        let button = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        run(
            &ctx,
            state,
            window,
            944.0,
            vec![egui::Event::PointerMoved(pos), button(true)],
        );
        run(&ctx, state, window, 944.0, vec![button(false)]).actions
    }

    #[test]
    fn a_rules_target_stays_whole_and_clear_of_its_value() {
        for language in [Language::English, Language::Russian] {
            i18n::in_language(language, || {
                let state = state(EXIT_NAME);
                let exit_target = tr!("target-exit", name = EXIT_NAME);
                let direct = tr!("direct");
                for column in [944.0, TWO_COLUMN_WIDTH] {
                    let frame = themed(&state, egui::vec2(960.0, 640.0), column);
                    let place = format!("{language:?}, column {column}");
                    let value = frame.find(FILE_NAME);
                    let target = frame.find(&exit_target);
                    assert!(!value.rect.intersects(target.rect), "{place}");
                    assert!(!target.elided, "{place}: target cut");
                    assert!(value.rect.right() <= target.rect.left(), "{place}");
                    assert_eq!(value.elided, column == TWO_COLUMN_WIDTH, "{place}");
                    let domain = frame.find("example.com");
                    let direct = frame.find(&direct);
                    assert!(!domain.rect.intersects(direct.rect), "{place}");
                    assert!(!domain.elided && !direct.elided, "{place}");
                }
            });
        }
    }

    #[test]
    fn a_target_too_long_for_the_card_is_cut_instead_of_covering_the_value() {
        for language in [Language::English, Language::Russian] {
            i18n::in_language(language, || {
                let name = "An exit whose name is far longer than any card can hold";
                let state = state(name);
                let frame = themed(&state, egui::vec2(960.0, 640.0), TWO_COLUMN_WIDTH);
                let value = frame.find(FILE_NAME);
                let target = frame.find(&tr!("target-exit", name = name));
                assert!(target.elided, "{language:?}");
                assert!(value.elided, "{language:?}");
                assert!(value.rect.width() > 0.0, "{language:?}");
                assert!(value.rect.right() <= target.rect.left(), "{language:?}");
            });
        }
    }

    #[test]
    fn the_connection_screen_has_no_lockdown_switch() {
        for language in [Language::English, Language::Russian] {
            i18n::in_language(language, || {
                for lockdown in [false, true] {
                    let frame = themed(&with_lockdown(lockdown), egui::vec2(960.0, 640.0), 944.0);
                    let place = format!("{language:?}, lockdown {lockdown}");
                    assert!(!frame.has(&tr!("lockdown")), "{place}");
                    assert!(!frame.has(&tr!("experimental")), "{place}");
                    assert!(frame.has(&tr!("kill-switch")), "{place}");
                    assert!(frame.has(&tr!("connect-on-start")), "{place}");
                }
            });
        }
    }

    #[test]
    fn a_kill_switch_held_by_lockdown_links_to_the_settings() {
        for language in [Language::English, Language::Russian] {
            i18n::in_language(language, || {
                let window = egui::vec2(960.0, 640.0);
                let on = with_lockdown(true);
                let frame = themed(&on, window, 944.0);
                assert!(frame.has(&tr!("kill-switch-lockdown")), "{language:?}");
                assert!(!frame.has(&tr!("kill-switch-detail")), "{language:?}");
                let actions = click(&on, window, &tr!("settings"));
                assert!(
                    matches!(
                        actions.as_slice(),
                        [Action::OpenSettingsSection(SettingsSection::Connection)]
                    ),
                    "{language:?}: {} actions",
                    actions.len()
                );
                let off = with_lockdown(false);
                let frame = themed(&off, window, 944.0);
                assert!(!frame.has(&tr!("settings")), "{language:?}");
                assert!(!frame.has(&tr!("kill-switch-lockdown")), "{language:?}");
                assert!(frame.has(&tr!("kill-switch-detail")), "{language:?}");
            });
        }
    }

    #[test]
    fn a_kill_switch_the_helper_cannot_give_says_so_and_does_not_react() {
        let window = egui::vec2(960.0, 640.0);
        for language in [Language::English, Language::Russian] {
            i18n::in_language(language, || {
                let mut none = state(EXIT_NAME);
                none.config.settings.kill_switch = true;
                none.protection = Some(rosetun_config::ProtectionCapabilities::default());
                let frame = themed(&none, window, 944.0);
                assert!(frame.has(&tr!("kill-switch-unavailable")), "{language:?}");
                assert!(!frame.has(&tr!("kill-switch-detail")), "{language:?}");
                let actions = click(&none, window, &tr!("kill-switch-unavailable"));
                assert!(
                    actions.is_empty(),
                    "{language:?}: {} actions",
                    actions.len()
                );

                for protection in [None, Some(crate::worker::FULL_PROTECTION)] {
                    let mut known = state(EXIT_NAME);
                    known.config.settings.kill_switch = true;
                    known.protection = protection;
                    let frame = themed(&known, window, 944.0);
                    let place = format!("{language:?}, {protection:?}");
                    assert!(frame.has(&tr!("kill-switch-detail")), "{place}");
                    assert!(!frame.has(&tr!("kill-switch-unavailable")), "{place}");
                    assert!(
                        matches!(
                            click(&known, window, &tr!("kill-switch-detail")).as_slice(),
                            [Action::SetKillSwitch(false)]
                        ),
                        "{place}"
                    );
                }
            });
        }
    }

    #[test]
    fn both_cards_are_as_tall_as_the_taller_one() {
        for language in [Language::English, Language::Russian] {
            i18n::in_language(language, || {
                for lockdown in [false, true] {
                    for column in [944.0, TWO_COLUMN_WIDTH] {
                        let frame =
                            themed(&with_lockdown(lockdown), egui::vec2(960.0, 640.0), column);
                        let place = format!("{language:?}, lockdown {lockdown}, column {column}");
                        // The sizing passes that measure the cards draw them too.
                        let [left, right] = frame.cards[frame.cards.len() - 2..] else {
                            panic!("{place}: two cards expected");
                        };
                        assert!((left.height() - right.height()).abs() < 0.5, "{place}");
                    }
                }
            });
        }
    }
}
