use super::*;

pub(super) fn control_cards(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
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
        ui.set_min_height((height - 34.0).max(0.0));
        ui.colored_label(theme::TEXT_DIM, tr!("protection"));
        let mut kill_switch = state.config.settings.kill_switch;
        if widgets::toggle_row(
            ui,
            tr!("kill-switch"),
            tr!("kill-switch-detail"),
            &mut kill_switch,
            state.config_ready && !state.operations.kill_switch && !state.operations.helper,
        )
        .changed()
        {
            actions.push(Action::SetKillSwitch(kill_switch));
        }
        let mut connect_on_start = state.config.interface.connect_on_start;
        if widgets::toggle_row(
            ui,
            tr!("connect-on-start"),
            tr!("connect-on-start-detail"),
            &mut connect_on_start,
            state.can_edit_settings(),
        )
        .changed()
        {
            actions.push(Action::SetConnectOnStart(connect_on_start));
        }
        if tunnel_up(state) && state.pending_reconnect(SessionPart::Protection) {
            ui.label(
                RichText::new(tr!("next-connect"))
                    .small()
                    .color(theme::ROSE_LIGHT),
            );
        }
    });
}

fn rules_card(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>, height: f32) {
    widgets::card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.set_min_height((height - 34.0).max(0.0));
        egui::Sides::new().shrink_left().show(
            ui,
            |ui| {
                ui.label(
                    RichText::new(tr!("rules-title"))
                        .small()
                        .color(theme::TEXT_DIM),
                );
            },
            |ui| {
                if ui
                    .add(
                        egui::Label::new(RichText::new(tr!("open-link")).color(theme::ROSE_LIGHT))
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
                .color(theme::TEXT_DIM),
            );
        }
        if let Some(rules) = state.config.active_rules() {
            let mut enabled = rules.rules.iter().filter(|rule| rule.enabled);
            let mut shown = 0;
            for rule in enabled.by_ref().take(2) {
                shown += 1;
                ui.horizontal(|ui| {
                    let width = (ui.available_width() - 90.0).max(0.0);
                    let value = if matches!(&rule.matcher, RuleMatcher::Template(_)) {
                        crate::rules::rule_lines(&rule.matcher).0
                    } else {
                        rosetun_core::rule_value_text(&rule.matcher)
                    };
                    ui.allocate_ui_with_layout(
                        egui::vec2(width, ui.text_style_height(&egui::TextStyle::Body)),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            ui.set_width(width);
                            ui.add(egui::Label::new(state.text(&value)).truncate());
                        },
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.colored_label(target_color(rule.target), target_label(rule.target));
                    });
                });
            }
            if shown == 0 {
                ui.add(
                    egui::Label::new(
                        RichText::new(tr!("no-rules-yet"))
                            .small()
                            .color(theme::TEXT_DIM),
                    )
                    .wrap(),
                );
            }
            let remaining = enabled.count();
            if remaining > 0 {
                ui.label(
                    RichText::new(crate::i18n::more_rules(remaining))
                        .small()
                        .color(theme::TEXT_DIM),
                );
            }
        } else {
            ui.add(
                egui::Label::new(
                    RichText::new(tr!("no-rules-yet"))
                        .small()
                        .color(theme::TEXT_DIM),
                )
                .wrap(),
            );
        }
        if tunnel_up(state) && state.pending_reconnect(SessionPart::Rules) {
            if state.can_apply() {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    ui.label(
                        RichText::new(tr!("not-applied"))
                            .small()
                            .color(theme::TEXT_DIM),
                    );
                    ui.label(
                        RichText::new(tr!("apply-separator"))
                            .small()
                            .color(theme::TEXT_DIM),
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
                        .color(theme::TEXT_DIM),
                );
            }
        }
    });
}

fn rule_set_picker(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    let name = state
        .config
        .active_rules()
        .map(|rules| state.text(&rules.name))
        .unwrap_or_else(|| tr!("default-rules").to_owned());
    let font = egui::FontId::new(
        egui::TextStyle::Body.resolve(ui.style()).size,
        egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
    );
    let available = ui.available_width();
    let name_width = ui
        .painter()
        .layout_no_wrap(name.clone(), font.clone(), theme::TEXT)
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
                theme::BORDER,
            );
        }
        let color = if enabled {
            theme::TEXT
        } else {
            theme::TEXT_DIM
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
            Icon::Chevron { open: true },
            theme::TEXT_DIM,
        );
    }
    if !enabled {
        return;
    }
    let response = response.on_hover_cursor(egui::CursorIcon::PointingHand);
    widgets::menu_popup(&response).show(|ui| {
        ui.set_min_width(response.rect.width().max(180.0));
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
