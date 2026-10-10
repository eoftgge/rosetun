use super::*;

pub(super) fn template_icon(template: RuleTemplate) -> Icon {
    match template {
        RuleTemplate::RussianSites => Icon::Globe,
        RuleTemplate::Messengers => Icon::Chat,
        RuleTemplate::Youtube => Icon::Play,
        RuleTemplate::Torrents => Icon::Download,
    }
}

pub(super) fn template_section(
    ui: &mut egui::Ui,
    state: &State,
    set: &RuleSet,
    actions: &mut Vec<Action>,
) {
    let font = egui::FontId::new(
        egui::TextStyle::Body.resolve(ui.style()).size,
        egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
    );
    ui.label(
        RichText::new(tr!("rules-templates"))
            .font(font)
            .color(theme::TEXT_MUTED),
    );
    ui.add_space(8.0);
    let width = ((ui.available_width() - 3.0 * 12.0) / 4.0).max(0.0);
    ui.with_layout(egui::Layout::left_to_right(egui::Align::Min), |ui| {
        ui.spacing_mut().item_spacing.x = 12.0;
        for template in RuleTemplate::ALL {
            ui.push_id(template.key(), |ui| {
                template_card(ui, state, set, template, width, actions);
            });
        }
    });
}

pub(super) fn template_card(
    ui: &mut egui::Ui,
    state: &State,
    set: &RuleSet,
    template: RuleTemplate,
    width: f32,
    actions: &mut Vec<Action>,
) {
    let rule = set.rules.iter().find(
        |rule| matches!(&rule.matcher, RuleMatcher::Template(current) if *current == template),
    );
    let target = rule.map_or_else(|| template.default_target(), |rule| rule.target);
    let redundant = rule.is_none() && target == set.default_target;
    ui.allocate_ui_with_layout(
        egui::vec2(width, 0.0),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            ui.set_width(width);
            ui.set_max_width(width);
            let frame = widgets::card_frame().inner_margin(14).stroke(Stroke::new(
                1.0,
                if rule.is_some() {
                    theme::ROSE_DARK
                } else {
                    theme::BORDER
                },
            ));
            let response = frame
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 10.0;
                        let badge = icons::icon_badge(ui, template_icon(template), 30.0);
                        if redundant {
                            badge.on_hover_text(tr!("template-redundant"));
                        }
                        let font = egui::FontId::new(
                            egui::TextStyle::Body.resolve(ui.style()).size,
                            egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(state.text(&crate::i18n::template_name(template)))
                                    .font(font)
                                    .color(theme::TEXT),
                            )
                            .truncate(),
                        )
                        .on_hover_text(if redundant {
                            tr!("template-redundant")
                        } else {
                            crate::i18n::template_name(template)
                        });
                    });
                    ui.add_space(8.0);
                    let description = state.text(&crate::i18n::template_description(template));
                    let height = 2.0 * ui.text_style_height(&egui::TextStyle::Small);
                    let mut job = egui::text::LayoutJob::simple(
                        description.clone(),
                        egui::TextStyle::Small.resolve(ui.style()),
                        theme::TEXT_DIM,
                        ui.available_width(),
                    );
                    job.wrap.max_rows = 2;
                    job.wrap.overflow_character = Some('…');
                    ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.set_min_height(height);
                            ui.add(egui::Label::new(job).wrap())
                                .on_hover_text(if redundant {
                                    tr!("template-redundant").to_owned()
                                } else {
                                    description
                                });
                        },
                    );
                    ui.add_space(10.0);
                    egui::Sides::new().shrink_left().height(30.0).show(
                        ui,
                        |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 6.0;
                                let (rect, dot) = ui.allocate_exact_size(
                                    egui::vec2(7.0, 7.0),
                                    egui::Sense::hover(),
                                );
                                if redundant {
                                    dot.on_hover_text(tr!("template-redundant"));
                                }
                                ui.painter().circle_filled(
                                    rect.center(),
                                    3.5,
                                    target_color(target),
                                );
                                let label = ui.add(
                                    egui::Label::new(
                                        RichText::new(target_label(target))
                                            .small()
                                            .color(target_color(target)),
                                    )
                                    .truncate(),
                                );
                                if redundant {
                                    label.on_hover_text(tr!("template-redundant"));
                                }
                            });
                        },
                        |ui| {
                            let button = if rule.is_some() {
                                widgets::outline_button_compact(
                                    ui,
                                    &tr!("template-added"),
                                    state.can_edit_rules(),
                                )
                                .on_hover_text(tr!("template-remove-hint"))
                            } else {
                                widgets::button_fill_compact(
                                    ui,
                                    &tr!("template-add"),
                                    state.can_edit_rules(),
                                )
                            };
                            let button = if redundant {
                                button.on_hover_text(tr!("template-redundant"))
                            } else {
                                button
                            };
                            if button.clicked() {
                                actions.push(if rule.is_some() {
                                    Action::RemoveTemplate(template)
                                } else {
                                    Action::AddTemplate(template)
                                });
                            }
                        },
                    );
                })
                .response;
            if redundant {
                response.on_hover_text(tr!("template-redundant"));
            }
        },
    );
}
