use super::table::{TargetChoice, rule_target_choices, target_button};
use super::*;

pub(super) fn preset_icon(template: RuleTemplate) -> Icon {
    match template {
        RuleTemplate::RussianSites => Icon::Globe,
        RuleTemplate::Messengers => Icon::Chat,
        RuleTemplate::Youtube => Icon::Play,
        RuleTemplate::Torrents => Icon::Download,
        RuleTemplate::AiServices => Icon::Sparkle,
        RuleTemplate::Social => Icon::Chat,
        RuleTemplate::Streaming => Icon::Play,
        RuleTemplate::Gaming => Icon::App,
    }
}

/// Whether `set` already contains a group matching `template` (by localized/default name or items).
pub(super) fn preset_in_set(set: &RuleSet, template: RuleTemplate) -> bool {
    let ru = template.default_name(true).to_lowercase();
    let en = template.default_name(false).to_lowercase();
    let current = crate::i18n::template_name(template).to_lowercase();
    let preset_items = template.matchers();
    set.rules.iter().any(|rule| match &rule.matcher {
        RuleMatcher::Group { name, items } => {
            let lower = name.trim().to_lowercase();
            lower == ru || lower == en || lower == current || *items == preset_items
        }
        _ => false,
    })
}

/// Compact starter cards shown inside an empty rule set, above the default rule.
pub(super) fn starter_section(
    ui: &mut egui::Ui,
    state: &State,
    set: &RuleSet,
    actions: &mut Vec<Action>,
) {
    let font = egui::FontId::new(
        egui::TextStyle::Body.resolve(ui.style()).size,
        egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
    );
    egui::Sides::new().shrink_left().show(
        ui,
        |ui| {
            ui.label(
                RichText::new(tr!("templates-starter-title"))
                    .font(font)
                    .color(theme::palette().text_muted),
            );
        },
        |ui| {
            if widgets::link(ui, &tr!("templates-all-button"), true).clicked() {
                actions.push(Action::OpenTemplatesCatalog);
            }
        },
    );
    ui.add_space(theme::space::S);
    let width = ((ui.available_width() - 3.0 * theme::space::M) / 4.0).max(0.0);
    ui.with_layout(egui::Layout::left_to_right(egui::Align::Min), |ui| {
        ui.spacing_mut().item_spacing.x = theme::space::M;
        for template in RuleTemplate::STARTER {
            ui.push_id(template.key(), |ui| {
                starter_card(ui, state, set, template, width, actions);
            });
        }
    });
    ui.add_space(theme::space::M);
}

pub(super) fn starter_card(
    ui: &mut egui::Ui,
    state: &State,
    set: &RuleSet,
    template: RuleTemplate,
    width: f32,
    actions: &mut Vec<Action>,
) {
    let added = preset_in_set(set, template);
    let target = template.default_target();
    let redundant = !added && target == set.default_target;
    ui.allocate_ui_with_layout(
        egui::vec2(width, 0.0),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            ui.set_width(width);
            ui.set_max_width(width);
            let frame = widgets::card_frame()
                .inner_margin(theme::margin::same(theme::space::M))
                .stroke(Stroke::new(
                    theme::stroke::HAIRLINE,
                    if added {
                        theme::palette().accent_dark
                    } else {
                        theme::palette().border
                    },
                ));
            let response = frame
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = theme::space::S;
                        let badge = icons::icon_badge(ui, preset_icon(template), 30.0);
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
                                    .color(theme::palette().text),
                            )
                            .truncate(),
                        )
                        .on_hover_text(if redundant {
                            tr!("template-redundant")
                        } else {
                            crate::i18n::template_name(template)
                        });
                    });
                    ui.add_space(theme::space::S);
                    let description = state.text(&crate::i18n::template_description(template));
                    let height = 2.0 * ui.text_style_height(&egui::TextStyle::Small);
                    let mut job = egui::text::LayoutJob::simple(
                        description.clone(),
                        egui::TextStyle::Small.resolve(ui.style()),
                        theme::palette().text_dim,
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
                                    tr!("template-redundant")
                                } else {
                                    description
                                });
                        },
                    );
                    ui.add_space(theme::space::S);
                    egui::Sides::new().shrink_left().height(30.0).show(
                        ui,
                        |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = theme::space::XS;
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
                            let button = if added {
                                widgets::outline_button_compact(ui, &tr!("template-added"), false)
                            } else {
                                widgets::outline_button_compact(
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
                            if !added && button.clicked() {
                                actions.push(Action::AddPresetGroup(template, target.into()));
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

fn hairline(ui: &mut egui::Ui) {
    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 1.0), egui::Sense::hover());
    ui.painter().hline(
        rect.x_range(),
        rect.center().y,
        Stroke::new(theme::stroke::HAIRLINE, theme::palette().border),
    );
}

fn items_toggle(ui: &mut egui::Ui, expanded: bool, progress: f32) -> egui::Response {
    let label = if expanded {
        tr!("templates-hide-items")
    } else {
        tr!("templates-show-items")
    };
    let font = egui::TextStyle::Small.resolve(ui.style());
    let galley = ui
        .painter()
        .layout_no_wrap(label.clone(), font, theme::palette().text_muted);
    let chevron_slot = 14.0;
    let gap = theme::space::XS;
    let size = egui::vec2(
        chevron_slot + gap + galley.size().x,
        galley.size().y.max(24.0),
    );
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    if ui.is_rect_visible(rect) {
        let color = if response.hovered() || response.has_focus() {
            theme::palette().text
        } else {
            theme::palette().text_muted
        };
        icons::paint(
            ui.painter(),
            egui::pos2(rect.left() + chevron_slot / 2.0, rect.center().y),
            Icon::Chevron { open: progress },
            color,
        );
        let text_galley = ui.painter().layout_no_wrap(
            label.clone(),
            egui::TextStyle::Small.resolve(ui.style()),
            color,
        );
        ui.painter().galley(
            egui::pos2(
                rect.left() + chevron_slot + gap,
                rect.center().y - text_galley.size().y / 2.0,
            ),
            text_galley,
            color,
        );
    }
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, &label));
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Modal catalog with all built-in presets, per-preset destination picker, and expandable items.
pub(crate) fn catalog_dialog(ctx: &egui::Context, state: &mut State, actions: &mut Vec<Action>) {
    if state.rules.screen.templates_catalog.is_none() {
        return;
    }
    let Some(set_id) = state.rules.screen.selected_set.clone() else {
        return;
    };
    let Some(set_index) = state
        .config
        .rule_sets
        .iter()
        .position(|set| set.id == set_id)
    else {
        return;
    };
    let can_edit = state.can_edit_rules();
    let reduce_motion = state.config.interface.reduce_motion;
    let target_choices = rule_target_choices(&state.config);
    let exits = state.config.exits.clone();
    let default_target = state.config.rule_sets[set_index].default_target;
    let added_flags: Vec<(RuleTemplate, bool)> = RuleTemplate::ALL
        .into_iter()
        .map(|template| {
            (
                template,
                preset_in_set(&state.config.rule_sets[set_index], template),
            )
        })
        .collect();

    let mut close = false;
    let response =
        widgets::Dialog::new("templates_catalog", widgets::DialogWidth::Wide).show(ctx, |ui| {
            egui::Sides::new().shrink_left().show(
                ui,
                |ui| {
                    ui.heading(tr!("templates-dialog-title"));
                },
                |ui| {
                    if widgets::outline_button_compact(ui, &tr!("group-new"), can_edit).clicked() {
                        actions.push(Action::OpenNewGroup);
                    }
                },
            );
            ui.add_space(theme::space::XS);
            ui.add(
                egui::Label::new(
                    RichText::new(tr!("templates-dialog-subtitle"))
                        .color(theme::palette().text_muted),
                )
                .wrap(),
            );
            ui.add_space(theme::space::M);

            let Some(catalog) = state.rules.screen.templates_catalog.as_mut() else {
                return;
            };
            let title_font = egui::FontId::new(
                egui::TextStyle::Body.resolve(ui.style()).size,
                egui::FontFamily::Name(theme::UI_SEMIBOLD.into()),
            );
            let scroll_height = (ui.ctx().content_rect().height() - 240.0).clamp(240.0, 440.0);
            hairline(ui);
            egui::ScrollArea::vertical()
                .id_salt("templates_catalog_scroll")
                .max_height(scroll_height)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    ui.add_space(theme::space::S);
                    ui.spacing_mut().item_spacing.y = theme::space::S;
                    for (template, added) in added_flags {
                        ui.push_id(template.key(), |ui| {
                            let matchers = template.matchers();
                            let destination = catalog.target(template);
                            let redundant = !added
                                && destination
                                    .settled()
                                    .is_some_and(|(t, _)| t == default_target);
                            let expanded = catalog.expanded.contains(&template);
                            let progress = widgets::reveal_progress(
                                ui.ctx(),
                                ui.scope_id().with("items_open"),
                                expanded,
                                reduce_motion,
                            );
                            let frame = widgets::card_frame()
                                .inner_margin(theme::margin::same(theme::space::M))
                                .stroke(Stroke::new(
                                    theme::stroke::HAIRLINE,
                                    if added {
                                        theme::palette().accent_dark
                                    } else {
                                        theme::palette().border
                                    },
                                ));
                            frame.show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = theme::space::M;
                                    icons::icon_badge(ui, preset_icon(template), 32.0);
                                    ui.vertical(|ui| {
                                        ui.spacing_mut().item_spacing.y = theme::space::XS;
                                        ui.horizontal(|ui| {
                                            ui.spacing_mut().item_spacing.x = theme::space::S;
                                            ui.label(
                                                RichText::new(crate::i18n::template_name(template))
                                                    .font(title_font.clone())
                                                    .color(theme::palette().text),
                                            );
                                            ui.label(
                                                RichText::new(crate::i18n::group_items_count(
                                                    matchers.len(),
                                                ))
                                                .small()
                                                .color(theme::palette().text_dim),
                                            );
                                        });
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(crate::i18n::template_description(
                                                    template,
                                                ))
                                                .small()
                                                .color(theme::palette().text_muted),
                                            )
                                            .wrap(),
                                        );
                                    });
                                });
                                ui.add_space(theme::space::M);
                                let mut toggle_items = false;
                                egui::Sides::new().shrink_left().height(34.0).show(
                                    ui,
                                    |ui| {
                                        if items_toggle(ui, expanded, progress).clicked() {
                                            toggle_items = true;
                                        }
                                    },
                                    |ui| {
                                        // Right side of `Sides` lays out right-to-left:
                                        // emit the Add button first so it sits at the far right,
                                        // and the destination picker to its left.
                                        ui.spacing_mut().item_spacing.x = theme::space::S;
                                        ui.spacing_mut().interact_size.y = 34.0;
                                        let button = if added {
                                            widgets::outline_button(
                                                ui,
                                                tr!("template-added"),
                                                false,
                                            )
                                        } else {
                                            widgets::outline_button(
                                                ui,
                                                tr!("template-add"),
                                                can_edit,
                                            )
                                        };
                                        let button = if redundant {
                                            button.on_hover_text(tr!("template-redundant"))
                                        } else {
                                            button
                                        };
                                        if !added && button.clicked() {
                                            actions.push(Action::AddPresetGroup(
                                                template,
                                                catalog.target(template),
                                            ));
                                        }
                                        if let Some(chosen) = target_button(
                                            ui,
                                            "preset_target",
                                            &TargetChoice::of(destination.clone(), &exits),
                                            &target_choices,
                                            !added && can_edit,
                                        ) {
                                            catalog.set_target(template, chosen);
                                        }
                                    },
                                );
                                if toggle_items {
                                    catalog.toggle_expanded(template);
                                }
                                widgets::reveal(
                                    ui,
                                    ui.scope_id().with("items_reveal"),
                                    progress,
                                    |ui| {
                                        ui.add_space(theme::space::S);
                                        ui.horizontal_wrapped(|ui| {
                                            ui.spacing_mut().item_spacing =
                                                egui::Vec2::splat(theme::space::XS);
                                            for item in &matchers {
                                                let text = rule_lines(item).0;
                                                widgets::text_chip(
                                                    ui,
                                                    &text,
                                                    theme::palette().text_muted,
                                                    egui::Sense::hover(),
                                                    false,
                                                );
                                            }
                                        });
                                    },
                                );
                            });
                        });
                    }
                    ui.add_space(theme::space::S);
                });
            hairline(ui);

            if widgets::dialog_done(ui, tr!("done")).clicked() {
                close = true;
            }
        });

    if close || response.should_close() {
        actions.push(Action::CloseTemplatesCatalog);
    }
}
