use super::*;

pub(crate) fn name_dialog(ctx: &egui::Context, state: &mut State, actions: &mut Vec<Action>) {
    let Some(dialog) = &mut state.rules.screen.name else {
        return;
    };
    let busy = state.operations.rules_edit;
    let (title, submit) = match dialog.kind {
        NameDialogKind::Create => (tr!("create-rule-set"), tr!("create-rule-set")),
        NameDialogKind::Rename(_) => (tr!("rename-rule-set"), tr!("rename")),
    };
    let choice = widgets::name_modal(
        ctx,
        widgets::NameModal {
            id: "rule_set_name",
            title,
            label: tr!("set-name"),
            submit,
            name: &mut dialog.name,
            focus: &mut dialog.focus,
            error: &mut dialog.error,
            busy,
            char_limit: None,
        },
    );
    match choice {
        widgets::ModalChoice::Cancel => actions.push(Action::CancelSetName),
        widgets::ModalChoice::Confirm => actions.push(Action::SubmitSetName),
        widgets::ModalChoice::None => {}
    }
}

pub(crate) fn delete_dialog(ctx: &egui::Context, state: &State, actions: &mut Vec<Action>) {
    let Some(id) = &state.rules.screen.delete_set else {
        return;
    };
    let busy = state.operations.rules_edit;
    let choice = widgets::confirm_modal(
        ctx,
        widgets::ConfirmModal {
            id: "delete_rules",
            title: tr!("delete-rule-set"),
            cancel: tr!("cancel"),
            confirm: tr!("delete"),
            busy,
            confirm_enabled: !busy,
            width: widgets::DialogWidth::Standard,
        },
        |ui| {
            if let Some(set) = state.config.rule_sets.iter().find(|set| &set.id == id) {
                ui.label(state.text(&set.name));
            }
            ui.add(egui::Label::new(tr!("delete-rule-set-detail")).wrap());
            if state.config.active_rule_set.as_ref() == Some(id) {
                ui.add(
                    egui::Label::new(
                        RichText::new(tr!("delete-active-rule-set-warning")).color(theme::ERROR),
                    )
                    .wrap(),
                );
            }
        },
    );
    match choice {
        widgets::ModalChoice::Cancel => actions.push(Action::CancelDeleteSet),
        widgets::ModalChoice::Confirm => actions.push(Action::ConfirmDeleteSet),
        widgets::ModalChoice::None => {}
    }
}

pub(crate) fn group_selection_dialog(
    ctx: &egui::Context,
    state: &mut State,
    actions: &mut Vec<Action>,
) {
    if state.rules.screen.group_selection.is_none() {
        return;
    }
    let busy = state.operations.rules_edit;
    let target_choices = table::rule_target_choices(&state.config);
    let exits = state.config.exits.clone();
    let Some(dialog) = &mut state.rules.screen.group_selection else {
        return;
    };
    let mut choice = widgets::ModalChoice::None;
    let mut submitted_by_enter = false;
    let response =
        widgets::Dialog::new("group_selection", widgets::DialogWidth::Standard).show(ctx, |ui| {
            ui.heading(tr!("group-create-title"));
            ui.add_space(theme::space::M);
            ui.label(
                RichText::new(tr!("group-name-label"))
                    .small()
                    .color(theme::palette().text_muted),
            );
            ui.add_space(theme::space::XS);
            let input_id = ui.scope_id().with("group_selection_name");
            let field = ui.add(
                widgets::TextField::new(&mut dialog.name)
                    .id(input_id)
                    .hint(&tr!("group-name-hint"))
                    .char_limit(rosetun_config::RULE_GROUP_NAME_LIMIT)
                    .invalid(dialog.error.is_some())
                    .enabled(!busy),
            );
            if field.changed() {
                dialog.error = None;
            }
            if std::mem::take(&mut dialog.focus) {
                field.request_focus();
            }
            let can_submit = !busy && !dialog.name.trim().is_empty();
            if can_submit
                && field.lost_focus()
                && ui.input(|input| input.key_pressed(egui::Key::Enter))
            {
                submitted_by_enter = true;
            }
            ui.add_space(theme::space::M);
            ui.label(
                RichText::new(tr!("where-to-route"))
                    .small()
                    .color(theme::palette().text_muted),
            );
            ui.add_space(theme::space::XS);
            if let Some(target) = table::target_field(
                ui,
                "group_selection_target",
                &table::TargetChoice::of(dialog.target.clone(), &exits),
                &target_choices,
                !busy,
            ) {
                dialog.target = target;
            }
            if dialog.mixed_targets {
                ui.add_space(theme::space::XS);
                ui.add(
                    egui::Label::new(
                        RichText::new(tr!("group-mixed-target-hint"))
                            .small()
                            .color(theme::palette().text_dim),
                    )
                    .wrap(),
                );
            }
            if let Some(error) = &dialog.error {
                ui.add_space(theme::space::S);
                ui.add(egui::Label::new(RichText::new(error).small().color(theme::ERROR)).wrap());
            }
            let footer = widgets::DialogFooter::new(
                if busy {
                    tr!("saving")
                } else {
                    tr!("group-create-confirm")
                },
                tr!("cancel"),
            )
            .primary_enabled(can_submit)
            .busy(busy);
            choice = widgets::dialog_footer(ui, footer).choice().into();
        });
    if submitted_by_enter {
        choice = widgets::ModalChoice::Confirm;
    } else if choice == widgets::ModalChoice::None && !busy && response.should_close() {
        choice = widgets::ModalChoice::Cancel;
    }
    match choice {
        widgets::ModalChoice::Cancel => actions.push(Action::CancelGroupSelection),
        widgets::ModalChoice::Confirm => actions.push(Action::SubmitGroupSelection),
        widgets::ModalChoice::None => {}
    }
}

pub(crate) fn group_editor_dialog(
    ctx: &egui::Context,
    state: &mut State,
    actions: &mut Vec<Action>,
) {
    if state.rules.screen.group_editor.is_none() {
        return;
    }
    let busy = state.operations.rules_edit;
    let target_choices = table::rule_target_choices(&state.config);
    let exits = state.config.exits.clone();
    let list_names: std::collections::BTreeMap<rosetun_config::ListId, String> = state
        .config
        .lists
        .iter()
        .map(|list| (list.id.clone(), state.text(&list.name)))
        .collect();
    let Some(dialog) = &mut state.rules.screen.group_editor else {
        return;
    };
    let editing = dialog.editing.is_some();
    let mut choice = widgets::ModalChoice::None;
    let response =
        widgets::Dialog::new("group_editor", widgets::DialogWidth::Wide).show(ctx, |ui| {
            ui.heading(if editing {
                tr!("group-edit")
            } else {
                tr!("group-new")
            });
            ui.add_space(theme::space::M);
            ui.label(
                RichText::new(tr!("group-name-label"))
                    .small()
                    .color(theme::palette().text_muted),
            );
            ui.add_space(theme::space::XS);
            let name_id = ui.scope_id().with("group_editor_name");
            let name_invalid = dialog.error.is_some() && dialog.name.trim().is_empty();
            let name_field = ui.add(
                widgets::TextField::new(&mut dialog.name)
                    .id(name_id)
                    .hint(&tr!("group-name-hint"))
                    .char_limit(rosetun_config::RULE_GROUP_NAME_LIMIT)
                    .invalid(name_invalid)
                    .enabled(!busy),
            );
            if name_field.changed() {
                dialog.error = None;
            }
            if std::mem::take(&mut dialog.focus) {
                name_field.request_focus();
            }
            ui.add_space(theme::space::M);
            ui.label(
                RichText::new(tr!("where-to-route"))
                    .small()
                    .color(theme::palette().text_muted),
            );
            ui.add_space(theme::space::XS);
            if let Some(target) = table::target_field(
                ui,
                "group_editor_target",
                &table::TargetChoice::of(dialog.target.clone(), &exits),
                &target_choices,
                !busy,
            ) {
                dialog.target = target;
            }
            ui.add_space(theme::space::L);
            egui::Sides::new().shrink_left().show(
                ui,
                |ui| {
                    ui.label(
                        RichText::new(tr!("group-items-label"))
                            .small()
                            .color(theme::palette().text_muted),
                    );
                },
                |ui| {
                    ui.label(
                        RichText::new(i18n::group_items_count(dialog.items.len()))
                            .small()
                            .color(theme::palette().text_dim),
                    );
                },
            );
            ui.add_space(theme::space::XS);

            // Quick-add input row.
            let add_label = tr!("group-add-item-button");
            let add_width = ui
                .painter()
                .layout_no_wrap(
                    add_label.clone(),
                    egui::TextStyle::Button.resolve(ui.style()),
                    theme::palette().text,
                )
                .size()
                .x
                + 2.0 * ui.spacing().button_padding.x
                + 16.0;
            let gap = theme::space::S;
            let input_width = (ui.available_width() - add_width - gap).max(120.0);
            let mut commit_item = false;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = gap;
                let item_field = ui.add(
                    widgets::TextField::new(&mut dialog.input)
                        .hint(&tr!("group-add-item-hint"))
                        .width(input_width)
                        .invalid(dialog.input_error.is_some())
                        .enabled(!busy),
                );
                if item_field.changed() {
                    dialog.input_error = None;
                }
                if !busy
                    && !dialog.input.trim().is_empty()
                    && item_field.lost_focus()
                    && ui.input(|input| input.key_pressed(egui::Key::Enter))
                {
                    commit_item = true;
                    item_field.request_focus();
                }
                if widgets::outline_button(
                    ui,
                    add_label.as_str(),
                    !busy && !dialog.input.trim().is_empty(),
                )
                .clicked()
                {
                    commit_item = true;
                }
            });
            if commit_item {
                dialog.commit_input();
            }
            if let Some(error) = &dialog.input_error {
                ui.add_space(theme::space::XS);
                ui.add(egui::Label::new(RichText::new(error).small().color(theme::ERROR)).wrap());
            }

            ui.add_space(theme::space::S);
            let mut remove_index = None;
            egui::ScrollArea::vertical()
                .id_salt("group_editor_items")
                .max_height(240.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = theme::space::XS;
                    if dialog.items.is_empty() {
                        ui.label(
                            RichText::new(tr!("group-empty-error"))
                                .small()
                                .color(theme::palette().text_dim),
                        );
                    }
                    for (idx, item) in dialog.items.iter().enumerate() {
                        ui.push_id(idx, |ui| {
                            let (label, caption) = match item {
                                RuleMatcher::List { list, category } => {
                                    let base = list_names
                                        .get(list)
                                        .cloned()
                                        .unwrap_or_else(|| list.as_str().to_owned());
                                    let full = match category {
                                        Some(cat) => format!("{base} · {cat}"),
                                        None => base,
                                    };
                                    (full, tr!("caption-list"))
                                }
                                _ => {
                                    let (val, cap) = rule_lines(item);
                                    (val, table::caption_text(&cap))
                                }
                            };
                            widgets::card_frame()
                                .fill(theme::palette().input)
                                .inner_margin(theme::margin::symmetric(
                                    theme::space::M,
                                    theme::space::XS,
                                ))
                                .show(ui, |ui| {
                                    ui.set_min_width(ui.available_width());
                                    egui::Sides::new().shrink_left().show(
                                        ui,
                                        |ui| {
                                            ui.horizontal(|ui| {
                                                ui.spacing_mut().item_spacing.x = theme::space::S;
                                                icons::icon_badge(ui, table::rule_icon(item), 24.0);
                                                ui.add(
                                                    egui::Label::new(
                                                        RichText::new(&label)
                                                            .color(theme::palette().text),
                                                    )
                                                    .truncate(),
                                                );
                                                ui.add(
                                                    egui::Label::new(
                                                        RichText::new(&caption)
                                                            .small()
                                                            .color(theme::palette().text_dim),
                                                    )
                                                    .truncate(),
                                                );
                                            });
                                        },
                                        |ui| {
                                            if icons::icon_button_sized(
                                                ui,
                                                Icon::Close,
                                                !busy,
                                                24.0,
                                            )
                                            .on_hover_text(tr!("group-remove-item-hint"))
                                            .clicked()
                                            {
                                                remove_index = Some(idx);
                                            }
                                        },
                                    );
                                });
                        });
                    }
                });
            if let Some(idx) = remove_index {
                dialog.remove_item(idx);
            }

            if let Some(error) = &dialog.error {
                ui.add_space(theme::space::S);
                ui.add(egui::Label::new(RichText::new(error).small().color(theme::ERROR)).wrap());
            }

            let can_save = !busy
                && !dialog.name.trim().is_empty()
                && (!dialog.items.is_empty() || !dialog.input.trim().is_empty());
            let primary = if busy {
                tr!("saving")
            } else if editing {
                tr!("save")
            } else {
                tr!("group-create-confirm")
            };
            let footer = widgets::DialogFooter::new(primary, tr!("cancel"))
                .primary_enabled(can_save)
                .busy(busy);
            choice = widgets::dialog_footer(ui, footer).choice().into();
        });
    if choice == widgets::ModalChoice::None && !busy && response.should_close() {
        choice = widgets::ModalChoice::Cancel;
    }
    match choice {
        widgets::ModalChoice::Cancel => actions.push(Action::CancelGroupEditor),
        widgets::ModalChoice::Confirm => actions.push(Action::SubmitGroupEditor),
        widgets::ModalChoice::None => {}
    }
}
