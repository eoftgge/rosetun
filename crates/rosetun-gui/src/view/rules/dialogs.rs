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
                        RichText::new(tr!("delete-active-rule-set-warning")).color(theme::error()),
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
                ui.add(egui::Label::new(RichText::new(error).small().color(theme::error())).wrap());
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
    let reduce_motion = state.config.interface.reduce_motion;
    let target_choices = table::rule_target_choices(&state.config);
    let exits = state.config.exits.clone();
    let lists = state.config.lists.clone();
    let list_names: std::collections::BTreeMap<rosetun_config::ListId, String> = lists
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
            ui.add_space(theme::space::S);

            let kinds = [
                (
                    crate::state::GroupItemKind::Address,
                    tr!("rule-kind-address"),
                ),
                (crate::state::GroupItemKind::Process, tr!("rule-kind-app")),
                (crate::state::GroupItemKind::List, tr!("rule-kind-list")),
            ];
            if let Some(kind) = widgets::segmented(
                ui,
                "group_editor_kind",
                dialog.item_kind,
                &kinds,
                true,
                !busy,
            ) {
                dialog.set_item_kind(kind);
            }
            ui.add_space(theme::space::S);

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

            let kind_appear = widgets::appear_progress(
                ui.ctx(),
                ui.scope_id().with("group_editor_kind_appear"),
                dialog.item_kind,
                reduce_motion,
            );
            widgets::appear(ui, kind_appear, |ui| match dialog.item_kind {
                crate::state::GroupItemKind::Address => {
                    let mut commit_item = false;
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = gap;
                        let item_field = ui.add(
                            widgets::TextField::new(&mut dialog.input)
                                .id(ui.scope_id().with("group_address_input"))
                                .hint(&tr!("group-address-hint"))
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
                    ui.add_space(theme::space::XS);
                    egui::Sides::new().shrink_left().show(
                        ui,
                        |ui| {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(tr!("group-address-tip"))
                                        .small()
                                        .color(theme::palette().text_dim),
                                )
                                .wrap(),
                            );
                        },
                        |ui| {
                            widgets::checkbox(
                                ui,
                                &mut dialog.subdomains,
                                tr!("include-subdomains"),
                                !busy,
                            )
                            .on_hover_text(tr!("include-subdomains-detail"));
                        },
                    );
                }
                crate::state::GroupItemKind::Process => {
                    let hint = if cfg!(windows) {
                        tr!("group-process-hint-windows")
                    } else {
                        tr!("group-process-hint-unix")
                    };
                    let tip = if cfg!(windows) {
                        tr!("group-process-tip-windows")
                    } else {
                        tr!("group-process-tip-unix")
                    };
                    let mut commit_item = false;
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = gap;
                        let item_field = ui.add(
                            widgets::TextField::new(&mut dialog.input)
                                .id(ui.scope_id().with("group_process_input"))
                                .hint(&hint)
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
                    ui.add_space(theme::space::XS);
                    ui.add(
                        egui::Label::new(
                            RichText::new(tip).small().color(theme::palette().text_dim),
                        )
                        .wrap(),
                    );
                }
                crate::state::GroupItemKind::List => {
                    if lists.is_empty() {
                        ui.add(
                            egui::Label::new(
                                RichText::new(tr!("rule-list-empty"))
                                    .small()
                                    .color(theme::palette().text_dim),
                            )
                            .wrap(),
                        );
                    } else {
                        if dialog
                            .list
                            .as_ref()
                            .is_none_or(|id| !lists.iter().any(|list| &list.id == id))
                        {
                            dialog.select_list(lists[0].id.clone());
                        }
                        let mut picked_list = None;
                        let selected_index = lists
                            .iter()
                            .position(|list| Some(&list.id) == dialog.list.as_ref())
                            .unwrap_or(0);
                        let selected = &lists[selected_index];
                        let selected_label = list_names
                            .get(&selected.id)
                            .cloned()
                            .unwrap_or_else(|| selected.name.clone());
                        let has_categories = selected.format.has_categories();

                        if has_categories {
                            ui.add_enabled_ui(!busy, |ui| {
                                widgets::drop_down(
                                    ui,
                                    "group_editor_list",
                                    None,
                                    selected_label.as_str(),
                                    |ui| {
                                        for list in &lists {
                                            let name = list_names
                                                .get(&list.id)
                                                .map_or(list.name.as_str(), String::as_str);
                                            if widgets::menu_item(
                                                ui,
                                                widgets::MenuItem {
                                                    label: name,
                                                    enabled: true,
                                                    selected: list.id == selected.id,
                                                    danger: false,
                                                    note: None,
                                                },
                                            )
                                            .clicked()
                                            {
                                                picked_list = Some(list.id.clone());
                                                ui.close();
                                            }
                                        }
                                    },
                                );
                            });
                        } else {
                            let mut commit_list = false;
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = gap;
                                ui.add_enabled_ui(!busy, |ui| {
                                    widgets::drop_down(
                                        ui,
                                        "group_editor_list",
                                        Some(input_width),
                                        selected_label.as_str(),
                                        |ui| {
                                            for list in &lists {
                                                let name = list_names
                                                    .get(&list.id)
                                                    .map_or(list.name.as_str(), String::as_str);
                                                if widgets::menu_item(
                                                    ui,
                                                    widgets::MenuItem {
                                                        label: name,
                                                        enabled: true,
                                                        selected: list.id == selected.id,
                                                        danger: false,
                                                        note: None,
                                                    },
                                                )
                                                .clicked()
                                                {
                                                    picked_list = Some(list.id.clone());
                                                    ui.close();
                                                }
                                            }
                                        },
                                    );
                                });
                                if widgets::outline_button(ui, add_label.as_str(), !busy).clicked()
                                {
                                    commit_list = true;
                                }
                            });
                            if commit_list {
                                dialog.commit_list(selected);
                            }
                        }

                        if let Some(id) = picked_list {
                            dialog.select_list(id);
                        }
                        let selected = lists
                            .iter()
                            .find(|list| Some(&list.id) == dialog.list.as_ref())
                            .unwrap_or(&lists[0]);
                        if selected.format.has_categories() {
                            ui.add_space(theme::space::XS);
                            let mut commit_list = false;
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = gap;
                                let cat_field = ui.add(
                                    widgets::TextField::new(&mut dialog.category)
                                        .id(ui.scope_id().with("group_list_category"))
                                        .hint(&tr!("group-list-category-hint"))
                                        .width(input_width)
                                        .invalid(dialog.input_error.is_some())
                                        .enabled(!busy),
                                );
                                if cat_field.changed() {
                                    dialog.input_error = None;
                                }
                                if !busy
                                    && !dialog.category.trim().is_empty()
                                    && cat_field.lost_focus()
                                    && ui.input(|input| input.key_pressed(egui::Key::Enter))
                                {
                                    commit_list = true;
                                    cat_field.request_focus();
                                }
                                if widgets::outline_button(
                                    ui,
                                    add_label.as_str(),
                                    !busy && !dialog.category.trim().is_empty(),
                                )
                                .clicked()
                                {
                                    commit_list = true;
                                }
                            });
                            if commit_list {
                                dialog.commit_list(selected);
                            }
                            if !selected.categories.is_empty() {
                                let suggestions = group_category_suggestions(
                                    &selected.categories,
                                    &dialog.category,
                                );
                                if !suggestions.is_empty() {
                                    ui.add_space(theme::space::XS);
                                    let mut toggled = None;
                                    ui.horizontal_wrapped(|ui| {
                                        ui.spacing_mut().item_spacing =
                                            egui::Vec2::splat(theme::space::XS);
                                        for category in suggestions {
                                            let added = dialog
                                                .contains_list_category(&selected.id, category);
                                            let color = if busy {
                                                theme::disabled()
                                            } else if added {
                                                theme::palette().accent_light
                                            } else {
                                                theme::palette().text_muted
                                            };
                                            let chip = widgets::text_chip(
                                                ui,
                                                category,
                                                color,
                                                if busy {
                                                    egui::Sense::hover()
                                                } else {
                                                    egui::Sense::click()
                                                },
                                                added,
                                            );
                                            let chip = if busy {
                                                chip
                                            } else {
                                                chip.on_hover_cursor(egui::CursorIcon::PointingHand)
                                            };
                                            if !busy && chip.clicked() {
                                                toggled = Some(category.to_owned());
                                            }
                                        }
                                    });
                                    if let Some(category) = toggled {
                                        dialog.toggle_list_category(selected, &category);
                                    }
                                }
                            }
                        }
                    }
                }
            });

            if let Some(error) = &dialog.input_error {
                ui.add_space(theme::space::XS);
                ui.add(egui::Label::new(RichText::new(error).small().color(theme::error())).wrap());
            }

            ui.add_space(theme::space::S);
            let mut remove_index = None;
            let mut move_item = None;
            let item_count = dialog.items.len();
            let can_reorder = !busy && item_count > 1;
            let dragged_item = egui::DragAndDrop::payload::<GroupItemDrag>(ui.ctx());
            let keys = item_keys(&dialog.items);
            let motion_id = ui.scope_id().with("group_editor_items_motion");
            let frame_nr = ui.ctx().cumulative_frame_nr();
            let now = ui.ctx().input(|input| input.time);
            let mut items_motion = ui
                .ctx()
                .data_mut(|data| data.get_temp::<GroupItemsMotion>(motion_id))
                .unwrap_or_default();
            items_motion.sync(frame_nr, now, &keys, reduce_motion);
            let mut any_motion = false;
            let mut measured_pitch: Option<f32> = None;
            egui::ScrollArea::vertical()
                .id_salt("group_editor_items")
                .max_height(210.0)
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
                        let key = keys[idx];
                        let (slide_dy, sliding) =
                            items_motion.slide_offset(key, now, reduce_motion);
                        let (fade_opacity, highlight, adding) =
                            items_motion.added_visuals(key, now, reduce_motion);
                        any_motion |= sliding || adding;
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
                            let dragged = dragged_item
                                .as_deref()
                                .is_some_and(|payload| payload.0 == idx);
                            let fill = if dragged {
                                theme::alpha::fade(
                                    theme::palette().input,
                                    theme::alpha::DISABLED_ALPHA,
                                )
                            } else {
                                theme::palette().input
                            };
                            let layer = ui.layer_id();
                            let start_shape = (slide_dy.abs() > 0.25).then(|| {
                                ui.ctx().graphics(|graphics| {
                                    graphics.get(layer).map_or(
                                        egui::layers::ShapeIdx(0),
                                        egui::layers::PaintList::next_idx,
                                    )
                                })
                            });
                            let row = ui
                                .scope(|ui| {
                                    if fade_opacity < 1.0 {
                                        ui.multiply_opacity(fade_opacity);
                                    }
                                    widgets::card_frame()
                                        .fill(fill)
                                        .inner_margin(theme::margin::symmetric(
                                            theme::space::M,
                                            theme::space::XS,
                                        ))
                                        .show(ui, |ui| {
                                            ui.set_min_width(ui.available_width());
                                            if dragged {
                                                ui.multiply_opacity(0.5);
                                            }
                                            egui::Sides::new().shrink_left().height(24.0).show(
                                                ui,
                                                |ui| {
                                                    ui.horizontal(|ui| {
                                                        ui.set_min_height(24.0);
                                                        ui.spacing_mut().item_spacing.x =
                                                            theme::space::S;
                                                        table::table_cell(ui, 20.0, 24.0, |ui| {
                                                            if can_reorder {
                                                                ui.dnd_drag_source(
                                                                    ui.scope_id()
                                                                        .with("group_item_handle"),
                                                                    GroupItemDrag(idx),
                                                                    |ui| {
                                                                        icons::icon_button_sized(
                                                                            ui,
                                                                            Icon::Grip,
                                                                            true,
                                                                            20.0,
                                                                        );
                                                                    },
                                                                );
                                                            } else {
                                                                icons::icon_button_sized(
                                                                    ui,
                                                                    Icon::Grip,
                                                                    false,
                                                                    20.0,
                                                                );
                                                            }
                                                        });
                                                        icons::icon_badge(
                                                            ui,
                                                            table::rule_icon(item),
                                                            24.0,
                                                        );
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
                                                                    .color(
                                                                        theme::palette().text_dim,
                                                                    ),
                                                            )
                                                            .truncate(),
                                                        );
                                                    });
                                                },
                                                |ui| {
                                                    // Sides lays out the right slot right-to-left, so
                                                    // Close comes first to render as: [^] [v] [×].
                                                    ui.spacing_mut().item_spacing.x =
                                                        theme::space::XS;
                                                    if icons::icon_button_sized(
                                                        ui,
                                                        Icon::Close,
                                                        !busy,
                                                        22.0,
                                                    )
                                                    .on_hover_text(tr!("group-remove-item-hint"))
                                                    .clicked()
                                                    {
                                                        remove_index = Some(idx);
                                                    }
                                                    if icons::icon_button_sized(
                                                        ui,
                                                        Icon::ChevronDown,
                                                        !busy && idx + 1 < item_count,
                                                        22.0,
                                                    )
                                                    .on_hover_text(tr!("group-move-item-down"))
                                                    .clicked()
                                                    {
                                                        move_item = Some((idx, idx + 1));
                                                    }
                                                    if icons::icon_button_sized(
                                                        ui,
                                                        Icon::ChevronUp,
                                                        !busy && idx > 0,
                                                        22.0,
                                                    )
                                                    .on_hover_text(tr!("group-move-item-up"))
                                                    .clicked()
                                                    {
                                                        move_item = Some((idx, idx - 1));
                                                    }
                                                },
                                            );
                                        })
                                        .response
                                })
                                .inner;

                            if row.rect.height() > 0.0 {
                                measured_pitch = Some(row.rect.height() + theme::space::XS);
                            }

                            if highlight > 0.0 {
                                let accent = theme::palette().accent_base;
                                let tint = theme::alpha::TINT * highlight;
                                ui.painter().rect(
                                    row.rect,
                                    egui::CornerRadius::same(theme::RADIUS),
                                    accent.gamma_multiply(tint),
                                    egui::Stroke::new(
                                        theme::stroke::HAIRLINE,
                                        accent.gamma_multiply(highlight),
                                    ),
                                    egui::StrokeKind::Inside,
                                );
                            }

                            if let Some(start_shape) = start_shape {
                                let shift = egui::emath::TSTransform::from_translation(egui::vec2(
                                    0.0, slide_dy,
                                ));
                                ui.ctx().graphics_mut(|graphics| {
                                    let list = graphics.entry(layer);
                                    let end_shape = list.next_idx();
                                    list.transform_range(start_shape, end_shape, shift);
                                });
                            }

                            if can_reorder
                                && let Some(payload) = row.dnd_hover_payload::<GroupItemDrag>()
                                && let Some(pointer) = ui.ctx().pointer_hover_pos()
                            {
                                let above = pointer.y < row.rect.center().y;
                                let slot = idx + usize::from(!above);
                                if let Some(target) =
                                    group_item_drop_target(payload.0, slot, item_count)
                                {
                                    let y = if above {
                                        row.rect.top()
                                    } else {
                                        row.rect.bottom()
                                    };
                                    ui.painter().line_segment(
                                        [
                                            egui::pos2(row.rect.left(), y),
                                            egui::pos2(row.rect.right(), y),
                                        ],
                                        egui::Stroke::new(
                                            theme::stroke::MARK,
                                            theme::palette().accent_base,
                                        ),
                                    );
                                    if let Some(released) =
                                        row.dnd_release_payload::<GroupItemDrag>()
                                        && group_item_drop_target(released.0, slot, item_count)
                                            == Some(target)
                                    {
                                        move_item = Some((released.0, target));
                                    }
                                }
                            }
                        });
                    }
                });
            if let Some(pitch) = measured_pitch {
                items_motion.row_pitch = pitch;
            }
            ui.ctx()
                .data_mut(|data| data.insert_temp(motion_id, items_motion));
            if let Some(idx) = remove_index {
                dialog.remove_item(idx);
                if !reduce_motion {
                    any_motion = true;
                }
            } else if let Some((from, to)) = move_item {
                dialog.move_item(from, to);
                if !reduce_motion {
                    any_motion = true;
                }
            }
            if any_motion {
                ui.ctx().request_repaint();
            }

            if let Some(error) = &dialog.error {
                ui.add_space(theme::space::S);
                ui.add(egui::Label::new(RichText::new(error).small().color(theme::error())).wrap());
            }

            let can_save = !busy
                && !dialog.name.trim().is_empty()
                && (!dialog.items.is_empty()
                    || dialog.has_pending_text_input()
                    || (dialog.item_kind == crate::state::GroupItemKind::List
                        && !dialog.category.trim().is_empty()));
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

/// Up to 12 categories from `categories` matching `query` (prefix matches first, then contains).
fn group_category_suggestions<'a>(categories: &'a [String], query: &str) -> Vec<&'a str> {
    const LIMIT: usize = 12;
    let needle = query.trim().to_ascii_lowercase();
    let needle = needle
        .split_once('@')
        .map_or(needle.as_str(), |(base, _)| base);
    if needle.is_empty() {
        return categories.iter().take(LIMIT).map(String::as_str).collect();
    }
    let mut prefix = Vec::new();
    let mut contains = Vec::new();
    for category in categories {
        let lower = category.to_ascii_lowercase();
        if lower.starts_with(needle) {
            prefix.push(category.as_str());
        } else if lower.contains(needle) {
            contains.push(category.as_str());
        }
    }
    prefix.into_iter().chain(contains).take(LIMIT).collect()
}

#[derive(Clone, Copy)]
struct GroupItemDrag(usize);

fn group_item_drop_target(from: usize, slot: usize, len: usize) -> Option<usize> {
    if from >= len || slot > len || slot == from || slot == from + 1 {
        return None;
    }
    Some(if from < slot { slot - 1 } else { slot })
}

const HIGHLIGHT_DURATION: f64 = crate::motion::NORMAL as f64 * 2.0;
const MAX_SLIDE_ROWS: f32 = 3.0;
const DEFAULT_ROW_PITCH: f32 = 36.0;

#[derive(Clone, Default)]
struct GroupItemsMotion {
    last_frame: u64,
    row_pitch: f32,
    indices: std::collections::HashMap<u64, usize>,
    slides: std::collections::HashMap<u64, (f32, f64)>,
    added: std::collections::HashMap<u64, f64>,
}

impl GroupItemsMotion {
    fn sync(&mut self, frame: u64, now: f64, keys: &[u64], reduce_motion: bool) {
        if self.last_frame == frame {
            return;
        }
        if self.last_frame == 0 || self.last_frame + 1 < frame || reduce_motion {
            self.slides.clear();
            self.added.clear();
            self.indices.clear();
            self.indices
                .extend(keys.iter().enumerate().map(|(i, &k)| (k, i)));
            self.last_frame = frame;
            return;
        }

        let pitch = if self.row_pitch > 0.0 {
            self.row_pitch
        } else {
            DEFAULT_ROW_PITCH
        };
        let max_slide = pitch * MAX_SLIDE_ROWS;
        let present: std::collections::HashSet<u64> = keys.iter().copied().collect();
        self.slides.retain(|k, (_, started)| {
            present.contains(k) && now - *started < f64::from(crate::motion::FAST)
        });
        self.added
            .retain(|k, started| present.contains(k) && now - *started < HIGHLIGHT_DURATION);

        for (idx, &key) in keys.iter().enumerate() {
            if let Some(&prev_idx) = self.indices.get(&key) {
                if prev_idx != idx {
                    let current_dy = self.slide_offset(key, now, false).0;
                    let delta = (prev_idx as f32 - idx as f32) * pitch;
                    let start_dy = (current_dy + delta).clamp(-max_slide, max_slide);
                    self.slides.insert(key, (start_dy, now));
                }
            } else {
                self.added.insert(key, now);
            }
        }

        self.indices.clear();
        self.indices
            .extend(keys.iter().enumerate().map(|(i, &k)| (k, i)));
        self.last_frame = frame;
    }

    fn slide_offset(&self, key: u64, now: f64, reduce_motion: bool) -> (f32, bool) {
        if reduce_motion {
            return (0.0, false);
        }
        if let Some(&(start_dy, started)) = self.slides.get(&key) {
            let t = ((now - started).max(0.0) / f64::from(crate::motion::FAST)) as f32;
            if t < 1.0 {
                let dy = start_dy * (1.0 - crate::motion::ease_out(t));
                return (dy, true);
            }
        }
        (0.0, false)
    }

    fn added_visuals(&self, key: u64, now: f64, reduce_motion: bool) -> (f32, f32, bool) {
        if reduce_motion {
            return (1.0, 0.0, false);
        }
        if let Some(&started) = self.added.get(&key) {
            let elapsed = (now - started).max(0.0);
            let fade_t = (elapsed / f64::from(crate::motion::FAST)) as f32;
            let opacity = crate::motion::ease_out(fade_t);
            let highlight_t = (elapsed / HIGHLIGHT_DURATION) as f32;
            if highlight_t < 1.0 {
                let highlight = 1.0 - crate::motion::ease_out(highlight_t);
                return (opacity, highlight, true);
            }
        }
        (1.0, 0.0, false)
    }
}

fn hash_matcher(item: &RuleMatcher, hasher: &mut impl std::hash::Hasher) {
    use std::hash::Hash;
    std::mem::discriminant(item).hash(hasher);
    match item {
        RuleMatcher::Domain(domain) => {
            std::mem::discriminant(domain).hash(hasher);
            match domain {
                rosetun_config::DomainMatch::Exact(value)
                | rosetun_config::DomainMatch::Suffix(value)
                | rosetun_config::DomainMatch::Keyword(value) => value.hash(hasher),
            }
        }
        RuleMatcher::Process(process) => {
            std::mem::discriminant(process).hash(hasher);
            match process {
                rosetun_config::ProcessMatch::Name(value) => value.hash(hasher),
                rosetun_config::ProcessMatch::Path(path) => path.hash(hasher),
            }
        }
        RuleMatcher::IpCidr(cidr) => cidr.hash(hasher),
        RuleMatcher::List { list, category } => {
            list.as_str().hash(hasher);
            category.hash(hasher);
        }
        RuleMatcher::Group { name, items } => {
            name.hash(hasher);
            items.len().hash(hasher);
            for child in items {
                hash_matcher(child, hasher);
            }
        }
    }
}

fn matcher_key(item: &RuleMatcher) -> u64 {
    let mut hasher = std::hash::DefaultHasher::new();
    hash_matcher(item, &mut hasher);
    std::hash::Hasher::finish(&hasher)
}

fn item_keys(items: &[RuleMatcher]) -> Vec<u64> {
    let mut seen: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
    items
        .iter()
        .map(|item| {
            let base = matcher_key(item);
            let occurrence = seen.entry(base).or_default();
            let key = if *occurrence == 0 {
                base
            } else {
                let mut hasher = std::hash::DefaultHasher::new();
                std::hash::Hash::hash(&(base, *occurrence), &mut hasher);
                std::hash::Hasher::finish(&hasher)
            };
            *occurrence += 1;
            key
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_items_motion_does_not_animate_on_initial_open_or_reopen() {
        let mut motion = GroupItemsMotion {
            row_pitch: 40.0,
            ..Default::default()
        };
        motion.sync(1, 1.0, &[10, 20, 30], false);
        for key in [10, 20, 30] {
            assert_eq!(motion.slide_offset(key, 1.0, false), (0.0, false));
            assert_eq!(motion.added_visuals(key, 1.0, false), (1.0, 0.0, false));
        }

        // Gap in frame numbers simulates closing and reopening the dialog.
        motion.sync(10, 2.0, &[30, 10, 40], false);
        for key in [30, 10, 40] {
            assert_eq!(motion.slide_offset(key, 2.0, false), (0.0, false));
            assert_eq!(motion.added_visuals(key, 2.0, false), (1.0, 0.0, false));
        }
    }

    #[test]
    fn group_items_motion_slides_reordered_items_and_chains_rapid_moves() {
        let mut motion = GroupItemsMotion {
            row_pitch: 40.0,
            ..Default::default()
        };
        motion.sync(1, 1.0, &[10, 20, 30], false);

        // Move item 30 from index 2 -> 1; item 20 shifts down.
        motion.sync(2, 1.1, &[10, 30, 20], false);
        let (dy_30, active_30) = motion.slide_offset(30, 1.1, false);
        let (dy_20, active_20) = motion.slide_offset(20, 1.1, false);
        assert!(active_30 && active_20);
        assert!((dy_30 - 40.0).abs() < 0.01, "expected +40.0, got {dy_30}");
        assert!((dy_20 - -40.0).abs() < 0.01, "expected -40.0, got {dy_20}");

        // Before the first slide finishes, move item 30 again from index 1 -> 0.
        let (in_flight, _) = motion.slide_offset(30, 1.14, false);
        assert!(in_flight > 0.0);
        motion.sync(3, 1.14, &[30, 10, 20], false);
        let (chained_dy, chained_active) = motion.slide_offset(30, 1.14, false);
        assert!(chained_active);
        assert!(
            (chained_dy - (in_flight + 40.0)).abs() < 0.01,
            "expected {}, got {chained_dy}",
            in_flight + 40.0
        );

        // Halfway through FAST, offset has eased closer to 0.
        let (mid_dy, mid_active) = motion.slide_offset(30, 1.14 + 0.07, false);
        assert!(mid_active);
        assert!(0.0 < mid_dy && mid_dy < chained_dy * 0.5, "mid_dy={mid_dy}");

        // After FAST completes, offset settles to 0.
        assert_eq!(
            motion.slide_offset(30, 1.14 + f64::from(crate::motion::FAST) + 0.01, false),
            (0.0, false)
        );
    }

    #[test]
    fn group_items_motion_highlights_newly_added_items_and_respects_reduce_motion() {
        let mut motion = GroupItemsMotion {
            row_pitch: 40.0,
            ..Default::default()
        };
        motion.sync(1, 1.0, &[10], false);

        motion.sync(2, 1.1, &[10, 20], false);
        assert_eq!(motion.added_visuals(10, 1.1, false), (1.0, 0.0, false));
        let (op0, hi0, active0) = motion.added_visuals(20, 1.1, false);
        assert!(active0);
        assert_eq!(op0, 0.0);
        assert_eq!(hi0, 1.0);

        let (op_mid, hi_mid, active_mid) = motion.added_visuals(20, 1.17, false);
        assert!(active_mid);
        assert!(0.0 < op_mid && op_mid < 1.0);
        assert!(0.0 < hi_mid && hi_mid < 1.0);

        assert_eq!(
            motion.added_visuals(20, 1.1 + HIGHLIGHT_DURATION + 0.01, false),
            (1.0, 0.0, false)
        );

        // With reduce_motion enabled, both slide and added visuals are instant.
        assert_eq!(motion.added_visuals(20, 1.1, true), (1.0, 0.0, false));
        motion.sync(3, 1.2, &[20, 10, 30], true);
        assert_eq!(motion.slide_offset(20, 1.2, true), (0.0, false));
        assert_eq!(motion.added_visuals(30, 1.2, true), (1.0, 0.0, false));
    }
}
