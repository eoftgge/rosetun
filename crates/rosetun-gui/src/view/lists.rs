use std::collections::BTreeSet;

use eframe::egui::{self, RichText, Stroke};
use rosetun_config::{List, ListFormat, ListSource, RuleMatcher};

use crate::display;
use crate::errors;
use crate::icons::{self, Icon};
use crate::state::{Action, AddListDialog, ListOutcome, State, source_file_name, used_by};
use crate::{i18n, theme, widgets};

const CARD_HEIGHT: f32 = theme::RULE_ROW;

pub(crate) fn format_name(format: ListFormat) -> String {
    match format {
        ListFormat::SingBoxBinary | ListFormat::SingBoxSource => tr!("list-format-singbox"),
        ListFormat::GeoSite => tr!("list-format-geosite"),
        ListFormat::GeoIp => tr!("list-format-geoip"),
        ListFormat::Text => tr!("list-format-text"),
    }
}

fn source_name(source: &ListSource) -> String {
    match source {
        ListSource::Url(value) => url::Url::parse(value)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .map_or_else(
                || tr!("list-source-unknown"),
                |host| display::safe_text(&host),
            ),
        ListSource::File { original_name } => {
            tr!("list-source-file", name = display::safe_text(original_name))
        }
    }
}

fn header_has_add_button(state: &State) -> bool {
    state.config_ready && !state.config.lists.is_empty()
}

pub(crate) fn show(ui: &mut egui::Ui, state: &State, actions: &mut Vec<Action>) {
    egui::Sides::new().shrink_left().wrap().show(
        ui,
        |ui| {
            ui.vertical(|ui| {
                ui.heading(tr!("lists-title"));
                ui.add(
                    egui::Label::new(RichText::new(tr!("lists-empty")).color(theme::TEXT_MUTED))
                        .wrap(),
                );
            });
        },
        |ui| {
            if header_has_add_button(state)
                && widgets::button_fill(ui, tr!("new-list-button"), true).clicked()
            {
                actions.push(Action::OpenAddList);
            }
        },
    );
    ui.add_space(8.0);
    if let Some(error) = &state.lists.error
        && widgets::dismissible_error(ui, error)
    {
        actions.push(Action::DismissListsError);
    }
    if let Some(error) = &state.lists.scan_error {
        ui.colored_label(theme::ERROR, error);
    }
    if !state.config_ready {
        ui.colored_label(theme::TEXT_DIM, tr!("loading"));
        return;
    }
    if state.config.lists.is_empty() {
        ui.add_space(12.0);
        widgets::card_frame().show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.vertical_centered(|ui| {
                ui.add_space(16.0);
                icons::icon_badge(ui, Icon::List, 40.0);
                ui.add_space(8.0);
                ui.add(egui::Label::new(tr!("lists-empty-prompt")).wrap());
                ui.add_space(12.0);
                if widgets::button_fill(ui, tr!("new-list-button"), true).clicked() {
                    actions.push(Action::OpenAddList);
                }
                ui.add_space(16.0);
            });
        });
        return;
    }
    ui.add_space(12.0);
    egui::ScrollArea::vertical()
        .id_salt("lists_cards")
        .max_height(ui.available_height().max(320.0))
        .show_rows(ui, CARD_HEIGHT, state.config.lists.len(), |ui, rows| {
            for index in rows {
                ui.push_id(&state.config.lists[index].id, |ui| {
                    list_card(ui, state, &state.config.lists[index], actions);
                });
            }
        });
}

fn list_card(
    ui: &mut egui::Ui,
    state: &State,
    list: &List,
    actions: &mut Vec<Action>,
) -> egui::Response {
    let busy = state.operations.update_all || state.operations.updating_lists.contains(&list.id);
    let used = used_by(&state.config, &list.id);
    let source = source_name(&list.source);
    let updated = list
        .updated_at
        .map(|time| i18n::last_updated(&i18n::updated_ago(time, display::now_unix())))
        .unwrap_or_else(|| tr!("never-updated"));
    let size = list
        .size
        .map(i18n::bytes)
        .unwrap_or_else(|| tr!("list-size-unknown"));
    let detail = if list.format.has_categories() {
        tr!(
            "list-row-detail-categories",
            source = &source,
            size = &size,
            updated = &updated,
            count = list.categories.len(),
            n = list.categories.len().to_string()
        )
    } else {
        tr!(
            "list-row-detail",
            source = &source,
            size = &size,
            updated = &updated
        )
    };
    let outcome = state.lists.outcomes.get(&list.id);
    let failed = outcome.and_then(|outcome| match outcome {
        ListOutcome::Failed(error) => Some(state.text(&errors::list(i18n::language(), error))),
        ListOutcome::Updated { .. } => None,
    });
    let applies_later = matches!(
        outcome,
        Some(ListOutcome::Updated {
            applies_later: true
        })
    );
    let affected: Vec<_> = state
        .lists
        .missing
        .iter()
        .filter(|missing| missing.list == list.id)
        .collect();
    let warning = if affected.is_empty() {
        None
    } else {
        let categories = affected
            .iter()
            .map(|missing| state.text(&missing.category))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ");
        Some(tr!(
            "list-missing-card",
            categories = &categories,
            count = affected.len(),
            n = affected.len().to_string()
        ))
    };
    let has_warning = failed.is_some() || !affected.is_empty();
    let detail = failed.or(warning).unwrap_or_else(|| {
        if applies_later {
            tr!("list-updated-later")
        } else {
            detail
        }
    });
    let name = tr!(
        "list-name-format",
        name = state.text(&list.name),
        format = format_name(list.format)
    );
    let count = state
        .config
        .rule_sets
        .iter()
        .flat_map(|set| &set.rules)
        .filter(
            |rule| matches!(&rule.matcher, RuleMatcher::List { list: id, .. } if id == &list.id),
        )
        .count();
    let usage = if count == 0 {
        tr!("list-unused")
    } else {
        tr!("list-used-rules", count = count, n = count.to_string())
    };
    widgets::card_frame()
        .stroke(Stroke::new(1.0, theme::BORDER))
        .inner_margin(egui::Margin {
            left: 12,
            right: 12,
            top: 5,
            bottom: 6,
        })
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.set_min_height(CARD_HEIGHT - 15.0);
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 10.0;
                icons::icon_badge(ui, Icon::List, 32.0);
                let width = (ui.available_width() - 170.0).max(100.0);
                ui.allocate_ui_with_layout(
                    egui::vec2(width, 40.0),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.set_width(width);
                        ui.add(egui::Label::new(RichText::new(&name).strong()).truncate())
                            .on_hover_text(&name);
                        ui.add(
                            egui::Label::new(RichText::new(&detail).small().color(
                                if has_warning {
                                    theme::WARNING
                                } else if applies_later {
                                    theme::ROSE_LIGHT
                                } else {
                                    theme::TEXT_MUTED
                                },
                            ))
                            .truncate(),
                        )
                        .on_hover_text(&detail);
                    },
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    list_menu(ui, state, list, &used, busy, actions);
                    ui.add(
                        egui::Label::new(RichText::new(&usage).small().color(theme::TEXT_DIM))
                            .truncate(),
                    )
                    .on_hover_text(&usage);
                });
            });
        })
        .response
}

fn list_menu(
    ui: &mut egui::Ui,
    state: &State,
    list: &List,
    used: &[String],
    busy: bool,
    actions: &mut Vec<Action>,
) {
    let menu =
        icons::icon_button_sized(ui, Icon::More, true, 28.0).on_hover_text(tr!("more-actions"));
    widgets::menu_popup(&menu).show(|ui| {
        ui.set_width(210.0);
        let update = widgets::menu_item(
            ui,
            widgets::MenuItem {
                label: &tr!("update"),
                enabled: !busy,
                selected: false,
                danger: false,
                note: None,
            },
        );
        if update.clicked() {
            actions.push(match &list.source {
                ListSource::Url(_) => Action::UpdateListManual(list.id.clone()),
                ListSource::File { .. } => Action::UpdateListFile(list.id.clone()),
            });
            ui.close();
        }
        if widgets::menu_item(
            ui,
            widgets::MenuItem {
                label: &tr!("rename"),
                enabled: !busy && state.lists.rename.is_none(),
                selected: false,
                danger: false,
                note: None,
            },
        )
        .clicked()
        {
            actions.push(Action::OpenRenameList(list.id.clone()));
            ui.close();
        }
        let remove = widgets::menu_item(
            ui,
            widgets::MenuItem {
                label: &tr!("delete"),
                enabled: !busy && used.is_empty() && state.lists.remove.is_none(),
                selected: false,
                danger: true,
                note: None,
            },
        );
        if !used.is_empty() {
            remove.on_hover_text(tr!(
                "list-delete-in-use",
                sets = display::safe_text(&used.join(", "))
            ));
        } else if remove.clicked() {
            actions.push(Action::OpenRemoveList(list.id.clone()));
            ui.close();
        }
    });
}

pub(crate) fn add_dialog(
    ctx: &egui::Context,
    dialog: &mut AddListDialog,
    actions: &mut Vec<Action>,
) {
    let busy = dialog.busy || dialog.browsing;
    let response = egui::Modal::new(egui::Id::new("add_list"))
        .frame(widgets::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(520.0);
            ui.heading(tr!("add-list"));
            ui.add_space(14.0);
            if let Some((format, categories, entries)) = dialog.result {
                let summary = if format.has_categories() {
                    tr!(
                        "list-added-categories",
                        format = format_name(format),
                        count = categories,
                        n = categories.to_string()
                    )
                } else if let Some(entries) = entries {
                    tr!(
                        "list-added-entries",
                        format = format_name(format),
                        count = entries,
                        n = entries.to_string()
                    )
                } else {
                    format_name(format)
                };
                ui.label(summary);
                ui.add_space(18.0);
                if widgets::button_fill(ui, tr!("done"), true).clicked() {
                    actions.push(Action::CancelAddList);
                }
                return;
            }
            ui.label(tr!("list-url"));
            let mut value = dialog.url.clone();
            let input = ui.add_enabled(
                !busy,
                egui::TextEdit::singleline(&mut value).desired_width(f32::INFINITY),
            );
            if dialog.focus_url {
                input.request_focus();
                dialog.focus_url = false;
            }
            if input.changed() {
                dialog.update_url(value);
            }
            ui.add_space(10.0);
            if widgets::outline_button(ui, tr!("choose-list-file"), !busy).clicked() {
                actions.push(Action::BrowseListFile);
            }
            if let Some(path) = &dialog.file {
                ui.label(tr!(
                    "list-selected-file",
                    name = display::safe_text(&source_file_name(path))
                ));
            }
            ui.add_space(14.0);
            ui.label(tr!("name"));
            if ui
                .add_enabled(
                    !busy,
                    egui::TextEdit::singleline(&mut dialog.name).desired_width(f32::INFINITY),
                )
                .changed()
            {
                dialog.name_manual = true;
                dialog.error = None;
            }
            if let Some(error) = &dialog.error {
                ui.add_space(10.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(errors::list(i18n::language(), error)).color(theme::ERROR),
                    )
                    .wrap(),
                );
            }
            ui.add_space(18.0);
            ui.horizontal(|ui| {
                if widgets::outline_button(ui, tr!("cancel"), !busy).clicked() {
                    actions.push(Action::CancelAddList);
                }
                if widgets::button_fill(
                    ui,
                    if busy { tr!("adding") } else { tr!("add") },
                    !busy
                        && !dialog.name.trim().is_empty()
                        && (dialog.file.is_some() || !dialog.url.trim().is_empty()),
                )
                .clicked()
                {
                    actions.push(Action::SubmitAddList);
                }
            });
        });
    if !busy && response.should_close() {
        actions.push(Action::CancelAddList);
    }
}

pub(crate) fn rename_dialog(ctx: &egui::Context, state: &mut State, actions: &mut Vec<Action>) {
    let Some(dialog) = &mut state.lists.rename else {
        return;
    };
    let choice = widgets::name_modal(
        ctx,
        widgets::NameModal {
            id: "rename_list",
            title: tr!("rename-list"),
            label: tr!("name"),
            submit: tr!("rename"),
            name: &mut dialog.name,
            focus: &mut dialog.focus,
            error: &mut dialog.error,
            busy: dialog.busy,
            char_limit: None,
        },
    );
    match choice {
        widgets::ModalChoice::Cancel => actions.push(Action::CancelRenameList),
        widgets::ModalChoice::Confirm => actions.push(Action::SubmitRenameList),
        widgets::ModalChoice::None => {}
    }
}

pub(crate) fn remove_dialog(ctx: &egui::Context, state: &State, actions: &mut Vec<Action>) {
    let Some(dialog) = &state.lists.remove else {
        return;
    };
    let choice = widgets::confirm_modal(
        ctx,
        widgets::ConfirmModal {
            id: "remove_list",
            title: tr!("delete-list"),
            cancel: tr!("cancel"),
            confirm: tr!("delete"),
            busy: dialog.busy,
            confirm_enabled: !dialog.busy,
            button_gap: 20.0,
        },
        |ui| {
            if let Some(list) = state.config.lists.iter().find(|list| list.id == dialog.id) {
                ui.label(state.text(&list.name));
            }
            ui.add_space(12.0);
            ui.add(egui::Label::new(tr!("delete-list-detail")).wrap());
            if let Some(error) = &dialog.error {
                ui.add(egui::Label::new(RichText::new(error).color(theme::ERROR)).wrap());
            }
        },
    );
    match choice {
        widgets::ModalChoice::Cancel => actions.push(Action::CancelRemoveList),
        widgets::ModalChoice::Confirm => actions.push(Action::ConfirmRemoveList),
        widgets::ModalChoice::None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_source_contains_only_the_url_host() {
        let source =
            ListSource::Url("https://user:secret@example.com/private/path?token=secret".into());
        assert_eq!(source_name(&source), "example.com");
    }

    #[test]
    fn add_list_button_moves_between_header_and_empty_state() {
        use rosetun_config::ListId;

        let mut state = State::default();
        state.config_ready = true;
        assert!(!header_has_add_button(&state));
        state.config.lists.push(List {
            id: ListId::new("example"),
            name: "Example".into(),
            source: ListSource::Url("https://example.com/list.txt".into()),
            format: ListFormat::Text,
            updated_at: None,
            size: None,
            sha256: None,
            categories: Vec::new(),
        });
        assert!(header_has_add_button(&state));
    }

    #[test]
    fn populated_list_card_matches_rule_row_height() {
        use rosetun_config::ListId;

        let list = List {
            id: ListId::new("example"),
            name: "Example".into(),
            source: ListSource::Url("https://example.com/lists/sites.txt".into()),
            format: ListFormat::Text,
            updated_at: None,
            size: Some(12),
            sha256: None,
            categories: Vec::new(),
        };
        let mut state = State::default();
        state.config_ready = true;
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut height = 0.0;
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.set_width(800.0);
                height = list_card(ui, &state, &list, &mut Vec::new()).rect.height();
            });
        });
        output.textures_delta.clear();
        assert_eq!(height, theme::RULE_ROW);
    }
}
