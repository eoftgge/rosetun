use eframe::egui::{self, RichText};
use rosetun_config::{ProcessMatch, RuleMatcher, RuleTarget};

use crate::rules::{ProcessMatchMode, process_matches_filter, update_process_match_mode};
use crate::state::{Action, AddRuleDialog, RuleInputKind};
use crate::{strings, theme};

const DIALOG_WIDTH: f32 = 640.0;
const BODY_HEIGHT: f32 = 380.0;
const BUTTON_ROW_HEIGHT: f32 = 40.0;
const PROCESS_FOOTER_HEIGHT: f32 = 180.0;

pub(crate) fn show(ctx: &egui::Context, dialog: &mut AddRuleDialog, actions: &mut Vec<Action>) {
    let response = egui::Modal::new(egui::Id::new("add_rule"))
        .frame(theme::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(DIALOG_WIDTH);
            ui.set_max_width(DIALOG_WIDTH);
            ui.heading(strings::NEW_RULE);
            ui.colored_label(theme::TEXT_MUTED, strings::NEW_RULE_SUBTITLE);
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                for (kind, label) in [
                    (RuleInputKind::Domain, strings::DOMAIN),
                    (RuleInputKind::Process, strings::PROCESS),
                ] {
                    if ui
                        .add_enabled(
                            !dialog.busy,
                            egui::Button::new(label).selected(dialog.kind == kind),
                        )
                        .clicked()
                    {
                        actions.push(Action::SelectRuleInput(kind));
                    }
                }
            });
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                for (target, label) in [
                    (RuleTarget::Proxy, strings::PROXY),
                    (RuleTarget::Direct, strings::DIRECT),
                    (RuleTarget::Block, strings::BLOCK),
                ] {
                    if ui
                        .add_enabled(
                            !dialog.busy,
                            egui::Button::new(label).selected(dialog.target == target),
                        )
                        .clicked()
                    {
                        dialog.target = target;
                        dialog.error = None;
                    }
                }
            });
            ui.add_space(16.0);
            let valid = ui
                .allocate_ui_with_layout(
                    egui::vec2(DIALOG_WIDTH, BODY_HEIGHT),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.set_min_size(egui::vec2(DIALOG_WIDTH, BODY_HEIGHT));
                        let valid = match dialog.kind {
                            RuleInputKind::Domain => domain_input(ui, dialog),
                            RuleInputKind::Process => process_input(ui, dialog, actions),
                        };
                        if let Some(error) = &dialog.error {
                            ui.add_space(8.0);
                            ui.add(
                                egui::Label::new(RichText::new(error).color(theme::ERROR)).wrap(),
                            );
                        }
                        valid
                    },
                )
                .inner;
            ui.add_space(18.0);
            ui.colored_label(theme::TEXT_DIM, strings::RULE_PRIORITY);
            ui.add_space(12.0);
            ui.allocate_ui_with_layout(
                egui::vec2(DIALOG_WIDTH, BUTTON_ROW_HEIGHT),
                egui::Layout::right_to_left(egui::Align::Center),
                |ui| {
                    ui.set_min_size(egui::vec2(DIALOG_WIDTH, BUTTON_ROW_HEIGHT));
                    if theme::button_fill(
                        ui,
                        if dialog.busy {
                            strings::ADDING_RULE
                        } else {
                            strings::ADD_RULE
                        },
                        !dialog.busy && valid,
                    )
                    .clicked()
                    {
                        actions.push(Action::SubmitAddRule);
                    }
                    if theme::outline_button(ui, strings::CANCEL, !dialog.busy).clicked() {
                        actions.push(Action::CancelAddRule);
                    }
                },
            );
        });
    if !dialog.busy && response.should_close() {
        actions.push(Action::CancelAddRule);
    }
}

fn domain_input(ui: &mut egui::Ui, dialog: &mut AddRuleDialog) -> bool {
    ui.label(strings::DOMAIN_INPUT);
    let input = ui.add_enabled(
        !dialog.busy,
        egui::TextEdit::singleline(&mut dialog.domain)
            .hint_text(strings::DOMAIN_PLACEHOLDER)
            .desired_width(f32::INFINITY),
    );
    if dialog.focus_input {
        input.request_focus();
        dialog.focus_input = false;
    }
    if input.changed() {
        dialog.error = None;
    }
    ui.add(egui::Label::new(RichText::new(strings::DOMAIN_HELP).color(theme::TEXT_DIM)).wrap());
    let parsed = rosetun_core::parse_domain_input(&dialog.domain);
    if !dialog.domain.trim().is_empty() {
        match &parsed {
            Ok(domain) => {
                let matcher = RuleMatcher::Domain(domain.clone());
                let preview = strings::will_match(&rosetun_core::rule_value_text(&matcher));
                ui.add(
                    egui::Label::new(RichText::new(&preview).color(theme::ROSE_LIGHT)).truncate(),
                )
                .on_hover_text(preview);
                if let Some(ascii) = rosetun_core::rule_value_ascii(&matcher) {
                    let stored = format!("Stored as {ascii}");
                    ui.add(
                        egui::Label::new(RichText::new(&stored).small().color(theme::TEXT_DIM))
                            .truncate(),
                    )
                    .on_hover_text(stored);
                }
            }
            Err(error) => {
                ui.colored_label(theme::ERROR, error.to_string());
            }
        };
    }
    parsed.is_ok()
}

fn process_input(ui: &mut egui::Ui, dialog: &mut AddRuleDialog, actions: &mut Vec<Action>) -> bool {
    let count: usize = dialog.processes.iter().map(|group| group.count).sum();
    ui.label(strings::running_processes(count));
    ui.horizontal(|ui| {
        let height = 28.0;
        let refresh_width = 88.0;
        let filter_width = ui.available_width() - refresh_width - ui.spacing().item_spacing.x;
        ui.add_enabled_ui(!dialog.busy, |ui| {
            ui.add_sized(
                [filter_width, height],
                egui::TextEdit::singleline(&mut dialog.process_filter)
                    .hint_text(strings::PROCESS_FILTER),
            );
        });
        if ui
            .add_enabled(
                !dialog.busy && dialog.load_request.is_none(),
                egui::Button::new(strings::REFRESH).min_size(egui::vec2(refresh_width, height)),
            )
            .clicked()
        {
            actions.push(Action::RefreshProcesses);
        }
    });
    if let Some(error) = &dialog.processes_error {
        ui.add(egui::Label::new(RichText::new(error).color(theme::ERROR)).wrap());
    }
    if dialog.load_request.is_some() {
        ui.colored_label(theme::TEXT_DIM, strings::LOADING_PROCESSES);
    }
    let preview_height = if dialog.process.trim().is_empty() {
        0.0
    } else {
        26.0
    };
    let error_height = if dialog.error.is_some() { 36.0 } else { 0.0 };
    let list_height =
        (ui.available_height() - PROCESS_FOOTER_HEIGHT - preview_height - error_height).max(0.0);
    egui::ScrollArea::vertical()
        .id_salt("running_processes")
        .max_height(list_height)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let mut visible = 0;
            for (index, group) in dialog.processes.iter().enumerate() {
                if !process_matches_filter(group, &dialog.process_filter) {
                    continue;
                }
                visible += 1;
                ui.push_id(index, |ui| {
                    let frame = theme::card_frame()
                        .inner_margin(egui::Margin::symmetric(12, 7))
                        .fill(if dialog.selected_process == Some(index) {
                            theme::BORDER
                        } else {
                            theme::CARD
                        });
                    let row = frame.show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.horizontal(|ui| {
                            let icon = group
                                .name
                                .chars()
                                .next()
                                .unwrap_or('?')
                                .to_uppercase()
                                .to_string();
                            ui.label(RichText::new(icon).strong().color(theme::ROSE_LIGHT));
                            ui.vertical(|ui| {
                                ui.set_width(ui.available_width());
                                let label = if group.count > 1 {
                                    strings::process_copies(&group.name, group.count)
                                } else {
                                    group.name.clone()
                                };
                                ui.add(egui::Label::new(RichText::new(&label).strong()).truncate())
                                    .on_hover_text(label);
                                let path = group.path.as_ref().map_or_else(
                                    || strings::PATH_UNAVAILABLE.to_owned(),
                                    |path| path.to_string_lossy().into_owned(),
                                );
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&path).small().color(theme::TEXT_DIM),
                                    )
                                    .truncate(),
                                )
                                .on_hover_text(path);
                            });
                        });
                    });
                    if ui
                        .interact(
                            row.response.rect,
                            row.response.id.with("select"),
                            egui::Sense::click(),
                        )
                        .clicked()
                        && !dialog.busy
                    {
                        dialog.selected_process = Some(index);
                        if dialog.match_mode == ProcessMatchMode::Path && group.path.is_none() {
                            dialog.match_mode = ProcessMatchMode::Name;
                        }
                        dialog.process = match dialog.match_mode {
                            ProcessMatchMode::Name => group.name.clone(),
                            ProcessMatchMode::Path => {
                                group.path.as_ref().unwrap().to_string_lossy().into_owned()
                            }
                        };
                        dialog.error = None;
                    }
                });
            }
            if visible == 0 && dialog.processes_loaded {
                ui.colored_label(
                    theme::TEXT_DIM,
                    if dialog.process_filter.is_empty() {
                        strings::NO_RUNNING_PROCESSES
                    } else {
                        strings::NO_PROCESSES_MATCH
                    },
                );
            }
        });
    ui.add_space(12.0);
    let full_path_available = dialog
        .selected_process
        .and_then(|index| dialog.processes.get(index))
        .and_then(|group| group.path.as_ref())
        .is_some()
        || matches!(
            rosetun_core::parse_process_input(&dialog.process),
            Ok(ProcessMatch::Path(_))
        );
    ui.horizontal(|ui| {
        for (mode, label) in [
            (ProcessMatchMode::Name, strings::MATCH_BY_NAME),
            (ProcessMatchMode::Path, strings::MATCH_BY_FULL_PATH),
        ] {
            if ui
                .add_enabled(
                    !dialog.busy && (mode == ProcessMatchMode::Name || full_path_available),
                    egui::Button::new(label).selected(dialog.match_mode == mode),
                )
                .clicked()
            {
                dialog.match_mode = mode;
                if let Some(group) = dialog
                    .selected_process
                    .and_then(|index| dialog.processes.get(index))
                {
                    dialog.process = match mode {
                        ProcessMatchMode::Name => group.name.clone(),
                        ProcessMatchMode::Path => {
                            group.path.as_ref().unwrap().to_string_lossy().into_owned()
                        }
                    };
                } else if mode == ProcessMatchMode::Name
                    && let Ok(ProcessMatch::Path(path)) =
                        rosetun_core::parse_process_input(&dialog.process)
                    && let Some(name) = path.file_name()
                {
                    dialog.process = name.to_string_lossy().into_owned();
                }
                dialog.error = None;
            }
        }
    });
    ui.add_space(12.0);
    ui.label(strings::PROCESS_INPUT);
    let input = ui.add_enabled(
        !dialog.busy,
        egui::TextEdit::singleline(&mut dialog.process)
            .hint_text(strings::PROCESS_PLACEHOLDER)
            .desired_width(f32::INFINITY),
    );
    if dialog.focus_input {
        input.request_focus();
        dialog.focus_input = false;
    }
    if input.changed() {
        dialog.selected_process = None;
        update_process_match_mode(&mut dialog.match_mode, &dialog.process);
        dialog.error = None;
    }
    let parsed = rosetun_core::parse_process_input(&dialog.process);
    if !dialog.process.trim().is_empty() {
        match &parsed {
            Ok(matcher) => {
                let preview = strings::will_match(&rosetun_core::rule_value_text(
                    &RuleMatcher::Process(matcher.clone()),
                ));
                ui.add(
                    egui::Label::new(RichText::new(&preview).color(theme::ROSE_LIGHT)).truncate(),
                )
                .on_hover_text(preview);
            }
            Err(error) => {
                ui.colored_label(theme::ERROR, error.to_string());
            }
        }
    }
    parsed.is_ok()
}
