use eframe::egui::{self, RichText};
use rosetun_config::{ProcessMatch, RuleMatcher, RuleTarget};

use crate::rules::{
    ProcessMatchMode, different_process_case, process_matches_filter, update_process_match_mode,
};
use crate::state::{Action, AddRuleDialog, RuleInputKind};
use crate::{strings, theme};

pub(crate) fn show(ctx: &egui::Context, dialog: &mut AddRuleDialog, actions: &mut Vec<Action>) {
    let response = egui::Modal::new(egui::Id::new("add_rule"))
        .frame(theme::modal_frame())
        .show(ctx, |ui| {
            ui.set_width(620.0);
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
            let valid = match dialog.kind {
                RuleInputKind::Domain => domain_input(ui, dialog),
                RuleInputKind::Process => process_input(ui, dialog, actions),
            };
            if let Some(error) = &dialog.error {
                ui.add_space(8.0);
                ui.add(egui::Label::new(RichText::new(error).color(theme::ERROR)).wrap());
            }
            ui.add_space(18.0);
            ui.colored_label(theme::TEXT_DIM, strings::RULE_PRIORITY);
            ui.add_space(12.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
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
            });
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
            Ok(domain) => ui.colored_label(
                theme::ROSE_LIGHT,
                strings::will_match(&rosetun_core::rule_value_text(&RuleMatcher::Domain(
                    domain.clone(),
                ))),
            ),
            Err(error) => ui.colored_label(theme::ERROR, error.to_string()),
        };
    }
    parsed.is_ok()
}

fn process_input(ui: &mut egui::Ui, dialog: &mut AddRuleDialog, actions: &mut Vec<Action>) -> bool {
    ui.horizontal(|ui| {
        let count: usize = dialog.processes.iter().map(|group| group.count).sum();
        ui.label(strings::running_processes(count));
        if theme::outline_button(
            ui,
            strings::REFRESH,
            !dialog.busy && dialog.load_request.is_none(),
        )
        .clicked()
        {
            actions.push(Action::RefreshProcesses);
        }
    });
    ui.add_enabled(
        !dialog.busy,
        egui::TextEdit::singleline(&mut dialog.process_filter)
            .hint_text(strings::PROCESS_FILTER)
            .desired_width(f32::INFINITY),
    );
    if let Some(error) = &dialog.processes_error {
        ui.add(egui::Label::new(RichText::new(error).color(theme::ERROR)).wrap());
    }
    if dialog.load_request.is_some() {
        ui.colored_label(theme::TEXT_DIM, strings::LOADING_PROCESSES);
    }
    egui::ScrollArea::vertical()
        .id_salt("running_processes")
        .max_height(220.0)
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
                                let label = if group.count > 1 {
                                    strings::process_copies(&group.name, group.count)
                                } else {
                                    group.name.clone()
                                };
                                ui.label(RichText::new(label).strong());
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(group.path.as_ref().map_or_else(
                                            || strings::PATH_UNAVAILABLE.into(),
                                            |path| path.to_string_lossy(),
                                        ))
                                        .size(11.0)
                                        .color(theme::TEXT_DIM),
                                    )
                                    .wrap(),
                                );
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
                ui.colored_label(
                    theme::ROSE_LIGHT,
                    strings::will_match(&rosetun_core::rule_value_text(&RuleMatcher::Process(
                        matcher.clone(),
                    ))),
                );
                if let ProcessMatch::Name(name) = matcher
                    && let Some(actual) = different_process_case(name, &dialog.processes)
                {
                    ui.colored_label(theme::ERROR, strings::process_case_warning(actual));
                }
            }
            Err(error) => {
                ui.colored_label(theme::ERROR, error.to_string());
            }
        }
    }
    parsed.is_ok()
}
