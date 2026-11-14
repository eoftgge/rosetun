use eframe::egui;
use rosetun_config::{ListSource, RuleMatcher, rules_exchange::Warning};

use crate::state::{Action, State};
use crate::{theme, widgets};

pub(crate) fn show(ctx: &egui::Context, state: &mut State, actions: &mut Vec<Action>) {
    let busy = state.rules.exchange.busy;
    if let Some(export) = &mut state.rules.exchange.export {
        let urls = !export.hosts.is_empty();
        let mut choice = widgets::FooterChoice::None;
        let response =
            widgets::Dialog::new("rules_export", widgets::DialogWidth::Standard).show(ctx, |ui| {
                ui.heading(tr!("rules-transfer-export"));
                ui.label(&export.name);
                ui.add_space(theme::space::M);
                ui.label(if export.selected.is_some() {
                    tr!("rules-transfer-selected")
                } else {
                    tr!("rules-transfer-all")
                });
                ui.add_space(theme::space::M);
                #[cfg(windows)]
                if let Some(file) = widgets::segmented(
                    ui,
                    "rules_export_destination",
                    export.file,
                    &[
                        (true, tr!("rules-transfer-to-file")),
                        (false, tr!("rules-transfer-to-clipboard")),
                    ],
                    false,
                    !busy,
                ) {
                    export.file = file;
                }
                #[cfg(target_os = "linux")]
                {
                    ui.label(tr!("rules-transfer-to-clipboard"));
                    ui.label(tr!("rules-transfer-linux"));
                }
                if urls {
                    ui.add_space(theme::space::L);
                    ui.label(tr!("rules-transfer-url-warning"));
                    for host in &export.hosts {
                        ui.label(host);
                    }
                }
                let mut footer = widgets::DialogFooter::new(
                    if urls {
                        tr!("rules-transfer-include")
                    } else {
                        tr!("rules-transfer-export")
                    },
                    tr!("cancel"),
                )
                .busy(busy);
                if urls {
                    footer = footer.other(tr!("rules-transfer-without"));
                }
                choice = widgets::dialog_footer(ui, footer).choice();
            });
        if response.should_close() && choice == widgets::FooterChoice::None {
            choice = widgets::FooterChoice::Cancel;
        }
        match choice {
            widgets::FooterChoice::Primary => actions.push(Action::ConfirmRulesExport(urls)),
            widgets::FooterChoice::Other => actions.push(Action::ConfirmRulesExport(false)),
            widgets::FooterChoice::Cancel => actions.push(Action::CancelRulesExchange),
            widgets::FooterChoice::None => {}
        }
    } else if let Some(import) = &mut state.rules.exchange.import {
        let choice = widgets::three_way_modal(
            ctx,
            widgets::ThreeWayModal {
                id: "rules_import",
                title: tr!("rules-transfer-preview"),
                cancel: tr!("cancel"),
                confirm: tr!("rules-transfer-add"),
                other: tr!("rules-transfer-replace"),
            },
            |ui| {
                ui.label(format!(
                    "{} {} · {} {} · {} {} · {} {}",
                    tr!("rules-transfer-add"),
                    import.add.rules.len(),
                    tr!("rules-transfer-duplicates"),
                    import.add.duplicates,
                    tr!("rules-transfer-disabled"),
                    import.add.rules.iter().filter(|rule| !rule.enabled).count(),
                    tr!("rules-transfer-invalid-rows"),
                    import
                        .add
                        .entries
                        .iter()
                        .filter(|entry| entry.invalid)
                        .count()
                ));
                ui.label(format!(
                    "{}: {}",
                    tr!("rules-transfer-replace"),
                    import.replace.rules.len()
                ));
                egui::ScrollArea::vertical()
                    .max_height(widgets::DialogWidth::Narrow.points())
                    .show(ui, |ui| {
                        for (row, rule) in import.replace.rules.iter().enumerate() {
                            let label = match &rule.matcher {
                                RuleMatcher::List { list, category } => {
                                    let entry = import
                                        .replace
                                        .lists
                                        .iter()
                                        .chain(&state.config.lists)
                                        .find(|entry| &entry.id == list);
                                    entry.map_or_else(
                                        || tr!("rules-transfer-needs-list"),
                                        |entry| {
                                            let file = match &entry.source {
                                                ListSource::File { original_name }
                                                    if original_name == "list-required" =>
                                                {
                                                    String::new()
                                                }
                                                ListSource::File { original_name } => {
                                                    format!(" ({original_name})")
                                                }
                                                ListSource::Url(value) => url::Url::parse(value)
                                                    .ok()
                                                    .and_then(|url| {
                                                        url.host_str()
                                                            .map(|host| format!(" ({host})"))
                                                    })
                                                    .unwrap_or_default(),
                                            };
                                            format!(
                                                "{}{} {}",
                                                entry.name,
                                                file,
                                                category.as_deref().unwrap_or_default()
                                            )
                                        },
                                    )
                                }
                                matcher => rosetun_core::rule_value_text(matcher),
                            };
                            let target = rule
                                .exit
                                .as_ref()
                                .and_then(|id| {
                                    state.config.exits.iter().find(|exit| &exit.id == id)
                                })
                                .map_or_else(
                                    || super::target_label(rule.target),
                                    |exit| {
                                        format!(
                                            "{}: {}",
                                            super::target_label(rule.target),
                                            exit.name
                                        )
                                    },
                                );
                            let index = import.replace.indexes[row];
                            ui.label(format!("{}: {label} → {target}", index + 1));
                            if !import.add.indexes.contains(&index) {
                                ui.label(tr!("rules-transfer-duplicate-add"));
                            }
                        }
                        for entry in &import.replace.entries {
                            for warning in &entry.warnings {
                                let text = match warning {
                                    Warning::OtherSystem => tr!("rules-transfer-other-system"),
                                    Warning::NeedsList => tr!("rules-transfer-needs-list"),
                                    Warning::NeedsFile => tr!("rules-transfer-needs-file"),
                                    Warning::ExitReplaced => tr!("rules-transfer-exit-replaced"),
                                    Warning::BroadDirect => tr!("rules-transfer-broad"),
                                };
                                ui.colored_label(
                                    theme::ERROR,
                                    format!("{}: {text}", entry.index + 1),
                                );
                            }
                        }
                    });
                if let Some(target) = import.add.default_target {
                    widgets::checkbox(
                        ui,
                        &mut import.default_target,
                        format!(
                            "{}: {}?",
                            tr!("rules-transfer-default"),
                            super::target_label(target)
                        ),
                        !busy,
                    );
                    if target == rosetun_config::RuleTarget::Direct {
                        ui.colored_label(theme::ERROR, tr!("rules-transfer-broad"));
                    }
                }
            },
        );
        match choice {
            widgets::ThreeWayChoice::Confirm => actions.push(Action::ConfirmRulesImport(false)),
            widgets::ThreeWayChoice::Other => actions.push(Action::ConfirmRulesImport(true)),
            widgets::ThreeWayChoice::Cancel => actions.push(Action::CancelRulesExchange),
            widgets::ThreeWayChoice::None => {}
        }
    } else if let Some(error) = &state.rules.exchange.error {
        let choice = widgets::confirm_modal(
            ctx,
            widgets::ConfirmModal {
                id: "rules_exchange_error",
                title: tr!("rules-transfer-import"),
                cancel: tr!("cancel"),
                confirm: tr!("done"),
                busy: false,
                confirm_enabled: true,
                width: widgets::DialogWidth::Standard,
            },
            |ui| {
                ui.label(error);
            },
        );
        if choice != widgets::ModalChoice::None {
            actions.push(Action::CancelRulesExchange);
        }
    }
    if let Some(notice) = &state.rules.exchange.notice {
        let done = tr!("done");
        if widgets::action_notice(
            ctx,
            "rules_export_notice",
            notice,
            &[widgets::NoticeAction {
                label: &done,
                hint: None,
                enabled: true,
            }],
        )
        .is_some()
        {
            actions.push(Action::CancelRulesExchange);
        }
    }
}

#[cfg(test)]
mod tests {
    use rosetun_config::{List, ListFormat, ListId, Rule, RuleId, RuleSet, RuleSetId, RuleTarget};

    use super::*;
    use crate::i18n::{self, Language};
    use crate::state::Screen;
    use crate::test_ui::TestScreen;
    use crate::worker::{RulesExportOutcome, WorkerEvent};

    fn state() -> State {
        let mut state = State::default();
        state.config_ready = true;
        state.screen = Screen::Rules;
        let mut set = RuleSet::new(RuleSetId::new("1"), "Main", RuleTarget::Proxy);
        let list = ListId::new("1");
        state.config.lists.push(List {
            id: list.clone(),
            name: "Sites".into(),
            source: ListSource::Url("https://lists.example.com/private-token".into()),
            format: ListFormat::Text,
            updated_at: None,
            size: None,
            sha256: None,
            categories: vec![],
        });
        set.rules.push(Rule {
            id: RuleId::new("1"),
            enabled: true,
            matcher: RuleMatcher::List {
                list,
                category: None,
            },
            target: RuleTarget::Proxy,
            exit: None,
        });
        state.rules.screen.selected_set = Some(set.id.clone());
        state.config.active_rule_set = Some(set.id.clone());
        state.config.rule_sets.push(set);
        state
    }

    #[test]
    fn the_rule_set_picker_only_selects_sets() {
        i18n::in_language(Language::English, || {
            let mut state = state();
            let mut screen = TestScreen::new(egui::vec2(1440.0, 1000.0));
            let shown = screen.settle(|ui| {
                crate::view::show(ui, &mut state);
            });
            assert!(
                !shown
                    .iter()
                    .any(|(text, _)| text == &tr!("rules-transfer-export")
                        || text == &tr!("rules-transfer-import"))
            );
            let shown = screen.click_text("Main", |ui| {
                crate::view::show(ui, &mut state);
            });
            for label in [
                format!(
                    "{}: {}",
                    tr!("rules-transfer-export"),
                    tr!("rules-transfer-all")
                ),
                format!(
                    "{}: {}",
                    tr!("rules-transfer-import"),
                    tr!("rules-transfer-clipboard")
                ),
            ] {
                assert!(
                    !shown.iter().any(|(text, _)| text == &label),
                    "exchange command leaked into set picker: {label}"
                );
            }
        });
    }

    #[test]
    fn exporting_another_set_does_not_activate_it() {
        let mut state = state();
        let active = state.config.active_rule_set.clone();
        let mut other = RuleSet::new(RuleSetId::new("2"), "Other", RuleTarget::Direct);
        other.rules.push(Rule {
            id: RuleId::new("2"),
            enabled: true,
            matcher: RuleMatcher::IpCidr("192.0.2.0/24".into()),
            target: RuleTarget::Block,
            exit: None,
        });
        state.config.rule_sets.push(other);
        state.act(Action::ChooseRuleSet(RuleSetId::new("2")));
        state.act(Action::OpenRulesExport(false));
        assert_eq!(state.rules.exchange.export.as_ref().unwrap().name, "Other");
        let Some(crate::state::Job::WriteRules(document, _)) =
            state.act(Action::ConfirmRulesExport(false))
        else {
            panic!("export job");
        };
        assert!(document.contains("192.0.2.0/24"));
        assert!(!document.contains("Sites"));
        assert_eq!(state.config.active_rule_set, active);
    }

    #[test]
    fn without_links_exports_to_the_chosen_destination_and_reports_copying() {
        i18n::in_language(Language::English, || {
            let mut state = state();
            state.act(Action::OpenRulesExport(false));
            assert_eq!(
                state.rules.exchange.export.as_ref().unwrap().file,
                cfg!(windows)
            );
            let mut screen = TestScreen::new(egui::vec2(1440.0, 1000.0));
            let mut area = None;
            screen.settle(|ui| {
                crate::view::show(ui, &mut state);
                area = ui
                    .ctx()
                    .memory(|memory| memory.area_rect(egui::Id::unique("rules_export")));
            });
            assert!(area.unwrap().center().distance(egui::pos2(720.0, 500.0)) < 1.0);
            #[cfg(windows)]
            screen.click_text(&tr!("rules-transfer-to-clipboard"), |ui| {
                crate::view::show(ui, &mut state);
            });
            let mut actions = Vec::new();
            screen.click_text(&tr!("rules-transfer-without"), |ui| {
                actions.extend(crate::view::show(ui, &mut state));
            });
            assert!(
                actions
                    .iter()
                    .any(|action| matches!(action, Action::ConfirmRulesExport(false)))
            );
            let Some(crate::state::Job::WriteRules(document, file)) =
                state.act(Action::ConfirmRulesExport(false))
            else {
                panic!("export job");
            };
            assert!(!file);
            assert!(!document.contains("private-token"));
            assert!(!document.contains("lists.example.com"));
            state.reduce(WorkerEvent::RulesWritten(Ok(RulesExportOutcome::Copied)));
            let shown = screen.settle(|ui| {
                crate::view::show(ui, &mut state);
            });
            assert!(
                shown
                    .iter()
                    .any(|(text, _)| text == &tr!("rules-transfer-copied"))
            );
        });
    }

    #[test]
    fn exporting_without_url_lists_has_no_link_consent_buttons() {
        i18n::in_language(Language::English, || {
            let mut state = state();
            state.config.rule_sets[0].rules.clear();
            state.act(Action::OpenRulesExport(false));
            let mut screen = TestScreen::new(egui::vec2(900.0, 720.0));
            let shown = screen.settle(|ui| {
                crate::view::show(ui, &mut state);
            });
            assert!(
                !shown
                    .iter()
                    .any(|(text, _)| text == &tr!("rules-transfer-without")
                        || text == &tr!("rules-transfer-include"))
            );
        });
    }
}
