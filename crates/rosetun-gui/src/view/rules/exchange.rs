use eframe::egui;
use rosetun_config::{ListSource, RuleMatcher, rules_exchange::Warning};

use crate::state::{Action, State};
use crate::{theme, widgets};

pub(crate) fn show(ctx: &egui::Context, state: &mut State, actions: &mut Vec<Action>) {
    let busy = state.rules.exchange.busy;
    if let Some(export) = &mut state.rules.exchange.export {
        let urls = !export.hosts.is_empty();
        let choice = widgets::three_way_modal(ctx, widgets::ThreeWayModal {
            id:"rules_export",title:tr!("rules-transfer-export"),cancel:tr!("cancel"),
            confirm:if urls { tr!("rules-transfer-include") } else { tr!("rules-transfer-export") },
            other:tr!("rules-transfer-without"),
        }, |ui| {
            if urls { ui.label(tr!("rules-transfer-url-warning")); for host in &export.hosts { ui.label(host); } }
            #[cfg(windows)]
            widgets::checkbox(ui,&mut export.file,tr!("rules-transfer-to-file"),true);
            #[cfg(target_os = "linux")]
            ui.label(tr!("rules-transfer-linux"));
            ui.label(tr!("rules-transfer-to-clipboard"));
        });
        match choice {
            widgets::ThreeWayChoice::Confirm => actions.push(Action::ConfirmRulesExport(urls)),
            widgets::ThreeWayChoice::Other => actions.push(Action::ConfirmRulesExport(false)),
            widgets::ThreeWayChoice::Cancel => actions.push(Action::CancelRulesExchange),
            widgets::ThreeWayChoice::None => {}
        }
    } else if let Some(import) = &mut state.rules.exchange.import {
        let choice = widgets::three_way_modal(ctx, widgets::ThreeWayModal {
            id:"rules_import",title:tr!("rules-transfer-preview"),cancel:tr!("cancel"),confirm:tr!("rules-transfer-add"),other:tr!("rules-transfer-replace"),
        }, |ui| {
            ui.label(format!("{} {} · {} {} · {} {} · {} {}",tr!("rules-transfer-add"),import.add.rules.len(),tr!("rules-transfer-duplicates"),import.add.duplicates,tr!("rules-transfer-disabled"),import.add.rules.iter().filter(|rule| !rule.enabled).count(),tr!("rules-transfer-invalid-rows"),import.add.entries.iter().filter(|entry| entry.invalid).count()));
            ui.label(format!("{}: {}",tr!("rules-transfer-replace"),import.replace.rules.len()));
            egui::ScrollArea::vertical().max_height(widgets::DialogWidth::Narrow.points()).show(ui, |ui| {
                for rule in &import.replace.rules {
                    let label = match &rule.matcher {
                        RuleMatcher::List { list, category } => {
                            let entry = import.replace.lists.iter().chain(&state.config.lists).find(|entry| &entry.id == list);
                            entry.map_or_else(|| tr!("rules-transfer-needs-list"), |entry| {
                                let file = match &entry.source { ListSource::File { original_name } => format!(" ({original_name})"), ListSource::Url(_) => String::new() };
                                format!("{}{} {}", entry.name,file,category.as_deref().unwrap_or_default())
                            })
                        }
                        matcher => rosetun_core::rule_value_text(matcher),
                    };
                    ui.label(format!("{label} → {}",super::target_label(rule.target)));
                }
                for entry in &import.replace.entries {
                    for warning in &entry.warnings {
                        let text = match warning { Warning::OtherSystem => tr!("rules-transfer-other-system"), Warning::NeedsList => tr!("rules-transfer-needs-list"), Warning::NeedsFile => tr!("rules-transfer-needs-file"), Warning::ExitReplaced => tr!("rules-transfer-exit-replaced"), Warning::BroadDirect => tr!("rules-transfer-broad") };
                        ui.colored_label(theme::ERROR,format!("{}: {text}",entry.index+1));
                    }
                }
            });
            if let Some(target) = import.add.default_target {
                widgets::checkbox(ui,&mut import.default_target,format!("{}: {}?",tr!("rules-transfer-default"),super::target_label(target)),!busy);
                if target == rosetun_config::RuleTarget::Direct { ui.colored_label(theme::ERROR,tr!("rules-transfer-broad")); }
            }
        });
        match choice {
            widgets::ThreeWayChoice::Confirm => actions.push(Action::ConfirmRulesImport(false)),
            widgets::ThreeWayChoice::Other => actions.push(Action::ConfirmRulesImport(true)),
            widgets::ThreeWayChoice::Cancel => actions.push(Action::CancelRulesExchange),
            widgets::ThreeWayChoice::None => {}
        }
    } else if let Some(error) = &state.rules.exchange.error {
        let choice = widgets::confirm_modal(ctx,widgets::ConfirmModal { id:"rules_exchange_error",title:tr!("rules-transfer-import"),cancel:tr!("cancel"),confirm:tr!("close"),busy:false,confirm_enabled:true,width:widgets::DialogWidth::Standard }, |ui| { ui.label(error); });
        if choice != widgets::ModalChoice::None { actions.push(Action::CancelRulesExchange); }
    }
}
