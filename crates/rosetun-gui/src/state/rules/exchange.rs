use rosetun_config::{
    AppConfig, RuleSetId,
    rules_exchange::{self, Document, Preview, System},
};

use super::{Action, Job, State};

#[derive(Default)]
pub(crate) struct ExchangeState {
    pub(crate) export: Option<Export>,
    pub(crate) import: Option<Import>,
    pub(crate) error: Option<String>,
    pub(crate) busy: bool,
    pub(crate) notice: Option<String>,
}
pub(crate) struct Export {
    pub(crate) name: String,
    config: AppConfig,
    set: RuleSetId,
    pub(crate) selected: Option<Vec<rosetun_config::RuleId>>,
    pub(crate) hosts: Vec<String>,
    pub(crate) file: bool,
}
pub(crate) struct Import {
    pub(crate) add: Preview,
    pub(crate) replace: Preview,
    pub(crate) default_target: bool,
    config: AppConfig,
    set: RuleSetId,
}
fn exchange_error(error: rules_exchange::ExchangeError) -> String {
    match error {
        rules_exchange::ExchangeError::Size => tr!("rules-transfer-size"),
        rules_exchange::ExchangeError::Count => tr!("rules-transfer-count"),
        rules_exchange::ExchangeError::Version => tr!("rules-transfer-version"),
        rules_exchange::ExchangeError::Invalid => tr!("rules-transfer-invalid"),
    }
}
impl State {
    pub(crate) fn act_rules_exchange(&mut self, action: Action) -> Option<Job> {
        match action {
            Action::CancelRulesExchange if !self.rules.exchange.busy => {
                self.rules.exchange.export = None;
                self.rules.exchange.import = None;
                self.rules.exchange.error = None;
                self.rules.exchange.notice = None;
            }
            Action::OpenRulesExport(selected) if self.can_edit_rules() => {
                self.rules.exchange.notice = None;
                let set = self.selected_rules()?;
                let selected = selected.then(|| self.selected_rule_ids());
                if selected.as_ref().is_some_and(Vec::is_empty) {
                    return None;
                }
                let text = match rules_exchange::export(
                    &self.config,
                    set,
                    selected.as_deref(),
                    true,
                    System::current(),
                ) {
                    Ok(text) => text,
                    Err(error) => {
                        self.rules.exchange.error = Some(exchange_error(error));
                        return None;
                    }
                };
                let document = rules_exchange::parse(&text).ok()?;
                let mut hosts = Vec::new();
                for list in document.lists {
                    if let Some(rules_exchange::Source::Url(value)) = list.source
                        && let Ok(url) = url::Url::parse(&value)
                        && let Some(host) = url.host_str()
                        && !hosts.iter().any(|existing| existing == host)
                    {
                        hosts.push(host.to_owned());
                    }
                }
                self.rules.exchange.export = Some(Export {
                    name: self.text(&set.name),
                    config: self.config.clone(),
                    set: set.id.clone(),
                    selected,
                    hosts,
                    file: cfg!(windows),
                });
                self.rules.exchange.error = None;
            }
            Action::ConfirmRulesExport(urls) if !self.rules.exchange.busy => {
                let pending = self.rules.exchange.export.take()?;
                let set = pending
                    .config
                    .rule_sets
                    .iter()
                    .find(|set| set.id == pending.set)?;
                match rules_exchange::export(
                    &pending.config,
                    set,
                    pending.selected.as_deref(),
                    urls,
                    System::current(),
                ) {
                    Ok(text) => {
                        self.rules.exchange.busy = true;
                        return Some(Job::WriteRules(text, pending.file));
                    }
                    Err(error) => self.rules.exchange.error = Some(exchange_error(error)),
                }
            }
            Action::ReadRulesImport(file) if self.can_edit_rules() && !self.rules.exchange.busy => {
                self.rules.exchange.error = None;
                self.rules.exchange.notice = None;
                self.rules.exchange.busy = true;
                return Some(Job::ReadRules(file));
            }
            Action::ConfirmRulesImport(replace)
                if self.can_edit_rules() && !self.rules.exchange.busy =>
            {
                let pending = self.rules.exchange.import.take()?;
                if self.config != pending.config {
                    self.rules.exchange.error = Some(tr!("rules-transfer-changed"));
                    return None;
                }
                let preview = if replace {
                    pending.replace
                } else {
                    pending.add
                };
                self.rules.exchange.busy = true;
                return self.start_rule_edit(Job::ImportRules(
                    pending.set,
                    preview,
                    replace,
                    pending.default_target,
                ));
            }
            _ => {}
        }
        None
    }
    pub(crate) fn reduce_rules_read(&mut self, result: Result<Option<String>, String>) {
        self.rules.exchange.busy = false;
        self.rules.exchange.import = None;
        let text = match result {
            Ok(Some(text)) => text,
            Ok(None) => return,
            Err(_) => {
                self.rules.exchange.error = Some(tr!("rules-transfer-read-error"));
                return;
            }
        };
        match rules_exchange::parse(&text) {
            Ok(document) => self.preview_rules_import(&document),
            Err(error) => self.rules.exchange.error = Some(exchange_error(error)),
        }
    }
    fn preview_rules_import(&mut self, document: &Document) {
        let Some(set) = self.selected_rules() else {
            return;
        };
        self.rules.exchange.import = Some(Import {
            add: rules_exchange::preview(document, &self.config, set, false, System::current()),
            replace: rules_exchange::preview(document, &self.config, set, true, System::current()),
            default_target: false,
            config: self.config.clone(),
            set: set.id.clone(),
        });
    }
    pub(crate) fn reduce_rules_written(
        &mut self,
        result: Result<crate::worker::RulesExportOutcome, String>,
    ) {
        use crate::worker::RulesExportOutcome;
        self.rules.exchange.busy = false;
        self.rules.exchange.error = None;
        self.rules.exchange.notice = None;
        match result {
            Ok(RulesExportOutcome::Copied) => {
                self.rules.exchange.notice = Some(tr!("rules-transfer-copied"));
            }
            #[cfg(windows)]
            Ok(RulesExportOutcome::Saved) => {
                self.rules.exchange.notice = Some(tr!("rules-transfer-saved"));
            }
            #[cfg(windows)]
            Ok(RulesExportOutcome::Cancelled) => {}
            Err(_) => self.rules.exchange.error = Some(tr!("rules-transfer-write-error")),
        }
    }
    pub(crate) fn finish_import_rules(&mut self, result: Result<(), rosetun_core::RuleSetError>) {
        self.rules.exchange.busy = false;
        self.finish_rule_edit(result);
        self.rules.screen.clear_selection();
    }
}
