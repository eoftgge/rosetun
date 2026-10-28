use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rosetun_config::{AppConfig, ListFormat, ListId, ListSource, Rule, RuleMatcher};
use rosetun_core::{ListError, MissingListCategory};

use super::{Action, Job, State};
use crate::errors;
use crate::worker::WorkerEvent;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(crate) enum RulesTab {
    #[default]
    Rules,
    Lists,
    Exits,
}

pub(crate) struct AddListDialog {
    pub(crate) url: String,
    pub(crate) file: Option<PathBuf>,
    pub(crate) name: String,
    pub(crate) name_manual: bool,
    pub(crate) busy: bool,
    pub(crate) browsing: bool,
    pub(crate) focus_url: bool,
    pub(crate) error: Option<ListError>,
    pub(crate) result: Option<(ListFormat, usize, Option<usize>)>,
}

impl Default for AddListDialog {
    fn default() -> Self {
        Self {
            url: String::new(),
            file: None,
            name: String::new(),
            name_manual: false,
            busy: false,
            browsing: false,
            focus_url: true,
            error: None,
            result: None,
        }
    }
}

impl AddListDialog {
    pub(crate) fn update_url(&mut self, value: String) {
        self.url = value;
        self.file = None;
        self.error = None;
        if !self.name_manual {
            self.name = suggested_url_name(&self.url).unwrap_or_default();
        }
    }

    pub(crate) fn set_file(&mut self, path: PathBuf) {
        if !self.name_manual {
            self.name = path
                .file_stem()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_owned();
        }
        self.file = Some(path);
        self.url.clear();
        self.error = None;
    }
}

fn suggested_url_name(input: &str) -> Option<String> {
    let url = url::Url::parse(input.trim()).ok()?;
    let name = url.path_segments()?.rfind(|part| !part.is_empty())?;
    let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
    (!stem.is_empty()).then(|| stem.to_owned())
}

pub(crate) struct RenameListDialog {
    pub(crate) id: ListId,
    pub(crate) name: String,
    pub(crate) focus: bool,
    pub(crate) busy: bool,
    pub(crate) error: Option<String>,
}

pub(crate) struct RemoveListDialog {
    pub(crate) id: ListId,
    pub(crate) busy: bool,
    pub(crate) error: Option<String>,
}

pub(crate) enum ListOutcome {
    Updated { applies_later: bool },
    Failed(ListError),
}

#[derive(Default)]
pub(crate) struct ListsState {
    pub(crate) tab: RulesTab,
    pub(crate) add: Option<AddListDialog>,
    pub(crate) rename: Option<RenameListDialog>,
    pub(crate) remove: Option<RemoveListDialog>,
    pub(crate) outcomes: BTreeMap<ListId, ListOutcome>,
    pub(crate) error: Option<String>,
    pub(crate) missing: Vec<MissingListCategory>,
    pub(crate) scan_error: Option<String>,
    scan_revision: u64,
    scan_needed: bool,
    scan_in_flight: Option<u64>,
}

pub(crate) fn used_by(config: &AppConfig, id: &ListId) -> Vec<String> {
    config
        .rule_sets
        .iter()
        .filter(|set| {
            set.rules
                .iter()
                .any(|rule| matches!(&rule.matcher, RuleMatcher::List { list, .. } if list == id))
        })
        .map(|set| set.name.clone())
        .collect()
}

impl State {
    pub(super) fn active_rules_use_list(&self, id: &ListId) -> bool {
        let uses_list = |rule: &Rule| {
            rule.enabled && matches!(&rule.matcher, RuleMatcher::List { list, .. } if list == id)
        };
        self.config
            .active_rules()
            .is_some_and(|set| set.rules.iter().any(uses_list))
            || self.session.temporary_rules.iter().any(uses_list)
    }

    pub(super) fn clear_delayed_list_updates(&mut self) {
        self.lists.outcomes.retain(|_, outcome| {
            !matches!(
                outcome,
                ListOutcome::Updated {
                    applies_later: true
                }
            )
        });
    }

    pub(super) fn request_list_inspection(&mut self) {
        self.lists.scan_revision = self.lists.scan_revision.wrapping_add(1);
        self.lists.scan_needed = true;
        self.lists.missing.clear();
        self.lists.scan_error = None;
    }

    pub(crate) fn take_list_inspection(&mut self) -> Option<Job> {
        if !self.config_ready || !self.lists.scan_needed || self.lists.scan_in_flight.is_some() {
            return None;
        }
        let revision = self.lists.scan_revision;
        self.lists.scan_in_flight = Some(revision);
        self.lists.scan_needed = false;
        Some(Job::InspectListCategories {
            revision,
            temporary: self.session.temporary_rules.clone(),
        })
    }

    pub(crate) fn missing_list_rule(
        &self,
        set: Option<&rosetun_config::RuleSetId>,
        rule: &rosetun_config::RuleId,
    ) -> Option<&MissingListCategory> {
        self.lists
            .missing
            .iter()
            .find(|missing| missing.set.as_ref() == set && &missing.rule == rule)
    }

    pub(crate) fn list_rule_name(&self, id: &ListId, category: Option<&str>) -> String {
        let name = self
            .config
            .lists
            .iter()
            .find(|list| &list.id == id)
            .map_or_else(|| tr!("list-source-unknown"), |list| self.text(&list.name));
        category.map_or(name.clone(), |category| {
            format!("{name}: {}", self.text(category))
        })
    }

    pub(crate) fn active_missing_categories(&self) -> usize {
        let active = self.config.active_rule_set.as_ref();
        let saved = self
            .config
            .active_rules()
            .map(|set| {
                set.rules
                    .iter()
                    .filter(|rule| {
                        rule.enabled && self.missing_list_rule(Some(&set.id), &rule.id).is_some()
                    })
                    .count()
            })
            .unwrap_or_default();
        let temporary = if active.is_some() {
            self.session
                .temporary_rules
                .iter()
                .filter(|rule| rule.enabled && self.missing_list_rule(None, &rule.id).is_some())
                .count()
        } else {
            0
        };
        saved + temporary
    }

    pub(super) fn reconcile_lists(&mut self) {
        self.lists
            .outcomes
            .retain(|id, _| self.config.lists.iter().any(|list| &list.id == id));
        if self
            .lists
            .rename
            .as_ref()
            .is_some_and(|dialog| !self.config.lists.iter().any(|list| list.id == dialog.id))
        {
            self.lists.rename = None;
        }
        if self
            .lists
            .remove
            .as_ref()
            .is_some_and(|dialog| !self.config.lists.iter().any(|list| list.id == dialog.id))
        {
            self.lists.remove = None;
        }
    }

    pub(super) fn reduce_lists(&mut self, event: WorkerEvent) {
        match event {
            WorkerEvent::ListAvailability { revision, result } => {
                if self.lists.scan_in_flight != Some(revision) {
                    return;
                }
                self.lists.scan_in_flight = None;
                if revision != self.lists.scan_revision {
                    self.lists.scan_needed = true;
                    return;
                }
                match result {
                    Ok(missing) => self.lists.missing = missing,
                    Err(error) => {
                        self.lists.scan_error =
                            Some(self.text(&errors::list(crate::i18n::language(), &error)));
                    }
                }
            }
            WorkerEvent::BrowsedListFile(path) => {
                if let Some(dialog) = &mut self.lists.add {
                    dialog.browsing = false;
                    if let Some(path) = path {
                        dialog.set_file(path);
                    }
                }
            }
            WorkerEvent::AddList(result) => {
                if let Some(dialog) = &mut self.lists.add {
                    dialog.busy = false;
                    match result {
                        Ok((list, entries)) => {
                            dialog.result = Some((list.format, list.categories.len(), entries));
                            dialog.error = None;
                        }
                        Err(error) => dialog.error = Some(error),
                    }
                }
            }
            WorkerEvent::UpdateList { id, result, manual } => {
                self.operations.updating_lists.remove(&id);
                if manual
                    && result.is_ok()
                    && self.session.session_request.is_some()
                    && self.active_rules_use_list(&id)
                {
                    self.session.lists_changed_since_apply = true;
                }
                self.lists.outcomes.insert(
                    id,
                    match result {
                        Ok(_) => ListOutcome::Updated {
                            applies_later: false,
                        },
                        Err(error) => ListOutcome::Failed(error),
                    },
                );
            }
            WorkerEvent::FileListUpdateCancelled(id) => {
                self.operations.updating_lists.remove(&id);
            }
            WorkerEvent::RenameList(result) => {
                let result = result
                    .map_err(|error| self.text(&errors::list(crate::i18n::language(), &error)));
                if let Some(dialog) = &mut self.lists.rename {
                    dialog.busy = false;
                    match result {
                        Ok(_) => self.lists.rename = None,
                        Err(error) => dialog.error = Some(error),
                    }
                }
            }
            WorkerEvent::RemoveList(result) => {
                let result = result
                    .map_err(|error| self.text(&errors::list(crate::i18n::language(), &error)));
                if let Some(dialog) = &mut self.lists.remove {
                    dialog.busy = false;
                    match result {
                        Ok(()) => self.lists.remove = None,
                        Err(error) => dialog.error = Some(error),
                    }
                }
            }
            _ => unreachable!("only list events are dispatched here"),
        }
    }

    pub(super) fn act_lists(&mut self, action: Action) -> Option<Job> {
        match action {
            Action::ShowLists => {
                self.lists.tab = RulesTab::Lists;
                return self.act_rules(Action::OpenRules);
            }
            Action::ShowRuleSets => self.lists.tab = RulesTab::Rules,
            Action::OpenAddList => {
                if self.config_ready && self.lists.add.is_none() {
                    self.lists.add = Some(AddListDialog::default());
                }
            }
            Action::CancelAddList => {
                if self
                    .lists
                    .add
                    .as_ref()
                    .is_some_and(|dialog| !dialog.busy && !dialog.browsing)
                {
                    self.lists.add = None;
                }
            }
            Action::BrowseListFile => {
                if let Some(dialog) = &mut self.lists.add
                    && !dialog.busy
                    && !dialog.browsing
                    && dialog.result.is_none()
                {
                    dialog.browsing = true;
                    return Some(Job::BrowseListFile);
                }
            }
            Action::SubmitAddList => {
                if let Some(dialog) = &mut self.lists.add
                    && !dialog.busy
                    && !dialog.browsing
                    && dialog.result.is_none()
                {
                    let name = dialog.name.trim();
                    if name.is_empty() {
                        dialog.error = Some(ListError::EmptyName);
                    } else if let Some(path) = dialog.file.as_ref() {
                        dialog.busy = true;
                        dialog.error = None;
                        return Some(Job::AddListFile(path.clone(), name.to_owned()));
                    } else if url::Url::parse(dialog.url.trim()).is_ok_and(|url| {
                        matches!(url.scheme(), "http" | "https") && url.host_str().is_some()
                    }) {
                        dialog.busy = true;
                        dialog.error = None;
                        return Some(Job::AddListUrl(
                            dialog.url.trim().to_owned(),
                            name.to_owned(),
                        ));
                    } else {
                        dialog.error = Some(ListError::InvalidUrl);
                    }
                }
            }
            action @ (Action::UpdateListManual(_) | Action::UpdateListFile(_)) => {
                let (id, choose_file) = match action {
                    Action::UpdateListManual(id) => (id, false),
                    Action::UpdateListFile(id) => (id, true),
                    _ => unreachable!(),
                };
                if self.config_ready
                    && !self.operations.update_all
                    && !self.operations.updating_lists.contains(&id)
                    && let Some(list) = self.config.lists.iter().find(|list| list.id == id)
                {
                    let file = matches!(list.source, ListSource::File { .. });
                    if file == choose_file {
                        self.operations.updating_lists.insert(id.clone());
                        self.lists.outcomes.remove(&id);
                        return Some(if file {
                            Job::UpdateListFile(id)
                        } else {
                            Job::UpdateListManual(id)
                        });
                    }
                }
            }
            Action::OpenRenameList(id) => {
                if self.lists.rename.is_none()
                    && let Some(list) = self.config.lists.iter().find(|list| list.id == id)
                {
                    self.lists.rename = Some(RenameListDialog {
                        id,
                        name: list.name.clone(),
                        focus: true,
                        busy: false,
                        error: None,
                    });
                }
            }
            Action::CancelRenameList => {
                if self
                    .lists
                    .rename
                    .as_ref()
                    .is_some_and(|dialog| !dialog.busy)
                {
                    self.lists.rename = None;
                }
            }
            Action::SubmitRenameList => {
                if let Some(dialog) = &mut self.lists.rename
                    && !dialog.busy
                {
                    dialog.busy = true;
                    dialog.error = None;
                    return Some(Job::RenameList(
                        dialog.id.clone(),
                        dialog.name.trim().to_owned(),
                    ));
                }
            }
            Action::OpenRemoveList(id) => {
                if self.lists.remove.is_none()
                    && self.config.lists.iter().any(|list| list.id == id)
                    && used_by(&self.config, &id).is_empty()
                {
                    self.lists.remove = Some(RemoveListDialog {
                        id,
                        busy: false,
                        error: None,
                    });
                }
            }
            Action::CancelRemoveList => {
                if self
                    .lists
                    .remove
                    .as_ref()
                    .is_some_and(|dialog| !dialog.busy)
                {
                    self.lists.remove = None;
                }
            }
            Action::ConfirmRemoveList => {
                if let Some(dialog) = &mut self.lists.remove
                    && !dialog.busy
                    && used_by(&self.config, &dialog.id).is_empty()
                {
                    dialog.busy = true;
                    dialog.error = None;
                    return Some(Job::RemoveList(dialog.id.clone()));
                }
            }
            Action::DismissListsError => self.lists.error = None,
            _ => unreachable!("only list actions are dispatched here"),
        }
        None
    }
}

pub(crate) fn source_file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned()
}
