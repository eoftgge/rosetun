#[cfg(windows)]
use std::path::PathBuf;

use rosetun_config::{
    DomainMatch, ListId, ProcessMatch, Rule, RuleId, RuleMatcher, RuleSetId, RuleTarget,
};

use super::super::{Action, Job, State};
use crate::errors;
use crate::rules::{ProcessGroup, ProcessMatchMode, group_processes};
use crate::worker::WorkerEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum RuleInputKind {
    Domain,
    List,
    #[default]
    Process,
}

pub(crate) const MAX_LIST_RULES: usize = 256;

pub(crate) struct AddRuleDialog {
    pub(crate) set: RuleSetId,
    pub(crate) kind: RuleInputKind,
    pub(crate) target: RuleTarget,
    pub(crate) domains: String,
    pub(crate) list: Option<ListId>,
    pub(crate) selected_categories: Vec<String>,
    pub(crate) category_filter: String,
    pub(crate) subdomains: bool,
    pub(crate) show_all: bool,
    pub(crate) advanced: bool,
    pub(crate) temporary_only: bool,
    pub(crate) editing: Option<RuleId>,
    original_domain: Option<DomainMatch>,
    pub(crate) process: String,
    pub(crate) process_filter: String,
    pub(crate) processes: Vec<ProcessGroup>,
    pub(crate) selected_process: Option<usize>,
    pub(crate) match_mode: ProcessMatchMode,
    #[cfg(windows)]
    pub(crate) browsing: bool,
    #[cfg(windows)]
    pub(crate) browsed: Option<PathBuf>,
    pub(crate) load_request: Option<u64>,
    pub(crate) processes_loaded: bool,
    pub(crate) processes_error: Option<String>,
    pub(crate) busy: bool,
    pub(crate) error: Option<String>,
    pub(crate) focus_input: bool,
}

impl AddRuleDialog {
    pub(crate) fn new(set: RuleSetId) -> Self {
        Self {
            set,
            kind: RuleInputKind::Process,
            target: RuleTarget::Proxy,
            domains: String::new(),
            list: None,
            selected_categories: Vec::new(),
            category_filter: String::new(),
            subdomains: true,
            show_all: false,
            advanced: false,
            temporary_only: false,
            editing: None,
            original_domain: None,
            process: String::new(),
            process_filter: String::new(),
            processes: Vec::new(),
            selected_process: None,
            match_mode: ProcessMatchMode::Name,
            #[cfg(windows)]
            browsing: false,
            #[cfg(windows)]
            browsed: None,
            load_request: None,
            processes_loaded: false,
            processes_error: None,
            busy: false,
            error: None,
            focus_input: true,
        }
    }

    pub(in crate::state) fn for_rule(set: RuleSetId, rule: &Rule) -> Option<Self> {
        let mut dialog = Self::new(set);
        dialog.editing = Some(rule.id.clone());
        dialog.target = rule.target;
        match &rule.matcher {
            RuleMatcher::Domain(domain) => {
                dialog.kind = RuleInputKind::Domain;
                dialog.subdomains = matches!(domain, DomainMatch::Suffix(_));
                dialog.domains = rosetun_core::rule_value_text(&rule.matcher)
                    .trim_start_matches("*.")
                    .to_owned();
                dialog.original_domain = Some(domain.clone());
            }
            RuleMatcher::List { list, category } => {
                dialog.kind = RuleInputKind::List;
                dialog.list = Some(list.clone());
                dialog.selected_categories = category.iter().cloned().collect();
            }
            RuleMatcher::Process(process) => {
                dialog.process = rosetun_core::rule_value_text(&rule.matcher);
                match process {
                    ProcessMatch::Name(name) => dialog.process_filter = name.clone(),
                    ProcessMatch::Path(path) => {
                        dialog.match_mode = ProcessMatchMode::Path;
                        dialog.advanced = true;
                        dialog.process_filter = path
                            .file_name()
                            .map_or_else(|| path.to_string_lossy(), |name| name.to_string_lossy())
                            .into_owned();
                        #[cfg(windows)]
                        {
                            dialog.browsed = Some(path.clone());
                        }
                    }
                }
            }
            _ => return None,
        }
        Some(dialog)
    }

    pub(crate) fn unchanged_domain(&self) -> Option<DomainMatch> {
        let original = self.original_domain.as_ref()?;
        let matcher = RuleMatcher::Domain(original.clone());
        let value = rosetun_core::rule_value_text(&matcher);
        let value = value.strip_prefix("*.").unwrap_or(&value);
        (self.domains.trim() == value
            && self.subdomains == matches!(original, DomainMatch::Suffix(_)))
        .then(|| original.clone())
    }

    pub(crate) fn select_list(&mut self, list: ListId) {
        if self.list.as_ref() != Some(&list) {
            self.list = Some(list);
            self.selected_categories.clear();
            self.category_filter.clear();
            self.error = None;
        }
    }

    pub(crate) fn toggle_category(&mut self, category: &str) {
        if let Some(index) = self
            .selected_categories
            .iter()
            .position(|item| item == category)
        {
            self.selected_categories.remove(index);
        } else {
            if self.editing.is_some() {
                self.selected_categories.clear();
            }
            self.selected_categories.push(category.to_owned());
        }
        self.error = None;
    }

    pub(crate) fn exceeds_list_limit(&self, existing: usize, has_categories: bool) -> bool {
        self.editing.is_none()
            && existing
                + if has_categories {
                    self.selected_categories.len()
                } else {
                    1
                }
                > MAX_LIST_RULES
    }

    pub(crate) fn set_process_match_mode(&mut self, mode: ProcessMatchMode) {
        self.match_mode = mode;
        if let Some(group) = self
            .selected_process
            .and_then(|index| self.processes.get(index))
        {
            let value = match mode {
                ProcessMatchMode::Name => Some(group.name.clone()),
                ProcessMatchMode::Path => group
                    .path
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned()),
            };
            if let Some(value) = value {
                self.process = value;
            }
        } else {
            #[cfg(windows)]
            if let Some(path) = &self.browsed {
                self.process = browsed_process_value(path, mode);
                self.error = None;
                return;
            }
            if mode == ProcessMatchMode::Name
                && let Ok(ProcessMatch::Path(path)) =
                    rosetun_core::parse_process_input(&self.process)
                && let Some(name) = path.file_name()
            {
                self.process = name.to_string_lossy().into_owned();
            }
        }
        self.error = None;
    }
}

#[cfg(windows)]
fn browsed_process_value(path: &std::path::Path, mode: ProcessMatchMode) -> String {
    match mode {
        ProcessMatchMode::Name => path
            .file_name()
            .map_or_else(|| path.to_string_lossy(), |name| name.to_string_lossy())
            .into_owned(),
        ProcessMatchMode::Path => path.to_string_lossy().into_owned(),
    }
}

impl State {
    pub(crate) fn selected_list_rule_count(&self) -> usize {
        let selected = self.rules.screen.selected_set.as_ref();
        let permanent = self
            .config
            .rule_sets
            .iter()
            .find(|set| Some(&set.id) == selected)
            .map_or(0, |set| {
                set.rules
                    .iter()
                    .filter(|rule| matches!(rule.matcher, RuleMatcher::List { .. }))
                    .count()
            });
        let temporary = if self.config.active_rule_set.as_ref() == selected {
            self.session
                .temporary_rules
                .iter()
                .filter(|rule| matches!(rule.matcher, RuleMatcher::List { .. }))
                .count()
        } else {
            0
        };
        permanent + temporary
    }

    fn load_processes(&mut self) -> Option<Job> {
        let dialog = self.rules.screen.add.as_mut()?;
        if dialog.kind != RuleInputKind::Process || dialog.load_request.is_some() || dialog.busy {
            return None;
        }
        self.rules.next_process_request += 1;
        dialog.load_request = Some(self.rules.next_process_request);
        dialog.processes_error = None;
        Some(Job::LoadProcesses(self.rules.next_process_request))
    }

    pub(super) fn reduce_rule_dialog(&mut self, event: WorkerEvent) {
        match event {
            WorkerEvent::Processes { request, result } => {
                let message = result
                    .as_ref()
                    .err()
                    .map(|error| self.text(&errors::process_list(crate::i18n::language(), error)));
                if let Some(dialog) = &mut self.rules.screen.add
                    && dialog.load_request == Some(request)
                {
                    dialog.load_request = None;
                    match result {
                        Ok(processes) => {
                            dialog.processes = group_processes(processes);
                            dialog.processes_loaded = true;
                            dialog.selected_process = None;
                            dialog.processes_error = None;
                        }
                        Err(_) => dialog.processes_error = message,
                    }
                }
            }
            #[cfg(windows)]
            WorkerEvent::BrowsedExecutable(path) => {
                if let Some(dialog) = &mut self.rules.screen.add {
                    if !dialog.browsing {
                        return;
                    }
                    dialog.browsing = false;
                    if dialog.kind == RuleInputKind::Process
                        && let Some(path) = path
                    {
                        dialog.process = browsed_process_value(&path, dialog.match_mode);
                        dialog.process_filter = path
                            .file_name()
                            .map_or_else(|| path.to_string_lossy(), |name| name.to_string_lossy())
                            .into_owned();
                        dialog.browsed = Some(path);
                        dialog.selected_process = None;
                        dialog.error = None;
                        dialog.focus_input = true;
                    }
                }
            }
            _ => unreachable!("only rule dialog events are dispatched here"),
        }
    }

    pub(super) fn act_rule_dialog(&mut self, action: Action) -> Option<Job> {
        match action {
            Action::OpenAddRule => {
                if self.can_edit_rules()
                    && self.rules.screen.add.is_none()
                    && let Some(set) = self.selected_rules()
                {
                    self.rules.screen.add = Some(AddRuleDialog::new(set.id.clone()));
                    return self.load_processes();
                }
            }
            Action::OpenEditRule(id) => {
                if self.can_edit_rules()
                    && self.rules.screen.add.is_none()
                    && let Some(set) = self.selected_rules()
                    && let Some(rule) = set
                        .rules
                        .iter()
                        .find(|rule| rule.id == id && crate::rules::editable(&rule.matcher))
                    && let Some(dialog) = AddRuleDialog::for_rule(set.id.clone(), rule)
                {
                    self.rules.screen.add = Some(dialog);
                    if self.rules.screen.add.as_ref().unwrap().kind == RuleInputKind::Process {
                        return self.load_processes();
                    }
                }
            }
            Action::CancelAddRule => {
                if self
                    .rules
                    .screen
                    .add
                    .as_ref()
                    .is_some_and(|dialog| !dialog.busy)
                {
                    self.rules.screen.add = None;
                }
            }
            Action::SelectRuleInput(kind) => {
                if let Some(dialog) = &mut self.rules.screen.add
                    && !dialog.busy
                    && dialog.kind != kind
                    && dialog.editing.is_none()
                {
                    dialog.kind = kind;
                    dialog.error = None;
                    dialog.focus_input = true;
                    if kind == RuleInputKind::Process && !dialog.processes_loaded {
                        return self.load_processes();
                    }
                }
            }
            Action::RefreshProcesses => return self.load_processes(),
            #[cfg(windows)]
            Action::BrowseExecutable => {
                if let Some(dialog) = &mut self.rules.screen.add
                    && dialog.kind == RuleInputKind::Process
                    && !dialog.busy
                    && !dialog.browsing
                {
                    dialog.browsing = true;
                    return Some(Job::BrowseExecutable);
                }
            }
            Action::SubmitAddRule => {
                if self.can_edit_rules()
                    && let Some(dialog) = &self.rules.screen.add
                    && !dialog.busy
                    && self.rules.screen.selected_set.as_ref() == Some(&dialog.set)
                {
                    let matchers: Option<Vec<_>> = match dialog.kind {
                        RuleInputKind::Domain => {
                            if let Some(original) = dialog.unchanged_domain() {
                                Some(vec![RuleMatcher::Domain(original)])
                            } else {
                                let parsed = rosetun_core::parse_domain_lines(
                                    &dialog.domains,
                                    dialog.subdomains,
                                );
                                (parsed.errors.is_empty() && !parsed.domains.is_empty()).then(
                                    || {
                                        parsed
                                            .domains
                                            .into_iter()
                                            .map(RuleMatcher::Domain)
                                            .collect()
                                    },
                                )
                            }
                        }
                        RuleInputKind::Process => {
                            rosetun_core::parse_process_input(&dialog.process)
                                .ok()
                                .map(|process| vec![RuleMatcher::Process(process)])
                        }
                        RuleInputKind::List => dialog.list.as_ref().and_then(|list| {
                            let entry = self.config.lists.iter().find(|entry| &entry.id == list)?;
                            let categories = if entry.format.has_categories() {
                                if dialog.selected_categories.is_empty() {
                                    return None;
                                }
                                dialog
                                    .selected_categories
                                    .iter()
                                    .cloned()
                                    .map(Some)
                                    .collect()
                            } else {
                                vec![None]
                            };
                            Some(
                                categories
                                    .into_iter()
                                    .map(|category| RuleMatcher::List {
                                        list: list.clone(),
                                        category,
                                    })
                                    .collect(),
                            )
                        }),
                    };
                    if let Some(mut matchers) = matchers {
                        if dialog.kind == RuleInputKind::List {
                            let over_limit = dialog.editing.is_none()
                                && self.selected_list_rule_count() + matchers.len()
                                    > MAX_LIST_RULES;
                            if over_limit {
                                return None;
                            }
                            if let Some(error) = matchers.iter().find_map(|matcher| {
                                rosetun_core::validate_list_matcher(&self.config, matcher).err()
                            }) {
                                let message =
                                    self.text(&errors::rule_set(crate::i18n::language(), &error));
                                if let Some(dialog) = &mut self.rules.screen.add {
                                    dialog.error = Some(message);
                                }
                                return None;
                            }
                        }
                        if dialog.editing.is_some() && matchers.len() != 1 {
                            return None;
                        }
                        if dialog.temporary_only && dialog.editing.is_none() {
                            let target = dialog.target;
                            return self.act(Action::AddTemporary(matchers, target));
                        }
                        let job = if let Some(id) = &dialog.editing {
                            let current = self
                                .selected_rules()
                                .and_then(|set| set.rules.iter().find(|rule| &rule.id == id))?;
                            let matcher = matchers.pop().unwrap();
                            if current.matcher == matcher && current.target == dialog.target {
                                self.rules.screen.add = None;
                                return None;
                            }
                            Job::UpdateRule(dialog.set.clone(), id.clone(), matcher, dialog.target)
                        } else if matches!(dialog.kind, RuleInputKind::Domain | RuleInputKind::List)
                        {
                            Job::AddRules(dialog.set.clone(), matchers, dialog.target)
                        } else {
                            Job::AddRule(dialog.set.clone(), matchers.pop().unwrap(), dialog.target)
                        };
                        if let Some(dialog) = &mut self.rules.screen.add {
                            dialog.busy = true;
                            dialog.error = None;
                        }
                        return self.start_rule_edit(job);
                    }
                }
            }
            _ => unreachable!("only rule dialog actions are dispatched here"),
        }
        None
    }
}
