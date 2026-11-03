use std::path::{Path, PathBuf};

use rosetun_config::{DomainMatch, ListId, ProcessMatch, Rule, RuleId, RuleMatcher, RuleSetId};
use rosetun_core::RuleDestination;

use super::super::{Action, Job, State};
use super::address::{
    Address, AddressChip, AddressError, MAX_ADDRESSES, address_matchers, has_local_address,
    split_addresses,
};
use crate::errors;
use crate::rules::{ProcessGroup, ProcessMatchMode, ProgramKey, group_processes};
use crate::worker::WorkerEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub(crate) enum RuleInputKind {
    #[default]
    Process,
    /// Domains, addresses and subnets in one field.
    Address,
    List,
}

pub(crate) const MAX_LIST_RULES: usize = 256;
/// The most programs one dialog adds. A temporary rule is one of the service's
/// `MAX_TEMPORARY_RULES`, so more could never be applied at once.
pub(crate) const MAX_PROGRAMS: usize = rosetun_ipc::MAX_TEMPORARY_RULES;
/// The program list is read again when the program kind is shown after this long.
pub(crate) const PROCESS_LIST_STALE_MS: u64 = 30_000;

/// A program the dialog makes a rule for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChosenProgram {
    pub(crate) key: ProgramKey,
    /// The executable's file name: what an "Any folder" rule matches.
    pub(crate) name: String,
    /// Where the program is, when that is known.
    pub(crate) path: Option<PathBuf>,
    /// The rule is for the file at `path` whatever the folder setting says: the program was
    /// given as a file or typed as a path.
    pub(crate) fixed_path: bool,
}

impl ChosenProgram {
    pub(crate) fn listed(group: &ProcessGroup) -> Self {
        Self {
            key: group.key(),
            name: group.name.clone(),
            path: group.path.clone(),
            fixed_path: false,
        }
    }

    /// A file, by its full path.
    pub(crate) fn file(path: PathBuf) -> Self {
        Self {
            key: ProgramKey::of_path(&path),
            name: file_name(&path),
            path: Some(path),
            fixed_path: true,
        }
    }

    pub(crate) fn named(name: String) -> Self {
        Self {
            key: ProgramKey::of_name(&name),
            name,
            path: None,
            fixed_path: false,
        }
    }

    /// The rule's condition when the folder setting is `mode`.
    fn matcher(&self, mode: ProcessMatchMode) -> Option<RuleMatcher> {
        let text = match (&self.path, mode) {
            (Some(path), ProcessMatchMode::Path) => path.to_string_lossy().into_owned(),
            (Some(path), ProcessMatchMode::Name) if self.fixed_path => {
                path.to_string_lossy().into_owned()
            }
            _ => self.name.clone(),
        };
        rosetun_core::parse_process_input(&text)
            .ok()
            .map(RuleMatcher::Process)
    }
}

pub(crate) struct AddRuleDialog {
    pub(crate) set: RuleSetId,
    pub(crate) kind: RuleInputKind,
    pub(crate) target: RuleDestination,
    /// The "Specific server" search in the destination picker.
    pub(crate) node_search: String,
    /// A temporary rule's new exit was saved; submit again with it.
    pub(crate) resubmit: bool,
    pub(crate) addresses: Vec<AddressChip>,
    /// The text typed after the chips, not yet an item.
    pub(crate) address_input: String,
    /// An item was dropped for `MAX_ADDRESSES`.
    pub(crate) address_overflow: bool,
    /// The recent sites offered under the address field, as they stood when the tunnel's
    /// connections were read once after the tab was opened; they stay as they are while the
    /// dialog is open. `None` until that answer comes.
    pub(crate) recent: Option<Vec<String>>,
    pub(crate) list: Option<ListId>,
    pub(crate) selected_categories: Vec<String>,
    pub(crate) category_filter: String,
    pub(crate) subdomains: bool,
    pub(crate) temporary_only: bool,
    pub(crate) editing: Option<RuleId>,
    original_domain: Option<DomainMatch>,
    pub(crate) process_filter: String,
    pub(crate) processes: Vec<ProcessGroup>,
    /// The programs ticked in the list, in the order they were ticked.
    pub(crate) chosen: Vec<ChosenProgram>,
    /// "Any folder" or "Only this folder", one for every chosen program.
    pub(crate) match_mode: ProcessMatchMode,
    #[cfg(windows)]
    pub(crate) browsing: bool,
    pub(crate) load_request: Option<u64>,
    pub(crate) processes_loaded: bool,
    /// When the list was read, in `State::frame_time`.
    pub(crate) processes_loaded_ms: Option<u64>,
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
            target: RuleDestination::Proxy,
            node_search: String::new(),
            resubmit: false,
            addresses: Vec::new(),
            address_input: String::new(),
            address_overflow: false,
            recent: None,
            list: None,
            selected_categories: Vec::new(),
            category_filter: String::new(),
            subdomains: true,
            temporary_only: false,
            editing: None,
            original_domain: None,
            process_filter: String::new(),
            processes: Vec::new(),
            chosen: Vec::new(),
            match_mode: ProcessMatchMode::Name,
            #[cfg(windows)]
            browsing: false,
            load_request: None,
            processes_loaded: false,
            processes_loaded_ms: None,
            processes_error: None,
            busy: false,
            error: None,
            focus_input: true,
        }
    }

    pub(in crate::state) fn for_rule(set: RuleSetId, rule: &Rule) -> Option<Self> {
        let mut dialog = Self::new(set).with_matcher(&rule.matcher)?;
        dialog.editing = Some(rule.id.clone());
        dialog.target = RuleDestination::of(rule);
        if let RuleMatcher::Domain(domain) = &rule.matcher {
            dialog.original_domain = Some(domain.clone());
        }
        Some(dialog)
    }

    /// The condition filled from `matcher`, or `None` for a kind the dialog
    /// does not edit. The action stays the default.
    pub(in crate::state) fn with_matcher(mut self, matcher: &RuleMatcher) -> Option<Self> {
        let dialog = &mut self;
        match matcher {
            RuleMatcher::Domain(DomainMatch::Keyword(_)) => return None,
            RuleMatcher::Domain(domain) => {
                dialog.kind = RuleInputKind::Address;
                dialog.subdomains = matches!(domain, DomainMatch::Suffix(_));
                dialog.addresses = vec![AddressChip::new(
                    rosetun_core::rule_value_text(matcher).trim_start_matches("*."),
                )];
            }
            RuleMatcher::List { list, category } => {
                dialog.kind = RuleInputKind::List;
                dialog.list = Some(list.clone());
                dialog.selected_categories = category.iter().cloned().collect();
            }
            RuleMatcher::IpCidr(cidr) => {
                dialog.kind = RuleInputKind::Address;
                dialog.addresses = vec![AddressChip::new(cidr)];
            }
            RuleMatcher::Process(process) => {
                dialog.chosen = vec![match process {
                    ProcessMatch::Name(name) => ChosenProgram::named(name.clone()),
                    ProcessMatch::Path(path) => {
                        dialog.match_mode = ProcessMatchMode::Path;
                        ChosenProgram {
                            fixed_path: false,
                            ..ChosenProgram::file(path.clone())
                        }
                    }
                }];
            }
            _ => return None,
        }
        Some(self)
    }

    /// Adds the items of `text` as chips: each once, the one item of an edit, no more than
    /// `MAX_ADDRESSES`.
    pub(crate) fn add_addresses(&mut self, text: &str) {
        for item in split_addresses(text) {
            if self.editing.is_some() && !self.addresses.is_empty() {
                break;
            }
            let chip = AddressChip::new(item);
            if self
                .addresses
                .iter()
                .any(|old| old.repeats(&chip, self.subdomains))
            {
                continue;
            }
            if self.addresses.len() >= MAX_ADDRESSES {
                self.address_overflow = true;
                break;
            }
            self.addresses.push(chip);
        }
        self.error = None;
    }

    /// Adds the site as a chip, or removes its chip when it is there already: a click on a
    /// recent site.
    pub(crate) fn toggle_address(&mut self, text: &str) {
        let chip = AddressChip::new(text);
        match self
            .addresses
            .iter()
            .position(|old| old.repeats(&chip, self.subdomains))
        {
            Some(index) => self.remove_address(index),
            None => self.add_addresses(text),
        }
    }

    /// Whether the field holds a chip for the site.
    pub(crate) fn has_address(&self, text: &str) -> bool {
        let chip = AddressChip::new(text);
        self.addresses
            .iter()
            .any(|old| old.repeats(&chip, self.subdomains))
    }

    /// Turns the text still being typed into chips.
    pub(crate) fn commit_address_input(&mut self) {
        let text = std::mem::take(&mut self.address_input);
        self.add_addresses(&text);
    }

    pub(crate) fn remove_address(&mut self, index: usize) {
        if index < self.addresses.len() {
            self.addresses.remove(index);
            self.address_overflow = false;
            self.error = None;
        }
    }

    pub(crate) fn remove_last_address(&mut self) {
        if self.addresses.pop().is_some() {
            self.address_overflow = false;
            self.error = None;
        }
    }

    /// The chips and the items still being typed after them.
    fn all_addresses(&self) -> impl Iterator<Item = AddressChip> + '_ {
        self.addresses
            .iter()
            .cloned()
            .chain(split_addresses(&self.address_input).map(AddressChip::new))
    }

    /// Each item of the address field, parsed.
    pub(crate) fn parsed_addresses(&self) -> Vec<Result<Address, AddressError>> {
        self.all_addresses().map(|chip| chip.parsed).collect()
    }

    /// The items that are neither a domain nor an address, with why.
    pub(crate) fn address_errors(&self) -> Vec<(String, AddressError)> {
        self.all_addresses()
            .filter_map(|chip| chip.parsed.err().map(|error| (chip.text, error)))
            .collect()
    }

    /// How many rules the good items make.
    pub(crate) fn address_rule_count(&self) -> usize {
        let parsed: Vec<_> = self
            .parsed_addresses()
            .into_iter()
            .filter_map(Result::ok)
            .collect();
        address_matchers(&parsed, self.subdomains).len()
    }

    /// More items than one dialog adds.
    pub(crate) fn too_many_addresses(&self) -> bool {
        self.address_overflow || self.all_addresses().count() > MAX_ADDRESSES
    }

    /// Whether the address field has a domain, so "and subdomains" applies.
    pub(crate) fn has_domain(&self) -> bool {
        self.parsed_addresses()
            .iter()
            .any(|item| item.as_ref().is_ok_and(Address::is_domain))
    }

    /// The rules the address field makes, or `None` while it is empty, has a bad item or
    /// too many, or holds more than the one rule being edited.
    pub(crate) fn address_rules(&self) -> Option<Vec<RuleMatcher>> {
        if let Some(original) = self.unchanged_domain() {
            return Some(vec![RuleMatcher::Domain(original)]);
        }
        if self.too_many_addresses() {
            return None;
        }
        let parsed: Option<Vec<Address>> = self
            .parsed_addresses()
            .into_iter()
            .map(Result::ok)
            .collect();
        let parsed = parsed
            .filter(|parsed| !parsed.is_empty() && (self.editing.is_none() || parsed.len() == 1))?;
        Some(address_matchers(&parsed, self.subdomains))
    }

    pub(crate) fn unchanged_domain(&self) -> Option<DomainMatch> {
        let original = self.original_domain.as_ref()?;
        let matcher = RuleMatcher::Domain(original.clone());
        let value = rosetun_core::rule_value_text(&matcher);
        let value = value.strip_prefix("*.").unwrap_or(&value);
        let items: Vec<_> = self.all_addresses().collect();
        (items.len() == 1
            && items[0].text == value
            && self.subdomains == matches!(original, DomainMatch::Suffix(_)))
        .then(|| original.clone())
    }

    /// Replaces each subnet with host bits by the subnet it starts.
    pub(crate) fn correct_ip_host_bits(&mut self) {
        self.commit_address_input();
        for chip in &mut self.addresses {
            if let Err(AddressError::Ip(rosetun_core::IpCidrError::HostBits { corrected })) =
                &chip.parsed
            {
                *chip = AddressChip::new(&corrected.clone());
            }
        }
        self.error = None;
    }

    pub(crate) fn local_ip_warning(&self) -> bool {
        has_local_address(&self.parsed_addresses())
    }

    /// Replaces the address field with `text`, not yet turned into chips.
    #[cfg(test)]
    pub(crate) fn set_addresses(&mut self, text: &str) {
        self.addresses.clear();
        self.address_overflow = false;
        self.address_input = text.to_owned();
    }

    /// Ticks the program `text` names, as typed in the search.
    #[cfg(test)]
    pub(crate) fn tick_program(&mut self, text: &str) {
        let program = match rosetun_core::parse_process_input(text).unwrap() {
            ProcessMatch::Name(name) => ChosenProgram::named(name),
            ProcessMatch::Path(path) => ChosenProgram::file(path),
        };
        self.toggle_program(program);
    }

    /// The items of the address field, one per line.
    #[cfg(test)]
    pub(crate) fn address_text(&self) -> String {
        self.all_addresses()
            .map(|chip| chip.text)
            .collect::<Vec<_>>()
            .join("\n")
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

    /// Ticks the program, or unticks it. An edit keeps one: ticking another replaces it.
    pub(crate) fn toggle_program(&mut self, program: ChosenProgram) {
        if let Some(index) = self.chosen.iter().position(|item| item.key == program.key) {
            self.chosen.remove(index);
        } else {
            if self.editing.is_some() {
                self.chosen.clear();
            }
            self.chosen.push(program);
        }
        self.error = None;
    }

    /// Ticks the listed program, or unticks it. "Only this folder" cannot take a program
    /// whose path is not known.
    pub(crate) fn toggle_listed(&mut self, index: usize) {
        if let Some(group) = self.processes.get(index)
            && (group.path.is_some() || self.match_mode == ProcessMatchMode::Name)
        {
            let program = ChosenProgram::listed(group);
            self.toggle_program(program);
        }
    }

    /// Ticks the program the search text names: a program name, or the path of a file.
    pub(crate) fn toggle_typed(&mut self) {
        let program = match rosetun_core::parse_process_input(self.process_filter.trim()) {
            Ok(ProcessMatch::Name(name)) => ChosenProgram::named(name),
            Ok(ProcessMatch::Path(path)) => ChosenProgram::file(path),
            Err(_) => return,
        };
        self.toggle_program(program);
    }

    /// Ticks a file chosen in the file dialog.
    #[cfg(windows)]
    pub(crate) fn add_file(&mut self, path: PathBuf) {
        let program = ChosenProgram::file(path);
        if !self.chosen.iter().any(|item| item.key == program.key) {
            self.toggle_program(program);
        }
        self.focus_input = true;
    }

    pub(crate) fn is_chosen(&self, key: &ProgramKey) -> bool {
        self.chosen.iter().any(|item| &item.key == key)
    }

    /// Unticks every program.
    pub(crate) fn clear_chosen(&mut self) {
        self.chosen.clear();
        self.error = None;
    }

    /// Whether "Only this folder" can apply: the path of every program is known.
    pub(crate) fn full_path_available(&self) -> bool {
        self.chosen.iter().all(|item| item.path.is_some())
    }

    /// Whether the folder setting changes anything: some program is not a file by its path.
    pub(crate) fn folder_setting_applies(&self) -> bool {
        self.chosen.iter().any(|item| !item.fixed_path)
    }

    /// The rules the chosen programs make, each once, or `None` while none is chosen, one is
    /// not a valid program, or there are more than one dialog adds.
    pub(crate) fn process_rules(&self) -> Option<Vec<RuleMatcher>> {
        if self.chosen.is_empty() || self.too_many_programs() {
            return None;
        }
        let mut matchers: Vec<RuleMatcher> = Vec::new();
        for program in &self.chosen {
            let matcher = program.matcher(self.match_mode)?;
            if !matchers.iter().any(|old| same_program(old, &matcher)) {
                matchers.push(matcher);
            }
        }
        (self.editing.is_none() || matchers.len() == 1).then_some(matchers)
    }

    /// How many rules the chosen programs make.
    pub(crate) fn process_rule_count(&self) -> usize {
        self.process_rules()
            .map_or(self.chosen.len(), |rules| rules.len())
    }

    /// More programs than one dialog adds.
    pub(crate) fn too_many_programs(&self) -> bool {
        self.chosen.len() > MAX_PROGRAMS
    }

    /// Points the programs given by name at the listed ones, so their icon shows and their
    /// path can be chosen. The name stays as it was given.
    fn resolve_chosen(&mut self) {
        for program in &mut self.chosen {
            let listed = match &program.key {
                ProgramKey::Name(_) => self
                    .processes
                    .iter()
                    .find(|group| group.name.eq_ignore_ascii_case(&program.name)),
                key => self.processes.iter().find(|group| &group.key() == key),
            };
            if let Some(group) = listed {
                program.key = group.key();
                program.path = group.path.clone();
            }
        }
        let mut seen = Vec::new();
        self.chosen.retain(|program| {
            let new = !seen.contains(&program.key);
            seen.push(program.key.clone());
            new
        });
    }

    pub(crate) fn set_process_match_mode(&mut self, mode: ProcessMatchMode) {
        if mode == ProcessMatchMode::Path && !self.full_path_available() {
            return;
        }
        self.match_mode = mode;
        self.error = None;
    }
}

/// Whether two program conditions are one rule: the same name or the same path, whatever
/// the letter case.
fn same_program(a: &RuleMatcher, b: &RuleMatcher) -> bool {
    match (a, b) {
        (
            RuleMatcher::Process(ProcessMatch::Name(a)),
            RuleMatcher::Process(ProcessMatch::Name(b)),
        ) => a.eq_ignore_ascii_case(b),
        (
            RuleMatcher::Process(ProcessMatch::Path(a)),
            RuleMatcher::Process(ProcessMatch::Path(b)),
        ) => ProgramKey::of_path(a) == ProgramKey::of_path(b),
        _ => false,
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map_or_else(|| path.to_string_lossy(), |name| name.to_string_lossy())
        .into_owned()
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
        let now = self.frame_time();
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
                            dialog.processes_loaded_ms = Some(now);
                            dialog.processes_error = None;
                            dialog.resolve_chosen();
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
                        dialog.add_file(path);
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
            Action::OpenAddRuleFor(matcher) => {
                let leave = self.act_rules(Action::OpenActiveRules);
                if self.can_edit_rules()
                    && self.rules.screen.add.is_none()
                    && let Some(set) = self.selected_rules()
                    && let Some(dialog) = AddRuleDialog::new(set.id.clone()).with_matcher(&matcher)
                {
                    self.rules.screen.add = Some(dialog);
                    return self.load_processes().or(leave);
                }
                return leave;
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
                let now = self.frame_time();
                if let Some(dialog) = &mut self.rules.screen.add
                    && !dialog.busy
                    && dialog.kind != kind
                    && dialog.editing.is_none()
                {
                    dialog.kind = kind;
                    dialog.error = None;
                    dialog.focus_input = true;
                    let stale = dialog
                        .processes_loaded_ms
                        .is_none_or(|loaded| now.saturating_sub(loaded) >= PROCESS_LIST_STALE_MS);
                    if kind == RuleInputKind::Process && (!dialog.processes_loaded || stale) {
                        return self.load_processes();
                    }
                }
            }
            Action::CorrectRuleIps => {
                if let Some(dialog) = &mut self.rules.screen.add
                    && dialog.kind == RuleInputKind::Address
                    && !dialog.busy
                {
                    dialog.correct_ip_host_bits();
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
                if let Some(dialog) = &mut self.rules.screen.add
                    && dialog.kind == RuleInputKind::Address
                    && !dialog.busy
                {
                    dialog.commit_address_input();
                }
                if self.can_edit_rules()
                    && let Some(dialog) = &self.rules.screen.add
                    && !dialog.busy
                    && self.rules.screen.selected_set.as_ref() == Some(&dialog.set)
                {
                    let matchers: Option<Vec<_>> = match dialog.kind {
                        RuleInputKind::Address => dialog.address_rules(),
                        RuleInputKind::Process => dialog.process_rules(),
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
                            if let RuleDestination::NewExit(exit) = &dialog.target {
                                let job = Job::CreateExit(exit.clone());
                                if let Some(dialog) = &mut self.rules.screen.add {
                                    dialog.busy = true;
                                    dialog.error = None;
                                }
                                return self.start_rule_edit(job);
                            }
                            let target = dialog.target.clone();
                            return self.act(Action::AddTemporary(matchers, target));
                        }
                        let job = if let Some(id) = &dialog.editing {
                            let current = self
                                .selected_rules()
                                .and_then(|set| set.rules.iter().find(|rule| &rule.id == id))?;
                            let matcher = matchers.pop().unwrap();
                            if current.matcher == matcher
                                && RuleDestination::of(current) == dialog.target
                            {
                                self.rules.screen.add = None;
                                return None;
                            }
                            Job::UpdateRule(
                                dialog.set.clone(),
                                id.clone(),
                                matcher,
                                dialog.target.clone(),
                            )
                        } else if dialog.kind != RuleInputKind::Process || matchers.len() > 1 {
                            Job::AddRules(dialog.set.clone(), matchers, dialog.target.clone())
                        } else {
                            Job::AddRule(
                                dialog.set.clone(),
                                matchers.pop().unwrap(),
                                dialog.target.clone(),
                            )
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
