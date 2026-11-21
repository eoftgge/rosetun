use std::collections::{BTreeMap, BTreeSet};

use rosetun_config::{
    DomainMatch, MAX_GROUP_ITEMS, ProcessMatch, RULE_GROUP_NAME_LIMIT, Rule, RuleId, RuleMatcher,
    RuleSetId, RuleTemplate,
};
use rosetun_core::RuleDestination;

use super::super::{Action, Job, State};
use crate::errors;
use crate::rules::{ProgramKey, RuleFilter, same_program_name};

#[derive(Default)]
pub(crate) struct TemplatesCatalogDialog {
    /// Per-preset destination overrides; defaults to `template.default_target()`.
    pub(crate) targets: BTreeMap<RuleTemplate, RuleDestination>,
    /// Presets whose item preview list is expanded inside the catalog modal.
    pub(crate) expanded: BTreeSet<RuleTemplate>,
}

impl TemplatesCatalogDialog {
    pub(crate) fn target(&self, template: RuleTemplate) -> RuleDestination {
        self.targets
            .get(&template)
            .cloned()
            .unwrap_or_else(|| template.default_target().into())
    }

    pub(crate) fn set_target(&mut self, template: RuleTemplate, target: RuleDestination) {
        self.targets.insert(template, target);
    }

    pub(crate) fn toggle_expanded(&mut self, template: RuleTemplate) {
        if !self.expanded.insert(template) {
            self.expanded.remove(&template);
        }
    }
}

pub(crate) struct GroupSelectionDialog {
    pub(crate) set: RuleSetId,
    pub(crate) rules: Vec<RuleId>,
    pub(crate) name: String,
    pub(crate) target: RuleDestination,
    pub(crate) mixed_targets: bool,
    pub(crate) error: Option<String>,
    pub(crate) focus: bool,
}

pub(crate) struct GroupEditorDialog {
    pub(crate) set: RuleSetId,
    pub(crate) editing: Option<RuleId>,
    pub(crate) name: String,
    pub(crate) items: Vec<RuleMatcher>,
    pub(crate) target: RuleDestination,
    pub(crate) input: String,
    pub(crate) input_error: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) focus: bool,
}

impl GroupEditorDialog {
    pub(crate) fn new(set: RuleSetId) -> Self {
        Self {
            set,
            editing: None,
            name: String::new(),
            items: Vec::new(),
            target: RuleDestination::Proxy,
            input: String::new(),
            input_error: None,
            error: None,
            focus: true,
        }
    }

    pub(crate) fn for_rule(set: RuleSetId, rule: &Rule) -> Option<Self> {
        let RuleMatcher::Group { name, items } = &rule.matcher else {
            return None;
        };
        Some(Self {
            set,
            editing: Some(rule.id.clone()),
            name: name.clone(),
            items: items.clone(),
            target: RuleDestination::of(rule),
            input: String::new(),
            input_error: None,
            error: None,
            focus: true,
        })
    }

    /// Parses the quick-add input line and appends it to `items`, setting `input_error` on failure.
    pub(crate) fn commit_input(&mut self) {
        let raw = self.input.trim();
        if raw.is_empty() {
            return;
        }
        let Ok(matcher) = parse_quick_item(raw) else {
            self.input_error = Some(tr!("group-item-invalid"));
            return;
        };
        if self
            .items
            .iter()
            .any(|item| same_group_item(item, &matcher))
        {
            self.input_error = Some(tr!("group-item-duplicate"));
            return;
        }
        if self.items.len() >= MAX_GROUP_ITEMS {
            self.input_error = Some(tr!("error-invalid-group"));
            return;
        }
        self.items.push(matcher);
        self.input.clear();
        self.input_error = None;
        self.error = None;
    }

    pub(crate) fn remove_item(&mut self, index: usize) {
        if index < self.items.len() {
            self.items.remove(index);
            self.error = None;
        }
    }
}

/// Parses a single condition typed in the group editor: IP/CIDR, executable path or `.exe`,
/// domain (with subdomains), or bare process name.
pub(crate) fn parse_quick_item(raw: &str) -> Result<RuleMatcher, ()> {
    let input = raw.trim();
    if input.is_empty() {
        return Err(());
    }
    if let Ok(cidr) = rosetun_core::parse_ip_cidr(input) {
        return Ok(RuleMatcher::IpCidr(cidr));
    }
    let is_url = input.starts_with("http://") || input.starts_with("https://");
    let looks_like_path = !is_url && input.contains(['\\', '/']);
    let looks_like_exe = input.len() > 4
        && input.is_char_boundary(input.len() - 4)
        && input[input.len() - 4..].eq_ignore_ascii_case(".exe");
    if looks_like_path || looks_like_exe {
        return rosetun_core::parse_process_input(input)
            .map(RuleMatcher::Process)
            .map_err(|_| ());
    }
    if let Ok(domain) = rosetun_core::parse_domain_input(input) {
        return Ok(RuleMatcher::Domain(rosetun_core::with_subdomains(
            domain, true,
        )));
    }
    rosetun_core::parse_process_input(input)
        .map(RuleMatcher::Process)
        .map_err(|_| ())
}

fn same_group_item(a: &RuleMatcher, b: &RuleMatcher) -> bool {
    match (a, b) {
        (
            RuleMatcher::Domain(DomainMatch::Exact(a)),
            RuleMatcher::Domain(DomainMatch::Exact(b)),
        )
        | (
            RuleMatcher::Domain(DomainMatch::Suffix(a)),
            RuleMatcher::Domain(DomainMatch::Suffix(b)),
        )
        | (
            RuleMatcher::Domain(DomainMatch::Keyword(a)),
            RuleMatcher::Domain(DomainMatch::Keyword(b)),
        ) => a.eq_ignore_ascii_case(b),
        (
            RuleMatcher::Process(ProcessMatch::Name(a)),
            RuleMatcher::Process(ProcessMatch::Name(b)),
        ) => same_program_name(a, b),
        (
            RuleMatcher::Process(ProcessMatch::Path(a)),
            RuleMatcher::Process(ProcessMatch::Path(b)),
        ) => ProgramKey::of_path(a) == ProgramKey::of_path(b),
        _ => a == b,
    }
}

impl State {
    pub(super) fn act_rule_groups(&mut self, action: Action) -> Option<Job> {
        match action {
            Action::OpenTemplatesCatalog => {
                if self.config_ready && self.selected_rules().is_some() {
                    self.rules
                        .screen
                        .templates_catalog
                        .get_or_insert_with(TemplatesCatalogDialog::default);
                }
            }
            Action::CloseTemplatesCatalog => {
                self.rules.screen.templates_catalog = None;
            }
            Action::AddPresetGroup(template, destination) => {
                if self.can_edit_rules()
                    && let Some(set) = self.selected_rules()
                {
                    let name = crate::i18n::template_name(template);
                    let matcher = template.to_group(name);
                    return self.start_rule_edit(Job::AddRule(
                        set.id.clone(),
                        matcher,
                        destination,
                    ));
                }
            }
            Action::ToggleGroupExpanded(id) => {
                let expanded = &mut self.rules.screen.expanded_groups;
                if !expanded.insert(id.clone()) {
                    expanded.remove(&id);
                }
            }
            Action::OpenGroupSelection => {
                if self.can_edit_rules()
                    && self.rules.screen.group_selection.is_none()
                    && let Some(set) = self.selected_rules()
                {
                    let ids = self.selected_rule_ids();
                    if ids.len() >= 2 {
                        let first_target = set
                            .rules
                            .iter()
                            .find(|rule| rule.id == ids[0])
                            .map_or(RuleDestination::Proxy, RuleDestination::of);
                        let mixed_targets = ids.iter().any(|id| {
                            set.rules
                                .iter()
                                .find(|rule| &rule.id == id)
                                .is_some_and(|rule| RuleDestination::of(rule) != first_target)
                        });
                        self.rules.screen.group_selection = Some(GroupSelectionDialog {
                            set: set.id.clone(),
                            rules: ids,
                            name: String::new(),
                            target: first_target,
                            mixed_targets,
                            error: None,
                            focus: true,
                        });
                    }
                }
            }
            Action::CancelGroupSelection => {
                if !self.operations.rules_edit {
                    self.rules.screen.group_selection = None;
                }
            }
            Action::SubmitGroupSelection => {
                if self.can_edit_rules()
                    && let Some(dialog) = &mut self.rules.screen.group_selection
                {
                    let name = dialog.name.trim().to_owned();
                    if name.is_empty() || name.chars().count() > RULE_GROUP_NAME_LIMIT {
                        dialog.error = Some(tr!("group-name-empty-error"));
                        return None;
                    }
                    let job = Job::GroupRules(
                        dialog.set.clone(),
                        dialog.rules.clone(),
                        name,
                        dialog.target.clone(),
                    );
                    dialog.error = None;
                    return self.start_rule_edit(job);
                }
            }
            Action::UngroupRule(rule) => {
                if self.can_edit_rules()
                    && let Some(set_id) = self.selected_rules().and_then(|set| {
                        set.rules
                            .iter()
                            .any(|item| {
                                item.id == rule && matches!(item.matcher, RuleMatcher::Group { .. })
                            })
                            .then(|| set.id.clone())
                    })
                {
                    self.rules.screen.expanded_groups.remove(&rule);
                    return self.start_rule_edit(Job::UngroupRule(set_id, rule));
                }
            }
            Action::RemoveGroupItem(rule, index) => {
                if self.can_edit_rules()
                    && let Some(set_id) = self.selected_rules().and_then(|set| {
                        set.rules
                            .iter()
                            .any(|item| {
                                item.id == rule
                                    && matches!(
                                        &item.matcher,
                                        RuleMatcher::Group { items, .. }
                                            if items.len() > 1 && index < items.len()
                                    )
                            })
                            .then(|| set.id.clone())
                    })
                {
                    return self.start_rule_edit(Job::RemoveGroupItem(set_id, rule, index));
                }
            }
            Action::OpenNewGroup => {
                if self.can_edit_rules()
                    && self.rules.screen.group_editor.is_none()
                    && let Some(set_id) = self.selected_rules().map(|set| set.id.clone())
                {
                    self.rules.screen.templates_catalog = None;
                    self.rules.screen.group_editor = Some(GroupEditorDialog::new(set_id));
                }
            }
            Action::CancelGroupEditor => {
                if !self.operations.rules_edit {
                    self.rules.screen.group_editor = None;
                }
            }
            Action::SubmitGroupEditor => {
                if self.can_edit_rules()
                    && let Some(dialog) = &mut self.rules.screen.group_editor
                {
                    if !dialog.input.trim().is_empty() {
                        dialog.commit_input();
                        if dialog.input_error.is_some() {
                            return None;
                        }
                    }
                    let name = dialog.name.trim().to_owned();
                    if name.is_empty() || name.chars().count() > RULE_GROUP_NAME_LIMIT {
                        dialog.error = Some(tr!("group-name-empty-error"));
                        return None;
                    }
                    if dialog.items.is_empty() {
                        dialog.error = Some(tr!("group-empty-error"));
                        return None;
                    }
                    let matcher = RuleMatcher::Group {
                        name,
                        items: dialog.items.clone(),
                    };
                    let target = dialog.target.clone();
                    let set_id = dialog.set.clone();
                    let editing = dialog.editing.clone();
                    dialog.error = None;
                    let job = if let Some(id) = editing {
                        let unchanged = self
                            .selected_rules()
                            .and_then(|set| set.rules.iter().find(|rule| rule.id == id))
                            .is_some_and(|current| {
                                current.matcher == matcher && RuleDestination::of(current) == target
                            });
                        if unchanged {
                            self.rules.screen.group_editor = None;
                            return None;
                        }
                        Job::UpdateRule(set_id, id, matcher, target)
                    } else {
                        Job::AddRule(set_id, matcher, target)
                    };
                    return self.start_rule_edit(job);
                }
            }
            _ => unreachable!("only group rule actions are dispatched here"),
        }
        None
    }

    pub(super) fn finish_group_selection(
        &mut self,
        result: Result<Rule, rosetun_core::RuleSetError>,
    ) {
        self.operations.rules_edit = false;
        match result {
            Ok(group) => {
                self.rules.screen.group_selection = None;
                self.rules.screen.clear_selection();
                self.rules.screen.selected_rules.insert(group.id.clone());
                self.rules.screen.selection_anchor = Some(group.id);
            }
            Err(error) => {
                let message = self.text(&errors::rule_set(crate::i18n::language(), &error));
                if let Some(dialog) = &mut self.rules.screen.group_selection {
                    dialog.error = Some(message);
                } else {
                    self.operation_error = Some(message);
                }
            }
        }
    }

    pub(super) fn finish_group_editor(&mut self, result: Result<(), rosetun_core::RuleSetError>) {
        self.operations.rules_edit = false;
        match result {
            Ok(()) => {
                self.rules.screen.group_editor = None;
                self.rules.screen.filter = RuleFilter::default();
                self.rules.screen.clear_selection();
            }
            Err(error) => {
                let message = self.text(&errors::rule_set(crate::i18n::language(), &error));
                if let Some(dialog) = &mut self.rules.screen.group_editor {
                    dialog.error = Some(message);
                } else {
                    self.operation_error = Some(message);
                }
            }
        }
    }
}
