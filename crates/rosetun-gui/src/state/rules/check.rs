//! "Check an address or program" on the Rules tab: where the active rules
//! would send what the user types, worked out by `rosetun_core::check`
//! without a connection. List contents are read on a worker and kept, in
//! memory only, until the lists or the list rules change. What is typed is
//! never logged or saved.

use rosetun_config::{DomainMatch, ListId, RuleId, RuleMatcher};
use rosetun_core::{
    Answer, ExplainedRoute, Explanation, InputError, Reason, RuleSource, SessionLists, StoreError,
    Subject, Unknown, check, rule_value_text,
};
use rosetun_ipc::ConnectRequest;

use super::super::route_reason::{ListsRead, list_keys};
use super::super::{Job, Screen, State};
use crate::state::RulesTab;

/// The lists the rules use and what they held when they were read.
#[derive(Clone, PartialEq, Eq)]
struct ListsKey {
    rules: Vec<(ListId, Option<String>)>,
    content: Vec<(Option<String>, Option<u64>, Option<u64>)>,
}

#[derive(Default)]
pub(crate) struct AddressCheck {
    pub(crate) input: String,
    read_for: Option<ListsKey>,
    read: ListsRead,
    next_request: u64,
}

/// What the line under the field shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckLine {
    /// The answer, up to the rule's link when there is one.
    pub(crate) text: String,
    /// "Rule 13" and the rule it shows in the table.
    pub(crate) rule: Option<(String, RuleId)>,
    /// Why the answer is not certain, or what a short answer stands on.
    pub(crate) hint: Option<String>,
    /// An answer, as opposed to a notice (checking, not understood).
    pub(crate) answer: bool,
}

/// What stands behind a route.
struct Why {
    /// A list or template the rule is for.
    basis: Option<String>,
    /// The rule's number in the active set and the rule.
    rule: Option<(usize, RuleId)>,
    /// All of it, for what is no rule of the table.
    text: Option<String>,
}

impl State {
    /// The check answers for the active set, and the table shows the set
    /// the user picked.
    pub(crate) fn rule_check_available(&self) -> bool {
        self.config_ready
            && self.rules.screen.selected_set.is_some()
            && self.rules.screen.selected_set == self.config.active_rule_set
    }

    fn check_request(&self) -> Option<ConnectRequest> {
        ConnectRequest::for_routing_check(
            &self.config,
            self.session.temporary_rules.clone(),
            self.request_inputs().context(),
        )
        .ok()
    }

    fn check_lists_key(&self, request: &ConnectRequest) -> ListsKey {
        let rules = list_keys(request);
        let content = rules
            .iter()
            .map(|(id, _)| {
                self.config
                    .lists
                    .iter()
                    .find(|list| list.id == *id)
                    .map_or((None, None, None), |list| {
                        (list.sha256.clone(), list.updated_at, list.size)
                    })
            })
            .collect();
        ListsKey { rules, content }
    }

    fn checking(&self) -> bool {
        self.screen == Screen::Rules
            && self.lists.tab == RulesTab::Rules
            && self.rule_check_available()
            && Subject::parse(&self.rules.check.input).is_ok()
    }

    /// The lists of the rules the check goes through, read when the answer
    /// needs them and they are not read yet.
    pub(crate) fn take_check_lists(&mut self) -> Option<Job> {
        if !self.checking() {
            return None;
        }
        let request = self.check_request()?;
        let key = self.check_lists_key(&request);
        let cache = &mut self.rules.check;
        if key.rules.is_empty() || cache.read_for.as_ref() == Some(&key) {
            return None;
        }
        cache.next_request += 1;
        cache.read = ListsRead::Reading(cache.next_request);
        cache.read_for = Some(key);
        Some(Job::CheckLists {
            request: cache.next_request,
            session: Box::new(request),
        })
    }

    pub(in crate::state) fn reduce_check_lists(
        &mut self,
        request: u64,
        result: Result<SessionLists, StoreError>,
    ) {
        let cache = &mut self.rules.check;
        if matches!(cache.read, ListsRead::Reading(current) if current == request) {
            cache.read = result.map_or(ListsRead::Failed, ListsRead::Read);
        }
    }

    /// The line under the field; `None` while the field is empty or the
    /// rules on screen are not the ones in use.
    pub(crate) fn rule_check(&self) -> Option<CheckLine> {
        if !self.rule_check_available() {
            return None;
        }
        let subject = match Subject::parse(&self.rules.check.input) {
            Ok(subject) => subject,
            Err(InputError::Empty) => return None,
            Err(InputError::Unrecognised) => return Some(notice(tr!("rule-check-invalid"))),
        };
        let request = self.check_request()?;
        let key = self.check_lists_key(&request);
        let empty = SessionLists::default();
        let cache = &self.rules.check;
        let lists = match (&cache.read, &cache.read_for) {
            _ if key.rules.is_empty() => &empty,
            (ListsRead::Read(lists), Some(read)) if *read == key => lists,
            // An unread list leaves its rule unverifiable.
            (ListsRead::Failed, Some(read)) if *read == key => &empty,
            _ => return Some(notice(tr!("rule-check-checking"))),
        };
        Some(self.check_line(&subject, &check(&request, lists, &subject)))
    }

    fn check_line(&self, subject: &Subject, answer: &Answer) -> CheckLine {
        let input = subject_text(subject);
        match answer {
            Answer::Known(Explanation::Routed { reason, route }) => {
                self.routed_line(&input, reason, route)
            }
            Answer::Known(Explanation::Unverifiable { .. }) => CheckLine {
                text: tr!("rule-check-unknown", input = input),
                rule: None,
                hint: Some(tr!("connections-why-unknown-list")),
                answer: false,
            },
            Answer::Depends { on, otherwise } => {
                let otherwise = match otherwise {
                    Explanation::Routed { reason, route } => self.outcome_text(reason, route),
                    Explanation::Unverifiable { .. } => tr!("rule-check-list-unreadable"),
                };
                let (text, hint) = match on {
                    Unknown::Network => (
                        tr!("rule-check-depends-network", input = input),
                        tr!("rule-check-depends-network-hint", otherwise = otherwise),
                    ),
                    Unknown::ProgramPath => (
                        tr!("rule-check-depends-path", input = input),
                        tr!("rule-check-depends-path-hint", otherwise = otherwise),
                    ),
                    Unknown::SiteAddress => (
                        tr!("rule-check-depends-address", input = input),
                        tr!("rule-check-depends-address-hint", otherwise = otherwise),
                    ),
                };
                CheckLine {
                    text,
                    rule: None,
                    hint: Some(hint),
                    answer: false,
                }
            }
        }
    }

    fn routed_line(&self, input: &str, reason: &Reason, route: &ExplainedRoute) -> CheckLine {
        let head = tr!(
            "rule-check-head",
            input = input.to_owned(),
            route = self.route_word(route)
        );
        let why = self.why(reason);
        let (text, rule) = match why {
            Why {
                text: Some(text), ..
            } => (tr!("rule-check-plain", head = head, why = text), None),
            Why {
                basis,
                rule: Some((number, id)),
                ..
            } => {
                let label = tr!("rule-check-number", number = number.to_string());
                let text = match basis {
                    Some(basis) => tr!("rule-check-lead-basis", head = head, basis = basis),
                    None => tr!("rule-check-lead", head = head),
                };
                (text, Some((label, id)))
            }
            Why { .. } => (head, None),
        };
        CheckLine {
            text,
            rule,
            hint: None,
            answer: true,
        }
    }

    /// "Japan · list “Videos” · rule 13" without the input, for a hint.
    fn outcome_text(&self, reason: &Reason, route: &ExplainedRoute) -> String {
        let why = self.why(reason);
        let why = match why {
            Why {
                text: Some(text), ..
            } => text,
            Why {
                basis,
                rule: Some((number, _)),
                ..
            } => match basis {
                Some(basis) => tr!(
                    "rule-check-basis-number",
                    basis = basis,
                    number = number.to_string()
                ),
                None => tr!("rule-check-number", number = number.to_string()),
            },
            Why { .. } => tr!("rule-check-rule-unknown"),
        };
        tr!(
            "rule-check-outcome",
            route = self.route_word(route),
            why = why
        )
    }

    fn route_word(&self, route: &ExplainedRoute) -> String {
        match route {
            ExplainedRoute::Proxy => tr!("proxy"),
            ExplainedRoute::Direct => tr!("direct"),
            ExplainedRoute::Block => tr!("block"),
            ExplainedRoute::Exit(id) => self
                .config
                .exits
                .iter()
                .find(|exit| exit.id == *id)
                .map_or_else(
                    || tr!("target-exit-any"),
                    |exit| crate::display::safe_text(&exit.name),
                ),
        }
    }

    fn why(&self, reason: &Reason) -> Why {
        let text = |text| Why {
            basis: None,
            rule: None,
            text: Some(text),
        };
        match reason {
            Reason::Rule {
                temporary: true, ..
            } => text(tr!("rule-check-temporary")),
            Reason::Rule { id, source, .. } => {
                let number = self.config.active_rules().and_then(|set| {
                    set.rules
                        .iter()
                        .position(|rule| rule.id == *id)
                        .map(|index| index + 1)
                });
                let basis = match source {
                    RuleSource::Condition(_) => None,
                    RuleSource::Template { template, .. } => Some(tr!(
                        "rule-check-template",
                        template = crate::i18n::template_name(*template)
                    )),
                    RuleSource::List { list, category } => Some(tr!(
                        "rule-check-list",
                        list = self.list_rule_name(list, category.as_deref())
                    )),
                };
                match number {
                    Some(number) => Why {
                        basis,
                        rule: Some((number, id.clone())),
                        text: None,
                    },
                    None => text(tr!("rule-check-rule-unknown")),
                }
            }
            Reason::LocalNetwork => text(tr!("rule-check-lan")),
            Reason::PrivateNetwork => text(tr!("rule-check-private")),
            Reason::Default => text(tr!("rule-check-default")),
        }
    }

    /// Shows a rule the check named: the table clears its filters, selects
    /// the rule and scrolls to it.
    pub(in crate::state) fn show_checked_rule(&mut self, rule: RuleId) {
        let screen = &mut self.rules.screen;
        if self.screen != Screen::Rules
            || !self
                .config
                .active_rules()
                .is_some_and(|set| set.rules.iter().any(|item| item.id == rule))
        {
            return;
        }
        screen.filter = crate::rules::RuleFilter::default();
        screen.selected_rules.clear();
        screen.selected_rules.insert(rule.clone());
        screen.selection_anchor = Some(rule);
        screen.reveal_selection = true;
    }
}

fn notice(text: String) -> CheckLine {
    CheckLine {
        text,
        rule: None,
        hint: None,
        answer: false,
    }
}

/// What was understood, as the line repeats it: a site in its readable form.
fn subject_text(subject: &Subject) -> String {
    match subject {
        Subject::Site(domain) => crate::display::safe_text(&rule_value_text(&RuleMatcher::Domain(
            DomainMatch::Exact(domain.clone()),
        ))),
        Subject::Address(ip) => ip.to_string(),
        Subject::ProgramName(program) | Subject::ProgramPath(program) => {
            crate::display::safe_text(program)
        }
    }
}
