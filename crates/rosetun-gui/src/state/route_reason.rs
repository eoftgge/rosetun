//! The "Why" row of a connection's details: the rule of the running session
//! that routes it, worked out by `rosetun_core::explain` from the request the
//! last connect or apply sent. List contents are read on a worker and kept,
//! in memory only, until the next connect, apply or disconnect.

use std::net::IpAddr;

use rosetun_config::{DomainMatch, ListId, LiveConnection, ProcessMatch, RuleId, RuleMatcher};
use rosetun_core::{
    ExplainedRoute, Explanation, Reason, RuleSource, SessionLists, StoreError, explain_connection,
};
use rosetun_ipc::ConnectRequest;

use super::{Job, SessionPart, State};

/// What the row shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouteReason {
    pub(crate) text: String,
    /// Why the route could not be told.
    pub(crate) hint: Option<String>,
    /// The set's rule to open in the editor.
    pub(crate) edit: Option<RuleId>,
    /// The engine saw no site name, so site rules could not match.
    pub(crate) nameless: bool,
    /// The rules on screen differ from the running session's.
    pub(crate) changed: bool,
}

#[derive(Default)]
pub(crate) struct SessionListsCache {
    /// The list rules the contents were read for.
    keys: Vec<(ListId, Option<String>)>,
    pub(super) read: ListsRead,
    next_request: u64,
}

#[derive(Default)]
pub(super) enum ListsRead {
    #[default]
    Unread,
    Reading(u64),
    Read(SessionLists),
    Failed,
}

impl SessionListsCache {
    /// The engine got new rules, or the session ended.
    pub(super) fn forget(&mut self) {
        self.keys = Vec::new();
        self.read = ListsRead::Unread;
    }
}

/// The session's enabled list rules, each list and category once.
fn list_keys(request: &ConnectRequest) -> Vec<(ListId, Option<String>)> {
    let mut keys = Vec::new();
    for rule in request.effective_rule_set().enabled() {
        if let RuleMatcher::List { list, category } = &rule.matcher {
            let key = (list.clone(), category.clone());
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
    }
    keys
}

impl State {
    /// The session's lists, once a connection's details are open.
    pub(crate) fn take_session_lists(&mut self) -> Option<Job> {
        if !self.connections_available() || self.traffic.connections.selected.is_none() {
            return None;
        }
        let request = self.session.session_request.as_ref()?;
        let keys = list_keys(request);
        let cache = &mut self.traffic.lists;
        if keys.is_empty() || (cache.keys == keys && !matches!(cache.read, ListsRead::Unread)) {
            return None;
        }
        cache.keys = keys;
        cache.next_request += 1;
        cache.read = ListsRead::Reading(cache.next_request);
        Some(Job::SessionLists {
            request: cache.next_request,
            session: Box::new(request.clone()),
        })
    }

    pub(super) fn reduce_session_lists(
        &mut self,
        request: u64,
        result: Result<SessionLists, StoreError>,
    ) {
        let cache = &mut self.traffic.lists;
        if matches!(cache.read, ListsRead::Reading(current) if current == request) {
            cache.read = result.map_or(ListsRead::Failed, ListsRead::Read);
        }
    }

    pub(crate) fn route_reason(&self, connection: &LiveConnection) -> RouteReason {
        let mut reason = RouteReason {
            text: tr!("connections-why-unknown"),
            hint: None,
            edit: None,
            nameless: connection.host.parse::<IpAddr>().is_ok(),
            changed: self.session.lists_changed_since_apply
                || self.pending_reconnect(SessionPart::Rules),
        };
        let Some(request) = self.session.session_request.as_ref() else {
            reason.hint = Some(tr!("connections-why-unknown-session"));
            return reason;
        };
        let empty = SessionLists::default();
        let keys = list_keys(request);
        let cache = &self.traffic.lists;
        let lists = match &cache.read {
            _ if keys.is_empty() => &empty,
            ListsRead::Read(lists) if cache.keys == keys => lists,
            // An unread list leaves its rule unverifiable.
            ListsRead::Failed if cache.keys == keys => &empty,
            _ => {
                reason.text = tr!("connections-why-checking");
                return reason;
            }
        };
        match explain_connection(request, lists, connection) {
            None => reason.hint = Some(tr!("connections-why-unknown-mismatch")),
            Some(Explanation::Unverifiable { .. }) => {
                reason.hint = Some(tr!("connections-why-unknown-list"));
            }
            Some(Explanation::Routed {
                reason:
                    Reason::Rule {
                        temporary: true,
                        source,
                        ..
                    },
                ..
            }) => {
                let condition = match &source {
                    RuleSource::Condition(matcher) | RuleSource::Template { matcher, .. } => {
                        self.rule_condition(matcher)
                    }
                    RuleSource::List { list, category } => tr!(
                        "connections-why-list-condition",
                        list = self.list_rule_name(list, category.as_deref())
                    ),
                };
                reason.text = tr!("connections-why-temporary", condition = condition);
            }
            Some(Explanation::Routed {
                reason: Reason::Rule { id, source, .. },
                ..
            }) => {
                let position = self.config.active_rules().and_then(|set| {
                    set.rules
                        .iter()
                        .position(|rule| rule.id == id)
                        .map(|index| (index + 1, &set.rules[index]))
                });
                reason.text = match (&source, position) {
                    (RuleSource::Template { template, matcher }, _) => tr!(
                        "connections-why-template",
                        template = crate::i18n::template_name(*template),
                        condition = self.rule_condition(matcher)
                    ),
                    (RuleSource::Condition(matcher), Some((number, _))) => tr!(
                        "connections-why-rule",
                        number = number.to_string(),
                        condition = self.rule_condition(matcher)
                    ),
                    (RuleSource::Condition(matcher), None) => tr!(
                        "connections-why-session-rule",
                        condition = self.rule_condition(matcher)
                    ),
                    (RuleSource::List { list, category }, Some((number, _))) => tr!(
                        "connections-why-list",
                        list = self.list_rule_name(list, category.as_deref()),
                        number = number.to_string()
                    ),
                    (RuleSource::List { list, category }, None) => tr!(
                        "connections-why-session-list",
                        list = self.list_rule_name(list, category.as_deref())
                    ),
                };
                reason.edit = position
                    .filter(|(_, rule)| crate::rules::editable(&rule.matcher))
                    .filter(|_| !matches!(source, RuleSource::Template { .. }))
                    .map(|(_, rule)| rule.id.clone());
            }
            Some(Explanation::Routed {
                reason: Reason::LocalNetwork,
                ..
            }) => reason.text = tr!("connections-why-lan"),
            Some(Explanation::Routed {
                reason: Reason::Default,
                route,
            }) => match route {
                ExplainedRoute::Proxy => reason.text = tr!("connections-why-default-proxy"),
                ExplainedRoute::Direct => reason.text = tr!("connections-why-default-direct"),
                // Neither reaches the engine's list, so the engine contradicts it.
                ExplainedRoute::Block | ExplainedRoute::Exit(_) => {
                    reason.hint = Some(tr!("connections-why-unknown-mismatch"));
                }
            },
        }
        reason
    }

    /// "youtube.com and subdomains", "Example.exe", "192.0.2.0/24".
    fn rule_condition(&self, matcher: &RuleMatcher) -> String {
        let (value, _) = crate::rules::rule_lines(matcher);
        let value = self.text(&value);
        match matcher {
            RuleMatcher::Domain(DomainMatch::Suffix(_)) => {
                tr!("connections-why-subdomains", site = value)
            }
            RuleMatcher::Domain(DomainMatch::Keyword(_)) => {
                tr!("connections-why-keyword", word = value)
            }
            RuleMatcher::Domain(DomainMatch::Exact(_))
            | RuleMatcher::Process(ProcessMatch::Name(_) | ProcessMatch::Path(_))
            | RuleMatcher::IpCidr(_)
            | RuleMatcher::List { .. }
            | RuleMatcher::Template(_) => value,
        }
    }
}
