use rosetun_config::{DomainMatch, Rule, RuleMatcher, RuleSet, RuleTarget};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum TypeFilter {
    #[default]
    All,
    Domains,
    Processes,
    Other,
}

#[derive(Default)]
pub(crate) struct RuleFilter {
    pub(crate) search: String,
    pub(crate) kind: TypeFilter,
    pub(crate) target: Option<RuleTarget>,
}

impl RuleFilter {
    pub(crate) fn is_active(&self) -> bool {
        !self.search.is_empty() || self.kind != TypeFilter::All || self.target.is_some()
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RuleCounts {
    pub(crate) domains: usize,
    pub(crate) processes: usize,
    pub(crate) other: usize,
}

impl RuleCounts {
    pub(crate) fn all(&self) -> usize {
        self.domains + self.processes + self.other
    }
}

fn kind(rule: &Rule) -> TypeFilter {
    match &rule.matcher {
        RuleMatcher::Domain(DomainMatch::Exact(_) | DomainMatch::Suffix(_)) => TypeFilter::Domains,
        RuleMatcher::Process(_) => TypeFilter::Processes,
        RuleMatcher::Domain(DomainMatch::Keyword(_)) | RuleMatcher::IpCidr(_) => TypeFilter::Other,
    }
}

pub(crate) fn rule_counts(set: &RuleSet) -> RuleCounts {
    let mut counts = RuleCounts::default();
    for rule in &set.rules {
        match kind(rule) {
            TypeFilter::Domains => counts.domains += 1,
            TypeFilter::Processes => counts.processes += 1,
            TypeFilter::Other => counts.other += 1,
            TypeFilter::All => unreachable!(),
        }
    }
    counts
}

pub(crate) fn visible_rules<'a>(set: &'a RuleSet, filter: &RuleFilter) -> Vec<(usize, &'a Rule)> {
    let search = filter.search.to_lowercase();
    set.rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| {
            (filter.kind == TypeFilter::All || kind(rule) == filter.kind)
                && filter.target.is_none_or(|target| rule.target == target)
                && (search.is_empty()
                    || rosetun_core::rule_value_text(&rule.matcher)
                        .to_lowercase()
                        .contains(&search))
        })
        .collect()
}

pub(crate) fn reorder_arrows(
    index: usize,
    len: usize,
    filter: &RuleFilter,
    busy: bool,
) -> (bool, bool) {
    let enabled = !busy && !filter.is_active() && index < len;
    (enabled && index > 0, enabled && index + 1 < len)
}

/// `slot` is a gap in the full list. Removing a rule shifts later gaps left.
pub(crate) fn drop_target(from: usize, slot: usize, len: usize) -> Option<usize> {
    if from >= len || slot > len {
        return None;
    }
    let target = slot - usize::from(slot > from);
    (target != from).then_some(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rosetun_config::{DomainMatch, ProcessMatch, RuleId, RuleSetId};
    use std::path::PathBuf;

    fn fixture() -> RuleSet {
        let mut set = RuleSet::new(RuleSetId::new("set"), "Test", RuleTarget::Proxy);
        let matchers = [
            RuleMatcher::Domain(DomainMatch::Exact("Example.COM".into())),
            RuleMatcher::Process(ProcessMatch::Name("App.exe".into())),
            RuleMatcher::Domain(DomainMatch::Suffix("example.org".into())),
            RuleMatcher::Domain(DomainMatch::Keyword("News".into())),
            RuleMatcher::IpCidr("10.0.0.0/8".into()),
            RuleMatcher::Process(ProcessMatch::Path(PathBuf::from("C:\\Apps\\other.exe"))),
        ];
        set.rules = matchers
            .into_iter()
            .enumerate()
            .map(|(index, matcher)| Rule {
                id: RuleId::new(index.to_string()),
                enabled: true,
                matcher,
                target: if index % 2 == 0 {
                    RuleTarget::Proxy
                } else {
                    RuleTarget::Block
                },
            })
            .collect();
        set
    }

    fn indices(set: &RuleSet, filter: &RuleFilter) -> Vec<usize> {
        visible_rules(set, filter)
            .into_iter()
            .map(|(index, _)| index)
            .collect()
    }

    #[test]
    fn counts_and_type_filters_include_other_matchers() {
        let set = fixture();
        assert_eq!(
            rule_counts(&set),
            RuleCounts {
                domains: 2,
                processes: 2,
                other: 2
            }
        );
        assert_eq!(rule_counts(&set).all(), 6);
        let mut filter = RuleFilter::default();
        assert_eq!(indices(&set, &filter), vec![0, 1, 2, 3, 4, 5]);
        filter.kind = TypeFilter::Domains;
        assert_eq!(indices(&set, &filter), vec![0, 2]);
        filter.kind = TypeFilter::Processes;
        assert_eq!(indices(&set, &filter), vec![1, 5]);
        filter.kind = TypeFilter::Other;
        assert_eq!(indices(&set, &filter), vec![3, 4]);
    }

    #[test]
    fn search_target_and_combined_filters_keep_full_list_indices() {
        let set = fixture();
        let mut filter = RuleFilter {
            search: "EXAMPLE".into(),
            ..RuleFilter::default()
        };
        assert_eq!(indices(&set, &filter), vec![0, 2]);
        filter.search.clear();
        filter.target = Some(RuleTarget::Block);
        assert_eq!(indices(&set, &filter), vec![1, 3, 5]);
        filter.kind = TypeFilter::Other;
        filter.search = "NEWS".into();
        assert_eq!(indices(&set, &filter), vec![3]);
        assert_eq!(visible_rules(&set, &filter)[0].1.id.as_str(), "3");
    }

    #[test]
    fn arrows_require_an_unfiltered_idle_full_list() {
        let mut filter = RuleFilter::default();
        assert_eq!(reorder_arrows(0, 3, &filter, false), (false, true));
        assert_eq!(reorder_arrows(1, 3, &filter, false), (true, true));
        assert_eq!(reorder_arrows(2, 3, &filter, false), (true, false));
        assert_eq!(reorder_arrows(1, 3, &filter, true), (false, false));
        filter.target = Some(RuleTarget::Direct);
        assert_eq!(reorder_arrows(1, 3, &filter, false), (false, false));
        filter.target = None;
        filter.search = "app".into();
        assert_eq!(reorder_arrows(1, 3, &filter, false), (false, false));
        filter.search.clear();
        filter.kind = TypeFilter::Processes;
        assert_eq!(reorder_arrows(1, 3, &filter, false), (false, false));
    }

    #[test]
    fn drop_slots_account_for_removal_before_insertion() {
        assert_eq!(drop_target(3, 1, 5), Some(1));
        assert_eq!(drop_target(1, 4, 5), Some(3));
        assert_eq!(drop_target(0, 5, 5), Some(4));
        assert_eq!(drop_target(2, 2, 5), None);
        assert_eq!(drop_target(2, 3, 5), None);
        assert_eq!(drop_target(5, 0, 5), None);
        assert_eq!(drop_target(0, 6, 5), None);
    }
}
