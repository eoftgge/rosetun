use std::collections::BTreeMap;
use std::path::PathBuf;

use rosetun_config::{DomainMatch, ProcessMatch, Rule, RuleMatcher, RuleSet, RuleTarget};
use rosetun_processes::RunningProcess;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessGroup {
    pub(crate) name: String,
    pub(crate) path: Option<PathBuf>,
    pub(crate) count: usize,
}

pub(crate) fn group_processes(processes: Vec<RunningProcess>) -> Vec<ProcessGroup> {
    let mut groups = BTreeMap::<(bool, String), ProcessGroup>::new();
    for process in processes {
        let key = match &process.path {
            Some(path) => (true, path.to_string_lossy().to_lowercase()),
            None => (false, process.name.to_lowercase()),
        };
        groups
            .entry(key)
            .and_modify(|group| group.count += 1)
            .or_insert(ProcessGroup {
                name: process.name,
                path: process.path,
                count: 1,
            });
    }
    let mut groups: Vec<_> = groups.into_values().collect();
    groups.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then_with(|| a.path.cmp(&b.path))
    });
    groups
}

pub(crate) fn process_matches_filter(process: &ProcessGroup, filter: &str) -> bool {
    let filter = filter.to_lowercase();
    process.name.to_lowercase().contains(&filter)
        || process
            .path
            .as_ref()
            .is_some_and(|path| path.to_string_lossy().to_lowercase().contains(&filter))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ProcessMatchMode {
    #[default]
    Name,
    Path,
}

pub(crate) fn update_process_match_mode(mode: &mut ProcessMatchMode, input: &str) {
    match rosetun_core::parse_process_input(input) {
        Ok(ProcessMatch::Path(_)) => *mode = ProcessMatchMode::Path,
        Ok(ProcessMatch::Name(_)) => *mode = ProcessMatchMode::Name,
        Err(_) => {}
    }
}

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

    fn process(pid: u32, name: &str, path: Option<&str>) -> RunningProcess {
        RunningProcess {
            pid,
            name: name.into(),
            path: path.map(PathBuf::from),
        }
    }

    #[test]
    fn processes_group_by_path_or_name_and_sort_case_insensitively() {
        let groups = group_processes(vec![
            process(10, "zeta.exe", Some(r"C:\Apps\zeta.exe")),
            process(11, "Beta.exe", None),
            process(12, "Alpha.exe", Some(r"C:\Apps\Alpha.exe")),
            process(13, "alpha.exe", Some(r"c:\apps\alpha.exe")),
            process(14, "beta.exe", None),
            process(15, "Beta.exe", Some(r"C:\Apps\Beta.exe")),
        ]);
        assert_eq!(groups.len(), 4);
        assert_eq!(groups[0].name, "Alpha.exe");
        assert_eq!(groups[0].count, 2);
        assert_eq!(groups[1].name, "Beta.exe");
        assert_eq!(groups[1].count, 2);
        assert!(groups[1].path.is_none());
        assert_eq!(groups[2].name, "Beta.exe");
        assert_eq!(groups[2].count, 1);
        assert_eq!(groups[3].name, "zeta.exe");
    }

    #[test]
    fn process_filter_searches_name_and_path_without_case() {
        let group = group_processes(vec![process(
            10,
            "Telegram.exe",
            Some(r"C:\Users\Test\Apps\Telegram.exe"),
        )]);
        assert!(process_matches_filter(&group[0], "TELEGRAM"));
        assert!(process_matches_filter(&group[0], "users\\TEST"));
        assert!(!process_matches_filter(&group[0], "firefox"));
    }

    #[test]
    fn a_typed_path_switches_to_full_path_mode() {
        let mut mode = ProcessMatchMode::Name;
        update_process_match_mode(&mut mode, "curl.exe");
        assert_eq!(mode, ProcessMatchMode::Name);
        update_process_match_mode(&mut mode, r#""C:\Apps\curl.exe""#);
        assert_eq!(mode, ProcessMatchMode::Path);
        update_process_match_mode(&mut mode, "curl.exe");
        assert_eq!(mode, ProcessMatchMode::Name);
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
}
