use std::collections::BTreeMap;
use std::path::PathBuf;

use rosetun_config::{ProcessMatch, Rule, RuleMatcher, RuleSet, RuleTarget, RuleTemplate};
use rosetun_processes::RunningProcess;

use crate::strings::{Strings, t};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessGroup {
    pub(crate) name: String,
    pub(crate) path: Option<PathBuf>,
    pub(crate) count: usize,
    pub(crate) windowed: bool,
}

pub(crate) fn group_processes(processes: Vec<RunningProcess>) -> Vec<ProcessGroup> {
    let mut groups = BTreeMap::<(bool, String), ProcessGroup>::new();
    for process in processes {
        let windowed = process.has_window && process.pid != std::process::id();
        let key = match &process.path {
            Some(path) => (true, path.to_string_lossy().to_lowercase()),
            None => (false, process.name.to_lowercase()),
        };
        groups
            .entry(key)
            .and_modify(|group| {
                group.count += 1;
                group.windowed |= windowed;
            })
            .or_insert(ProcessGroup {
                name: process.name,
                path: process.path,
                count: 1,
                windowed,
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

/// Whether the rule dialog can show this rule for editing.
pub(crate) fn editable(matcher: &RuleMatcher) -> bool {
    matches!(
        matcher,
        RuleMatcher::Domain(
            rosetun_config::DomainMatch::Exact(_) | rosetun_config::DomainMatch::Suffix(_)
        ) | RuleMatcher::Process(_)
    )
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

/// The line under a rule's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuleCaption {
    ThisAddress,
    WithSubdomains,
    Keyword,
    AnyFolder,
    /// The full path of a process rule.
    Path(String),
    Addresses,
    Template,
}

/// What a rule row shows: the value in bold and the caption under it.
pub(crate) fn rule_lines(matcher: &RuleMatcher) -> (String, RuleCaption) {
    rule_lines_in(matcher, t())
}

fn rule_lines_in(matcher: &RuleMatcher, strings: &Strings) -> (String, RuleCaption) {
    let value = rosetun_core::rule_value_text(matcher);
    match matcher {
        RuleMatcher::Domain(rosetun_config::DomainMatch::Exact(_)) => {
            (value, RuleCaption::ThisAddress)
        }
        RuleMatcher::Domain(rosetun_config::DomainMatch::Suffix(_)) => (
            value.strip_prefix("*.").unwrap_or(&value).to_owned(),
            RuleCaption::WithSubdomains,
        ),
        RuleMatcher::Domain(rosetun_config::DomainMatch::Keyword(keyword)) => {
            (keyword.clone(), RuleCaption::Keyword)
        }
        RuleMatcher::Process(ProcessMatch::Name(_)) => (value, RuleCaption::AnyFolder),
        RuleMatcher::Process(ProcessMatch::Path(_)) => {
            let name = value
                .rsplit(['/', '\\'])
                .next()
                .filter(|name| !name.is_empty())
                .unwrap_or(&value)
                .to_owned();
            (name, RuleCaption::Path(value))
        }
        RuleMatcher::IpCidr(_) => (value, RuleCaption::Addresses),
        RuleMatcher::Template(template) => (
            strings.template_name(*template).to_owned(),
            RuleCaption::Template,
        ),
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
        RuleMatcher::Domain(_) => TypeFilter::Domains,
        RuleMatcher::Process(_) => TypeFilter::Processes,
        RuleMatcher::IpCidr(_) => TypeFilter::Other,
        RuleMatcher::Template(RuleTemplate::RussianSites | RuleTemplate::Youtube) => {
            TypeFilter::Domains
        }
        RuleMatcher::Template(RuleTemplate::Messengers | RuleTemplate::Torrents) => {
            TypeFilter::Processes
        }
    }
}

pub(crate) fn rule_counts(set: &RuleSet) -> RuleCounts {
    rule_counts_slice(&set.rules)
}

pub(crate) fn rule_counts_slice(rules: &[Rule]) -> RuleCounts {
    let mut counts = RuleCounts::default();
    for rule in rules {
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
    visible_rules_in(&set.rules, filter, t())
}

pub(crate) fn visible_rules_slice<'a>(
    rules: &'a [Rule],
    filter: &RuleFilter,
) -> Vec<(usize, &'a Rule)> {
    visible_rules_in(rules, filter, t())
}

fn visible_rules_in<'a>(
    rules: &'a [Rule],
    filter: &RuleFilter,
    strings: &Strings,
) -> Vec<(usize, &'a Rule)> {
    let search = filter.search.to_lowercase();
    rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| {
            (filter.kind == TypeFilter::All || kind(rule) == filter.kind)
                && filter.target.is_none_or(|target| rule.target == target)
                && (search.is_empty()
                    || rosetun_core::rule_value_text(&rule.matcher)
                        .to_lowercase()
                        .contains(&search)
                    || rule_lines_in(&rule.matcher, strings)
                        .0
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
            has_window: false,
        }
    }

    #[test]
    fn edit_dialog_supports_only_exact_suffix_and_process_matchers() {
        for matcher in [
            RuleMatcher::Domain(DomainMatch::Exact("example.com".into())),
            RuleMatcher::Domain(DomainMatch::Suffix("example.com".into())),
            RuleMatcher::Process(ProcessMatch::Name("App.exe".into())),
            RuleMatcher::Process(ProcessMatch::Path(PathBuf::from("C:\\Apps\\App.exe"))),
        ] {
            assert!(editable(&matcher));
        }
        for matcher in [
            RuleMatcher::Domain(DomainMatch::Keyword("news".into())),
            RuleMatcher::IpCidr("10.0.0.0/8".into()),
            RuleMatcher::Template(rosetun_config::RuleTemplate::Youtube),
        ] {
            assert!(!editable(&matcher));
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
    fn grouped_process_is_windowed_when_any_other_pid_has_a_window() {
        let mut visible = process(11, "Editor.exe", Some(r"C:\Apps\Editor.exe"));
        visible.has_window = true;
        let mut self_process = process(std::process::id(), "Rosetun.exe", None);
        self_process.has_window = true;
        let groups = group_processes(vec![
            process(10, "Editor.exe", Some(r"C:\Apps\Editor.exe")),
            visible,
            self_process,
        ]);
        assert!(groups[0].windowed);
        assert_eq!(groups[0].count, 2);
        assert!(!groups[1].windowed);
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
    fn rule_lines_show_value_and_caption_for_each_matcher() {
        let cases = [
            (
                RuleMatcher::Domain(DomainMatch::Exact("xn--d1acufc.xn--p1ai".into())),
                "домен.рф",
                RuleCaption::ThisAddress,
            ),
            (
                RuleMatcher::Domain(DomainMatch::Suffix("example.com".into())),
                "example.com",
                RuleCaption::WithSubdomains,
            ),
            (
                RuleMatcher::Domain(DomainMatch::Keyword("news".into())),
                "news",
                RuleCaption::Keyword,
            ),
            (
                RuleMatcher::Process(ProcessMatch::Name("app.exe".into())),
                "app.exe",
                RuleCaption::AnyFolder,
            ),
            (
                RuleMatcher::Process(ProcessMatch::Path(PathBuf::from(r"C:\Apps\app.exe"))),
                "app.exe",
                RuleCaption::Path(r"C:\Apps\app.exe".into()),
            ),
            (
                RuleMatcher::IpCidr("10.0.0.0/8".into()),
                "10.0.0.0/8",
                RuleCaption::Addresses,
            ),
        ];
        for (matcher, expected_value, expected_caption) in cases {
            assert_eq!(
                rule_lines(&matcher),
                (expected_value.to_owned(), expected_caption)
            );
        }
    }

    #[test]
    fn templates_are_counted_as_websites_or_apps_and_searchable_in_russian() {
        let mut set = RuleSet::new(RuleSetId::new("set"), "Test", RuleTarget::Proxy);
        set.rules = RuleTemplate::ALL
            .into_iter()
            .enumerate()
            .map(|(index, template)| Rule {
                id: RuleId::new(index.to_string()),
                enabled: true,
                matcher: RuleMatcher::Template(template),
                target: template.default_target(),
            })
            .collect();
        assert_eq!(rule_counts(&set).domains, 2);
        assert_eq!(rule_counts(&set).processes, 2);
        let mut filter = RuleFilter {
            kind: TypeFilter::Domains,
            ..RuleFilter::default()
        };
        assert_eq!(indices(&set, &filter), vec![0, 2]);
        filter.kind = TypeFilter::Processes;
        assert_eq!(indices(&set, &filter), vec![1, 3]);
        assert_eq!(
            rule_lines_in(&set.rules[3].matcher, &crate::strings::RU),
            ("Торренты".to_owned(), RuleCaption::Template)
        );
        filter.search = "торр".into();
        assert_eq!(
            visible_rules_in(&set.rules, &filter, &crate::strings::RU)
                .into_iter()
                .map(|(index, _)| index)
                .collect::<Vec<_>>(),
            vec![3]
        );
        filter.search = "template:torrents".into();
        assert_eq!(
            visible_rules_in(&set.rules, &filter, &crate::strings::RU)
                .into_iter()
                .map(|(index, _)| index)
                .collect::<Vec<_>>(),
            vec![3]
        );
    }

    #[test]
    fn counts_and_type_filters_include_other_matchers() {
        let set = fixture();
        assert_eq!(
            rule_counts(&set),
            RuleCounts {
                domains: 3,
                processes: 2,
                other: 1
            }
        );
        assert_eq!(rule_counts(&set).all(), 6);
        let mut filter = RuleFilter::default();
        assert_eq!(indices(&set, &filter), vec![0, 1, 2, 3, 4, 5]);
        filter.kind = TypeFilter::Domains;
        assert_eq!(indices(&set, &filter), vec![0, 2, 3]);
        filter.kind = TypeFilter::Processes;
        assert_eq!(indices(&set, &filter), vec![1, 5]);
        filter.kind = TypeFilter::Other;
        assert_eq!(indices(&set, &filter), vec![4]);
    }

    #[test]
    fn temporary_rules_use_the_same_filters_and_counts() {
        let rules = vec![Rule {
            id: RuleId::new("t1"),
            enabled: true,
            matcher: RuleMatcher::Domain(DomainMatch::Exact("session.example".into())),
            target: RuleTarget::Direct,
        }];
        assert_eq!(rule_counts_slice(&rules).domains, 1);
        let filter = RuleFilter {
            search: "SESSION".into(),
            kind: TypeFilter::Domains,
            target: Some(RuleTarget::Direct),
        };
        assert_eq!(
            visible_rules_slice(&rules, &filter)[0].1.id,
            RuleId::new("t1")
        );
        assert!(
            visible_rules_slice(
                &rules,
                &RuleFilter {
                    target: Some(RuleTarget::Block),
                    ..filter
                }
            )
            .is_empty()
        );
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
        filter.kind = TypeFilter::Domains;
        filter.search = "NEWS".into();
        assert_eq!(indices(&set, &filter), vec![3]);
        assert_eq!(visible_rules(&set, &filter)[0].1.id.as_str(), "3");
    }
}
