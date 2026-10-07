use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use rosetun_config::RuleTemplate;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        loop {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("rosetun-rules-{}-{sequence}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("could not create test directory: {error}"),
            }
        }
    }

    fn config_path(&self) -> PathBuf {
        self.0.join("config.json")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn save_config(path: &Path, config: AppConfig) {
    Store::at(path)
        .modify(|current| {
            *current = config;
            Ok::<_, StoreError>(())
        })
        .unwrap();
}

fn domain(value: &str) -> RuleMatcher {
    RuleMatcher::Domain(DomainMatch::Exact(value.to_owned()))
}

fn rule(id: &str, value: &str) -> Rule {
    Rule {
        id: RuleId::new(id),
        enabled: true,
        matcher: domain(value),
        target: RuleTarget::Proxy,
    }
}

macro_rules! assert_no_write {
    ($store:expr, $operation:expr, $pattern:pat) => {{
        let before = fs::read($store.path()).unwrap();
        assert!(matches!($operation, Err($pattern)));
        assert_eq!(fs::read($store.path()).unwrap(), before);
    }};
}

#[test]
fn create_and_rename_rule_sets_validate_names_and_select_only_the_first() {
    let directory = TestDirectory::new();
    let store = Store::at(directory.config_path());
    let first = create_rule_set(&store, "  First  ", RuleTarget::Direct).unwrap();
    assert_eq!(
        first,
        RuleSet::new(RuleSetId::new("1"), "First", RuleTarget::Direct)
    );
    assert_eq!(
        store.load().unwrap().active_rule_set,
        Some(first.id.clone())
    );

    let second = create_rule_set(&store, "Second", RuleTarget::Block).unwrap();
    assert_eq!(second.id, RuleSetId::new("2"));
    assert_eq!(
        store.load().unwrap().active_rule_set,
        Some(first.id.clone())
    );

    rename_rule_set(&store, &second.id, "  Renamed  ").unwrap();
    let config = store.load().unwrap();
    assert_eq!(config.rule_sets[1].name, "Renamed");
    assert_eq!(config.active_rule_set, Some(first.id));
    assert_no_write!(
        store,
        create_rule_set(&store, " \t ", RuleTarget::Proxy),
        RuleSetError::EmptyName
    );
    assert_no_write!(
        store,
        rename_rule_set(&store, &second.id, "  "),
        RuleSetError::EmptyName
    );
    assert_no_write!(
        store,
        rename_rule_set(&store, &RuleSetId::new("missing"), "Name"),
        RuleSetError::SetNotFound
    );
}

#[test]
fn deletion_clears_only_the_active_rule_set() {
    let directory = TestDirectory::new();
    let store = Store::at(directory.config_path());
    let first = create_rule_set(&store, "First", RuleTarget::Proxy).unwrap();
    let second = create_rule_set(&store, "Second", RuleTarget::Block).unwrap();

    delete_rule_set(&store, &second.id).unwrap();
    assert_eq!(
        store.load().unwrap().active_rule_set,
        Some(first.id.clone())
    );
    assert_no_write!(
        store,
        delete_rule_set(&store, &second.id),
        RuleSetError::SetNotFound
    );
    delete_rule_set(&store, &first.id).unwrap();
    let config = store.load().unwrap();
    assert!(config.rule_sets.is_empty());
    assert_eq!(config.active_rule_set, None);

    let replacement = create_rule_set(&store, "Replacement", RuleTarget::Proxy).unwrap();
    assert_eq!(replacement.id, RuleSetId::new("1"));
    assert_eq!(store.load().unwrap().active_rule_set, Some(replacement.id));
}

#[test]
fn deleting_active_set_does_not_select_an_inactive_set() {
    let directory = TestDirectory::new();
    let store = Store::at(directory.config_path());
    let first = create_rule_set(&store, "First", RuleTarget::Proxy).unwrap();
    let second = create_rule_set(&store, "Second", RuleTarget::Direct).unwrap();
    delete_rule_set(&store, &first.id).unwrap();
    assert_eq!(store.load().unwrap().rule_sets[0].id, second.id);
    assert_eq!(store.load().unwrap().active_rule_set, None);
    create_rule_set(&store, "Third", RuleTarget::Proxy).unwrap();
    assert_eq!(store.load().unwrap().active_rule_set, None);
}

#[test]
fn set_default_target_persists_and_missing_set_does_not_write() {
    let directory = TestDirectory::new();
    let store = Store::at(directory.config_path());
    let set = create_rule_set(&store, "Set", RuleTarget::Proxy).unwrap();
    set_default_target(&store, &set.id, RuleTarget::Block).unwrap();
    assert_eq!(
        store.load().unwrap().rule_sets[0].default_target,
        RuleTarget::Block
    );
    assert_no_write!(
        store,
        set_default_target(&store, &RuleSetId::new("missing"), RuleTarget::Direct),
        RuleSetError::SetNotFound
    );
}

#[test]
fn added_rules_are_enabled_first_and_unique_even_when_disabled() {
    let directory = TestDirectory::new();
    let store = Store::at(directory.config_path());
    let set = create_rule_set(&store, "Set", RuleTarget::Proxy).unwrap();
    let first = add_rule(&store, &set.id, domain("a.example"), RuleTarget::Direct).unwrap();
    let second = add_rule(&store, &set.id, domain("b.example"), RuleTarget::Block).unwrap();
    assert_eq!(first.id, RuleId::new("1"));
    assert_eq!(second.id, RuleId::new("2"));
    assert!(second.enabled);
    assert_eq!(second.target, RuleTarget::Block);
    assert_eq!(
        store.load().unwrap().rule_sets[0].rules,
        vec![second, first.clone()]
    );

    set_rule_enabled(&store, &set.id, &first.id, false).unwrap();
    assert_no_write!(
        store,
        add_rule(&store, &set.id, domain("a.example"), RuleTarget::Block),
        RuleSetError::DuplicateRule
    );
    assert_no_write!(
        store,
        add_rule(
            &store,
            &RuleSetId::new("missing"),
            domain("c.example"),
            RuleTarget::Proxy
        ),
        RuleSetError::SetNotFound
    );
}

#[test]
fn batch_add_preserves_input_order_at_the_top_and_skips_duplicates() {
    let directory = TestDirectory::new();
    let store = Store::at(directory.config_path());
    let set = create_rule_set(&store, "Set", RuleTarget::Proxy).unwrap();
    let old = add_rule(&store, &set.id, domain("old.example"), RuleTarget::Block).unwrap();
    let result = add_rules(
        &store,
        &set.id,
        vec![
            domain("first.example"),
            domain("old.example"),
            domain("second.example"),
            domain("first.example"),
        ],
        RuleTarget::Direct,
    )
    .unwrap();
    assert_eq!(result.skipped, 2);
    assert_eq!(result.added.len(), 2);
    assert_eq!(result.added[0].id, RuleId::new("2"));
    assert_eq!(result.added[1].id, RuleId::new("3"));
    assert_eq!(result.added[0].matcher, domain("first.example"));
    assert_eq!(result.added[1].matcher, domain("second.example"));
    assert!(
        result
            .added
            .iter()
            .all(|rule| rule.enabled && rule.target == RuleTarget::Direct)
    );
    assert_eq!(
        store.load().unwrap().rule_sets[0].rules,
        vec![result.added[0].clone(), result.added[1].clone(), old]
    );
    assert_no_write!(
        store,
        add_rules(
            &store,
            &set.id,
            vec![domain("old.example"), domain("first.example")],
            RuleTarget::Proxy
        ),
        RuleSetError::DuplicateRule
    );
    let before = fs::read(store.path()).unwrap();
    assert_eq!(
        add_rules(&store, &set.id, Vec::new(), RuleTarget::Proxy).unwrap(),
        AddedRules {
            added: Vec::new(),
            skipped: 0
        }
    );
    assert_eq!(fs::read(store.path()).unwrap(), before);
}

#[test]
fn update_rule_keeps_identity_position_and_enabled_and_rejects_other_matchers() {
    let directory = TestDirectory::new();
    let store = Store::at(directory.config_path());
    let set = create_rule_set(&store, "Set", RuleTarget::Proxy).unwrap();
    let first = add_rule(&store, &set.id, domain("first.example"), RuleTarget::Proxy).unwrap();
    let middle = add_rule(&store, &set.id, domain("middle.example"), RuleTarget::Block).unwrap();
    let last = add_rule(&store, &set.id, domain("last.example"), RuleTarget::Proxy).unwrap();
    set_rule_enabled(&store, &set.id, &middle.id, false).unwrap();
    assert_no_write!(
        store,
        update_rule(
            &store,
            &set.id,
            &middle.id,
            domain("first.example"),
            RuleTarget::Direct
        ),
        RuleSetError::DuplicateRule
    );
    assert_no_write!(
        store,
        update_rule(
            &store,
            &set.id,
            &RuleId::new("missing"),
            domain("new.example"),
            RuleTarget::Proxy
        ),
        RuleSetError::RuleNotFound
    );
    update_rule(
        &store,
        &set.id,
        &middle.id,
        domain("middle.example"),
        RuleTarget::Direct,
    )
    .unwrap();
    update_rule(
        &store,
        &set.id,
        &middle.id,
        domain("new.example"),
        RuleTarget::Proxy,
    )
    .unwrap();
    let rules = store.load().unwrap().rule_sets.remove(0).rules;
    assert_eq!(rules[0], last);
    assert_eq!(rules[1].id, middle.id);
    assert!(!rules[1].enabled);
    assert_eq!(rules[1].matcher, domain("new.example"));
    assert_eq!(rules[1].target, RuleTarget::Proxy);
    assert_eq!(rules[2], first);
}

#[test]
fn new_ids_reuse_gaps_and_ignore_non_numeric_ids() {
    let directory = TestDirectory::new();
    let store = Store::at(directory.config_path());
    let mut set = RuleSet::new(RuleSetId::new("1"), "Set", RuleTarget::Proxy);
    set.rules = vec![
        rule("3", "a.example"),
        rule("custom", "b.example"),
        rule("1", "c.example"),
    ];
    let config = AppConfig {
        rule_sets: vec![
            set,
            RuleSet::new(RuleSetId::new("custom"), "Other", RuleTarget::Proxy),
            RuleSet::new(RuleSetId::new("3"), "Third", RuleTarget::Proxy),
        ],
        active_rule_set: Some(RuleSetId::new("1")),
        ..AppConfig::default()
    };
    save_config(store.path(), config);

    let created = create_rule_set(&store, "New", RuleTarget::Direct).unwrap();
    assert_eq!(created.id, RuleSetId::new("2"));
    assert_eq!(
        store.load().unwrap().active_rule_set,
        Some(RuleSetId::new("1"))
    );
    let in_existing = add_rule(
        &store,
        &RuleSetId::new("1"),
        domain("d.example"),
        RuleTarget::Proxy,
    )
    .unwrap();
    assert_eq!(in_existing.id, RuleId::new("2"));
    let in_new = add_rule(&store, &created.id, domain("d.example"), RuleTarget::Proxy).unwrap();
    assert_eq!(in_new.id, RuleId::new("1"));
}

#[test]
fn changing_rule_target_and_enabled_state_persists() {
    let directory = TestDirectory::new();
    let store = Store::at(directory.config_path());
    let set = create_rule_set(&store, "Set", RuleTarget::Proxy).unwrap();
    let rule = add_rule(&store, &set.id, domain("a.example"), RuleTarget::Proxy).unwrap();
    set_rule_target(&store, &set.id, &rule.id, RuleTarget::Direct).unwrap();
    set_rule_enabled(&store, &set.id, &rule.id, false).unwrap();
    assert_eq!(
        store.load().unwrap().rule_sets[0].rules[0].target,
        RuleTarget::Direct
    );
    assert!(!store.load().unwrap().rule_sets[0].rules[0].enabled);
    set_rule_enabled(&store, &set.id, &rule.id, true).unwrap();
    assert!(store.load().unwrap().rule_sets[0].rules[0].enabled);

    let missing_set = RuleSetId::new("missing");
    let missing_rule = RuleId::new("missing");
    assert_no_write!(
        store,
        set_rule_target(&store, &missing_set, &rule.id, RuleTarget::Block),
        RuleSetError::SetNotFound
    );
    assert_no_write!(
        store,
        set_rule_target(&store, &set.id, &missing_rule, RuleTarget::Block),
        RuleSetError::RuleNotFound
    );
    assert_no_write!(
        store,
        set_rule_enabled(&store, &missing_set, &rule.id, false),
        RuleSetError::SetNotFound
    );
    assert_no_write!(
        store,
        set_rule_enabled(&store, &set.id, &missing_rule, false),
        RuleSetError::RuleNotFound
    );
}

#[test]
fn moving_rules_up_down_and_past_the_end_preserves_order() {
    let directory = TestDirectory::new();
    let store = Store::at(directory.config_path());
    let set = create_rule_set(&store, "Set", RuleTarget::Proxy).unwrap();
    let first = add_rule(&store, &set.id, domain("a.example"), RuleTarget::Proxy).unwrap();
    let middle = add_rule(&store, &set.id, domain("b.example"), RuleTarget::Proxy).unwrap();
    let last = add_rule(&store, &set.id, domain("c.example"), RuleTarget::Proxy).unwrap();

    let ids = || {
        store.load().unwrap().rule_sets[0]
            .rules
            .iter()
            .map(|rule| rule.id.clone())
            .collect::<Vec<_>>()
    };
    move_rule(&store, &set.id, &first.id, 0).unwrap();
    assert_eq!(
        ids(),
        vec![first.id.clone(), last.id.clone(), middle.id.clone()]
    );
    move_rule(&store, &set.id, &first.id, 2).unwrap();
    assert_eq!(
        ids(),
        vec![last.id.clone(), middle.id.clone(), first.id.clone()]
    );
    move_rule(&store, &set.id, &last.id, usize::MAX).unwrap();
    assert_eq!(ids(), vec![middle.id, first.id.clone(), last.id.clone()]);

    assert_no_write!(
        store,
        move_rule(&store, &RuleSetId::new("missing"), &last.id, 0),
        RuleSetError::SetNotFound
    );
    assert_no_write!(
        store,
        move_rule(&store, &set.id, &RuleId::new("missing"), 0),
        RuleSetError::RuleNotFound
    );
}

#[test]
fn removing_rules_persists_and_missing_ids_do_not_write() {
    let directory = TestDirectory::new();
    let store = Store::at(directory.config_path());
    let set = create_rule_set(&store, "Set", RuleTarget::Proxy).unwrap();
    let rule = add_rule(&store, &set.id, domain("a.example"), RuleTarget::Direct).unwrap();
    assert_no_write!(
        store,
        remove_rule(&store, &RuleSetId::new("missing"), &rule.id),
        RuleSetError::SetNotFound
    );
    assert_no_write!(
        store,
        remove_rule(&store, &set.id, &RuleId::new("missing")),
        RuleSetError::RuleNotFound
    );
    remove_rule(&store, &set.id, &rule.id).unwrap();
    assert!(store.load().unwrap().rule_sets[0].rules.is_empty());
    assert_no_write!(
        store,
        remove_rule(&store, &set.id, &rule.id),
        RuleSetError::RuleNotFound
    );
}

#[test]
fn domain_input_accepts_exact_suffix_urls_and_idns() {
    for (input, expected) in [
        ("example.com", DomainMatch::Exact("example.com".to_owned())),
        (
            "youtube.com/watch?v=1",
            DomainMatch::Exact("youtube.com".to_owned()),
        ),
        (
            "*.example.com/x",
            DomainMatch::Suffix("example.com".to_owned()),
        ),
        (
            "example.com#top",
            DomainMatch::Exact("example.com".to_owned()),
        ),
        (
            "*.Example.COM",
            DomainMatch::Suffix("example.com".to_owned()),
        ),
        (".ru", DomainMatch::Suffix("ru".to_owned())),
        (
            "https://GitHub.com/path?q=1",
            DomainMatch::Exact("github.com".to_owned()),
        ),
        (
            " example.com. ",
            DomainMatch::Exact("example.com".to_owned()),
        ),
        (
            "пример.рф",
            DomainMatch::Exact("xn--e1afmkfd.xn--p1ai".to_owned()),
        ),
    ] {
        assert_eq!(parse_domain_input(input), Ok(expected), "{input}");
    }
}

#[test]
fn domain_input_rejects_ips_and_invalid_domains() {
    for input in ["1.2.3.4", "[::1]", "https://1.2.3.4/path", "https://[::1]/"] {
        assert_eq!(
            parse_domain_input(input),
            Err(RuleInputError::IpAddress),
            "{input}"
        );
    }
    for input in [
        "a.*.com",
        "example.com:443",
        "example.com:443/x",
        "ex ample.com",
        "",
        "  ",
        "ftp://example.com",
        "*.",
        "https:///",
    ] {
        assert_eq!(
            parse_domain_input(input),
            Err(RuleInputError::InvalidDomain),
            "{input}"
        );
    }
}

#[test]
fn domain_lines_keep_original_line_numbers_and_deduplicate() {
    let parsed = parse_domain_lines(
        "youtube.com\n  \r\nwww.youtube.com\n192.168.1.1\nru\nexample.org\nexample.org\n",
        true,
    );
    assert_eq!(
        parsed.domains,
        vec![
            DomainMatch::Suffix("youtube.com".into()),
            DomainMatch::Suffix("example.org".into()),
        ]
    );
    assert_eq!(
        parsed.errors,
        vec![
            DomainLineError {
                line: 4,
                error: RuleInputError::IpAddress
            },
            DomainLineError {
                line: 5,
                error: RuleInputError::SingleLabel
            },
        ]
    );
    assert_eq!(
        parse_domain_lines("one.example\n\nsecond.example\nthird.example", false).domains,
        vec![
            DomainMatch::Exact("one.example".into()),
            DomainMatch::Exact("second.example".into()),
            DomainMatch::Exact("third.example".into()),
        ]
    );
    assert_eq!(
        parse_domain_lines("example.com\n192.168.1.1", false).errors,
        vec![DomainLineError {
            line: 2,
            error: RuleInputError::IpAddress
        }]
    );
}

#[test]
fn domain_lines_handle_www_explicit_suffix_and_single_label() {
    assert_eq!(
        parse_domain_lines("https://www.youtube.com/watch?v=1\nwww.com", true).domains,
        vec![
            DomainMatch::Suffix("youtube.com".into()),
            DomainMatch::Suffix("www.com".into()),
        ]
    );
    assert_eq!(
        parse_domain_lines("www.youtube.com\n*.example.com", false).domains,
        vec![
            DomainMatch::Exact("www.youtube.com".into()),
            DomainMatch::Suffix("example.com".into()),
        ]
    );
    assert_eq!(
        parse_domain_lines("ru", true).errors,
        vec![DomainLineError {
            line: 1,
            error: RuleInputError::SingleLabel
        }]
    );
}

#[test]
fn process_input_accepts_names_and_absolute_paths() {
    for (input, expected) in [
        (
            "Telegram.exe",
            ProcessMatch::Name("Telegram.exe".to_owned()),
        ),
        (
            "\"C:\\Program Files\\App\\app.exe\"",
            ProcessMatch::Path(PathBuf::from("C:\\Program Files\\App\\app.exe")),
        ),
        (
            "C:/Apps/app.exe",
            ProcessMatch::Path(PathBuf::from("C:/Apps/app.exe")),
        ),
        (
            "/usr/bin/app",
            ProcessMatch::Path(PathBuf::from("/usr/bin/app")),
        ),
        (
            "\\\\server\\share\\app.exe",
            ProcessMatch::Path(PathBuf::from("\\\\server\\share\\app.exe")),
        ),
    ] {
        assert_eq!(parse_process_input(input), Ok(expected), "{input}");
    }
}

#[test]
fn process_input_rejects_relative_paths_and_invalid_names() {
    for input in [
        "apps\\app.exe",
        "apps/app.exe",
        "C:apps\\app.exe",
        "\\app.exe",
    ] {
        assert_eq!(
            parse_process_input(input),
            Err(RuleInputError::RelativePath),
            "{input}"
        );
    }
    for input in ["app*.exe", "", "  ", "\"\"", "app?.exe", "bad:name.exe"] {
        assert_eq!(
            parse_process_input(input),
            Err(RuleInputError::InvalidProcess),
            "{input}"
        );
    }
}

#[test]
fn template_rules_are_unique_even_when_disabled() {
    let directory = TestDirectory::new();
    let store = Store::at(directory.config_path());
    let set = create_rule_set(&store, "Set", RuleTarget::Proxy).unwrap();
    let matcher = RuleMatcher::Template(RuleTemplate::RussianSites);
    let first = add_rule(&store, &set.id, matcher.clone(), RuleTarget::Direct).unwrap();
    set_rule_enabled(&store, &set.id, &first.id, false).unwrap();
    assert_no_write!(
        store,
        add_rule(&store, &set.id, matcher, RuleTarget::Block),
        RuleSetError::DuplicateRule
    );
    assert!(
        add_rule(
            &store,
            &set.id,
            RuleMatcher::Template(RuleTemplate::Youtube),
            RuleTarget::Proxy
        )
        .is_ok()
    );
}

#[test]
fn template_contents_pass_rule_input_validation() {
    for template in RuleTemplate::ALL {
        for matcher in template.matchers() {
            match matcher {
                RuleMatcher::Domain(DomainMatch::Suffix(domain)) => assert_eq!(
                    parse_domain_input(&format!("*.{domain}")),
                    Ok(DomainMatch::Suffix(domain))
                ),
                RuleMatcher::Process(ProcessMatch::Name(name)) => {
                    assert_eq!(parse_process_input(&name), Ok(ProcessMatch::Name(name)));
                }
                other => panic!("unexpected matcher in {}: {other:?}", template.key()),
            }
        }
    }
}

#[test]
fn rule_value_text_formats_every_matcher() {
    for (matcher, expected) in [
        (domain("example.com"), "example.com"),
        (
            RuleMatcher::Domain(DomainMatch::Suffix("example.com".to_owned())),
            "*.example.com",
        ),
        (
            RuleMatcher::Domain(DomainMatch::Keyword("example".to_owned())),
            "contains \"example\"",
        ),
        (
            RuleMatcher::Process(ProcessMatch::Name("Telegram.exe".to_owned())),
            "Telegram.exe",
        ),
        (
            RuleMatcher::Process(ProcessMatch::Path(PathBuf::from("/usr/bin/app"))),
            "/usr/bin/app",
        ),
        (
            RuleMatcher::IpCidr("192.0.2.0/24".to_owned()),
            "192.0.2.0/24",
        ),
        (
            RuleMatcher::Template(RuleTemplate::RussianSites),
            "template:russian_sites",
        ),
    ] {
        assert_eq!(rule_value_text(&matcher), expected);
    }
}

#[test]
fn exact_and_suffix_domains_round_trip_through_text() {
    for matcher in [
        domain("example.com"),
        RuleMatcher::Domain(DomainMatch::Suffix("example.com".to_owned())),
    ] {
        assert_eq!(
            parse_domain_input(&rule_value_text(&matcher)).map(RuleMatcher::Domain),
            Ok(matcher)
        );
    }
}
