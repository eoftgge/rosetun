//! Versioned, secret-free rule exchange, independent of persisted settings.
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AppConfig, CountryCode, DomainMatch, ExitId, ExitTarget, List, ListFormat, ListId, ListSource,
    ProcessMatch, Rule, RuleId, RuleMatcher, RuleSet, RuleTarget, RuleTemplate,
};

pub const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_RULES: usize = 10_000;
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum System {
    Windows,
    Linux,
}
impl System {
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Linux
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub format: String,
    pub version: u32,
    pub exported_by: String,
    pub system: System,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub default_target: Option<RuleTarget>,
    pub rules: Vec<Value>,
    pub lists: Vec<SharedList>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedList {
    pub name: String,
    pub format: ListFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    Url(String),
    File { original_name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub name: String,
    pub subscription: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<CountryCode>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedRule {
    enabled: bool,
    matcher: Matcher,
    target: RuleTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    server: Option<Server>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Matcher {
    Domain(DomainMatch),
    Process(ProcessMatch),
    IpCidr(String),
    List {
        list: usize,
        category: Option<String>,
    },
    Template(RuleTemplate),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Warning {
    OtherSystem,
    NeedsList,
    NeedsFile,
    ExitReplaced,
    BroadDirect,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryReport {
    pub index: usize,
    pub warnings: Vec<Warning>,
    pub invalid: bool,
}
#[derive(Clone)]
pub struct Preview {
    expected: Box<AppConfig>,
    pub rules: Vec<Rule>,
    pub indexes: Vec<usize>,
    pub lists: Vec<List>,
    pub duplicates: usize,
    pub entries: Vec<EntryReport>,
    pub default_target: Option<RuleTarget>,
}
impl Preview {
    pub fn is_current(&self, config: &AppConfig) -> bool {
        self.expected.as_ref() == config
    }
}
impl std::fmt::Debug for Preview {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Preview")
            .field("rules", &self.rules.len())
            .field("duplicates", &self.duplicates)
            .finish_non_exhaustive()
    }
}
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    #[error("rules document exceeds the size limit")]
    Size,
    #[error("invalid rules document or unknown fields")]
    Invalid,
    #[error("unsupported rules document version")]
    Version,
    #[error("too many rules or lists")]
    Count,
}

fn fresh_id() -> String {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u128::from(u64::MAX - 1)) as u64;
    NEXT_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |previous| {
            Some(time.max(previous + 1))
        })
        .map_or_else(|previous| previous, |previous| time.max(previous + 1))
        .to_string()
}
fn server(config: &AppConfig, id: &ExitId) -> Option<Server> {
    let exit = config.exits.iter().find(|exit| &exit.id == id)?;
    match &exit.target {
        ExitTarget::Node { selection, .. } => {
            let sub = config
                .subscriptions
                .iter()
                .find(|sub| sub.id == selection.subscription)?;
            let node = sub.node(&selection.node)?;
            Some(Server {
                name: node.name.clone(),
                subscription: sub.name.clone(),
                country: crate::node_country(&node.name),
            })
        }
        ExitTarget::Country(_) => None,
    }
}

/// Only referenced lists are included. URL disclosure requires the caller's explicit consent.
pub fn export(
    config: &AppConfig,
    set: &RuleSet,
    selected: Option<&[RuleId]>,
    with_urls: bool,
    system: System,
) -> Result<String, ExchangeError> {
    let mut document = Document {
        format: "rosetun-rules".into(),
        version: 1,
        exported_by: env!("CARGO_PKG_VERSION").into(),
        system,
        default_target: selected.is_none().then_some(set.default_target),
        rules: Vec::new(),
        lists: Vec::new(),
    };
    let mut ids = Vec::new();
    for rule in &set.rules {
        if selected.is_some_and(|ids| !ids.contains(&rule.id)) {
            continue;
        }
        let matcher = match &rule.matcher {
            RuleMatcher::Domain(value) => Matcher::Domain(value.clone()),
            RuleMatcher::Process(value) => Matcher::Process(value.clone()),
            RuleMatcher::IpCidr(value) => Matcher::IpCidr(value.clone()),
            RuleMatcher::Template(value) => Matcher::Template(*value),
            RuleMatcher::List { list, category } => {
                let index = if let Some(index) = ids.iter().position(|id| id == list) {
                    index
                } else {
                    let entry = config.lists.iter().find(|entry| &entry.id == list);
                    document.lists.push(SharedList {
                        name: entry.map_or_else(String::new, |entry| entry.name.clone()),
                        format: entry.map_or(ListFormat::Text, |entry| entry.format),
                        source: entry.and_then(|entry| match &entry.source {
                            ListSource::Url(url) if with_urls => Some(Source::Url(url.clone())),
                            ListSource::File { original_name }
                                if original_name == "list-required" =>
                            {
                                None
                            }
                            ListSource::File { original_name } => Some(Source::File {
                                original_name: original_name.clone(),
                            }),
                            ListSource::Url(_) => None,
                        }),
                    });
                    ids.push(list.clone());
                    ids.len() - 1
                };
                Matcher::List {
                    list: index,
                    category: category.clone(),
                }
            }
        };
        document.rules.push(
            serde_json::to_value(SharedRule {
                enabled: rule.enabled,
                matcher,
                target: rule.target,
                server: rule.exit.as_ref().and_then(|id| server(config, id)),
            })
            .map_err(|_| ExchangeError::Invalid)?,
        );
    }
    if document.rules.len() > MAX_RULES || document.lists.len() > MAX_RULES {
        return Err(ExchangeError::Count);
    }
    let text = serde_json::to_string_pretty(&document).map_err(|_| ExchangeError::Invalid)?;
    if text.len() > MAX_DOCUMENT_BYTES {
        return Err(ExchangeError::Size);
    }
    Ok(text)
}

pub fn parse(text: &str) -> Result<Document, ExchangeError> {
    if text.len() > MAX_DOCUMENT_BYTES {
        return Err(ExchangeError::Size);
    }
    let value: Value = serde_json::from_str(text).map_err(|_| ExchangeError::Invalid)?;
    if value.get("format").and_then(Value::as_str) != Some("rosetun-rules") {
        return Err(ExchangeError::Invalid);
    }
    if value.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(ExchangeError::Version);
    }
    let document: Document = serde_json::from_value(value).map_err(|_| ExchangeError::Invalid)?;
    if document.rules.len() > MAX_RULES || document.lists.len() > MAX_RULES {
        return Err(ExchangeError::Count);
    }
    if document.default_target == Some(RuleTarget::Exit) {
        return Err(ExchangeError::Invalid);
    }
    for list in &document.lists {
        if let Some(Source::File { original_name }) = &list.source
            && (original_name.is_empty()
                || matches!(original_name.as_str(), "." | "..")
                || original_name.contains(['/', '\\']))
        {
            return Err(ExchangeError::Invalid);
        }
        if let Some(Source::Url(value)) = &list.source {
            let url = url::Url::parse(value).map_err(|_| ExchangeError::Invalid)?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err(ExchangeError::Invalid);
            }
        }
    }
    Ok(document)
}

/// Preserves Linux case. Foreign paths remain unchanged and must be disabled.
pub fn translate_process(value: &ProcessMatch, from: System, to: System) -> (ProcessMatch, bool) {
    match value {
        ProcessMatch::Path(path) => {
            let text = path.to_string_lossy();
            let foreign = (to == System::Linux
                && (text.contains('\\') || text.as_bytes().get(1) == Some(&b':')))
                || (to == System::Windows && text.starts_with('/'));
            (value.clone(), from != to || foreign)
        }
        ProcessMatch::Name(name) => {
            let name = if from == to {
                name.clone()
            } else if to == System::Linux {
                if name.to_ascii_lowercase().ends_with(".exe") {
                    name[..name.len() - 4].to_owned()
                } else {
                    name.clone()
                }
            } else if name.to_ascii_lowercase().ends_with(".exe") {
                name.clone()
            } else {
                format!("{name}.exe")
            };
            (ProcessMatch::Name(name), false)
        }
    }
}
fn normalize(
    matcher: Matcher,
    lists: &[ListId],
    from: System,
    to: System,
    warnings: &mut Vec<Warning>,
) -> Option<RuleMatcher> {
    Some(match matcher {
        Matcher::Domain(DomainMatch::Keyword(value)) => {
            if value.is_empty() || value.chars().any(char::is_control) {
                return None;
            }
            RuleMatcher::Domain(DomainMatch::Keyword(value.to_lowercase()))
        }
        Matcher::Domain(value) => {
            let text = match value {
                DomainMatch::Exact(value) => value,
                DomainMatch::Suffix(value) => format!("*.{value}"),
                DomainMatch::Keyword(_) => unreachable!(),
            };
            let domain = crate::parse_domain_input(&text).ok()?;
            let (DomainMatch::Exact(value) | DomainMatch::Suffix(value)) = &domain else {
                return None;
            };
            if value.split('.').any(str::is_empty) {
                return None;
            }
            RuleMatcher::Domain(domain)
        }
        Matcher::IpCidr(value) => RuleMatcher::IpCidr(crate::parse_ip_cidr(&value).ok()?),
        Matcher::Process(value) => {
            let text = match &value {
                ProcessMatch::Name(value) => value.as_str(),
                ProcessMatch::Path(value) => value.to_str()?,
            };
            if text.trim().is_empty() || text.chars().any(char::is_control) {
                return None;
            }
            if matches!(&value, ProcessMatch::Name(name) if name.contains(['/', '\\', ':'])) {
                return None;
            }
            if matches!(&value, ProcessMatch::Path(_))
                && !(text.starts_with('/')
                    || text.starts_with("\\\\")
                    || text.as_bytes().get(1) == Some(&b':'))
            {
                return None;
            }
            let (value, foreign) = translate_process(&value, from, to);
            if matches!(&value, ProcessMatch::Name(name) if name.is_empty()) {
                return None;
            }
            if foreign {
                warnings.push(Warning::OtherSystem);
            }
            RuleMatcher::Process(value)
        }
        Matcher::Template(value) => RuleMatcher::Template(value),
        Matcher::List { list, category } => RuleMatcher::List {
            list: lists.get(list)?.clone(),
            category,
        },
    })
}
fn same_rule(a: &Rule, b: &Rule, system: System) -> bool {
    let matcher = match (&a.matcher, &b.matcher) {
        (
            RuleMatcher::Process(ProcessMatch::Name(a)),
            RuleMatcher::Process(ProcessMatch::Name(b)),
        ) if system == System::Windows => a.eq_ignore_ascii_case(b),
        (
            RuleMatcher::Process(ProcessMatch::Path(a)),
            RuleMatcher::Process(ProcessMatch::Path(b)),
        ) if system == System::Windows => a
            .to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy()),
        _ => a.matcher == b.matcher,
    };
    matcher && a.target == b.target && a.exit == b.exit
}
pub fn broad_direct(rule: &Rule) -> bool {
    rule.target == RuleTarget::Direct
        && match &rule.matcher {
            RuleMatcher::IpCidr(value) => matches!(value.as_str(), "0.0.0.0/0" | "::/0"),
            RuleMatcher::Domain(DomainMatch::Suffix(value)) => !value.contains('.'),
            RuleMatcher::Domain(DomainMatch::Keyword(value)) => value.len() < 4,
            _ => false,
        }
}
/// Builds the entire preview without changing settings or fetching lists.
pub fn preview(
    document: &Document,
    config: &AppConfig,
    set: &RuleSet,
    replace: bool,
    system: System,
) -> Preview {
    let mut result = Preview {
        expected: Box::new(config.clone()),
        rules: Vec::new(),
        indexes: Vec::new(),
        lists: Vec::new(),
        duplicates: 0,
        entries: Vec::new(),
        default_target: document.default_target,
    };
    let ids: Vec<_> = document
        .lists
        .iter()
        .map(|shared| {
            let source = shared.source.clone().unwrap_or(Source::File {
                original_name: "list-required".into(),
            });
            let stored_source = match &source {
                Source::Url(url) => ListSource::Url(url.clone()),
                Source::File { original_name } => ListSource::File {
                    original_name: original_name.clone(),
                },
            };
            if let Some(list) = config.lists.iter().chain(&result.lists).find(|list| {
                list.format == shared.format
                    && list.source == stored_source
                    && (matches!(source, Source::Url(_)) || list.name == shared.name)
            }) {
                return list.id.clone();
            }
            let id = ListId::new(fresh_id());
            {
                result.lists.push(List {
                    id: id.clone(),
                    name: shared.name.clone(),
                    format: shared.format,
                    source: match &source {
                        Source::Url(url) => ListSource::Url(url.clone()),
                        Source::File { original_name } => ListSource::File {
                            original_name: original_name.clone(),
                        },
                    },
                    updated_at: None,
                    size: None,
                    sha256: None,
                    categories: Vec::new(),
                });
            }
            id
        })
        .collect();
    for (index, value) in document.rules.iter().enumerate() {
        let mut report = EntryReport {
            index,
            warnings: Vec::new(),
            invalid: false,
        };
        let parsed = serde_json::from_value::<SharedRule>(value.clone()).ok();
        let rule = parsed.and_then(|shared| {
            let matcher = normalize(
                shared.matcher,
                &ids,
                document.system,
                system,
                &mut report.warnings,
            )?;
            if let RuleMatcher::List { list, category } = &matcher {
                let entry = result.lists.iter_mut().find(|entry| &entry.id == list);
                if let Some(entry) = entry {
                    if entry.format.has_categories() {
                        let category = category.as_deref()?;
                        let base = category.split('@').next()?;
                        if base.is_empty()
                            || !base.bytes().all(|byte| {
                                byte.is_ascii_lowercase()
                                    || byte.is_ascii_digit()
                                    || matches!(byte, b'_' | b'-')
                            })
                        {
                            return None;
                        }
                        if !entry.categories.iter().any(|existing| existing == base) {
                            entry.categories.push(base.into());
                        }
                    }
                    if !matches!(
                        entry.validate_category(category.as_deref()),
                        Ok(()) | Err(crate::ListCategoryError::Unknown)
                    ) {
                        return None;
                    }
                }
            }
            if let RuleMatcher::List { list, .. } = &matcher {
                let source = ids
                    .iter()
                    .position(|id| id == list)
                    .and_then(|index| document.lists.get(index));
                if let Some(entry) = config.lists.iter().find(|entry| &entry.id == list) {
                    let RuleMatcher::List { category, .. } = &matcher else {
                        return None;
                    };
                    if !matches!(
                        entry.validate_category(category.as_deref()),
                        Ok(()) | Err(crate::ListCategoryError::Unknown)
                    ) {
                        return None;
                    }
                }
                match source.and_then(|list| list.source.as_ref()) {
                    None => report.warnings.push(Warning::NeedsList),
                    Some(Source::File { .. }) => report.warnings.push(Warning::NeedsFile),
                    Some(Source::Url(_)) => {}
                }
            }
            let mut target = shared.target;
            let exit = if target == RuleTarget::Exit {
                let found = shared.server.as_ref().and_then(|description| {
                    let matches: Vec<_> = config
                        .exits
                        .iter()
                        .filter(|exit| server(config, &exit.id).as_ref() == Some(description))
                        .collect();
                    (matches.len() == 1).then(|| matches[0].id.clone())
                });
                if found.is_none() {
                    target = RuleTarget::Proxy;
                    report.warnings.push(Warning::ExitReplaced);
                }
                found
            } else {
                None
            };
            let rule = Rule {
                id: RuleId::new(fresh_id()),
                enabled: shared.enabled
                    && !report.warnings.iter().any(|warning| {
                        matches!(
                            warning,
                            Warning::OtherSystem | Warning::NeedsList | Warning::NeedsFile
                        )
                    }),
                matcher,
                target,
                exit,
            };
            if broad_direct(&rule) {
                report.warnings.push(Warning::BroadDirect);
            }
            Some(rule)
        });
        match rule {
            Some(rule)
                if result
                    .rules
                    .iter()
                    .chain(set.rules.iter().filter(|_| !replace))
                    .any(|existing| same_rule(existing, &rule, system)) =>
            {
                result.duplicates += 1;
            }
            Some(rule) => {
                result.indexes.push(index);
                result.rules.push(rule);
            }
            None => report.invalid = true,
        }
        result.entries.push(report);
    }
    result.lists.retain(|list| {
        result.rules.iter().any(
            |rule| matches!(&rule.matcher, RuleMatcher::List { list: id, .. } if id == &list.id),
        )
    });
    result
}

impl std::fmt::Debug for Document {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Document")
            .field("version", &self.version)
            .field("rules", &self.rules.len())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for SharedList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedList")
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<list source>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuleSetId;
    fn set() -> RuleSet {
        RuleSet::new(RuleSetId::new("private-set-id"), "Test", RuleTarget::Proxy)
    }
    fn rule(matcher: RuleMatcher) -> Rule {
        Rule {
            id: RuleId::new("private-rule-id"),
            enabled: true,
            matcher,
            target: RuleTarget::Proxy,
            exit: None,
        }
    }
    fn doc(rules: Vec<Value>) -> Document {
        Document {
            format: "rosetun-rules".into(),
            version: 1,
            exported_by: "test".into(),
            system: System::Windows,
            default_target: None,
            rules,
            lists: vec![],
        }
    }
    #[test]
    fn round_trip_preserves_rules_and_changes_ids() {
        let config = AppConfig::default();
        let mut original = set();
        original.rules = vec![
            rule(RuleMatcher::Domain(DomainMatch::Suffix(
                "example.com".into(),
            ))),
            rule(RuleMatcher::IpCidr("192.0.2.0/24".into())),
            rule(RuleMatcher::Template(RuleTemplate::Torrents)),
            rule(RuleMatcher::Process(ProcessMatch::Name(
                "FireFox.exe".into(),
            ))),
        ];
        let text = export(&config, &original, None, false, System::Windows).unwrap();
        assert!(!text.contains("private-"));
        let preview = preview(
            &parse(&text).unwrap(),
            &config,
            &set(),
            false,
            System::Windows,
        );
        assert_eq!(preview.rules.len(), original.rules.len());
        for (a, b) in preview.rules.iter().zip(&original.rules) {
            assert_eq!(a.matcher, b.matcher);
            assert_eq!(a.target, b.target);
            assert_eq!(a.enabled, b.enabled);
            assert_ne!(a.id, b.id);
        }
    }
    #[test]
    fn process_translation_preserves_linux_case_and_disables_foreign_paths() {
        let name = ProcessMatch::Name("FireFox.EXE".into());
        assert_eq!(
            translate_process(&name, System::Windows, System::Linux),
            (ProcessMatch::Name("FireFox".into()), false)
        );
        assert_eq!(
            translate_process(
                &ProcessMatch::Name("firefox".into()),
                System::Linux,
                System::Windows
            ),
            (ProcessMatch::Name("firefox.exe".into()), false)
        );
        assert!(
            translate_process(
                &ProcessMatch::Path("C:\\Apps\\firefox.exe".into()),
                System::Windows,
                System::Linux
            )
            .1
        );
        assert!(
            translate_process(
                &ProcessMatch::Path("/usr/bin/firefox".into()),
                System::Linux,
                System::Windows
            )
            .1
        );
        assert_eq!(
            translate_process(&name, System::Linux, System::Linux).0,
            name
        );
    }
    #[test]
    fn duplicates_ignore_ids_and_enabled_state_and_windows_name_case() {
        let config = AppConfig::default();
        let mut original = set();
        original.rules = vec![rule(RuleMatcher::Process(ProcessMatch::Name(
            "FIREFOX.EXE".into(),
        )))];
        let text = export(&config, &original, None, false, System::Windows).unwrap();
        original.rules[0].enabled = false;
        assert_eq!(
            preview(
                &parse(&text).unwrap(),
                &config,
                &original,
                false,
                System::Windows
            )
            .duplicates,
            1
        );
        assert_eq!(
            preview(
                &parse(&text).unwrap(),
                &config,
                &original,
                true,
                System::Windows
            )
            .rules
            .len(),
            1
        );
    }
    #[test]
    fn invalid_rows_are_reported_without_losing_valid_rows() {
        let document = doc(vec![
            serde_json::json!({"enabled":true,"matcher":{"domain":{"exact":"EXAMPLE.COM"}},"target":"proxy"}),
            serde_json::json!({"enabled":true,"matcher":{"ip_cidr":"192.0.2.5/24"},"target":"direct"}),
            serde_json::json!({"enabled":true,"matcher":{"list":{"list":8,"category":null}},"target":"proxy"}),
            serde_json::json!({"enabled":true,"matcher":{"domain":{"exact":"bad..domain"}},"target":"proxy"}),
            serde_json::json!({"unknown":true}),
        ]);
        let result = preview(
            &document,
            &AppConfig::default(),
            &set(),
            false,
            System::Linux,
        );
        assert_eq!(result.rules.len(), 1);
        assert_eq!(result.entries.iter().filter(|row| row.invalid).count(), 4);
        assert_eq!(
            result.rules[0].matcher,
            RuleMatcher::Domain(DomainMatch::Exact("example.com".into()))
        );
    }
    #[test]
    fn schema_and_resource_limits_are_enforced() {
        assert!(matches!(
            parse(&" ".repeat(MAX_DOCUMENT_BYTES + 1)),
            Err(ExchangeError::Size)
        ));
        let mut value = serde_json::to_value(doc(vec![])).unwrap();
        value["version"] = 2.into();
        assert!(matches!(
            parse(&value.to_string()),
            Err(ExchangeError::Version)
        ));
        value["version"] = 1.into();
        value["unknown"] = true.into();
        assert!(parse(&value.to_string()).is_err());
        let document = doc(vec![Value::Null; MAX_RULES + 1]);
        assert!(matches!(
            parse(&serde_json::to_string(&document).unwrap()),
            Err(ExchangeError::Count)
        ));
    }
    #[test]
    fn list_urls_require_consent_and_file_lists_remain_disabled() {
        let mut config = AppConfig::default();
        let id = ListId::new("private-list-id");
        config.lists.push(List {
            id: id.clone(),
            name: "Sites".into(),
            source: ListSource::Url("https://lists.example.com/token-secret".into()),
            format: ListFormat::Text,
            updated_at: Some(123),
            size: Some(123),
            sha256: Some("private-hash".into()),
            categories: vec![],
        });
        let mut original = set();
        original.rules.push(rule(RuleMatcher::List {
            list: id,
            category: None,
        }));
        let hidden = export(&config, &original, None, false, System::Windows).unwrap();
        for secret in [
            "lists.example.com",
            "token-secret",
            "private-list-id",
            "private-hash",
            "updated_at",
        ] {
            assert!(!hidden.contains(secret));
        }
        let result = preview(
            &parse(&hidden).unwrap(),
            &config,
            &set(),
            false,
            System::Linux,
        );
        assert!(!result.rules[0].enabled);
        assert!(result.entries[0].warnings.contains(&Warning::NeedsList));
        let consent = export(&config, &original, None, true, System::Windows).unwrap();
        assert!(consent.contains("token-secret"));
        config.lists[0].source = ListSource::File {
            original_name: "sites.txt".into(),
        };
        let text = export(&config, &original, None, true, System::Windows).unwrap();
        let result = preview(
            &parse(&text).unwrap(),
            &config,
            &set(),
            false,
            System::Linux,
        );
        assert!(!result.rules[0].enabled);
        assert!(result.entries[0].warnings.contains(&Warning::NeedsFile));
        assert!(text.contains("sites.txt"));
    }

    #[test]
    fn server_descriptions_never_disclose_node_credentials_and_require_an_exact_match() {
        let (mut config, _) =
            crate::from_json(include_bytes!("../tests/fixtures/v8.json")).unwrap();
        let sub = &config.subscriptions[0];
        let node = &sub.nodes[0];
        let selection = crate::Selection {
            subscription: sub.id.clone(),
            node: node.id.clone(),
        };
        let host = node.server.clone();
        let port = node.port.to_string();
        let id = ExitId::new("999");
        config.exits.clear();
        config.exits.push(crate::Exit {
            id: id.clone(),
            name: "Example exit".into(),
            target: ExitTarget::Node {
                selection,
                fallback: None,
            },
        });
        let mut original = set();
        let mut entry = rule(RuleMatcher::Domain(DomainMatch::Exact(
            "example.com".into(),
        )));
        entry.target = RuleTarget::Exit;
        entry.exit = Some(id);
        original.rules.push(entry);
        let text = export(&config, &original, None, true, System::Windows).unwrap();
        for secret in [
            host.as_str(),
            port.as_str(),
            "test-secret",
            "fixture-password",
            "public_key",
            "private_key",
            "password",
            "server:",
            "999",
        ] {
            assert!(!text.contains(secret), "unexpected secret: {secret}");
        }
        let document = parse(&text).unwrap();
        let matched = preview(&document, &config, &set(), false, System::Windows);
        assert_eq!(matched.rules[0].target, RuleTarget::Exit);
        config.subscriptions[0].name = "Different provider".into();
        let missing = preview(&document, &config, &set(), false, System::Windows);
        assert_eq!(missing.rules[0].target, RuleTarget::Proxy);
    }

    #[test]
    fn selected_exports_omit_the_default_and_unused_lists() {
        let config = AppConfig::default();
        let mut original = set();
        original.rules = vec![rule(RuleMatcher::IpCidr("2001:db8::/32".into()))];
        let text = export(&config, &original, Some(&[]), false, System::Linux).unwrap();
        let document = parse(&text).unwrap();
        assert!(document.default_target.is_none());
        assert!(document.rules.is_empty());
        assert!(document.lists.is_empty());
    }
    #[test]
    fn foreign_program_paths_are_disabled_but_names_are_translated() {
        let document = doc(vec![
            serde_json::json!({"enabled":true,"matcher":{"process":{"name":"FireFox.exe"}},"target":"proxy"}),
            serde_json::json!({"enabled":true,"matcher":{"process":{"path":"C:\\Apps\\firefox.exe"}},"target":"proxy"}),
        ]);
        let result = preview(
            &document,
            &AppConfig::default(),
            &set(),
            false,
            System::Linux,
        );
        assert!(result.rules[0].enabled);
        assert_eq!(
            result.rules[0].matcher,
            RuleMatcher::Process(ProcessMatch::Name("FireFox".into()))
        );
        assert!(!result.rules[1].enabled);
        assert!(result.entries[1].warnings.contains(&Warning::OtherSystem));
    }
    #[test]
    fn canonical_domains_and_repeated_rows_are_deduplicated() {
        let document = doc(vec![
            serde_json::json!({"enabled":true,"matcher":{"domain":{"suffix":"ПРИМЕР.example"}},"target":"proxy"}),
            serde_json::json!({"enabled":false,"matcher":{"domain":{"suffix":"xn--e1afmkfd.example"}},"target":"proxy"}),
        ]);
        let result = preview(
            &document,
            &AppConfig::default(),
            &set(),
            false,
            System::Linux,
        );
        assert_eq!(result.rules.len(), 1);
        assert_eq!(result.duplicates, 1);
    }
    #[test]
    fn missing_exit_falls_back_with_a_warning_and_wide_direct_is_flagged() {
        let document = doc(vec![
            serde_json::json!({"enabled":true,"matcher":{"ip_cidr":"0.0.0.0/0"},"target":"direct"}),
            serde_json::json!({"enabled":true,"matcher":{"domain":{"suffix":"example.com"}},"target":"exit","server":{"name":"Example","subscription":"Example provider"}}),
        ]);
        let result = preview(
            &document,
            &AppConfig::default(),
            &set(),
            false,
            System::Linux,
        );
        assert!(result.entries[0].warnings.contains(&Warning::BroadDirect));
        assert_eq!(result.rules[1].target, RuleTarget::Proxy);
        assert!(result.entries[1].warnings.contains(&Warning::ExitReplaced));
    }
}
