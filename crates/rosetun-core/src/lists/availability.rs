use std::collections::HashMap;

use rosetun_config::{AppConfig, ListId, Rule, RuleId, RuleMatcher, RuleSetId, list_tag};

use super::{ListError, last_good};
use crate::Store;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingListCategory {
    pub set: Option<RuleSetId>,
    pub rule: RuleId,
    pub list: ListId,
    pub category: String,
    pub last_good: bool,
}

pub fn inspect_missing_categories(
    store: &Store,
    config: &AppConfig,
    temporary: &[Rule],
) -> Result<Vec<MissingListCategory>, ListError> {
    let mut found = Vec::new();
    let mut cached = HashMap::new();
    for set in &config.rule_sets {
        inspect_rules(
            store,
            config,
            &set.rules,
            Some(&set.id),
            &mut cached,
            &mut found,
        )?;
    }
    inspect_rules(store, config, temporary, None, &mut cached, &mut found)?;
    Ok(found)
}

fn inspect_rules(
    store: &Store,
    config: &AppConfig,
    rules: &[Rule],
    set: Option<&RuleSetId>,
    cached: &mut HashMap<String, bool>,
    found: &mut Vec<MissingListCategory>,
) -> Result<(), ListError> {
    for rule in rules {
        let RuleMatcher::List {
            list: id,
            category: Some(category),
        } = &rule.matcher
        else {
            continue;
        };
        let list = config
            .lists
            .iter()
            .find(|item| &item.id == id)
            .ok_or(ListError::NotFound)?;
        if !list.format.has_categories() {
            continue;
        }
        let base = category.split_once('@').map_or(category.as_str(), |(base, _)| base);
        if list.categories.iter().any(|name| name == base) {
            continue;
        }
        let tag = list_tag(id, Some(category));
        let has_copy = if let Some(has_copy) = cached.get(&tag) {
            *has_copy
        } else {
            let has_copy = last_good::load(store, &tag)?.is_some();
            cached.insert(tag, has_copy);
            has_copy
        };
        found.push(MissingListCategory {
            set: set.cloned(),
            rule: rule.id.clone(),
            list: id.clone(),
            category: category.clone(),
            last_good: has_copy,
        });
    }
    Ok(())
}
