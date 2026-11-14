//! Atomic application of a reviewed rules import.
use rosetun_config::{RuleSetId, rules_exchange::Preview};

use crate::{RuleSetError, Store};

pub fn apply(
    store: &Store,
    id: &RuleSetId,
    preview: &Preview,
    replace: bool,
    default_target: bool,
) -> Result<(), RuleSetError> {
    store.modify(|config| {
        if !preview.is_current(config) {
            return Err(RuleSetError::ImportChanged);
        }
        if let Some(set) = &preview.new_set {
            if &set.id != id
                || config
                    .rule_sets
                    .iter()
                    .any(|existing| existing.id == set.id)
            {
                return Err(RuleSetError::ImportChanged);
            }
            if set.name.trim().is_empty() {
                return Err(RuleSetError::EmptyName);
            }
            let mut set = set.clone();
            set.name = set.name.trim().to_owned();
            set.rules.clear();
            config.rule_sets.push(set);
        }
        let index = config
            .rule_sets
            .iter()
            .position(|set| &set.id == id)
            .ok_or(RuleSetError::SetNotFound)?;
        for list in &preview.lists {
            if !config.lists.iter().any(|existing| existing.id == list.id) {
                config.lists.push(list.clone());
            }
        }
        let set = &mut config.rule_sets[index];
        if replace {
            set.rules.clear();
        }
        set.rules.extend(preview.rules.clone());
        if default_target && let Some(target) = preview.default_target {
            set.default_target = target;
        }
        Ok(())
    })
}

pub fn draft_set(config: &rosetun_config::AppConfig) -> rosetun_config::RuleSet {
    rosetun_config::RuleSet::new(
        RuleSetId::new(crate::rules::next_id(
            config.rule_sets.iter().map(|set| set.id.as_str()),
        )),
        "",
        rosetun_config::RuleTarget::Proxy,
    )
}
