//! Atomic application of a reviewed rules import.
use rosetun_config::{RuleSetId, rules_exchange::Preview};

use crate::{RuleSetError, Store};

pub fn apply(store: &Store, id: &RuleSetId, preview: &Preview, replace: bool, default_target: bool) -> Result<(), RuleSetError> {
    store.modify(|config| {
        let index = config.rule_sets.iter().position(|set| &set.id == id).ok_or(RuleSetError::SetNotFound)?;
        for list in &preview.lists {
            if !config.lists.iter().any(|existing| existing.id == list.id) { config.lists.push(list.clone()); }
        }
        let set = &mut config.rule_sets[index];
        if replace { set.rules.clear(); }
        set.rules.extend(preview.rules.clone());
        if default_target && let Some(target) = preview.default_target { set.default_target = target; }
        Ok(())
    })
}
