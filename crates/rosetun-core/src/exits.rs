use rosetun_config::{
    AppConfig, CountryCode, Exit, ExitId, ExitTarget, RuleTarget, Selection, node_country,
};

pub use rosetun_config::resolve_exits;
use rosetun_ipc::MAX_EXTRA_NODES;

use crate::{Store, StoreError, rules::next_id};

#[derive(Debug, thiserror::Error)]
pub enum ExitError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("exit does not exist")]
    NotFound,
    #[error("selected node does not exist")]
    NodeNotFound,
    #[error("exit name must not be empty")]
    EmptyName,
    #[error("there are already {MAX_EXTRA_NODES} exits, the most one connection can use")]
    TooMany,
}

/// An exit the user picked by country or node; created on the first rule that uses it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewExit {
    Country { code: CountryCode, name: String },
    Node { selection: Selection, name: String },
}

fn get_or_create(
    config: &mut AppConfig,
    target: ExitTarget,
    name: &str,
) -> Result<Exit, ExitError> {
    if let Some(exit) = config
        .exits
        .iter()
        .find(|exit| match (&exit.target, &target) {
            (
                ExitTarget::Node {
                    selection: existing,
                    ..
                },
                ExitTarget::Node { selection, .. },
            ) => existing == selection,
            _ => exit.target == target,
        })
    {
        return Ok(exit.clone());
    }
    if config.exits.len() >= MAX_EXTRA_NODES {
        return Err(ExitError::TooMany);
    }
    let name = name.trim();
    if name.is_empty() {
        return Err(ExitError::EmptyName);
    }
    let exit = Exit {
        id: ExitId::new(next_id(config.exits.iter().map(|exit| exit.id.as_str()))),
        name: name.to_owned(),
        target,
    };
    config.exits.push(exit.clone());
    Ok(exit)
}

pub(crate) fn exit_in(config: &mut AppConfig, new: &NewExit) -> Result<Exit, ExitError> {
    match new {
        NewExit::Country { code, name } => {
            get_or_create(config, ExitTarget::Country(code.clone()), name)
        }
        NewExit::Node { selection, name } => {
            let node = config
                .subscriptions
                .iter()
                .find(|subscription| subscription.id == selection.subscription)
                .and_then(|subscription| subscription.node(&selection.node))
                .ok_or(ExitError::NodeNotFound)?;
            let target = ExitTarget::Node {
                selection: selection.clone(),
                fallback: node_country(&node.name),
            };
            get_or_create(config, target, name)
        }
    }
}

pub fn create_exit(store: &Store, new: &NewExit) -> Result<Exit, ExitError> {
    store.modify(|config| exit_in(config, new))
}

pub fn exit_for_country(store: &Store, code: CountryCode, name: &str) -> Result<Exit, ExitError> {
    create_exit(
        store,
        &NewExit::Country {
            code,
            name: name.to_owned(),
        },
    )
}

pub fn exit_for_node(store: &Store, selection: &Selection, name: &str) -> Result<Exit, ExitError> {
    create_exit(
        store,
        &NewExit::Node {
            selection: selection.clone(),
            name: name.to_owned(),
        },
    )
}

pub fn rename_exit(store: &Store, id: &ExitId, name: &str) -> Result<(), ExitError> {
    store.modify(|config| {
        let name = name.trim();
        if name.is_empty() {
            return Err(ExitError::EmptyName);
        }
        let exit = config
            .exits
            .iter_mut()
            .find(|exit| &exit.id == id)
            .ok_or(ExitError::NotFound)?;
        exit.name = name.to_owned();
        Ok(())
    })
}

pub fn change_exit_target(store: &Store, id: &ExitId, target: ExitTarget) -> Result<(), ExitError> {
    store.modify(|config| {
        let exit = config
            .exits
            .iter_mut()
            .find(|exit| &exit.id == id)
            .ok_or(ExitError::NotFound)?;
        exit.target = target;
        Ok(())
    })
}

pub fn delete_exit(store: &Store, id: &ExitId) -> Result<usize, ExitError> {
    store.modify(|config| {
        let index = config
            .exits
            .iter()
            .position(|exit| &exit.id == id)
            .ok_or(ExitError::NotFound)?;
        config.exits.remove(index);
        let mut blocked = 0;
        for rule in config.rule_sets.iter_mut().flat_map(|set| &mut set.rules) {
            if rule.exit.as_ref() == Some(id) {
                rule.target = RuleTarget::Block;
                rule.exit = None;
                blocked += 1;
            }
        }
        Ok(blocked)
    })
}

pub fn exit_rule_count(config: &AppConfig, id: &ExitId) -> usize {
    config
        .rule_sets
        .iter()
        .flat_map(|set| &set.rules)
        .filter(|rule| rule.target == RuleTarget::Exit && rule.exit.as_ref() == Some(id))
        .count()
}

#[cfg(test)]
mod tests;
