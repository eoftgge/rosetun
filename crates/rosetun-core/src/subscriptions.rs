use rosetun_config::{Subscription, SubscriptionId};
use rosetun_subscription::Parsed;

use crate::update::apply_update;
use crate::{Store, StoreError, UpdateReport};

#[derive(Debug, thiserror::Error)]
pub enum CommitUpdateError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("subscription does not exist")]
    SubscriptionNotFound,
    #[error(
        "subscription request settings changed while the update was being fetched; retry the update"
    )]
    RequestSettingsChanged,
}

/// Commits a response fetched using `requested` against the current configuration.
/// Local preferences and selections are taken from the current file.
pub fn commit_subscription_update(
    store: &Store,
    requested: &Subscription,
    parsed: Parsed,
    now_unix: u64,
) -> Result<UpdateReport, CommitUpdateError> {
    store.modify(|config| {
        let current = config
            .subscriptions
            .iter()
            .find(|subscription| subscription.id == requested.id)
            .ok_or(CommitUpdateError::SubscriptionNotFound)?;

        if current.url != requested.url
            || current.user_agent != requested.user_agent
            || current.send_hwid != requested.send_hwid
        {
            return Err(CommitUpdateError::RequestSettingsChanged);
        }

        Ok(apply_update(config, &requested.id, parsed, now_unix))
    })
}

#[derive(Debug, thiserror::Error)]
pub enum RemoveSubscriptionError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("subscription does not exist")]
    SubscriptionNotFound,
}

/// Removes a subscription and clears its active selection without changing rules.
pub fn remove_subscription(
    store: &Store,
    id: &SubscriptionId,
) -> Result<(), RemoveSubscriptionError> {
    store.modify(|config| {
        let index = config
            .subscriptions
            .iter()
            .position(|subscription| &subscription.id == id)
            .ok_or(RemoveSubscriptionError::SubscriptionNotFound)?;

        config.subscriptions.remove(index);

        if config
            .active
            .as_ref()
            .is_some_and(|selection| &selection.subscription == id)
        {
            config.active = None;
        }

        Ok(())
    })
}

#[derive(Debug, thiserror::Error)]
pub enum AddSubscriptionError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("subscription URL is already added")]
    AlreadyExists,
    #[error("no subscription IDs are available")]
    IdExhausted,
}

/// Saves a prepared subscription, replacing its ID with the smallest free
/// positive decimal ID from the current configuration.
pub fn add_subscription(
    store: &Store,
    mut subscription: Subscription,
) -> Result<Subscription, AddSubscriptionError> {
    store.modify(|config| {
        if config
            .subscriptions
            .iter()
            .any(|existing| existing.url == subscription.url)
        {
            return Err(AddSubscriptionError::AlreadyExists);
        }

        let occupied: std::collections::BTreeSet<_> = config
            .subscriptions
            .iter()
            .map(|subscription| subscription.id.as_str())
            .collect();

        let mut candidate = 1_u64;
        let id = loop {
            let value = candidate.to_string();
            if !occupied.contains(value.as_str()) {
                break SubscriptionId::new(value);
            }
            candidate = candidate
                .checked_add(1)
                .ok_or(AddSubscriptionError::IdExhausted)?;
        };

        subscription.id = id;
        config.subscriptions.push(subscription.clone());

        Ok(subscription)
    })
}
