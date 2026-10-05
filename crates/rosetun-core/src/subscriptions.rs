use rosetun_config::{Subscription, SubscriptionId};
use rosetun_subscription::Parsed;

use crate::update::apply_update;
use crate::{FetchError, Store, StoreError, Timeouts, UpdateReport, fetch};

#[derive(Debug, thiserror::Error)]
pub enum UpdateSubscriptionError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("subscription does not exist")]
    NotFound,
    #[error(transparent)]
    Fetch(#[from] FetchError),
    #[error(
        "subscription request settings changed while the update was being fetched; retry the update"
    )]
    RequestSettingsChanged,
    #[error("system clock is before the Unix epoch")]
    Clock(#[from] std::time::SystemTimeError),
}

impl From<CommitUpdateError> for UpdateSubscriptionError {
    fn from(error: CommitUpdateError) -> Self {
        match error {
            CommitUpdateError::Store(error) => Self::Store(error),
            CommitUpdateError::SubscriptionNotFound => Self::NotFound,
            CommitUpdateError::RequestSettingsChanged => Self::RequestSettingsChanged,
        }
    }
}

pub fn update_subscription(
    store: &Store,
    id: &SubscriptionId,
    timeouts: Timeouts,
) -> Result<UpdateReport, UpdateSubscriptionError> {
    update_subscription_with(store, id, timeouts, &mut fetch)
}

fn update_subscription_with(
    store: &Store,
    id: &SubscriptionId,
    timeouts: Timeouts,
    fetch_subscription: &mut impl FnMut(&Subscription, Timeouts) -> Result<Parsed, FetchError>,
) -> Result<UpdateReport, UpdateSubscriptionError> {
    let config = store.load()?;
    let requested = config
        .subscriptions
        .iter()
        .find(|subscription| &subscription.id == id)
        .ok_or(UpdateSubscriptionError::NotFound)?;

    let parsed = fetch_subscription(requested, timeouts)?;
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    commit_subscription_update(store, requested, parsed, now_unix).map_err(Into::into)
}

pub type SubscriptionUpdateResult = (
    SubscriptionId,
    Result<UpdateReport, UpdateSubscriptionError>,
);

pub fn update_all(
    store: &Store,
    timeouts: Timeouts,
) -> Result<Vec<SubscriptionUpdateResult>, StoreError> {
    update_all_with(store, timeouts, fetch)
}

pub(crate) fn update_all_with(
    store: &Store,
    timeouts: Timeouts,
    mut fetch_subscription: impl FnMut(&Subscription, Timeouts) -> Result<Parsed, FetchError>,
) -> Result<Vec<SubscriptionUpdateResult>, StoreError> {
    let ids: Vec<_> = store
        .load()?
        .subscriptions
        .into_iter()
        .map(|subscription| subscription.id)
        .collect();

    Ok(ids
        .into_iter()
        .map(|id| {
            let result = update_subscription_with(store, &id, timeouts, &mut fetch_subscription);
            (id, result)
        })
        .collect())
}

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

pub fn add_subscription(
    store: &Store,
    mut template: Subscription,
    parsed: Parsed,
    now_unix: u64,
) -> Result<(Subscription, UpdateReport), AddSubscriptionError> {
    store.modify(|config| {
        if config
            .subscriptions
            .iter()
            .any(|existing| existing.url == template.url)
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

        template.id = id.clone();
        template.nodes.clear();

        let index = config.subscriptions.len();
        config.subscriptions.push(template);

        let report = apply_update(config, &id, parsed, now_unix);
        Ok((config.subscriptions[index].clone(), report))
    })
}

#[cfg(test)]
mod tests;
