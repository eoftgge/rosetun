use rosetun_config::Subscription;
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
