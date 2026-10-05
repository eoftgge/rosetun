use rosetun_config::{Subscription, SubscriptionId};
use rosetun_subscription::Parsed;

use crate::update::apply_update;
use crate::{FetchError, Store, StoreError, Timeouts, UpdateReport, fetch};

#[derive(Debug, Clone)]
pub struct AddOptions {
    pub name: Option<String>,
    pub user_agent: Option<String>,
    pub send_hwid: bool,
}

impl Default for AddOptions {
    fn default() -> Self {
        Self {
            name: None,
            user_agent: None,
            send_hwid: true,
        }
    }
}

pub struct PreparedSubscription {
    template: Subscription,
    name: Option<String>,
    plain_http: bool,
}

impl std::fmt::Debug for PreparedSubscription {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedSubscription")
            .field("url", &crate::redacted_subscription_url(&self.template.url))
            .field("plain_http", &self.plain_http)
            .finish_non_exhaustive()
    }
}

impl PreparedSubscription {
    pub fn uses_plain_http(&self) -> bool {
        self.plain_http
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AddFromUrlError {
    #[error("{0}")]
    Url(String),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("already added as {}", crate::terminal_text(.0.as_str()))]
    AlreadyExists(SubscriptionId),
    #[error("invalid subscription URL")]
    InvalidUrl(#[source] url::ParseError),
    #[error("subscription URL requires a host")]
    MissingHost,
    #[error("{message}")]
    Fetch {
        #[source]
        source: FetchError,
        message: String,
    },
    #[error("system clock is before the Unix epoch")]
    Clock(#[from] std::time::SystemTimeError),
    #[error(transparent)]
    Commit(#[from] AddSubscriptionError),
}

pub fn prepare_subscription(
    store: &Store,
    input: &str,
    options: AddOptions,
) -> Result<PreparedSubscription, AddFromUrlError> {
    let url = crate::normalize_subscription_url(input).map_err(AddFromUrlError::Url)?;
    let config = store.load()?;
    if let Some(existing) = config.subscriptions.iter().find(|sub| sub.url == url) {
        return Err(AddFromUrlError::AlreadyExists(existing.id.clone()));
    }
    let parsed_url = url::Url::parse(&url).map_err(AddFromUrlError::InvalidUrl)?;
    let host = parsed_url.host_str().ok_or(AddFromUrlError::MissingHost)?;
    let plain_http = parsed_url.scheme() == "http";
    let template = Subscription {
        id: SubscriptionId::new("pending"),
        name: host.to_owned(),
        url,
        nodes: Vec::new(),
        auto_update: false,
        updated_at_unix: None,
        user_agent: options.user_agent,
        send_hwid: options.send_hwid,
        info: None,
        update_interval_hours: None,
        support_url: None,
        web_page_url: None,
        announce: None,
        notices: Vec::new(),
    };
    Ok(PreparedSubscription {
        template,
        name: options.name,
        plain_http,
    })
}

pub fn add_prepared_subscription(
    store: &Store,
    prepared: PreparedSubscription,
    timeouts: Timeouts,
) -> Result<(Subscription, UpdateReport), AddFromUrlError> {
    add_prepared_subscription_with(store, prepared, timeouts, fetch)
}

pub(crate) fn add_prepared_subscription_with(
    store: &Store,
    prepared: PreparedSubscription,
    timeouts: Timeouts,
    mut fetch_subscription: impl FnMut(&Subscription, Timeouts) -> Result<Parsed, FetchError>,
) -> Result<(Subscription, UpdateReport), AddFromUrlError> {
    let mut template = prepared.template;
    let parsed = fetch_subscription(&template, timeouts).map_err(|source| {
        let message = crate::fetch_error_message(&source, &template.url);
        AddFromUrlError::Fetch { source, message }
    })?;
    // The parser already applies profile-title and Content-Disposition priority.
    template.name = prepared
        .name
        .or_else(|| parsed.meta.title.clone())
        .unwrap_or(template.name);
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    add_subscription(store, template, parsed, now_unix).map_err(Into::into)
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateSubscriptionError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("subscription does not exist")]
    NotFound,
    #[error("{message}")]
    Fetch {
        #[source]
        source: FetchError,
        message: String,
    },
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
) -> Result<(Subscription, UpdateReport), UpdateSubscriptionError> {
    update_subscription_with(store, id, timeouts, &mut fetch)
}

fn update_subscription_with(
    store: &Store,
    id: &SubscriptionId,
    timeouts: Timeouts,
    fetch_subscription: &mut impl FnMut(&Subscription, Timeouts) -> Result<Parsed, FetchError>,
) -> Result<(Subscription, UpdateReport), UpdateSubscriptionError> {
    let config = store.load()?;
    let requested = config
        .subscriptions
        .iter()
        .find(|subscription| &subscription.id == id)
        .ok_or(UpdateSubscriptionError::NotFound)?;

    let parsed = fetch_subscription(requested, timeouts).map_err(|source| {
        let message = crate::fetch_error_message(&source, &requested.url);
        UpdateSubscriptionError::Fetch { source, message }
    })?;
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    commit_subscription_update(store, requested, parsed, now_unix).map_err(Into::into)
}

pub type SubscriptionUpdateResult = (
    SubscriptionId,
    Result<(Subscription, UpdateReport), UpdateSubscriptionError>,
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
) -> Result<(Subscription, UpdateReport), CommitUpdateError> {
    store.modify(|config| {
        let index = config
            .subscriptions
            .iter()
            .position(|subscription| subscription.id == requested.id)
            .ok_or(CommitUpdateError::SubscriptionNotFound)?;
        let current = &config.subscriptions[index];

        if current.url != requested.url
            || current.user_agent != requested.user_agent
            || current.send_hwid != requested.send_hwid
        {
            return Err(CommitUpdateError::RequestSettingsChanged);
        }

        let report = apply_update(config, &requested.id, parsed, now_unix);
        Ok((config.subscriptions[index].clone(), report))
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
pub enum MoveSubscriptionError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("subscription does not exist")]
    NotFound,
}

pub fn move_subscription(
    store: &Store,
    id: &SubscriptionId,
    to_index: usize,
) -> Result<(), MoveSubscriptionError> {
    store.modify(|config| {
        let index = config
            .subscriptions
            .iter()
            .position(|subscription| &subscription.id == id)
            .ok_or(MoveSubscriptionError::NotFound)?;
        let subscription = config.subscriptions.remove(index);
        config
            .subscriptions
            .insert(to_index.min(config.subscriptions.len()), subscription);
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
