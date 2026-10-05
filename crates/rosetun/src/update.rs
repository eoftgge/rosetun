use rosetun_config::{AppConfig, SubscriptionId};
pub(crate) use rosetun_core::{UpdateReport, group_skipped};
use rosetun_subscription::Parsed;
use std::collections::BTreeSet;

pub(crate) fn apply_update(
    config: &mut AppConfig,
    id: &SubscriptionId,
    parsed: Parsed,
    now_unix: u64,
) -> UpdateReport {
    let subscription = config
        .subscriptions
        .iter_mut()
        .find(|subscription| &subscription.id == id)
        .expect("apply_update requires an existing subscription");

    let previous_ids: BTreeSet<_> = subscription
        .nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect();
    let next_ids: BTreeSet<_> = parsed.nodes.iter().map(|node| node.id.as_str()).collect();

    let added = next_ids.difference(&previous_ids).count();
    let removed = previous_ids.difference(&next_ids).count();
    let retained = previous_ids.intersection(&next_ids).count();

    let selection_cleared = config.active.as_ref().is_some_and(|selection| {
        &selection.subscription == id && !next_ids.contains(selection.node.as_str())
    });

    let report = UpdateReport {
        added,
        removed,
        retained,
        selection_cleared,
        skipped: group_skipped(&parsed.skipped),
        notices: parsed.meta.notices.clone(),
    };

    subscription.nodes = parsed.nodes;
    subscription.info = parsed.meta.info;
    subscription.update_interval_hours = parsed.meta.update_interval_hours;
    subscription.support_url = parsed.meta.support_url;
    subscription.web_page_url = parsed.meta.web_page_url;
    subscription.announce = parsed.meta.announce;
    subscription.notices = parsed.meta.notices;
    subscription.updated_at_unix = Some(now_unix);

    if selection_cleared {
        config.active = None;
    }

    report
}
