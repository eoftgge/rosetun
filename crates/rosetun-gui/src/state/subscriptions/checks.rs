use std::time::Duration;

use rosetun_config::{ConnectionState, NodeId, Subscription, SubscriptionId};
use rosetun_core::Ping;
use rosetun_ipc::{ClientError, ErrorCode, HelperError, ProbeOutcome, ProbeResult};

use super::super::{Job, State};
use crate::errors;
use crate::worker::{HelperCommandError, WorkerEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PingResult {
    Pending,
    /// TCP connect time.
    Answered(Duration),
    /// No TCP answer.
    NoAnswer,
    /// A request through the node answered.
    Works(Duration),
    /// A request through the node failed.
    Fails,
    Unresolved,
    Unsupported,
}

impl State {
    pub(crate) fn can_ping(&self) -> bool {
        !self.operations.helper
            && (!self.helper_available
                || matches!(
                    self.status.state,
                    ConnectionState::Disconnected | ConnectionState::Failed { .. }
                ))
    }

    pub(crate) fn can_full_check(&self) -> bool {
        self.helper_available && self.config_ready
    }

    pub(crate) fn best_ping(&self, subscription: &Subscription) -> Option<Duration> {
        subscription
            .nodes
            .iter()
            .filter_map(|node| {
                match self
                    .subscriptions
                    .pings
                    .get(&(subscription.id.clone(), node.id.clone()))
                {
                    Some(PingResult::Answered(elapsed) | PingResult::Works(elapsed)) => {
                        Some(*elapsed)
                    }
                    _ => None,
                }
            })
            .min()
    }

    pub(super) fn start_check(
        &mut self,
        id: SubscriptionId,
        node: Option<NodeId>,
        full: bool,
    ) -> Option<Job> {
        if !(if full {
            self.can_full_check()
        } else {
            self.can_ping()
        }) || self.operations.pinging.contains(&id)
            || self.subscription_busy(&id)
        {
            return None;
        }
        let subscription = self
            .config
            .subscriptions
            .iter()
            .find(|subscription| subscription.id == id && !subscription.nodes.is_empty())?;
        if node
            .as_ref()
            .is_some_and(|selected| subscription.node(selected).is_none())
        {
            return None;
        }
        for current in &subscription.nodes {
            if node.as_ref().is_none_or(|selected| selected == &current.id) {
                self.subscriptions
                    .pings
                    .insert((id.clone(), current.id.clone()), PingResult::Pending);
            }
        }
        self.operations.pinging.insert(id.clone());
        Some(match (full, node) {
            (false, None) => Job::Ping(id),
            (false, Some(node)) => Job::PingNode(id, node),
            (true, None) => Job::FullCheck(id),
            (true, Some(node)) => Job::FullCheckNode(id, node),
        })
    }

    pub(super) fn reduce_subscription_check(&mut self, event: WorkerEvent) {
        match event {
            WorkerEvent::Ping {
                subscription,
                node,
                result,
            } => {
                if self.operations.pinging.contains(&subscription)
                    && self
                        .config
                        .subscriptions
                        .iter()
                        .any(|sub| sub.id == subscription && sub.node(&node).is_some())
                {
                    let result = match result {
                        Ping::Answered(elapsed) => PingResult::Answered(elapsed),
                        Ping::NoAnswer => PingResult::NoAnswer,
                        Ping::Unsupported => PingResult::Unsupported,
                    };
                    self.subscriptions
                        .pings
                        .insert((subscription, node), result);
                }
            }
            WorkerEvent::PingDone(subscription) => {
                self.operations.pinging.remove(&subscription);
                for ((id, _), result) in &mut self.subscriptions.pings {
                    if id == &subscription && *result == PingResult::Pending {
                        *result = PingResult::NoAnswer;
                    }
                }
            }
            WorkerEvent::FullCheck {
                subscription,
                result,
            } => {
                if !self.operations.pinging.remove(&subscription) {
                    return;
                }
                self.subscriptions
                    .pings
                    .retain(|(id, _), ping| id != &subscription || *ping != PingResult::Pending);
                match result {
                    Ok(results) => {
                        for ProbeResult { node, outcome } in results {
                            if self
                                .config
                                .subscriptions
                                .iter()
                                .any(|sub| sub.id == subscription && sub.node(&node).is_some())
                            {
                                let ping = match outcome {
                                    ProbeOutcome::Works { millis } => {
                                        PingResult::Works(Duration::from_millis(u64::from(millis)))
                                    }
                                    ProbeOutcome::Fails => PingResult::Fails,
                                    ProbeOutcome::Unresolved => PingResult::Unresolved,
                                    ProbeOutcome::Unsupported => PingResult::Unsupported,
                                };
                                self.subscriptions
                                    .pings
                                    .insert((subscription.clone(), node), ping);
                            }
                        }
                    }
                    Err(error) => {
                        self.operation_error = Some(
                            if matches!(
                                &error,
                                HelperCommandError::Client(ClientError::Helper(HelperError {
                                    code: ErrorCode::Busy,
                                    ..
                                }))
                            ) {
                                tr!("full-check-busy").to_owned()
                            } else {
                                self.text(&errors::helper_command(crate::i18n::language(), &error))
                            },
                        );
                    }
                }
            }
            _ => unreachable!("only server checks are dispatched here"),
        }
    }
}
