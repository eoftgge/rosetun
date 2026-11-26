use std::sync::atomic::Ordering;
use std::time::Instant;

use rosetun_config::{ConnectionMode, ConnectionState};
use rosetun_ipc::{ConnectRequest, ErrorCode, HelperError};

use super::{
    Caller, Helper, NameLookup, RECONNECT_BACKOFF, Reconnect, Session, SessionHolder, StartMode,
    exits, probe::resolve_node_for_apply, protected_endpoints, validate_request,
};

impl Helper {
    pub(crate) fn apply_as(
        &self,
        caller: &Caller,
        request: &ConnectRequest,
    ) -> Result<(), HelperError> {
        self.check_owner(caller)?;
        let mut session = self.session_for(SessionHolder::Apply)?;
        self.check_owner(caller)?;
        validate_request(request)?;
        self.require_protection(request)?;
        self.require_engine_rights(request)?;
        if !matches!(
            self.with_status(|status| status.state.clone()),
            ConnectionState::Connected
        ) {
            return Err(HelperError::new(
                ErrorCode::InvalidState,
                "the tunnel is not connected",
            ));
        }
        let current = session.request.clone().ok_or_else(|| {
            HelperError::new(ErrorCode::InvalidState, "the tunnel is not connected")
        })?;
        if current == *request {
            return Ok(());
        }
        if needs_reconnect(&current, request) {
            return Err(HelperError::new(
                ErrorCode::InvalidState,
                "reconnect to change protection settings",
            ));
        }

        let mut metadata_only = current.clone();
        metadata_only.settings.auto_reconnect = request.settings.auto_reconnect;
        metadata_only.settings.autostart = request.settings.autostart;
        if metadata_only == *request {
            session.request = Some(request.clone());
            return Ok(());
        }

        let endpoint = resolve_node_for_apply(
            &request.node,
            session.last_endpoint.as_ref(),
            session.engine_lookup(),
        )
        .ok_or_else(|| {
            HelperError::new(
                ErrorCode::RoutingFailed,
                "cannot resolve the new server through the tunnel",
            )
        })?;

        let extra_endpoints = exits::apply_endpoints(
            &request.extra_nodes,
            &session.last_extra_endpoints,
            session.engine_lookup(),
        );
        if (current.settings.connection_mode == ConnectionMode::SystemProxy
            && request.settings.connection_mode == ConnectionMode::SystemProxy
            && current.settings.local_proxy == request.settings.local_proxy)
            || (super::native_tun_requested(&current) && super::native_tun_requested(request))
        {
            session.reserve_lists(request, Some(&current))?;
            let previous_exit_tags = session.exit_tags.clone();
            if let Err(error) = session.apply_proxy(&current, request, endpoint, &extra_endpoints) {
                if error.code == ErrorCode::Cancelled {
                    self.finish_cancelled(&mut session);
                } else {
                    session.pin_lists(&current.lists);
                }
                return Err(error);
            }
            session.request = Some(request.clone());
            session.pin_lists(&request.lists);
            let published = self.publish_terminal(|status| {
                status.state = ConnectionState::Connected;
                status.node = Some(request.node.id.clone());
                session.record_chain(status, request);
            });
            if published.is_err() {
                self.finish_cancelled(&mut session);
            } else if previous_exit_tags != session.exit_tags {
                if let Some(monitor) = session.monitor.take() {
                    monitor.stop();
                }
                session.start_monitor();
            }
            return published;
        }

        let previous_endpoint = protected_endpoints(&current.node, session.last_endpoint.as_ref())
            .map_err(|_| {
                HelperError::new(
                    ErrorCode::RoutingFailed,
                    "previous server address is unavailable",
                )
            })?;
        let previous_extra_endpoints = exits::start_endpoints(
            &current.extra_nodes,
            StartMode::ProtectedReconnect,
            &session.last_extra_endpoints,
            // Never used: a protected reconnect does not resolve.
            NameLookup::System,
        );
        session.reserve_lists(request, Some(&current))?;
        tracing::info!(
            server = current.node != request.node || current.selection != request.selection,
            rules =
                current.rule_set != request.rule_set || current.extra_nodes != request.extra_nodes,
            temporary = current.temporary_rules != request.temporary_rules,
            temporary_rules = request.temporary_rules.len(),
            extra_nodes = request.extra_nodes.len(),
            dns = current.settings.dns != request.settings.dns,
            "applying session changes"
        );
        self.begin_attempt(ConnectionState::Reconnecting);
        let mode = session.protection.restart_mode();
        // The proxy mode without a kill switch drops the DNS lock; the
        // previous session has to bring it back, so its start cannot rely on it.
        match session
            .start(request, mode, Some(endpoint), Some(extra_endpoints))
            .and_then(|()| {
                self.publish_terminal(|status| {
                    status.state = ConnectionState::Connected;
                    status.node = Some(request.node.id.clone());
                    session.record_chain(status, request);
                })
            }) {
            Ok(()) => {
                session.request = Some(request.clone());
                session.pin_lists(&request.lists);
                self.resumed.store(false, Ordering::Release);
                session.start_monitor();
                session.start_watchdog();
                tracing::info!("session changes applied");
                Ok(())
            }
            Err(error) => {
                if error.code == ErrorCode::Cancelled {
                    self.finish_cancelled(&mut session);
                    return Err(error);
                }
                tracing::warn!(code = ?error.code, "session changes failed; restoring previous session");
                let mode = session.protection.restart_mode();
                let rollback = session
                    .start(
                        &current,
                        mode,
                        Some(previous_endpoint),
                        Some(previous_extra_endpoints),
                    )
                    .and_then(|()| {
                        self.publish_terminal(|status| {
                            status.state = ConnectionState::Connected;
                            status.node = Some(current.node.id.clone());
                            session.record_chain(status, &current);
                        })
                    });
                match rollback {
                    Ok(()) => {
                        session.pin_lists(&current.lists);
                        self.resumed.store(false, Ordering::Release);
                        session.start_monitor();
                        session.start_watchdog();
                        Err(HelperError::new(
                            error.code,
                            format!("changes were not applied: {}", error.message),
                        ))
                    }
                    Err(rollback_error) => {
                        session.pin_lists(&current.lists);
                        if rollback_error.code == ErrorCode::Cancelled {
                            self.finish_cancelled(&mut session);
                            return Err(rollback_error);
                        }
                        tracing::warn!(code = ?rollback_error.code, "session changes rollback failed");
                        self.restart_failed(
                            &mut session,
                            current.settings.auto_reconnect,
                            "apply failed",
                            rollback_error,
                        );
                        Err(error)
                    }
                }
            }
        }
    }

    /// Restarts the running session as it is: same server, rules and settings. Same path as the
    /// automatic reconnect, so the guard stays up between the old engine and the new one.
    pub(crate) fn reconnect_as(&self, caller: &Caller) -> Result<(), HelperError> {
        self.check_owner(caller)?;
        let mut session = self.session_for(SessionHolder::Reconnect)?;
        self.check_owner(caller)?;
        if !matches!(
            self.with_status(|status| status.state.clone()),
            ConnectionState::Connected
        ) {
            return Err(HelperError::new(
                ErrorCode::InvalidState,
                "the tunnel is not connected",
            ));
        }
        let request = session.request.clone().ok_or_else(|| {
            HelperError::new(ErrorCode::InvalidState, "the tunnel is not connected")
        })?;
        let mode = session.protection.restart_mode();
        tracing::info!(?mode, "reconnecting at the client's request");
        self.begin_attempt(ConnectionState::Reconnecting);
        match session.start(&request, mode, None, None).and_then(|()| {
            self.publish_terminal(|status| {
                status.state = ConnectionState::Connected;
                session.record_chain(status, &request);
            })
        }) {
            Ok(()) => {
                self.resumed.store(false, Ordering::Release);
                session.start_monitor();
                session.start_watchdog();
                tracing::info!("tunnel reconnected at the client's request");
                Ok(())
            }
            Err(error) => {
                if error.code == ErrorCode::Cancelled {
                    self.finish_cancelled(&mut session);
                    return Err(error);
                }
                tracing::warn!(code = ?error.code, "reconnect at the client's request failed");
                self.restart_failed(
                    &mut session,
                    request.settings.auto_reconnect,
                    "reconnect failed",
                    error.clone(),
                );
                Err(error)
            }
        }
    }

    /// The engine did not come back: retry later if the session asks for that, otherwise end it.
    /// Protection that must outlive the session stays either way.
    fn restart_failed(
        &self,
        session: &mut Session,
        auto_reconnect: bool,
        cause: &'static str,
        error: HelperError,
    ) {
        self.with_status(|status| {
            status.connect_stage = None;
            status.stage_since_unix = None;
        });
        if auto_reconnect {
            if let Err(cleanup_error) = session.stop_engine() {
                tracing::error!(code = ?cleanup_error.code, cause, "failed to stop engine after a failed restart");
            }
            session.reconnect = Some(Reconnect {
                failures: 1,
                next_at: Instant::now() + RECONNECT_BACKOFF[0],
                cause,
            });
            return;
        }
        let protected = session.protection.keeps_protection();
        if protected {
            if let Err(cleanup_error) = session.stop_engine() {
                tracing::error!(code = ?cleanup_error.code, cause, "failed to stop engine after a failed protected restart");
            }
        } else {
            session.teardown();
        }
        session.request = None;
        session.pin_lists(&[]);
        self.with_status(|status| {
            status.state = if protected {
                ConnectionState::FailedProtected {
                    failure_kind: super::failure_kind(&error),
                    reason: error.message,
                }
            } else {
                ConnectionState::Failed {
                    failure_kind: super::failure_kind(&error),
                    reason: error.message,
                }
            };
            status.since_unix = None;
        });
    }

    #[cfg(test)]
    pub fn apply(&self, request: &ConnectRequest) -> Result<(), HelperError> {
        self.apply_as(&super::test_caller(), request)
    }

    #[cfg(test)]
    pub fn reconnect(&self) -> Result<(), HelperError> {
        self.reconnect_as(&super::test_caller())
    }
}

pub(super) fn needs_reconnect(current: &ConnectRequest, next: &ConnectRequest) -> bool {
    current.settings.engine != next.settings.engine
        || current.settings.tun != next.settings.tun
        || current.settings.kill_switch != next.settings.kill_switch
        || current.settings.allow_lan != next.settings.allow_lan
}
