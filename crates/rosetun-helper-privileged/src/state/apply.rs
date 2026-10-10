use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::time::Instant;

use rosetun_config::{ConnectionState, Settings};
use rosetun_ipc::{ConnectRequest, ErrorCode, HelperError};

use super::{
    Helper, RECONNECT_BACKOFF, Reconnect, StartMode, node_with_endpoint, normalize_server,
    probe::resolve_for_apply, render_config, validate_request,
};

impl Helper {
    pub fn apply(&self, request: &ConnectRequest) -> Result<(), HelperError> {
        let mut session = self.session()?;
        validate_request(request)?;
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
        if needs_reconnect(&current.settings, &request.settings) {
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

        let endpoint = request
            .node
            .server
            .parse::<IpAddr>()
            .ok()
            .or_else(|| {
                session
                    .last_endpoint
                    .as_ref()
                    .filter(|cached| cached.server == normalize_server(&request.node.server))
                    .map(|cached| cached.address)
            })
            .or_else(|| resolve_for_apply(&request.node))
            .ok_or_else(|| {
                HelperError::new(
                    ErrorCode::RoutingFailed,
                    "cannot resolve the new server through the tunnel",
                )
            })?;

        let backend = self.engines.get(request.settings.engine).ok_or_else(|| {
            HelperError::new(
                ErrorCode::EngineFailed,
                format!(
                    "engine {} is not registered",
                    request.settings.engine.as_str()
                ),
            )
        })?;
        render_config(
            backend,
            &node_with_endpoint(&request.node, endpoint),
            &request.effective_rule_set(),
            &request.lists,
            &request.settings,
            None,
            false,
        )?;

        let previous_endpoint = current
            .node
            .server
            .parse::<IpAddr>()
            .ok()
            .or_else(|| {
                session
                    .last_endpoint
                    .as_ref()
                    .filter(|cached| cached.server == normalize_server(&current.node.server))
                    .map(|cached| cached.address)
            })
            .ok_or_else(|| {
                HelperError::new(
                    ErrorCode::RoutingFailed,
                    "previous server address is unavailable",
                )
            })?;
        session.reserve_lists(request, Some(&current))?;
        tracing::info!(
            server = current.node != request.node || current.selection != request.selection,
            rules = current.rule_set != request.rule_set,
            temporary = current.temporary_rules != request.temporary_rules,
            temporary_rules = request.temporary_rules.len(),
            dns = current.settings.dns != request.settings.dns,
            "applying session changes"
        );
        self.begin_attempt(ConnectionState::Reconnecting);
        let mode = if session.guard.is_some() {
            StartMode::ProtectedReconnect
        } else {
            StartMode::Fresh
        };
        match session
            .start(
                &request.node,
                &request.effective_rule_set(),
                &request.lists,
                &request.settings,
                mode,
                Some(endpoint),
            )
            .and_then(|()| {
                self.publish_terminal(|status| {
                    status.state = ConnectionState::Connected;
                    status.node = Some(request.node.id.clone());
                })
            }) {
            Ok(()) => {
                session.request = Some(request.clone());
                session.pin_lists(&request.lists);
                self.resumed.store(false, Ordering::Release);
                session.start_monitor(request.settings.engine);
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
                let rollback = session
                    .start(
                        &current.node,
                        &current.effective_rule_set(),
                        &current.lists,
                        &current.settings,
                        mode,
                        Some(previous_endpoint),
                    )
                    .and_then(|()| {
                        self.publish_terminal(|status| {
                            status.state = ConnectionState::Connected;
                            status.node = Some(current.node.id.clone());
                        })
                    });
                match rollback {
                    Ok(()) => {
                        session.pin_lists(&current.lists);
                        self.resumed.store(false, Ordering::Release);
                        session.start_monitor(current.settings.engine);
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
                        self.with_status(|status| {
                            status.connect_stage = None;
                            status.stage_since_unix = None;
                        });
                        tracing::warn!(code = ?rollback_error.code, "session changes rollback failed");
                        if current.settings.auto_reconnect {
                            if let Err(cleanup_error) = session.stop_engine() {
                                tracing::error!(code = ?cleanup_error.code, "failed to stop engine after apply failure");
                            }
                            session.reconnect = Some(Reconnect {
                                failures: 1,
                                next_at: Instant::now() + RECONNECT_BACKOFF[0],
                                cause: "apply failed",
                            });
                        } else {
                            let protected = session.keeps_protection();
                            if protected {
                                if let Err(cleanup_error) = session.stop_engine() {
                                    tracing::error!(code = ?cleanup_error.code, "failed to stop engine after protected apply failure");
                                }
                            } else {
                                session.teardown();
                            }
                            session.request = None;
                            session.pin_lists(&[]);
                            self.with_status(|status| {
                                status.state = if protected {
                                    ConnectionState::FailedProtected {
                                        failure_kind: super::failure_kind(rollback_error.code),
                                        reason: rollback_error.message,
                                    }
                                } else {
                                    ConnectionState::Failed {
                                        failure_kind: super::failure_kind(rollback_error.code),
                                        reason: rollback_error.message,
                                    }
                                };
                                status.since_unix = None;
                            });
                        }
                        Err(error)
                    }
                }
            }
        }
    }
}

pub(super) fn needs_reconnect(current: &Settings, next: &Settings) -> bool {
    current.engine != next.engine
        || current.tun != next.tun
        || current.kill_switch != next.kill_switch
        || current.allow_lan != next.allow_lan
}
