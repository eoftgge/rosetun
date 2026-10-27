use super::*;

impl WorkerDispatcher {
    pub(crate) fn connect(&self, inputs: ExitInputs) {
        self.spawn_task("rosetun-connect", move |publisher| {
            tracing::info!("connect command started");
            let result = publisher
                .store
                .load()
                .map_err(HelperCommandError::Store)
                .and_then(|config| {
                    let request =
                        ConnectRequest::from_config_with_exits(&config, inputs.context())?;
                    let prepared = rosetun_core::prepare_lists(&publisher.store, request.clone())?;
                    let snapshot = AppliedSnapshot::from_config(&config);
                    with_helper(|client| {
                        rosetun_core::send_prepared(client, &prepared, ListOperation::Connect)
                    })?;
                    Ok((request, snapshot))
                });
            let result = match result {
                Ok((request, snapshot)) => {
                    tracing::info!("connect command succeeded");
                    emit(
                        &publisher.tx,
                        &publisher.repaint,
                        WorkerEvent::ConnectSnapshot(snapshot),
                    );
                    Ok(request)
                }
                Err(error) => {
                    tracing::warn!(%error, "connect command failed");
                    Err(error)
                }
            };
            publisher.complete(WorkerEvent::Connect(result));
        });
    }

    pub(crate) fn apply(&self, request: Box<ConnectRequest>) {
        self.spawn_task("rosetun-apply", move |publisher| {
            tracing::info!("apply command started");
            let result = rosetun_core::prepare_lists(&publisher.store, request.as_ref().clone())
                .map_err(HelperCommandError::from)
                .and_then(|prepared| {
                    with_helper(|client| {
                        rosetun_core::send_prepared(client, &prepared, ListOperation::Apply)
                    })
                })
                .map(|()| *request);
            match &result {
                Ok(_) => tracing::info!("apply command succeeded"),
                Err(error) => tracing::warn!(%error, "apply command failed"),
            }
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::Apply(result),
            );
        });
    }

    pub(crate) fn restore_applied(&self, snapshot: AppliedSnapshot) {
        self.spawn_complete("rosetun-restore-applied", move |store| {
            WorkerEvent::RestoreApplied(restore_rules_and_dns(store, &snapshot))
        });
    }

    pub(crate) fn restore_edits(&self, snapshot: AppliedSnapshot) {
        self.spawn_complete("rosetun-restore-edits", move |store| {
            WorkerEvent::RestoreEdits(restore_rules_and_dns(store, &snapshot))
        });
    }

    pub(crate) fn load_temporary_rules(&self, request: u64) {
        self.spawn_helper(
            "rosetun-load-temporary-rules",
            rosetun_ipc::HelperClient::temporary_rules,
            move |publisher, result| {
                emit(
                    &publisher.tx,
                    &publisher.repaint,
                    WorkerEvent::TemporaryRules { request, result },
                );
            },
        );
    }

    pub(crate) fn disconnect(&self) {
        self.spawn_task("rosetun-disconnect", move |publisher| {
            tracing::info!("disconnect command started");
            let result = with_helper(rosetun_ipc::HelperClient::disconnect_tunnel);
            match &result {
                Ok(()) => tracing::info!("disconnect command succeeded"),
                Err(error) => tracing::warn!(%error, "disconnect command failed"),
            }
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::Disconnect(result),
            );
        });
    }

    pub(crate) fn check_failure_interference(&self, request: u64, own_alias: String) {
        self.spawn_task("rosetun-check-failure-interference", move |publisher| {
            let adapters = rosetun_adapters::other_tunnels(&own_alias);
            let processes = running_processes();
            if adapters.is_err() || processes.is_err() {
                tracing::warn!("could not inspect possible connection conflicts");
            }
            let hints = FailureInterference {
                other_vpns: adapters.unwrap_or_default(),
                traffic_tools: processes.map(conflicting_processes).unwrap_or_default(),
            };
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::FailureInterference { request, hints },
            );
        });
    }

    pub(crate) fn set_kill_switch(&self, enabled: bool) {
        self.spawn_complete("rosetun-set-kill-switch", move |store| {
            WorkerEvent::SetKillSwitch(set_kill_switch(store, enabled))
        });
    }

    /// The saved "Local network" value is read here, not when the job was
    /// queued: a LAN change sends this right after it is written.
    ///
    /// Only an administrator changes Lockdown, so the GUI runs the CLI next
    /// to it elevated and passes the LAN value: the elevated process may run
    /// as another account with its own settings.
    pub(crate) fn set_lockdown(&self, enabled: bool) {
        self.spawn_task("rosetun-set-lockdown", move |publisher| {
            tracing::info!(enabled, "Lockdown command started");
            let result = publisher
                .store
                .load()
                .map_err(HelperCommandError::Store)
                .and_then(|config| run_lockdown_command(enabled, config.settings.allow_lan));
            match &result {
                Ok(LockdownChange::Done) => tracing::info!(enabled, "Lockdown command succeeded"),
                Ok(LockdownChange::Declined) => {
                    tracing::info!("Lockdown command cancelled at the administrator prompt");
                }
                Err(error) => tracing::warn!(%error, "Lockdown command failed"),
            }
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::SetLockdown { enabled, result },
            );
        });
    }

    pub(crate) fn tunnel_delay(&self) {
        self.spawn_helper(
            "rosetun-tunnel-delay",
            rosetun_ipc::HelperClient::tunnel_delay,
            |publisher, result| publisher.complete(WorkerEvent::TunnelDelay(result)),
        );
    }

    /// Asked once a second while the Traffic tab is open, so one pipe
    /// connection is kept for it instead of a new one (and a service log line)
    /// per request. It closes after [`CONNECTIONS_IDLE`] without requests.
    /// Emits without reloading the configuration.
    pub(crate) fn connections(&self) {
        let mut sender = self
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(requests) = sender.as_ref()
            && requests.send(()).is_ok()
        {
            return;
        }
        let (requests, received) = std::sync::mpsc::channel();
        let publisher = self.publisher.clone();
        let spawned = thread::Builder::new()
            .name("rosetun-connections".into())
            .spawn(move || serve_connections(&received, &publisher));
        if spawned.is_ok() && requests.send(()).is_ok() {
            *sender = Some(requests);
        }
    }

    pub(crate) fn close_connection(&self, id: String) {
        self.spawn_helper(
            "rosetun-close-connection",
            move |client| client.close_connection(&id),
            |publisher, result| {
                emit(
                    &publisher.tx,
                    &publisher.repaint,
                    WorkerEvent::CloseConnection(result),
                );
            },
        );
    }

    pub(crate) fn lookup_exit(&self, generation: u64, route: ExitRoute) {
        self.spawn_task("rosetun-lookup-exit", move |publisher| {
            let result = rosetun_core::exit_info(Duration::from_secs(5));
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::Exit {
                    generation,
                    route,
                    result,
                },
            );
        });
    }
}

/// `rosetun.exe lockdown …` from the GUI's folder, elevated through UAC.
fn run_lockdown_command(
    enabled: bool,
    allow_lan: bool,
) -> Result<LockdownChange, HelperCommandError> {
    let cli = std::env::current_exe()
        .map_err(HelperCommandError::LockdownLaunch)?
        .with_file_name(format!("rosetun{}", std::env::consts::EXE_SUFFIX));
    match rosetun_shell::run_elevated(&cli, &lockdown_arguments(enabled, allow_lan)) {
        Ok(None) => Ok(LockdownChange::Declined),
        Ok(Some(0)) => Ok(LockdownChange::Done),
        Ok(Some(code)) => Err(HelperCommandError::LockdownCommand(code)),
        Err(error) => Err(HelperCommandError::LockdownLaunch(error)),
    }
}

fn lockdown_arguments(enabled: bool, allow_lan: bool) -> String {
    if enabled {
        format!("lockdown on --lan {}", if allow_lan { "on" } else { "off" })
    } else {
        "lockdown off".to_owned()
    }
}

fn conflicting_processes(processes: Vec<RunningProcess>) -> Vec<String> {
    let mut names: Vec<_> = processes
        .into_iter()
        .filter(|process| {
            process.name.eq_ignore_ascii_case("winws.exe")
                || process.name.eq_ignore_ascii_case("goodbyedpi.exe")
        })
        .map(|process| process.name)
        .collect();
    names.sort_by_key(|name| name.to_ascii_lowercase());
    names.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    names
}

const CONNECTIONS_IDLE: Duration = Duration::from_secs(30);

fn serve_connections(requests: &std::sync::mpsc::Receiver<()>, publisher: &ConfigPublisher) {
    let mut client: Option<HelperClient> = None;
    loop {
        match requests.recv_timeout(CONNECTIONS_IDLE) {
            Ok(()) => {
                let result = match client.take() {
                    Some(client) => Ok(client),
                    None => HelperClient::connect(&rosetun_ipc::default_endpoint(), CLIENT_NAME),
                }
                .and_then(|mut connected| {
                    let list = connected.connections();
                    // A transport failure may leave the pipe out of step; the next request
                    // reconnects. A refusal from the service keeps it usable.
                    if matches!(list, Ok(_) | Err(ClientError::Helper(_))) {
                        client = Some(connected);
                    }
                    list
                })
                .map_err(HelperCommandError::from);
                let received_ms = crate::display::monotonic_ms();
                if !emit(
                    &publisher.tx,
                    &publisher.repaint,
                    WorkerEvent::Connections {
                        result,
                        received_ms,
                    },
                ) {
                    return;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => client = None,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

#[cfg(test)]
mod lockdown_command_tests {
    use super::lockdown_arguments;

    #[test]
    fn the_elevated_command_carries_the_lan_value_only_when_turning_on() {
        assert_eq!(lockdown_arguments(true, true), "lockdown on --lan on");
        assert_eq!(lockdown_arguments(true, false), "lockdown on --lan off");
        assert_eq!(lockdown_arguments(false, true), "lockdown off");
    }
}

#[cfg(test)]
mod failure_interference_tests {
    use super::{RunningProcess, conflicting_processes};

    #[test]
    fn identifies_traffic_tools_without_process_name_case_or_duplicates() {
        let processes = ["WINWS.EXE", "winws.exe", "GOODBYEDPI.exe", "example.exe"]
            .into_iter()
            .enumerate()
            .map(|(index, name)| RunningProcess {
                pid: index as u32 + 5,
                name: name.into(),
                path: None,
                has_window: false,
            })
            .collect();
        assert_eq!(
            conflicting_processes(processes),
            ["GOODBYEDPI.exe", "WINWS.EXE"]
        );
    }
}
