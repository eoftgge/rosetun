use super::*;

impl WorkerDispatcher {
    pub(crate) fn connect(&self) {
        self.spawn_task("rosetun-connect", move |publisher| {
            tracing::info!("Connect command started");
            let result = publisher
                .store
                .load()
                .map_err(HelperCommandError::Store)
                .and_then(|config| {
                    let request = ConnectRequest::from_config(&config)?;
                    let snapshot = AppliedSnapshot::from_config(&config);
                    with_helper(|client| client.connect_tunnel(request.clone()))?;
                    Ok((request, snapshot))
                });
            let result = match result {
                Ok((request, snapshot)) => {
                    tracing::info!("Connect command succeeded");
                    emit(
                        &publisher.tx,
                        &publisher.repaint,
                        WorkerEvent::ConnectSnapshot(snapshot),
                    );
                    Ok(request)
                }
                Err(error) => {
                    tracing::warn!(%error, "Connect command failed");
                    Err(error)
                }
            };
            publisher.complete(WorkerEvent::Connect(result));
        });
    }

    pub(crate) fn apply(&self, request: Box<ConnectRequest>) {
        self.spawn_task("rosetun-apply", move |publisher| {
            tracing::info!("Apply command started");
            let result = with_helper(|client| client.apply_tunnel(request.as_ref().clone()))
                .map(|()| *request);
            match &result {
                Ok(_) => tracing::info!("Apply command succeeded"),
                Err(error) => tracing::warn!(%error, "Apply command failed"),
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
            |client| client.temporary_rules(),
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
            tracing::info!("Disconnect command started");
            let result = with_helper(|client| client.disconnect_tunnel());
            match &result {
                Ok(()) => tracing::info!("Disconnect command succeeded"),
                Err(error) => tracing::warn!(%error, "Disconnect command failed"),
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
                tracing::warn!("Could not inspect possible connection conflicts");
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

    pub(crate) fn tunnel_delay(&self) {
        self.spawn_helper(
            "rosetun-tunnel-delay",
            |client| client.tunnel_delay(),
            |publisher, result| publisher.complete(WorkerEvent::TunnelDelay(result)),
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
