use super::super::updates::{UPDATE_CHECK_INTERVAL, UPDATE_CHECK_RETRY};
use super::*;

#[test]
fn missing_last_check_starts_immediately_after_config_load_then_waits_a_day() {
    let mut state = State::default();
    assert!(state.take_update_check(1_000).is_none());
    state.config_ready = true;
    assert!(matches!(
        state.take_update_check(1_001),
        Some(Job::CheckUpdates)
    ));
    assert!(state.take_update_check(1_001).is_none());
    state.finish_update_check(Ok(None), 1_002);
    assert_eq!(state.config.interface.last_update_check, Some(1_002));
    assert!(!state.updates.update_check_failed);
    assert!(
        state
            .take_update_check(1_002 + UPDATE_CHECK_INTERVAL - 1)
            .is_none()
    );
    assert!(matches!(
        state.take_update_check(1_002 + UPDATE_CHECK_INTERVAL),
        Some(Job::CheckUpdates)
    ));
}

#[test]
fn recent_check_waits_for_the_remaining_hours_and_old_or_future_check_runs_now() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    let now = 200_000;
    state.config.interface.last_update_check = Some(now - 2 * 60 * 60);
    assert!(state.take_update_check(now).is_none());
    assert!(state.take_update_check(now + 22 * 60 * 60 - 1).is_none());
    assert!(matches!(
        state.take_update_check(now + 22 * 60 * 60),
        Some(Job::CheckUpdates)
    ));

    let mut old = State {
        config_ready: true,
        ..State::default()
    };
    old.config.interface.last_update_check = Some(now - 30 * 60 * 60);
    assert!(matches!(
        old.take_update_check(now),
        Some(Job::CheckUpdates)
    ));

    let mut future = State {
        config_ready: true,
        ..State::default()
    };
    future.config.interface.last_update_check = Some(now + 60);
    assert!(matches!(
        future.take_update_check(now),
        Some(Job::CheckUpdates)
    ));
}

#[test]
fn failed_release_check_preserves_timestamp_and_retries_in_six_hours() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    state.config.interface.last_update_check = Some(1_000);
    assert!(matches!(
        state.take_update_check(100_000),
        Some(Job::CheckUpdates)
    ));
    state.finish_update_check(Err(UpdateCheckError::Parse), 100_005);
    assert_eq!(state.config.interface.last_update_check, Some(1_000));
    assert!(state.updates.update_check_failed);
    assert!(
        state
            .take_update_check(100_005 + UPDATE_CHECK_RETRY - 1)
            .is_none()
    );
    assert!(matches!(
        state.take_update_check(100_005 + UPDATE_CHECK_RETRY),
        Some(Job::CheckUpdates)
    ));
    state.finish_update_check(Ok(None), 100_006 + UPDATE_CHECK_RETRY);
    assert!(!state.updates.update_check_failed);
    assert_eq!(
        state.config.interface.last_update_check,
        Some(100_006 + UPDATE_CHECK_RETRY)
    );
}

#[test]
fn release_check_waits_for_setting_and_safe_connection_state() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    state.config.interface.check_updates = false;
    assert!(state.take_update_check(1_000).is_none());
    state.config.interface.check_updates = true;
    state.helper_available = true;
    state.status.state = ConnectionState::Connecting;
    assert!(state.take_update_check(1_060).is_none());
    state.status.state = ConnectionState::Reconnecting;
    assert!(state.take_update_check(1_120).is_none());
    state.status.state = ConnectionState::FailedProtected {
        failure_kind: None,
        reason: "failure".into(),
    };
    assert!(state.take_update_check(1_180).is_none());
    state.status.state = ConnectionState::Connected;
    assert!(state.take_update_check(1_239).is_none());
    assert!(matches!(
        state.take_update_check(1_240),
        Some(Job::CheckUpdates)
    ));
}

#[test]
fn skipped_release_stays_known_and_a_newer_release_is_shown() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    let release = |version: &str| Release {
        version: version.into(),
        url: "https://example.com/release".into(),
        prerelease: true,
    };
    state.config.interface.skipped_version = Some("999.0.0-alpha.3".into());
    state.take_update_check(1_000);
    state.finish_update_check(Ok(Some(release("999.0.0-alpha.3"))), 1_001);
    assert!(state.available_update().is_none());
    assert_eq!(
        state.updates.newest_release.as_ref().unwrap().version,
        "999.0.0-alpha.3"
    );

    state.take_update_check(1_001 + UPDATE_CHECK_INTERVAL);
    state.finish_update_check(
        Ok(Some(release("999.0.0-alpha.4"))),
        1_002 + UPDATE_CHECK_INTERVAL,
    );
    assert_eq!(state.available_update().unwrap().version, "999.0.0-alpha.4");
    state.config.interface.skipped_version = Some("999.0.0-alpha.4".into());
    let config = state.config.clone();
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config,
    });
    assert!(state.available_update().is_none());
    assert_eq!(
        state.updates.newest_release.as_ref().unwrap().version,
        "999.0.0-alpha.4"
    );
    state.config.interface.check_updates = false;
    state.config.interface.skipped_version = None;
    assert!(state.available_update().is_some());
}

#[test]
fn manual_update_check_works_when_automatic_checks_are_off() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    state.config.interface.check_updates = false;
    assert!(state.take_update_check(100_000).is_none());
    assert!(matches!(
        state.act(Action::CheckUpdatesNow),
        Some(Job::CheckUpdates)
    ));
    assert!(state.act(Action::CheckUpdatesNow).is_none());
    state.reduce(WorkerEvent::UpdateCheck {
        checked_at: 100_001,
        result: Err(UpdateCheckError::Parse),
    });
    assert!(state.updates.update_check_failed);
    assert!(state.config.interface.last_update_check.is_none());
    assert!(matches!(
        state.act(Action::CheckUpdatesNow),
        Some(Job::CheckUpdates)
    ));
    state.reduce(WorkerEvent::UpdateCheck {
        checked_at: 100_002,
        result: Ok(None),
    });
    assert!(!state.updates.update_check_failed);
    assert_eq!(state.config.interface.last_update_check, Some(100_002));
}

#[test]
fn manual_update_check_is_blocked_in_transitional_states() {
    let mut state = State {
        config_ready: true,
        helper_available: true,
        ..State::default()
    };
    for status in [
        ConnectionState::Connecting,
        ConnectionState::Reconnecting,
        ConnectionState::FailedProtected {
            failure_kind: None,
            reason: "failure".into(),
        },
    ] {
        state.status.state = status;
        assert!(!state.can_check_updates());
        assert!(state.act(Action::CheckUpdatesNow).is_none());
    }
    state.status.state = ConnectionState::Connected;
    assert!(state.can_check_updates());
}

fn restarted_with(config: &rosetun_config::AppConfig) -> State {
    let mut state = State::default();
    state.reduce(WorkerEvent::Config {
        generation: 1,
        config: config.clone(),
    });
    state
}

fn found(version: &str) -> Release {
    Release {
        version: version.into(),
        url: format!("https://github.com/eoftgge/rosetun/releases/tag/v{version}"),
        prerelease: false,
    }
}

#[test]
fn a_found_release_survives_a_restart_without_the_network() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    state.take_update_check(1_000);
    state.finish_update_check(Ok(Some(found("999.0.0"))), 1_001);
    assert_eq!(
        state.config.interface.newest_release.as_deref(),
        Some("999.0.0")
    );

    let mut restarted = restarted_with(&state.config);
    assert_eq!(restarted.available_update(), Some(&found("999.0.0")));
    assert!(restarted.take_update_check(1_002).is_none());
}

#[test]
fn a_remembered_release_not_newer_than_this_build_is_not_offered() {
    let mut config = rosetun_config::AppConfig::default();
    config.interface.newest_release = Some("0.0.1".into());
    let restarted = restarted_with(&config);
    assert!(restarted.updates.newest_release.is_none());
    assert!(restarted.available_update().is_none());
}

#[test]
fn a_successful_check_without_a_newer_release_clears_the_record() {
    let mut config = rosetun_config::AppConfig::default();
    config.interface.newest_release = Some("999.0.0".into());
    let mut state = restarted_with(&config);
    assert!(state.available_update().is_some());

    assert!(matches!(
        state.act(Action::CheckUpdatesNow),
        Some(Job::CheckUpdates)
    ));
    state.finish_update_check(Ok(None), 1_000);
    assert!(state.available_update().is_none());
    assert_eq!(state.config.interface.newest_release, None);
}

#[test]
fn a_skipped_remembered_release_is_not_offered() {
    let mut config = rosetun_config::AppConfig::default();
    config.interface.newest_release = Some("999.0.0".into());
    config.interface.skipped_version = Some("999.0.0".into());
    let restarted = restarted_with(&config);
    assert!(restarted.updates.newest_release.is_some());
    assert!(restarted.available_update().is_none());
}

#[test]
fn an_announced_update_is_saved_once() {
    let mut state = State {
        config_ready: true,
        ..State::default()
    };
    assert!(matches!(
        state.act(Action::AnnounceUpdate("999.0.0".into())),
        Some(Job::AnnounceUpdate(version)) if version == "999.0.0"
    ));
    assert_eq!(
        state.config.interface.announced_update.as_deref(),
        Some("999.0.0")
    );
    state.reduce(WorkerEvent::AnnounceUpdate);
    assert!(state.operations.settings.is_none());
    assert!(
        state
            .act(Action::AnnounceUpdate("999.0.0".into()))
            .is_none()
    );
}

fn offering(version: &str) -> State {
    State {
        config_ready: true,
        updates: UpdatesState {
            newest_release: Some(rosetun_core::Release {
                version: version.into(),
                url: "https://example.com/release".into(),
                prerelease: false,
            }),
            ..UpdatesState::default()
        },
        ..State::default()
    }
}

fn downloaded(state: &mut State, version: &str) {
    state.reduce(WorkerEvent::UpdateDownloaded {
        version: version.into(),
        result: Ok(rosetun_core::DownloadedUpdate::for_tests(
            version,
            std::path::PathBuf::from("rosetun-setup.exe"),
        )),
    });
}

#[test]
fn only_windows_downloads_the_installer_and_only_once_at_a_time() {
    let mut state = offering("999.0.0");
    let job = state.act(Action::DownloadUpdate);
    if !State::can_install_updates() {
        assert!(job.is_none());
        assert_eq!(state.offer_download(), &UpdateDownload::Idle);
        return;
    }
    let Some(Job::DownloadUpdate {
        version, via_vpn, ..
    }) = job
    else {
        panic!("a download job expected");
    };
    assert_eq!(version, "999.0.0");
    assert_eq!(via_vpn, state.config.interface.subscriptions_via_vpn);
    assert!(state.act(Action::DownloadUpdate).is_none());
    state.reduce(WorkerEvent::UpdateProgress {
        version: "999.0.0".into(),
        received: 50,
        total: Some(100),
    });
    assert_eq!(
        state.offer_download(),
        &UpdateDownload::Downloading {
            version: "999.0.0".into(),
            received: 50,
            total: Some(100),
        }
    );
    downloaded(&mut state, "999.0.0");
    assert!(matches!(state.offer_download(), UpdateDownload::Ready(_)));
}

#[test]
fn cancel_stops_the_thread_and_a_cancelled_download_returns_to_the_offer() {
    if !State::can_install_updates() {
        return;
    }
    let mut state = offering("999.0.0");
    let Some(Job::DownloadUpdate { cancel, .. }) = state.act(Action::DownloadUpdate) else {
        panic!("a download job expected");
    };
    state.act(Action::CancelUpdateDownload);
    assert!(cancel.load(std::sync::atomic::Ordering::Relaxed));
    state.reduce(WorkerEvent::UpdateDownloaded {
        version: "999.0.0".into(),
        result: Err(rosetun_core::UpdateDownloadError::Cancelled),
    });
    assert_eq!(state.offer_download(), &UpdateDownload::Idle);
    let Some(Job::DownloadUpdate { cancel, .. }) = state.act(Action::DownloadUpdate) else {
        panic!("a new download job expected");
    };
    assert!(!cancel.load(std::sync::atomic::Ordering::Relaxed));
}

#[test]
fn a_failed_check_is_shown_and_a_late_result_for_another_version_is_ignored() {
    if !State::can_install_updates() {
        return;
    }
    let mut state = offering("999.0.0");
    state.act(Action::DownloadUpdate);
    state.reduce(WorkerEvent::UpdateDownloaded {
        version: "998.0.0".into(),
        result: Err(rosetun_core::UpdateDownloadError::Mismatch),
    });
    assert!(matches!(
        state.offer_download(),
        UpdateDownload::Downloading { .. }
    ));
    state.reduce(WorkerEvent::UpdateDownloaded {
        version: "999.0.0".into(),
        result: Err(rosetun_core::UpdateDownloadError::BadSignature),
    });
    assert_eq!(
        state.offer_download(),
        &UpdateDownload::Failed {
            version: "999.0.0".into(),
            failure: UpdateFailure::Download(rosetun_core::UpdateDownloadError::BadSignature),
        }
    );
    assert!(matches!(
        state.act(Action::DownloadUpdate),
        Some(Job::DownloadUpdate { .. })
    ));
}

#[test]
fn a_newer_offer_hides_the_download_of_an_older_one() {
    if !State::can_install_updates() {
        return;
    }
    let mut state = offering("999.0.0");
    state.act(Action::DownloadUpdate);
    downloaded(&mut state, "999.0.0");
    state.updates.newest_release = Some(rosetun_core::Release {
        version: "999.1.0".into(),
        url: "https://example.com/release".into(),
        prerelease: false,
    });
    assert_eq!(state.offer_download(), &UpdateDownload::Idle);
    assert!(state.act(Action::InstallUpdate).is_none());
}

#[test]
fn installing_asks_first_during_a_session_and_a_declined_prompt_keeps_the_file() {
    if !State::can_install_updates() {
        return;
    }
    let mut state = offering("999.0.0");
    state.act(Action::DownloadUpdate);
    downloaded(&mut state, "999.0.0");
    state.helper_available = true;
    state.status.state = ConnectionState::Connected;
    assert!(state.act(Action::InstallUpdate).is_none());
    assert!(state.updates.confirm_install);
    assert!(state.act(Action::ConfirmInstallUpdate(false)).is_none());
    assert!(!state.updates.confirm_install);
    assert!(matches!(state.offer_download(), UpdateDownload::Ready(_)));

    state.act(Action::InstallUpdate);
    assert!(matches!(
        state.act(Action::ConfirmInstallUpdate(true)),
        Some(Job::InstallUpdate(update)) if update.version == "999.0.0"
    ));
    assert!(matches!(
        state.offer_download(),
        UpdateDownload::Installing(_)
    ));
    state.reduce(WorkerEvent::UpdateInstall(Some(UpdateFailure::Declined)));
    assert!(matches!(state.offer_download(), UpdateDownload::Ready(_)));

    state.status.state = ConnectionState::Disconnected;
    assert!(matches!(
        state.act(Action::InstallUpdate),
        Some(Job::InstallUpdate(_))
    ));
    state.reduce(WorkerEvent::UpdateInstall(Some(UpdateFailure::Installer(
        5,
    ))));
    assert_eq!(
        state.offer_download(),
        &UpdateDownload::Failed {
            version: "999.0.0".into(),
            failure: UpdateFailure::Installer(5),
        }
    );
}
