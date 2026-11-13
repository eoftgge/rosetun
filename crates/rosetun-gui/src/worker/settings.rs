use super::*;

impl WorkerDispatcher {
    pub(crate) fn set_interface_scale(&self, percent: u16) {
        self.spawn_complete("rosetun-set-interface-scale", move |store| {
            WorkerEvent::SetInterfaceScale(set_interface_scale(store, percent))
        });
    }

    pub(crate) fn set_language(&self, language: LanguageSetting) {
        self.spawn_complete("rosetun-set-language", move |store| {
            WorkerEvent::SetLanguage(set_language(store, language))
        });
    }

    pub(crate) fn set_accent(&self, accent: AccentPreset) {
        self.spawn_complete("rosetun-set-accent", move |store| {
            WorkerEvent::SetAccent(set_accent(store, accent))
        });
    }

    pub(crate) fn change_setting(&self, change: SettingChange) {
        self.spawn_complete("rosetun-change-setting", move |store| {
            WorkerEvent::Setting(change, rosetun_core::change_setting(store, change))
        });
    }

    #[cfg(any(windows, target_os = "linux"))]
    pub(crate) fn load_autostart(&self) {
        self.spawn_task("rosetun-load-autostart", move |publisher| {
            let result = std::env::current_exe()
                .and_then(|exe| rosetun_shell::autostart_enabled(&exe))
                .inspect_err(|error| {
                    tracing::warn!(code = error.raw_os_error(), "could not read autostart");
                });
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::AutostartLoaded(result),
            );
        });
    }

    #[cfg(any(windows, target_os = "linux"))]
    pub(crate) fn set_autostart(&self, enabled: bool) {
        self.spawn_task("rosetun-set-autostart", move |publisher| {
            let result = (|| {
                let exe = std::env::current_exe()?;
                if enabled {
                    let description = tr!("autostart-task-description");
                    rosetun_shell::enable_autostart(&autostart(&exe, &description))?;
                } else {
                    rosetun_shell::disable_autostart()?;
                }
                rosetun_shell::autostart_enabled(&exe)
            })()
            .inspect_err(|error| {
                tracing::warn!(
                    code = error.raw_os_error(),
                    enabled,
                    "could not change autostart"
                );
            });
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::SetAutostart(result),
            );
        });
    }

    /// Moves autostart of an earlier version from the Run value to the
    /// sign-in task, without telling the user. Runs at every start until it
    /// succeeds; nothing is left to move after that.
    #[cfg(windows)]
    pub(crate) fn move_autostart_to_task(&self) {
        self.spawn_task("rosetun-move-autostart", move |_| {
            let description = tr!("autostart-task-description");
            let result = std::env::current_exe().and_then(|exe| {
                rosetun_shell::move_autostart_to_task(&autostart(&exe, &description))
            });
            match result {
                Ok(true) => tracing::info!("autostart moved to the sign-in task"),
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(code = error.raw_os_error(), "could not move autostart");
                }
            }
        });
    }

    pub(crate) fn skip_version(&self, version: String) {
        self.spawn_complete("rosetun-skip-version", move |store| {
            WorkerEvent::SkipVersion(rosetun_core::skip_version(store, Some(version)))
        });
    }

    #[cfg(any(windows, target_os = "linux", test))]
    pub(crate) fn announce_update(&self, version: String) {
        self.spawn_complete("rosetun-announce-update", move |store| {
            if rosetun_core::record_update_announced(store, version).is_err() {
                tracing::warn!("could not save the announced update");
            }
            WorkerEvent::AnnounceUpdate
        });
    }

    pub(crate) fn set_dns(&self, dns: DnsSettings) {
        self.spawn_complete("rosetun-set-dns", move |store| {
            WorkerEvent::SetDns(set_dns(store, dns))
        });
    }

    pub(crate) fn reset_settings(&self) {
        self.spawn_complete("rosetun-reset-settings", move |store| {
            WorkerEvent::ResetSettings(reset_settings(store))
        });
    }

    pub(crate) fn set_verbose_log(&self, on: bool) {
        self.spawn_task("rosetun-set-verbose-log", move |publisher| {
            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_secs())
                .unwrap_or_default();
            let result = set_verbose_log(&publisher.store, on, now_unix);
            publisher.complete(WorkerEvent::SetVerboseLog(result));
        });
    }

    #[cfg(any(windows, target_os = "linux"))]
    pub(crate) fn open_folder(&self, folder: PathBuf) {
        self.spawn_task("rosetun-open-folder", move |publisher| {
            #[cfg(windows)]
            let result = Command::new("explorer.exe").arg(folder).spawn().map(|_| ());
            #[cfg(target_os = "linux")]
            let result = rosetun_shell::open_folder(&folder);
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::OpenFolder(result),
            );
        });
    }
}

#[cfg(any(windows, target_os = "linux"))]
fn autostart<'a>(exe: &'a Path, description: &'a str) -> rosetun_shell::Autostart<'a> {
    rosetun_shell::Autostart {
        exe,
        argument: crate::HIDDEN_ARG,
        description,
    }
}
