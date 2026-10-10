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

    pub(crate) fn set_reduce_motion(&self, enabled: bool) {
        self.spawn_complete("rosetun-set-reduce-motion", move |store| {
            WorkerEvent::SetReduceMotion(rosetun_core::set_reduce_motion(store, enabled))
        });
    }

    #[cfg(windows)]
    pub(crate) fn load_autostart(&self) {
        self.spawn_task("rosetun-load-autostart", move |publisher| {
            let result = rosetun_shell::autostart_enabled();
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::AutostartLoaded(result),
            );
        });
    }

    #[cfg(windows)]
    pub(crate) fn set_autostart(&self, enabled: bool) {
        self.spawn_task("rosetun-set-autostart", move |publisher| {
            let result = (|| {
                if enabled {
                    let exe = std::env::current_exe()?;
                    rosetun_shell::enable_autostart(&exe, crate::HIDDEN_ARG)?;
                } else {
                    rosetun_shell::disable_autostart()?;
                }
                rosetun_shell::autostart_enabled()
            })();
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::SetAutostart(result),
            );
        });
    }

    #[cfg(windows)]
    pub(crate) fn set_close_to_tray(&self, enabled: bool) {
        self.spawn_complete("rosetun-set-close-to-tray", move |store| {
            WorkerEvent::SetCloseToTray(rosetun_core::set_close_to_tray(store, enabled))
        });
    }

    pub(crate) fn set_connect_on_start(&self, enabled: bool) {
        self.spawn_complete("rosetun-set-connect-on-start", move |store| {
            WorkerEvent::SetConnectOnStart(rosetun_core::set_connect_on_start(store, enabled))
        });
    }

    pub(crate) fn set_auto_reconnect(&self, enabled: bool) {
        self.spawn_complete("rosetun-set-auto-reconnect", move |store| {
            WorkerEvent::SetAutoReconnect(rosetun_core::set_auto_reconnect(store, enabled))
        });
    }

    pub(crate) fn set_auto_update_subscriptions(&self, enabled: bool) {
        self.spawn_complete("rosetun-set-auto-update-subscriptions", move |store| {
            WorkerEvent::SetAutoUpdateSubscriptions(rosetun_core::set_auto_update_subscriptions(
                store, enabled,
            ))
        });
    }

    pub(crate) fn set_check_updates(&self, enabled: bool) {
        self.spawn_complete("rosetun-set-check-updates", move |store| {
            WorkerEvent::SetCheckUpdates(rosetun_core::set_check_updates(store, enabled))
        });
    }

    pub(crate) fn skip_version(&self, version: String) {
        self.spawn_complete("rosetun-skip-version", move |store| {
            WorkerEvent::SkipVersion(rosetun_core::skip_version(store, Some(version)))
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

    #[cfg(windows)]
    pub(crate) fn open_folder(&self, folder: PathBuf) {
        self.spawn_task("rosetun-open-folder", move |publisher| {
            let result = Command::new("explorer.exe").arg(folder).spawn().map(|_| ());
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::OpenFolder(result),
            );
        });
    }
}
