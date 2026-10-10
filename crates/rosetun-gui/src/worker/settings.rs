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

    pub(crate) fn change_setting(&self, change: SettingChange) {
        self.spawn_complete("rosetun-change-setting", move |store| {
            WorkerEvent::Setting(change, rosetun_core::change_setting(store, change))
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
