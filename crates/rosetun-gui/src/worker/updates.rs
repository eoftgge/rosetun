use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use super::*;
use crate::state::UpdateFailure;

/// Progress without a known size is reported this often.
const PROGRESS_STEP_BYTES: u64 = 1024 * 1024;
/// Setup's own window shows the progress; the GUI asks it back once installed.
#[cfg(windows)]
const INSTALLER_ARGUMENTS: &str = "/SILENT /SUPPRESSMSGBOXES /NORESTART /LAUNCH=1";

impl WorkerDispatcher {
    pub(crate) fn check_updates(&self) {
        self.spawn_task("rosetun-check-updates", move |publisher| {
            let result =
                rosetun_core::latest_release(env!("CARGO_PKG_VERSION"), Duration::from_secs(15));
            let checked_at = crate::state::now_unix();
            if let Ok(release) = &result {
                let newest = release.as_ref().map(|release| release.version.clone());
                if rosetun_core::record_update_check(&publisher.store, checked_at, newest).is_err()
                {
                    tracing::warn!("could not save update check time");
                } else {
                    publisher.publish();
                }
            }
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::UpdateCheck { checked_at, result },
            );
        });
    }

    pub(crate) fn download_update(&self, version: String, via_vpn: bool, cancel: Arc<AtomicBool>) {
        self.spawn_task("rosetun-download-update", move |publisher| {
            let result = match update_directory() {
                Some(directory) => {
                    let mut reported = Reported::default();
                    rosetun_core::download_update(
                        &version,
                        &directory,
                        via_vpn,
                        &cancel,
                        |received, total| {
                            if reported.due(received, total) {
                                emit(
                                    &publisher.tx,
                                    &publisher.repaint,
                                    WorkerEvent::UpdateProgress {
                                        version: version.clone(),
                                        received,
                                        total,
                                    },
                                );
                            }
                        },
                    )
                }
                None => Err(rosetun_core::UpdateDownloadError::Save),
            };
            match &result {
                Ok(_) => tracing::info!(%version, "update downloaded and verified"),
                Err(error) => tracing::warn!(%version, %error, "update download stopped"),
            }
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::UpdateDownloaded { version, result },
            );
        });
    }

    pub(crate) fn install_update(&self, update: rosetun_core::DownloadedUpdate) {
        self.spawn_task("rosetun-install-update", move |publisher| {
            let failure = install(&update);
            match &failure {
                Some(failure) => {
                    tracing::warn!(version = %update.version, ?failure, "update installer did not finish");
                }
                None => tracing::info!(version = %update.version, "update installer finished"),
            }
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::UpdateInstall(failure),
            );
        });
    }
}

/// Throttles progress events to whole percents, or to steps without a size.
#[derive(Default)]
struct Reported {
    last: Option<u64>,
}

impl Reported {
    fn due(&mut self, received: u64, total: Option<u64>) -> bool {
        let mark = match total {
            Some(total) if total > 0 => received.saturating_mul(100) / total,
            _ => received / PROGRESS_STEP_BYTES,
        };
        if self.last == Some(mark) {
            return false;
        }
        self.last = Some(mark);
        true
    }
}

/// The current user's own folder, out of reach of other accounts.
fn update_directory() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .map(|base| PathBuf::from(base).join("Rosetun").join("updates"))
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Runs the checked installer. Setup normally ends this process before it
/// answers; an answer means it declined, failed or finished without that.
#[cfg(windows)]
fn install(update: &rosetun_core::DownloadedUpdate) -> Option<UpdateFailure> {
    if let Err(error) = update.verify() {
        return Some(UpdateFailure::Download(error));
    }
    match rosetun_shell::run_elevated_shown(&update.path, INSTALLER_ARGUMENTS) {
        Ok(Some(0)) => None,
        Ok(Some(code)) => Some(UpdateFailure::Installer(code)),
        Ok(None) => Some(UpdateFailure::Declined),
        Err(_) => Some(UpdateFailure::Start),
    }
}

#[cfg(not(windows))]
fn install(_update: &rosetun_core::DownloadedUpdate) -> Option<UpdateFailure> {
    Some(UpdateFailure::Start)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_is_reported_once_per_percent_or_step() {
        let mut reported = Reported::default();
        assert!(reported.due(0, Some(1000)));
        assert!(!reported.due(5, Some(1000)));
        assert!(reported.due(10, Some(1000)));
        assert!(reported.due(1000, Some(1000)));
        let mut unknown = Reported::default();
        assert!(unknown.due(1, None));
        assert!(!unknown.due(PROGRESS_STEP_BYTES - 1, None));
        assert!(unknown.due(PROGRESS_STEP_BYTES, None));
    }
}
