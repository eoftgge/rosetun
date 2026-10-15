use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use rosetun_config::redact_report_text;
use rosetun_ipc::{ClientError, ErrorCode, HelperClient};

use super::{CLIENT_NAME, WorkerDispatcher, WorkerEvent, emit};
use crate::report::ReportSnapshot;

const REPORT_LOG_LIMIT: usize = 1024 * 1024;

macro_rules! report_label {
    ($key:literal, $language:expr) => {
        crate::i18n::tr_in($language, $key, &fluent_bundle::FluentArgs::new())
    };
}

impl WorkerDispatcher {
    pub(crate) fn save_report(&self, mut snapshot: Box<ReportSnapshot>, own_alias: String) {
        self.spawn_task("rosetun-support-report", move |publisher| {
            let filename = format!("rosetun-report-{}.txt", report_timestamp());
            let path = rfd::FileDialog::new()
                .add_filter(
                    report_label!("report-text-file", snapshot.language_for_report),
                    &["txt"],
                )
                .set_file_name(&filename)
                .save_file();
            let mut new_checks = None;
            let result = path
                .map(|path| {
                    if snapshot.checks.is_none() {
                        let results = rosetun_core::check_system(&own_alias);
                        snapshot.set_checks(&results);
                        new_checks = Some(results);
                    }
                    let log = read_client_log(publisher.store.path())
                        .map(|text| redact_report_text(&text))
                        .unwrap_or_else(|_| {
                            report_label!(
                                "report-client-log-unavailable",
                                snapshot.language_for_report
                            )
                        });
                    let (helper_version, engine_versions, helper_log) = helper_details(&snapshot);
                    if let Some(version) = helper_version {
                        snapshot.helper_version = Some(version);
                    }
                    #[cfg(windows)]
                    let build = rosetun_shell::windows_build().ok();
                    #[cfg(not(windows))]
                    let build = None;
                    let report = snapshot.render(
                        build,
                        (engine_versions.0.as_deref(), engine_versions.1.as_deref()),
                        &log,
                        &helper_log,
                    );
                    save_new_file(&path, report.as_bytes())?;
                    Ok(path)
                })
                .transpose();
            emit(
                &publisher.tx,
                &publisher.repaint,
                WorkerEvent::ReportSaved { result, new_checks },
            );
        });
    }
}

fn helper_details(
    snapshot: &ReportSnapshot,
) -> (Option<String>, (Option<String>, Option<String>), String) {
    match HelperClient::connect(&rosetun_ipc::default_endpoint(), CLIENT_NAME) {
        Ok(mut client) => {
            let version = Some(client.helper_version().to_owned());
            let (sing_box, xray) = client.engine_versions();
            let versions = (sing_box.map(str::to_owned), xray.map(str::to_owned));
            let log = match client.diagnostic_log() {
                Ok(text) => redact_report_text(&text),
                Err(ClientError::Helper(error)) if error.code == ErrorCode::AccessDenied => {
                    report_label!("report-helper-log-denied", snapshot.language_for_report)
                }
                Err(ClientError::Transport(_) | ClientError::Closed) => {
                    report_label!(
                        "report-helper-log-unavailable",
                        snapshot.language_for_report
                    )
                }
                Err(_) => report_label!("report-helper-log-error", snapshot.language_for_report),
            };
            (version, versions, log)
        }
        Err(_) => (
            None,
            (None, None),
            report_label!(
                "report-helper-log-unavailable",
                snapshot.language_for_report
            ),
        ),
    }
}

fn read_client_log(config_path: &Path) -> io::Result<String> {
    let path = config_path.with_file_name(crate::constants::LOG_FILE_NAME);
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    }
    let mut file = options.open(path)?;
    let length = file.metadata()?.len();
    let count = length.min(REPORT_LOG_LIMIT as u64);
    file.seek(SeekFrom::Start(length - count))?;
    let mut tail = Vec::with_capacity(count as usize);
    file.take(count).read_to_end(&mut tail)?;
    Ok(String::from_utf8_lossy(&tail).into_owned())
}

fn save_new_file(path: &Path, content: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(error) = file.write_all(content).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

fn report_timestamp() -> String {
    rosetun_shell::local_report_timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saving_does_not_replace_an_existing_report() {
        let path = std::env::temp_dir().join(format!(
            "rosetun-report-test-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap()
            .write_all(b"old report")
            .unwrap();
        let result = save_new_file(&path, b"new report");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&path).unwrap(), "old report");
        fs::remove_file(path).unwrap();
    }
}
