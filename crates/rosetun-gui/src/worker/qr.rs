//! QR reads for the add-subscription dialog. Nothing here logs: the decoded text is a
//! subscription secret, and so are the image and the file name.

use super::*;
use crate::qr::{self, QrError};
use crate::state::QrSource;

impl WorkerDispatcher {
    pub(crate) fn read_qr(&self, request: u64, source: QrSource) {
        self.spawn_task("rosetun-read-qr", move |publisher| {
            let event = match source {
                QrSource::File => WorkerEvent::Qr {
                    request,
                    result: pick_image().map(|path| qr::links_in_file(&path)),
                },
                QrSource::Clipboard => WorkerEvent::Qr {
                    request,
                    result: Some(clipboard_links()),
                },
                QrSource::ScreenClip => match open_screen_clip() {
                    Ok(sequence) => WorkerEvent::QrScreenClip { request, sequence },
                    Err(error) => WorkerEvent::Qr {
                        request,
                        result: Some(Err(error)),
                    },
                },
            };
            emit(&publisher.tx, &publisher.repaint, event);
        });
    }

    pub(crate) fn poll_screen_clip(&self, request: u64, sequence: u32) {
        #[cfg(not(windows))]
        let _ = sequence;
        self.spawn_task("rosetun-poll-screen-clip", move |publisher| {
            #[cfg(windows)]
            let event = {
                let current = rosetun_shell::clipboard_sequence();
                match (current != sequence).then(clipboard_links) {
                    // Something else was copied meanwhile; keep waiting for the clip.
                    None | Some(Err(QrError::NoClipboardImage)) => WorkerEvent::QrScreenClip {
                        request,
                        sequence: current,
                    },
                    Some(result) => WorkerEvent::Qr {
                        request,
                        result: Some(result),
                    },
                }
            };
            #[cfg(not(windows))]
            let event = WorkerEvent::Qr {
                request,
                result: Some(Err(QrError::ScreenClipUnavailable)),
            };
            emit(&publisher.tx, &publisher.repaint, event);
        });
    }
}

fn pick_image() -> Option<PathBuf> {
    #[cfg(windows)]
    return rfd::FileDialog::new()
        .set_title(tr!("choose-qr-image"))
        .add_filter(
            tr!("qr-image-files"),
            &["png", "jpg", "jpeg", "bmp", "webp"],
        )
        .pick_file();
    #[cfg(not(windows))]
    None
}

/// Reads the clipboard without changing it.
fn clipboard_links() -> Result<Vec<String>, QrError> {
    let mut clipboard = arboard::Clipboard::new().map_err(|_| QrError::Clipboard)?;
    let image = clipboard.get_image().map_err(|error| match error {
        arboard::Error::ContentNotAvailable | arboard::Error::ConversionFailure => {
            QrError::NoClipboardImage
        }
        _ => QrError::Clipboard,
    })?;
    qr::links_in_rgba(image.width, image.height, &image.bytes)
}

fn open_screen_clip() -> Result<u32, QrError> {
    #[cfg(windows)]
    {
        let sequence = rosetun_shell::clipboard_sequence();
        rosetun_shell::start_screen_clip().map_err(|_| QrError::ScreenClipUnavailable)?;
        Ok(sequence)
    }
    #[cfg(not(windows))]
    Err(QrError::ScreenClipUnavailable)
}

#[cfg(all(test, not(windows)))]
mod tests {
    use std::sync::mpsc;

    use super::*;

    #[test]
    fn screen_clip_requests_and_polls_report_unavailable() {
        assert!(matches!(open_screen_clip(), Err(QrError::ScreenClipUnavailable)));
        let (tx, rx) = mpsc::channel();
        let workers = WorkerDispatcher {
            publisher: ConfigPublisher {
                store: Store::at(std::env::temp_dir().join("rosetun-screen-clip-unavailable")),
                tx,
                repaint: egui::Context::default(),
                generation: Arc::default(),
            },
            connections: Arc::default(),
        };
        workers.read_qr(41, QrSource::ScreenClip);
        workers.poll_screen_clip(42, 7);
        let mut requests = Vec::new();
        for _ in 0..2 {
            match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
                WorkerEvent::Qr {
                    request,
                    result: Some(Err(QrError::ScreenClipUnavailable)),
                } => requests.push(request),
                _ => panic!("unexpected screen clip event"),
            }
        }
        requests.sort_unstable();
        assert_eq!(requests, [41, 42]);
    }
}
