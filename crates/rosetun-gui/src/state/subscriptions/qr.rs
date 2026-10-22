use super::AddDialog;
use crate::qr::QrError;
use crate::state::{Action, Job, State};
use crate::worker::WorkerEvent;

/// How long the add dialog waits for a screen clip to reach the clipboard.
pub(crate) const SCREEN_CLIP_TIMEOUT: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QrSource {
    File,
    Clipboard,
    ScreenClip,
}

#[derive(Debug, Default)]
pub(crate) struct QrImport {
    pub(crate) stage: QrStage,
    pub(crate) error: Option<QrError>,
    /// Links from an image with several codes, for the user to pick one.
    pub(crate) choices: Vec<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) enum QrStage {
    #[default]
    Idle,
    Reading,
    ScreenClip(ScreenClip),
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ScreenClip {
    /// The clipboard's sequence number before the overlay opened, then after each change that
    /// brought no image; `None` until the worker has opened the overlay.
    sequence: Option<u32>,
    started: Option<u64>,
    last_poll: Option<u64>,
    polling: bool,
}

impl QrImport {
    pub(crate) fn busy(&self) -> bool {
        self.stage != QrStage::Idle
    }
}

impl State {
    pub(in crate::state) fn act_qr(&mut self, action: Action) -> Option<Job> {
        let dialog = self.subscriptions.add.as_mut()?;
        match action {
            Action::ReadQr(source) => {
                if dialog.busy || dialog.qr.busy() {
                    return None;
                }
                self.subscriptions.qr_request += 1;
                let request = self.subscriptions.qr_request;
                dialog.qr.error = None;
                dialog.qr.choices.clear();
                dialog.qr.stage = if source == QrSource::ScreenClip {
                    QrStage::ScreenClip(ScreenClip::default())
                } else {
                    QrStage::Reading
                };
                return Some(Job::ReadQr { request, source });
            }
            Action::CancelQr => {
                if matches!(dialog.qr.stage, QrStage::ScreenClip(_)) {
                    dialog.qr.stage = QrStage::Idle;
                    self.subscriptions.qr_request += 1;
                }
            }
            Action::ChooseQrLink(index) if index < dialog.qr.choices.len() => {
                let link = dialog.qr.choices.swap_remove(index);
                dialog.qr.choices.clear();
                put_link(dialog, link);
            }
            _ => {}
        }
        None
    }

    pub(in crate::state) fn reduce_qr(&mut self, event: WorkerEvent) {
        let current = self.subscriptions.qr_request;
        let Some(dialog) = self.subscriptions.add.as_mut() else {
            return;
        };
        match event {
            WorkerEvent::Qr { request, result } if request == current && dialog.qr.busy() => {
                dialog.qr.stage = QrStage::Idle;
                match result {
                    None => {}
                    Some(Ok(mut links)) if links.len() == 1 => put_link(dialog, links.remove(0)),
                    Some(Ok(links)) => dialog.qr.choices = links,
                    Some(Err(error)) => dialog.qr.error = Some(error),
                }
            }
            WorkerEvent::QrScreenClip { request, sequence } if request == current => {
                if let QrStage::ScreenClip(clip) = &mut dialog.qr.stage {
                    clip.sequence = Some(sequence);
                    clip.polling = false;
                }
            }
            _ => {}
        }
    }

    /// Once a second while a screen clip is awaited, until [`SCREEN_CLIP_TIMEOUT`].
    pub(in crate::state) fn screen_clip_due(&self) -> Option<u64> {
        let QrStage::ScreenClip(clip) = &self.subscriptions.add.as_ref()?.qr.stage else {
            return None;
        };
        let Some(started) = clip.started else {
            return Some(0);
        };
        let deadline = started.saturating_add(SCREEN_CLIP_TIMEOUT);
        let poll = (clip.sequence.is_some() && !clip.polling)
            .then(|| clip.last_poll.map_or(0, |last| last.saturating_add(1)));
        Some(poll.map_or(deadline, |poll| poll.min(deadline)))
    }

    pub(crate) fn take_screen_clip_poll(&mut self, now: u64) -> Option<Job> {
        if now < self.screen_clip_due()? {
            return None;
        }
        let request = self.subscriptions.qr_request;
        let dialog = self.subscriptions.add.as_mut()?;
        let QrStage::ScreenClip(clip) = &mut dialog.qr.stage else {
            return None;
        };
        let started = *clip.started.get_or_insert(now);
        if now >= started.saturating_add(SCREEN_CLIP_TIMEOUT) {
            dialog.qr.stage = QrStage::Idle;
            dialog.qr.error = Some(QrError::ScreenClipTimedOut);
            self.subscriptions.qr_request += 1;
            return None;
        }
        let sequence = clip.sequence?;
        if clip.polling || clip.last_poll.is_some_and(|last| now <= last) {
            return None;
        }
        clip.polling = true;
        clip.last_poll = Some(now);
        Some(Job::PollScreenClip { request, sequence })
    }
}

/// As a paste would: the link replaces the field and goes through the same checks as typed text.
fn put_link(dialog: &mut AddDialog, link: String) {
    dialog.url = link;
    dialog.error = None;
    dialog.focus_url = true;
}
