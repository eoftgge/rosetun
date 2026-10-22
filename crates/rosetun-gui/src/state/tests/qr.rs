use std::io::Write;
use std::sync::{Arc, Mutex};

use super::super::subscriptions::SCREEN_CLIP_TIMEOUT;
use super::*;
use crate::qr::tests::{canvas, code, png};
use crate::qr::{self, QrError};

const LINK: &str = "sub.example.com/private-token";
const HAPP: &str = "happ://add/https://sub.example.com/happ-token";

fn open_dialog() -> State {
    let mut state = State::default();
    state.act(Action::OpenAdd);
    state
}

fn dialog(state: &State) -> &AddDialog {
    state.subscriptions.add.as_ref().unwrap()
}

fn read(state: &mut State, source: QrSource) -> u64 {
    match state.act(Action::ReadQr(source)) {
        Some(Job::ReadQr { request, source: sent }) if sent == source => request,
        _ => panic!("no QR read job"),
    }
}

fn start_screen_clip(state: &mut State, now: u64) -> u64 {
    let request = read(state, QrSource::ScreenClip);
    assert!(matches!(dialog(state).qr.stage, QrStage::ScreenClip(_)));
    assert!(state.take_screen_clip_poll(now).is_none(), "no poll before the overlay opened");
    state.reduce(WorkerEvent::QrScreenClip {
        request,
        sequence: 7,
    });
    request
}

#[test]
fn a_decoded_link_fills_the_field_and_is_normalized_as_if_pasted() {
    let mut state = open_dialog();
    let request = read(&mut state, QrSource::File);
    assert_eq!(dialog(&state).qr.stage, QrStage::Reading);
    assert!(dialog(&state).qr.busy());
    let result = qr::links_in_bytes(&png(&code(LINK, 4)));
    state.reduce(WorkerEvent::Qr {
        request,
        result: Some(result),
    });
    let shown = dialog(&state);
    assert_eq!(shown.url, LINK);
    assert_eq!(shown.qr.stage, QrStage::Idle);
    assert!(shown.qr.error.is_none());
    match state.act(Action::SubmitAdd) {
        Some(Job::Add { input, .. }) => assert_eq!(input, "https://sub.example.com/private-token"),
        _ => panic!("the link was not submitted"),
    }

    let mut state = open_dialog();
    let request = read(&mut state, QrSource::Clipboard);
    state.reduce(WorkerEvent::Qr {
        request,
        result: Some(qr::links_in_bytes(&png(&code(HAPP, 4)))),
    });
    assert_eq!(dialog(&state).url, HAPP);
    assert_eq!(
        rosetun_core::normalize_subscription_url(&dialog(&state).url).unwrap(),
        "https://sub.example.com/happ-token"
    );
}

#[test]
fn a_decoded_link_is_not_added_on_its_own() {
    let mut state = open_dialog();
    let request = read(&mut state, QrSource::File);
    state.reduce(WorkerEvent::Qr {
        request,
        result: Some(Ok(vec![LINK.into()])),
    });
    assert!(!dialog(&state).busy);
}

#[test]
fn two_codes_offer_a_choice() {
    let mut state = open_dialog();
    let request = read(&mut state, QrSource::File);
    let first = code(LINK, 4);
    let second = code(HAPP, 4);
    let image = canvas(
        first.width() * 2,
        first.height(),
        &[(&first, 0, 0), (&second, first.width(), 0)],
    );
    let result = qr::links_in_bytes(&png(&image));
    state.reduce(WorkerEvent::Qr {
        request,
        result: Some(result),
    });
    let mut choices = dialog(&state).qr.choices.clone();
    assert_eq!(dialog(&state).url, "", "nothing is chosen for the user");
    choices.sort();
    assert_eq!(choices, vec![HAPP.to_owned(), LINK.to_owned()]);
    let index = dialog(&state)
        .qr
        .choices
        .iter()
        .position(|link| link == HAPP)
        .unwrap();
    assert!(state.act(Action::ChooseQrLink(index)).is_none());
    assert_eq!(dialog(&state).url, HAPP);
    assert!(dialog(&state).qr.choices.is_empty());
}

#[test]
fn errors_and_a_closed_file_dialog_leave_the_field_alone() {
    let mut state = open_dialog();
    state.subscriptions.add.as_mut().unwrap().url = "https://sub.example.com/typed".into();
    let request = read(&mut state, QrSource::File);
    state.reduce(WorkerEvent::Qr {
        request,
        result: None,
    });
    assert_eq!(dialog(&state).url, "https://sub.example.com/typed");
    assert!(dialog(&state).qr.error.is_none());
    assert!(!dialog(&state).qr.busy());

    let request = read(&mut state, QrSource::Clipboard);
    state.reduce(WorkerEvent::Qr {
        request,
        result: Some(Err(QrError::NoClipboardImage)),
    });
    assert_eq!(dialog(&state).url, "https://sub.example.com/typed");
    assert_eq!(dialog(&state).qr.error, Some(QrError::NoClipboardImage));
    assert!(!errors::qr(crate::i18n::Language::English, QrError::NoClipboardImage).is_empty());

    read(&mut state, QrSource::File);
    assert!(dialog(&state).qr.error.is_none(), "a new read clears the old error");
    assert!(
        state.act(Action::ReadQr(QrSource::Clipboard)).is_none(),
        "one read at a time"
    );
    assert!(state.act(Action::SubmitAdd).is_none(), "no add while a read may replace the link");
}

#[test]
fn the_screen_clip_is_polled_once_a_second() {
    let mut state = open_dialog();
    let request = start_screen_clip(&mut state, 1_000);
    assert_eq!(state.next_wake(1_000), Some(Duration::ZERO));
    assert!(matches!(
        state.take_screen_clip_poll(1_000),
        Some(Job::PollScreenClip { request: sent, sequence: 7 }) if sent == request
    ));
    assert!(state.take_screen_clip_poll(1_000).is_none(), "one poll in flight");
    // Something other than an image was copied: wait past the new number.
    state.reduce(WorkerEvent::QrScreenClip {
        request,
        sequence: 8,
    });
    assert!(state.take_screen_clip_poll(1_000).is_none());
    assert_eq!(state.next_wake(1_000), Some(Duration::from_secs(1)));
    assert!(matches!(
        state.take_screen_clip_poll(1_001),
        Some(Job::PollScreenClip { sequence: 8, .. })
    ));
    state.reduce(WorkerEvent::Qr {
        request,
        result: Some(Ok(vec![LINK.into()])),
    });
    assert_eq!(dialog(&state).url, LINK);
    assert_eq!(dialog(&state).qr.stage, QrStage::Idle);
    assert!(state.take_screen_clip_poll(1_002).is_none());
}

#[test]
fn the_screen_clip_wait_can_be_cancelled() {
    let mut state = open_dialog();
    let request = start_screen_clip(&mut state, 1_000);
    assert!(state.take_screen_clip_poll(1_000).is_some());
    assert!(state.act(Action::CancelQr).is_none());
    assert_eq!(dialog(&state).qr.stage, QrStage::Idle);
    assert!(dialog(&state).qr.error.is_none());
    assert!(state.take_screen_clip_poll(1_005).is_none());
    assert_eq!(state.next_wake(1_005), None);
    // The poll that was in flight answers late.
    state.reduce(WorkerEvent::Qr {
        request,
        result: Some(Ok(vec![LINK.into()])),
    });
    assert_eq!(dialog(&state).url, "");

    // A closed dialog drops its answer too, even after it is opened again.
    let request = start_screen_clip(&mut state, 2_000);
    assert!(state.act(Action::CancelAdd).is_none());
    assert!(state.subscriptions.add.is_none());
    state.act(Action::OpenAdd);
    state.reduce(WorkerEvent::Qr {
        request,
        result: Some(Ok(vec![LINK.into()])),
    });
    assert_eq!(dialog(&state).url, "");
}

#[test]
fn the_screen_clip_wait_ends_after_a_minute() {
    let mut state = open_dialog();
    let request = start_screen_clip(&mut state, 1_000);
    assert!(state.take_screen_clip_poll(1_000).is_some());
    state.reduce(WorkerEvent::QrScreenClip {
        request,
        sequence: 7,
    });
    let last = 1_000 + SCREEN_CLIP_TIMEOUT - 1;
    assert!(state.take_screen_clip_poll(last).is_some());
    state.reduce(WorkerEvent::QrScreenClip {
        request,
        sequence: 7,
    });
    assert_eq!(state.next_wake(last), Some(Duration::from_secs(1)));
    assert!(state.take_screen_clip_poll(last + 1).is_none());
    assert_eq!(dialog(&state).qr.stage, QrStage::Idle);
    assert_eq!(dialog(&state).qr.error, Some(QrError::ScreenClipTimedOut));
    state.reduce(WorkerEvent::Qr {
        request,
        result: Some(Ok(vec![LINK.into()])),
    });
    assert_eq!(dialog(&state).url, "", "a clip after the timeout is dropped");
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn no_log_line_carries_the_link() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!("capture works");
        let bytes = png(&code(LINK, 4));
        let path = std::env::temp_dir().join(format!(
            "rosetun-qr-private-token-{}.png",
            std::process::id()
        ));
        std::fs::write(&path, &bytes).unwrap();
        let from_file = qr::links_in_file(&path);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(from_file, Ok(vec![LINK.to_owned()]));
        let _ = qr::links_in_bytes(&png(&code("Meeting at noon private-token", 4)));
        let _ = qr::links_in_bytes(b"private-token");

        let mut state = open_dialog();
        let request = read(&mut state, QrSource::File);
        state.reduce(WorkerEvent::Qr {
            request,
            result: Some(from_file),
        });
        let request = start_screen_clip(&mut state, 1_000);
        state.take_screen_clip_poll(1_000);
        state.reduce(WorkerEvent::Qr {
            request,
            result: Some(Ok(vec![LINK.into(), HAPP.into()])),
        });
        state.act(Action::ChooseQrLink(1));
        let _ = state.act(Action::SubmitAdd);
    });
    let output = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(output.contains("capture works"), "{output}");
    assert!(!output.contains("private-token"), "{output}");
    assert!(!output.contains("happ-token"), "{output}");
    assert!(!output.contains("sub.example.com"), "{output}");
}
