//! FR-003: the port fakes of `testkit` behave as the ports' contracts describe
//! (contracts/ffi-api.md section 3), so every later host test can rely on them.

use passwsync_ffi::ports::{Clipboard, KeySealer, LogSink, PlatformError, UiNotifier};
use passwsync_ffi::records::CoreEvent;
use passwsync_ffi::testkit::{
    ClipEvent, FakeClipboard, FakeSealer, RecordingLog, RecordingNotifier, SealCall, SealerMode,
};

const LABEL: &str = "passwsync identity v1";

#[test]
fn sealer_envelope_round_trips() {
    let sealer = FakeSealer::new();
    let sealed = sealer.seal(LABEL.into(), b"device key".to_vec()).unwrap();
    assert_ne!(
        sealed,
        b"device key".to_vec(),
        "the envelope is not the plaintext"
    );
    assert_eq!(
        sealer.open(LABEL.into(), sealed).unwrap(),
        b"device key".to_vec()
    );
}

#[test]
fn sealer_rejects_a_wrong_label() {
    let sealer = FakeSealer::new();
    let sealed = sealer.seal(LABEL.into(), b"device key".to_vec()).unwrap();
    assert_eq!(
        sealer.open("passwsync peers v1".into(), sealed),
        Err(PlatformError::Failed)
    );
}

#[test]
fn sealer_detects_tamper() {
    let sealer = FakeSealer::new();
    let mut sealed = sealer.seal(LABEL.into(), b"device key".to_vec()).unwrap();
    FakeSealer::tamper(&mut sealed);
    assert_eq!(
        sealer.open(LABEL.into(), sealed),
        Err(PlatformError::Failed)
    );
    assert_eq!(
        sealer.open(LABEL.into(), b"never issued".to_vec()),
        Err(PlatformError::Failed)
    );
}

#[test]
fn sealer_simulates_invalidation_and_unavailability() {
    let sealer = FakeSealer::new();
    let sealed = sealer.seal(LABEL.into(), b"k".to_vec()).unwrap();
    sealer.set_mode(SealerMode::Invalidated);
    assert_eq!(
        sealer.open(LABEL.into(), sealed.clone()),
        Err(PlatformError::Invalidated)
    );
    assert_eq!(
        sealer.seal(LABEL.into(), b"k".to_vec()),
        Err(PlatformError::Invalidated)
    );
    sealer.set_mode(SealerMode::Unavailable);
    assert_eq!(
        sealer.open(LABEL.into(), sealed.clone()),
        Err(PlatformError::Unavailable)
    );
    sealer.set_mode(SealerMode::Normal);
    assert_eq!(sealer.open(LABEL.into(), sealed).unwrap(), b"k".to_vec());
}

#[test]
fn reset_regenerates_the_key_so_old_envelopes_fail() {
    let sealer = FakeSealer::new();
    let sealed = sealer.seal(LABEL.into(), b"k".to_vec()).unwrap();
    sealer.reset().unwrap();
    assert_eq!(sealer.resets(), 1);
    assert_eq!(
        sealer.open(LABEL.into(), sealed),
        Err(PlatformError::Failed)
    );
}

#[test]
fn sealer_records_every_label_and_plaintext() {
    let sealer = FakeSealer::new();
    let sealed = sealer.seal(LABEL.into(), b"one".to_vec()).unwrap();
    sealer.open(LABEL.into(), sealed).unwrap();
    let _ = sealer.seal("passwsync peers v1".into(), b"two".to_vec());
    let _ = sealer.reset();
    assert_eq!(
        sealer.calls(),
        vec![
            SealCall::Seal {
                label: LABEL.into(),
                plaintext: b"one".to_vec()
            },
            SealCall::Open {
                label: LABEL.into(),
                plaintext: Some(b"one".to_vec())
            },
            SealCall::Seal {
                label: "passwsync peers v1".into(),
                plaintext: b"two".to_vec()
            },
            SealCall::Reset,
        ]
    );
    assert_eq!(
        sealer.labels(),
        vec![
            LABEL.to_string(),
            LABEL.to_string(),
            "passwsync peers v1".to_string()
        ]
    );
    assert_eq!(sealer.plaintexts(), vec![b"one".to_vec(), b"two".to_vec()]);
}

#[test]
fn clipboard_records_sets_and_clears() {
    let clip = FakeClipboard::new();
    let first = clip.set_sensitive(b"alice".to_vec()).unwrap();
    let second = clip.set_sensitive(b"hunter2".to_vec()).unwrap();
    assert!(second > first, "timestamps increase");
    assert_eq!(clip.current(), Some(b"hunter2".to_vec()));
    assert!(!clip.clear_if_ours(first), "an older timestamp is not ours");
    assert_eq!(clip.current(), Some(b"hunter2".to_vec()));
    assert!(clip.clear_if_ours(second));
    assert_eq!(clip.current(), None);
    assert_eq!(
        clip.events(),
        vec![
            ClipEvent::Set {
                value: b"alice".to_vec(),
                timestamp: first
            },
            ClipEvent::Set {
                value: b"hunter2".to_vec(),
                timestamp: second
            },
            ClipEvent::Kept { timestamp: first },
            ClipEvent::Cleared { timestamp: second },
        ]
    );
}

#[test]
fn clipboard_that_cannot_be_inspected_is_cleared() {
    let clip = FakeClipboard::new();
    let ts = clip.set_sensitive(b"x".to_vec()).unwrap();
    clip.set_cannot_inspect(true);
    assert!(
        clip.clear_if_ours(ts + 1000),
        "cannot inspect: clear anyway"
    );
    assert_eq!(clip.current(), None);
}

#[test]
fn clipboard_replaced_by_another_app_is_kept() {
    let clip = FakeClipboard::new();
    let ts = clip.set_sensitive(b"x".to_vec()).unwrap();
    clip.replace_by_other_app(b"their text".to_vec());
    assert!(!clip.clear_if_ours(ts));
    assert_eq!(clip.current(), Some(b"their text".to_vec()));
}

#[test]
fn clipboard_can_fail() {
    let clip = FakeClipboard::new();
    clip.set_failing(true);
    assert_eq!(
        clip.set_sensitive(b"x".to_vec()),
        Err(PlatformError::Unavailable)
    );
    assert_eq!(clip.current(), None);
}

#[test]
fn log_and_notifier_record_in_order() {
    let log = RecordingLog::new();
    log.line("first".into());
    log.line("second".into());
    assert_eq!(log.lines(), vec!["first".to_string(), "second".to_string()]);

    let notifier = RecordingNotifier::new();
    notifier.changed(CoreEvent::WalletsChanged);
    notifier.changed(CoreEvent::Locked {
        name: "Personal".into(),
    });
    notifier.changed(CoreEvent::AllLocked);
    assert_eq!(
        notifier.events(),
        vec![
            CoreEvent::WalletsChanged,
            CoreEvent::Locked {
                name: "Personal".into()
            },
            CoreEvent::AllLocked
        ]
    );
}

#[test]
fn fakes_are_usable_as_shared_ports() {
    use std::sync::Arc;
    let sealer: Arc<dyn KeySealer> = Arc::new(FakeSealer::new());
    let clip: Arc<dyn Clipboard> = Arc::new(FakeClipboard::new());
    let log: Arc<dyn LogSink> = Arc::new(RecordingLog::new());
    let notifier: Arc<dyn UiNotifier> = Arc::new(RecordingNotifier::new());
    std::thread::spawn(move || {
        let _ = sealer.seal(LABEL.into(), vec![1]);
        let _ = clip.set_sensitive(vec![1]);
        log.line("x".into());
        notifier.changed(CoreEvent::SyncChanged);
    })
    .join()
    .unwrap();
}
