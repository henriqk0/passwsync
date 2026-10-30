//! FR-021 to FR-024: copy marks the clip sensitive, writes a marker without the value and
//! clears at the deadline (sweeper, `on_deadline`), on every lock, on screen off and shutdown;
//! a clip replaced by another app is kept; a marker left behind is cleared at the next start;
//! reveals hide at the timeout, on lock and when the view is left.

mod common;

use std::fs;
use std::thread;
use std::time::{Duration, Instant};

use common::{Fakes, TempDir, core_with_wallet, input, set_mode};
use passwsync_ffi::error::CoreError;
use passwsync_ffi::records::{CopyField, CoreEvent};
use passwsync_ffi::testkit::ClipEvent;

const SECRET: &str = "MARKER-clip-secret-pw";
const MARKER_FILE: &str = "clipboard-pending";

fn setup(
    tag: &str,
    fakes: &Fakes,
) -> (
    TempDir,
    std::sync::Arc<passwsync_ffi::api::PasswsyncCore>,
    String,
) {
    let dir = TempDir::new(tag);
    let core = core_with_wallet(dir.path(), fakes, "Personal");
    let id = core
        .add_credential("Personal".into(), input("Mail", "alice", Some(SECRET)))
        .unwrap();
    (dir, core, id)
}

fn cleared(fakes: &Fakes) -> usize {
    fakes
        .clipboard
        .events()
        .iter()
        .filter(|e| matches!(e, ClipEvent::Cleared { .. }))
        .count()
}

#[test]
fn copy_sets_a_sensitive_clip_writes_a_marker_and_counts_down() {
    let fakes = Fakes::new();
    let (dir, core, id) = setup("clip-copy", &fakes);
    assert_eq!(core.clipboard_pending_ms(), None);
    let ticket = core
        .copy_field("Personal".into(), id.clone(), CopyField::Password)
        .unwrap();
    assert_eq!(ticket.clear_in_ms, 30_000);
    assert_eq!(
        fakes.clipboard.current().as_deref(),
        Some(SECRET.as_bytes())
    );
    let marker = fs::read_to_string(dir.path().join(MARKER_FILE)).unwrap();
    let timestamp = match fakes.clipboard.events().last() {
        Some(ClipEvent::Set { timestamp, .. }) => *timestamp,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        marker,
        format!("deadline_boottime_s=30\nclip_timestamp={timestamp}\n")
    );
    assert!(!marker.contains(SECRET));
    assert_eq!(core.clipboard_pending_ms(), Some(30_000));
    fakes.clock.advance(Duration::from_secs(12));
    assert_eq!(core.clipboard_pending_ms(), Some(18_000));
    // The username can be copied as well; the countdown restarts.
    core.copy_field("Personal".into(), id, CopyField::Username)
        .unwrap();
    assert_eq!(fakes.clipboard.current().as_deref(), Some(&b"alice"[..]));
    assert_eq!(core.clipboard_pending_ms(), Some(30_000));
    let wallets = core.list_wallets().unwrap();
    assert!(wallets[0].pending_copy);
}

#[test]
fn the_deadline_clears_through_on_deadline() {
    let fakes = Fakes::new();
    let (dir, core, id) = setup("clip-deadline", &fakes);
    core.copy_field("Personal".into(), id, CopyField::Password)
        .unwrap();
    let plan = core.on_background();
    assert_eq!(
        plan.deadline_in_ms,
        Some(30_000),
        "clipboard before idle lock"
    );
    fakes.clock.advance(Duration::from_secs(29));
    assert_eq!(core.on_deadline().deadline_in_ms, Some(1_000));
    assert_eq!(
        fakes.clipboard.current().as_deref(),
        Some(SECRET.as_bytes())
    );
    fakes.clock.advance(Duration::from_secs(1));
    let plan = core.on_deadline();
    assert_eq!(fakes.clipboard.current(), None);
    assert_eq!(cleared(&fakes), 1);
    assert!(!dir.path().join(MARKER_FILE).exists());
    assert_eq!(core.clipboard_pending_ms(), None);
    // Next deadline: the idle lock of the unlocked wallet.
    assert_eq!(plan.deadline_in_ms, Some(15 * 60 * 1000 - 30_000));
    assert!(
        fakes
            .notifier
            .events()
            .contains(&CoreEvent::ClipboardCleared)
    );
    assert!(
        fakes
            .log
            .lines()
            .contains(&"passwsync: clipboard cleared".to_string())
    );
}

#[test]
fn the_deadline_also_counts_while_the_phone_sleeps() {
    let fakes = Fakes::new();
    let (_dir, core, id) = setup("clip-sleep", &fakes);
    core.copy_field("Personal".into(), id, CopyField::Password)
        .unwrap();
    fakes.clock.suspend(Duration::from_secs(40));
    core.on_deadline();
    assert_eq!(fakes.clipboard.current(), None);
}

#[test]
fn the_sweeper_clears_at_the_deadline_in_the_foreground() {
    let mut fakes = Fakes::new();
    fakes.sweep_period = Duration::from_millis(10);
    let (_dir, core, id) = setup("clip-sweeper", &fakes);
    core.on_foreground();
    core.copy_field("Personal".into(), id, CopyField::Password)
        .unwrap();
    fakes.clock.advance(Duration::from_secs(31));
    let started = Instant::now();
    while fakes.clipboard.current().is_some() && started.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(fakes.clipboard.current(), None, "the sweeper cleared it");
}

#[test]
fn every_lock_cause_clears_immediately() {
    type Cause = fn(&passwsync_ffi::api::PasswsyncCore);
    let causes: [(&str, Cause); 4] = [
        ("lock_wallet", |c| c.lock_wallet("Personal".into()).unwrap()),
        ("lock_all", |c| c.lock_all()),
        ("screen_off", |c| c.on_screen_off()),
        ("shutdown", |c| c.shutdown()),
    ];
    for (what, cause) in causes {
        let fakes = Fakes::new();
        let (dir, core, id) = setup("clip-lock", &fakes);
        core.copy_field("Personal".into(), id, CopyField::Password)
            .unwrap();
        cause(&core);
        assert_eq!(fakes.clipboard.current(), None, "{what}");
        assert!(!dir.path().join(MARKER_FILE).exists(), "{what}");
        assert_eq!(core.clipboard_pending_ms(), None, "{what}");
    }
}

#[test]
fn a_suspend_or_idle_lock_clears_too() {
    let fakes = Fakes::new();
    let (_dir, core, id) = setup("clip-idle", &fakes);
    core.copy_field("Personal".into(), id, CopyField::Password)
        .unwrap();
    // A suspend locks every wallet through the service's sweep; the lock observer clears.
    fakes.clock.suspend(Duration::from_secs(10));
    core.on_foreground();
    assert_eq!(fakes.clipboard.current(), None, "suspend lock cleared it");
}

#[test]
fn a_clip_replaced_by_another_app_is_kept() {
    let fakes = Fakes::new();
    let (dir, core, id) = setup("clip-other", &fakes);
    core.copy_field("Personal".into(), id, CopyField::Password)
        .unwrap();
    fakes
        .clipboard
        .replace_by_other_app(b"someone else".to_vec());
    core.lock_all();
    assert_eq!(
        fakes.clipboard.current().as_deref(),
        Some(&b"someone else"[..])
    );
    assert!(matches!(
        fakes.clipboard.events().last(),
        Some(ClipEvent::Kept { .. })
    ));
    assert!(
        !dir.path().join(MARKER_FILE).exists(),
        "nothing left to clear"
    );
}

#[test]
fn a_clip_that_cannot_be_inspected_is_cleared() {
    let fakes = Fakes::new();
    let (_dir, core, id) = setup("clip-blind", &fakes);
    core.copy_field("Personal".into(), id, CopyField::Password)
        .unwrap();
    fakes.clipboard.replace_by_other_app(b"other".to_vec());
    fakes.clipboard.set_cannot_inspect(true);
    core.lock_all();
    assert_eq!(fakes.clipboard.current(), None);
}

#[test]
fn a_marker_left_by_the_previous_process_is_cleared_at_start() {
    let fakes = Fakes::new();
    let (dir, core, id) = setup("clip-restart", &fakes);
    core.copy_field("Personal".into(), id, CopyField::Password)
        .unwrap();
    // The process dies without clearing (force-stop): only the marker remains.
    std::mem::forget(core);
    let restarted = Fakes {
        clipboard: fakes.clipboard.clone(),
        ..Fakes::new()
    };
    let core = restarted.start(dir.path()).unwrap();
    assert_eq!(fakes.clipboard.current(), None);
    assert!(!dir.path().join(MARKER_FILE).exists());
    assert_eq!(core.clipboard_pending_ms(), None);
    assert!(
        restarted
            .log
            .lines()
            .contains(&"passwsync: clipboard cleared".to_string())
    );
}

#[test]
fn an_unreadable_marker_clears_unconditionally() {
    let fakes = Fakes::new();
    let dir = TempDir::new("clip-garbage");
    {
        let core = fakes.start(dir.path()).unwrap();
        drop(core);
    }
    fakes.clipboard.replace_by_other_app(b"maybe ours".to_vec());
    let path = dir.path().join(MARKER_FILE);
    fs::write(&path, b"garbage").unwrap();
    set_mode(&path, 0o600);
    let _core = fakes.start(dir.path()).unwrap();
    assert_eq!(fakes.clipboard.current(), None);
    assert!(!path.exists());
}

#[test]
fn a_failing_clipboard_is_a_platform_error_and_leaves_no_marker() {
    let fakes = Fakes::new();
    let (dir, core, id) = setup("clip-fail", &fakes);
    fakes.clipboard.set_failing(true);
    assert_eq!(
        core.copy_field("Personal".into(), id, CopyField::Password)
            .map(|_| ()),
        Err(CoreError::Platform)
    );
    assert!(!dir.path().join(MARKER_FILE).exists());
    assert_eq!(core.clipboard_pending_ms(), None);
}

#[test]
fn reveals_hide_at_the_timeout_on_lock_and_when_the_view_is_left() {
    let fakes = Fakes::new();
    let (_dir, core, id) = setup("clip-reveal", &fakes);
    let expired = |fakes: &Fakes| {
        fakes
            .notifier
            .events()
            .iter()
            .filter(|e| **e == CoreEvent::RevealExpired)
            .count()
    };
    let ticket = core.reveal_password("Personal".into(), id.clone()).unwrap();
    assert_eq!(ticket.hide_in_ms, 30_000);
    fakes.clock.advance(Duration::from_secs(30));
    core.on_deadline();
    assert_eq!(expired(&fakes), 1, "timeout");
    core.reveal_password("Personal".into(), id.clone()).unwrap();
    core.leave_credential_view();
    assert_eq!(expired(&fakes), 2, "left the view");
    core.leave_credential_view();
    assert_eq!(expired(&fakes), 2, "nothing revealed any more");
    core.reveal_password("Personal".into(), id).unwrap();
    core.lock_wallet("Personal".into()).unwrap();
    assert_eq!(expired(&fakes), 3, "lock");
}

#[test]
fn a_reveal_deadline_is_part_of_the_background_plan() {
    let fakes = Fakes::new();
    let (_dir, core, id) = setup("clip-reveal-plan", &fakes);
    core.reveal_password("Personal".into(), id).unwrap();
    fakes.clock.advance(Duration::from_secs(10));
    assert_eq!(core.on_background().deadline_in_ms, Some(20_000));
}
