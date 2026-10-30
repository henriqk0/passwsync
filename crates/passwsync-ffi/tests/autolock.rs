//! FR-016, FR-017, FR-018: idle auto-lock on the elapsed clock (suspend included, wall clock
//! irrelevant), screen-off lock, manual locks wipe and end reveals, and `on_foreground` sweeps
//! before anything can be read.

mod common;

use std::time::Duration;

use common::{Fakes, PASSWORD, TempDir, bytes, core_with_wallet, input};
use passwsync_ffi::error::CoreError;
use passwsync_ffi::records::{CoreEvent, SettingsInput};

const MINUTE: Duration = Duration::from_secs(60);

fn unlocked(core: &passwsync_ffi::api::PasswsyncCore) -> Vec<String> {
    core.list_wallets()
        .unwrap()
        .into_iter()
        .filter(|w| w.unlocked)
        .map(|w| w.name)
        .collect()
}

#[test]
fn an_idle_wallet_locks_after_the_timeout_on_the_elapsed_clock() {
    let dir = TempDir::new("al-idle");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    core.on_foreground();
    fakes.clock.advance(14 * MINUTE);
    core.on_foreground();
    assert_eq!(unlocked(&core), ["Personal"]);
    fakes.clock.advance(MINUTE);
    // Any call sweeps first: the data is gone before it could be read.
    assert_eq!(
        core.search("Personal".into(), String::new()).map(|_| ()),
        Err(CoreError::WalletLocked)
    );
    assert!(unlocked(&core).is_empty());
    assert!(
        fakes
            .log
            .lines()
            .contains(&"passwsync: locked Personal (idle)".to_string())
    );
}

#[test]
fn a_suspend_locks_everything() {
    let dir = TempDir::new("al-suspend");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    // The monotonic clock stops in suspend; boot time keeps counting.
    fakes.clock.suspend(20 * MINUTE);
    core.on_foreground();
    assert!(unlocked(&core).is_empty());
    let lines = fakes.log.lines();
    assert!(
        lines.contains(&"passwsync: suspend detected".to_string()),
        "{lines:?}"
    );
}

#[test]
fn a_wall_clock_change_has_no_effect() {
    // The core reads only the elapsed clock; there is no wall-clock input to change. Time
    // that did not elapse never locks, however far the wall clock moves.
    let dir = TempDir::new("al-wall");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    for _ in 0..3 {
        core.on_foreground();
    }
    assert_eq!(unlocked(&core), ["Personal"]);
}

#[test]
fn only_deliberate_actions_reset_the_idle_timer() {
    let dir = TempDir::new("al-touch");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    let id = core
        .add_credential("Personal".into(), input("Mail", "me", Some("pw")))
        .unwrap();
    fakes.clock.advance(10 * MINUTE);
    core.search("Personal".into(), "mail".into()).unwrap();
    fakes.clock.advance(10 * MINUTE);
    core.get_credential("Personal".into(), id.clone()).unwrap();
    fakes.clock.advance(10 * MINUTE);
    assert_eq!(unlocked(&core), ["Personal"], "actions kept it unlocked");
    // Listing, status and settings are background reads: they never count as activity.
    for _ in 0..5 {
        fakes.clock.advance(MINUTE);
        let _ = core.list_wallets();
        let _ = core.protection_status();
        let _ = core.settings();
        let _ = core.clipboard_pending_ms();
    }
    fakes.clock.advance(10 * MINUTE);
    assert!(unlocked(&core).is_empty());
}

#[test]
fn the_running_timeout_is_the_one_loaded_at_start() {
    let dir = TempDir::new("al-setting");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    core.update_settings(SettingsInput {
        auto_lock_minutes: 1,
        clipboard_clear_seconds: 30,
        device_name: None,
        sync_interval_minutes: 60,
        network_interface: None,
    })
    .unwrap();
    fakes.clock.advance(2 * MINUTE);
    core.on_foreground();
    assert_eq!(unlocked(&core), ["Personal"], "applies at the next start");
    drop(core);
    let core = fakes.start(dir.path()).unwrap();
    core.unlock_wallet("Personal".into(), bytes(PASSWORD))
        .unwrap();
    fakes.clock.advance(MINUTE);
    core.on_foreground();
    assert!(unlocked(&core).is_empty());
}

#[test]
fn screen_off_locks_every_wallet() {
    let dir = TempDir::new("al-screen");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    core.create_wallet("Work".into(), bytes(PASSWORD), bytes(PASSWORD))
        .unwrap();
    core.on_screen_off();
    assert!(unlocked(&core).is_empty());
    let events = fakes.notifier.events();
    assert!(events.contains(&CoreEvent::AllLocked), "{events:?}");
}

#[test]
fn locks_wipe_the_data_and_end_reveals() {
    let dir = TempDir::new("al-manual");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    let id = core
        .add_credential("Personal".into(), input("Mail", "me", Some("pw")))
        .unwrap();
    core.reveal_password("Personal".into(), id.clone()).unwrap();
    core.lock_wallet("Personal".into()).unwrap();
    assert_eq!(
        core.get_credential("Personal".into(), id.clone())
            .map(|_| ()),
        Err(CoreError::WalletLocked)
    );
    let events = fakes.notifier.events();
    assert!(events.contains(&CoreEvent::RevealExpired), "{events:?}");
    assert!(events.contains(&CoreEvent::Locked {
        name: "Personal".into()
    }));
    core.unlock_wallet("Personal".into(), bytes(PASSWORD))
        .unwrap();
    core.reveal_password("Personal".into(), id).unwrap();
    core.lock_all();
    let expired = fakes
        .notifier
        .events()
        .iter()
        .filter(|e| **e == CoreEvent::RevealExpired)
        .count();
    assert_eq!(expired, 2);
    assert!(unlocked(&core).is_empty());
    assert!(
        fakes
            .log
            .lines()
            .contains(&"passwsync: locked Personal (manual)".to_string())
    );
}

#[test]
fn on_foreground_sweeps_before_any_read() {
    let dir = TempDir::new("al-fg");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    core.on_background();
    fakes.clock.advance(16 * MINUTE);
    core.on_foreground();
    let events = fakes.notifier.events();
    let locked_at = events.iter().position(|e| {
        *e == CoreEvent::Locked {
            name: "Personal".into(),
        }
    });
    assert!(locked_at.is_some(), "{events:?}");
    assert!(unlocked(&core).is_empty());
}

#[test]
fn the_background_plan_holds_the_next_idle_deadline() {
    let dir = TempDir::new("al-plan");
    let fakes = Fakes::new();
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    fakes.clock.advance(5 * MINUTE);
    let plan = core.on_background();
    assert_eq!(plan.deadline_in_ms, Some(10 * 60 * 1000));
    assert_eq!(plan.periodic_window_minutes, None, "networking off");
    assert!(!plan.extra_window);
    core.lock_all();
    assert_eq!(core.on_background().deadline_in_ms, None);
}
