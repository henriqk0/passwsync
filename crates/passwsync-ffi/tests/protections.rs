//! FR-007, FR-008: process protections at start (data-model.md section 2). A failed core-dump
//! or non-dumpable protection blocks every secret operation with `ProtectionMissing` while
//! status, settings and the rest keep working; the memory-lock level is reported, never fatal.

mod common;

use common::{Fakes, PASSWORD, TempDir, bytes, core_with_wallet};
use passwsync_ffi::error::{CoreError, Protection};
use passwsync_ffi::protect::{self, ProcessControls};
use passwsync_ffi::records::{MemoryLockLevel, SettingsInput};
use passwsync_ffi::testkit::FakeProcess;

const MIB: u64 = 1024 * 1024;

fn level_of(process: FakeProcess) -> MemoryLockLevel {
    protect::determine(&process).memory_lock
}

#[test]
fn every_protection_working_gives_full_and_unlock_allowed() {
    let dir = TempDir::new("prot-full");
    let fakes = Fakes::new();
    let core = fakes.start(dir.path()).unwrap();
    let status = core.protection_status();
    assert!(status.core_dumps_disabled);
    assert!(status.non_dumpable);
    assert_eq!(status.memory_lock, MemoryLockLevel::Full);
    assert!(status.can_unlock);
    assert_eq!(status.missing, None);
}

#[test]
fn the_protections_run_in_the_normative_order() {
    let process = FakeProcess::new();
    protect::determine(&process);
    assert_eq!(
        process.calls(),
        ["core_dumps", "non_dumpable", "memlock_limit", "mlockall"]
    );
    // A limit below the requirement never tries mlockall; the page locker is probed instead.
    let low = FakeProcess::new().memlock_limit(Some(64 * MIB));
    protect::determine(&low);
    assert_eq!(
        low.calls(),
        ["core_dumps", "non_dumpable", "memlock_limit", "page_lock"]
    );
}

#[test]
fn memory_lock_levels() {
    assert_eq!(level_of(FakeProcess::new()), MemoryLockLevel::Full);
    assert_eq!(
        level_of(FakeProcess::new().memlock_limit(Some(256 * MIB))),
        MemoryLockLevel::Full
    );
    assert_eq!(
        level_of(FakeProcess::new().mlockall_ok(false)),
        MemoryLockLevel::SecretsOnly
    );
    assert_eq!(
        level_of(FakeProcess::new().memlock_limit(Some(64 * 1024))),
        MemoryLockLevel::SecretsOnly
    );
    assert_eq!(
        level_of(
            FakeProcess::new()
                .memlock_limit(Some(0))
                .page_lock_ok(false)
        ),
        MemoryLockLevel::None
    );
    assert_eq!(
        level_of(FakeProcess::new().mlockall_ok(false).page_lock_ok(false)),
        MemoryLockLevel::None
    );
}

#[test]
fn no_memory_lock_still_allows_unlock() {
    let dir = TempDir::new("prot-none");
    let fakes = Fakes::with_process(FakeProcess::new().mlockall_ok(false).page_lock_ok(false));
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    assert_eq!(core.protection_status().memory_lock, MemoryLockLevel::None);
    assert!(core.protection_status().can_unlock);
    core.lock_wallet("Personal".into()).unwrap();
    core.unlock_wallet("Personal".into(), bytes(PASSWORD))
        .unwrap();
}

fn refused(which: Protection) {
    let dir = TempDir::new("prot-missing");
    // First a wallet made while every protection works.
    {
        let fakes = Fakes::new();
        let core = core_with_wallet(dir.path(), &fakes, "Personal");
        drop(core);
    }
    let fakes = Fakes::with_process(FakeProcess::new().fail(which));
    let core = fakes.start(dir.path()).unwrap();
    let status = core.protection_status();
    assert!(!status.can_unlock);
    assert_eq!(status.missing, Some(which));
    let want = Err(CoreError::ProtectionMissing { which });
    assert_eq!(
        core.create_wallet("Other".into(), bytes(PASSWORD), bytes(PASSWORD)),
        want
    );
    assert_eq!(core.unlock_wallet("Personal".into(), bytes(PASSWORD)), want);
    assert_eq!(
        core.change_password(
            "Personal".into(),
            bytes(PASSWORD),
            bytes("a new long master password"),
            bytes("a new long master password"),
        ),
        want
    );
    // Status, listing and settings still work.
    let names: Vec<_> = core
        .list_wallets()
        .unwrap()
        .into_iter()
        .map(|w| w.name)
        .collect();
    assert_eq!(names, ["Personal"]);
    assert_eq!(core.settings().auto_lock_minutes, 15);
    core.update_settings(SettingsInput {
        auto_lock_minutes: 10,
        clipboard_clear_seconds: 30,
        device_name: None,
        sync_interval_minutes: 60,
        network_interface: None,
    })
    .unwrap();
    core.lock_all();
}

#[test]
fn core_dumps_failing_refuses_every_secret_operation() {
    refused(Protection::CoreDumps);
}

#[test]
fn non_dumpable_failing_refuses_every_secret_operation() {
    refused(Protection::NonDumpable);
}

#[test]
fn the_first_failed_protection_is_named() {
    let both = FakeProcess::new()
        .fail(Protection::CoreDumps)
        .fail(Protection::NonDumpable);
    let status = protect::determine(&both);
    assert!(!status.core_dumps_disabled && !status.non_dumpable);
    assert_eq!(status.missing, Some(Protection::CoreDumps));
}

#[test]
fn exactly_one_protection_level_line_per_start_and_no_secret() {
    let dir = TempDir::new("prot-log");
    let fakes = Fakes::with_process(FakeProcess::new().mlockall_ok(false));
    let core = core_with_wallet(dir.path(), &fakes, "Personal");
    let _ = core.protection_status();
    let _ = core.protection_status();
    let lines = fakes.log.lines();
    let level: Vec<_> = lines
        .iter()
        .filter(|l| l.contains("protection level"))
        .collect();
    assert_eq!(level, ["passwsync: protection level secrets-only"]);
    assert!(lines.iter().all(|l| !l.contains(PASSWORD)), "{lines:?}");
}

#[test]
fn the_real_controls_implement_the_trait() {
    // Compile-time: the production implementation is a `ProcessControls`. Not called here:
    // it would change this test process.
    fn takes(_: &dyn ProcessControls) {}
    takes(&protect::OsProcess);
}
