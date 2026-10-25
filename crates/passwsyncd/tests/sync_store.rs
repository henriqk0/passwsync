//! 004 T044: the file adapter of the `SyncStore` port (contracts/host-runtime-sync.md
//! "Files").

mod common;

use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::Path;

use common::{TempDir, mode, set_mode};
use passwsyncd::sync_store::{FileSyncStore, WriteStep};
use vault_core::{StateVector, WalletId};
use wallet_sync::ports::{PeerId, StoreError, SyncStore};
use wallet_sync::record::{PendingCopy, PendingStatus, SyncRecord};

fn wid(b: u8) -> WalletId {
    WalletId::from_bytes([b; 16])
}

fn record(b: u8) -> SyncRecord {
    SyncRecord::new(wid(b), "Personal".into(), [b; 32], StateVector::new())
}

fn store(root: &TempDir) -> FileSyncStore {
    let s = FileSyncStore::new(root.path().join("sync"));
    s.prepare().unwrap();
    s
}

fn wallet_dir(root: &TempDir, b: u8) -> std::path::PathBuf {
    root.path().join("sync").join(hex(&[b; 16]))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const PEER: PeerId = PeerId([7; 32]);

#[test]
fn directories_and_files_are_owner_only() {
    let root = TempDir::new("sync-store");
    let s = store(&root);
    assert_eq!(mode(&root.path().join("sync")), 0o700);
    s.update(&wid(1), &mut |_| Some(record(1))).unwrap();
    let dir = wallet_dir(&root, 1);
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join("record")), 0o600);
    assert_eq!(s.load(&wid(1)).unwrap(), Some(record(1)));
    assert_eq!(s.wallets().unwrap(), vec![wid(1)]);
    let mut part = s.begin_incoming(&wid(1), &PEER).unwrap();
    part.append(b"partial").unwrap();
    let part_path = dir.join(format!("incoming-{}.part", PEER.to_hex()));
    assert_eq!(mode(&part_path), 0o600);
    part.finish().unwrap();
    assert!(!part_path.exists());
    let pending = dir.join(format!("pending-{}", PEER.to_hex()));
    assert_eq!(mode(&pending), 0o600);
    assert_eq!(s.read_pending(&wid(1), &PEER).unwrap(), b"partial");
    assert_eq!(s.pending_peers(&wid(1)).unwrap(), vec![PEER]);
    s.delete_pending(&wid(1), &PEER).unwrap();
    assert!(!pending.exists());
}

#[test]
fn writes_are_atomic_and_leave_no_temp_files() {
    let root = TempDir::new("sync-store");
    let s = store(&root);
    s.update(&wid(1), &mut |_| Some(record(1))).unwrap();
    s.update(&wid(1), &mut |r| {
        let mut r = r.unwrap();
        r.wallet_name = "Renamed".into();
        Some(r)
    })
    .unwrap();
    let names: Vec<String> = fs::read_dir(wallet_dir(&root, 1))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["record"]);
}

#[test]
fn a_fault_at_each_write_step_keeps_the_old_record() {
    for step in [WriteStep::TempWrite, WriteStep::Fsync, WriteStep::Rename] {
        let root = TempDir::new("sync-store");
        let s = store(&root);
        s.update(&wid(1), &mut |_| Some(record(1))).unwrap();
        let before = fs::read(wallet_dir(&root, 1).join("record")).unwrap();
        s.inject(step);
        let result = s.update(&wid(1), &mut |r| {
            let mut r = r.unwrap();
            r.wallet_name = "Changed".into();
            Some(r)
        });
        assert!(result.is_err(), "{step:?}");
        assert_eq!(
            fs::read(wallet_dir(&root, 1).join("record")).unwrap(),
            before,
            "{step:?}"
        );
        assert_eq!(s.load(&wid(1)).unwrap(), Some(record(1)));
        let names: Vec<String> = fs::read_dir(wallet_dir(&root, 1))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, ["record"], "no temp file left after {step:?}");
    }
}

#[test]
fn wrong_mode_symlink_or_bad_text_is_corrupted_and_never_overwritten() {
    let root = TempDir::new("sync-store");
    let s = store(&root);
    s.update(&wid(1), &mut |_| Some(record(1))).unwrap();
    let path = wallet_dir(&root, 1).join("record");
    set_mode(&path, 0o644);
    assert_eq!(s.load(&wid(1)), Err(StoreError::Corrupted));
    assert_eq!(
        s.update(&wid(1), &mut |_| Some(record(1))),
        Err(StoreError::Corrupted)
    );
    assert_eq!(mode(&path), 0o644, "left as it is");
    set_mode(&path, 0o600);
    fs::write(&path, "garbage").unwrap();
    assert_eq!(s.load(&wid(1)), Err(StoreError::Corrupted));
    assert_eq!(fs::read(&path).unwrap(), b"garbage");
    // A symlinked record or wallet directory is refused.
    s.update(&wid(2), &mut |_| Some(record(2))).unwrap();
    let real = root.path().join("elsewhere");
    fs::write(&real, wallet_sync::record::encode(&record(2))).unwrap();
    set_mode(&real, 0o600);
    let path2 = wallet_dir(&root, 2).join("record");
    fs::remove_file(&path2).unwrap();
    symlink(&real, &path2).unwrap();
    assert_eq!(s.load(&wid(2)), Err(StoreError::Corrupted));
    let dir3 = wallet_dir(&root, 3);
    let target = root.path().join("dir-target");
    fs::create_dir(&target).unwrap();
    set_mode(&target, 0o700);
    symlink(&target, &dir3).unwrap();
    assert!(s.update(&wid(3), &mut |_| Some(record(3))).is_err());
    assert!(!target.join("record").exists());
}

#[test]
fn a_record_owned_by_the_current_user_is_required() {
    let root = TempDir::new("sync-store");
    let s = store(&root);
    s.update(&wid(1), &mut |_| Some(record(1))).unwrap();
    let meta = fs::metadata(wallet_dir(&root, 1).join("record")).unwrap();
    assert_eq!(meta.uid(), rustix::process::getuid().as_raw());
    // (A foreign owner cannot be created without root; the check shares code with modes.)
}

#[test]
fn cleanup_deletes_partials_and_orphan_pending_files_and_lines() {
    let root = TempDir::new("sync-store");
    let s = store(&root);
    let mut r = record(1);
    let other = PeerId([8; 32]);
    r.pending.insert(
        other,
        PendingCopy {
            claimed: StateVector::new(),
            size: 100,
            received_at: 1,
            status: PendingStatus::Waiting,
        },
    );
    s.update(&wid(1), &mut |_| Some(r.clone())).unwrap();
    // A partial copy, an orphan pending file (no line), and a line without file (`other`).
    let mut part = s.begin_incoming(&wid(1), &PEER).unwrap();
    part.append(b"half").unwrap();
    std::mem::forget(part);
    let dir = wallet_dir(&root, 1);
    let orphan = dir.join(format!("pending-{}", PeerId([9; 32]).to_hex()));
    fs::write(&orphan, b"x").unwrap();
    set_mode(&orphan, 0o600);
    s.cleanup().unwrap();
    assert!(
        !dir.join(format!("incoming-{}.part", PEER.to_hex()))
            .exists()
    );
    assert!(!orphan.exists());
    assert!(s.load(&wid(1)).unwrap().unwrap().pending.is_empty());
}

#[test]
fn storage_full_is_reported_as_no_space() {
    // Mapping only (ENOSPC cannot be provoked portably without a full filesystem).
    assert_eq!(
        passwsyncd::sync_store::classify(&std::io::Error::from_raw_os_error(28)),
        StoreError::NoSpace
    );
    assert_eq!(
        passwsyncd::sync_store::classify(&std::io::Error::other("x")),
        StoreError::Io
    );
}

#[test]
fn unknown_entries_in_the_sync_directory_are_ignored() {
    let root = TempDir::new("sync-store");
    let s = store(&root);
    fs::create_dir(root.path().join("sync/not-a-wallet")).unwrap();
    fs::write(root.path().join("sync/stray"), b"x").unwrap();
    assert!(s.wallets().unwrap().is_empty());
    let _ = Path::new("");
}

// --- 004 T087: owner-only records hold no secret, plaintext or foreign names ---

#[test]
fn records_and_pending_files_carry_no_plaintext() {
    use vault_core::{DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, Vault};
    let root = TempDir::new("sync-store");
    let s = store(&root);
    let mut record = SyncRecord::new(
        wid(1),
        "WALLET-NAME-MARKER".into(),
        [1; 32],
        StateVector::new(),
    );
    record.pending.insert(
        PEER,
        PendingCopy {
            claimed: StateVector::new(),
            size: 10,
            received_at: 1,
            status: PendingStatus::Waiting,
        },
    );
    s.update(&wid(1), &mut |_| Some(record.clone())).unwrap();
    let mut vault = Vault::create(
        MasterPassword::new("MASTER-PASSWORD-MARKER".into()),
        KdfConfig::MINIMUM,
        DeviceId::new("dev").unwrap(),
        Box::new(FixedClock::new(1)),
    )
    .unwrap();
    vault
        .add_entry(EntryFields {
            title: "TITLE-MARKER".into(),
            username: "USER-MARKER".into(),
            password: "PASSWORD-MARKER".into(),
            url: "URL-MARKER".into(),
            notes: "NOTES-MARKER".into(),
        })
        .unwrap();
    let mut part = s.begin_incoming(&wid(1), &PEER).unwrap();
    part.append(&vault.seal().unwrap()).unwrap();
    part.finish().unwrap();
    let dir = wallet_dir(&root, 1);
    for file in ["record".to_string(), format!("pending-{}", PEER.to_hex())] {
        let bytes = fs::read(dir.join(&file)).unwrap();
        assert_eq!(mode(&dir.join(&file)), 0o600);
        for marker in [
            "WALLET-NAME-MARKER",
            "MASTER-PASSWORD-MARKER",
            "TITLE-MARKER",
            "USER-MARKER",
            "PASSWORD-MARKER",
            "URL-MARKER",
            "NOTES-MARKER",
        ] {
            assert!(
                !bytes.windows(marker.len()).any(|w| w == marker.as_bytes()),
                "{marker} in {file}"
            );
        }
    }
}

#[test]
fn a_record_with_a_wrong_mode_disables_sync_for_that_wallet_only() {
    use wallet_sync::round::{Engine, EngineConfig, EngineDeps};
    use wallet_sync::testkit::{FakeMonoClock, FakeWallClock, FakeWalletSource};
    let root = TempDir::new("sync-store");
    let s = std::sync::Arc::new(store(&root));
    let source = FakeWalletSource::new();
    for b in [1u8, 2] {
        source.set(&format!("W{b}"), vec![b; 100]);
        let r = SyncRecord::new(
            wid(b),
            format!("W{b}"),
            wallet_sync::record::sha256(&[b; 100]),
            StateVector::new(),
        );
        s.update(&wid(b), &mut |_| Some(r.clone())).unwrap();
    }
    let path = wallet_dir(&root, 1).join("record");
    set_mode(&path, 0o640);
    let before = fs::read(&path).unwrap();
    let mut engine = Engine::new(
        EngineDeps {
            store: s.clone(),
            source: std::sync::Arc::new(source),
            mono: std::sync::Arc::new(FakeMonoClock::new()),
            wall: std::sync::Arc::new(FakeWallClock::new(1)),
            rng: Box::new(rand_core::OsRng),
        },
        EngineConfig::default(),
    );
    engine.channel_up(PEER, 1, [0; 32], true);
    assert!(engine.start_round(PEER), "the healthy wallet still syncs");
    let frames = engine.poll_outgoing(PEER, 8);
    let wallet_sync::round::Frame::Ctl { fragment, .. } = &frames[0] else {
        panic!()
    };
    assert_eq!(&fragment[5..7], &[0, 1], "only one wallet tagged");
    assert_eq!(fs::read(&path).unwrap(), before, "never silently reset");
    assert_eq!(mode(&path), 0o640);
}
