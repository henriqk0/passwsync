//! 005 T021: the file adapter of the `ReceivedStore` port (contracts/host-runtime-share.md
//! "Files (added)").

mod common;

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use common::{TempDir, mode, set_mode};
use passwsyncd::paths::{Env, Paths};
use passwsyncd::share_store::{FsReceivedStore, ReceiveFault, encode_meta};
use wallet_sync::ports::{PeerId, ReceivedMeta, ReceivedStore, StoreError};

const SENDER: PeerId = PeerId([0x42; 32]);
const ID: [u8; 16] = [0x0f; 16];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn store(root: &TempDir) -> FsReceivedStore {
    let s = FsReceivedStore::new(root.path().join("received"));
    s.prepare().unwrap();
    s
}

fn file(root: &TempDir, id: [u8; 16], ext: &str) -> PathBuf {
    root.path()
        .join("received")
        .join(format!("{}.{ext}", hex(&id)))
}

fn ciphertext(len: usize) -> Vec<u8> {
    let mut bytes = b"PWSV\x02\x00".to_vec();
    bytes.resize(len, 0xC3);
    bytes
}

fn receive(s: &FsReceivedStore, id: [u8; 16], at: u64, bytes: &[u8]) -> Result<(), StoreError> {
    let mut w = s.begin(id, SENDER, at)?;
    for chunk in bytes.chunks(1000) {
        w.append(chunk)?;
    }
    w.finish()
}

fn names(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    out.sort();
    out
}

#[test]
fn the_received_path_lives_under_the_data_home() {
    let root = TempDir::new("share-paths");
    let env = Env {
        home: Some(root.path().to_path_buf()),
        xdg_config_home: None,
        xdg_data_home: Some(root.path().join("data")),
        xdg_runtime_dir: Some(root.path().join("run")),
    };
    let paths = Paths::resolve(&env).unwrap();
    assert_eq!(
        paths.received_dir,
        root.path().join("data/passwsync/received")
    );
}

#[test]
fn directory_0700_and_files_0600_with_the_documented_write_order() {
    let root = TempDir::new("share-store");
    let s = store(&root);
    let dir = root.path().join("received");
    assert_eq!(mode(&dir), 0o700);
    let bytes = ciphertext(2345);
    let mut w = s.begin(ID, SENDER, 1_761_400_000).unwrap();
    w.append(&bytes[..1000]).unwrap();
    // While receiving only the partial file exists, owner-only.
    assert_eq!(names(&dir), [format!("{}.part", hex(&ID))]);
    assert_eq!(mode(&file(&root, ID, "part")), 0o600);
    assert!(s.list().unwrap().is_empty());
    w.append(&bytes[1000..]).unwrap();
    w.finish().unwrap();
    assert_eq!(
        names(&dir),
        [format!("{}.meta", hex(&ID)), format!("{}.pwsw", hex(&ID))]
    );
    assert_eq!(mode(&file(&root, ID, "pwsw")), 0o600);
    assert_eq!(mode(&file(&root, ID, "meta")), 0o600);
    assert_eq!(
        fs::read(file(&root, ID, "pwsw")).unwrap(),
        bytes,
        "verbatim"
    );
    assert_eq!(
        s.list().unwrap(),
        vec![ReceivedMeta {
            id: ID,
            sender: SENDER,
            received_at: 1_761_400_000,
            size: 2345,
        }]
    );
    assert_eq!(s.read(ID).unwrap(), bytes);
    s.delete(ID).unwrap();
    assert!(names(&dir).is_empty());
    assert_eq!(s.delete(ID), Err(StoreError::NotFound));
    assert_eq!(s.read(ID), Err(StoreError::NotFound));
}

#[test]
fn the_meta_text_format_holds_only_non_secret_facts() {
    let root = TempDir::new("share-meta");
    let s = store(&root);
    receive(&s, ID, 1_761_400_123, &ciphertext(500)).unwrap();
    let text = fs::read_to_string(file(&root, ID, "meta")).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 5, "{text}");
    assert_eq!(lines[0], "passwsync-received-v1");
    assert_eq!(lines[1], format!("sender {}", SENDER.to_hex()));
    assert_eq!(lines[2], "received 1761400123");
    assert_eq!(lines[3], "size 500");
    let check = lines[4].strip_prefix("check ").unwrap();
    assert_eq!(check.len(), 64);
    let preceding = &text[..text.find("check ").unwrap()];
    use sha2::{Digest, Sha256};
    assert_eq!(check, hex(&Sha256::digest(preceding.as_bytes())));
    assert!(text.ends_with('\n'));
    assert!(text.len() <= 1024);
    assert_eq!(
        encode_meta(&ReceivedMeta {
            id: ID,
            sender: SENDER,
            received_at: 1_761_400_123,
            size: 500,
        }),
        text
    );
    for forbidden in ["wallet", "name", "code", "password", &hex(&ID)] {
        assert!(!text.contains(forbidden), "{forbidden} in meta");
    }
}

#[test]
fn a_permissive_or_foreign_directory_is_unusable_and_never_rewritten() {
    let root = TempDir::new("share-perm");
    let dir = root.path().join("received");
    fs::create_dir(&dir).unwrap();
    set_mode(&dir, 0o755);
    let s = FsReceivedStore::new(dir.clone());
    assert_eq!(s.prepare(), Err(StoreError::Corrupted));
    assert_eq!(mode(&dir), 0o755, "left as it is");
    assert_eq!(s.list(), Err(StoreError::Corrupted));
    assert!(s.begin(ID, SENDER, 1).is_err());
    assert!(names(&dir).is_empty(), "nothing written");
    // A symlink in place of the directory is refused too.
    let target = TempDir::new("share-target");
    let link = root.path().join("received-link");
    symlink(target.path(), &link).unwrap();
    assert_eq!(
        FsReceivedStore::new(link).prepare(),
        Err(StoreError::Corrupted)
    );
}

#[test]
fn list_skips_and_reports_unparsable_entries() {
    let root = TempDir::new("share-list");
    let s = store(&root);
    receive(&s, [1; 16], 10, &ciphertext(300)).unwrap();
    receive(&s, [2; 16], 20, &ciphertext(300)).unwrap();
    receive(&s, [3; 16], 30, &ciphertext(300)).unwrap();
    // [2]: checksum broken; [3]: size differs from the file.
    let meta2 = file(&root, [2; 16], "meta");
    let text = fs::read_to_string(&meta2)
        .unwrap()
        .replace("received 20", "received 21");
    fs::write(&meta2, text).unwrap();
    fs::write(file(&root, [3; 16], "pwsw"), ciphertext(299)).unwrap();
    let (listed, skipped) = s.list_report().unwrap();
    assert_eq!(
        listed.iter().map(|m| m.id).collect::<Vec<_>>(),
        vec![[1; 16]]
    );
    assert_eq!(skipped, 2);
    assert_eq!(s.list().unwrap().len(), 1);
    // Unrelated names are ignored entirely.
    fs::write(root.path().join("received/notes.txt"), b"x").unwrap();
    assert_eq!(s.list_report().unwrap().1, 2);
}

#[test]
fn faults_at_every_step_leave_no_usable_partial_file() {
    for fault in [
        ReceiveFault::Create,
        ReceiveFault::Append,
        ReceiveFault::Fsync,
        ReceiveFault::Rename,
        ReceiveFault::DirFsync,
        ReceiveFault::MetaWrite,
    ] {
        let root = TempDir::new("share-fault");
        let s = store(&root);
        s.inject(fault);
        assert!(
            receive(&s, ID, 5, &ciphertext(1500)).is_err(),
            "{fault:?} must fail"
        );
        assert!(
            names(&root.path().join("received")).is_empty(),
            "{fault:?}: {:?}",
            names(&root.path().join("received"))
        );
        assert!(s.list().unwrap().is_empty());
    }
}

#[test]
fn a_dropped_writer_deletes_its_partial_file() {
    let root = TempDir::new("share-drop");
    let s = store(&root);
    let mut w = s.begin(ID, SENDER, 1).unwrap();
    w.append(&ciphertext(100)).unwrap();
    drop(w);
    assert!(names(&root.path().join("received")).is_empty());
    let mut w = s.begin(ID, SENDER, 1).unwrap();
    w.append(&ciphertext(100)).unwrap();
    w.abort();
    assert!(names(&root.path().join("received")).is_empty());
}
