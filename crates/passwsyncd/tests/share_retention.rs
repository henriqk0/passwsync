//! 005 T067 (US4, FR-022a, FR-023, SC-007): start-up step 5e cleans `received/`; the existing
//! sweeper tick deletes received wallets past 24 hours and ends stale redemptions; revoking a
//! sender deletes its received wallets. Nothing here stops the service.

mod common;

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::server::{Fixture, TestServer, net_config};
use common::share::*;
use device_link::files::encode_peers;
use device_link::identity::DeviceKey;
use device_link::name::DeviceName;
use device_link::registry::PeerPin;
use passwsyncd::share_store::encode_meta;
use wallet_sync::ports::{PeerId, ReceivedMeta};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    common::set_mode(path, 0o600);
}

/// A complete entry: ciphertext of `size` bytes and its meta.
fn entry(dir: &Path, id: u8, sender: PeerId, received_at: u64, size: usize) {
    let meta = ReceivedMeta {
        id: [id; 16],
        sender,
        received_at,
        size: size as u64,
    };
    private_file(
        &dir.join(format!("{}.pwsw", hex(&[id; 16]))),
        &vec![0x42; size],
    );
    private_file(
        &dir.join(format!("{}.meta", hex(&[id; 16]))),
        encode_meta(&meta).as_bytes(),
    );
}

#[test]
fn start_up_deletes_every_unusable_class_and_keeps_at_most_eight() {
    let fx = Fixture::new(&net_config());
    let pinned = DeviceKey::from_private([61; 32]);
    let pin = PeerPin {
        public: *pinned.public(),
        name: DeviceName::parse("Laptop").unwrap(),
        paired_at: 1,
        last_seen: None,
        last_addr: None,
    };
    let peers = fx.config_dir.join("peers");
    private_file(&peers, encode_peers(&[pin]).as_bytes());
    let dir = fx.home.join(".local/share/passwsync/received");
    fs::create_dir_all(&dir).unwrap();
    common::set_mode(&dir, 0o700);
    common::set_mode(dir.parent().unwrap(), 0o700);
    let sender = PeerId(*pinned.id().as_bytes());
    let stranger = PeerId([0x77; 32]);
    let t = now();
    // Ten good entries (two are the newest extras), received in order.
    for id in 1..=10u8 {
        entry(&dir, id, sender, t - 1000 + u64::from(id), 100);
    }
    // partial
    private_file(&dir.join(format!("{}.part", hex(&[20; 16]))), b"partial");
    // orphans: ciphertext without meta, meta without ciphertext
    private_file(&dir.join(format!("{}.pwsw", hex(&[21; 16]))), &[1; 100]);
    entry(&dir, 22, sender, t, 100);
    fs::remove_file(dir.join(format!("{}.pwsw", hex(&[22; 16])))).unwrap();
    // corrupted: checksum broken; size differs
    entry(&dir, 23, sender, t, 100);
    let meta = dir.join(format!("{}.meta", hex(&[23; 16])));
    let text = fs::read_to_string(&meta)
        .unwrap()
        .replace("size 100", "size 101");
    private_file(&meta, text.as_bytes());
    entry(&dir, 24, sender, t, 100);
    private_file(&dir.join(format!("{}.pwsw", hex(&[24; 16]))), &[1; 99]);
    // unpinned sender
    entry(&dir, 25, stranger, t, 100);
    // expired: older than 24 h, and more than 5 minutes in the future
    entry(&dir, 26, sender, t - 86_401, 100);
    entry(&dir, 27, sender, t + 3_600, 100);

    let server = TestServer::start_in(fx);
    let s = server.login();
    let view = server.api(&s, "GET", "/api/share", None).json();
    let ids: Vec<String> = view["received"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_string())
        .collect();
    let kept: Vec<String> = (1..=8u8).map(|id| hex(&[id; 16])).collect();
    assert_eq!(ids, kept, "the oldest eight good entries stay");
    let mut left: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    left.sort();
    assert_eq!(left.len(), 16, "{left:?}");
    let log = server.log_text();
    for (class, count) in [
        ("partial", 1),
        ("orphan", 2),
        ("corrupted", 2),
        ("unpinned", 1),
        ("expired", 2),
        ("excess", 2),
    ] {
        assert_eq!(
            log.matches(&format!("received cleaned ({class}) count={count}"))
                .count(),
            1,
            "{class}\n{log}"
        );
    }
    let notices = view["notices"].as_array().unwrap();
    let total: u64 = notices
        .iter()
        .filter(|n| n["kind"] == "received_cleaned")
        .map(|n| n["count"].as_u64().unwrap())
        .sum();
    assert_eq!(total, 10);
}

#[test]
fn a_foreign_or_permissive_received_directory_disables_sharing_without_stopping() {
    let fx = Fixture::new(&net_config());
    let dir = fx.home.join(".local/share/passwsync/received");
    fs::create_dir_all(&dir).unwrap();
    common::set_mode(dir.parent().unwrap(), 0o700);
    common::set_mode(&dir, 0o755);
    let server = TestServer::start_in(fx);
    let s = server.login();
    let view = server.api(&s, "GET", "/api/share", None).json();
    assert_eq!(view["available"], false);
    assert_eq!(view["unavailable_reason"], "received_unusable");
    assert_eq!(common::mode(&dir), 0o755, "never rewritten");
}

#[test]
fn the_sweeper_tick_deletes_received_wallets_after_24_hours() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    share_to(&a, &b, "Personal");
    assert_eq!(received(&b).len(), 1);
    b.server
        .running()
        .advance_share_clock(Duration::from_secs(86_400));
    b.server.running().share_tick_now();
    assert!(received(&b).is_empty());
    let view = share_state(&b);
    assert!(
        view["notices"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["kind"] == "received_expired"),
        "{view}"
    );
    assert!(
        b.server
            .log_text()
            .contains("received wallet discarded peer=")
    );
    assert!(b.server.log_text().contains("(expired)"));
}

#[test]
fn the_sweeper_tick_ends_a_redemption_that_waited_too_long() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    let code = invite_code(&a, "Personal", &b.device_id());
    assert_eq!(receive(&b, &code, Some(&a.device_id()), None).status, 202);
    assert!(wait_receive(&b, "awaiting_sender"));
    b.server
        .running()
        .advance_share_clock(Duration::from_secs(311));
    b.server.running().share_tick_now();
    assert_eq!(receive_state(&b), "failed");
    assert_eq!(share_state(&b)["receive"]["reason"], "timeout");
}

#[test]
fn revoking_a_sender_deletes_its_received_wallets() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    share_to(&a, &b, "Personal");
    assert_eq!(received(&b).len(), 1);
    let a_id = a.device_id();
    assert_eq!(
        b.api("POST", &format!("/api/devices/{a_id}/revoke"), None)
            .status,
        200
    );
    assert!(received(&b).is_empty());
    let dir = b.server.fx.home.join(".local/share/passwsync/received");
    assert_eq!(fs::read_dir(dir).unwrap().count(), 0);
    assert!(b.server.log_text().contains("(revoked)"));
    assert!(
        share_state(&b)["notices"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["kind"] == "received_deleted_revoked")
    );
}
