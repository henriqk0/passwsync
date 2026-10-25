//! 004 T065 (FR-001, US6 scenario 3): revoking a peer stops sync at once, deletes its pending
//! copies and its lines in every record; an unpinned peer never syncs.

mod common;

use std::fs;
use std::time::Duration;

use common::server::wait_for;
use common::sync::*;

const WALLET: &str = "Personal";

fn record_texts(i: &Instance) -> Vec<String> {
    let dir = i.server.fx.home.join(".local/share/passwsync/sync");
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        if let Ok(text) = fs::read_to_string(entry.path().join("record")) {
            out.push(text);
        }
    }
    out
}

fn pending_files(i: &Instance) -> usize {
    let dir = i.server.fx.home.join(".local/share/passwsync/sync");
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .flat_map(|d| fs::read_dir(d.path()).into_iter().flatten().flatten())
        .filter(|f| f.file_name().to_string_lossy().starts_with("pending-"))
        .count()
}

#[test]
fn revoking_a_peer_stops_sync_and_drops_its_pending_copies() {
    let a = instance("Laptop");
    let b = instance("Phone");
    a.create_wallet(WALLET);
    pair_via(&a, &b, a.peer_port);
    copy_wallet_file(&a, &b, WALLET);
    b.unlock(WALLET);
    // B locks; A changes: B stores A's copy as pending.
    assert_eq!(
        b.api("POST", &format!("/api/wallets/{WALLET}/lock"), None)
            .status,
        200
    );
    a.add(WALLET, "Only on A", "", "", "", "");
    assert!(
        wait_for(Duration::from_secs(10), || pending_files(&b) == 1),
        "B log:\n{}",
        b.server.log_text()
    );
    let a_id = a.device_id();
    assert!(
        record_texts(&b)
            .iter()
            .any(|t| t.contains(&format!("pending {a_id}")))
    );
    let before = fs::read(b.wallet_file(WALLET)).unwrap();

    // B revokes A.
    let resp = b.api("POST", &format!("/api/devices/{a_id}/revoke"), None);
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(
        pending_files(&b),
        0,
        "pending copies of a revoked peer are deleted"
    );
    for text in record_texts(&b) {
        assert!(!text.contains(&a_id), "peer lines removed");
    }
    // Nothing flows any more: A keeps editing, B's files do not change.
    a.add(WALLET, "After revoke", "", "", "", "");
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(pending_files(&b), 0);
    assert_eq!(fs::read(b.wallet_file(WALLET)).unwrap(), before);
    // The revoked device is no longer pinned on B and its channel is gone: an unpinned key
    // can never open a channel again (003 refuses it), so no sync frame can flow.
    assert_eq!(
        net(&b.server, &b.session)["paired"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert!(wait_for(Duration::from_secs(10), || {
        net(&a.server, &a.session)["paired"][0]["status"] != "connected"
    }));
}
