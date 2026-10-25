//! 005 T049 (US2, FR-021, SC-005): an unopened received wallet takes no part in sync; once
//! opened it syncs both ways, including the sender's changes made in between.

mod common;

use std::fs;
use std::time::Duration;

use common::server::wait_for;
use common::share::*;
use common::sync::*;

fn sync_entries(i: &Instance) -> usize {
    let dir = i.server.fx.home.join(".local/share/passwsync/sync");
    fs::read_dir(dir).map_or(0, |d| d.count())
}

#[test]
fn unopened_received_wallets_are_not_synced_and_opened_ones_converge() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    a.add("Personal", "Bank", "u", "p", "", "");
    let id = share_to(&a, &b, "Personal");
    assert_eq!(sync_entries(&b), 0);

    // Edits on A while B has only the received (unopened) copy.
    a.add("Personal", "Mail", "u", "p", "", "");
    assert_eq!(
        a.api("POST", "/api/sync/now", Some(r#"{"wallet":null}"#))
            .status,
        202
    );
    std::thread::sleep(Duration::from_millis(800));
    assert_eq!(sync_entries(&b), 0, "nothing under B's sync/");
    let state = b.api("GET", "/api/state", None).json();
    assert_eq!(state["wallets"], serde_json::json!([]), "not a wallet yet");
    let sync = b.api("GET", "/api/sync", None).json();
    assert!(
        !sync.to_string().contains("Personal"),
        "absent from B's sync status: {sync}"
    );
    assert!(!b.server.log_text().contains("sync pending stored"));
    assert!(!a.server.log_text().contains("sync pending stored"));

    // Opened: B catches up with A's later change, and B's edits reach A.
    assert_eq!(open_received(&b, &id, "Personal", PASSWORD).status, 200);
    assert!(
        wait_for(Duration::from_secs(15), || b.titles("Personal")
            == ["Bank", "Mail"]),
        "B: {:?}\n{}",
        b.titles("Personal"),
        b.server.log_text()
    );
    b.add("Personal", "From B", "u", "p", "", "");
    assert!(wait_for(Duration::from_secs(15), || a.titles("Personal")
        == ["Bank", "From B", "Mail"]));
}
