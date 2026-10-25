//! 005 T041 (US1) and T080 (US5): two real service instances over loopback share a wallet.

mod common;

use std::fs;
use std::time::Duration;

use common::server::wait_for;
use common::share::*;
use common::sync::*;

fn received_dir(i: &Instance) -> std::path::PathBuf {
    i.server.fx.home.join(".local/share/passwsync/received")
}

#[test]
fn a_wallet_shared_by_paired_list_opens_on_the_recipient_with_identical_credentials() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    a.add(
        "Personal",
        "Bank",
        "me@bank",
        "s3cret-1",
        "https://bank.example",
        "n1",
    );
    a.add("Personal", "Mail", "me@mail", "s3cret-2", "", "");
    let code = invite_code(&a, "Personal", &b.device_id());
    assert_eq!(receive(&b, &code, Some(&a.device_id()), None).status, 202);
    assert!(wait_invitation(&a, "awaiting_acceptance"));
    assert_eq!(accept(&a, &b.device_id()).status, 200);
    assert!(wait_receive(&b, "stored"), "{}", share_state(&b));
    assert!(wait_invitation(&a, "completed"));
    let listed = received(&b);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["sender"]["device_id"], a.device_id().as_str());
    let id = listed[0]["id"].as_str().unwrap().to_string();
    // Only ciphertext at rest on B before opening.
    let pwsw = fs::read(received_dir(&b).join(format!("{id}.pwsw"))).unwrap();
    assert_eq!(pwsw, fs::read(a.wallet_file("Personal")).unwrap());
    assert!(!contains(&pwsw, b"Bank") && !contains(&pwsw, b"s3cret-1"));

    let resp = open_received(&b, &id, "Shared", PASSWORD);
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(b.titles("Shared"), a.titles("Personal"));
    assert_eq!(b.titles("Shared"), ["Bank", "Mail"]);
    // The stored file is byte for byte what A sent.
    assert_eq!(
        fs::read(b.wallet_file("Shared")).unwrap(),
        fs::read(a.wallet_file("Personal")).unwrap()
    );
    // The received files are gone; the invitation cannot be used again.
    assert_eq!(fs::read_dir(received_dir(&b)).unwrap().count(), 0);
    assert!(received(&b).is_empty());
    assert_eq!(receive(&b, &code, Some(&a.device_id()), None).status, 202);
    assert!(wait_receive(&b, "failed"));
    assert_eq!(share_state(&b)["receive"]["reason"], "invalid");
    assert_eq!(
        invitation_state(&a),
        "completed",
        "still the completed result"
    );
}

#[test]
fn a_wallet_shared_by_manual_address_arrives_too() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    a.add("Personal", "Bank", "u", "p", "", "");
    let code = invite_code(&a, "Personal", &b.device_id());
    let addr = format!("127.0.0.1:{}", a.peer_port);
    assert_eq!(receive(&b, &code, None, Some(&addr)).status, 202);
    assert!(
        wait_invitation(&a, "awaiting_acceptance"),
        "{}",
        share_state(&a)
    );
    assert_eq!(accept(&a, &b.device_id()).status, 200);
    assert!(wait_receive(&b, "stored"), "{}", share_state(&b));
    let id = received(&b)[0]["id"].as_str().unwrap().to_string();
    assert_eq!(open_received(&b, &id, "Copy", PASSWORD).status, 200);
    assert!(wait_for(Duration::from_secs(2), || b.titles("Copy") == ["Bank"]));
}

// --- 005 T080 (US5) ---

fn sync_reasons(i: &Instance) -> Vec<String> {
    i.api("GET", "/api/state", None).json()["wallets"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|w| w["sync"]["reason"].as_str().map(str::to_string))
        .collect()
}

#[test]
fn a_wallet_already_held_opens_as_already_present_and_keeps_syncing() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    a.add("Personal", "Bank", "u", "p", "", "");
    copy_wallet_file(&a, &b, "Personal");
    b.unlock("Personal"); // B holds it with a 004 sync record
    let id = share_to(&a, &b, "Personal");
    let resp = open_received(&b, &id, "Copy", PASSWORD);
    assert_eq!(resp.status, 409, "{}", resp.text());
    assert_eq!(resp.json()["existing"], "Personal");
    assert!(!b.wallet_file("Copy").exists());
    a.add("Personal", "Mail", "u", "p", "", "");
    assert!(wait_for(Duration::from_secs(15), || b.titles("Personal")
        == ["Bank", "Mail"]));
}

#[test]
fn a_corrupted_received_file_gives_the_generic_error_and_can_be_discarded() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    let id = share_to(&a, &b, "Personal");
    let path = received_dir(&b).join(format!("{id}.pwsw"));
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x10;
    fs::write(&path, bytes).unwrap();
    let resp = open_received(&b, &id, "Shared", PASSWORD);
    assert_eq!(resp.status, 422);
    assert_eq!(resp.error_code(), "invalid_password_or_corrupted");
    assert_eq!(
        b.api("POST", &format!("/api/received/{id}/discard"), None)
            .status,
        200
    );
    assert!(received(&b).is_empty());
    assert!(!b.wallet_file("Shared").exists());
}

#[test]
fn a_wallet_held_but_never_unlocked_ends_as_duplicate_without_data_loss() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    a.add("Personal", "Bank", "u", "p", "", "");
    copy_wallet_file(&a, &b, "Personal"); // held, never unlocked: no sync record
    let id = share_to(&a, &b, "Personal");
    assert_eq!(open_received(&b, &id, "Second", PASSWORD).status, 200);
    b.unlock("Personal");
    assert!(
        wait_for(Duration::from_secs(5), || sync_reasons(&b)
            .contains(&"duplicate_wallet_id".to_string())),
        "{:?}",
        b.api("GET", "/api/state", None).json()
    );
    assert_eq!(b.titles("Personal"), ["Bank"]);
    assert_eq!(b.titles("Second"), ["Bank"]);
}

#[test]
fn a_copy_sent_before_a_password_change_opens_with_the_old_password() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    a.add("Personal", "Bank", "u", "p", "", "");
    let id = share_to(&a, &b, "Personal");
    // A changes the master password afterwards (the received bytes are what was sent).
    let mut vault = vault_core::Vault::unlock(
        &fs::read(a.wallet_file("Personal")).unwrap(),
        vault_core::MasterPassword::new(PASSWORD.into()),
        vault_core::DeviceId::new("laptop").unwrap(),
        Box::new(vault_core::FixedClock::new(10)),
    )
    .unwrap();
    vault
        .change_master_password(vault_core::MasterPassword::new(
            "a brand new password".into(),
        ))
        .unwrap();
    fs::write(a.wallet_file("Personal"), vault.seal().unwrap()).unwrap();
    let resp = open_received(&b, &id, "Shared", PASSWORD);
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(b.titles("Shared"), ["Bank"]);
}
