//! 007 T111 (US5; FR-047, FR-049): cores over loopback converge after edits on both within the
//! 004 timings; concurrent edits become a conflict listed, revealed, copied and resolved with
//! the desktop rules; a locked wallet stores received data as ciphertext and merges at the
//! next unlock; sync status per wallet and device; `sync_now` is foreground-only; pending
//! copies under another master password; a core syncs with a plain desktop `HostCore`.

mod common;

use std::time::Duration;

use common::*;
use passwsync_ffi::error::CoreError;
use passwsync_ffi::records::{
    ConflictChoice, CopyField, PasswordChoiceKind, PendingStatus, WalletSyncState,
};

const WALLET: &str = "Shared";
const LIMIT: Duration = Duration::from_secs(20);

#[test]
fn edits_on_both_cores_converge() {
    let _guard = serial();
    let (a, b) = synced_pair("sync-converge", WALLET);
    a.core()
        .add_credential(WALLET.into(), input("From A", "ua", Some("pa")))
        .unwrap();
    assert!(
        wait_for(LIMIT, || titles(b.core(), WALLET) == ["First", "From A"]),
        "b: {:?}",
        titles(b.core(), WALLET)
    );
    b.core()
        .add_credential(WALLET.into(), input("From B", "ub", Some("pb")))
        .unwrap();
    assert!(wait_for(LIMIT, || titles(a.core(), WALLET)
        == ["First", "From A", "From B"]));
    // Status per wallet and per device.
    let status = a.core().sync_status();
    let wallet = status.wallets.iter().find(|w| w.wallet == WALLET).unwrap();
    assert!(
        wait_for(LIMIT, || {
            a.core()
                .sync_status()
                .wallets
                .iter()
                .any(|w| w.wallet == WALLET && w.state == WalletSyncState::InSync)
        }),
        "{wallet:?}"
    );
    let b_id = b.id();
    assert!(status.peers.iter().any(|p| p.device.id == b_id));
    let listed = a.core().list_wallets().unwrap();
    assert_ne!(listed[0].sync, WalletSyncState::SyncOff);
    // "Sync now" in the foreground only.
    a.core().sync_now().unwrap();
    background(&a);
    assert_eq!(a.core().sync_now().err(), Some(CoreError::NotForeground));
    a.core().shutdown();
    b.core().shutdown();
}

#[test]
fn concurrent_edits_become_a_conflict_with_desktop_reveal_copy_and_resolve() {
    let _guard = serial();
    let (a, b) = synced_pair("sync-conflict", WALLET);
    let id = a.core().search(WALLET.into(), "First".into()).unwrap()[0]
        .id
        .clone();
    background(&a);
    background(&b);
    a.core()
        .update_credential(
            WALLET.into(),
            id.clone(),
            input("Edit A", "ua", Some("conflict-pw-a")),
        )
        .unwrap();
    b.core()
        .update_credential(
            WALLET.into(),
            id.clone(),
            input("Edit B", "ub", Some("conflict-pw-b")),
        )
        .unwrap();
    a.core().on_foreground();
    b.core().on_foreground();
    assert!(
        wait_for(LIMIT, || a
            .core()
            .conflicts(WALLET.into())
            .is_ok_and(|c| c.len() == 1)),
        "a: {:?}",
        a.core().conflicts(WALLET.into()).map(|c| c.len())
    );
    let conflict = &a.core().conflicts(WALLET.into()).unwrap()[0];
    assert_eq!(conflict.id, id);
    assert_eq!(conflict.versions, 2);
    let versions = a
        .core()
        .conflict_versions(WALLET.into(), id.clone())
        .unwrap();
    assert_eq!(versions.len(), 2);
    let mut seen: Vec<String> = versions.iter().map(|v| v.title.clone()).collect();
    seen.sort();
    assert_eq!(seen, ["Edit A", "Edit B"]);
    // Desktop parity: reveal and copy one version's password with the 002 rules.
    let ticket = a
        .core()
        .reveal_conflict_password(WALLET.into(), id.clone(), 1)
        .unwrap();
    assert!(ticket.password == b"conflict-pw-a" || ticket.password == b"conflict-pw-b");
    assert!(ticket.hide_in_ms > 0);
    let copy = a
        .core()
        .copy_conflict_field(WALLET.into(), id.clone(), 0, CopyField::Password)
        .unwrap();
    assert!(copy.clear_in_ms > 0);
    let clip = a.fakes.clipboard.current().unwrap();
    assert!(clip == b"conflict-pw-a" || clip == b"conflict-pw-b");
    assert!(a.core().clipboard_pending_ms().is_some());
    assert!(matches!(
        a.core()
            .reveal_conflict_password(WALLET.into(), id.clone(), 9),
        Err(CoreError::InvalidVersionIndex)
    ));
    a.core()
        .resolve_conflict(WALLET.into(), id.clone(), ConflictChoice::Keep { index: 0 })
        .unwrap();
    assert!(a.core().conflicts(WALLET.into()).unwrap().is_empty());
    assert_eq!(
        a.core()
            .resolve_conflict(WALLET.into(), id, ConflictChoice::Both)
            .err(),
        Some(CoreError::NotConflicted)
    );
    a.core().shutdown();
    b.core().shutdown();
}

#[test]
fn a_locked_wallet_keeps_received_data_encrypted_and_merges_at_unlock() {
    let _guard = serial();
    let (a, b) = synced_pair("sync-locked", WALLET);
    b.core().lock_wallet(WALLET.into()).unwrap();
    a.core()
        .add_credential(WALLET.into(), input("Marker Locked Title", "u", Some("p")))
        .unwrap();
    // The copy arrives while locked: a pending copy, ciphertext only.
    assert!(
        wait_for(LIMIT, || b
            .core()
            .pending_copies(WALLET.into())
            .is_ok_and(|p| !p.is_empty())),
        "pending copy"
    );
    let pending = b.core().pending_copies(WALLET.into()).unwrap();
    assert_eq!(pending[0].peer.id, a.id());
    assert_eq!(pending[0].status, PendingStatus::Waiting);
    for (path, is_dir, _) in tree(b.dir.path()) {
        if !is_dir {
            let bytes = std::fs::read(b.dir.path().join(&path)).unwrap();
            assert!(
                !String::from_utf8_lossy(&bytes).contains("Marker Locked Title"),
                "{path} holds plaintext"
            );
        }
    }
    b.core()
        .unlock_wallet(WALLET.into(), bytes(PASSWORD))
        .unwrap();
    assert!(wait_for(LIMIT, || titles(b.core(), WALLET)
        == ["First", "Marker Locked Title"]));
    a.core().shutdown();
    b.core().shutdown();
}

#[test]
fn a_copy_under_another_master_password_opens_with_that_password() {
    let _guard = serial();
    let (a, b) = synced_pair("sync-pending", WALLET);
    background(&b);
    a.core()
        .change_password(
            WALLET.into(),
            bytes(PASSWORD),
            bytes(OTHER_PASSWORD),
            bytes(OTHER_PASSWORD),
        )
        .unwrap();
    a.core()
        .add_credential(WALLET.into(), input("After Change", "u", Some("p")))
        .unwrap();
    b.core().on_foreground();
    assert!(
        wait_for(LIMIT, || b.core().pending_copies(WALLET.into()).is_ok_and(
            |p| p.iter().any(|c| c.status == PendingStatus::CannotOpen)
        )),
        "{:?}",
        b.core().pending_copies(WALLET.into()).map(|p| p.len())
    );
    assert_eq!(
        b.core()
            .open_pending_with_password(WALLET.into(), a.id(), bytes("wrong password here"))
            .err(),
        Some(CoreError::InvalidPasswordOrCorrupted)
    );
    b.core()
        .open_pending_with_password(WALLET.into(), a.id(), bytes(OTHER_PASSWORD))
        .unwrap();
    assert_eq!(titles(b.core(), WALLET), ["After Change", "First"]);
    // The password choice applies to concurrent password changes only.
    assert!(
        b.core()
            .resolve_password_choice(
                WALLET.into(),
                a.id(),
                PasswordChoiceKind::Local,
                bytes(OTHER_PASSWORD)
            )
            .is_err()
    );
    a.core().shutdown();
    b.core().shutdown();
}

#[test]
fn a_core_syncs_with_a_plain_desktop_host_core() {
    let _guard = serial();
    let (pd, pa) = (free_port(), free_port());
    let desktop = Desktop::start("sync-desktop", 91, pd, vec![pa]);
    let mut a = Node::new("sync-desk-a", "Phone-A", vec![pd]);
    a.discovery_port = pa;
    write_network_settings(a.dir.path(), "Phone-A", a.peer_port, pa);
    a.start().on_foreground();
    let a_view = a.core().start_pairing().unwrap();
    let a_id = device_link::identity::DeviceId::from_hex(&a.id()).unwrap();
    let addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, a.peer_port);
    desktop
        .host
        .net
        .join(addr, &a_view.code.unwrap(), Some(a_id))
        .unwrap()
        .unwrap();
    assert!(wait_for(Duration::from_secs(10), || a
        .core()
        .pairing()
        .state
        == passwsync_ffi::records::PairingState::Confirming));
    a.core().accept_pairing(desktop.id()).unwrap();
    let d_id = desktop.id();
    assert!(wait_for(Duration::from_secs(10), || a
        .core()
        .network()
        .paired
        .iter()
        .any(|p| p.device.id == d_id && p.status == "connected")));
    a.core()
        .create_wallet(WALLET.into(), bytes(PASSWORD), bytes(PASSWORD))
        .unwrap();
    a.core()
        .add_credential(WALLET.into(), input("Phone Entry", "u", Some("p")))
        .unwrap();
    let file = format!("wallets/{WALLET}.pwsw");
    std::fs::copy(a.dir.path().join(&file), desktop.dir.path().join(&file)).unwrap();
    set_mode(&desktop.dir.path().join(&file), 0o600);
    let name = wallet_service::WalletName::parse(WALLET).unwrap();
    desktop
        .host
        .service
        .unlock(&name, zeroize::Zeroizing::new(PASSWORD.to_owned()))
        .unwrap();
    desktop
        .host
        .service
        .add_entry(
            &name,
            vault_core::EntryFields {
                title: "Desktop Entry".into(),
                username: String::new(),
                password: String::new(),
                url: String::new(),
                notes: String::new(),
            },
        )
        .unwrap();
    assert!(
        wait_for(LIMIT, || titles(a.core(), WALLET)
            == ["Desktop Entry", "Phone Entry"]),
        "{:?}",
        titles(a.core(), WALLET)
    );
    a.core().shutdown();
}
