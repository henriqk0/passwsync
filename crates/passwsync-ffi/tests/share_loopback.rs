//! 007 T119 (US6; FR-051, FR-052): a full 005 invitation between two cores (create, redeem with
//! the typed code, recipient confirmation by name and fingerprint, ciphertext-only transfer,
//! open with the master password, then sync); cancellation; foreground-only calls; leaving the
//! foreground cancels an invitation that has not started; unopened received wallets expire
//! (reported once) and a partial file is removed at the next start; revoke deletes unopened
//! wallets; a core shares with a plain desktop `HostCore` in both directions.

mod common;

use std::time::Duration;

use common::*;
use device_link::identity::DeviceId;
use passwsync_ffi::error::CoreError;
use passwsync_ffi::records::{CoreEvent, InvitationState};
use zeroize::Zeroizing;

const WALLET: &str = "Family";
const LIMIT: Duration = Duration::from_secs(20);

/// Two paired, connected nodes; `a` holds the unlocked wallet `WALLET` with one credential.
fn paired_with_wallet(tag: &str) -> (Node, Node) {
    let (a, b) = two_nodes(tag);
    pair(&a, &b);
    assert!(wait_for(Duration::from_secs(8), || connected(&a, &b)));
    a.core()
        .create_wallet(WALLET.into(), bytes(PASSWORD), bytes(PASSWORD))
        .unwrap();
    a.core()
        .add_credential(
            WALLET.into(),
            input("Shared Entry", "u", Some("shared-secret")),
        )
        .unwrap();
    (a, b)
}

/// `a` invites `b`, `b` redeems, `a` accepts; waits until `b` holds the received wallet.
fn share(a: &Node, b: &Node) -> String {
    let view = a.core().create_invitation(WALLET.into(), b.id()).unwrap();
    assert_eq!(view.state, InvitationState::Active);
    assert_eq!(view.recipient.id, b.id());
    assert_eq!(view.code.len(), 8);
    b.core()
        .redeem_invitation(a.id(), bytes(&view.code))
        .unwrap();
    assert!(
        wait_for(LIMIT, || a
            .core()
            .invitation()
            .is_some_and(|i| i.state == InvitationState::AwaitingAcceptance)),
        "{:?}",
        a.core().invitation()
    );
    // The sender confirms the recipient by name and fingerprint.
    let waiting = a.core().invitation().unwrap();
    assert_eq!(waiting.recipient.name, "Phone-B");
    assert_eq!(
        waiting.recipient.fingerprint,
        b.core().network().this_device.unwrap().fingerprint
    );
    a.core().accept_recipient(b.id()).unwrap();
    assert!(
        wait_for(LIMIT, || b.core().received().len() == 1),
        "received: {:?}",
        b.core().received()
    );
    b.core().received()[0].id.clone()
}

#[test]
fn a_full_invitation_transfers_ciphertext_and_opens_with_the_master_password() {
    let _guard = serial();
    let (a, b) = paired_with_wallet("share-full");
    let id = share(&a, &b);
    let received = &b.core().received()[0];
    assert_eq!(received.from.id, a.id());
    assert!(received.expires_in_ms > 23 * 3600 * 1000);
    // Ciphertext only on disk.
    for (path, is_dir, _) in tree(b.dir.path()) {
        if !is_dir {
            let bytes = std::fs::read(b.dir.path().join(&path)).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                !text.contains("Shared Entry") && !text.contains("shared-secret"),
                "{path}"
            );
        }
    }
    assert_eq!(
        b.core()
            .open_received(id.clone(), WALLET.into(), bytes("not the password"))
            .err(),
        Some(CoreError::InvalidPasswordOrCorrupted)
    );
    b.core()
        .open_received(id, WALLET.into(), bytes(PASSWORD))
        .unwrap();
    assert!(b.core().received().is_empty());
    assert_eq!(titles(b.core(), WALLET), ["Shared Entry"]);
    // Then it syncs like any wallet.
    a.core()
        .add_credential(WALLET.into(), input("After Share", "u", Some("p")))
        .unwrap();
    assert!(wait_for(LIMIT, || titles(b.core(), WALLET)
        == ["After Share", "Shared Entry"]));
    a.core().shutdown();
    b.core().shutdown();
}

#[test]
fn foreground_only_calls_cancellation_and_background_cancel() {
    let _guard = serial();
    let (a, b) = paired_with_wallet("share-fg");
    let view = a.core().create_invitation(WALLET.into(), b.id()).unwrap();
    a.core().cancel_invitation();
    assert!(
        a.core()
            .invitation()
            .is_none_or(|i| i.state == InvitationState::Cancelled)
    );
    assert!(
        b.core()
            .redeem_invitation(a.id(), bytes(&view.code))
            .is_ok()
    );
    assert!(wait_for(LIMIT, || b.core().received().is_empty()));
    // Leaving the foreground cancels an invitation whose transfer has not started.
    a.core().create_invitation(WALLET.into(), b.id()).unwrap();
    a.core().on_background();
    assert!(
        a.core()
            .invitation()
            .is_none_or(|i| i.state == InvitationState::Cancelled),
        "{:?}",
        a.core().invitation()
    );
    let fg = Some(CoreError::NotForeground);
    assert_eq!(a.core().create_invitation(WALLET.into(), b.id()).err(), fg);
    assert_eq!(a.core().accept_recipient(b.id()).err(), fg);
    assert_eq!(
        a.core().redeem_invitation(b.id(), bytes("12345678")).err(),
        fg
    );
    a.core().on_foreground();
    // Unknown wallet and device.
    assert_eq!(
        a.core().create_invitation("Nope".into(), b.id()).err(),
        Some(CoreError::WalletNotFound)
    );
    assert!(matches!(
        a.core().create_invitation(WALLET.into(), "00".repeat(32)),
        Err(CoreError::Share { .. })
    ));
    a.core().shutdown();
    b.core().shutdown();
}

#[test]
fn unopened_wallets_expire_once_and_partial_files_go_at_start() {
    let _guard = serial();
    let (a, mut b) = paired_with_wallet("share-expiry");
    share(&a, &b);
    background(&b);
    b.core()
        .advance_share_clock(Duration::from_secs(24 * 3600 + 60));
    let report = b.core().run_sync_window();
    assert!(report.ran);
    assert!(b.core().received().is_empty(), "deleted at the window");
    let expired = |events: &[CoreEvent]| {
        events
            .iter()
            .filter(|e| **e == CoreEvent::ReceivedExpired)
            .count()
    };
    assert_eq!(expired(&b.fakes.notifier.events()), 1);
    b.core().run_sync_window();
    assert_eq!(expired(&b.fakes.notifier.events()), 1, "reported once");
    // A partial file of an interrupted transfer is removed at the next start.
    a.core().shutdown();
    b.core().shutdown();
    drop(b.core.take());
    let part = b
        .dir
        .path()
        .join("received")
        .join(format!("{}.part", "ab".repeat(16)));
    std::fs::write(&part, b"partial").unwrap();
    set_mode(&part, 0o600);
    let core = b.start();
    assert!(!part.exists());
    core.shutdown();
}

#[test]
fn revoke_deletes_unopened_wallets_from_that_device() {
    let _guard = serial();
    let (a, b) = paired_with_wallet("share-revoke");
    share(&a, &b);
    b.core().revoke_device(a.id()).unwrap();
    assert!(b.core().received().is_empty());
    a.core().shutdown();
    b.core().shutdown();
}

#[test]
fn a_core_and_a_desktop_host_core_share_in_both_directions() {
    let _guard = serial();
    let (pd, pa) = (free_port(), free_port());
    let desktop = Desktop::start("share-desktop", 93, pd, vec![pa]);
    let mut a = Node::new("share-desk-a", "Phone-A", vec![pd]);
    a.discovery_port = pa;
    write_network_settings(a.dir.path(), "Phone-A", a.peer_port, pa);
    a.start().on_foreground();
    let a_id = DeviceId::from_hex(&a.id()).unwrap();
    let d_id = DeviceId::from_hex(&desktop.id()).unwrap();
    let code = a.core().start_pairing().unwrap().code.unwrap();
    let addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, a.peer_port);
    desktop
        .host
        .net
        .join(addr, &code, Some(a_id))
        .unwrap()
        .unwrap();
    assert!(wait_for(Duration::from_secs(10), || a
        .core()
        .pairing()
        .state
        == passwsync_ffi::records::PairingState::Confirming));
    a.core().accept_pairing(desktop.id()).unwrap();
    assert!(wait_for(Duration::from_secs(10), || {
        a.core()
            .network()
            .paired
            .iter()
            .any(|p| p.device.id == desktop.id() && p.status == "connected")
    }));

    // Phone to desktop.
    a.core()
        .create_wallet(WALLET.into(), bytes(PASSWORD), bytes(PASSWORD))
        .unwrap();
    let view = a
        .core()
        .create_invitation(WALLET.into(), desktop.id())
        .unwrap();
    desktop
        .host
        .share
        .redeem(Zeroizing::new(view.code.clone()), Some(a_id), None)
        .unwrap();
    assert!(wait_for(LIMIT, || {
        a.core()
            .invitation()
            .is_some_and(|i| i.state == InvitationState::AwaitingAcceptance)
    }));
    a.core().accept_recipient(desktop.id()).unwrap();
    assert!(wait_for(LIMIT, || desktop
        .host
        .share
        .core()
        .received
        .list_report()
        .is_ok_and(|(l, _)| l.len() == 1)));

    // Desktop to phone.
    let name = wallet_service::WalletName::parse("Desk").unwrap();
    desktop
        .host
        .service
        .create(
            "Desk",
            Zeroizing::new(PASSWORD.into()),
            Zeroizing::new(PASSWORD.into()),
        )
        .unwrap();
    desktop.host.share.create(&name, &a_id).unwrap();
    let code = desktop
        .host
        .share
        .core()
        .engine()
        .view()
        .invitation
        .unwrap()
        .code
        .unwrap()
        .to_string();
    a.core()
        .redeem_invitation(d_id.to_hex(), bytes(&code))
        .unwrap();
    assert!(wait_for(LIMIT, || desktop
        .host
        .share
        .core()
        .engine()
        .view()
        .invitation
        .is_some_and(|i| i.state == "awaiting_acceptance")));
    desktop.host.share.accept(&a_id).unwrap();
    assert!(wait_for(LIMIT, || a.core().received().len() == 1));
    let id = a.core().received()[0].id.clone();
    a.core()
        .open_received(id, "Desk".into(), bytes(PASSWORD))
        .unwrap();
    assert!(
        a.core()
            .list_wallets()
            .unwrap()
            .iter()
            .any(|w| w.name == "Desk")
    );
    a.core().shutdown();
}
