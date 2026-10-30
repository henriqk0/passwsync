//! 007 T104 (US4; FR-050 to FR-053): two cores over loopback pair in both roles exactly as 003;
//! wrong codes and refusals follow 003; no wallet or master password is involved; leaving the
//! foreground cancels a pairing; revoke removes the pin and closes the channel; a core pairs
//! with a plain desktop `HostCore`.

mod common;

use std::time::Duration;

use common::*;
use device_link::identity::DeviceId;
use passwsync_ffi::api::pairing_state;
use passwsync_ffi::error::CoreError;
use passwsync_ffi::identity::PEERS_LABEL;
use passwsync_ffi::records::PairingState;

#[test]
fn the_pairing_state_mapping_is_a_fixed_table() {
    for (word, state) in [
        ("waiting", PairingState::Waiting),
        ("connecting", PairingState::Waiting),
        ("exchanging", PairingState::Waiting),
        ("awaiting_acceptance", PairingState::Confirming),
        ("paired", PairingState::Completed),
        ("failed", PairingState::Failed),
        ("anything else", PairingState::Failed),
    ] {
        assert_eq!(pairing_state(word), state, "{word}");
    }
}

#[test]
fn two_cores_pair_in_both_roles_with_pins_sealed_and_no_wallet() {
    let _guard = serial();
    let (a, b) = two_nodes("pair");
    // No wallet exists and no master password is ever asked for.
    assert!(a.core().list_wallets().unwrap().is_empty());
    let a_seals = a.fakes.sealer.labels().len();
    pair(&a, &b);
    assert!(
        wait_for(Duration::from_secs(8), || connected(&a, &b)),
        "channel up"
    );
    // The joiner sees the initiator's name and fingerprint for the comparison.
    let a_view = a.core().network().this_device.unwrap();
    let paired = b.core().network().paired;
    let seen = paired.iter().find(|p| p.device.id == a_view.id).unwrap();
    assert_eq!(seen.device.fingerprint, a_view.fingerprint);
    assert_eq!(seen.device.name, "Phone-A");
    // Pins written through the sealer with their label.
    let labels = a.fakes.sealer.labels();
    assert!(
        labels[a_seals..].iter().any(|l| l == PEERS_LABEL),
        "{labels:?}"
    );
    assert!(a.dir.path().join("peers.sealed").exists());
    assert!(b.dir.path().join("peers.sealed").exists());
    assert!(a.core().list_wallets().unwrap().is_empty());
    // Initiator (a) and joiner (b) are both cores: both roles are covered.
    a.core().shutdown();
    b.core().shutdown();
}

#[test]
fn a_wrong_code_fails_and_pins_nothing() {
    let _guard = serial();
    let (a, b) = two_nodes("pair-wrong");
    let a_id = a.id();
    let code = a.core().start_pairing().unwrap().code.unwrap();
    assert!(wait_for(Duration::from_secs(10), || b
        .core()
        .network()
        .nearby
        .iter()
        .any(|n| n.device.id == a_id)));
    let wrong: String = code
        .chars()
        .map(|c| if c == '0' { '1' } else { '0' })
        .collect();
    b.core().join_pairing(a_id.clone(), bytes(&wrong)).unwrap();
    assert!(
        wait_for(Duration::from_secs(10), || b.core().pairing().state
            == PairingState::Failed),
        "{:?}",
        b.core().pairing()
    );
    assert!(a.core().network().paired.is_empty());
    assert!(b.core().network().paired.is_empty());
    // Malformed codes are refused before anything is sent.
    assert!(matches!(
        b.core().join_pairing(a_id.clone(), bytes("12ab")),
        Err(CoreError::Pairing { .. })
    ));
    assert_eq!(
        b.core().join_pairing(a_id, vec![0xff, 0xfe]).err(),
        Some(CoreError::InvalidInput)
    );
    a.core().shutdown();
    b.core().shutdown();
}

#[test]
fn a_rejected_pairing_pins_nothing() {
    let _guard = serial();
    let (a, b) = two_nodes("pair-reject");
    let a_id = a.id();
    let code = a.core().start_pairing().unwrap().code.unwrap();
    assert!(wait_for(Duration::from_secs(10), || b
        .core()
        .network()
        .nearby
        .iter()
        .any(|n| n.device.id == a_id)));
    b.core().join_pairing(a_id, bytes(&code)).unwrap();
    assert!(wait_for(Duration::from_secs(10), || a
        .core()
        .pairing()
        .state
        == PairingState::Confirming));
    a.core().reject_pairing();
    assert!(wait_for(Duration::from_secs(10), || b
        .core()
        .pairing()
        .state
        == PairingState::Failed));
    assert!(a.core().network().paired.is_empty());
    assert!(b.core().network().paired.is_empty());
    a.core().shutdown();
    b.core().shutdown();
}

#[test]
fn leaving_the_foreground_cancels_the_pairing_and_invalidates_the_code() {
    let _guard = serial();
    let (a, b) = two_nodes("pair-bg");
    let view = a.core().start_pairing().unwrap();
    assert_eq!(view.state, PairingState::Waiting);
    assert!(view.code.is_some());
    a.core().on_background();
    let after = a.core().pairing();
    assert!(after.code.is_none(), "code invalidated");
    assert_ne!(after.state, PairingState::Waiting);
    a.core().on_foreground();
    let after = a.core().pairing();
    assert!(after.code.is_none(), "still invalid after returning");
    a.core().shutdown();
    b.core().shutdown();
}

#[test]
fn revoke_removes_the_pin_and_closes_the_channel() {
    let _guard = serial();
    let (a, b) = two_nodes("pair-revoke");
    pair(&a, &b);
    assert!(wait_for(Duration::from_secs(8), || connected(&a, &b)));
    let b_id = b.id();
    assert!(matches!(
        a.core().revoke_device("zz".into()),
        Err(CoreError::Pairing { .. })
    ));
    a.core().revoke_device(b_id.clone()).unwrap();
    assert!(
        a.core()
            .network()
            .paired
            .iter()
            .all(|p| p.device.id != b_id)
    );
    assert!(wait_for(Duration::from_secs(8), || !connected(&a, &b)));
    a.core().shutdown();
    b.core().shutdown();
}

#[test]
fn a_core_pairs_with_a_plain_desktop_host_core_in_both_roles() {
    let _guard = serial();
    let (pd, pa) = (free_port(), free_port());
    let desktop = Desktop::start("pair-desktop", 77, pd, vec![pa]);
    let mut a = Node::new("pair-desk-a", "Phone-A", vec![pd]);
    a.discovery_port = pa;
    write_network_settings(a.dir.path(), "Phone-A", a.peer_port, pa);
    a.start().on_foreground();
    let d_id = desktop.id();
    // The phone joins the desktop's code.
    desktop.host.net.start_pairing().unwrap().unwrap();
    assert!(wait_for(Duration::from_secs(10), || a
        .core()
        .network()
        .nearby
        .iter()
        .any(|n| n.device.id == d_id)));
    let code = desktop
        .host
        .net
        .snapshot()
        .unwrap()
        .pairing
        .unwrap()
        .code
        .unwrap()
        .to_string();
    a.core().join_pairing(d_id.clone(), bytes(&code)).unwrap();
    let a_id = DeviceId::from_hex(&a.id()).unwrap();
    assert!(wait_for(Duration::from_secs(10), || desktop
        .host
        .net
        .snapshot()
        .unwrap()
        .pairing
        .is_some_and(|p| p.state == "awaiting_acceptance")));
    desktop.host.net.accept(&a_id).unwrap();
    assert!(wait_for(Duration::from_secs(10), || a
        .core()
        .network()
        .paired
        .iter()
        .any(|p| p.device.id == d_id && p.status == "connected")));
    // And revoked from the phone, the desktop's channel closes.
    a.core().revoke_device(d_id).unwrap();
    assert!(wait_for(Duration::from_secs(8), || desktop
        .host
        .net
        .snapshot()
        .unwrap()
        .paired
        .iter()
        .all(|p| p.status.as_str() != "connected")));
    // Then the phone initiates and the desktop joins.
    desktop.host.net.revoke(&a_id).unwrap();
    let view = a.core().start_pairing().unwrap();
    let addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, a.peer_port);
    desktop
        .host
        .net
        .join(addr, &view.code.unwrap(), Some(a_id))
        .unwrap()
        .unwrap();
    let d = desktop.id();
    assert!(wait_for(Duration::from_secs(10), || a
        .core()
        .pairing()
        .state
        == PairingState::Confirming));
    a.core().accept_pairing(d.clone()).unwrap();
    assert!(wait_for(Duration::from_secs(10), || a
        .core()
        .network()
        .paired
        .iter()
        .any(|p| p.device.id == d && p.status == "connected")));
    a.core().shutdown();
}
