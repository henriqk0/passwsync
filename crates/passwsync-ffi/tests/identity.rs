//! FR-034, FR-035, FR-037: the device identity and the pins are Keystore-sealed blobs; the
//! sealer sees exactly two labels and nothing but the identity and pin encodings.

mod common;

use std::fs;
use std::path::Path;
use std::sync::Arc;

use common::{TempDir, mode};
use device_link::files::{decode_device_key, decode_peers};
use device_link::name::DeviceName;
use device_link::policy::AddressPolicy;
use device_link::registry::PeerPin;
use host_runtime::config::NetworkSettings;
use host_runtime::log::Log;
use host_runtime::net_runtime::{IdentityError, IdentityStore, NetDeps, NetRuntime, NetState};
use passwsync_ffi::identity::{
    IDENTITY_FILE, IDENTITY_LABEL, PEERS_FILE, PEERS_LABEL, SEALED_LIMIT, SealedIdentity,
};
use passwsync_ffi::ports::KeySealer;
use passwsync_ffi::testkit::{FakeSealer, SealCall, SealerMode};

const MARKER: &[u8] = b"MARKER-wallet-Personal-correct-horse-battery";

fn setup(tag: &str) -> (TempDir, Arc<FakeSealer>) {
    let dir = TempDir::new(tag);
    fs::create_dir(dir.path().join("wallets")).unwrap();
    fs::write(dir.path().join("wallets/Personal.pwsw"), MARKER).unwrap();
    (dir, Arc::new(FakeSealer::new()))
}

fn identity(dir: &Path, sealer: &Arc<FakeSealer>) -> SealedIdentity {
    SealedIdentity::new(dir, Arc::clone(sealer) as Arc<dyn KeySealer>)
}

fn pin(seed: u8) -> PeerPin {
    let key = device_link::identity::DeviceKey::from_private([seed; 32]);
    PeerPin {
        public: *key.public(),
        name: DeviceName::parse("laptop").unwrap(),
        paired_at: 1_000,
        last_seen: None,
        last_addr: None,
    }
}

fn net_on() -> NetworkSettings {
    NetworkSettings {
        enabled: true,
        ..NetworkSettings::default()
    }
}

fn assert_wallets_unaffected(dir: &Path) {
    assert_eq!(fs::read(dir.join("wallets/Personal.pwsw")).unwrap(), MARKER);
}

#[test]
fn the_labels_are_fixed() {
    assert_eq!(IDENTITY_LABEL, "passwsync identity v1");
    assert_eq!(PEERS_LABEL, "passwsync peers v1");
    assert_eq!(IDENTITY_FILE, "identity.sealed");
    assert_eq!(PEERS_FILE, "peers.sealed");
    assert_eq!(SEALED_LIMIT, 64 * 1024);
}

#[test]
fn first_start_creates_a_sealed_identity_and_a_second_start_reads_the_same_key() {
    let (dir, sealer) = setup("create");
    let key = identity(dir.path(), &sealer).load_or_create_key().unwrap();
    let file = dir.path().join(IDENTITY_FILE);
    assert!(file.is_file());
    assert_eq!(mode(&file), 0o600);
    let raw = fs::read(&file).unwrap();
    assert!(
        !raw.windows(32).any(|w| w == key.private_bytes()),
        "the file holds the sealed form only"
    );

    let again = identity(dir.path(), &sealer).load_or_create_key().unwrap();
    assert_eq!(again.id(), key.id());
    // The sealed plaintext is the 003 device-key encoding.
    let sealed = sealer.plaintexts();
    assert_eq!(sealed.len(), 1, "created once, then only opened");
    assert_eq!(decode_device_key(&sealed[0]).unwrap().id(), key.id());
}

#[test]
fn pins_round_trip_sealed_with_their_own_label() {
    let (dir, sealer) = setup("pins");
    let store_identity = identity(dir.path(), &sealer);
    let key = store_identity.load_or_create_key().unwrap();
    let store = store_identity.peer_store(*key.public(), AddressPolicy::lan());
    assert!(store.load().unwrap().is_empty(), "missing file: no pins");
    store.save(&[pin(7)]).unwrap();
    let file = dir.path().join(PEERS_FILE);
    assert_eq!(mode(&file), 0o600);
    let loaded = store.load().unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].public, pin(7).public);

    let last = sealer.plaintexts().pop().unwrap();
    let text = std::str::from_utf8(&last).unwrap();
    assert_eq!(
        decode_peers(text, key.public(), AddressPolicy::lan())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn only_the_two_labels_and_no_wallet_bytes_reach_the_sealer() {
    let (dir, sealer) = setup("labels");
    let store_identity = identity(dir.path(), &sealer);
    let key = store_identity.load_or_create_key().unwrap();
    let store = store_identity.peer_store(*key.public(), AddressPolicy::lan());
    store.save(&[pin(7), pin(8)]).unwrap();
    store.load().unwrap();
    identity(dir.path(), &sealer).load_or_create_key().unwrap();

    for label in sealer.labels() {
        assert!(
            label == IDENTITY_LABEL || label == PEERS_LABEL,
            "unexpected label {label}"
        );
    }
    for call in sealer.calls() {
        let plaintext = match call {
            SealCall::Seal { plaintext, .. } => plaintext,
            SealCall::Open {
                plaintext: Some(p), ..
            } => p,
            _ => continue,
        };
        assert!(!plaintext.windows(MARKER.len()).any(|w| w == MARKER));
        assert!(!plaintext.windows(8).any(|w| w == b"Personal"));
    }
    assert_wallets_unaffected(dir.path());
}

#[test]
fn an_oversized_identity_file_is_refused_before_open() {
    let (dir, sealer) = setup("big");
    fs::write(
        dir.path().join(IDENTITY_FILE),
        vec![0u8; SEALED_LIMIT as usize + 1],
    )
    .unwrap();
    common::set_mode(&dir.path().join(IDENTITY_FILE), 0o600);
    assert_eq!(
        identity(dir.path(), &sealer).load_or_create_key().err(),
        Some(IdentityError::Unusable)
    );
    assert!(sealer.calls().is_empty(), "open was never called");
}

fn tampered_identity(tag: &str) -> (TempDir, Arc<FakeSealer>) {
    let (dir, sealer) = setup(tag);
    identity(dir.path(), &sealer).load_or_create_key().unwrap();
    let file = dir.path().join(IDENTITY_FILE);
    let mut bytes = fs::read(&file).unwrap();
    FakeSealer::tamper(&mut bytes);
    fs::write(&file, &bytes).unwrap();
    (dir, sealer)
}

#[test]
fn a_tampered_identity_is_unusable_networking_off_and_never_replaced() {
    let (dir, sealer) = tampered_identity("tamper");
    let before = fs::read(dir.path().join(IDENTITY_FILE)).unwrap();
    let store = identity(dir.path(), &sealer);
    assert_eq!(
        store.load_or_create_key().err(),
        Some(IdentityError::Unusable)
    );
    let (log, _buffer) = Log::to_buffer();
    let net = NetRuntime::start(net_on(), &store, NetDeps::production(), &log);
    assert_eq!(net.state(), NetState::IdentityUnusable);
    assert!(net.snapshot().is_none(), "no node");
    assert_eq!(fs::read(dir.path().join(IDENTITY_FILE)).unwrap(), before);
    assert_wallets_unaffected(dir.path());
}

#[test]
fn an_invalidated_or_unavailable_keystore_makes_the_identity_unusable() {
    for mode in [SealerMode::Invalidated, SealerMode::Unavailable] {
        let (dir, sealer) = setup("invalid");
        identity(dir.path(), &sealer).load_or_create_key().unwrap();
        sealer.set_mode(mode);
        assert_eq!(
            identity(dir.path(), &sealer).load_or_create_key().err(),
            Some(IdentityError::Unusable),
            "{mode:?}"
        );
        assert_wallets_unaffected(dir.path());
    }
}

#[test]
fn tampered_or_unopenable_pins_give_peers_unusable_with_networking_off() {
    for case in ["tamper", "invalidated", "unavailable"] {
        let (dir, sealer) = setup("peers");
        let store = identity(dir.path(), &sealer);
        let key = store.load_or_create_key().unwrap();
        store
            .peer_store(*key.public(), AddressPolicy::lan())
            .save(&[pin(9)])
            .unwrap();
        match case {
            "tamper" => {
                let file = dir.path().join(PEERS_FILE);
                let mut bytes = fs::read(&file).unwrap();
                FakeSealer::tamper(&mut bytes);
                fs::write(&file, &bytes).unwrap();
            }
            "invalidated" => {
                // The identity was opened before; only the pins fail from here on.
                sealer.set_mode(SealerMode::Invalidated);
            }
            _ => sealer.set_mode(SealerMode::Unavailable),
        }
        let pins = store.peer_store(*key.public(), AddressPolicy::lan());
        assert!(pins.load().is_err(), "{case}");
        if case == "tamper" {
            let (log, _buffer) = Log::to_buffer();
            let net = NetRuntime::start(net_on(), &store, NetDeps::production(), &log);
            assert_eq!(net.state(), NetState::PeersUnusable);
            assert!(net.snapshot().is_none(), "no node");
        }
        assert_wallets_unaffected(dir.path());
    }
}

#[test]
fn an_oversized_pins_file_is_refused_before_open() {
    let (dir, sealer) = setup("bigpins");
    let store = identity(dir.path(), &sealer);
    let key = store.load_or_create_key().unwrap();
    let file = dir.path().join(PEERS_FILE);
    fs::write(&file, vec![0u8; SEALED_LIMIT as usize + 1]).unwrap();
    common::set_mode(&file, 0o600);
    let calls = sealer.calls().len();
    assert!(
        store
            .peer_store(*key.public(), AddressPolicy::lan())
            .load()
            .is_err()
    );
    assert_eq!(sealer.calls().len(), calls, "open was never called");
}

// --- T103 (US4, FR-037): reset_identity through the core ------------------------------------

mod part2 {
    use std::fs;
    use std::time::Duration;

    use super::common::{Fakes, Node, PASSWORD, bytes, write_network_settings};
    use super::{IDENTITY_FILE, PEERS_FILE, SealerMode, TempDir};
    use passwsync_ffi::records::NetStateView;

    #[test]
    fn reset_identity_makes_a_new_key_empties_the_pins_and_keeps_the_setting() {
        let mut node = Node::new("reset", "Phone", Vec::new());
        let core = node.start();
        core.create_wallet("Personal".into(), bytes(PASSWORD), bytes(PASSWORD))
            .unwrap();
        let wallet = fs::read(node.dir.path().join("wallets/Personal.pwsw")).unwrap();
        let old = core.network().this_device.unwrap();
        core.on_foreground();
        let resets = node.fakes.sealer.resets();
        core.reset_identity().unwrap();
        assert_eq!(node.fakes.sealer.resets(), resets + 1, "KeySealer::reset");
        assert!(
            node.dir.path().join(IDENTITY_FILE).exists(),
            "new key sealed"
        );
        assert!(!node.dir.path().join(PEERS_FILE).exists(), "pins emptied");
        assert!(
            node.fakes
                .log
                .lines()
                .iter()
                .any(|l| l.contains("device identity reset"))
        );
        assert!(core.settings().networking, "the setting stays as set");
        assert!(core.settings().restart_required);
        assert_eq!(
            fs::read(node.dir.path().join("wallets/Personal.pwsw")).unwrap(),
            wallet,
            "wallets untouched"
        );
        core.shutdown();
        drop(core);
        node.core = None;
        let core = node.start();
        let new = core.network().this_device.unwrap();
        assert_ne!(new.fingerprint, old.fingerprint);
        assert!(core.network().paired.is_empty());
        assert!(
            core.list_wallets()
                .unwrap()
                .iter()
                .any(|w| w.name == "Personal")
        );
        core.on_foreground();
        assert!(super::common::wait_for(Duration::from_secs(2), || core
            .network()
            .state
            == NetStateView::On));
        core.shutdown();
    }

    #[test]
    fn with_an_unusable_identity_the_switch_saves_but_the_state_stays_unusable() {
        let dir = TempDir::new("unusable-switch");
        let fakes = Fakes::new();
        drop(fakes.start(dir.path()).unwrap());
        write_network_settings(dir.path(), "Phone", 40_001, 40_002);
        fakes.sealer.set_mode(SealerMode::Invalidated);
        let core = fakes.start(dir.path()).unwrap();
        assert_eq!(core.network().state, NetStateView::IdentityUnusable);
        core.set_networking(true, true).unwrap();
        assert!(core.settings().networking);
        assert_eq!(core.network().state, NetStateView::IdentityUnusable);
    }
}
