//! 005 T030: `Service::adopt_received` (contracts/core-api-share.md "wallet-service", R10):
//! a received file opened with the master password becomes a held, unlocked wallet whose
//! stored bytes are exactly the received ones.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use vault_core::{DeviceId, FixedClock, KdfConfig, MasterPassword, StorageError, Vault};
use wallet_service::{
    AdoptVerdict, CopyFacts, CopyVerdict, PeerRef, PendingCopies, PendingOutcome, PendingRef,
    ServiceError, UnlockFacts, WalletName,
};

#[derive(Default)]
struct Port {
    unlocked: Mutex<Vec<(WalletName, Vec<u8>, UnlockFacts)>>,
}

impl PendingCopies for Port {
    fn list(&self, _: &WalletName) -> Vec<PendingRef> {
        Vec::new()
    }
    fn load(&self, _: &WalletName, _: &PeerRef) -> Result<Vec<u8>, StorageError> {
        Err(StorageError::NotFound)
    }
    fn check(&self, _: &WalletName, _: &PeerRef, _: &CopyFacts) -> CopyVerdict {
        CopyVerdict::Reject
    }
    fn outcome(&self, _: &WalletName, _: &PeerRef, _: PendingOutcome) {}
    fn unlocked(&self, wallet: &WalletName, file: &[u8], facts: &UnlockFacts) -> bool {
        self.unlocked
            .lock()
            .unwrap()
            .push((wallet.clone(), file.to_vec(), facts.clone()));
        false
    }
    fn upgraded(&self, _: &WalletName) {}
}

/// A wallet sealed on another device (format 2) with `titles`.
pub fn received_bytes(kdf: KdfConfig, titles: &[&str]) -> (Vec<u8>, Vault) {
    let mut vault = Vault::create(
        MasterPassword::new(PASSWORD.into()),
        kdf,
        DeviceId::new("sender-device").unwrap(),
        Box::new(FixedClock::new(5)),
    )
    .unwrap();
    for title in titles {
        vault.add_entry(fields(title)).unwrap();
    }
    (vault.seal().unwrap(), vault)
}

fn proceed() -> impl Fn(&UnlockFacts) -> AdoptVerdict {
    |_| AdoptVerdict::Proceed
}

#[test]
fn the_correct_password_stores_the_bytes_verbatim_and_unlocks() {
    let fx = fx();
    let port = Arc::new(Port::default());
    fx.service.set_pending_copies(port.clone());
    let (bytes, sender) = received_bytes(KdfConfig::MINIMUM, &["Bank", "Mail"]);
    let seen = Mutex::new(Vec::new());
    let decide = |facts: &UnlockFacts| {
        seen.lock().unwrap().push(facts.clone());
        AdoptVerdict::Proceed
    };
    let wallet = fx
        .service
        .adopt_received("Shared", &bytes, pw(PASSWORD), &decide)
        .unwrap();
    assert_eq!(wallet, name("Shared"));
    assert_eq!(fx.dir.bytes(&wallet).unwrap(), bytes, "stored verbatim");
    let status = fx.service.list().unwrap();
    assert!(status.iter().any(|s| s.name == wallet && s.unlocked));
    let titles: Vec<String> = fx
        .service
        .search(&wallet, "")
        .unwrap()
        .iter()
        .map(|e| e.title.to_string())
        .collect();
    assert_eq!(titles, ["Bank", "Mail"]);
    // The authenticated facts went to `decide` and to the 004 hook, once each.
    let facts = UnlockFacts {
        wallet_id: sender.wallet_id(),
        state: sender.state().clone(),
        format_version: 2,
    };
    assert_eq!(*seen.lock().unwrap(), vec![facts.clone()]);
    let calls = port.unlocked.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, wallet);
    assert_eq!(calls[0].1, bytes);
    assert_eq!(calls[0].2, facts);
}

#[test]
fn names_are_validated_and_never_replace_a_wallet() {
    let fx = fx();
    let (bytes, _) = received_bytes(KdfConfig::MINIMUM, &[]);
    let called = Mutex::new(0);
    let decide = |_: &UnlockFacts| {
        *called.lock().unwrap() += 1;
        AdoptVerdict::Proceed
    };
    assert_eq!(
        fx.service
            .adopt_received(".hidden", &bytes, pw(PASSWORD), &decide),
        Err(ServiceError::InvalidName)
    );
    let existing = create(&fx, "Personal");
    let before = fx.dir.bytes(&existing).unwrap();
    assert_eq!(
        fx.service
            .adopt_received("Personal", &bytes, pw(PASSWORD), &decide),
        Err(ServiceError::WalletExists)
    );
    assert_eq!(fx.dir.bytes(&existing).unwrap(), before, "untouched");
    assert_eq!(*called.lock().unwrap(), 0, "no derivation, no decision");
    assert_eq!(fx.service.list().unwrap().len(), 1);
}

#[test]
fn the_kdf_cap_is_enforced_before_any_derivation() {
    let fx = fx();
    let (mut bytes, _) = received_bytes(KdfConfig::MINIMUM, &[]);
    bytes[7..11].copy_from_slice(&1_048_576u32.to_le_bytes());
    let started = Instant::now();
    assert_eq!(
        fx.service
            .adopt_received("Shared", &bytes, pw(PASSWORD), &proceed()),
        Err(ServiceError::KdfParamsOutOfRange)
    );
    assert!(started.elapsed() < Duration::from_millis(50));
    assert!(fx.dir.bytes(&name("Shared")).is_none());
}

#[test]
fn the_kdf_gate_serializes_the_derivation() {
    let fx = Arc::new(fx());
    let (bytes, _) = received_bytes(KdfConfig::MINIMUM, &[]);
    let gate = fx.service.hold_kdf_gate();
    let worker = {
        let fx = Arc::clone(&fx);
        std::thread::spawn(move || {
            fx.service
                .adopt_received("Shared", &bytes, pw(PASSWORD), &|_| AdoptVerdict::Proceed)
        })
    };
    std::thread::sleep(Duration::from_millis(100));
    assert!(!worker.is_finished(), "waits for the KDF gate");
    drop(gate);
    assert!(worker.join().unwrap().is_ok());
}

#[test]
fn on_any_error_nothing_is_written() {
    let fx = fx();
    let (bytes, _) = received_bytes(KdfConfig::MINIMUM, &[]);
    assert_eq!(
        fx.service
            .adopt_received("Shared", &bytes, pw("wrong password!!"), &proceed()),
        Err(ServiceError::InvalidPasswordOrCorrupted)
    );
    assert!(fx.dir.bytes(&name("Shared")).is_none());
    assert!(fx.service.list().unwrap().is_empty());
}
