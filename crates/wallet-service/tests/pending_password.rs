//! 004 T085: opening a pending copy with its own password, and choosing a password after
//! concurrent password changes (FR-022, research R6).

mod common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use common::*;
use vault_core::{
    DeviceId, FixedClock, MasterPassword, PasswordChoice, StateVector, StorageError, Vault,
};
use wallet_service::{
    CopyFacts, CopyVerdict, PeerRef, PendingCopies, PendingOutcome, PendingRef, ServiceError,
    UnlockFacts, WalletName,
};

#[derive(Default)]
struct FakePort {
    copies: Mutex<BTreeMap<PeerRef, (Vec<u8>, StateVector)>>,
    reject: Mutex<Vec<PeerRef>>,
    outcomes: Mutex<Vec<(PeerRef, PendingOutcome)>>,
    unlocked: Mutex<usize>,
}

impl PendingCopies for FakePort {
    fn list(&self, _: &WalletName) -> Vec<PendingRef> {
        self.copies
            .lock()
            .unwrap()
            .iter()
            .map(|(peer, (bytes, state))| PendingRef {
                peer: *peer,
                claimed_state: state.clone(),
                size: bytes.len() as u64,
            })
            .collect()
    }
    fn load(&self, _: &WalletName, peer: &PeerRef) -> Result<Vec<u8>, StorageError> {
        self.copies
            .lock()
            .unwrap()
            .get(peer)
            .map(|c| c.0.clone())
            .ok_or(StorageError::NotFound)
    }
    fn check(&self, _: &WalletName, peer: &PeerRef, _: &CopyFacts) -> CopyVerdict {
        if self.reject.lock().unwrap().contains(peer) {
            CopyVerdict::Reject
        } else {
            CopyVerdict::Accept
        }
    }
    fn outcome(&self, _: &WalletName, peer: &PeerRef, outcome: PendingOutcome) {
        self.outcomes.lock().unwrap().push((*peer, outcome));
    }
    fn unlocked(&self, _: &WalletName, _: &[u8], _: &UnlockFacts) -> bool {
        *self.unlocked.lock().unwrap() += 1;
        false
    }
    fn upgraded(&self, _: &WalletName) {}
}

fn peer(n: u8) -> PeerRef {
    PeerRef([n; 32])
}

/// The stored wallet changed elsewhere (as another device) and sealed.
fn changed_copy(fx: &Fx, w: &WalletName, edit: impl FnOnce(&mut Vault)) -> (Vec<u8>, StateVector) {
    let mut other = Vault::unlock(
        &fx.dir.bytes(w).unwrap(),
        MasterPassword::new(PASSWORD.into()),
        DeviceId::new("phone").unwrap(),
        Box::new(FixedClock::new(3_000)),
    )
    .unwrap();
    edit(&mut other);
    (other.seal().unwrap(), other.state().clone())
}

const NEW: &str = "the password changed on the phone";

fn setup() -> (Fx, WalletName, Arc<FakePort>) {
    let fx = fx();
    let w = create(&fx, "Personal");
    let port = Arc::new(FakePort::default());
    fx.service.set_pending_copies(port.clone());
    (fx, w, port)
}

fn phone_changed_password(fx: &Fx, w: &WalletName) -> (Vec<u8>, StateVector) {
    changed_copy(fx, w, |v| {
        v.change_master_password(MasterPassword::new(NEW.into()))
            .unwrap();
        v.add_entry(fields("From phone")).unwrap();
    })
}

#[test]
fn the_right_password_merges_a_copy_that_could_not_be_opened() {
    let (fx, w, port) = setup();
    port.copies
        .lock()
        .unwrap()
        .insert(peer(1), phone_changed_password(&fx, &w));
    assert_eq!(
        fx.service
            .open_pending_with_password(&w, &peer(1), pw("not the password at all")),
        Err(ServiceError::InvalidPasswordOrCorrupted)
    );
    assert!(
        port.outcomes.lock().unwrap().is_empty(),
        "the copy stays pending"
    );
    let report = fx
        .service
        .open_pending_with_password(&w, &peer(1), pw(NEW))
        .unwrap();
    assert!(report.password_adopted, "the newer password change wins");
    assert_eq!(fx.service.search(&w, "").unwrap().len(), 1);
    let saved = fx.dir.bytes(&w).unwrap();
    assert!(
        Vault::unlock(
            &saved,
            MasterPassword::new(NEW.into()),
            DeviceId::new("x").unwrap(),
            Box::new(FixedClock::new(0))
        )
        .is_ok()
    );
    assert!(matches!(
        port.outcomes.lock().unwrap()[0],
        (
            _,
            PendingOutcome::Merged {
                password_adopted: true,
                ..
            }
        )
    ));
}

#[test]
fn opening_a_pending_copy_needs_the_wallet_unlocked() {
    let (fx, w, port) = setup();
    port.copies
        .lock()
        .unwrap()
        .insert(peer(1), phone_changed_password(&fx, &w));
    fx.service.lock(&w).unwrap();
    assert_eq!(
        fx.service.open_pending_with_password(&w, &peer(1), pw(NEW)),
        Err(ServiceError::WalletLocked)
    );
}

#[test]
fn concurrent_password_changes_need_a_choice() {
    let (fx, w, port) = setup();
    port.copies
        .lock()
        .unwrap()
        .insert(peer(1), phone_changed_password(&fx, &w));
    // This device changed its password too, concurrently.
    fx.service
        .change_password(&w, pw("a local new password"), pw("a local new password"))
        .unwrap();
    assert_eq!(
        fx.service.open_pending_with_password(&w, &peer(1), pw(NEW)),
        Err(ServiceError::PasswordConflict)
    );
    assert_eq!(
        port.outcomes.lock().unwrap().last().unwrap().1,
        PendingOutcome::PasswordConflict
    );
    // A wrong password is refused.
    assert_eq!(
        fx.service
            .choose_password(&w, &peer(1), PasswordChoice::Copy, pw("wrong wrong wrong")),
        Err(ServiceError::InvalidPasswordOrCorrupted)
    );
    // Keep the local one: the copy's password opens the copy, the local key is kept.
    let report = fx
        .service
        .choose_password(&w, &peer(1), PasswordChoice::Local, pw(NEW))
        .unwrap();
    assert!(!report.password_adopted);
    let saved = fx.dir.bytes(&w).unwrap();
    assert!(
        Vault::unlock(
            &saved,
            MasterPassword::new("a local new password".into()),
            DeviceId::new("x").unwrap(),
            Box::new(FixedClock::new(0))
        )
        .is_ok()
    );
    assert_eq!(fx.service.search(&w, "").unwrap().len(), 1);
}
