//! 004 T083: `Service::unlock` merges the wallet's pending copies (research R13).

mod common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use common::*;
use vault_core::{DeviceId, FixedClock, MasterPassword, StateVector, StorageError, Vault};
use wallet_service::{
    CopyFacts, CopyVerdict, PeerRef, PendingCopies, PendingOutcome, PendingRef, UnlockFacts,
    UnlockOutcome, WalletName,
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

fn setup() -> (Fx, WalletName, Arc<FakePort>) {
    let fx = fx();
    let w = create(&fx, "Personal");
    let port = Arc::new(FakePort::default());
    fx.service.set_pending_copies(port.clone());
    (fx, w, port)
}

#[test]
fn pending_copies_are_merged_and_saved_once_during_unlock() {
    let (fx, w, port) = setup();
    let c1 = changed_copy(&fx, &w, |v| {
        v.add_entry(fields("From phone")).unwrap();
    });
    let c2 = changed_copy(&fx, &w, |v| {
        v.add_entry(fields("From tablet")).unwrap();
    });
    port.copies.lock().unwrap().insert(peer(1), c1);
    port.copies.lock().unwrap().insert(peer(2), c2);
    fx.service.lock(&w).unwrap();
    let before = fx.dir.bytes(&w).unwrap();
    assert_eq!(
        fx.service.unlock(&w, pw(PASSWORD)),
        Ok(UnlockOutcome::Unlocked)
    );
    assert_eq!(*port.unlocked.lock().unwrap(), 1);
    let titles: Vec<String> = fx
        .service
        .search(&w, "")
        .unwrap()
        .iter()
        .map(|e| e.title.to_string())
        .collect();
    assert_eq!(titles.len(), 2, "{titles:?}");
    assert_ne!(fx.dir.bytes(&w).unwrap(), before, "saved");
    assert_eq!(reopen(&fx, &w).all_records().count(), 2);
    let outcomes = port.outcomes.lock().unwrap().clone();
    assert_eq!(outcomes.len(), 2);
    assert!(
        outcomes
            .iter()
            .all(|(_, o)| matches!(o, PendingOutcome::Merged { .. }))
    );
}

#[test]
fn an_invalid_or_unopenable_copy_never_blocks_the_unlock() {
    let (fx, w, port) = setup();
    let good = changed_copy(&fx, &w, |v| {
        v.add_entry(fields("Good")).unwrap();
    });
    let other_password = changed_copy(&fx, &w, |v| {
        v.change_master_password(MasterPassword::new("a different master password".into()))
            .unwrap();
        v.add_entry(fields("Hidden")).unwrap();
    });
    let rejected = changed_copy(&fx, &w, |v| {
        v.add_entry(fields("Rejected")).unwrap();
    });
    let garbage = (b"garbage, not a wallet".to_vec(), StateVector::new());
    {
        let mut copies = port.copies.lock().unwrap();
        copies.insert(peer(1), good);
        copies.insert(peer(2), other_password);
        copies.insert(peer(3), rejected);
        copies.insert(peer(4), garbage);
    }
    port.reject.lock().unwrap().push(peer(3));
    fx.service.lock(&w).unwrap();
    assert_eq!(
        fx.service.unlock(&w, pw(PASSWORD)),
        Ok(UnlockOutcome::Unlocked)
    );
    let titles: Vec<String> = fx
        .service
        .search(&w, "")
        .unwrap()
        .iter()
        .map(|e| e.title.to_string())
        .collect();
    assert_eq!(titles, ["Good"]);
    let outcomes: BTreeMap<PeerRef, PendingOutcome> =
        port.outcomes.lock().unwrap().iter().cloned().collect();
    assert!(matches!(outcomes[&peer(1)], PendingOutcome::Merged { .. }));
    assert_eq!(
        outcomes[&peer(2)],
        PendingOutcome::CannotOpen,
        "entered password does not open it"
    );
    assert_eq!(outcomes[&peer(3)], PendingOutcome::Invalid);
    assert_eq!(outcomes[&peer(4)], PendingOutcome::Invalid);
}

#[test]
fn a_copy_under_a_newer_password_opens_with_that_password_at_unlock() {
    let (fx, w, port) = setup();
    // The phone changed the password to one the person now types here.
    let copy = changed_copy(&fx, &w, |v| {
        v.change_master_password(MasterPassword::new("the new shared password".into()))
            .unwrap();
        v.add_entry(fields("After change")).unwrap();
    });
    port.copies.lock().unwrap().insert(peer(1), copy);
    fx.service.lock(&w).unwrap();
    // The old password opens the wallet; the copy then needs its own password: cannot open.
    assert_eq!(
        fx.service.unlock(&w, pw(PASSWORD)),
        Ok(UnlockOutcome::Unlocked)
    );
    assert_eq!(
        port.outcomes.lock().unwrap().clone(),
        vec![(peer(1), PendingOutcome::CannotOpen)]
    );
}

#[test]
fn nothing_new_is_reported_unchanged_and_nothing_is_saved() {
    let (fx, w, port) = setup();
    let same = changed_copy(&fx, &w, |_| {});
    port.copies.lock().unwrap().insert(peer(1), same);
    fx.service.lock(&w).unwrap();
    let before = fx.dir.bytes(&w).unwrap();
    fx.service.unlock(&w, pw(PASSWORD)).unwrap();
    assert_eq!(fx.dir.bytes(&w).unwrap(), before);
    assert_eq!(
        port.outcomes.lock().unwrap().clone(),
        vec![(peer(1), PendingOutcome::Unchanged)]
    );
}

#[test]
fn a_wrong_password_unlocks_nothing_and_touches_no_copy() {
    let (fx, w, port) = setup();
    port.copies.lock().unwrap().insert(
        peer(1),
        changed_copy(&fx, &w, |v| {
            v.add_entry(fields("x")).unwrap();
        }),
    );
    fx.service.lock(&w).unwrap();
    assert!(fx.service.unlock(&w, pw("wrong password here")).is_err());
    assert!(port.outcomes.lock().unwrap().is_empty());
    assert_eq!(*port.unlocked.lock().unwrap(), 0);
}
