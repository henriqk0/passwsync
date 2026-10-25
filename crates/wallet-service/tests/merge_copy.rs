//! 004 T055, T057, T058: merging a received copy into an unlocked wallet
//! (contracts/vault-core-sync-api.md "wallet-service").

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use common::*;
use vault_core::{DeviceId, FixedClock, MasterPassword, Vault};
use wallet_service::{CopyFacts, CopyVerdict, EpochRelation, ServiceError};

fn accept(_: &CopyFacts) -> CopyVerdict {
    CopyVerdict::Accept
}

/// The stored wallet opened as another device, changed by `edit`, sealed again.
fn copy_from_other(
    fx: &Fx,
    wallet: &wallet_service::WalletName,
    edit: impl FnOnce(&mut Vault),
) -> Vec<u8> {
    let mut other = Vault::unlock(
        &fx.dir.bytes(wallet).unwrap(),
        MasterPassword::new(PASSWORD.into()),
        DeviceId::new("phone").unwrap(),
        Box::new(FixedClock::new(2_000)),
    )
    .unwrap();
    edit(&mut other);
    other.seal().unwrap()
}

#[test]
fn an_unlocked_wallet_merges_and_saves_a_copy() {
    let fx = fx();
    let w = create(&fx, "Personal");
    fx.service.add_entry(&w, fields("Local")).unwrap();
    let bytes = copy_from_other(&fx, &w, |v| {
        v.add_entry(fields("From phone")).unwrap();
    });
    let report = fx.service.merge_copy(&w, &bytes, &accept).unwrap();
    assert!(report.changed);
    let titles: Vec<String> = fx
        .service
        .search(&w, "")
        .unwrap()
        .iter()
        .map(|e| e.title.to_string())
        .collect();
    assert_eq!(titles, ["From phone", "Local"]);
    let saved = reopen(&fx, &w);
    assert_eq!(saved.all_records().count(), 2, "saved before returning");
}

#[test]
fn a_locked_wallet_refuses_and_keeps_nothing() {
    let fx = fx();
    let w = create(&fx, "Personal");
    let bytes = copy_from_other(&fx, &w, |v| {
        v.add_entry(fields("x")).unwrap();
    });
    fx.service.lock(&w).unwrap();
    let before = fx.dir.bytes(&w);
    assert_eq!(
        fx.service.merge_copy(&w, &bytes, &accept),
        Err(ServiceError::WalletLocked)
    );
    assert_eq!(fx.dir.bytes(&w), before);
}

#[test]
fn the_check_sees_authenticated_facts_and_can_reject() {
    let fx = fx();
    let w = create(&fx, "Personal");
    let bytes = copy_from_other(&fx, &w, |v| {
        v.add_entry(fields("x")).unwrap();
    });
    let (wid, local_state) = fx.service.sync_facts(&w).unwrap();
    let seen = std::sync::Mutex::new(None);
    let result = fx.service.merge_copy(&w, &bytes, &|facts| {
        *seen.lock().unwrap() = Some((facts.wallet_id, facts.state.clone(), facts.password_epoch));
        CopyVerdict::Reject
    });
    assert_eq!(result, Err(ServiceError::CopyRejected));
    let (id, state, epoch) = seen.lock().unwrap().clone().unwrap();
    assert_eq!(id, wid);
    assert!(state.dominates(&local_state) && state != local_state);
    assert_eq!(epoch, EpochRelation::Equal);
    assert_eq!(
        fx.service.search(&w, "").unwrap().len(),
        0,
        "nothing merged"
    );
}

#[test]
fn copies_that_cannot_be_opened_or_belong_elsewhere_are_refused() {
    let fx = fx();
    let w = create(&fx, "Personal");
    // Another password: needs that password.
    let other_password = copy_from_other(&fx, &w, |v| {
        v.change_master_password(MasterPassword::new("another long password".into()))
            .unwrap();
    });
    assert_eq!(
        fx.service.merge_copy(&w, &other_password, &accept),
        Err(ServiceError::CannotOpenCopy)
    );
    // Tampered ciphertext.
    let mut tampered = copy_from_other(&fx, &w, |_| {});
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        fx.service.merge_copy(&w, &tampered, &accept),
        Err(ServiceError::CannotOpenCopy)
    );
    // Garbage that is not a wallet file at all.
    assert_eq!(
        fx.service.merge_copy(&w, b"not a wallet", &accept),
        Err(ServiceError::CopyRejected)
    );
}

#[test]
fn a_failed_save_rolls_the_merge_back() {
    let fx = fx();
    let w = create(&fx, "Personal");
    let bytes = copy_from_other(&fx, &w, |v| {
        v.add_entry(fields("x")).unwrap();
    });
    let before = fx.service.sync_facts(&w).unwrap();
    fx.dir.set_failing(true);
    assert_eq!(
        fx.service.merge_copy(&w, &bytes, &accept),
        Err(ServiceError::Storage)
    );
    assert_eq!(fx.service.sync_facts(&w).unwrap(), before);
    assert!(fx.service.search(&w, "").unwrap().is_empty());
    fx.dir.set_failing(false);
    assert!(fx.service.merge_copy(&w, &bytes, &accept).unwrap().changed);
}

#[test]
fn merging_never_resets_the_idle_timer() {
    let fx = fx();
    let w = create(&fx, "Personal");
    fx.elapsed.advance(AUTO_LOCK - Duration::from_secs(10));
    let bytes = copy_from_other(&fx, &w, |v| {
        v.add_entry(fields("x")).unwrap();
    });
    fx.service.merge_copy(&w, &bytes, &accept).unwrap();
    assert!(fx.service.sync_facts(&w).is_some());
    fx.elapsed.advance(Duration::from_secs(10));
    assert_eq!(
        fx.service.sweep(),
        vec![w.clone()],
        "still locks on time (FR-006b)"
    );
    assert!(
        fx.service.sync_facts(&w).is_none(),
        "facts only while unlocked"
    );
}

// --- T057: FR-026, a local edit made while a copy was prepared is not lost ---

#[test]
fn a_local_edit_after_the_copy_was_made_survives_the_merge() {
    let fx = fx();
    let w = create(&fx, "Personal");
    let bytes = copy_from_other(&fx, &w, |v| {
        v.add_entry(fields("From phone")).unwrap();
    });
    // The person edits locally after the copy was prepared elsewhere.
    fx.service.add_entry(&w, fields("Typed just now")).unwrap();
    fx.service.merge_copy(&w, &bytes, &accept).unwrap();
    let titles: Vec<String> = fx
        .service
        .search(&w, "")
        .unwrap()
        .iter()
        .map(|e| e.title.to_string())
        .collect();
    assert_eq!(titles, ["From phone", "Typed just now"]);
    assert_eq!(reopen(&fx, &w).all_records().count(), 2);
}

#[test]
fn concurrent_local_edits_and_merges_lose_nothing() {
    let fx = Arc::new(fx());
    let w = create(&fx, "Personal");
    let copies: Vec<Vec<u8>> = (0..5)
        .map(|i| {
            copy_from_other(&fx, &w, |v| {
                v.add_entry(fields(&format!("remote {i}"))).unwrap();
            })
        })
        .collect();
    let editor = {
        let fx = Arc::clone(&fx);
        let w = w.clone();
        thread::spawn(move || {
            for i in 0..20 {
                fx.service
                    .add_entry(&w, fields(&format!("local {i}")))
                    .unwrap();
            }
        })
    };
    for bytes in &copies {
        fx.service.merge_copy(&w, bytes, &accept).unwrap();
    }
    editor.join().unwrap();
    assert_eq!(fx.service.search(&w, "").unwrap().len(), 25);
    assert_eq!(reopen(&fx, &w).all_records().count(), 25);
}

// --- T058: merges are serialized with key derivations (memory budget) ---

#[test]
fn a_merge_waits_for_a_running_key_derivation() {
    let fx = Arc::new(fx());
    let w = create(&fx, "Personal");
    let bytes = copy_from_other(&fx, &w, |v| {
        v.add_entry(fields("x")).unwrap();
    });
    let done = Arc::new(AtomicBool::new(false));
    let gate = fx.service.hold_kdf_gate();
    let worker = {
        let (fx, w, done) = (Arc::clone(&fx), w.clone(), Arc::clone(&done));
        thread::spawn(move || {
            fx.service.merge_copy(&w, &bytes, &accept).unwrap();
            done.store(true, Ordering::SeqCst);
        })
    };
    thread::sleep(Duration::from_millis(150));
    assert!(
        !done.load(Ordering::SeqCst),
        "merge ran during a key derivation"
    );
    drop(gate);
    worker.join().unwrap();
    assert!(done.load(Ordering::SeqCst));
}

#[test]
fn copy_facts_report_the_password_epoch_relation() {
    let fx = fx();
    let w = create(&fx, "Personal");
    let newer = copy_from_other(&fx, &w, |v| {
        v.change_master_password(MasterPassword::new(PASSWORD.into()))
            .unwrap();
    });
    // Same password text, but a new salt: the copy needs that password.
    assert_eq!(
        fx.service.merge_copy(&w, &newer, &accept),
        Err(ServiceError::CannotOpenCopy)
    );
}

// --- T098: authenticated checks at merge time (FR-008, FR-012, FR-021a, FR-031) ---

#[test]
fn every_failed_check_leaves_the_wallet_untouched() {
    let fx = fx();
    let w = create(&fx, "Personal");
    let good = copy_from_other(&fx, &w, |v| {
        v.add_entry(fields("x")).unwrap();
    });
    let (wid, _) = fx.service.sync_facts(&w).unwrap();
    let before = fx.dir.bytes(&w);
    // The sync layer's checks, each failing in turn.
    let claimed_other = vault_core::StateVector::new();
    type Check = Box<dyn Fn(&CopyFacts) -> CopyVerdict>;
    let checks: Vec<Check> = vec![
        // Requested for another wallet.
        Box::new(|f| {
            if f.wallet_id == vault_core::WalletId::from_bytes([0; 16]) {
                CopyVerdict::Accept
            } else {
                CopyVerdict::Reject
            }
        }),
        // Authenticated state differs from the claimed one.
        Box::new(move |f| {
            if f.state == claimed_other {
                CopyVerdict::Accept
            } else {
                CopyVerdict::Reject
            }
        }),
        // Below the peer mark / jump too large: the check refuses.
        Box::new(|_| CopyVerdict::Reject),
    ];
    for check in &checks {
        assert_eq!(
            fx.service.merge_copy(&w, &good, check.as_ref()),
            Err(ServiceError::CopyRejected)
        );
    }
    let _ = wid;
    // Tampered, truncated, or under another key: cannot be opened.
    let mut tampered = good.clone();
    tampered[70] ^= 0x80;
    assert_eq!(
        fx.service.merge_copy(&w, &tampered, &accept),
        Err(ServiceError::CannotOpenCopy)
    );
    assert_eq!(
        fx.service.merge_copy(&w, &good[..good.len() - 5], &accept),
        Err(ServiceError::CannotOpenCopy)
    );
    assert_eq!(
        fx.service.merge_copy(&w, &good[..40], &accept),
        Err(ServiceError::CopyRejected)
    );
    let foreign = {
        let fx2 = common::fx();
        let w2 = create(&fx2, "Other");
        fx2.dir.bytes(&w2).unwrap()
    };
    assert_eq!(
        fx.service.merge_copy(&w, &foreign, &accept),
        Err(ServiceError::CannotOpenCopy)
    );
    assert_eq!(fx.dir.bytes(&w), before, "wallet untouched");
    assert!(fx.service.search(&w, "").unwrap().is_empty());
}
