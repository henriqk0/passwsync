mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use common::*;
use vault_core::KdfConfig;
use wallet_service::{ServiceError, UnlockOutcome};

#[test]
fn correct_password_unlocks_a_locked_wallet() {
    let fx = fx();
    let wallet = foreign_wallet(&fx, "Personal", KdfConfig::MINIMUM, &["GitHub"]);
    assert!(!fx.service.list().unwrap()[0].unlocked);
    assert_eq!(
        fx.service.unlock(&wallet, pw(PASSWORD)),
        Ok(UnlockOutcome::Unlocked)
    );
    assert!(fx.service.list().unwrap()[0].unlocked);
    fx.service.add_entry(&wallet, fields("GitLab")).unwrap();
    assert_eq!(
        reopen(&fx, &wallet).list().len(),
        2,
        "existing entries kept"
    );
}

#[test]
fn wrong_password_gives_the_generic_error_and_stays_locked() {
    let fx = fx();
    let wallet = foreign_wallet(&fx, "Personal", KdfConfig::MINIMUM, &[]);
    assert_eq!(
        fx.service.unlock(&wallet, pw("wrong password!!")),
        Err(ServiceError::InvalidPasswordOrCorrupted)
    );
    assert!(!fx.service.list().unwrap()[0].unlocked);
    assert_eq!(
        fx.service.add_entry(&wallet, fields("x")),
        Err(ServiceError::WalletLocked)
    );
}

#[test]
fn already_unlocked_returns_without_running_the_kdf() {
    let fx = fx();
    let wallet = create(&fx, "Personal");
    let started = Instant::now();
    assert_eq!(
        fx.service
            .unlock(&wallet, pw("anything at all, even wrong")),
        Ok(UnlockOutcome::AlreadyUnlocked)
    );
    assert!(started.elapsed() < Duration::from_millis(20));
}

#[test]
fn unknown_wallet_is_not_found() {
    let fx = fx();
    assert_eq!(
        fx.service.unlock(&name("Nobody"), pw(PASSWORD)),
        Err(ServiceError::WalletNotFound)
    );
}

#[test]
fn kdf_memory_above_the_cap_is_refused_before_argon2() {
    let fx = fx();
    let at_cap = KdfConfig {
        memory_kib: 131_072,
        iterations: 2,
        parallelism: 1,
    };
    let wallet = foreign_wallet(&fx, "AtCap", at_cap, &[]);
    assert_eq!(
        fx.service.unlock(&wallet, pw(PASSWORD)),
        Ok(UnlockOutcome::Unlocked)
    );
    // Rewrite the header of a valid file to ask for more memory than the cap: a real
    // Argon2 run would take long; the refusal must be immediate.
    let big = foreign_wallet(&fx, "Big", KdfConfig::MINIMUM, &[]);
    let mut bytes = fx.dir.bytes(&big).unwrap();
    bytes[7..11].copy_from_slice(&1_048_576u32.to_le_bytes());
    fx.dir.insert(&big, &bytes);
    let started = Instant::now();
    assert_eq!(
        fx.service.unlock(&big, pw(PASSWORD)),
        Err(ServiceError::KdfParamsOutOfRange)
    );
    assert!(started.elapsed() < Duration::from_millis(50));
}

#[test]
fn format_errors_map_to_their_classes() {
    let fx = fx();
    type Damage = fn(&mut Vec<u8>);
    let cases: [(&str, Damage, ServiceError); 4] = [
        ("Magic", |b| b[0] = b'X', ServiceError::MalformedFile),
        ("Version", |b| b[4] = 9, ServiceError::UnsupportedVersion),
        ("Kdf", |b| b[6] = 7, ServiceError::UnsupportedKdf),
        ("Short", |b| b.truncate(10), ServiceError::MalformedFile),
    ];
    for (wallet, damage, expected) in cases {
        let n = foreign_wallet(&fx, wallet, KdfConfig::MINIMUM, &[]);
        let mut bytes = fx.dir.bytes(&n).unwrap();
        damage(&mut bytes);
        fx.dir.insert(&n, &bytes);
        assert_eq!(
            fx.service.unlock(&n, pw(PASSWORD)),
            Err(expected),
            "{wallet}"
        );
    }
    let tampered = foreign_wallet(&fx, "Tampered", KdfConfig::MINIMUM, &[]);
    let mut bytes = fx.dir.bytes(&tampered).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fx.dir.insert(&tampered, &bytes);
    assert_eq!(
        fx.service.unlock(&tampered, pw(PASSWORD)),
        Err(ServiceError::InvalidPasswordOrCorrupted)
    );
}

#[test]
fn a_new_service_starts_with_every_wallet_locked() {
    let first = fx();
    create(&first, "Personal");
    let second = fx_with_dir(first.dir.clone());
    assert!(!second.service.list().unwrap()[0].unlocked);
}

#[test]
fn key_derivations_are_serialized_service_wide() {
    let fx = Arc::new(fx());
    let names: Vec<_> = (0..3)
        .map(|i| foreign_wallet(&fx, &format!("W{i}"), KdfConfig::MINIMUM, &[]))
        .collect();
    let gate = fx.service.kdf_gate_probe();
    let peak = Arc::new(AtomicUsize::new(0));
    let handles: Vec<_> = names
        .into_iter()
        .map(|n| {
            let fx = Arc::clone(&fx);
            thread::spawn(move || fx.service.unlock(&n, pw(PASSWORD)).unwrap())
        })
        .collect();
    let watcher = {
        let gate = Arc::clone(&gate);
        let peak = Arc::clone(&peak);
        thread::spawn(move || {
            for _ in 0..2000 {
                peak.fetch_max(gate.load(Ordering::SeqCst), Ordering::SeqCst);
                thread::sleep(Duration::from_micros(100));
            }
        })
    };
    for handle in handles {
        handle.join().unwrap();
    }
    watcher.join().unwrap();
    assert_eq!(peak.load(Ordering::SeqCst), 1, "never two KDF runs at once");
}

/// Runs `op` on another thread and says whether it finished within two seconds.
fn completes(fx: &Arc<Fx>, op: impl FnOnce(&Fx) + Send + 'static) -> bool {
    let (done, finished) = std::sync::mpsc::channel();
    let fx = Arc::clone(fx);
    thread::spawn(move || {
        op(&fx);
        let _ = done.send(());
    });
    finished.recv_timeout(Duration::from_secs(2)).is_ok()
}

/// While a key derivation is waiting (the test holds the KDF gate, standing in for a slow
/// Argon2 run), the wallet list and other wallets keep being served.
#[test]
fn list_and_other_wallets_are_served_while_a_key_derivation_runs() {
    for pending in ["unlock", "create"] {
        let fx = Arc::new(fx());
        let other = create(&fx, "Other");
        let locked = foreign_wallet(&fx, "Locked", KdfConfig::MINIMUM, &[]);
        let gate = fx.service.hold_kdf_gate();
        let worker = {
            let fx = Arc::clone(&fx);
            thread::spawn(move || match pending {
                "unlock" => {
                    fx.service.unlock(&locked, pw(PASSWORD)).unwrap();
                }
                _ => {
                    fx.service
                        .create("New", pw(PASSWORD), pw(PASSWORD))
                        .unwrap();
                }
            })
        };
        thread::sleep(Duration::from_millis(100));
        assert!(
            completes(&fx, |fx| {
                fx.service.list().unwrap();
            }),
            "list blocked by a pending {pending}"
        );
        let o = other.clone();
        assert!(
            completes(&fx, move |fx| {
                fx.service.add_entry(&o, fields("GitHub")).unwrap();
                fx.service.search(&o, "").unwrap();
            }),
            "another wallet blocked by a pending {pending}"
        );
        assert!(
            completes(&fx, move |fx| {
                fx.service.lock(&other).unwrap();
            }),
            "locking another wallet blocked by a pending {pending}"
        );
        drop(gate);
        worker.join().unwrap();
    }
}

#[test]
fn concurrent_unlocks_of_one_wallet_run_one_kdf() {
    let fx = Arc::new(fx());
    let wallet = foreign_wallet(&fx, "Personal", KdfConfig::MINIMUM, &[]);
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let fx = Arc::clone(&fx);
            let wallet = wallet.clone();
            thread::spawn(move || fx.service.unlock(&wallet, pw(PASSWORD)).unwrap())
        })
        .collect();
    let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| **o == UnlockOutcome::Unlocked)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| **o == UnlockOutcome::AlreadyUnlocked)
            .count(),
        3
    );
}
