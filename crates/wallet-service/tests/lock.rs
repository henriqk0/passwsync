mod common;

use std::time::Duration;

use common::*;
use vault_core::KdfConfig;
use wallet_service::{ServiceError, UnlockOutcome};

fn unlocked(fx: &Fx) -> Vec<String> {
    fx.service
        .list()
        .unwrap()
        .into_iter()
        .filter(|w| w.unlocked)
        .map(|w| w.name.to_string())
        .collect()
}

#[test]
fn lock_is_idempotent_and_blocks_further_operations() {
    let fx = fx();
    let wallet = create(&fx, "Personal");
    let id = fx.service.add_entry(&wallet, fields("GitHub")).unwrap();
    assert_eq!(fx.service.lock(&wallet), Ok(true));
    assert_eq!(fx.service.lock(&wallet), Ok(false));
    assert!(unlocked(&fx).is_empty());
    assert_eq!(
        fx.service.search(&wallet, "").unwrap_err(),
        ServiceError::WalletLocked
    );
    assert_eq!(
        fx.service.get_entry(&wallet, id).unwrap_err(),
        ServiceError::WalletLocked
    );
    assert_eq!(
        fx.service.add_entry(&wallet, fields("x")),
        Err(ServiceError::WalletLocked)
    );
    assert_eq!(
        fx.service.lock(&name("Nobody")),
        Err(ServiceError::WalletNotFound)
    );
    assert_eq!(
        fx.service.unlock(&wallet, pw(PASSWORD)),
        Ok(UnlockOutcome::Unlocked)
    );
    assert_eq!(fx.service.search(&wallet, "").unwrap().len(), 1);
}

#[test]
fn lock_all_returns_the_wallets_it_locked() {
    let fx = fx();
    create(&fx, "b");
    create(&fx, "a");
    foreign_wallet(&fx, "c", KdfConfig::MINIMUM, &[]);
    let locked: Vec<String> = fx
        .service
        .lock_all()
        .iter()
        .map(|n| n.to_string())
        .collect();
    assert_eq!(locked, ["a", "b"]);
    assert!(fx.service.lock_all().is_empty());
    assert!(unlocked(&fx).is_empty());
}

#[test]
fn sweep_locks_wallets_idle_for_the_auto_lock_time() {
    let fx = fx();
    let a = create(&fx, "a");
    let b = create(&fx, "b");
    fx.elapsed.advance(AUTO_LOCK - Duration::from_secs(60));
    fx.service.search(&b, "").unwrap(); // deliberate action on b
    fx.elapsed.advance(Duration::from_secs(59));
    assert!(fx.service.sweep().is_empty());
    fx.elapsed.advance(Duration::from_secs(1));
    let locked: Vec<String> = fx.service.sweep().iter().map(|n| n.to_string()).collect();
    assert_eq!(locked, ["a"]);
    assert_eq!(unlocked(&fx), ["b"]);
    fx.elapsed.advance(AUTO_LOCK);
    assert_eq!(fx.service.sweep(), vec![b]);
    assert_eq!(
        fx.service.search(&a, "").unwrap_err(),
        ServiceError::WalletLocked
    );
}

#[test]
fn deliberate_actions_reset_idle_but_listing_does_not() {
    let fx = fx();
    let wallet = create(&fx, "Personal");
    let id = fx.service.add_entry(&wallet, fields("GitHub")).unwrap();
    let actions: [&dyn Fn(); 5] = [
        &|| {
            let _ = fx.service.search(&wallet, "");
        },
        &|| {
            let _ = fx.service.get_entry(&wallet, id);
        },
        &|| {
            drop(
                fx.service
                    .field(&wallet, id, wallet_service::Field::Password),
            )
        },
        &|| {
            let _ = fx.service.update_entry(&wallet, id, fields("GitHub"));
        },
        &|| {
            let _ = fx.service.unlock(&wallet, pw(PASSWORD));
        },
    ];
    for action in actions {
        fx.elapsed.advance(AUTO_LOCK - Duration::from_secs(1));
        action();
        fx.elapsed.advance(Duration::from_secs(2));
        assert!(fx.service.sweep().is_empty());
    }
    fx.elapsed.advance(AUTO_LOCK - Duration::from_secs(10));
    for _ in 0..20 {
        fx.service.list().unwrap();
        fx.elapsed.advance(Duration::from_secs(1));
    }
    assert_eq!(fx.service.sweep(), vec![wallet]);
}

#[test]
fn suspend_longer_than_5_seconds_locks_everything() {
    let fx = fx();
    create(&fx, "Personal");
    fx.elapsed.advance(Duration::from_secs(100));
    fx.elapsed.suspend(Duration::from_secs(5));
    assert_eq!(fx.service.check_suspend(), None, "5 s is not a suspend");
    fx.elapsed.suspend(Duration::from_millis(5_001));
    let locked = fx.service.check_suspend().expect("suspend detected");
    assert_eq!(locked, vec![name("Personal")]);
    assert!(unlocked(&fx).is_empty());
    assert_eq!(fx.service.check_suspend(), None, "offset updated");
}

#[test]
fn short_suspends_accumulate_until_they_exceed_5_seconds() {
    // data-model.md: the offset is updated only when a suspend is detected, so several
    // short suspends add up (any false positive only locks: the safe direction).
    let fx = fx();
    create(&fx, "Personal");
    for _ in 0..5 {
        fx.elapsed.suspend(Duration::from_secs(1));
        assert_eq!(fx.service.check_suspend(), None);
    }
    fx.elapsed.suspend(Duration::from_millis(1));
    assert!(fx.service.check_suspend().is_some());
}
