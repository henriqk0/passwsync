//! 005 T059 (US3, FR-009a, R7): the `LockObserver` hears about every lock, whatever the cause,
//! after the wallet is locked and outside the service's locks.

mod common;

use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use common::*;
use wallet_service::{LockObserver, Service, WalletName};

#[derive(Default)]
struct Recorder {
    names: Mutex<Vec<String>>,
    /// Calls back into the service from the observer: must not deadlock, and must already
    /// see the wallet locked.
    service: Mutex<Weak<Service>>,
    seen_unlocked: Mutex<Vec<bool>>,
}

impl LockObserver for Recorder {
    fn locked(&self, name: &WalletName) {
        self.names.lock().unwrap().push(name.to_string());
        if let Some(service) = self.service.lock().unwrap().upgrade() {
            let still = service
                .list()
                .unwrap()
                .iter()
                .any(|w| &w.name == name && w.unlocked);
            self.seen_unlocked.lock().unwrap().push(still);
        }
    }
}

fn setup() -> (Arc<Fx>, Arc<Recorder>) {
    let fx = Arc::new(fx());
    let recorder = Arc::new(Recorder::default());
    fx.service.set_lock_observer(recorder.clone());
    (fx, recorder)
}

fn take(recorder: &Recorder) -> Vec<String> {
    std::mem::take(&mut *recorder.names.lock().unwrap())
}

#[test]
fn manual_lock_and_lock_all_are_observed_once_each() {
    let (fx, rec) = setup();
    let a = create(&fx, "A");
    create(&fx, "B");
    fx.service.lock(&a).unwrap();
    assert_eq!(take(&rec), ["A"]);
    fx.service.lock(&a).unwrap();
    assert!(take(&rec).is_empty(), "already locked: not observed again");
    fx.service.unlock(&a, pw(PASSWORD)).unwrap();
    let mut all = fx.service.lock_all();
    all.sort();
    let mut seen = take(&rec);
    seen.sort();
    assert_eq!(seen, ["A", "B"]);
    assert_eq!(all.len(), 2);
}

#[test]
fn idle_and_suspend_locks_are_observed() {
    let (fx, rec) = setup();
    create(&fx, "A");
    fx.elapsed.advance(AUTO_LOCK);
    assert_eq!(fx.service.sweep().len(), 1);
    assert_eq!(take(&rec), ["A"]);
    fx.service.unlock(&name("A"), pw(PASSWORD)).unwrap();
    fx.elapsed.suspend(Duration::from_secs(60));
    assert!(fx.service.check_suspend().is_some());
    assert_eq!(take(&rec), ["A"]);
}

#[test]
fn a_failed_unlock_is_not_observed_and_only_one_observer_is_kept() {
    let (fx, rec) = setup();
    let a = foreign_wallet(&fx, "A", vault_core::KdfConfig::MINIMUM, &[]);
    assert!(fx.service.unlock(&a, pw("not the password!")).is_err());
    assert!(take(&rec).is_empty());
    let second = Arc::new(Recorder::default());
    fx.service.set_lock_observer(second.clone());
    fx.service.unlock(&a, pw(PASSWORD)).unwrap();
    fx.service.lock(&a).unwrap();
    assert!(take(&rec).is_empty(), "replaced");
    assert_eq!(take(&second), ["A"]);
}

#[test]
fn the_observer_can_call_back_into_the_service() {
    let fx = Arc::new(fx());
    let service: Arc<Service> = Arc::new(Service::new(
        Arc::new(fx.dir.clone()),
        fx.time.clone(),
        fx.elapsed.clone(),
        fx.service.config().clone(),
    ));
    let rec = Arc::new(Recorder::default());
    *rec.service.lock().unwrap() = Arc::downgrade(&service);
    service.set_lock_observer(rec.clone());
    let a = service.create("A", pw(PASSWORD), pw(PASSWORD)).unwrap();
    service.lock(&a).unwrap();
    service.unlock(&a, pw(PASSWORD)).unwrap();
    service.lock_all();
    fx.elapsed.advance(AUTO_LOCK);
    service.unlock(&a, pw(PASSWORD)).unwrap();
    fx.elapsed.advance(AUTO_LOCK);
    service.sweep();
    assert_eq!(take(&rec), ["A", "A", "A"]);
    assert_eq!(
        *rec.seen_unlocked.lock().unwrap(),
        [false, false, false],
        "already locked when observed"
    );
}
