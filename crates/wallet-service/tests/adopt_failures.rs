//! 005 T076 (US5, FR-019, FR-020): a received wallet that cannot be opened creates nothing.

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use vault_core::{DeviceId, FixedClock, KdfConfig, MasterPassword, Vault};
use wallet_service::testkit::MemoryWalletDirectory;
use wallet_service::{AdoptVerdict, ServiceError, UnlockFacts};

fn received(titles: &[&str]) -> Vec<u8> {
    let mut vault = Vault::create(
        MasterPassword::new(PASSWORD.into()),
        KdfConfig::MINIMUM,
        DeviceId::new("sender-device").unwrap(),
        Box::new(FixedClock::new(5)),
    )
    .unwrap();
    for t in titles {
        vault.add_entry(fields(t)).unwrap();
    }
    vault.seal().unwrap()
}

fn proceed(_: &UnlockFacts) -> AdoptVerdict {
    AdoptVerdict::Proceed
}

fn nothing_created(fx: &Fx) {
    assert!(fx.dir.list_names().is_empty(), "nothing written");
    assert!(fx.service.list().unwrap().is_empty());
}

trait Names {
    fn list_names(&self) -> Vec<String>;
}

impl Names for MemoryWalletDirectory {
    fn list_names(&self) -> Vec<String> {
        use wallet_service::WalletDirectory;
        self.list().unwrap().iter().map(|n| n.to_string()).collect()
    }
}

#[test]
fn a_wrong_password_gives_the_generic_error_and_writes_nothing() {
    let fx = fx();
    let bytes = received(&["Bank"]);
    let called = Mutex::new(0);
    let decide = |_: &UnlockFacts| {
        *called.lock().unwrap() += 1;
        AdoptVerdict::Proceed
    };
    assert_eq!(
        fx.service
            .adopt_received("Shared", &bytes, pw("not the password!"), &decide),
        Err(ServiceError::InvalidPasswordOrCorrupted)
    );
    assert_eq!(
        *called.lock().unwrap(),
        0,
        "no facts without authentication"
    );
    nothing_created(&fx);
    // A retry with the right password works (the received bytes are untouched).
    assert!(
        fx.service
            .adopt_received("Shared", &bytes, pw(PASSWORD), &proceed)
            .is_ok()
    );
}

#[test]
fn a_tampered_file_looks_like_a_wrong_password() {
    let fx = fx();
    let mut bytes = received(&["Bank"]);
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    assert_eq!(
        fx.service
            .adopt_received("Shared", &bytes, pw(PASSWORD), &proceed),
        Err(ServiceError::InvalidPasswordOrCorrupted)
    );
    nothing_created(&fx);
}

#[test]
fn malformed_files_kdf_out_of_range_and_oversize_are_refused_before_any_derivation() {
    let fx = fx();
    let good = received(&[]);
    let mut magic = good.clone();
    magic[0] = b'X';
    assert_eq!(
        fx.service
            .adopt_received("A", &magic, pw(PASSWORD), &proceed),
        Err(ServiceError::MalformedFile)
    );
    assert_eq!(
        fx.service
            .adopt_received("A", &good[..10], pw(PASSWORD), &proceed),
        Err(ServiceError::MalformedFile)
    );
    let mut kdf = good.clone();
    kdf[7..11].copy_from_slice(&1_048_576u32.to_le_bytes());
    assert_eq!(
        fx.service.adopt_received("A", &kdf, pw(PASSWORD), &proceed),
        Err(ServiceError::KdfParamsOutOfRange)
    );
    let huge = vec![0u8; 64 * 1024 * 1024 + 1];
    let result = fx
        .service
        .adopt_received("A", &huge, pw(PASSWORD), &proceed);
    assert!(
        matches!(
            result,
            Err(ServiceError::MalformedFile | ServiceError::WalletTooLarge)
        ),
        "{result:?}"
    );
    nothing_created(&fx);
}

#[test]
fn a_format_1_file_is_unsupported() {
    let fx = fx();
    // postcard of { wallet_id: [4; 16], created_at: 1, entries: [] }
    let mut plain = vec![4u8; 16];
    plain.extend_from_slice(&[0x02, 0x00]);
    let v1 = vault_core::testkit::seal_payload(PASSWORD, KdfConfig::MINIMUM, 1, &plain);
    assert_eq!(
        fx.service
            .adopt_received("Old", &v1, pw(PASSWORD), &proceed),
        Err(ServiceError::UnsupportedVersion)
    );
    nothing_created(&fx);
}

#[test]
fn already_present_creates_no_second_wallet() {
    let fx = fx();
    let bytes = received(&["Bank"]);
    let decide = |_: &UnlockFacts| AdoptVerdict::AlreadyPresent(name("Personal"));
    assert_eq!(
        fx.service
            .adopt_received("Shared", &bytes, pw(PASSWORD), &decide),
        Err(ServiceError::AlreadyPresent)
    );
    nothing_created(&fx);
}

#[test]
fn a_storage_error_creates_nothing() {
    let fx = fx();
    fx.dir.set_failing(true);
    let bytes = received(&[]);
    assert_eq!(
        fx.service
            .adopt_received("Shared", &bytes, pw(PASSWORD), &proceed),
        Err(ServiceError::Storage)
    );
    fx.dir.set_failing(false);
    nothing_created(&fx);
}

#[test]
fn attempts_are_serialized_through_the_kdf_gate() {
    let fx = Arc::new(fx());
    let bytes = received(&[]);
    let gate = fx.service.hold_kdf_gate();
    let probe = fx.service.kdf_gate_probe();
    let worker = {
        let fx = Arc::clone(&fx);
        std::thread::spawn(move || {
            fx.service
                .adopt_received("Shared", &bytes, pw("wrong password!!"), &proceed)
        })
    };
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert_eq!(probe.load(std::sync::atomic::Ordering::SeqCst), 0);
    drop(gate);
    assert_eq!(
        worker.join().unwrap(),
        Err(ServiceError::InvalidPasswordOrCorrupted)
    );
}
