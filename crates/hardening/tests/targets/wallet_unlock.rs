//! Target 3 `wallet_unlock` (FR-012, research R8): full `Vault::unlock` with the correct
//! synthetic password. Keys are derived only for headers at `KdfConfig::MINIMUM`; any input
//! that differs from a seed must fail with exactly the generic error and return nothing.

use std::sync::OnceLock;

use hardening::mutate::{Input, Seed};
use hardening::oracle::{FailureKind, Verdict};
use hardening::runner::Target;
use vault_core::testkit::{encode_payload, encode_payload_v1, parse_header, seal_payload_with};
use vault_core::{DeviceId, FixedClock, KdfConfig, MasterPassword, Vault, VaultError};

use super::common::violation;
use super::wallet_header::kind;
use super::wallet_payload::{live, payload};

pub const PASSWORD: &str = "fuzz-only-password";
pub const KINDS: &[&str] = &[
    "MalformedFile",
    "UnsupportedVersion",
    "UnsupportedKdf",
    "KdfParamsOutOfRange",
    "InvalidPasswordOrCorrupted",
    "NotDerived",
];

fn unlock(bytes: &[u8]) -> Result<Vault, VaultError> {
    Vault::unlock(
        bytes,
        MasterPassword::new(PASSWORD.into()),
        DeviceId::new("fz-unlock").unwrap(),
        Box::new(FixedClock::new(1)),
    )
}

/// Deterministic sealed wallets (fixed plaintext, salt and nonce), so seeds and counts are
/// identical across runs (SC-002).
fn sealed() -> &'static Vec<Vec<u8>> {
    static SEALED: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    SEALED.get_or_init(|| {
        let entries = || vec![live(1, "fz-1", 8), live(2, "fz-2", 8)];
        let v2 = seal_payload_with(
            PASSWORD,
            KdfConfig::MINIMUM,
            2,
            &encode_payload(&payload(entries())),
            [0x11; 32],
            [0x22; 12],
        );
        let v1 = seal_payload_with(
            PASSWORD,
            KdfConfig::MINIMUM,
            1,
            &encode_payload_v1(&payload(entries())),
            [0x33; 32],
            [0x44; 12],
        );
        vec![v2, v1]
    })
}

pub fn seeds() -> Vec<Seed> {
    vec![
        Seed::new("v2-minimum", sealed()[0].clone()),
        Seed::new("v1-minimum", sealed()[1].clone()),
    ]
}

pub fn one(input: &Input) -> Verdict {
    let bytes = &input.bytes;
    let header = match parse_header(bytes) {
        Err(error) => {
            // Rejected by the header checks: unlock must give the same kind, before deriving.
            return match unlock(bytes) {
                Err(e) if kind(&e) == kind(&error) => Verdict::Rejected(kind(&error)),
                _ => violation(FailureKind::NotGeneric, "unlock and header checks disagree"),
            };
        }
        Ok(header) => header,
    };
    if header.kdf != KdfConfig::MINIMUM {
        // KDF bytes are judged by the header checks only; never derived (R8).
        return Verdict::Rejected("NotDerived");
    }
    let genuine = sealed().iter().any(|s| s == bytes);
    let inner = match (unlock(bytes), genuine) {
        (Ok(_), true) => Verdict::Accepted,
        (Err(VaultError::InvalidPasswordOrCorrupted), false) => {
            Verdict::Rejected("InvalidPasswordOrCorrupted")
        }
        (Ok(_), false) => violation(FailureKind::NotGeneric, "a modified wallet unlocked"),
        (Err(_), false) => violation(FailureKind::NotGeneric, "error is not the generic one"),
        (Err(_), true) => violation(FailureKind::ValueBound, "a genuine wallet did not unlock"),
    };
    Verdict::Derived(Box::new(inner))
}

pub fn target() -> Target {
    Target::new("wallet_unlock", seeds, one)
        .derived(64, 4096)
        .sweep(false)
        .time_limit(std::time::Duration::from_secs(10))
        .alloc_bound((64 + 20) * 1024 * 1024)
        .error_kinds(KINDS)
}

pub fn one_bytes(data: &[u8]) {
    hardening::runner::check_bytes(&target(), 0, data);
}
