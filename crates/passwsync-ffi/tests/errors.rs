//! contracts/ffi-api.md section 4: `CoreError` has exactly 37 variants, fixed messages without
//! user data and the stable 001-005 codes for the service errors.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use passwsync_ffi::error::{CoreError, Protection};
use passwsync_ffi::ports::PlatformError;
use vault_core::{DeviceId, FixedClock, KdfConfig};
use wallet_service::testkit::{FakeElapsedClock, MemoryWalletDirectory};
use wallet_service::{Service, ServiceConfig, ServiceError};
use zeroize::Zeroizing;

const SERVICE: [ServiceError; 25] = [
    ServiceError::InvalidName,
    ServiceError::PasswordTooShort,
    ServiceError::PasswordMismatch,
    ServiceError::EmptyTitle,
    ServiceError::FieldTooLarge,
    ServiceError::WalletNotFound,
    ServiceError::EntryNotFound,
    ServiceError::WalletExists,
    ServiceError::WalletLocked,
    ServiceError::InvalidPasswordOrCorrupted,
    ServiceError::MalformedFile,
    ServiceError::UnsupportedVersion,
    ServiceError::UnsupportedKdf,
    ServiceError::KdfParamsOutOfRange,
    ServiceError::WalletTooLarge,
    ServiceError::EntryConflicted,
    ServiceError::CannotOpenCopy,
    ServiceError::CopyRejected,
    ServiceError::TooManyConflicts,
    ServiceError::PasswordConflict,
    ServiceError::NotConflicted,
    ServiceError::InvalidVersionIndex,
    ServiceError::AlreadyPresent,
    ServiceError::Storage,
    ServiceError::Internal,
];

fn others() -> Vec<CoreError> {
    vec![
        CoreError::ProtectionMissing {
            which: Protection::CoreDumps,
        },
        CoreError::ProtectionMissing {
            which: Protection::NonDumpable,
        },
        CoreError::InvalidInput,
        CoreError::NetworkOff,
        CoreError::NotForeground,
        CoreError::NoPeer,
        CoreError::Busy,
        CoreError::IdentityUnusable,
        CoreError::PeersUnusable,
        CoreError::Pairing { reason: "expired" },
        CoreError::Share { reason: "expired" },
        CoreError::AlreadyStarted,
        CoreError::Platform,
    ]
}

fn all() -> Vec<CoreError> {
    let mut out: Vec<CoreError> = SERVICE.iter().map(|&e| CoreError::from(e)).collect();
    out.extend(others());
    out
}

#[test]
fn there_are_exactly_37_variants() {
    let codes: BTreeSet<&str> = all().into_iter().map(CoreError::code).collect();
    assert_eq!(codes.len(), 37, "{codes:?}");
    // The source lists the variants once; B5 compares the same list.
    let source = include_str!("../src/error.rs");
    let enum_body = source.split("pub enum CoreError").nth(1).unwrap();
    let extra = enum_body.split("impl From").next().unwrap();
    let declared = extra
        .lines()
        .map(str::trim)
        .filter(|l| l.chars().next().is_some_and(char::is_uppercase))
        .count();
    assert_eq!(declared, 12, "12 non-service variants are declared");
}

#[test]
fn service_errors_keep_their_stable_codes() {
    for error in SERVICE {
        assert_eq!(CoreError::from(error).code(), error.code(), "{error:?}");
        assert_eq!(CoreError::from(error).to_string(), error.message());
    }
    assert_eq!(
        CoreError::from(ServiceError::KdfParamsOutOfRange).code(),
        "kdf_params_out_of_range"
    );
    assert_eq!(
        CoreError::from(ServiceError::CopyRejected).code(),
        "invalid_copy"
    );
}

#[test]
fn display_is_a_fixed_string_without_user_data() {
    let mut seen = BTreeSet::new();
    for error in all() {
        let text = error.to_string();
        assert!(!text.is_empty());
        assert!(!text.contains("expired"), "reason not interpolated: {text}");
        assert!(!text.contains('{'), "no placeholder: {text}");
        seen.insert(text);
    }
    // The two protections have their own message; every other variant may share none.
    assert!(seen.len() >= 36);
    assert_eq!(
        CoreError::Pairing { reason: "a" }.to_string(),
        CoreError::Pairing { reason: "b" }.to_string()
    );
}

#[test]
fn platform_errors_map_to_platform() {
    for error in [
        PlatformError::Unavailable,
        PlatformError::Invalidated,
        PlatformError::Failed,
    ] {
        assert_eq!(CoreError::from(error), CoreError::Platform);
        assert!(!error.to_string().is_empty());
    }
}

fn service(dir: &MemoryWalletDirectory) -> Service {
    Service::new(
        Arc::new(dir.clone()),
        Arc::new(FixedClock::new(1_000)),
        Arc::new(FakeElapsedClock::new()),
        ServiceConfig {
            device: DeviceId::new("0123456789abcdef0123456789abcdef").unwrap(),
            wallet_kdf: KdfConfig::MINIMUM,
            auto_lock: Duration::from_secs(900),
        },
    )
}

fn pw(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_string())
}

#[test]
fn wrong_password_and_corrupted_file_give_the_same_error() {
    let dir = MemoryWalletDirectory::new();
    let svc = service(&dir);
    let name = svc
        .create(
            "Personal",
            pw("correct horse battery"),
            pw("correct horse battery"),
        )
        .unwrap();
    svc.lock(&name).unwrap();
    let wrong = CoreError::from(svc.unlock(&name, pw("wrong password!!")).unwrap_err());

    let mut bytes = dir.bytes(&name).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    dir.insert(&name, &bytes);
    let fresh = service(&dir);
    let corrupt = CoreError::from(
        fresh
            .unlock(&name, pw("correct horse battery"))
            .unwrap_err(),
    );

    assert_eq!(wrong, CoreError::InvalidPasswordOrCorrupted);
    assert_eq!(corrupt, wrong);
    assert_eq!(wrong.code(), "invalid_password_or_corrupted");
    assert_eq!(wrong.to_string(), corrupt.to_string());
}
