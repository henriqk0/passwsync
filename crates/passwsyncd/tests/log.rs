use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use passwsyncd::log::{ErrorClass, LockReason, Log, LogEvent, Protection, Reason, Rejections};
use wallet_service::WalletName;

fn text(event: LogEvent<'_>) -> String {
    event.to_string()
}

#[test]
fn every_variant_renders_the_contract_text() {
    let wallet = WalletName::parse("Personal").unwrap();
    let addr: SocketAddr = "127.0.0.1:27471".parse().unwrap();
    assert_eq!(text(LogEvent::Started { addr }), "started 127.0.0.1:27471");
    assert_eq!(
        text(LogEvent::LaunchFile {
            path: Path::new("/run/user/1/passwsync/launch-url")
        }),
        "launch file /run/user/1/passwsync/launch-url"
    );
    assert_eq!(text(LogEvent::ProtectionsApplied), "protections applied");
    let failures = [
        (Protection::CoreDumps, "core-dumps"),
        (Protection::NonDumpable, "non-dumpable"),
        (Protection::MemlockLimit, "memlock-limit"),
        (Protection::Mlockall, "mlockall"),
    ];
    for (which, name) in failures {
        assert_eq!(
            text(LogEvent::ProtectionFailed {
                which,
                class: ErrorClass::LimitTooLow
            }),
            format!("protection failed: {name} (limit-too-low)")
        );
    }
    assert_eq!(
        text(LogEvent::Unlocked { wallet: &wallet }),
        "unlocked Personal"
    );
    let reasons = [
        (LockReason::Manual, "manual"),
        (LockReason::All, "all"),
        (LockReason::Idle, "idle"),
        (LockReason::Suspend, "suspend"),
        (LockReason::Stop, "stop"),
    ];
    for (reason, word) in reasons {
        assert_eq!(
            text(LogEvent::Locked {
                wallet: &wallet,
                reason
            }),
            format!("locked Personal ({word})")
        );
    }
    assert_eq!(text(LogEvent::SuspendDetected), "suspend detected");
    assert_eq!(
        text(LogEvent::Error {
            class: ErrorClass::Storage
        }),
        "error storage"
    );
    assert_eq!(text(LogEvent::Stopping), "stopping");
}

#[test]
fn error_classes_are_fixed_words() {
    let classes = [
        (ErrorClass::Permission, "permission"),
        (ErrorClass::Resource, "resource"),
        (ErrorClass::LimitTooLow, "limit-too-low"),
        (ErrorClass::Io, "io"),
        (ErrorClass::Storage, "storage"),
        (ErrorClass::Internal, "internal"),
    ];
    for (class, word) in classes {
        assert_eq!(text(LogEvent::Error { class }), format!("error {word}"));
    }
}

#[test]
fn rejections_aggregate_and_emit_once_per_minute_only_when_non_zero() {
    let rejections = Rejections::default();
    assert!(
        rejections.flush(Duration::from_secs(0)).is_none(),
        "nothing counted"
    );
    rejections.count(Reason::Host);
    rejections.count(Reason::Host);
    rejections.count(Reason::Peer);
    rejections.count(Reason::Size);
    let line = rejections
        .flush(Duration::from_secs(100))
        .unwrap()
        .to_string();
    assert_eq!(
        line,
        "rejected host=2 origin=0 csrf=0 session=0 size=1 peer=1"
    );
    assert!(
        rejections.flush(Duration::from_secs(101)).is_none(),
        "reset after emit"
    );
    rejections.count(Reason::Csrf);
    assert!(
        rejections.flush(Duration::from_secs(130)).is_none(),
        "under a minute"
    );
    rejections.count(Reason::Origin);
    rejections.count(Reason::Session);
    let line = rejections
        .flush(Duration::from_secs(160))
        .unwrap()
        .to_string();
    assert_eq!(
        line,
        "rejected host=0 origin=1 csrf=1 session=1 size=0 peer=0"
    );
}

#[test]
fn log_writes_one_line_per_event() {
    let (log, buffer) = Log::to_buffer();
    log.emit(&LogEvent::ProtectionsApplied);
    log.emit(&LogEvent::Stopping);
    assert_eq!(
        String::from_utf8(buffer.lock().unwrap().clone()).unwrap(),
        "passwsyncd: protections applied\npasswsyncd: stopping\n"
    );
}
