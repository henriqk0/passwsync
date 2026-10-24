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

// --- 003: network events (contracts/host-runtime-network.md "Log events") ---

mod network {
    use std::time::Duration;

    use device_link::error::{DropCounters, DropReason, FailReason};
    use device_link::identity::DeviceId;
    use device_link::name::InterfaceName;
    use passwsyncd::log::{DisconnectReason, DropLog, LogEvent, NetUnavailable, RefuseReason};

    fn text(event: LogEvent<'_>) -> String {
        event.to_string()
    }

    #[test]
    fn every_network_variant_renders_the_contract_text() {
        let fp = DeviceId::from_bytes([0; 32]).fingerprint();
        let f = fp.as_str();
        let ifs = [
            InterfaceName::parse("wlan0").unwrap(),
            InterfaceName::parse("eth0").unwrap(),
        ];
        assert_eq!(text(LogEvent::NetworkOff), "network off");
        assert_eq!(
            text(LogEvent::NetworkOn {
                peer: 27472,
                discovery: 27473,
                interfaces: &ifs
            }),
            "network on peer=27472 discovery=27473 interfaces=wlan0,eth0"
        );
        let unavailable = [
            (NetUnavailable::IdentityUnusable, "identity-unusable"),
            (NetUnavailable::PeersUnusable, "peers-unusable"),
            (NetUnavailable::PortInUse(27472), "port-in-use 27472"),
            (NetUnavailable::NoLocalNetwork, "no-local-network"),
        ];
        for (why, word) in unavailable {
            assert_eq!(
                text(LogEvent::NetworkUnavailable(why)),
                format!("network unavailable ({word})")
            );
        }
        assert_eq!(
            text(LogEvent::InterfacesChanged {
                interfaces: &ifs[..1]
            }),
            "network interfaces changed wlan0"
        );
        assert_eq!(text(LogEvent::PairingStarted), "pairing started");
        assert_eq!(
            text(LogEvent::PairingSucceeded { fingerprint: &fp }),
            format!("pairing succeeded {f}")
        );
        for reason in FailReason::ALL {
            assert_eq!(
                text(LogEvent::PairingFailed(reason)),
                format!("pairing failed ({})", reason.as_str())
            );
        }
        assert_eq!(
            text(LogEvent::PeerConnected { fingerprint: &fp }),
            format!("peer connected {f}")
        );
        for (why, word) in [
            (DisconnectReason::Timeout, "timeout"),
            (DisconnectReason::Closed, "closed"),
            (DisconnectReason::Error, "error"),
            (DisconnectReason::Duplicate, "duplicate"),
        ] {
            assert_eq!(
                text(LogEvent::PeerDisconnected {
                    fingerprint: &fp,
                    why
                }),
                format!("peer disconnected {f} ({word})")
            );
        }
        for (why, word) in [
            (RefuseReason::Unpaired, "unpaired"),
            (RefuseReason::Revoked, "revoked"),
            (RefuseReason::KeyMismatch, "key-mismatch"),
        ] {
            assert_eq!(
                text(LogEvent::PeerRefused {
                    fingerprint: &fp,
                    why
                }),
                format!("peer refused {f} ({word})")
            );
        }
        assert_eq!(
            text(LogEvent::RefusedByPeer { fingerprint: &fp }),
            format!("refused by peer {f}")
        );
        assert_eq!(
            text(LogEvent::DeviceRevoked { fingerprint: &fp }),
            format!("device revoked {f}")
        );
    }

    #[test]
    fn drop_counts_are_logged_at_most_once_a_minute_only_when_non_zero_then_reset() {
        let counters = DropCounters::default();
        let gate = DropLog::default();
        assert!(gate.flush(&counters, Duration::from_secs(0)).is_none());
        counters.count(DropReason::Public);
        counters.count(DropReason::Malformed);
        counters.count(DropReason::Malformed);
        counters.count(DropReason::Oversized);
        counters.count(DropReason::Overflow);
        counters.count(DropReason::Timeout);
        assert_eq!(
            gate.flush(&counters, Duration::from_secs(100))
                .unwrap()
                .to_string(),
            "dropped public=1 malformed=2 oversized=1 overflow=1 timeout=1"
        );
        assert!(
            gate.flush(&counters, Duration::from_secs(101)).is_none(),
            "reset"
        );
        counters.count(DropReason::Overflow);
        assert!(
            gate.flush(&counters, Duration::from_secs(130)).is_none(),
            "under a minute"
        );
        assert_eq!(
            gate.flush(&counters, Duration::from_secs(160))
                .unwrap()
                .to_string(),
            "dropped public=0 malformed=0 oversized=0 overflow=1 timeout=0"
        );
    }

    #[test]
    fn interface_names_are_a_closed_charset() {
        assert!(InterfaceName::parse("wlan0").is_ok());
        assert!(InterfaceName::parse("").is_err());
        assert!(InterfaceName::parse("a b").is_err());
        assert!(InterfaceName::parse("abcdefghijklmnop").is_err());
        assert!(InterfaceName::parse("x\n").is_err());
    }
}
