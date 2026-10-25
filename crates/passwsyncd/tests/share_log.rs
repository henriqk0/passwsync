//! 005 T023: the closed sharing log events (contracts/host-runtime-share.md "Log events").
//! Peers are identified by fingerprint only; no event has a field that could carry a code,
//! proof, `rid`, wallet name, wallet id, received id, key, password or contents.

use device_link::identity::DeviceId;
use passwsyncd::log::{
    CleanClass, DiscardReason, InvitationEnd, LogEvent, RedeemRefusal, ShareFailure,
};

fn fp() -> device_link::identity::Fingerprint {
    DeviceId::from_public(&[7; 32]).fingerprint()
}

#[test]
fn every_sharing_event_renders_the_contract_text() {
    let fp = fp();
    let f = fp.as_str();
    let cases: Vec<(LogEvent<'_>, String)> = vec![
        (
            LogEvent::ShareInvitationCreated { fingerprint: &fp },
            format!("share invitation created recipient={f}"),
        ),
        (
            LogEvent::ShareRedeemed { fingerprint: &fp },
            format!("share redeemed peer={f}"),
        ),
        (
            LogEvent::ShareAccepted { fingerprint: &fp },
            format!("share accepted peer={f}"),
        ),
        (
            LogEvent::ShareTransferCompleted {
                fingerprint: &fp,
                bytes: 2400,
            },
            format!("share transfer completed peer={f} bytes=2400"),
        ),
        (
            LogEvent::ShareReceiveStarted { fingerprint: &fp },
            format!("share receive started peer={f}"),
        ),
        (
            LogEvent::ShareReceived {
                fingerprint: &fp,
                bytes: 99,
            },
            format!("share received peer={f} bytes=99"),
        ),
        (
            LogEvent::ReceivedOpened { fingerprint: &fp },
            format!("received wallet opened peer={f}"),
        ),
        (
            LogEvent::ReceivedAlreadyPresent { fingerprint: &fp },
            format!("received wallet already present peer={f}"),
        ),
        (
            LogEvent::SharePeerUnsupported { fingerprint: &fp },
            format!("share peer unsupported {f}"),
        ),
    ];
    for (event, expected) in cases {
        assert_eq!(event.to_string(), expected);
    }
    for (end, word) in [
        (InvitationEnd::Cancelled, "cancelled"),
        (InvitationEnd::Replaced, "replaced"),
        (InvitationEnd::Locked, "locked"),
        (InvitationEnd::Revoked, "revoked"),
        (InvitationEnd::Expired, "expired"),
        (InvitationEnd::Rejected, "rejected"),
        (InvitationEnd::Completed, "completed"),
        (InvitationEnd::Failed, "failed"),
    ] {
        assert_eq!(
            LogEvent::ShareInvitationEnded(end).to_string(),
            format!("share invitation ended ({word})")
        );
    }
    for (why, word) in [
        (RedeemRefusal::WrongCode, "wrong-code"),
        (RedeemRefusal::NotRecipient, "not-recipient"),
        (RedeemRefusal::NoInvitation, "no-invitation"),
        (RedeemRefusal::Expired, "expired"),
        (RedeemRefusal::Used, "used"),
        (RedeemRefusal::Cancelled, "cancelled"),
    ] {
        assert_eq!(
            LogEvent::ShareRedeemRefused {
                fingerprint: &fp,
                why
            }
            .to_string(),
            format!("share redeem refused peer={f} ({word})")
        );
    }
    for (reason, word) in [
        (ShareFailure::Invalid, "invalid"),
        (ShareFailure::Rejected, "rejected"),
        (ShareFailure::Cancelled, "cancelled"),
        (ShareFailure::Expired, "expired"),
        (ShareFailure::Busy, "busy"),
        (ShareFailure::Storage, "storage"),
        (ShareFailure::TooLarge, "too-large"),
        (ShareFailure::SenderError, "sender-error"),
        (ShareFailure::RecipientCancelled, "recipient-cancelled"),
        (ShareFailure::ReceivedLimit, "received-limit"),
        (ShareFailure::ChannelLost, "channel-lost"),
        (ShareFailure::Timeout, "timeout"),
        (ShareFailure::Unreachable, "unreachable"),
        (ShareFailure::Unsupported, "unsupported"),
        (ShareFailure::IdMismatch, "id-mismatch"),
        (ShareFailure::Protocol, "protocol"),
    ] {
        assert_eq!(
            LogEvent::ShareTransferAborted {
                fingerprint: &fp,
                reason,
                bytes: 7,
            }
            .to_string(),
            format!("share transfer aborted peer={f} ({word}) bytes=7")
        );
        assert_eq!(
            LogEvent::ShareReceiveFailed {
                fingerprint: &fp,
                reason
            }
            .to_string(),
            format!("share receive failed peer={f} ({word})")
        );
    }
    for (why, word) in [
        (DiscardReason::Person, "person"),
        (DiscardReason::Expired, "expired"),
        (DiscardReason::Revoked, "revoked"),
    ] {
        assert_eq!(
            LogEvent::ReceivedDiscarded {
                fingerprint: &fp,
                why
            }
            .to_string(),
            format!("received wallet discarded peer={f} ({word})")
        );
    }
    for (class, word) in [
        (CleanClass::Partial, "partial"),
        (CleanClass::Orphan, "orphan"),
        (CleanClass::Corrupted, "corrupted"),
        (CleanClass::Expired, "expired"),
        (CleanClass::Unpinned, "unpinned"),
        (CleanClass::Excess, "excess"),
    ] {
        assert_eq!(
            LogEvent::ReceivedCleaned { class, count: 3 }.to_string(),
            format!("received cleaned ({word}) count=3")
        );
    }
}

#[test]
fn sharing_events_carry_only_typed_non_secret_fields() {
    // Every sharing variant's fields are a fingerprint, a closed reason or a count: the
    // source of the enum must not give any of them a string, byte array, wallet name or id.
    let source = include_str!("../src/log.rs");
    let start = source.find("// --- 005 sharing events").expect("marker");
    let end = source[start..].find("\n}\n").unwrap() + start;
    let block = &source[start..end];
    for forbidden in [
        "WalletName",
        "&'a str",
        "String",
        "[u8",
        "Vec<",
        "WalletId",
        "code",
        "proof",
        "rid",
        "password",
    ] {
        assert!(!block.contains(forbidden), "{forbidden} in the 005 events");
    }
}

// --- 005 T088: a full sharing run logs only closed events and no secret ---

mod common;

mod share_log_scan {
    use super::common::share::*;
    use super::common::sync::*;

    const PREFIXES: &[&str] = &[
        "started ",
        "launch file ",
        "protections applied",
        "unlocked ",
        "locked ",
        "stopping",
        "network off",
        "network on ",
        "pairing started",
        "pairing succeeded ",
        "peer connected ",
        "peer disconnected ",
        "device revoked ",
        "dropped ",
        "rejected ",
        "sync round start ",
        "sync round end ",
        "sync merged ",
        "sync pending stored ",
        "sync peer legacy ",
        "refused by peer ",
        "peer refused ",
        "share invitation created ",
        "share invitation ended ",
        "share redeem refused ",
        "share redeemed ",
        "share accepted ",
        "share transfer completed ",
        "share transfer aborted ",
        "share receive started ",
        "share received ",
        "share receive failed ",
        "received wallet opened ",
        "received wallet already present ",
        "received wallet discarded ",
        "received cleaned ",
        "share peer unsupported ",
    ];

    #[test]
    fn sharing_logs_are_closed_events_without_secrets() {
        let wallet = "Wallet-Secret-Name";
        let (a, b) = paired("Laptop-Name-Marker", "Phone-Name-Marker");
        a.create_wallet(wallet);
        a.add(
            wallet,
            "TITLE-MARKER",
            "USER-MARKER",
            "PASSWORD-MARKER",
            "",
            "NOTES-MARKER",
        );
        // A refused redemption, then a full share, an open and a discard.
        let code1 = invite_code(&a, wallet, &b.device_id());
        let wrong = if code1 == "00000000" {
            "11111111"
        } else {
            "00000000"
        };
        assert_eq!(receive(&b, wrong, Some(&a.device_id()), None).status, 202);
        assert!(wait_receive(&b, "failed"));
        let code2 = invite_code(&a, wallet, &b.device_id());
        assert_eq!(receive(&b, &code2, Some(&a.device_id()), None).status, 202);
        assert!(wait_invitation(&a, "awaiting_acceptance"));
        assert_eq!(accept(&a, &b.device_id()).status, 200);
        assert!(wait_receive(&b, "stored"));
        let id = received(&b)[0]["id"].as_str().unwrap().to_string();
        assert_eq!(open_received(&b, &id, "Opened-Name", PASSWORD).status, 200);
        let id2 = share_to(&a, &b, wallet);
        assert_eq!(
            b.api("POST", &format!("/api/received/{id2}/discard"), None)
                .status,
            200
        );
        assert!(a.server.log_text().contains("share invitation created"));
        assert!(b.server.log_text().contains("share received "));
        for log in [a.server.log_text(), b.server.log_text()] {
            for line in log.lines() {
                let body = line
                    .strip_prefix("passwsyncd: ")
                    .expect("one prefix per line");
                assert!(
                    PREFIXES
                        .iter()
                        .any(|p| body.starts_with(p) || body == p.trim_end()),
                    "not a closed event: {line}"
                );
                if body.starts_with("share ") || body.starts_with("received ") {
                    assert!(
                        !body.contains(wallet) && !body.contains("Opened-Name"),
                        "{line}"
                    );
                }
            }
            for needle in [
                code1.as_str(),
                code2.as_str(),
                id.as_str(),
                id2.as_str(),
                PASSWORD,
                "TITLE-MARKER",
                "USER-MARKER",
                "PASSWORD-MARKER",
                "NOTES-MARKER",
                "Laptop-Name-Marker",
                "Phone-Name-Marker",
            ] {
                assert!(!log.contains(needle), "{needle} in the log");
            }
        }
    }
}
