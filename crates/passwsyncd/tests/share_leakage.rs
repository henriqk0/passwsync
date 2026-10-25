//! 005 T043 (SC-002): a full share session leaks no secret. The bytes of the session are
//! recorded at the socket (a relay between the two instances); the received files and the
//! logs are scanned too. Any hit fails.

mod common;

use std::fs;
use std::time::Duration;

use common::server::wait_for;
use common::share::*;
use common::sync::*;
use vault_core::{DeviceId, FixedClock, MasterPassword, Vault};

const WALLET: &str = "Wallet-Secret-Name";

#[test]
fn a_full_share_session_carries_no_password_name_credential_or_code() {
    let a = instance("Laptop-Secret-Name");
    let b = instance("Phone-Secret-Name");
    a.create_wallet(WALLET);
    a.add(
        WALLET,
        "TITLE-MARKER",
        "USER-MARKER",
        "PASSWORD-MARKER",
        "https://URL-MARKER.example",
        "NOTES-MARKER",
    );
    // B reaches A only through the recording relay.
    let (relay, seen) = recording_proxy(a.peer_port);
    pair_via(&a, &b, relay);
    assert!(wait_for(Duration::from_secs(10), || peer_share(
        &a,
        &b.device_id()
    ) == "supported"));
    let before = seen.lock().unwrap().len();
    let code = invite_code(&a, WALLET, &b.device_id());
    let addr = format!("127.0.0.1:{relay}");
    assert_eq!(
        receive(&b, &code, Some(&a.device_id()), Some(&addr)).status,
        202
    );
    assert!(
        wait_invitation(&a, "awaiting_acceptance"),
        "{}",
        share_state(&a)
    );
    assert_eq!(accept(&a, &b.device_id()).status, 200);
    assert!(wait_receive(&b, "stored"), "{}", share_state(&b));
    let id = received(&b)[0]["id"].as_str().unwrap().to_string();

    // Files at rest on B: ciphertext and non-secret meta only.
    let dir = b.server.fx.home.join(".local/share/passwsync/received");
    let meta = fs::read(dir.join(format!("{id}.meta"))).unwrap();
    let pwsw = fs::read(dir.join(format!("{id}.pwsw"))).unwrap();
    for (label, bytes) in [("meta", &meta), ("pwsw", &pwsw)] {
        for needle in [
            WALLET,
            PASSWORD,
            code.as_str(),
            "TITLE-MARKER",
            "PASSWORD-MARKER",
        ] {
            assert!(!contains(bytes, needle.as_bytes()), "{needle} in {label}");
        }
    }

    // The traffic of the share session (and the whole run).
    let traffic = seen.lock().unwrap().clone();
    assert!(
        traffic.len() - before >= pwsw.len(),
        "the share session crossed the relay ({} bytes)",
        traffic.len() - before
    );
    assert!(contains(&traffic, b"PWSC\x03\x01"), "channel v3 Hello");
    let vault = Vault::unlock(
        &fs::read(a.wallet_file(WALLET)).unwrap(),
        MasterPassword::new(PASSWORD.into()),
        DeviceId::new("check").unwrap(),
        Box::new(FixedClock::new(0)),
    )
    .unwrap();
    let wallet_id = *vault.wallet_id().as_bytes();
    let a_id = a.device_id();
    let b_id = b.device_id();
    for needle in [
        WALLET,
        PASSWORD,
        code.as_str(),
        "TITLE-MARKER",
        "USER-MARKER",
        "PASSWORD-MARKER",
        "URL-MARKER",
        "NOTES-MARKER",
        "Laptop-Secret-Name",
        "Phone-Secret-Name",
        a_id.as_str(),
        b_id.as_str(),
    ] {
        assert!(
            !contains(&traffic, needle.as_bytes()),
            "{needle} crossed the network"
        );
    }
    assert!(!contains(&traffic, &wallet_id), "wallet id on the wire");
    // Device ids (proof inputs) in binary form never appear in clear either.
    for hex in [&a_id, &b_id] {
        let raw: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        assert!(!contains(&traffic, &raw), "device id on the wire");
    }
    // Every Hello is the 6-byte plaintext header; the stream holds no other "PWSC".
    let hellos = traffic.windows(4).filter(|w| *w == b"PWSC").count();
    let v3 = traffic.windows(6).filter(|w| *w == b"PWSC\x03\x01").count();
    let pairing = traffic.windows(6).filter(|w| *w == b"PWSC\x01\x02").count();
    assert_eq!(hellos, v3 + pairing, "only Hello headers are in clear");

    // After opening, the log of both devices holds no code, wallet name or password.
    assert_eq!(open_received(&b, &id, WALLET, PASSWORD).status, 200);
    for log in [a.server.log_text(), b.server.log_text()] {
        assert!(log.contains("share "), "sharing was logged");
        for needle in [code.as_str(), PASSWORD, "TITLE-MARKER", &id] {
            assert!(!log.contains(needle), "{needle} in the log");
        }
        for line in log
            .lines()
            .filter(|l| l.contains("share ") || l.contains("received "))
        {
            assert!(
                !line.contains(WALLET),
                "wallet name in a sharing line: {line}"
            );
        }
    }
}
