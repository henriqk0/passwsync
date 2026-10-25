//! 005 T061 (US3, FR-004..FR-010, SC-003): over real instances, every invalid redemption is
//! refused, sends no wallet bytes, is shown on both devices and logged by fingerprint.

mod common;

use std::time::Duration;

use common::server::{Fixture, TestServer, wait_for};
use common::share::*;
use common::sync::*;

fn fp(i: &Instance) -> String {
    net(&i.server, &i.session)["this_device"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_string()
}

fn reason(i: &Instance) -> String {
    share_state(i)["invitation"]["reason"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

fn receive_reason(i: &Instance) -> String {
    share_state(i)["receive"]["reason"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

#[test]
fn a_third_device_with_the_right_code_is_refused_and_invalidates() {
    let (a, b) = paired("Laptop", "Phone");
    let c = instance("Tablet");
    pair_via(&a, &c, a.peer_port);
    a.create_wallet("Personal");
    let code = invite_code(&a, "Personal", &b.device_id());
    assert_eq!(receive(&c, &code, Some(&a.device_id()), None).status, 202);
    assert!(wait_receive(&c, "failed"));
    assert_eq!(receive_reason(&c), "invalid");
    assert!(wait_invitation(&a, "refused"));
    assert_eq!(reason(&a), "not_recipient");
    assert!(a.server.log_text().contains(&format!(
        "share redeem refused peer={} (not-recipient)",
        fp(&c)
    )));
    // The real recipient is refused now too.
    assert_eq!(receive(&b, &code, Some(&a.device_id()), None).status, 202);
    assert!(wait_receive(&b, "failed"));
    assert_eq!(receive_reason(&b), "invalid");
    assert!(received(&b).is_empty() && received(&c).is_empty());
}

#[test]
fn a_wrong_code_invalidates_and_a_used_code_is_refused() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    let code = invite_code(&a, "Personal", &b.device_id());
    let wrong = if code == "00000000" {
        "11111111"
    } else {
        "00000000"
    };
    assert_eq!(receive(&b, wrong, Some(&a.device_id()), None).status, 202);
    assert!(wait_receive(&b, "failed"));
    assert_eq!(receive_reason(&b), "invalid");
    assert!(wait_invitation(&a, "refused"));
    assert_eq!(reason(&a), "wrong_code");
    assert!(a.server.log_text().contains("(wrong-code)"));

    // A completed invitation cannot be used again ("already used").
    let id = share_to(&a, &b, "Personal");
    assert!(!id.is_empty());
    // Any redemption of the completed invitation is refused as used.
    assert_eq!(
        receive(&b, "12345678", Some(&a.device_id()), None).status,
        202
    );
    assert!(wait_receive(&b, "failed"));
    assert_eq!(receive_reason(&b), "invalid");
    assert!(a.server.log_text().contains("(used)"));
    assert_eq!(received(&b).len(), 1, "only the one real delivery");
}

#[test]
fn expiry_after_300_seconds_is_told_to_the_recipient() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    let code = invite_code(&a, "Personal", &b.device_id());
    a.server
        .running()
        .advance_share_clock(Duration::from_secs(301));
    a.server.running().share_tick_now();
    assert_eq!(invitation_state(&a), "expired");
    assert!(
        a.server
            .log_text()
            .contains("share invitation ended (expired)")
    );
    assert_eq!(receive(&b, &code, Some(&a.device_id()), None).status, 202);
    assert!(wait_receive(&b, "failed"));
    assert_eq!(receive_reason(&b), "expired");
    assert!(a.server.log_text().contains("(expired)"));
    assert!(received(&b).is_empty());
}

#[test]
fn locking_the_wallet_while_the_recipient_waits_cancels_by_sender() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    let code = invite_code(&a, "Personal", &b.device_id());
    assert_eq!(receive(&b, &code, Some(&a.device_id()), None).status, 202);
    assert!(wait_invitation(&a, "awaiting_acceptance"));
    assert_eq!(
        a.api("POST", "/api/wallets/Personal/lock", None).status,
        200
    );
    assert_eq!(invitation_state(&a), "cancelled");
    assert_eq!(reason(&a), "wallet_locked");
    assert!(wait_receive(&b, "failed"), "{}", share_state(&b));
    assert_eq!(receive_reason(&b), "cancelled_by_sender");
    assert!(
        a.server
            .log_text()
            .contains("share invitation ended (locked)")
    );
    // A lock by the idle timer counts the same (any lock cause).
    a.unlock("Personal");
    let _code = invite_code(&a, "Personal", &b.device_id());
    a.server.clock.advance(Duration::from_secs(16 * 60));
    a.server.running().sweep_now();
    assert_eq!(invitation_state(&a), "cancelled");
    assert_eq!(reason(&a), "wallet_locked");
    assert!(received(&b).is_empty());
}

#[test]
fn revoking_the_recipient_cancels_and_it_never_gets_past_the_handshake() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    let code = invite_code(&a, "Personal", &b.device_id());
    let b_id = b.device_id();
    assert_eq!(
        a.api("POST", &format!("/api/devices/{b_id}/revoke"), None)
            .status,
        200
    );
    assert_eq!(invitation_state(&a), "cancelled");
    assert_eq!(reason(&a), "recipient_revoked");
    assert!(
        a.server
            .log_text()
            .contains("share invitation ended (revoked)")
    );
    let log_before = a.server.log_text().matches("share redeem").count();
    assert_eq!(receive(&b, &code, Some(&a.device_id()), None).status, 202);
    assert!(wait_receive(&b, "failed"), "{}", share_state(&b));
    assert_eq!(receive_reason(&b), "unreachable");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        a.server.log_text().matches("share redeem").count(),
        log_before,
        "the revoked device never reached the share protocol"
    );
    assert!(received(&b).is_empty());
}

#[test]
fn a_restart_of_the_sender_makes_the_code_invalid() {
    let (mut a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    let code = invite_code(&a, "Personal", &b.device_id());
    let fx = std::mem::replace(&mut a.server.fx, Fixture::new(""));
    a.server.stop();
    let server = TestServer::start_in(fx);
    let session = server.login();
    let a = Instance {
        server,
        session,
        peer_port: a.peer_port,
    };
    assert!(
        wait_for(Duration::from_secs(10), || connected(&b)),
        "B reconnects to A"
    );
    assert!(
        share_state(&a)["invitation"].is_null(),
        "invitations live in memory only"
    );
    assert_eq!(receive(&b, &code, Some(&a.device_id()), None).status, 202);
    assert!(wait_receive(&b, "failed"), "{}", share_state(&b));
    assert_eq!(receive_reason(&b), "invalid");
    assert!(a.server.log_text().contains("(no-invitation)"));
    assert!(received(&b).is_empty());
}
