//! 005 T071 (US4): cancel, reject, receive-cancel, discard and notice routes over raw HTTP
//! (contracts/http-api-share.md "Actions"); none of them touches idle timers.

mod common;

use std::time::Duration;

use common::share::*;
use serde_json::json;

#[test]
fn cancel_reports_cancelled_already_delivered_or_nothing() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    let resp = a.api("POST", "/api/share/cancel", None);
    assert_eq!((resp.status, resp.json()), (200, json!({})));
    let code = invite_code(&a, "Personal", &b.device_id());
    let resp = a.api("POST", "/api/share/cancel", None);
    assert_eq!(
        (resp.status, resp.json()),
        (200, json!({"state": "cancelled"}))
    );
    assert_eq!(invitation_state(&a), "cancelled");
    // B's later redemption is told "cancelled by sender".
    assert_eq!(receive(&b, &code, Some(&a.device_id()), None).status, 202);
    assert!(wait_receive(&b, "failed"));
    assert_eq!(share_state(&b)["receive"]["reason"], "cancelled_by_sender");
    // After completion the copy is already delivered.
    share_to(&a, &b, "Personal");
    let resp = a.api("POST", "/api/share/cancel", None);
    assert_eq!(
        (resp.status, resp.json()),
        (200, json!({"already_delivered": true}))
    );
    assert_eq!(invitation_state(&a), "completed");
}

#[test]
fn reject_needs_a_pending_recipient() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    let resp = a.api("POST", "/api/share/reject", None);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (409, "nothing_pending")
    );
    let code = invite_code(&a, "Personal", &b.device_id());
    assert_eq!(receive(&b, &code, Some(&a.device_id()), None).status, 202);
    assert!(wait_invitation(&a, "awaiting_acceptance"));
    let resp = a.api("POST", "/api/share/reject", None);
    assert_eq!((resp.status, resp.json()), (200, json!({})));
    assert_eq!(invitation_state(&a), "rejected");
    assert!(wait_receive(&b, "failed"));
    assert_eq!(share_state(&b)["receive"]["reason"], "rejected");
    assert!(received(&b).is_empty());
}

#[test]
fn receive_cancel_tells_the_sender() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    let resp = b.api("POST", "/api/receive/cancel", None);
    assert_eq!(
        (resp.status, resp.json()),
        (200, json!({})),
        "nothing running"
    );
    let code = invite_code(&a, "Personal", &b.device_id());
    assert_eq!(receive(&b, &code, Some(&a.device_id()), None).status, 202);
    assert!(wait_invitation(&a, "awaiting_acceptance"));
    let resp = b.api("POST", "/api/receive/cancel", None);
    assert_eq!((resp.status, resp.json()), (200, json!({})));
    assert_eq!(receive_state(&b), "cancelled");
    assert!(wait_invitation(&a, "failed"), "{}", share_state(&a));
    assert_eq!(
        share_state(&a)["invitation"]["reason"],
        "recipient_cancelled"
    );
}

#[test]
fn discard_deletes_a_received_wallet() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    let id = share_to(&a, &b, "Personal");
    let resp = b.api("POST", &format!("/api/received/{id}/discard"), None);
    assert_eq!((resp.status, resp.json()), (200, json!({})));
    assert!(received(&b).is_empty());
    let resp = b.api("POST", &format!("/api/received/{id}/discard"), None);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (404, "received_not_found")
    );
    let resp = b.api("POST", "/api/received/nothex/discard", None);
    assert_eq!(resp.status, 404);
    assert!(b.server.log_text().contains("(person)"));
    let state = b.api("GET", "/api/state", None).json();
    assert_eq!(state["wallets"], json!([]), "no wallet was created");
}

#[test]
fn notices_can_be_dismissed() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    share_to(&a, &b, "Personal");
    b.server
        .running()
        .advance_share_clock(Duration::from_secs(86_400));
    b.server.running().share_tick_now();
    let notices = share_state(&b)["notices"].as_array().unwrap().clone();
    assert_eq!(notices.len(), 1);
    let id = notices[0]["id"].as_u64().unwrap();
    let body = json!({ "ids": [id] }).to_string();
    let resp = b.api("POST", "/api/share/notices/dismiss", Some(&body));
    assert_eq!((resp.status, resp.json()), (200, json!({})));
    assert!(share_state(&b)["notices"].as_array().unwrap().is_empty());
    let resp = b.api(
        "POST",
        "/api/share/notices/dismiss",
        Some("{\"ids\":\"x\"}"),
    );
    assert_eq!(resp.status, 400);
}

#[test]
fn none_of_these_routes_resets_idle_timers() {
    let (a, b) = paired("Laptop", "Phone");
    a.create_wallet("Personal");
    a.server.clock.advance(Duration::from_secs(14 * 60));
    for path in [
        "/api/share/cancel",
        "/api/share/reject",
        "/api/receive/cancel",
        "/api/received/00000000000000000000000000000000/discard",
    ] {
        let _ = a.api("POST", path, None);
    }
    let _ = a.api("POST", "/api/share/notices/dismiss", Some("{\"ids\":[]}"));
    a.server.clock.advance(Duration::from_secs(2 * 60));
    a.server.running().sweep_now();
    let state = a.api("GET", "/api/state", None).json();
    assert_eq!(state["wallets"][0]["unlocked"], false);
    let _ = b;
}
