mod common;

use std::time::Duration;

use common::server::{Session, TestServer};
use serde_json::json;

const PW: &str = "MARKER-pw-correct-horse";

fn with_wallets(names: &[&str]) -> (TestServer, Session) {
    let server = TestServer::start();
    let s = server.login();
    for name in names {
        let body = json!({"name": name, "password": PW, "password_confirm": PW});
        assert_eq!(
            server
                .api(&s, "POST", "/api/wallets", Some(&body.to_string()))
                .status,
            201
        );
        let entry = json!({"title": "GitHub"}).to_string();
        let path = format!("/api/wallets/{name}/entries");
        assert_eq!(server.api(&s, "POST", &path, Some(&entry)).status, 201);
    }
    (server, s)
}

fn search_status(server: &TestServer, s: &Session, name: &str) -> u16 {
    let path = format!("/api/wallets/{name}/search");
    server
        .api(s, "POST", &path, Some("{\"query\":\"\"}"))
        .status
}

#[test]
fn manual_lock_is_idempotent_and_then_423() {
    let (server, s) = with_wallets(&["Personal", "Work"]);
    let resp = server.api(&s, "POST", "/api/wallets/Personal/lock", None);
    assert_eq!(resp.status, 200);
    assert_eq!(resp.json(), json!({"locked": ["Personal"]}));
    let again = server.api(&s, "POST", "/api/wallets/Personal/lock", None);
    assert_eq!(again.json(), json!({"locked": []}));
    assert_eq!(search_status(&server, &s, "Personal"), 423);
    assert_eq!(search_status(&server, &s, "Work"), 200);
    assert!(server.log_text().contains("locked Personal (manual)"));
    let resp = server.api(&s, "POST", "/api/wallets/Nobody/lock", None);
    assert_eq!(
        (resp.status, resp.error_code().as_str()),
        (404, "wallet_not_found")
    );
    assert_eq!(
        server
            .api(&s, "GET", "/api/wallets/Personal/lock", None)
            .status,
        405
    );
}

#[test]
fn lock_all_locks_every_wallet() {
    let (server, s) = with_wallets(&["Personal", "Work"]);
    let resp = server.api(&s, "POST", "/api/lock-all", None);
    assert_eq!(resp.status, 200);
    assert_eq!(resp.json(), json!({"locked": ["Personal", "Work"]}));
    assert_eq!(
        server.api(&s, "POST", "/api/lock-all", None).json(),
        json!({"locked": []})
    );
    assert_eq!(search_status(&server, &s, "Personal"), 423);
    assert_eq!(search_status(&server, &s, "Work"), 423);
    let log = server.log_text();
    assert!(log.contains("locked Personal (all)") && log.contains("locked Work (all)"));
    assert_eq!(server.api(&s, "GET", "/api/lock-all", None).status, 405);
}

#[test]
fn suspend_is_checked_before_every_handler() {
    let (server, s) = with_wallets(&["Personal"]);
    server.clock.advance(Duration::from_secs(60));
    server.clock.suspend(Duration::from_secs(120));
    // Even the background state request runs the check first.
    let state = server.api(&s, "GET", "/api/state", None).json();
    assert_eq!(
        state["wallets"],
        json!([{"name": "Personal", "unlocked": false}])
    );
    let log = server.log_text();
    assert!(log.contains("suspend detected"), "{log}");
    assert!(log.contains("locked Personal (suspend)"), "{log}");
    assert_eq!(search_status(&server, &s, "Personal"), 423);
}

#[test]
fn suspend_before_a_page_request_also_locks() {
    let (server, _) = with_wallets(&["Personal"]);
    server.clock.suspend(Duration::from_secs(60));
    assert_eq!(server.get("/static/app.css").status, 200);
    assert!(server.log_text().contains("locked Personal (suspend)"));
}

#[test]
fn stopping_locks_every_wallet_first() {
    let (mut server, _) = with_wallets(&["Personal", "Work"]);
    assert_eq!(server.stop(), 0);
    let log = server.log_text();
    let stop_p = log
        .find("locked Personal (stop)")
        .expect("Personal locked on stop");
    let stop_w = log.find("locked Work (stop)").expect("Work locked on stop");
    let stopping = log.find("stopping").unwrap();
    assert!(stop_p < stopping && stop_w < stopping, "{log}");
}
