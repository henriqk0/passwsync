//! 005 T050 (US2): share A -> B, then B -> C; edits anywhere converge on all three, and a
//! conflict made while C is cut off is shown on both sides after reconnection (004).

mod common;

use std::time::Duration;

use common::server::{Fixture, TestServer, wait_for};
use common::share::*;
use common::sync::*;
use serde_json::json;

const WALLET: &str = "Family";

fn conflicts(i: &Instance) -> usize {
    let resp = i.api("GET", &format!("/api/wallets/{WALLET}/conflicts"), None);
    if resp.status != 200 {
        return 0;
    }
    resp.json()["entries"].as_array().map_or(0, Vec::len)
}

#[test]
fn a_chain_of_shares_converges_and_shows_partition_conflicts_on_both_sides() {
    let a = instance("A");
    let mut b = instance("B");
    let c = instance("C");
    pair_via(&a, &b, a.peer_port); // B dials A
    pair_via(&b, &c, b.peer_port); // C dials B; A and C never meet
    a.create_wallet(WALLET);
    let base = a.add(WALLET, "Base", "u", "p", "", "");
    let id = share_to(&a, &b, WALLET);
    assert_eq!(open_received(&b, &id, WALLET, PASSWORD).status, 200);
    let id = share_to(&b, &c, WALLET);
    assert_eq!(open_received(&c, &id, WALLET, PASSWORD).status, 200);

    a.add(WALLET, "From A", "", "", "", "");
    c.add(WALLET, "From C", "", "", "", "");
    let all = vec![
        "Base".to_string(),
        "From A".to_string(),
        "From C".to_string(),
    ];
    assert!(
        wait_for(Duration::from_secs(30), || a.titles(WALLET) == all
            && b.titles(WALLET) == all
            && c.titles(WALLET) == all),
        "A {:?} B {:?} C {:?}",
        a.titles(WALLET),
        b.titles(WALLET),
        c.titles(WALLET)
    );

    // B goes away: A and C are partitioned and both edit the same credential.
    let fx = std::mem::replace(&mut b.server.fx, Fixture::new(""));
    b.server.stop();
    let edit = |i: &Instance, title: &str| {
        let body =
            json!({"title": title, "username": "u", "password": "p", "url": "", "notes": ""});
        let resp = i.api(
            "PUT",
            &format!("/api/wallets/{WALLET}/entries/{base}"),
            Some(&body.to_string()),
        );
        assert_eq!(resp.status, 200, "{}", resp.text());
    };
    edit(&a, "Edited on A");
    edit(&c, "Edited on C");

    // B comes back; the conflict reaches both sides.
    let server = TestServer::start_in(fx);
    let session = server.login();
    let b = Instance {
        server,
        session,
        peer_port: b.peer_port,
    };
    b.unlock(WALLET);
    assert!(
        wait_for(Duration::from_secs(40), || conflicts(&a) == 1
            && conflicts(&c) == 1),
        "A {} C {}\nB log:\n{}",
        conflicts(&a),
        conflicts(&c),
        b.server.log_text()
    );
}
