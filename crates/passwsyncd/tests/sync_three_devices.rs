//! 004 T130 (US6): three real instances in a chain A-B-C.

mod common;

use std::time::Duration;

use common::server::{Fixture, TestServer, wait_for};
use common::sync::*;

const WALLET: &str = "Shared";

#[test]
fn a_chain_converges_survives_a_restart_and_stops_at_a_revoked_link() {
    let a = instance("A");
    let mut b = instance("B");
    let c = instance("C");
    a.create_wallet(WALLET);
    pair_via(&a, &b, a.peer_port); // B dials A
    pair_via(&b, &c, b.peer_port); // C dials B; A and C never meet
    copy_wallet_file(&a, &b, WALLET);
    copy_wallet_file(&a, &c, WALLET);
    b.unlock(WALLET);
    c.unlock(WALLET);
    a.add(WALLET, "From A", "", "", "", "");
    c.add(WALLET, "From C", "", "", "", "");
    let both = vec!["From A".to_string(), "From C".to_string()];
    assert!(
        wait_for(Duration::from_secs(20), || a.titles(WALLET) == both
            && c.titles(WALLET) == both
            && b.titles(WALLET) == both),
        "A {:?} B {:?} C {:?}",
        a.titles(WALLET),
        b.titles(WALLET),
        c.titles(WALLET)
    );

    // B restarts; the chain keeps working after it comes back.
    let fx = std::mem::replace(&mut b.server.fx, Fixture::new(""));
    b.server.stop();
    let server = TestServer::start_in(fx);
    let session = server.login();
    let b = Instance {
        server,
        session,
        peer_port: b.peer_port,
    };
    b.unlock(WALLET);
    a.add(WALLET, "After restart", "", "", "", "");
    assert!(
        wait_for(Duration::from_secs(30), || c
            .titles(WALLET)
            .contains(&"After restart".to_string())),
        "C {:?}",
        c.titles(WALLET)
    );

    // C revokes B: nothing from A reaches C any more.
    let b_id = b.device_id();
    assert_eq!(
        c.api("POST", &format!("/api/devices/{b_id}/revoke"), None)
            .status,
        200
    );
    a.add(WALLET, "After revoke", "", "", "", "");
    assert!(wait_for(Duration::from_secs(10), || b
        .titles(WALLET)
        .contains(&"After revoke".to_string())));
    std::thread::sleep(Duration::from_millis(1500));
    assert!(!c.titles(WALLET).contains(&"After revoke".to_string()));
}
