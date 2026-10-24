//! 003 US1: with `network = off` the process holds only the 002 loopback listener and the
//! device private key is not kept in memory (SC-002, FR-007, FR-009). One test per file:
//! the inventory covers the whole test process.

mod common;

use common::inventory::sockets;
use common::server::TestServer;

#[test]
fn networking_off_opens_only_the_loopback_listener_and_wipes_the_key() {
    let server = TestServer::start();
    assert_eq!(server.running().network_status(), "off");
    assert!(server.running().fingerprint().is_some(), "identity exists");
    assert!(!server.running().device_key_held(), "key wiped (FR-007)");
    // Exercise the UI once so accepted connections come and go.
    let session = server.login();
    let resp = server.api(&session, "GET", "/api/network", None);
    assert_eq!(resp.status, 200);
    std::thread::sleep(std::time::Duration::from_millis(100));
    let socks = sockets();
    let listeners: Vec<_> = socks.iter().filter(|s| s.is_listener()).collect();
    assert_eq!(listeners.len(), 1, "{socks:?}");
    assert_eq!(listeners[0].local, format!("127.0.0.1:{}", server.port));
    assert!(
        socks.iter().all(|s| s.proto == "tcp"),
        "no UDP and no IPv6 socket: {socks:?}"
    );
    assert!(
        socks
            .iter()
            .all(|s| s.local.starts_with("127.0.0.1:") && !s.local.starts_with("0.0.0.0")),
        "{socks:?}"
    );
    assert!(server.log_text().contains("network off"));
}
