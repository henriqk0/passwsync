//! 004 T139 (host side): no relay, URL, internet or per-wallet sync setting, and no sharing
//! routes (FR-039, FR-006c).

mod common;

use common::server::TestServer;
use passwsyncd::config::parse;

#[test]
fn no_relay_url_internet_or_per_wallet_sync_key_exists() {
    for key in [
        "sync",
        "sync_relay",
        "sync_server",
        "sync_url",
        "relay",
        "internet_sync",
        "sync_enabled",
        "sync_wallets",
        "sync_wallet_personal",
    ] {
        let error = parse(&format!("{key} = 1")).unwrap_err().to_string();
        assert_eq!(error, format!("config: {key}: unknown key"));
    }
}

#[test]
fn no_sharing_invitation_or_per_wallet_toggle_route_exists() {
    let server = TestServer::start();
    let s = server.login();
    for (method, path) in [
        ("POST", "/api/wallets/Personal/sync/enable"),
        ("POST", "/api/wallets/Personal/sync/disable"),
        ("POST", "/api/wallets/Personal/share"),
        ("POST", "/api/sync/relay"),
        ("POST", "/api/invitations"),
        ("GET", "/api/sync/settings"),
    ] {
        let resp = server.api(&s, method, path, Some("{}"));
        assert_eq!(resp.status, 404, "{method} {path}");
    }
}
