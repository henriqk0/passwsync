//! 005 T044 (FR-024): a peer on the 004 build (channel v2 at most) cannot receive shares,
//! is shown as not supporting sharing, and 004 sync with it keeps working.

mod common;

use std::fs;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::server::{Fixture, TestServer, net_config, wait_for};
use common::share::*;
use device_link::files::encode_peers;
use device_link::name::DeviceName;
use device_link::registry::PeerPin;
use passwsyncd::assets::APP_JS;
use serde_json::json;

#[test]
fn a_v2_peer_is_unsupported_for_sharing_but_still_syncs() {
    let old = fake_v2_peer(91);
    let fx = Fixture::new(&net_config());
    let pin = PeerPin {
        public: *old.key.public(),
        name: DeviceName::parse("Old Phone").unwrap(),
        paired_at: 1,
        last_seen: None,
        last_addr: Some(old.addr),
    };
    let path = fx.config_dir.join("peers");
    fs::write(&path, encode_peers(&[pin])).unwrap();
    common::set_mode(&path, 0o600);
    let server = TestServer::start_in(fx);
    let s = server.login();
    let old_id = old.key.id().to_hex();

    assert!(
        wait_for(Duration::from_secs(10), || old
            .channels
            .load(Ordering::SeqCst)
            >= 1),
        "A fell back to channel v2"
    );
    assert!(
        old.v3_refused.load(Ordering::SeqCst) >= 1,
        "v3 was tried first"
    );
    let share_of = || {
        server.api(&s, "GET", "/api/share", None).json()["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["device_id"] == old_id.as_str())
            .map(|p| p["share"].as_str().unwrap().to_string())
            .unwrap_or_default()
    };
    assert!(wait_for(Duration::from_secs(5), || share_of() == "unsupported"));
    assert!(server.log_text().contains("share peer unsupported "));

    let body = json!({"name": "W", "password": common::sync::PASSWORD, "password_confirm": common::sync::PASSWORD});
    assert_eq!(
        server
            .api(&s, "POST", "/api/wallets", Some(&body.to_string()))
            .status,
        201
    );
    let resp = server.api(
        &s,
        "POST",
        "/api/wallets/W/share",
        Some(&json!({"device_id": old_id}).to_string()),
    );
    assert_eq!(resp.status, 409, "{}", resp.text());
    assert_eq!(resp.error_code(), "peer_unsupported");

    // 004 sync with it is unaffected: the peer is a sync peer, not "sync unsupported".
    let sync = server.api(&s, "GET", "/api/sync", None).json();
    let peer = sync["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["device_id"] == old_id.as_str())
        .cloned()
        .unwrap();
    assert_eq!(peer["sync"], "supported");
    let net = server.api(&s, "GET", "/api/network", None).json();
    assert_eq!(net["paired"][0]["status"], "connected");

    // The UI explains it.
    let js = String::from_utf8(APP_JS.to_vec()).unwrap();
    assert!(js.contains("this device does not support sharing"));
}
