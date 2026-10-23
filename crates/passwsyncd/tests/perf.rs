//! Release-only measurements (`cargo test --release -- --ignored`): SC-007, SC-008.

mod common;

use std::time::{Duration, Instant};

use common::server::TestServer;
use serde_json::json;
use vault_core::{DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, Vault};

const PW: &str = "correct horse battery";

/// Writes a wallet with `count` credentials straight to the wallet directory.
fn plant_wallet(server: &TestServer, name: &str, count: usize) {
    let mut vault = Vault::create(
        MasterPassword::new(PW.into()),
        KdfConfig::MINIMUM,
        DeviceId::new("perf").unwrap(),
        Box::new(FixedClock::new(0)),
    )
    .unwrap();
    for i in 0..count {
        let mut fields = EntryFields::default();
        fields.title = format!("Site {i:05} {}", if i % 10 == 0 { "git" } else { "web" });
        fields.username = format!("user{i}@example.com");
        fields.password = format!("password-{i}-xxxxxxxxxxxxxxxx");
        fields.url = format!("https://site{i}.example.com/login");
        fields.notes = "some notes about this account".into();
        vault.add_entry(fields).unwrap();
    }
    std::fs::create_dir_all(&server.fx.wallets_dir).unwrap();
    std::fs::write(
        server.fx.wallets_dir.join(format!("{name}.pwsw")),
        vault.seal().unwrap(),
    )
    .unwrap();
}

#[test]
#[ignore = "release-mode performance check (SC-007)"]
fn listing_and_searching_10000_entries_takes_under_300_ms() {
    let server = TestServer::start();
    plant_wallet(&server, "Big", 10_000);
    let s = server.login();
    let unlock = json!({"password": PW}).to_string();
    assert_eq!(
        server
            .api(&s, "POST", "/api/wallets/Big/unlock", Some(&unlock))
            .status,
        200
    );
    for query in ["", "git", "nothing-matches"] {
        let body = json!({"query": query}).to_string();
        let started = Instant::now();
        let resp = server.api(&s, "POST", "/api/wallets/Big/search", Some(&body));
        let took = started.elapsed();
        assert_eq!(resp.status, 200);
        assert!(
            took < Duration::from_millis(300),
            "query {query:?} took {took:?}"
        );
    }
}
