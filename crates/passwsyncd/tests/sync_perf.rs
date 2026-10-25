//! 004 T067 (SC-008): a 10 000-credential wallet that differs by one credential syncs in
//! under 10 seconds over loopback. `cargo test -p passwsyncd --test sync_perf -- --ignored`.

mod common;

use std::fs;
use std::time::{Duration, Instant};

use common::server::{Fixture, TestServer, free_net_port, wait_for};
use common::sync::*;
use vault_core::{DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, Vault};

const WALLET: &str = "Big";

fn big_wallet() -> Vec<u8> {
    let mut vault = Vault::create(
        MasterPassword::new(PASSWORD.into()),
        KdfConfig::MINIMUM,
        DeviceId::new("generator").unwrap(),
        Box::new(FixedClock::new(1)),
    )
    .unwrap();
    for n in 0..10_000 {
        vault
            .add_entry(EntryFields {
                title: format!("Service {n}"),
                username: format!("user{n}@example.com"),
                password: format!("p4ssw0rd-{n:08}-abcdefgh"),
                url: format!("https://service{n}.example.com/login"),
                notes: format!("Typical note for entry {n}."),
            })
            .unwrap();
    }
    vault.seal().unwrap()
}

fn with_wallet(name: &str, bytes: &[u8]) -> Instance {
    let (peer, disc) = (free_net_port(), free_net_port());
    let fx = Fixture::new(&config(name, peer, disc));
    fs::create_dir_all(&fx.wallets_dir).unwrap();
    common::set_mode(fx.wallets_dir.parent().unwrap(), 0o700);
    common::set_mode(&fx.wallets_dir, 0o700);
    let path = fx.wallets_dir.join(format!("{WALLET}.pwsw"));
    fs::write(&path, bytes).unwrap();
    common::set_mode(&path, 0o600);
    let server = TestServer::start_in(fx);
    let session = server.login();
    Instance {
        server,
        session,
        peer_port: peer,
    }
}

#[test]
#[ignore = "performance check (SC-008)"]
fn a_10000_entry_wallet_differing_by_one_entry_syncs_in_under_10_seconds() {
    let bytes = big_wallet();
    let a = with_wallet("A", &bytes);
    let b = with_wallet("B", &bytes);
    a.unlock(WALLET);
    b.unlock(WALLET);
    pair_via(&a, &b, a.peer_port);
    let started = Instant::now();
    a.add(WALLET, "Only-new", "", "", "", "");
    let found = || {
        let resp = b.api(
            "POST",
            &format!("/api/wallets/{WALLET}/search"),
            Some(r#"{"query":"Only-new"}"#),
        );
        resp.status == 200
            && resp.json()["entries"]
                .as_array()
                .is_some_and(|e| e.len() == 1)
    };
    assert!(wait_for(Duration::from_secs(30), found));
    let elapsed = started.elapsed();
    eprintln!("10 000-entry wallet synced in {elapsed:?}");
    assert!(elapsed < Duration::from_secs(10), "took {elapsed:?}");
}
