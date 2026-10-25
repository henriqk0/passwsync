//! 005 T083 (SC-006): a 10 000-credential wallet is shared in under 10 seconds over
//! loopback, with at most one shared transfer slot and bounded buffers.
//! `cargo test -p passwsyncd --test share_perf -- --ignored`.

mod common;

use std::fs;
use std::time::{Duration, Instant};

use common::server::{Fixture, TestServer, free_net_port, wait_for};
use common::share::*;
use common::sync::*;
use vault_core::{DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, Vault};

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

#[test]
#[ignore = "performance check (SC-006)"]
fn a_10000_credential_wallet_is_shared_in_under_10_seconds() {
    let bytes = big_wallet();
    let (peer, disc) = (free_net_port(), free_net_port());
    let fx = Fixture::new(&config("A", peer, disc));
    place_wallet(&fx, "Big", &bytes);
    let server = TestServer::start_in(fx);
    let session = server.login();
    let a = Instance {
        server,
        session,
        peer_port: peer,
    };
    a.unlock("Big"); // creates the 004 record that makes it eligible
    let b = instance("B");
    pair_via(&a, &b, a.peer_port);
    assert!(wait_for(Duration::from_secs(10), || peer_share(
        &a,
        &b.device_id()
    ) == "supported"));
    let code = invite_code(&a, "Big", &b.device_id());
    assert_eq!(receive(&b, &code, Some(&a.device_id()), None).status, 202);
    assert!(wait_invitation(&a, "awaiting_acceptance"));
    let started = Instant::now();
    assert_eq!(accept(&a, &b.device_id()).status, 200);
    assert!(wait_for(Duration::from_secs(10), || receive_state(&b) == "stored"));
    let took = started.elapsed();
    assert!(took < Duration::from_secs(10), "took {took:?}");
    let id = received(&b)[0]["id"].as_str().unwrap().to_string();
    let stored = fs::read(
        b.server
            .fx
            .home
            .join(format!(".local/share/passwsync/received/{id}.pwsw")),
    )
    .unwrap();
    assert_eq!(stored, bytes);
    eprintln!("shared {} bytes in {took:?}", bytes.len());
}
