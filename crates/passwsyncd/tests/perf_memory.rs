//! Release-only SC-008 check, in its own test binary so the process measured holds only
//! this scenario (`cargo test --release -- --ignored`).

mod common;

use std::time::Duration;

use common::server::TestServer;
use serde_json::json;
use vault_core::{DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, Vault};

const PW: &str = "correct horse battery";

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

/// VmRSS of this process in KiB.
fn rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with("VmRSS:")).unwrap();
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

/// utime + stime ticks of this whole process.
fn cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let after = &stat[stat.rfind(')').unwrap() + 2..];
    let fields: Vec<&str> = after.split_whitespace().collect();
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}

#[test]
#[ignore = "release-mode memory and idle-CPU check (SC-008)"]
fn one_unlocked_1000_entry_wallet_stays_under_50_mb_and_idles_quietly() {
    let server = TestServer::start();
    plant_wallet(&server, "Daily", 1_000);
    let s = server.login();
    let unlock = json!({"password": PW}).to_string();
    assert_eq!(
        server
            .api(&s, "POST", "/api/wallets/Daily/unlock", Some(&unlock))
            .status,
        200
    );
    for _ in 0..20 {
        let body = json!({"query": "git"}).to_string();
        assert_eq!(
            server
                .api(&s, "POST", "/api/wallets/Daily/search", Some(&body))
                .status,
            200
        );
    }
    let rss = rss_kib();
    assert!(rss < 50 * 1024, "VmRSS {rss} KiB");
    let before = cpu_ticks();
    std::thread::sleep(Duration::from_secs(30));
    let used = cpu_ticks() - before;
    assert!(used <= 5, "idle process used {used} ticks in 30 s");
}
