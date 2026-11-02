//! 008 B-08 (002 SC-008): resident memory of an idle service holding one unlocked
//! 1,000-entry wallet. The 002 test `crates/passwsyncd/tests/perf_memory.rs` asserts the bound
//! but prints no value and stays unchanged in 008, so this release measurement (its own
//! process: `scripts/bench.sh`, `--ignored`) prints the `BUDGET` line. The service is started
//! through the real `passwsyncd::app::start` (fake process hardening, temporary XDG tree,
//! networking off); the wallet is unlocked in the same process through `vault-core`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use passwsyncd::app::{Deps, start};
use passwsyncd::hardening::FakeHardening;
use passwsyncd::log::Log;
use passwsyncd::net_runtime::NetDeps;
use passwsyncd::paths::Env;
use vault_core::{DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, Vault};
use wallet_service::testkit::FakeElapsedClock;

fn private_dir(path: &Path) {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .unwrap();
}

fn rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with("VmRSS:")).unwrap();
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

struct Tree(PathBuf);

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "release-mode memory measurement (Linux), run by scripts/bench.sh"]
fn idle_service_with_one_unlocked_1000_entry_wallet() {
    let root = Tree(std::env::temp_dir().join(format!("passwsync-bench-{}", std::process::id())));
    let home = root.0.join("home");
    let run = root.0.join("run");
    private_dir(&home.join(".config/passwsync"));
    private_dir(&run);
    let config = home.join(".config/passwsync/config");
    // A free loopback port above 1023 (the service binds it again right away).
    let port = std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap();
    std::fs::write(&config, format!("port = {port}\n")).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (log, _buffer) = Log::to_buffer();
    let running = start(Deps {
        env: Env {
            home: Some(home.clone()),
            xdg_config_home: None,
            xdg_data_home: None,
            xdg_runtime_dir: Some(run.clone()),
        },
        hardening: Box::new(FakeHardening::ok()),
        log,
        wallet_kdf: KdfConfig::MINIMUM,
        elapsed: Arc::new(FakeElapsedClock::new()),
        net: NetDeps::production(),
    })
    .expect("service starts");
    let mut vault = Vault::create(
        MasterPassword::new("fuzz-only-password".into()),
        KdfConfig::DEFAULT,
        DeviceId::new("fz-bench").unwrap(),
        Box::new(FixedClock::new(1)),
    )
    .unwrap();
    for n in 0..1_000 {
        vault
            .add_entry(EntryFields {
                title: format!("fz service {n}"),
                username: format!("fz-user-{n}"),
                password: format!("fz-pass-{n:08}"),
                url: format!("https://fz{n}.example"),
                notes: "fz".repeat(20),
            })
            .unwrap();
    }
    let bytes = vault.seal().unwrap();
    drop(vault);
    let unlocked = Vault::unlock(
        &bytes,
        MasterPassword::new("fuzz-only-password".into()),
        DeviceId::new("fz-bench").unwrap(),
        Box::new(FixedClock::new(1)),
    )
    .unwrap();
    std::thread::sleep(Duration::from_secs(2));
    let mb = rss_kib() / 1024;
    println!(
        "BUDGET id=B-08 value={mb} unit=MB limit=50 cmp=lt source=002-SC-008 class=measured verdict={}",
        if mb < 50 { "PASS" } else { "OVER" }
    );
    std::hint::black_box(&unlocked);
    running.stop();
    assert!(mb < 50, "idle service RSS {mb} MB");
}
