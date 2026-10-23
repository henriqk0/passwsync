mod common;

use std::fs;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use common::server::TestServer;
use passwsyncd::log::{Log, Reason, Rejections};
use passwsyncd::sweeper::{SWEEP_INTERVAL, tick};
use vault_core::{DeviceId, FixedClock, KdfConfig};
use wallet_service::testkit::{FakeElapsedClock, MemoryWalletDirectory};
use wallet_service::{Service, ServiceConfig};
use zeroize::Zeroizing;

const PW: &str = "correct horse battery";

fn service(auto_lock: Duration) -> (Service, Arc<FakeElapsedClock>) {
    let clock = Arc::new(FakeElapsedClock::new());
    let service = Service::new(
        Arc::new(MemoryWalletDirectory::new()),
        Arc::new(FixedClock::new(0)),
        clock.clone(),
        ServiceConfig {
            device: DeviceId::new("0123456789abcdef0123456789abcdef").unwrap(),
            wallet_kdf: KdfConfig::MINIMUM,
            auto_lock,
        },
    );
    (service, clock)
}

fn text(buffer: &std::sync::Mutex<Vec<u8>>) -> String {
    String::from_utf8(buffer.lock().unwrap().clone()).unwrap()
}

#[test]
fn interval_is_15_seconds() {
    assert_eq!(SWEEP_INTERVAL, Duration::from_secs(15));
}

#[test]
fn tick_locks_idle_wallets_and_logs_them() {
    let (service, clock) = service(Duration::from_secs(60));
    let pw = || Zeroizing::new(PW.to_string());
    service.create("Personal", pw(), pw()).unwrap();
    let rejections = Rejections::default();
    let (log, buffer) = Log::to_buffer();
    clock.advance(Duration::from_secs(59));
    tick(&service, &rejections, &log, clock.as_ref());
    assert_eq!(text(&buffer), "");
    clock.advance(Duration::from_secs(1));
    tick(&service, &rejections, &log, clock.as_ref());
    assert_eq!(text(&buffer), "passwsyncd: locked Personal (idle)\n");
}

#[test]
fn tick_detects_suspend_and_logs_aggregated_rejections() {
    let (service, clock) = service(Duration::from_secs(900));
    let pw = || Zeroizing::new(PW.to_string());
    service.create("Personal", pw(), pw()).unwrap();
    let rejections = Rejections::default();
    rejections.count(Reason::Host);
    rejections.count(Reason::Csrf);
    let (log, buffer) = Log::to_buffer();
    clock.suspend(Duration::from_secs(600));
    tick(&service, &rejections, &log, clock.as_ref());
    assert_eq!(
        text(&buffer),
        "passwsyncd: suspend detected\n\
         passwsyncd: locked Personal (suspend)\n\
         passwsyncd: rejected host=1 origin=0 csrf=1 session=0 size=0 peer=0\n"
    );
}

/// CPU ticks (user + system) used so far by the thread named `name` in this process.
fn thread_ticks(name: &str) -> Option<u64> {
    for task in fs::read_dir("/proc/self/task").ok()?.flatten() {
        let comm = fs::read_to_string(task.path().join("comm")).unwrap_or_default();
        if comm.trim_end() == name {
            let stat = fs::read_to_string(task.path().join("stat")).ok()?;
            let after = &stat[stat.rfind(')')? + 2..];
            let fields: Vec<&str> = after.split_whitespace().collect();
            return Some(fields[11].parse::<u64>().ok()? + fields[12].parse::<u64>().ok()?);
        }
    }
    None
}

#[test]
fn sweeper_thread_sleeps_instead_of_busy_polling_and_stops_promptly() {
    let mut server = TestServer::start();
    thread::sleep(Duration::from_millis(100));
    let before = thread_ticks("sweeper").expect("sweeper thread running");
    thread::sleep(Duration::from_millis(1500));
    let after = thread_ticks("sweeper").unwrap();
    assert!(
        after - before <= 1,
        "sweeper used {} ticks while idle",
        after - before
    );
    let started = Instant::now();
    server.stop();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "stop wakes the sweeper"
    );
}
