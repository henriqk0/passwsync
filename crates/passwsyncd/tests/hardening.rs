mod common;

use std::net::TcpStream;

use common::server::Fixture;
use passwsyncd::app::start;
use passwsyncd::hardening::{FakeHardening, apply, memlock_sufficient};
use passwsyncd::log::{ErrorClass, Protection};

const ORDER: [Protection; 4] = [
    Protection::CoreDumps,
    Protection::NonDumpable,
    Protection::MemlockLimit,
    Protection::Mlockall,
];

#[test]
fn protections_are_applied_in_the_normative_order() {
    let fake = FakeHardening::ok();
    let calls = fake.calls();
    apply(&fake).unwrap();
    assert_eq!(*calls.lock().unwrap(), ORDER);
}

#[test]
fn each_failure_stops_the_sequence_at_that_protection() {
    for (index, which) in ORDER.iter().enumerate() {
        let fake = FakeHardening::failing(*which);
        let calls = fake.calls();
        let (failed, class) = apply(&fake).unwrap_err();
        assert_eq!(failed, *which);
        assert_eq!(class, ErrorClass::Permission);
        assert_eq!(*calls.lock().unwrap(), ORDER[..=index]);
    }
}

#[test]
fn memlock_limit_threshold_is_256_mib_or_unlimited() {
    assert!(memlock_sufficient(None));
    assert!(memlock_sufficient(Some(256 * 1024 * 1024)));
    assert!(memlock_sufficient(Some(u64::MAX)));
    assert!(!memlock_sufficient(Some(256 * 1024 * 1024 - 1)));
    assert!(!memlock_sufficient(Some(8 * 1024 * 1024)));
    assert!(!memlock_sufficient(Some(0)));
}

#[test]
fn failed_protection_aborts_start_up_with_exit_3_and_nothing_else_happens() {
    for which in ORDER {
        let fx = Fixture::new("");
        let (deps, log, _) = fx.deps(FakeHardening::failing(which));
        let error = match start(deps) {
            Ok(_) => panic!("start-up must fail"),
            Err(error) => error,
        };
        assert_eq!(error.exit_code(), 3);
        let text = String::from_utf8(log.lock().unwrap().clone()).unwrap();
        assert!(
            text.contains(&format!("protection failed: {} (permission)", which.name())),
            "{text}"
        );
        assert!(!text.contains("protections applied"));
        assert!(!text.contains("started"));
        assert!(!fx.runtime_dir.exists(), "no runtime dir, no launch file");
        assert!(!fx.wallets_dir.exists(), "paths not touched");
        assert!(!fx.config_dir.join("device-id").exists(), "no device id");
        assert!(
            TcpStream::connect(("127.0.0.1", fx.port)).is_err(),
            "not bound"
        );
    }
}

#[test]
fn protections_are_logged_before_anything_is_served() {
    let fx = Fixture::new("");
    let (deps, log, _) = fx.deps(FakeHardening::ok());
    let running = start(deps).unwrap();
    let text = String::from_utf8(log.lock().unwrap().clone()).unwrap();
    let applied = text.find("protections applied").unwrap();
    let started = text.find("started 127.0.0.1:").unwrap();
    assert!(applied < started, "{text}");
    running.stop();
}
