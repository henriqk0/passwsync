//! FR-030: termination signals lock everything, delete the launch file and exit 0.
//! One test function: signal handlers are process-wide, so the runs must not overlap.

mod common;

use std::thread;
use std::time::Duration;

use common::server::Fixture;
use passwsyncd::app::run;
use passwsyncd::hardening::FakeHardening;
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};

fn wait_for(path: &std::path::Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("{} never appeared", path.display());
}

#[test]
fn sigterm_sigint_and_sighup_stop_cleanly_with_exit_0() {
    for signal in [SIGTERM, SIGINT, SIGHUP] {
        let fx = Fixture::new("");
        let (deps, log, _) = fx.deps(FakeHardening::ok());
        let worker = thread::spawn(move || run(Vec::new(), deps));
        wait_for(&fx.launch_file);
        thread::sleep(Duration::from_millis(100));
        signal_hook::low_level::raise(signal).unwrap();
        let code = worker.join().unwrap();
        assert_eq!(code, 0, "signal {signal}");
        assert!(!fx.launch_file.exists(), "signal {signal}");
        let text = String::from_utf8(log.lock().unwrap().clone()).unwrap();
        assert!(text.ends_with("passwsyncd: stopping\n"), "{text}");
    }
}
