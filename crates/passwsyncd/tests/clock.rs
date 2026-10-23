use passwsyncd::clock::OsElapsedClock;
use wallet_service::ElapsedClock;

#[test]
fn monotonic_never_decreases_and_boottime_is_at_least_monotonic() {
    let clock = OsElapsedClock;
    let mut last = clock.monotonic();
    for _ in 0..1000 {
        let now = clock.monotonic();
        assert!(now >= last);
        last = now;
    }
    let mono = clock.monotonic();
    let boot = clock.boottime();
    assert!(boot >= mono, "boottime {boot:?} < monotonic {mono:?}");
}
