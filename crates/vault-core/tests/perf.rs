//! Release-mode checks for SC-003, SC-004, SC-005. Run with
//! `cargo test --release -p vault-core -- --ignored`.
//!
//! 008 (contracts/benchmarks.md): each measurement prints one `BUDGET` line (numbers only)
//! before asserting; `scripts/bench.sh` collects them.

use std::time::{Duration, Instant};

use vault_core::{DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, Vault};

fn pw() -> MasterPassword {
    MasterPassword::new("correct horse battery".to_string())
}

fn device() -> DeviceId {
    DeviceId::new("laptop").unwrap()
}

fn create(kdf: KdfConfig) -> Vault {
    Vault::create(pw(), kdf, device(), Box::new(FixedClock::new(1))).unwrap()
}

fn add_typical_entries(vault: &mut Vault, count: usize) {
    for n in 0..count {
        vault
            .add_entry(EntryFields {
                title: format!("Service {n}"),
                username: format!("user{n}@example.com"),
                password: format!("p4ssw0rd-{n:08}-abcdefgh"),
                url: format!("https://service{n}.example.com/login"),
                notes: format!("Typical note for entry {n}, a sentence or two of free text."),
            })
            .unwrap();
    }
}

/// A `kB` field of `/proc/self/status` in KiB (Linux).
fn status_kib(field: &str) -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with(field)).unwrap();
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

/// One `BUDGET` line (008 contracts/benchmarks.md); numbers only.
fn budget(id: &str, value: u64, unit: &str, limit: u64, cmp: &str, source: &str) {
    let verdict = match cmp {
        "lt" if value < limit => "PASS",
        "ge" if value >= limit => "PASS",
        "info" => "INFO",
        _ => "OVER",
    };
    println!(
        "BUDGET id={id} value={value} unit={unit} limit={limit} cmp={cmp} source={source} class=measured verdict={verdict}"
    );
}

fn unlock_ms(bytes: &[u8]) -> u64 {
    let started = Instant::now();
    Vault::unlock(bytes, pw(), device(), Box::new(FixedClock::new(1))).unwrap();
    started.elapsed().as_millis() as u64
}

/// Restarts the kernel's peak-RSS counter (`VmHWM`) at the current RSS.
fn reset_peak_rss() {
    std::fs::write("/proc/self/clear_refs", "5").expect("reset VmHWM");
}

#[test]
#[ignore = "release-mode performance check"]
fn unlock_with_default_kdf_takes_between_0_3_and_2_seconds() {
    let bytes = create(KdfConfig::DEFAULT).seal().unwrap();
    let started = Instant::now();
    Vault::unlock(&bytes, pw(), device(), Box::new(FixedClock::new(1))).unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(300),
        "KDF too cheap: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "unlock too slow: {elapsed:?}"
    );
}

#[test]
#[ignore = "release-mode performance check"]
fn list_and_search_over_10000_entries_take_under_100_ms() {
    let mut vault = create(KdfConfig::MINIMUM);
    add_typical_entries(&mut vault, 10_000);

    let started = Instant::now();
    let listed = vault.list().len();
    let list_time = started.elapsed();
    let started = Instant::now();
    let found = vault.search("service 99").len();
    let search_time = started.elapsed();
    budget(
        "B-05",
        list_time.as_millis() as u64,
        "ms",
        100,
        "lt",
        "001-SC-004",
    );
    budget(
        "B-06",
        search_time.as_millis() as u64,
        "ms",
        100,
        "lt",
        "001-SC-004",
    );

    assert_eq!(listed, 10_000);
    assert!(found > 0);
    assert!(
        list_time < Duration::from_millis(100),
        "list took {list_time:?}"
    );
    assert!(
        search_time < Duration::from_millis(100),
        "search took {search_time:?}"
    );
}

/// Peak memory while 10,000 entries are added to an unlocked vault, excluding the Argon2
/// working memory: that is transient and already released (and the peak counter reset) before
/// measuring. Measured through `/proc` because a counting global allocator needs `unsafe`,
/// which the workspace forbids.
#[test]
#[ignore = "release-mode memory check (Linux)"]
fn ten_thousand_unlocked_entries_peak_under_64_mb() {
    let mut vault = create(KdfConfig::MINIMUM);
    reset_peak_rss();
    let baseline = status_kib("VmRSS:");
    add_typical_entries(&mut vault, 10_000);
    let peak = status_kib("VmHWM:").saturating_sub(baseline);
    budget("B-07", peak / 1024, "MB", 64, "lt", "001-SC-005");
    assert!(peak < 64 * 1024, "peak grew by {peak} KiB");
    std::hint::black_box(&vault);
}

/// 004 T028 (Constitution V, SC-008): merging a 10 000-entry copy that differs by one entry
/// stays fast and its extra peak memory stays bounded (the copy is held decrypted only while
/// it is merged). Release mode: `cargo test --release -p vault-core -- --ignored`.
#[test]
#[ignore = "release-mode performance and memory check (Linux)"]
fn merging_a_10000_entry_copy_differing_by_one_entry_is_bounded() {
    use vault_core::testkit::{copy_of, fork};
    let mut base = create(KdfConfig::MINIMUM);
    add_typical_entries(&mut base, 10_000);
    let mut other = fork(&base, "phone", 2);
    let id = base.list()[0].id();
    let mut fields = EntryFields::default();
    fields.title = "changed on the phone".into();
    other.update_entry(id, fields).unwrap();
    let copy = copy_of(&other);
    drop(other);
    reset_peak_rss();
    let baseline = status_kib("VmRSS:");
    let started = Instant::now();
    let report = base.merge(copy).unwrap();
    let elapsed = started.elapsed();
    let peak = status_kib("VmHWM:").saturating_sub(baseline);
    assert!(report.changed);
    eprintln!("merge of 10 000 entries: {elapsed:?}, peak +{peak} KiB");
    // B-17 proxy: the extra peak of holding and merging the decrypted 10 000-entry copy (the
    // memory part of 004 SC-008; the end-to-end sync in passwsyncd/tests/sync_perf.rs reports
    // the duration only).
    budget("B-17", peak / 1024, "MB", 64, "lt", "004-SC-008");
    assert!(elapsed < Duration::from_secs(2), "merge took {elapsed:?}");
    assert!(peak < 64 * 1024, "peak grew by {peak} KiB");
}

/// 008 B-01, B-02: median and worst of 9 unlocks at the default KDF (001 SC-003).
#[test]
#[ignore = "release-mode performance check"]
fn unlock_default_median_and_worst() {
    let bytes = create(KdfConfig::DEFAULT).seal().unwrap();
    let mut times: Vec<u64> = (0..9).map(|_| unlock_ms(&bytes)).collect();
    times.sort_unstable();
    let (median, worst) = (times[4], times[8]);
    budget("B-01", median, "ms", 2000, "lt", "001-SC-003");
    budget("B-02", worst, "ms", 2000, "lt", "001-SC-003");
    assert!(worst < 2000, "worst unlock {worst} ms");
}

/// 008 B-03: time per guess with a wrong password at the default KDF (at least 0.3 s).
#[test]
#[ignore = "release-mode performance check"]
fn time_per_guess() {
    let bytes = create(KdfConfig::DEFAULT).seal().unwrap();
    let started = Instant::now();
    let wrong = MasterPassword::new("not the right password".to_string());
    assert!(Vault::unlock(&bytes, wrong, device(), Box::new(FixedClock::new(1))).is_err());
    let ms = started.elapsed().as_millis() as u64;
    budget("B-03", ms, "ms", 300, "ge", "001-SC-003");
    assert!(ms >= 300, "a guess costs only {ms} ms");
}

/// 008 B-04: unlock at the service KDF cap (131,072 KiB); information only, no budget.
#[test]
#[ignore = "release-mode performance check"]
fn unlock_at_service_cap() {
    let cap = KdfConfig {
        memory_kib: 131_072,
        ..KdfConfig::DEFAULT
    };
    let bytes = create(cap).seal().unwrap();
    budget("B-04", unlock_ms(&bytes), "ms", 0, "info", "008-FR-018");
}
