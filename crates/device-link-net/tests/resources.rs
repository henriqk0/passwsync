//! Resource budget (SC-007, FR-039), measured with real timers. Slow; run with
//! `cargo test --release -- --ignored`.

mod support;

use std::fs;
use std::time::{Duration, Instant};

use device_link::link::Timing;
use support::{Options, TestNode, pair, start, wait_for};

fn rss_kib() -> u64 {
    let status = fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap()
}

/// utime + stime of this process in clock ticks (100 Hz on Linux).
fn cpu_ticks() -> u64 {
    let stat = fs::read_to_string("/proc/self/stat").unwrap();
    let after = &stat[stat.rfind(')').unwrap() + 2..];
    let fields: Vec<&str> = after.split_whitespace().collect();
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}

#[test]
fn wakes_are_counted() {
    let a = start(1, "A", Options::default());
    let before = a.node.wakes();
    std::thread::sleep(Duration::from_millis(700));
    assert!(a.node.wakes() > before, "the discovery timer ticked");
    a.node.stop();
}

#[test]
#[ignore]
fn idle_with_five_peers_stays_within_budget() {
    let baseline = rss_kib();
    let a = start(
        1,
        "A",
        Options {
            timing: Timing::default(),
            ..Options::default()
        },
    );
    let peers: Vec<TestNode> = (2..7)
        .map(|i| {
            start(
                i,
                "Peer",
                Options {
                    timing: Timing::default(),
                    ..Options::default()
                },
            )
        })
        .collect();
    for peer in &peers {
        pair(&a, peer);
    }
    assert!(wait_for(Duration::from_secs(30), || a.node.channel_count() == 5));
    // Idle window.
    let window = Duration::from_secs(95);
    let (wakes, ticks, started) = (a.node.wakes(), cpu_ticks(), Instant::now());
    std::thread::sleep(window);
    let elapsed = started.elapsed().as_secs_f64();
    let cpu = (cpu_ticks() - ticks) as f64 / 100.0 / elapsed;
    let woke = a.node.wakes() - wakes;
    let rss_delta = rss_kib().saturating_sub(baseline);
    eprintln!("cpu {cpu:.4} wakes {woke} rss +{rss_delta} KiB (6 nodes in process)");
    assert!(cpu < 0.01, "CPU {cpu}");
    // <= 1 wake per 30 s per peer on average, plus the discovery tick.
    let periods = window.as_secs() / 30 + 1;
    assert!(woke <= 5 * periods + periods + 5, "{woke} wakes");
    assert!(rss_delta < 10 * 1024, "RSS grew {rss_delta} KiB");
    assert_eq!(a.node.channel_count(), 5);
    a.node.stop();
    for peer in peers {
        peer.node.stop();
    }
}
