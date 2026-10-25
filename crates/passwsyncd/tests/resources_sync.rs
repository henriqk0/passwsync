//! 004 T121 (SC-006): idle cost of sync. The traffic budget is computed exactly with the
//! real engine and scheduler; CPU and memory are measured live (`--ignored`).

mod common;

use std::sync::Arc;
use std::time::Duration;

use vault_core::{DeviceId, StateVector, WalletId};
use wallet_sync::ports::{PeerId, SyncStore};
use wallet_sync::record::{SyncRecord, sha256};
use wallet_sync::round::{Engine, EngineConfig, EngineDeps, RoundClass};
use wallet_sync::sched::{Scheduler, SyncTiming};
use wallet_sync::testkit::{FakeMonoClock, FakeWallClock, FakeWalletSource, MemorySyncStore};

fn engine(store: &MemorySyncStore, source: &FakeWalletSource) -> Engine {
    Engine::new(
        EngineDeps {
            store: Arc::new(store.clone()),
            source: Arc::new(source.clone()),
            mono: Arc::new(FakeMonoClock::new()),
            wall: Arc::new(FakeWallClock::new(1)),
            rng: Box::new(rand_core::OsRng),
        },
        EngineConfig::default(),
    )
}

/// Bytes of one round between two devices holding 10 wallets, all in sync.
fn idle_round_bytes() -> u64 {
    let (sa, sb) = (MemorySyncStore::new(), MemorySyncStore::new());
    let (fa, fb) = (FakeWalletSource::new(), FakeWalletSource::new());
    let state = StateVector::from_pairs(vec![
        (
            DeviceId::new("0123456789abcdef0123456789abcdef").unwrap(),
            40,
        ),
        (
            DeviceId::new("fedcba9876543210fedcba9876543210").unwrap(),
            17,
        ),
    ])
    .unwrap();
    for i in 0..10u8 {
        let wallet = WalletId::from_bytes([i; 16]);
        let bytes = vec![i; 4000];
        for (store, files) in [(&sa, &fa), (&sb, &fb)] {
            files.set(&format!("w{i}"), bytes.clone());
            let r = SyncRecord::new(wallet, format!("w{i}"), sha256(&bytes), state.clone());
            store.update(&wallet, &mut |_| Some(r.clone())).unwrap();
        }
    }
    let (mut a, mut b) = (engine(&sa, &fa), engine(&sb, &fb));
    let (pa, pb) = (PeerId([1; 32]), PeerId([2; 32]));
    a.channel_up(pb, 1, [7; 32], true);
    b.channel_up(pa, 1, [7; 32], false);
    assert!(a.start_round(pb));
    let mut bytes = 0u64;
    loop {
        let ab = a.poll_outgoing(pb, 64);
        let ba = b.poll_outgoing(pa, 64);
        if ab.is_empty() && ba.is_empty() {
            break;
        }
        for f in ab {
            bytes += frame_wire_bytes(&f);
            b.on_frame(pa, 1, f);
        }
        for f in ba {
            bytes += frame_wire_bytes(&f);
            a.on_frame(pb, 1, f);
        }
    }
    bytes
}

/// Payload plus Noise tag (16) and frame length (2), as on the wire.
fn frame_wire_bytes(frame: &wallet_sync::round::Frame) -> u64 {
    let payload = match frame {
        wallet_sync::round::Frame::Ctl { fragment, .. } => fragment.len() + 2,
        wallet_sync::round::Frame::Data(d) => d.len() + 1,
    };
    (payload + 16 + 2) as u64
}

#[test]
fn idle_sync_costs_less_than_1_kib_per_peer_per_hour() {
    let round = idle_round_bytes();
    // The scheduler starts at most one idle round per peer per (jittered) safety interval.
    let mut sched = Scheduler::new(SyncTiming::default(), Box::new(rand_core::OsRng));
    let peer = PeerId([1; 32]);
    sched.channel_up(peer, Duration::ZERO);
    let mut rounds = 0u64;
    let mut now = Duration::ZERO;
    let day = Duration::from_secs(24 * 3600);
    while now < day {
        for p in sched.due(now, &|_| false) {
            rounds += 1;
            sched.round_finished(p, RoundClass::Ok, now);
        }
        now = sched
            .next_deadline()
            .unwrap_or(day)
            .max(now + Duration::from_millis(1));
    }
    let per_hour = round * rounds / 24;
    eprintln!("idle round {round} B, {rounds} rounds/day, {per_hour} B/peer/hour");
    assert!(per_hour < 1024, "{per_hour} B/peer/hour");
}

fn proc_stat_cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let after = &stat[stat.rfind(')').unwrap() + 2..];
    let fields: Vec<&str> = after.split(' ').collect();
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}

fn rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with("VmRSS:")).unwrap();
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[test]
#[ignore = "live resource measurement (Linux)"]
fn five_peers_with_ten_wallets_idle_cheaply() {
    use common::sync::*;
    let hub = instance("Hub");
    let mut peers = Vec::new();
    let baseline = rss_kib();
    for i in 0..10 {
        hub.create_wallet(&format!("W{i}"));
    }
    for i in 0..5 {
        let p = instance(&format!("Peer{i}"));
        pair_via(&hub, &p, hub.peer_port);
        for w in 0..10 {
            copy_wallet_file(&hub, &p, &format!("W{w}"));
            p.unlock(&format!("W{w}"));
        }
        peers.push(p);
    }
    std::thread::sleep(Duration::from_secs(2));
    let rss_before = rss_kib();
    let ticks_before = proc_stat_cpu_ticks();
    let window = Duration::from_secs(10);
    std::thread::sleep(window);
    let ticks = proc_stat_cpu_ticks() - ticks_before;
    let rss_growth = rss_kib().saturating_sub(rss_before);
    // 100 ticks per second; six services share this process.
    let cpu_percent_per_service = ticks as f64 / window.as_secs_f64() / 6.0;
    let per_service_kib = rss_before.saturating_sub(baseline) / 6;
    eprintln!(
        "idle CPU {cpu_percent_per_service:.3} %/service, RSS {per_service_kib} KiB/service, growth {rss_growth} KiB"
    );
    assert!(cpu_percent_per_service < 1.0);
    assert!(rss_growth < 8 * 1024, "no growth while idle");
    assert!(per_service_kib < 64 * 1024);
}
