//! 008 T092 deterministic budgets (contracts/benchmarks.md B-09, B-13, B-18, B-19, B-20). Each
//! test prints its `BUDGET` line before asserting; these tests run in the gate (`budgets` step)
//! and are collected by `scripts/bench.sh`.

use std::sync::Arc;
use std::time::Duration;

use device_link::testkit::ScriptedRng;
use vault_core::{DeviceId, StateVector, WalletId};
use wallet_sync::codec::{MAX_CTL, MAX_FRAGMENT, MAX_TAGS};
use wallet_sync::ports::{PeerId, SyncStore};
use wallet_sync::record::{SyncRecord, sha256};
use wallet_sync::round::{Engine, EngineConfig, EngineDeps, Frame};
use wallet_sync::testkit::{FakeMonoClock, FakeWallClock, FakeWalletSource, MemorySyncStore};

const MIB: u64 = 1024 * 1024;

fn budget(id: &str, value: u64, unit: &str, limit: u64, cmp: &str, source: &str) {
    let ok = match cmp {
        "lt" => value < limit,
        "le" => value <= limit,
        "eq" => value == limit,
        _ => false,
    };
    println!(
        "BUDGET id={id} value={value} unit={unit} limit={limit} cmp={cmp} source={source} class=deterministic verdict={}",
        if ok { "PASS" } else { "OVER" }
    );
}

// --- B-20 parser bounds -------------------------------------------------------------------

#[test]
fn b20_every_public_bound_equals_the_spec_value() {
    let bounds: [(&str, u64, u64); 12] = [
        ("frame", device_link::wire::MAX_FRAME as u64, 1024),
        ("fragment", MAX_FRAGMENT as u64, 1000),
        (
            "channel chunk",
            device_link::wire::MAX_SYNC_CHUNK as u64,
            1000,
        ),
        ("control message", MAX_CTL as u64, 24 * 1024),
        ("tags", MAX_TAGS as u64, 512),
        (
            "http head",
            passwsyncd::http::request::MAX_HEAD_BYTES as u64,
            16 * 1024,
        ),
        (
            "http headers",
            passwsyncd::http::request::MAX_HEADERS as u64,
            48,
        ),
        (
            "http body",
            passwsyncd::http::request::MAX_BODY_BYTES as u64,
            8 * MIB,
        ),
        ("wallet min", vault_core::MIN_WALLET_FILE as u64, 79),
        ("wallet max", vault_core::MAX_WALLET_FILE as u64, 64 * MIB),
        ("text field", vault_core::MAX_FIELD_BYTES as u64, MIB),
        (
            "service KDF cap",
            u64::from(wallet_service::KDF_MEMORY_CAP_KIB),
            131_072,
        ),
    ];
    let differing = bounds.iter().filter(|(_, got, want)| got != want).count() as u64;
    budget("B-20", differing, "count", 0, "eq", "008-FR-019");
    for (name, got, want) in bounds {
        assert_eq!(got, want, "{name}");
    }
    assert_eq!(u64::from(wallet_sync::codec::MIN_COPY), 79);
    assert_eq!(u64::from(wallet_sync::codec::MAX_COPY), 64 * MIB);
}

// --- B-09 idle wake-ups -------------------------------------------------------------------

#[test]
fn b09_the_idle_service_has_only_the_documented_sweeper_timer() {
    // The only periodic timer of an idle service without networking is the sweeper (002);
    // its behaviour is tested in crates/passwsyncd/tests/sweeper.rs. This states the bound.
    let interval = passwsyncd::sweeper::SWEEP_INTERVAL;
    let per_minute = 60 / interval.as_secs();
    budget("B-09", per_minute, "count", 4, "le", "002-SC-008");
    assert_eq!(interval, Duration::from_secs(15));
}

// --- sync helpers (deterministic: seeded RNG, fake clocks, opaque files) ------------------

struct Device {
    id: PeerId,
    engine: Engine,
    store: MemorySyncStore,
    source: FakeWalletSource,
}

fn device(seed: u8) -> Device {
    let store = MemorySyncStore::new();
    let source = FakeWalletSource::new();
    let engine = Engine::new(
        EngineDeps {
            store: Arc::new(store.clone()),
            source: Arc::new(source.clone()),
            mono: Arc::new(FakeMonoClock::new()),
            wall: Arc::new(FakeWallClock::new(1_761_200_000)),
            rng: Box::new(ScriptedRng::seeded(u64::from(seed))),
        },
        EngineConfig::default(),
    );
    Device {
        id: PeerId([seed; 32]),
        engine,
        store,
        source,
    }
}

fn wid(n: u8) -> WalletId {
    WalletId::from_bytes([n; 16])
}

fn file(filler: u8, len: usize) -> Vec<u8> {
    let mut bytes = b"PWSV\x02\x00".to_vec();
    bytes.resize(len, filler);
    bytes
}

fn put(dev: &Device, wallet: WalletId, name: &str, bytes: &[u8], counter: u64) {
    dev.source.set(name, bytes.to_vec());
    let state = StateVector::from_pairs(vec![(DeviceId::new("x").unwrap(), counter)]).unwrap();
    let record = SyncRecord::new(wallet, name.into(), sha256(bytes), state);
    dev.store
        .update(&wallet, &mut |_| Some(record.clone()))
        .unwrap();
}

fn wire(frame: &Frame) -> u64 {
    match frame {
        Frame::Ctl { fragment, .. } => fragment.len() as u64 + 2,
        Frame::Data(bytes) => bytes.len() as u64 + 1,
    }
}

/// Frames per poll, as the hosts poll (`SEND_BATCH` in host-runtime's sync and share
/// runtimes): the engine reads a chunk of the served file only when a frame is polled, so one
/// batch is everything a transfer holds outside the store at once.
const SEND_BATCH: usize = 64;

/// Moves frames both ways until quiet; returns the bytes exchanged and the largest number of
/// bytes `b` handed out for `a` in one batch.
fn pump(a: &mut Device, b: &mut Device) -> (u64, u64) {
    let (mut bytes, mut queued) = (0, 0);
    for _ in 0..1_000_000 {
        let ab = a.engine.poll_outgoing(b.id, SEND_BATCH);
        let ba = b.engine.poll_outgoing(a.id, SEND_BATCH);
        if ab.is_empty() && ba.is_empty() {
            return (bytes, queued);
        }
        queued = queued.max(ba.iter().map(wire).sum());
        for f in ab {
            bytes += wire(&f);
            b.engine.on_frame(a.id, 1, f);
        }
        for f in ba {
            bytes += wire(&f);
            a.engine.on_frame(b.id, 1, f);
        }
    }
    panic!("pump did not settle");
}

fn connect(a: &mut Device, b: &mut Device) {
    a.engine.channel_up(b.id, 1, [3; 32], true);
    b.engine.channel_up(a.id, 1, [3; 32], false);
}

// --- B-13 idle sync traffic ---------------------------------------------------------------

/// One hub with 10 wallets and 5 peers holding the same wallets; one idle round per peer per
/// hour (the default safety interval is one hour). Bytes per peer per simulated hour.
fn idle_hour_bytes() -> Vec<u64> {
    let mut hub = device(1);
    let mut out = Vec::new();
    for w in 0..10u8 {
        put(&hub, wid(w), &format!("W{w}"), &file(w, 300), 1);
    }
    for p in 0..5u8 {
        let mut peer = device(10 + p);
        for w in 0..10u8 {
            put(&peer, wid(w), &format!("W{w}"), &file(w, 300), 1);
        }
        connect(&mut hub, &mut peer);
        assert!(hub.engine.start_round(peer.id));
        out.push(pump(&mut hub, &mut peer).0);
    }
    out
}

#[test]
fn b13_idle_sync_is_under_1_kib_per_peer_per_hour_and_identical_across_runs() {
    let first = idle_hour_bytes();
    let second = idle_hour_bytes();
    let worst = first.iter().copied().max().unwrap();
    budget("B-13", worst, "B", 1024, "lt", "004-SC-006");
    assert_eq!(first, second, "idle traffic differs between runs");
    assert!(worst < 1024, "{worst} B per peer per hour");
}

// --- B-18 transfer buffer -----------------------------------------------------------------

#[test]
fn b18_a_transfer_never_holds_more_than_1_mib() {
    let (mut a, mut b) = (device(1), device(2));
    put(&a, wid(1), "W", &file(1, 200), 1);
    let big = file(7, 3 * 1024 * 1024);
    put(&b, wid(1), "W", &big, 2);
    connect(&mut a, &mut b);
    assert!(a.engine.start_round(b.id));
    let (_, queued) = pump(&mut a, &mut b);
    budget("B-18", queued, "B", MIB, "le", "004-FR-029");
    assert_eq!(a.store.read_pending(&wid(1), &b.id).unwrap(), big);
    assert!(queued <= MIB, "{queued} bytes queued at once");
}

// --- B-19 concurrent transfers ------------------------------------------------------------

#[test]
fn b19_at_most_two_transfers_run_at_once() {
    let mut hub = device(1);
    put(&hub, wid(1), "W", &file(9, 50_000), 2);
    let mut peers: Vec<Device> = (0..3u8).map(|i| device(20 + i)).collect();
    for p in &mut peers {
        put(p, wid(1), "W", &file(1, 200), 1);
        connect(p, &mut hub);
        assert!(p.engine.start_round(hub.id));
    }
    let mut max_active = 0;
    for _ in 0..10_000 {
        let mut moved = false;
        for p in &mut peers {
            for f in p.engine.poll_outgoing(hub.id, 4) {
                moved = true;
                hub.engine.on_frame(p.id, 1, f);
            }
            max_active = max_active.max(hub.engine.transfers_active());
            for f in hub.engine.poll_outgoing(p.id, 4) {
                moved = true;
                p.engine.on_frame(hub.id, 1, f);
            }
            max_active = max_active.max(hub.engine.transfers_active());
        }
        if !moved {
            break;
        }
    }
    budget("B-19", max_active as u64, "count", 2, "le", "004-FR-029");
    assert_eq!(hub.engine.slots().max(), 2);
    assert!(max_active <= 2, "{max_active} transfers at once");
    assert_eq!(max_active, 2, "the bound is reached under load");
}
