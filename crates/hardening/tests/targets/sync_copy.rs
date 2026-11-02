//! Target 14 `sync_copy` (FR-014, 004 FR-029): the receive side of a sync copy transfer. Two
//! testkit engines run a real round (deterministic: seeded RNG, fake clocks, opaque files);
//! one frame of the sender's copy (CopyStart, CopyData, CopyEnd or CopyAbort) is replaced by
//! the input. Input encoding: `0x20 || more || fragment` for a control fragment, otherwise
//! `0x21 || bytes` (any other first byte is also a data chunk of the remaining bytes).
//!
//! Oracles: at most two transfers at once; a pending copy is stored only at exactly the
//! announced size, holds exactly the bytes received, and is never adopted by the engine
//! itself (adoption is the merger's job, which authenticates the wallet); no panic.

use std::sync::{Arc, OnceLock};

use device_link::testkit::ScriptedRng;
use hardening::mutate::{Input, Seed};
use hardening::oracle::{FailureKind, Verdict};
use hardening::runner::Target;
use vault_core::{DeviceId, StateVector, WalletId};
use wallet_sync::codec::{Ctl, MAX_COPY, MIN_COPY, decode};
use wallet_sync::ports::{PeerId, SyncStore};
use wallet_sync::record::{SyncRecord, sha256};
use wallet_sync::round::{Engine, EngineConfig, EngineDeps, Frame, SyncEvent};
use wallet_sync::testkit::{FakeMonoClock, FakeWallClock, FakeWalletSource, MemorySyncStore};

use super::common::{check, verdict, violation};

const CONN: u64 = 1;
const SESSION: [u8; 32] = [3; 32];
/// Largest number of concurrent transfers (004 FR-029, budget B-19).
pub const MAX_TRANSFERS: usize = 2;

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

fn wallet() -> WalletId {
    WalletId::from_bytes([0x5a; 16])
}

fn state(counter: u64) -> StateVector {
    StateVector::from_pairs(vec![(DeviceId::new("x").unwrap(), counter)]).unwrap()
}

fn file_bytes(filler: u8, len: usize) -> Vec<u8> {
    let mut bytes = b"PWSV\x02\x00".to_vec();
    bytes.resize(len, filler);
    bytes
}

fn put(dev: &Device, bytes: &[u8], counter: u64) {
    dev.source.set("W", bytes.to_vec());
    let record = SyncRecord::new(wallet(), "W".into(), sha256(bytes), state(counter));
    dev.store
        .update(&wallet(), &mut |_| Some(record.clone()))
        .unwrap();
}

/// A scenario: `a` holds the older state and receives `b`'s file of `len` bytes.
#[derive(Clone, Copy)]
pub struct Scenario {
    len: usize,
    /// `b`'s file changes while it is streamed (CopyAbort).
    changes: bool,
}

pub const SCENARIOS: [Scenario; 3] = [
    Scenario {
        len: 2_500,
        changes: false,
    },
    Scenario {
        len: 3_000,
        changes: true,
    },
    Scenario {
        len: 1024 * 1024,
        changes: false,
    },
];

fn encode_frame(frame: &Frame) -> Vec<u8> {
    match frame {
        Frame::Ctl { more, fragment } => {
            let mut out = vec![0x20, u8::from(*more)];
            out.extend_from_slice(fragment);
            out
        }
        Frame::Data(bytes) => {
            let mut out = vec![0x21];
            out.extend_from_slice(bytes);
            out
        }
    }
}

fn decode_frame(bytes: &[u8]) -> Frame {
    match bytes {
        [0x20, more, fragment @ ..] => Frame::Ctl {
            more: *more != 0,
            fragment: fragment.to_vec(),
        },
        [_, rest @ ..] => Frame::Data(rest.to_vec()),
        [] => Frame::Data(Vec::new()),
    }
}

/// What `a` saw and kept.
struct CopyRun {
    /// Every frame `b` sent to `a`, in order (after substitution).
    to_a: Vec<Frame>,
    events: Vec<SyncEvent>,
    pending: Option<Vec<u8>>,
    max_transfers: usize,
    announced: Option<u32>,
    data_after_start: Vec<u8>,
    merges: usize,
}

fn copy_run(scenario: Scenario, replace: Option<(usize, Frame)>) -> CopyRun {
    let (mut a, mut b) = (device(1), device(2));
    put(&a, &file_bytes(1, 200), 1);
    let file = file_bytes(7, scenario.len);
    put(&b, &file, 2);
    if scenario.changes {
        b.source.change_on_open("W", file_bytes(9, scenario.len));
    }
    a.engine.channel_up(b.id, CONN, SESSION, true);
    b.engine.channel_up(a.id, CONN, SESSION, false);
    a.engine.start_round(b.id);
    let mut run = CopyRun {
        to_a: Vec::new(),
        events: Vec::new(),
        pending: None,
        max_transfers: 0,
        announced: None,
        data_after_start: Vec::new(),
        merges: 0,
    };
    for _ in 0..10_000 {
        let ab = a.engine.poll_outgoing(b.id, 64);
        let ba = b.engine.poll_outgoing(a.id, 64);
        if ab.is_empty() && ba.is_empty() {
            break;
        }
        for frame in ab {
            b.engine.on_frame(a.id, CONN, frame);
        }
        for frame in ba {
            let frame = match &replace {
                Some((index, with)) if *index == run.to_a.len() => with.clone(),
                _ => frame,
            };
            match &frame {
                Frame::Ctl {
                    more: false,
                    fragment,
                } => {
                    if let Ok(Ctl::CopyStart { size, .. }) = decode(fragment) {
                        run.announced = Some(size);
                        run.data_after_start.clear();
                    }
                }
                Frame::Data(bytes) => run.data_after_start.extend_from_slice(bytes),
                Frame::Ctl { .. } => {}
            }
            run.to_a.push(frame.clone());
            a.engine.on_frame(b.id, CONN, frame);
            run.max_transfers = run
                .max_transfers
                .max(a.engine.transfers_active())
                .max(b.engine.transfers_active());
        }
    }
    run.events = a.engine.take_events();
    run.merges = a.engine.take_merge_requests().len();
    run.pending = a.store.read_pending(&wallet(), &b.id).ok();
    run
}

/// The genuine transcript of each scenario and the indexes of its copy frames.
struct Recorded {
    frames: Vec<Vec<Frame>>,
    /// `(scenario, frame index)` per seed.
    slots: Vec<(usize, usize)>,
}

fn recorded() -> &'static Recorded {
    static RECORDED: OnceLock<Recorded> = OnceLock::new();
    RECORDED.get_or_init(|| {
        let mut frames = Vec::new();
        let mut slots = Vec::new();
        for (s, scenario) in SCENARIOS.iter().enumerate() {
            let run = copy_run(*scenario, None);
            let kind = |f: &Frame| match f {
                Frame::Ctl { fragment, .. } => fragment.first().copied().unwrap_or(0),
                Frame::Data(_) => 0xDA,
            };
            let start = run
                .to_a
                .iter()
                .position(|f| kind(f) == 0x06)
                .expect("CopyStart");
            let data: Vec<usize> = (0..run.to_a.len())
                .filter(|i| kind(&run.to_a[*i]) == 0xDA)
                .collect();
            slots.push((s, start));
            if let (Some(first), Some(last)) = (data.first(), data.last()) {
                slots.push((s, *first));
                slots.push((s, data[data.len() / 2]));
                slots.push((s, *last));
            }
            for end in [0x07, 0x08] {
                if let Some(i) = run.to_a.iter().position(|f| kind(f) == end) {
                    slots.push((s, i));
                }
            }
            frames.push(run.to_a);
        }
        Recorded { frames, slots }
    })
}

pub fn seeds() -> Vec<Seed> {
    let rec = recorded();
    rec.slots
        .iter()
        .map(|(s, i)| Seed::new("copy-frame", encode_frame(&rec.frames[*s][*i])))
        .collect()
}

pub fn one(input: &Input) -> Verdict {
    let rec = recorded();
    let (s, index) = rec.slots[input.seed % rec.slots.len()];
    let replace = decode_frame(&input.bytes);
    let run = copy_run(SCENARIOS[s], Some((index, replace)));
    verdict(|| {
        check(
            run.max_transfers <= MAX_TRANSFERS,
            "more than two transfers at once",
        )?;
        if run
            .events
            .iter()
            .any(|e| matches!(e, SyncEvent::Merged { .. }))
        {
            return Err(violation(
                FailureKind::StateLeak,
                "engine adopted a copy without the merger",
            ));
        }
        let stored = run
            .events
            .iter()
            .any(|e| matches!(e, SyncEvent::PendingStored { .. }));
        if let Some(size) = run.announced {
            check(
                (MIN_COPY..=MAX_COPY).contains(&size) || !stored,
                "a copy announced outside 79..=64 MiB was stored",
            )?;
        }
        if stored {
            let pending = run.pending.as_deref().unwrap_or_default();
            check(
                run.announced == Some(pending.len() as u32),
                "pending copy size differs from the announced size",
            )?;
            check(
                pending == run.data_after_start.as_slice(),
                "pending copy differs from the bytes received",
            )?;
            check(run.merges >= 1, "stored copy without a merge request")?;
        }
        if !input.mutated {
            let genuine_ok = if SCENARIOS[s].changes {
                !stored
            } else {
                stored
            };
            check(genuine_ok, "genuine transfer did not end as recorded")?;
            return Ok(if stored {
                Verdict::Accepted
            } else {
                Verdict::Rejected("NoCopy")
            });
        }
        let closed = run
            .events
            .iter()
            .any(|e| matches!(e, SyncEvent::CloseChannel { .. }));
        Ok(if stored {
            Verdict::Accepted
        } else if closed {
            Verdict::Rejected("Protocol")
        } else {
            Verdict::Rejected("NoCopy")
        })
    })
}

pub fn target() -> Target {
    Target::new("sync_copy", seeds, one)
        .alloc_bound(2 * 1024 * 1024)
        .input_cap(1100)
        .error_kinds(&["Protocol", "NoCopy"])
}

pub fn one_bytes(data: &[u8]) {
    let seed = data.first().map_or(0, |b| usize::from(*b));
    hardening::runner::check_bytes(&target(), seed, data.get(1..).unwrap_or_default());
}
