//! 005 T013: `TransferSlots` (research R8, FR-017): one service-wide transfer limit shared
//! by the 004 sync engine and the share engine.

mod support;

use std::sync::Arc;

use support::*;
use wallet_sync::codec::{Ctl, RefuseReason};
use wallet_sync::ports::SyncStore;
use wallet_sync::round::{Engine, EngineConfig, EngineDeps, Frame};
use wallet_sync::slots::TransferSlots;

const S: [u8; 32] = [3; 32];

#[test]
fn slots_are_taken_up_to_the_maximum_and_released_on_drop() {
    let slots = TransferSlots::new(2);
    assert_eq!(slots.max(), 2);
    assert_eq!(slots.active(), 0);
    let one = slots.try_take().expect("first");
    let two = slots.try_take().expect("second");
    assert_eq!(slots.active(), 2);
    assert!(slots.try_take().is_none(), "third refused");
    drop(one);
    assert_eq!(slots.active(), 1);
    let three = slots.try_take().expect("freed by drop");
    drop(two);
    drop(three);
    assert_eq!(slots.active(), 0);
}

#[test]
fn a_guard_dropped_on_an_abort_path_releases_its_slot() {
    let slots = TransferSlots::new(1);
    let result: Result<(), ()> = (|| {
        let _guard = slots.try_take().ok_or(())?;
        Err(()) // aborted while holding the slot
    })();
    assert!(result.is_err());
    assert_eq!(slots.active(), 0);
    // A panic unwinding through the holder also releases it.
    let shared = Arc::clone(&slots);
    let _ = std::panic::catch_unwind(move || {
        let _guard = shared.try_take().unwrap();
        panic!("abort");
    });
    assert_eq!(slots.active(), 0);
    assert!(slots.try_take().is_some());
}

#[test]
fn zero_slots_never_grant() {
    assert!(TransferSlots::new(0).try_take().is_none());
}

/// b (newer) answers a's Want; returns b's answer.
/// b (kept alive, so a started serve still holds its slot) is returned with the answers.
fn want_answer(b_slots: Arc<TransferSlots>) -> (Vec<Ctl>, Device) {
    let mut a = device(1);
    add_wallet(&a, wid(1), "W", sv(&[("x", 1)]), 1);
    let bytes = file_bytes(7, 3000);
    let base = device(2);
    base.source.set("W", bytes.clone());
    base.store
        .update(&wid(1), &mut |_| {
            Some(wallet_sync::record::SyncRecord::new(
                wid(1),
                "W".into(),
                wallet_sync::record::sha256(&bytes),
                sv(&[("x", 2)]),
            ))
        })
        .unwrap();
    let mut b = Device {
        engine: Engine::with_slots(
            EngineDeps {
                store: Arc::new(base.store.clone()),
                source: Arc::new(base.source.clone()),
                mono: base.mono.clone(),
                wall: base.wall.clone(),
                rng: Box::new(TestRng(5)),
            },
            EngineConfig::default(),
            Arc::clone(&b_slots),
        ),
        ..base
    };
    connect(&mut a, &mut b, S);
    assert!(a.engine.start_round(b.id));
    let mut answers = Vec::new();
    for _ in 0..20 {
        for f in a.engine.poll_outgoing(b.id, 64) {
            b.engine.on_frame(a.id, CONN, f);
        }
        let frames = b.engine.poll_outgoing(a.id, 1);
        if frames.is_empty() {
            break;
        }
        for f in frames {
            if let Frame::Ctl {
                more: false,
                fragment,
            } = &f
            {
                if let Ok(ctl) = wallet_sync::codec::decode(fragment) {
                    let stop = matches!(ctl, Ctl::CopyStart { .. } | Ctl::Refuse { .. });
                    answers.push(ctl);
                    if stop {
                        return (answers, b);
                    }
                }
            }
            a.engine.on_frame(b.id, CONN, f);
        }
    }
    (answers, b)
}

#[test]
fn two_share_transfers_leave_no_slot_for_a_sync_serve() {
    let slots = TransferSlots::new(2);
    let _share_one = slots.try_take().unwrap();
    let _share_two = slots.try_take().unwrap();
    let (answers, _) = want_answer(Arc::clone(&slots));
    assert!(
        answers.iter().any(|c| matches!(
            c,
            Ctl::Refuse {
                reason: RefuseReason::Busy,
                ..
            }
        )),
        "{answers:?}"
    );
}

#[test]
fn a_sync_serve_draws_from_the_shared_counter() {
    let slots = TransferSlots::new(2);
    let _share = slots.try_take().unwrap();
    let (answers, _b) = want_answer(Arc::clone(&slots));
    assert!(
        answers.iter().any(|c| matches!(c, Ctl::CopyStart { .. })),
        "{answers:?}"
    );
    assert_eq!(slots.active(), 2, "the sync serve holds the second slot");
    assert!(slots.try_take().is_none(), "nothing left for a share");
}

#[test]
fn engine_new_keeps_the_004_limit_from_its_config() {
    // `Engine::new` builds its own `TransferSlots::new(config.max_transfers)`: 004 limits are
    // unchanged (the 004 transfer tests cover the behaviour in depth).
    let dev = device(7);
    assert_eq!(dev.engine.transfers_active(), 0);
    assert_eq!(dev.engine.slots().max(), 2);
    let zero = device_with(
        8,
        EngineConfig {
            max_transfers: 0,
            ..EngineConfig::default()
        },
    );
    assert_eq!(zero.engine.slots().max(), 0);
}
