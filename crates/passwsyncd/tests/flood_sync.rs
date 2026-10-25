//! 004 T123: hostile peers cannot exhaust memory or CPU, and other peers keep syncing.

use std::sync::Arc;
use std::time::Duration;

use vault_core::{DeviceId, StateVector, WalletId};
use wallet_sync::codec::{Ctl, encode, fragment};
use wallet_sync::ports::{PeerId, SyncStore};
use wallet_sync::record::{SyncRecord, sha256};
use wallet_sync::round::{Engine, EngineConfig, EngineDeps, Frame, RoundClass, SyncEvent};
use wallet_sync::testkit::{FakeMonoClock, FakeWallClock, FakeWalletSource, MemorySyncStore};

struct Dev {
    engine: Engine,
    store: MemorySyncStore,
    mono: Arc<FakeMonoClock>,
}

fn sv(n: u64) -> StateVector {
    StateVector::from_pairs(vec![(DeviceId::new("d").unwrap(), n)]).unwrap()
}

fn dev(state: u64, size: usize) -> Dev {
    let store = MemorySyncStore::new();
    let files = FakeWalletSource::new();
    let bytes = vec![state as u8; size];
    files.set("W", bytes.clone());
    let wallet = WalletId::from_bytes([1; 16]);
    let r = SyncRecord::new(wallet, "W".into(), sha256(&bytes), sv(state));
    store.update(&wallet, &mut |_| Some(r.clone())).unwrap();
    let mono = Arc::new(FakeMonoClock::new());
    let engine = Engine::new(
        EngineDeps {
            store: Arc::new(store.clone()),
            source: Arc::new(files),
            mono: mono.clone(),
            wall: Arc::new(FakeWallClock::new(1)),
            rng: Box::new(rand_core::OsRng),
        },
        EngineConfig::default(),
    );
    Dev {
        engine,
        store,
        mono,
    }
}

fn inject(d: &mut Dev, from: PeerId, ctl: &Ctl) {
    for (more, frag) in fragment(&encode(ctl)) {
        d.engine.on_frame(
            from,
            1,
            Frame::Ctl {
                more,
                fragment: frag,
            },
        );
    }
}

fn closed(d: &mut Dev) -> bool {
    d.engine
        .take_events()
        .iter()
        .any(|e| matches!(e, SyncEvent::CloseChannel { .. }))
}

const HOSTILE: PeerId = PeerId([0xEE; 32]);
const FRIEND: PeerId = PeerId([0x11; 32]);

#[test]
fn endless_tags_never_grow_the_outbox_without_bound() {
    let mut d = dev(1, 200);
    d.engine.channel_up(HOSTILE, 1, [1; 32], true);
    assert!(d.engine.start_round(HOSTILE));
    // The hostile peer answers Matches then floods Tags without reading anything.
    inject(
        &mut d,
        HOSTILE,
        &Ctl::Matches {
            round: 1,
            entries: vec![(0, false)],
        },
    );
    let mut was_closed = false;
    for round in 2..10_000u32 {
        inject(
            &mut d,
            HOSTILE,
            &Ctl::Tags {
                round,
                entries: vec![],
            },
        );
        if closed(&mut d) {
            was_closed = true;
            break;
        }
    }
    assert!(was_closed, "a peer that floods without reading is cut off");
    assert!(d.engine.poll_outgoing(HOSTILE, 100_000).len() <= 1);
}

#[test]
fn oversized_and_malformed_input_closes_the_round() {
    let mut d = dev(1, 200);
    d.engine.channel_up(HOSTILE, 1, [1; 32], false);
    let mut tags = vec![0x01, 0, 0, 0, 1, 0x02, 0x01];
    tags.extend(std::iter::repeat_n(0u8, 513 * 32));
    for (more, frag) in tags
        .chunks(1000)
        .enumerate()
        .map(|(i, c)| (i < 16, c.to_vec()))
    {
        d.engine.on_frame(
            HOSTILE,
            1,
            Frame::Ctl {
                more,
                fragment: frag,
            },
        );
    }
    assert!(closed(&mut d), "513 tags");
    let mut d = dev(1, 200);
    d.engine.channel_up(HOSTILE, 1, [1; 32], false);
    let mut huge = vec![0x06, 0, 0, 0, 1, 0, 0];
    huge.extend_from_slice(&(64 * 1024 * 1024 + 1u32).to_be_bytes());
    d.engine.on_frame(
        HOSTILE,
        1,
        Frame::Ctl {
            more: false,
            fragment: huge,
        },
    );
    assert!(closed(&mut d), "CopyStart above 64 MiB");
}

#[test]
fn a_slow_loris_transfer_is_cut_off_and_other_peers_keep_syncing() {
    let mut d = dev(1, 200);
    d.engine.channel_up(HOSTILE, 1, [1; 32], true);
    assert!(d.engine.start_round(HOSTILE));
    let tags = d.engine.poll_outgoing(HOSTILE, 64);
    let Frame::Ctl { fragment: t, .. } = &tags[0] else {
        panic!()
    };
    let digest_tag: [u8; 16] = t[7..23].try_into().unwrap();
    let _ = digest_tag;
    inject(
        &mut d,
        HOSTILE,
        &Ctl::Matches {
            round: 1,
            entries: vec![(0, false)],
        },
    );
    inject(
        &mut d,
        HOSTILE,
        &Ctl::Summary {
            round: 1,
            idx: 0,
            no_offer: false,
            state: sv(9),
        },
    );
    let _ = d.engine.poll_outgoing(HOSTILE, 64); // our Summary and Want
    inject(
        &mut d,
        HOSTILE,
        &Ctl::CopyStart {
            round: 1,
            idx: 0,
            size: 64 * 1024 * 1024,
        },
    );
    // One byte every 20 s keeps the 30 s progress timer alive...
    let mut cut = false;
    for _ in 0..200 {
        d.mono.advance(Duration::from_secs(20));
        d.engine.on_frame(HOSTILE, 1, Frame::Data(vec![0]));
        d.engine.tick();
        if d.engine.take_events().iter().any(|e| {
            matches!(
                e,
                SyncEvent::RoundEnded {
                    class: RoundClass::Timeout,
                    ..
                }
            )
        }) {
            cut = true;
            break;
        }
    }
    assert!(cut, "a round has an overall deadline");
    assert_eq!(d.store.partial_count(), 0);
    // A friendly peer still completes a round.
    let mut f = dev(1, 200);
    d.engine.channel_up(FRIEND, 1, [2; 32], true);
    f.engine.channel_up(PeerId([0; 32]), 1, [2; 32], false);
    assert!(d.engine.start_round(FRIEND));
    loop {
        let out = d.engine.poll_outgoing(FRIEND, 64);
        let back = f.engine.poll_outgoing(PeerId([0; 32]), 64);
        if out.is_empty() && back.is_empty() {
            break;
        }
        for fr in out {
            f.engine.on_frame(PeerId([0; 32]), 1, fr);
        }
        for fr in back {
            d.engine.on_frame(FRIEND, 1, fr);
        }
    }
    assert!(d.engine.take_events().iter().any(|e| matches!(
        e,
        SyncEvent::RoundEnded {
            class: RoundClass::Ok,
            ..
        }
    )));
}

#[test]
fn at_most_32_peers_are_tracked() {
    let mut d = dev(1, 200);
    for i in 0..40u8 {
        d.engine.channel_up(PeerId([i; 32]), 1, [i; 32], true);
    }
    assert_eq!(d.engine.connected().len(), 32);
}
