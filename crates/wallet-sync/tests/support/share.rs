//! In-memory devices driving real share engines (005) over a frame pump (sans-IO).

use std::sync::Arc;
use std::time::Duration;

use vault_core::WalletId;
use wallet_sync::ports::{PeerId, SyncStore};
use wallet_sync::record::{SyncRecord, sha256};
use wallet_sync::share::codec::ShareMsg;
use wallet_sync::share::{InviteWallet, OutFrame, ShareDeps, ShareEngine, ShareEvent};
use wallet_sync::slots::TransferSlots;
use wallet_sync::testkit::{
    FakeMonoClock, FakeWallClock, FakeWalletSource, InMemoryReceivedStore, MemorySyncStore,
};
use zeroize::Zeroizing;

use super::{TestRng, file_bytes, sv};

pub const SESSION: [u8; 32] = [0x5e; 32];
pub const CONN: u64 = 1;
pub const CODE: &str = "12345678";
pub const T0: u64 = 1_761_400_000;

pub struct ShareDevice {
    pub id: PeerId,
    pub engine: ShareEngine,
    pub store: MemorySyncStore,
    pub received: InMemoryReceivedStore,
    pub source: FakeWalletSource,
    pub mono: Arc<FakeMonoClock>,
    pub wall: Arc<FakeWallClock>,
    pub slots: Arc<TransferSlots>,
}

pub fn share_device(seed: u8) -> ShareDevice {
    share_device_with_slots(seed, TransferSlots::new(2))
}

pub fn share_device_with_slots(seed: u8, slots: Arc<TransferSlots>) -> ShareDevice {
    let store = MemorySyncStore::new();
    let received = InMemoryReceivedStore::new();
    let source = FakeWalletSource::new();
    let mono = Arc::new(FakeMonoClock::new());
    let wall = Arc::new(FakeWallClock::new(T0));
    let id = PeerId([seed; 32]);
    let engine = ShareEngine::new(ShareDeps {
        store: Arc::new(store.clone()),
        received: Arc::new(received.clone()),
        source: Arc::new(source.clone()),
        mono: mono.clone(),
        wall: wall.clone(),
        rng: Box::new(TestRng(u64::from(seed) * 0x9e37_79b9 + 7)),
        slots: Arc::clone(&slots),
        own_id: id,
    });
    ShareDevice {
        id,
        engine,
        store,
        received,
        source,
        mono,
        wall,
        slots,
    }
}

pub fn wallet_id(n: u8) -> WalletId {
    WalletId::from_bytes([n; 16])
}

/// A format-2 wallet file of `len` bytes with a valid sync record; returns the bytes.
pub fn eligible_wallet(dev: &ShareDevice, name: &str, len: usize) -> Vec<u8> {
    let bytes = file_bytes(0x77, len);
    dev.source.set(name, bytes.clone());
    let record = SyncRecord::new(wallet_id(1), name.into(), sha256(&bytes), sv(&[("a", 3)]));
    dev.store
        .update(&wallet_id(1), &mut |_| Some(record.clone()))
        .unwrap();
    bytes
}

pub fn invite_wallet(name: &str) -> InviteWallet {
    InviteWallet {
        name: name.into(),
        id: wallet_id(1),
        format: 2,
    }
}

pub fn code(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_string())
}

/// Both engines see a share-enabled channel `conn` with `session`.
pub fn link(a: &mut ShareDevice, b: &mut ShareDevice, conn: u64, session: [u8; 32]) {
    a.engine.channel_up(b.id, conn, session, true);
    b.engine.channel_up(a.id, conn, session, true);
}

/// Every message seen on the wire, per direction, plus raw data bytes.
#[derive(Default, Debug)]
pub struct Wire {
    pub a_to_b: Vec<ShareMsg>,
    pub b_to_a: Vec<ShareMsg>,
    pub data_a_to_b: usize,
    pub data_b_to_a: usize,
    pub raw: Vec<u8>,
}

/// Moves frames both ways on `conn` until nothing is left.
pub fn pump_conn(a: &mut ShareDevice, b: &mut ShareDevice, conn: u64) -> Wire {
    let mut wire = Wire::default();
    for _ in 0..1_000_000 {
        let ab = a.engine.poll_outgoing(b.id, 64);
        let ba = b.engine.poll_outgoing(a.id, 64);
        if ab.is_empty() && ba.is_empty() {
            return wire;
        }
        for frame in ab {
            deliver(&mut wire, true, a.id, b, conn, frame);
        }
        for frame in ba {
            deliver(&mut wire, false, b.id, a, conn, frame);
        }
    }
    panic!("pump did not settle");
}

pub fn pump(a: &mut ShareDevice, b: &mut ShareDevice) -> Wire {
    pump_conn(a, b, CONN)
}

fn deliver(
    wire: &mut Wire,
    from_a: bool,
    from: PeerId,
    to: &mut ShareDevice,
    conn: u64,
    f: OutFrame,
) {
    match f {
        OutFrame::Msg(msg) => {
            wire.raw.extend_from_slice(&msg.encode());
            if from_a {
                wire.a_to_b.push(msg.clone());
            } else {
                wire.b_to_a.push(msg.clone());
            }
            to.engine.on_msg(from, conn, msg);
        }
        OutFrame::Data(bytes) => {
            wire.raw.extend_from_slice(&bytes);
            if from_a {
                wire.data_a_to_b += bytes.len();
            } else {
                wire.data_b_to_a += bytes.len();
            }
            to.engine.on_data(from, conn, &bytes);
        }
    }
}

/// Messages `dev` wants to send to `to` (drains its outbox; data frames are dropped).
pub fn drain_msgs(dev: &mut ShareDevice, to: PeerId) -> Vec<ShareMsg> {
    let mut out = Vec::new();
    loop {
        let frames = dev.engine.poll_outgoing(to, 64);
        if frames.is_empty() {
            return out;
        }
        out.extend(frames.into_iter().filter_map(|f| match f {
            OutFrame::Msg(m) => Some(m),
            OutFrame::Data(_) => None,
        }));
    }
}

pub fn advance(dev: &ShareDevice, by: Duration) {
    dev.mono.advance(by);
}

pub fn closed(events: &[ShareEvent]) -> bool {
    events
        .iter()
        .any(|e| matches!(e, ShareEvent::CloseChannel { .. }))
}

/// A (sender, wallet "Personal") and B (recipient) linked, with an active invitation for B.
pub fn invited(len: usize) -> (ShareDevice, ShareDevice, Vec<u8>) {
    let mut a = share_device(1);
    let mut b = share_device(2);
    let bytes = eligible_wallet(&a, "Personal", len);
    link(&mut a, &mut b, CONN, SESSION);
    a.engine
        .create(invite_wallet("Personal"), b.id, code(CODE))
        .unwrap();
    (a, b, bytes)
}

/// `invited`, then B redeems with `typed` on the channel and frames are pumped.
pub fn redeemed(len: usize, typed: &str) -> (ShareDevice, ShareDevice, Vec<u8>, Wire) {
    let (mut a, mut b, bytes) = invited(len);
    b.engine.redeem(Some(a.id), code(typed)).unwrap();
    b.engine.sender_channel(a.id, CONN);
    let wire = pump(&mut a, &mut b);
    (a, b, bytes, wire)
}
