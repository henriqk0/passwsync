//! In-memory devices driving real `wallet-sync` engines over a frame pump (sans-IO).
#![allow(dead_code)]

pub mod sim;

use std::sync::Arc;
use std::time::Duration;

use rand_core::{CryptoRng, RngCore};
use vault_core::{DeviceId, StateVector, WalletId};
use wallet_sync::codec::{Ctl, Reassembler, decode};
use wallet_sync::ports::{PeerId, SyncStore};
use wallet_sync::record::{SyncRecord, sha256};
use wallet_sync::round::{Engine, EngineConfig, EngineDeps, Frame, SyncEvent};
use wallet_sync::testkit::{FakeMonoClock, FakeWallClock, FakeWalletSource, MemorySyncStore};

/// Deterministic xorshift RNG for jitter and warning ids.
pub struct TestRng(pub u64);

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

pub struct Device {
    pub id: PeerId,
    pub engine: Engine,
    pub store: MemorySyncStore,
    pub source: FakeWalletSource,
    pub mono: Arc<FakeMonoClock>,
    pub wall: Arc<FakeWallClock>,
}

pub fn device(seed: u8) -> Device {
    device_with(seed, EngineConfig::default())
}

pub fn device_with(seed: u8, config: EngineConfig) -> Device {
    let store = MemorySyncStore::new();
    let source = FakeWalletSource::new();
    let mono = Arc::new(FakeMonoClock::new());
    let wall = Arc::new(FakeWallClock::new(1_761_200_000));
    let engine = Engine::new(
        EngineDeps {
            store: Arc::new(store.clone()),
            source: Arc::new(source.clone()),
            mono: mono.clone(),
            wall: wall.clone(),
            rng: Box::new(TestRng(u64::from(seed) * 0x9e37_79b9 + 1)),
        },
        config,
    );
    Device {
        id: PeerId([seed; 32]),
        engine,
        store,
        source,
        mono,
        wall,
    }
}

pub fn wid(n: u16) -> WalletId {
    let mut b = [0u8; 16];
    b[..2].copy_from_slice(&n.to_be_bytes());
    b[15] = 0x5a;
    WalletId::from_bytes(b)
}

pub fn sv(pairs: &[(&str, u64)]) -> StateVector {
    StateVector::from_pairs(
        pairs
            .iter()
            .map(|(d, c)| (DeviceId::new(*d).unwrap(), *c))
            .collect(),
    )
    .unwrap()
}

/// A wallet file (opaque bytes) plus a record describing it.
pub fn add_wallet(dev: &Device, wallet: WalletId, name: &str, state: StateVector, filler: u8) {
    let bytes = file_bytes(filler, 200);
    dev.source.set(name, bytes.clone());
    let record = SyncRecord::new(wallet, name.into(), sha256(&bytes), state);
    dev.store
        .update(&wallet, &mut |_| Some(record.clone()))
        .unwrap();
}

pub fn file_bytes(filler: u8, len: usize) -> Vec<u8> {
    let mut bytes = b"PWSV\x02\x00".to_vec();
    bytes.resize(len, filler);
    bytes
}

pub const CONN: u64 = 1;

/// `a` dialed `b`: both see the channel with the same session hash.
pub fn connect(a: &mut Device, b: &mut Device, session: [u8; 32]) {
    a.engine.channel_up(b.id, CONN, session, true);
    b.engine.channel_up(a.id, CONN, session, false);
}

/// Every control message seen on the wire, per direction.
#[derive(Default)]
pub struct Transcript {
    pub a_to_b: Vec<Ctl>,
    pub b_to_a: Vec<Ctl>,
    pub raw: Vec<u8>,
    pub data_bytes: usize,
    reasm_ab: Reassembler,
    reasm_ba: Reassembler,
}

impl Transcript {
    fn note(&mut self, from_a: bool, frame: &Frame) {
        match frame {
            Frame::Ctl { more, fragment } => {
                self.raw.extend_from_slice(fragment);
                let reasm = if from_a {
                    &mut self.reasm_ab
                } else {
                    &mut self.reasm_ba
                };
                if let Ok(Some(msg)) = reasm.push(*more, fragment) {
                    if let Ok(ctl) = decode(&msg) {
                        if from_a {
                            self.a_to_b.push(ctl);
                        } else {
                            self.b_to_a.push(ctl);
                        }
                    }
                }
            }
            Frame::Data(bytes) => {
                self.raw.extend_from_slice(bytes);
                self.data_bytes += bytes.len();
            }
        }
    }

    pub fn ctypes(list: &[Ctl]) -> Vec<&'static str> {
        list.iter()
            .map(|c| match c {
                Ctl::Tags { .. } => "Tags",
                Ctl::Matches { .. } => "Matches",
                Ctl::Summary { .. } => "Summary",
                Ctl::Want { .. } => "Want",
                Ctl::Refuse { .. } => "Refuse",
                Ctl::CopyStart { .. } => "CopyStart",
                Ctl::CopyEnd { .. } => "CopyEnd",
                Ctl::CopyAbort { .. } => "CopyAbort",
                Ctl::Done { .. } => "Done",
                Ctl::Busy { .. } => "Busy",
            })
            .collect()
    }
}

/// Moves frames both ways until nothing is left; returns the transcript.
pub fn pump(a: &mut Device, b: &mut Device) -> Transcript {
    let mut t = Transcript::default();
    pump_into(a, b, &mut t);
    t
}

pub fn pump_into(a: &mut Device, b: &mut Device, t: &mut Transcript) {
    for _ in 0..1_000_000 {
        let ab = a.engine.poll_outgoing(b.id, 64);
        let ba = b.engine.poll_outgoing(a.id, 64);
        if ab.is_empty() && ba.is_empty() {
            return;
        }
        for frame in ab {
            t.note(true, &frame);
            b.engine.on_frame(a.id, CONN, frame);
        }
        for frame in ba {
            t.note(false, &frame);
            a.engine.on_frame(b.id, CONN, frame);
        }
    }
    panic!("pump did not settle");
}

pub fn events(dev: &mut Device) -> Vec<SyncEvent> {
    dev.engine.take_events()
}

pub fn advance(dev: &Device, by: Duration) {
    dev.mono.advance(by);
}

pub fn record(dev: &Device, wallet: WalletId) -> SyncRecord {
    dev.store.load(&wallet).unwrap().unwrap()
}

/// Injects one control message from `from` into `dev` as if it came over the channel.
pub fn inject(dev: &mut Device, from: PeerId, ctl: &Ctl) {
    for (more, fragment) in wallet_sync::codec::fragment(&wallet_sync::codec::encode(ctl)) {
        dev.engine
            .on_frame(from, CONN, Frame::Ctl { more, fragment });
    }
}

/// Decoded control messages `dev` wants to send to `to` (drains its outbox).
pub fn drain_ctl(dev: &mut Device, to: PeerId) -> Vec<Ctl> {
    let mut out = Vec::new();
    let mut r = Reassembler::default();
    loop {
        let frames = dev.engine.poll_outgoing(to, 64);
        if frames.is_empty() {
            return out;
        }
        for f in frames {
            if let Frame::Ctl { more, fragment } = f {
                if let Ok(Some(m)) = r.push(more, &fragment) {
                    if let Ok(c) = decode(&m) {
                        out.push(c);
                    }
                }
            }
        }
    }
}

pub fn closed(events: &[SyncEvent]) -> bool {
    events
        .iter()
        .any(|e| matches!(e, SyncEvent::CloseChannel { .. }))
}
