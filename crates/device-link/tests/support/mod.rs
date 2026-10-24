//! In-memory harness for the sans-IO pairing machines: two devices, a frame pump, and a
//! hand-driven "raw" joiner built directly on `spake2` + `snow` for malformed-input tests.
#![allow(dead_code)]

pub mod channel;

use std::sync::Arc;
use std::time::Duration;

use device_link::code::PairingCode;
use device_link::error::FailReason;
use device_link::identity::{DeviceId, DeviceKey};
use device_link::name::DeviceName;
use device_link::pairing::{
    InitiatorState, JoinerState, NOISE_PAIR, PAIR_PROLOGUE, PairingInitiator, PairingJoiner,
    SPAKE_ID_A, SPAKE_ID_B,
};
use device_link::registry::{PeerPin, PeerRegistry};
use device_link::testkit::{MemoryPeerStore, ScriptedRng};
use device_link::wire::{HelloKind, Payload, hello, parse_hello};

pub const NOW_UNIX: u64 = 1_761_200_000;

pub struct Device {
    pub key: DeviceKey,
    pub name: DeviceName,
    pub reg: PeerRegistry,
    pub store: Arc<MemoryPeerStore>,
}

impl Device {
    pub fn new(seed: u8, name: &str) -> Self {
        let key = DeviceKey::from_private([seed; 32]);
        let store = Arc::new(MemoryPeerStore::new());
        let reg = PeerRegistry::load(*key.public(), store.clone()).unwrap();
        Self {
            key,
            name: DeviceName::parse(name).unwrap(),
            reg,
            store,
        }
    }

    pub fn id(&self) -> DeviceId {
        self.key.id()
    }

    pub fn pin_of(&self, other: &Device) -> PeerPin {
        PeerPin {
            public: *other.key.public(),
            name: other.name.clone(),
            paired_at: NOW_UNIX,
            last_seen: None,
            last_addr: None,
        }
    }
}

pub fn code(value: u32) -> PairingCode {
    PairingCode::generate(&mut ScriptedRng::new(&[value]), Duration::ZERO).unwrap()
}

/// One pairing attempt between initiator device `a` and joiner device `b`.
pub struct Run {
    pub a: Option<PairingInitiator>,
    pub b: PairingJoiner,
    /// Frames B sent that have not reached A yet (the first is the Hello).
    pub to_a: Vec<Vec<u8>>,
    pub to_b: Vec<Vec<u8>>,
    pub now: Duration,
    /// Every frame body seen on the wire, in order.
    pub wire: Vec<Vec<u8>>,
}

impl Run {
    pub fn start(b: &Device, typed: &str, expected: Option<DeviceId>, seed: u64) -> Self {
        let mut joiner = PairingJoiner::start(
            &b.key,
            b.name.clone(),
            typed,
            expected,
            &mut ScriptedRng::seeded(seed),
        )
        .unwrap();
        let to_a = joiner.outgoing();
        Self {
            a: None,
            b: joiner,
            to_a,
            to_b: Vec::new(),
            now: Duration::from_secs(1),
            wire: Vec::new(),
        }
    }

    /// Delivers one frame from B to A (creating A's machine on the Hello).
    pub fn deliver_to_a(&mut self, a: &mut Device, code: Option<&mut PairingCode>, frame: Vec<u8>) {
        self.wire.push(frame.clone());
        match self.a.as_mut() {
            None => {
                assert_eq!(parse_hello(&frame).unwrap(), HelloKind::Pairing);
                self.a = Some(PairingInitiator::new(&a.key, a.name.clone(), &frame));
            }
            Some(machine) => {
                machine.on_frame(&frame, code, &a.reg, self.now);
                self.to_b.extend(machine.outgoing());
            }
        }
    }

    pub fn deliver_to_b(&mut self, b: &mut Device, frame: Vec<u8>) {
        self.wire.push(frame.clone());
        self.b.on_frame(&frame, &mut b.reg, NOW_UNIX);
        self.to_a.extend(self.b.outgoing());
    }

    /// Shuttles frames until neither side has anything to send. `tamper` may change a frame
    /// in transit (index on the wire, body).
    pub fn pump_with(
        &mut self,
        a: &mut Device,
        b: &mut Device,
        code: &mut Option<PairingCode>,
        tamper: &mut dyn FnMut(usize, &mut Vec<u8>),
    ) {
        loop {
            // Frames A queued outside `on_frame` (accept, reject, expiry).
            if let Some(machine) = self.a.as_mut() {
                self.to_b.extend(machine.outgoing());
            }
            if self.a_failed() && self.to_a.is_empty() {
                while !self.to_b.is_empty() {
                    let frame = self.to_b.remove(0);
                    self.deliver_to_b(b, frame);
                }
                self.b.on_closed();
                return;
            }
            if !self.to_a.is_empty() {
                let mut frame = self.to_a.remove(0);
                tamper(self.wire.len(), &mut frame);
                self.deliver_to_a(a, code.as_mut(), frame);
                if self.a_failed() {
                    // A's last words (e.g. PairReject) still reach B, then A closes.
                    while !self.to_b.is_empty() {
                        let frame = self.to_b.remove(0);
                        self.deliver_to_b(b, frame);
                    }
                    self.b.on_closed();
                    return;
                }
            } else if !self.to_b.is_empty() {
                let mut frame = self.to_b.remove(0);
                tamper(self.wire.len(), &mut frame);
                self.deliver_to_b(b, frame);
                if self.b_failed() {
                    if let Some(machine) = self.a.as_mut() {
                        machine.on_closed(code.as_mut());
                    }
                    return;
                }
            } else {
                return;
            }
        }
    }

    pub fn pump(&mut self, a: &mut Device, b: &mut Device, code: &mut Option<PairingCode>) {
        self.pump_with(a, b, code, &mut |_, _| {});
    }

    pub fn a_state(&self) -> InitiatorState {
        self.a.as_ref().unwrap().state()
    }

    pub fn a_failed(&self) -> bool {
        matches!(
            self.a.as_ref().map(PairingInitiator::state),
            Some(InitiatorState::Failed(_))
        )
    }

    pub fn b_failed(&self) -> bool {
        matches!(self.b.state(), JoinerState::Failed(_))
    }

    pub fn a_reason(&self) -> Option<FailReason> {
        match self.a.as_ref()?.state() {
            InitiatorState::Failed(reason) => Some(reason),
            _ => None,
        }
    }

    pub fn b_reason(&self) -> Option<FailReason> {
        match self.b.state() {
            JoinerState::Failed(reason) => Some(reason),
            _ => None,
        }
    }
}

pub fn assert_nothing_pinned(a: &Device, b: &Device) {
    assert!(a.reg.is_empty(), "A pinned something");
    assert!(b.reg.is_empty(), "B pinned something");
    assert!(a.store.pins().is_empty() && b.store.pins().is_empty());
}

/// A hand-driven joiner speaking the protocol directly through `spake2` and `snow`, so tests
/// can send malformed or out-of-order frames that the real machine never produces.
pub struct RawJoiner {
    pub hello: Vec<u8>,
    pub spake_b: Vec<u8>,
    spake: Option<spake2::Spake2<spake2::Ed25519Group>>,
    pub noise: Option<snow::HandshakeState>,
    pub transport: Option<snow::TransportState>,
    key: [u8; 32],
}

impl RawJoiner {
    pub fn new(key_seed: u8, typed: &str) -> Self {
        let (spake, spake_b) = spake2::Spake2::<spake2::Ed25519Group>::start_b_with_rng(
            &spake2::Password::new(typed.as_bytes()),
            &spake2::Identity::new(SPAKE_ID_A),
            &spake2::Identity::new(SPAKE_ID_B),
            ScriptedRng::seeded(7),
        );
        Self {
            hello: hello(HelloKind::Pairing).to_vec(),
            spake_b,
            spake: Some(spake),
            noise: None,
            transport: None,
            key: [key_seed; 32],
        }
    }

    /// Consumes SPAKE_A and returns Noise msg1.
    pub fn msg1(&mut self, spake_a: &[u8]) -> Vec<u8> {
        let psk = self.spake.take().unwrap().finish(spake_a).unwrap();
        let psk: [u8; 32] = psk.try_into().unwrap();
        let mut prologue = PAIR_PROLOGUE.to_vec();
        prologue.extend_from_slice(&self.hello);
        prologue.extend_from_slice(&self.spake_b);
        prologue.extend_from_slice(spake_a);
        let mut noise = snow::Builder::new(NOISE_PAIR.parse().unwrap())
            .local_private_key(&self.key)
            .unwrap()
            .psk(2, &psk)
            .unwrap()
            .prologue(&prologue)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut buf = [0u8; 1024];
        let n = noise.write_message(&[], &mut buf).unwrap();
        self.noise = Some(noise);
        buf[..n].to_vec()
    }

    /// Reads msg2 and returns msg3 carrying `payload` bytes (may be malformed).
    pub fn msg3(&mut self, msg2: &[u8], payload: &[u8]) -> Vec<u8> {
        let noise = self.noise.as_mut().unwrap();
        let mut out = [0u8; 1024];
        noise.read_message(msg2, &mut out).unwrap();
        let mut buf = [0u8; 1024];
        let n = noise.write_message(payload, &mut buf).unwrap();
        let noise = self.noise.take().unwrap();
        self.transport = Some(noise.into_transport_mode().unwrap());
        buf[..n].to_vec()
    }

    pub fn encrypt(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut buf = [0u8; 1024];
        let n = self
            .transport
            .as_mut()
            .unwrap()
            .write_message(payload, &mut buf)
            .unwrap();
        buf[..n].to_vec()
    }

    pub fn decrypt(&mut self, frame: &[u8]) -> Option<Payload> {
        let mut out = [0u8; 1024];
        let n = self
            .transport
            .as_mut()?
            .read_message(frame, &mut out)
            .ok()?;
        Payload::decode(&out[..n]).ok()
    }
}
