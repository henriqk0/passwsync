//! Pairing state machines (research R4, contracts/peer-protocol.md "Pairing"): SPAKE2 keyed
//! by the code; its output is the PSK of `Noise_XXpsk2_25519_ChaChaPoly_BLAKE2s` and its
//! transcript is bound in the Noise prologue. Pins are committed in two phases (FR-022b).
//! Only `spake2` and `snow` APIs are used; no primitive is implemented here.

use std::time::Duration;

use rand_core::CryptoRngCore;
use snow::{HandshakeState, TransportState};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::{Zeroize, Zeroizing};

use crate::code::{CodeState, PairingCode};
use crate::error::{Error, FailReason};
use crate::identity::{DeviceId, DeviceKey};
use crate::name::DeviceName;
use crate::noise;
use crate::registry::{PeerPin, PeerRegistry};
use crate::wire::{HelloKind, MAX_FRAME, Payload, RejectReason, hello};

pub const SPAKE_ID_A: &[u8] = b"passwsync-pair-initiator-v1";
pub const SPAKE_ID_B: &[u8] = b"passwsync-pair-joiner-v1";
pub const NOISE_PAIR: &str = "Noise_XXpsk2_25519_ChaChaPoly_BLAKE2s";
pub const NOISE_CHANNEL: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
pub const PAIR_PROLOGUE: &[u8] = b"passwsync-pair-v1";
pub const CHANNEL_PROLOGUE: &[u8] = b"passwsync-channel-v1";
/// 004: prologue of channel protocol v2 (binds the Hello version, R7).
pub const CHANNEL_PROLOGUE_V2: &[u8] = b"passwsync-channel-v2";
/// 005: channel protocol v3 (sync + share), bound into the Noise prologue like v2.
pub const CHANNEL_PROLOGUE_V3: &[u8] = b"passwsync-channel-v3";
pub const SPAKE_LEN: usize = 33;
/// Every read step other than the person's decision (FR-030).
pub const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// A peer whose static key was proven in the handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    pub id: DeviceId,
    pub public: [u8; 32],
    pub name: DeviceName,
}

/// Copies the SPAKE2 output into a wiped array and wipes the returned `Vec`.
fn spake_key(spake: Spake2<Ed25519Group>, message: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut out = spake.finish(message).map_err(|_| Error::Protocol)?;
    let mut key = Zeroizing::new([0u8; 32]);
    let ok = out.len() == 32;
    if ok {
        key.copy_from_slice(&out);
    }
    out.zeroize();
    if ok { Ok(key) } else { Err(Error::Crypto) }
}

fn reject_to_fail(reason: RejectReason) -> FailReason {
    match reason {
        RejectReason::Rejected => FailReason::Rejected,
        RejectReason::Expired => FailReason::Expired,
        RejectReason::SelfPair => FailReason::SelfPair,
        RejectReason::AlreadyPaired => FailReason::AlreadyPaired,
        RejectReason::Limit => FailReason::Limit,
    }
}

fn pin_error_to_fail(error: Error) -> FailReason {
    match error {
        Error::SelfPair => FailReason::SelfPair,
        Error::AlreadyPaired => FailReason::AlreadyPaired,
        Error::Limit => FailReason::Limit,
        _ => FailReason::Protocol,
    }
}

fn frame_ok(body: &[u8]) -> bool {
    !body.is_empty() && body.len() <= MAX_FRAME
}

// ---------------------------------------------------------------------------------------
// Joiner (B): dials, enters the code.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JoinerState {
    Exchanging,
    AwaitingAcceptance { peer: DeviceId, seconds_left: u16 },
    Paired(PeerInfo),
    Failed(FailReason),
}

enum JoinStep {
    AwaitSpakeA(Spake2<Ed25519Group>),
    AwaitMsg2(Box<HandshakeState>),
    AwaitPending(Box<TransportState>, [u8; 32]),
    AwaitCommit(Box<TransportState>, [u8; 32]),
    Done,
}

pub struct PairingJoiner {
    private: Zeroizing<[u8; 32]>,
    own_public: [u8; 32],
    name: DeviceName,
    expected: Option<DeviceId>,
    prologue: Vec<u8>,
    step: JoinStep,
    state: JoinerState,
    out: Vec<Vec<u8>>,
}

impl PairingJoiner {
    /// Queues frames 1 (Hello) and 2 (SPAKE_B). `typed` is the normalized 8-digit code.
    pub fn start(
        key: &DeviceKey,
        name: DeviceName,
        typed: &str,
        expected: Option<DeviceId>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, Error> {
        let (spake, spake_b) = Spake2::<Ed25519Group>::start_b_with_rng(
            &Password::new(typed.as_bytes()),
            &Identity::new(SPAKE_ID_A),
            &Identity::new(SPAKE_ID_B),
            rng,
        );
        let hello = hello(HelloKind::Pairing);
        let mut prologue = Vec::with_capacity(PAIR_PROLOGUE.len() + 6 + 2 * SPAKE_LEN);
        prologue.extend_from_slice(PAIR_PROLOGUE);
        prologue.extend_from_slice(&hello);
        prologue.extend_from_slice(&spake_b);
        Ok(Self {
            private: Zeroizing::new(*key.private_bytes()),
            own_public: *key.public(),
            name,
            expected,
            prologue,
            step: JoinStep::AwaitSpakeA(spake),
            state: JoinerState::Exchanging,
            out: vec![hello.to_vec(), spake_b],
        })
    }

    pub fn state(&self) -> JoinerState {
        self.state.clone()
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, JoinerState::Paired(_) | JoinerState::Failed(_))
    }

    /// Frame bodies to send, in order.
    pub fn outgoing(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.out)
    }

    /// How long to wait for A's next frame: the step timeout, or the person's decision
    /// time (`seconds_left + 10 s`) while acceptance is pending.
    pub fn read_timeout(&self) -> Duration {
        match self.state {
            JoinerState::AwaitingAcceptance { seconds_left, .. } => {
                Duration::from_secs(u64::from(seconds_left)) + STEP_TIMEOUT
            }
            _ => STEP_TIMEOUT,
        }
    }

    fn fail(&mut self, reason: FailReason) {
        self.step = JoinStep::Done;
        self.out.clear();
        self.state = JoinerState::Failed(reason);
    }

    pub fn on_closed(&mut self) {
        if self.is_done() {
            return;
        }
        let reason = match self.step {
            JoinStep::AwaitSpakeA(_) => FailReason::RefusedNotPairing,
            _ => FailReason::Protocol,
        };
        self.fail(reason);
    }

    pub fn on_timeout(&mut self) {
        if !self.is_done() {
            self.fail(FailReason::Timeout);
        }
    }

    pub fn on_frame(&mut self, body: &[u8], registry: &mut PeerRegistry, now_unix: u64) {
        if self.is_done() {
            return;
        }
        if !frame_ok(body) {
            return self.fail(FailReason::Protocol);
        }
        let step = std::mem::replace(&mut self.step, JoinStep::Done);
        let result = match step {
            JoinStep::AwaitSpakeA(spake) => self.on_spake_a(spake, body),
            JoinStep::AwaitMsg2(hs) => self.on_msg2(*hs, body, registry),
            JoinStep::AwaitPending(ts, public) => self.on_pending(ts, public, body),
            JoinStep::AwaitCommit(ts, public) => {
                self.on_commit(ts, public, body, registry, now_unix)
            }
            JoinStep::Done => Err(FailReason::Protocol),
        };
        if let Err(reason) = result {
            self.fail(reason);
        }
    }

    fn on_spake_a(&mut self, spake: Spake2<Ed25519Group>, body: &[u8]) -> Result<(), FailReason> {
        if body.len() != SPAKE_LEN {
            return Err(FailReason::Protocol);
        }
        let psk = spake_key(spake, body).map_err(|_| FailReason::Protocol)?;
        self.prologue.extend_from_slice(body);
        let mut hs = noise::builder(NOISE_PAIR, &self.private, &self.prologue)
            .and_then(|b| b.psk(2, &psk).map_err(|_| Error::Crypto))
            .and_then(|b| b.build_initiator().map_err(|_| Error::Crypto))
            .map_err(|_| FailReason::Protocol)?;
        let msg1 = noise::write_handshake(&mut hs, &[]).map_err(|_| FailReason::Protocol)?;
        self.out.push(msg1);
        self.step = JoinStep::AwaitMsg2(Box::new(hs));
        Ok(())
    }

    fn on_msg2(
        &mut self,
        mut hs: HandshakeState,
        body: &[u8],
        registry: &PeerRegistry,
    ) -> Result<(), FailReason> {
        // psk2 puts the PSK into this message: a wrong code is detected here, before B
        // reveals its static key or name.
        let payload =
            noise::read_handshake(&mut hs, body).map_err(|_| FailReason::WrongCodeOrTampered)?;
        if !payload.is_empty() {
            return Err(FailReason::Protocol);
        }
        let public = noise::remote_static(&hs).map_err(|_| FailReason::Protocol)?;
        let id = DeviceId::from_public(&public);
        if public == self.own_public {
            return Err(FailReason::SelfPair);
        }
        if self.expected.is_some_and(|expected| expected != id) {
            return Err(FailReason::IdMismatch);
        }
        if registry.contains(&id) || registry.is_pinned_key(&public) {
            return Err(FailReason::AlreadyPaired);
        }
        if registry.is_full() {
            return Err(FailReason::Limit);
        }
        let hello = Zeroizing::new(
            Payload::PairHello {
                name: self.name.clone(),
            }
            .encode(),
        );
        let msg3 = noise::write_handshake(&mut hs, &hello).map_err(|_| FailReason::Protocol)?;
        let ts = hs.into_transport_mode().map_err(|_| FailReason::Protocol)?;
        self.out.push(msg3);
        self.step = JoinStep::AwaitPending(Box::new(ts), public);
        Ok(())
    }

    fn on_pending(
        &mut self,
        mut ts: Box<TransportState>,
        public: [u8; 32],
        body: &[u8],
    ) -> Result<(), FailReason> {
        match noise::open(&mut ts, body).map_err(|_| FailReason::Protocol)? {
            Payload::PairPending { seconds_left } => {
                self.state = JoinerState::AwaitingAcceptance {
                    peer: DeviceId::from_public(&public),
                    seconds_left,
                };
                self.step = JoinStep::AwaitCommit(ts, public);
                Ok(())
            }
            Payload::PairReject { reason } => Err(reject_to_fail(reason)),
            _ => Err(FailReason::Protocol),
        }
    }

    fn on_commit(
        &mut self,
        mut ts: Box<TransportState>,
        public: [u8; 32],
        body: &[u8],
        registry: &mut PeerRegistry,
        now_unix: u64,
    ) -> Result<(), FailReason> {
        match noise::open(&mut ts, body).map_err(|_| FailReason::Protocol)? {
            Payload::PairCommit { name } => {
                registry
                    .pin(PeerPin {
                        public,
                        name: name.clone(),
                        paired_at: now_unix,
                        last_seen: None,
                        last_addr: None,
                    })
                    .map_err(pin_error_to_fail)?;
                let ack =
                    noise::seal(&mut ts, &Payload::PairAck).map_err(|_| FailReason::Protocol)?;
                self.out.push(ack);
                self.state = JoinerState::Paired(PeerInfo {
                    id: DeviceId::from_public(&public),
                    public,
                    name,
                });
                Ok(())
            }
            Payload::PairReject { reason } => Err(reject_to_fail(reason)),
            _ => Err(FailReason::Protocol),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Initiator (A): shows the code, accepts.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InitiatorState {
    Exchanging,
    AwaitingAcceptance(PeerInfo),
    Paired(PeerInfo),
    Failed(FailReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptError {
    NothingPending,
    Mismatch,
    Expired,
    Storage,
}

enum InitStep {
    AwaitSpakeB,
    AwaitMsg1(Box<HandshakeState>),
    AwaitMsg3(Box<HandshakeState>),
    AwaitAccept(Box<TransportState>),
    AwaitAck(Box<TransportState>),
    Done,
}

pub struct PairingInitiator {
    private: Zeroizing<[u8; 32]>,
    name: DeviceName,
    prologue: Vec<u8>,
    step: InitStep,
    state: InitiatorState,
    out: Vec<Vec<u8>>,
    /// Whether this exchange used up the code (only then may it fail the code).
    consumed: bool,
}

impl PairingInitiator {
    /// Created after a valid pairing Hello (`hello` = its frame body).
    pub fn new(key: &DeviceKey, name: DeviceName, hello: &[u8]) -> Self {
        let mut prologue = Vec::with_capacity(PAIR_PROLOGUE.len() + 6 + 2 * SPAKE_LEN);
        prologue.extend_from_slice(PAIR_PROLOGUE);
        prologue.extend_from_slice(hello);
        Self {
            private: Zeroizing::new(*key.private_bytes()),
            name,
            prologue,
            step: InitStep::AwaitSpakeB,
            state: InitiatorState::Exchanging,
            out: Vec::new(),
            consumed: false,
        }
    }

    pub fn state(&self) -> InitiatorState {
        self.state.clone()
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, InitiatorState::Failed(_)) || matches!(self.step, InitStep::Done)
    }

    pub fn awaiting_acceptance(&self) -> bool {
        matches!(self.step, InitStep::AwaitAccept(_))
    }

    /// Waiting for B's commit acknowledgement (A's pin is already saved).
    pub fn awaiting_ack(&self) -> bool {
        matches!(self.step, InitStep::AwaitAck(_))
    }

    pub fn outgoing(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.out)
    }

    pub fn read_timeout(&self) -> Duration {
        STEP_TIMEOUT
    }

    fn fail(&mut self, reason: FailReason, code: Option<&mut PairingCode>) {
        if self.consumed {
            if let Some(code) = code {
                code.fail();
            }
        }
        self.step = InitStep::Done;
        self.state = InitiatorState::Failed(reason);
    }

    pub fn on_closed(&mut self, code: Option<&mut PairingCode>) {
        if matches!(self.state, InitiatorState::Failed(_)) {
            return;
        }
        let reason = match self.step {
            InitStep::AwaitMsg3(_) => FailReason::WrongCodeOrTampered,
            // A lost acknowledgement leaves A's pin in place (FR-022b).
            InitStep::AwaitAck(_) | InitStep::Done => {
                self.step = InitStep::Done;
                return;
            }
            _ => FailReason::Protocol,
        };
        self.fail(reason, code);
    }

    pub fn on_timeout(&mut self, code: Option<&mut PairingCode>) {
        match self.step {
            InitStep::AwaitAccept(_) => {}
            InitStep::AwaitAck(_) | InitStep::Done => self.step = InitStep::Done,
            _ if !matches!(self.state, InitiatorState::Failed(_)) => {
                self.fail(FailReason::Timeout, code)
            }
            _ => {}
        }
    }

    /// Expiry while the person has not decided: `PairReject(expired)` to B.
    pub fn tick(&mut self, code: Option<&mut PairingCode>, now: Duration) {
        let expired = code.as_ref().is_none_or(|c| now >= c.expires_at());
        if self.awaiting_acceptance() && expired {
            self.send_reject(RejectReason::Expired);
            self.fail(FailReason::Expired, code);
        }
    }

    pub fn reject(&mut self, code: Option<&mut PairingCode>) {
        if self.awaiting_acceptance() {
            self.send_reject(RejectReason::Rejected);
            self.fail(FailReason::Rejected, code);
        }
    }

    fn send_reject(&mut self, reason: RejectReason) {
        let step = std::mem::replace(&mut self.step, InitStep::Done);
        if let InitStep::AwaitAccept(mut ts) | InitStep::AwaitAck(mut ts) = step {
            if let Ok(frame) = noise::seal(&mut ts, &Payload::PairReject { reason }) {
                self.out.push(frame);
            }
        }
    }

    pub fn on_frame(
        &mut self,
        body: &[u8],
        mut code: Option<&mut PairingCode>,
        registry: &PeerRegistry,
        now: Duration,
    ) {
        if self.is_done() {
            return;
        }
        if !frame_ok(body) {
            return self.fail(FailReason::Protocol, code);
        }
        let step = std::mem::replace(&mut self.step, InitStep::Done);
        let result = match step {
            InitStep::AwaitSpakeB => self.on_spake_b(body, code.as_deref_mut(), now),
            InitStep::AwaitMsg1(hs) => self.on_msg1(*hs, body),
            InitStep::AwaitMsg3(hs) => self.on_msg3(*hs, body, code.as_deref_mut(), registry, now),
            InitStep::AwaitAccept(_) => Err(FailReason::Protocol),
            InitStep::AwaitAck(mut ts) => {
                // A's pin stays whatever B sends now (FR-022b).
                if let Ok(Payload::PairAck) = noise::open(&mut ts, body) {
                    if let Some(code) = code.as_deref_mut() {
                        code.accept();
                    }
                }
                Ok(())
            }
            InitStep::Done => Ok(()),
        };
        if let Err(reason) = result {
            self.fail(reason, code);
        }
    }

    fn on_spake_b(
        &mut self,
        body: &[u8],
        code: Option<&mut PairingCode>,
        now: Duration,
    ) -> Result<(), FailReason> {
        let Some(code) = code else {
            return Err(FailReason::RefusedNotPairing);
        };
        match code.state(now) {
            CodeState::Active => {}
            CodeState::Expired => return Err(FailReason::Expired),
            _ => return Err(FailReason::RefusedNotPairing),
        }
        if body.len() != SPAKE_LEN {
            return Err(FailReason::Protocol);
        }
        let (spake, spake_a) = Spake2::<Ed25519Group>::start_a(
            &Password::new(code.digits().as_bytes()),
            &Identity::new(SPAKE_ID_A),
            &Identity::new(SPAKE_ID_B),
        );
        // A malformed SPAKE_B closes without using up the code.
        let psk = spake_key(spake, body).map_err(|_| FailReason::Protocol)?;
        code.consume(now)
            .map_err(|_| FailReason::RefusedNotPairing)?;
        self.consumed = true;
        self.prologue.extend_from_slice(body);
        self.prologue.extend_from_slice(&spake_a);
        let hs = noise::builder(NOISE_PAIR, &self.private, &self.prologue)
            .and_then(|b| b.psk(2, &psk).map_err(|_| Error::Crypto))
            .and_then(|b| b.build_responder().map_err(|_| Error::Crypto))
            .map_err(|_| FailReason::Protocol)?;
        self.out.push(spake_a);
        self.step = InitStep::AwaitMsg1(Box::new(hs));
        Ok(())
    }

    fn on_msg1(&mut self, mut hs: HandshakeState, body: &[u8]) -> Result<(), FailReason> {
        let payload = noise::read_handshake(&mut hs, body).map_err(|_| FailReason::Protocol)?;
        if !payload.is_empty() {
            return Err(FailReason::Protocol);
        }
        let msg2 = noise::write_handshake(&mut hs, &[]).map_err(|_| FailReason::Protocol)?;
        self.out.push(msg2);
        self.step = InitStep::AwaitMsg3(Box::new(hs));
        Ok(())
    }

    fn on_msg3(
        &mut self,
        mut hs: HandshakeState,
        body: &[u8],
        code: Option<&mut PairingCode>,
        registry: &PeerRegistry,
        now: Duration,
    ) -> Result<(), FailReason> {
        let payload =
            noise::read_handshake(&mut hs, body).map_err(|_| FailReason::WrongCodeOrTampered)?;
        let name = match Payload::decode(&payload) {
            Ok(Payload::PairHello { name }) => name,
            _ => return Err(FailReason::Protocol),
        };
        let public = noise::remote_static(&hs).map_err(|_| FailReason::Protocol)?;
        let ts = hs.into_transport_mode().map_err(|_| FailReason::Protocol)?;
        self.step = InitStep::AwaitAccept(Box::new(ts));
        let Some(code) = code else {
            self.step = InitStep::Done;
            return Err(FailReason::Cancelled);
        };
        if let Err(error) = registry.check_new(&public) {
            let (reject, fail) = match error {
                Error::SelfPair => (RejectReason::SelfPair, FailReason::SelfPair),
                Error::AlreadyPaired => (RejectReason::AlreadyPaired, FailReason::AlreadyPaired),
                _ => (RejectReason::Limit, FailReason::Limit),
            };
            self.send_reject(reject);
            return Err(fail);
        }
        let seconds_left = u16::try_from(code.seconds_left(now)).unwrap_or(u16::MAX);
        if let InitStep::AwaitAccept(ts) = &mut self.step {
            let pending = noise::seal(ts, &Payload::PairPending { seconds_left })
                .map_err(|_| FailReason::Protocol)?;
            self.out.push(pending);
        }
        self.state = InitiatorState::AwaitingAcceptance(PeerInfo {
            id: DeviceId::from_public(&public),
            public,
            name,
        });
        Ok(())
    }

    /// The person accepted `device_id`: pin and save first, then send `PairCommit`.
    pub fn accept(
        &mut self,
        device_id: &DeviceId,
        registry: &mut PeerRegistry,
        code: Option<&mut PairingCode>,
        now: Duration,
        now_unix: u64,
    ) -> Result<PeerInfo, AcceptError> {
        let InitiatorState::AwaitingAcceptance(peer) = self.state.clone() else {
            return Err(AcceptError::NothingPending);
        };
        if !self.awaiting_acceptance() {
            return Err(AcceptError::NothingPending);
        }
        if peer.id != *device_id {
            return Err(AcceptError::Mismatch);
        }
        let Some(code) = code else {
            self.send_reject(RejectReason::Rejected);
            self.fail(FailReason::Cancelled, None);
            return Err(AcceptError::NothingPending);
        };
        if now >= code.expires_at() {
            self.send_reject(RejectReason::Expired);
            self.fail(FailReason::Expired, Some(code));
            return Err(AcceptError::Expired);
        }
        let pinned = registry.pin(PeerPin {
            public: peer.public,
            name: peer.name.clone(),
            paired_at: now_unix,
            last_seen: None,
            last_addr: None,
        });
        if pinned.is_err() {
            self.send_reject(RejectReason::Rejected);
            self.fail(FailReason::Protocol, Some(code));
            return Err(AcceptError::Storage);
        }
        let step = std::mem::replace(&mut self.step, InitStep::Done);
        if let InitStep::AwaitAccept(mut ts) = step {
            let commit = Payload::PairCommit {
                name: self.name.clone(),
            };
            if let Ok(frame) = noise::seal(&mut ts, &commit) {
                self.out.push(frame);
            }
            self.step = InitStep::AwaitAck(ts);
        }
        code.accept();
        self.state = InitiatorState::Paired(peer.clone());
        Ok(peer)
    }
}

// ---------------------------------------------------------------------------------------

/// Which side of an exchange a device is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Joiner,
}

/// At most one pairing exchange per device at a time (incoming or outgoing). Crossed joins
/// therefore cannot both succeed.
#[derive(Default, Debug)]
pub struct PairingSlot {
    role: Option<Role>,
}

impl PairingSlot {
    pub fn try_acquire(&mut self, role: Role) -> bool {
        if self.role.is_some() {
            return false;
        }
        self.role = Some(role);
        true
    }

    pub fn release(&mut self) {
        self.role = None;
    }

    pub fn is_busy(&self) -> bool {
        self.role.is_some()
    }

    pub fn role(&self) -> Option<Role> {
        self.role
    }
}
