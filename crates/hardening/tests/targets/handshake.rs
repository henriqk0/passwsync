//! Live device-link sessions shared by the handshake targets (pairing and channel, both
//! sides) and the channel payload target. Keys come from the testkit's seeded RNG; Noise and
//! SPAKE2 draw their ephemeral values from the OS, so genuine messages differ per session.
//! The targets' inputs are therefore XOR edit masks (seed: all zero, the message length of a
//! recorded session) applied to the live message of a fresh session
//! (`common::transfer_edit`, research R10): deterministic inputs and counts (SC-002).

use std::sync::Arc;
use std::time::Duration;

use device_link::channel::{Channel, ChannelDialer, ChannelError, ChannelResponder};
use device_link::code::PairingCode;
use device_link::identity::DeviceKey;
use device_link::name::DeviceName;
use device_link::pairing::{InitiatorState, JoinerState, PairingInitiator, PairingJoiner};
use device_link::registry::PeerRegistry;
use device_link::testkit::{MemoryPeerStore, ScriptedRng};
use device_link::wire::HelloVersion;

use super::common::transfer_edit;

pub fn key(seed: u64) -> DeviceKey {
    DeviceKey::generate(&mut ScriptedRng::seeded(seed)).expect("key")
}

pub fn name(text: &str) -> DeviceName {
    DeviceName::parse(text).expect("name")
}

/// A replacement for message `slot` of one direction: the recorded genuine message and the
/// input bytes (edit transferred onto the live message).
pub struct Substitute<'a> {
    pub slot: usize,
    pub recorded: &'a [u8],
    pub input: &'a [u8],
}

impl Substitute<'_> {
    fn apply(&self, index: usize, live: Vec<u8>) -> Vec<u8> {
        if index == self.slot {
            transfer_edit(self.recorded, self.input, &live)
        } else {
            live
        }
    }
}

// --- Channel (Noise XX) ------------------------------------------------------------------

/// What a channel session ended in, per side.
pub struct ChannelRun {
    /// Messages dialer -> responder handed to `ChannelResponder::on_frame` (msg1, msg3).
    pub to_responder: Vec<Vec<u8>>,
    /// Messages responder -> dialer handed to `ChannelDialer::on_frame` (msg2, Welcome).
    pub to_dialer: Vec<Vec<u8>>,
    pub responder_error: Option<ChannelError>,
    pub dialer_error: Option<ChannelError>,
    pub dialer_channel: Option<Channel>,
    pub responder_channel: Option<Channel>,
}

/// Runs one channel handshake between two fixed paired keys. `to_responder` / `to_dialer`
/// optionally replace one message of that direction.
pub fn channel_run(
    version: HelloVersion,
    to_responder: Option<&Substitute<'_>>,
    to_dialer: Option<&Substitute<'_>>,
) -> ChannelRun {
    let (ka, kb) = (key(1), key(2));
    let pinned_a = *ka.public();
    let is_pinned = move |public: &[u8; 32]| *public == pinned_a;
    let mut run = ChannelRun {
        to_responder: Vec::new(),
        to_dialer: Vec::new(),
        responder_error: None,
        dialer_error: None,
        dialer_channel: None,
        responder_channel: None,
    };
    let Ok(mut dialer) =
        ChannelDialer::start_version(&ka, *kb.public(), name("fz-dialer"), version)
    else {
        return run;
    };
    let mut out = dialer.outgoing();
    let hello = out.remove(0);
    let mut responder = ChannelResponder::new(&kb, name("fz-responder"), &hello);
    let mut pending_r: Vec<Vec<u8>> = out;
    for _round in 0..4 {
        let mut pending_d = Vec::new();
        for msg in pending_r.drain(..) {
            let msg = match to_responder {
                Some(s) => s.apply(run.to_responder.len(), msg),
                None => msg,
            };
            run.to_responder.push(msg.clone());
            let result = responder.on_frame(&msg, &is_pinned);
            pending_d.extend(responder.outgoing());
            match result {
                Ok(None) => {}
                Ok(Some(channel)) => run.responder_channel = Some(channel),
                Err(error) => run.responder_error = Some(error),
            }
        }
        for msg in pending_d.drain(..) {
            let msg = match to_dialer {
                Some(s) => s.apply(run.to_dialer.len(), msg),
                None => msg,
            };
            run.to_dialer.push(msg.clone());
            match dialer.on_frame(&msg) {
                Ok(None) => {}
                Ok(Some(channel)) => run.dialer_channel = Some(channel),
                Err(error) => run.dialer_error = Some(error),
            }
            pending_r.extend(dialer.outgoing());
        }
        if pending_r.is_empty() {
            break;
        }
    }
    run
}

/// A connected channel pair (dialer, responder) for `version`.
pub fn channel_pair(version: HelloVersion) -> (Channel, Channel) {
    let mut run = channel_run(version, None, None);
    (
        run.dialer_channel.take().expect("dialer channel"),
        run.responder_channel.take().expect("responder channel"),
    )
}

// --- Pairing (SPAKE2 + Noise XXpsk2) -------------------------------------------------------

pub const NOW: Duration = Duration::from_secs(1_000);
pub const NOW_UNIX: u64 = 1_761_200_000;

/// What a pairing exchange ended in.
pub struct PairingRun {
    /// Joiner -> initiator messages handed to `PairingInitiator::on_frame`
    /// (SPAKE_B, msg1, msg3, PairAck).
    pub to_initiator: Vec<Vec<u8>>,
    /// Initiator -> joiner messages handed to `PairingJoiner::on_frame`
    /// (SPAKE_A, msg2, PairPending, PairCommit).
    pub to_joiner: Vec<Vec<u8>>,
    pub initiator: InitiatorState,
    pub joiner: JoinerState,
    pub initiator_pins: usize,
    pub joiner_pins: usize,
    pub code: device_link::code::CodeState,
}

/// Runs one pairing exchange: A shows the code, B joins with it, A's person accepts as soon as
/// A asks. Optional replacements as in [`channel_run`].
pub fn pairing_run(
    to_initiator: Option<&Substitute<'_>>,
    to_joiner: Option<&Substitute<'_>>,
) -> PairingRun {
    let (ka, kb) = (key(11), key(12));
    let mut code = PairingCode::generate(&mut ScriptedRng::seeded(3), NOW).expect("code");
    let mut reg_a =
        PeerRegistry::load(*ka.public(), Arc::new(MemoryPeerStore::new())).expect("registry");
    let mut reg_b =
        PeerRegistry::load(*kb.public(), Arc::new(MemoryPeerStore::new())).expect("registry");
    let digits = code.digits().to_owned();
    let mut joiner = PairingJoiner::start(
        &kb,
        name("fz-joiner"),
        &digits,
        Some(ka.id()),
        &mut ScriptedRng::seeded(4),
    )
    .expect("joiner");
    let mut run = PairingRun {
        to_initiator: Vec::new(),
        to_joiner: Vec::new(),
        initiator: InitiatorState::Exchanging,
        joiner: JoinerState::Exchanging,
        initiator_pins: 0,
        joiner_pins: 0,
        code: code.state(NOW),
    };
    let mut out_b = joiner.outgoing();
    let hello = out_b.remove(0);
    let mut initiator = PairingInitiator::new(&ka, name("fz-initiator"), &hello);
    for _round in 0..8 {
        let mut out_a = Vec::new();
        for msg in out_b.drain(..) {
            let msg = match to_initiator {
                Some(s) => s.apply(run.to_initiator.len(), msg),
                None => msg,
            };
            run.to_initiator.push(msg.clone());
            initiator.on_frame(&msg, Some(&mut code), &reg_a, NOW);
            out_a.extend(initiator.outgoing());
        }
        if let InitiatorState::AwaitingAcceptance(peer) = initiator.state() {
            if initiator.awaiting_acceptance() {
                let _ = initiator.accept(&peer.id, &mut reg_a, Some(&mut code), NOW, NOW_UNIX);
                out_a.extend(initiator.outgoing());
            }
        }
        for msg in out_a.drain(..) {
            let msg = match to_joiner {
                Some(s) => s.apply(run.to_joiner.len(), msg),
                None => msg,
            };
            run.to_joiner.push(msg.clone());
            joiner.on_frame(&msg, &mut reg_b, NOW_UNIX);
            out_b.extend(joiner.outgoing());
        }
        if out_b.is_empty() {
            break;
        }
    }
    // The connection closes when nothing moves any more.
    initiator.on_closed(Some(&mut code));
    joiner.on_closed();
    run.initiator = initiator.state();
    run.joiner = joiner.state();
    run.initiator_pins = reg_a.len();
    run.joiner_pins = reg_b.len();
    run.code = code.state(NOW);
    run
}

// --- Shared oracle of the two channel handshake targets ------------------------------------

pub const VERSIONS: [HelloVersion; 3] = [HelloVersion::V1, HelloVersion::V2, HelloVersion::V3];
pub const CHANNEL_KINDS: &[&str] = &["Protocol", "Crypto", "Stalled"];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ChannelSide {
    Responder,
    Dialer,
}

/// Seed `i` is message `i % slots` of Hello version `i / slots`. Unmutated: both sides get a
/// channel. Mutated: the fuzzed side gets no channel and a protocol or crypto error (or
/// nothing, when the other side gave up first).
pub fn channel_one(
    input: &hardening::mutate::Input,
    slots: usize,
    recorded: &[Vec<Vec<u8>>],
    side: ChannelSide,
    run: impl Fn(HelloVersion, &Substitute<'_>) -> ChannelRun,
) -> hardening::oracle::Verdict {
    use hardening::oracle::{FailureKind, Verdict};
    let (version, slot) = ((input.seed / slots) % VERSIONS.len(), input.seed % slots);
    // XOR edit mask over the live message (all zero = genuine): deterministic seeds (SC-002).
    let zeros = vec![0; recorded[version][slot].len()];
    let sub = Substitute {
        slot,
        recorded: &zeros,
        input: &input.bytes,
    };
    let result = run(VERSIONS[version], &sub);
    if !input.mutated {
        if result.dialer_channel.is_some() && result.responder_channel.is_some() {
            return Verdict::Accepted;
        }
        return Verdict::Violation(FailureKind::ValueBound, "genuine handshake failed".into());
    }
    let (channel, error) = match side {
        ChannelSide::Responder => (result.responder_channel.is_some(), result.responder_error),
        ChannelSide::Dialer => (result.dialer_channel.is_some(), result.dialer_error),
    };
    if channel {
        return Verdict::Violation(
            FailureKind::StateLeak,
            "mutated handshake returned a channel".into(),
        );
    }
    match error {
        Some(ChannelError::Protocol) => Verdict::Rejected("Protocol"),
        Some(ChannelError::Crypto) => Verdict::Rejected("Crypto"),
        None => Verdict::Rejected("Stalled"),
        Some(ChannelError::Unpaired { .. }) => Verdict::Rejected("Unpaired"),
        Some(ChannelError::KeyMismatch { .. }) => Verdict::Rejected("KeyMismatch"),
        Some(ChannelError::Refused) => Verdict::Rejected("Refused"),
    }
}
