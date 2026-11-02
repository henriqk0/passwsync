//! Target 8 `pairing_initiator` (FR-013): `PairingInitiator::on_frame` fed a genuine joiner
//! transcript with one message replaced by the input (SPAKE_B, msg1 or msg3). A mutated
//! exchange ends failed, pins nothing, and leaves the code unused or failed (003 rules).

use std::sync::OnceLock;

use device_link::code::CodeState;
use device_link::pairing::{InitiatorState, JoinerState};
use hardening::mutate::{Input, Seed};
use hardening::oracle::{FailureKind, Verdict};
use hardening::runner::Target;

use super::common::{check, violation};
use super::handshake::{Substitute, pairing_run};

/// Joiner -> initiator messages that are mutated (the PairAck after acceptance is not: the
/// initiator's pin stays whatever B sends then, FR-022b).
pub const SLOTS: usize = 3;

fn recorded() -> &'static Vec<Vec<u8>> {
    static RECORDED: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    RECORDED.get_or_init(|| {
        let run = pairing_run(None, None);
        assert!(
            matches!(run.initiator, InitiatorState::Paired(_)),
            "genuine pairing"
        );
        run.to_initiator
    })
}

pub fn seeds() -> Vec<Seed> {
    let labels = ["spake-b", "msg1", "msg3"];
    (0..SLOTS)
        .map(|slot| Seed::new(labels[slot], vec![0; recorded()[slot].len()]))
        .collect()
}

pub fn one(input: &Input) -> Verdict {
    let slot = input.seed % SLOTS;
    // The input is an XOR edit mask over the live message (all zero = genuine), so seeds and
    // counts do not depend on the session's fresh randomness (SC-002).
    let zeros = vec![0; recorded()[slot].len()];
    let sub = Substitute {
        slot,
        recorded: &zeros,
        input: &input.bytes,
    };
    let run = pairing_run(Some(&sub), None);
    if !input.mutated {
        let paired = matches!(run.initiator, InitiatorState::Paired(_))
            && matches!(run.joiner, JoinerState::Paired(_))
            && run.initiator_pins == 1
            && run.code == CodeState::Accepted;
        return match check(paired, "genuine exchange did not pair") {
            Ok(()) => Verdict::Accepted,
            Err(v) => v,
        };
    }
    if !matches!(run.initiator, InitiatorState::Failed(_)) {
        return violation(FailureKind::StateLeak, "mutated exchange did not fail");
    }
    if run.initiator_pins != 0 {
        return violation(FailureKind::StateLeak, "mutated exchange pinned a peer");
    }
    if !matches!(run.code, CodeState::Active | CodeState::Failed) {
        return violation(FailureKind::StateLeak, "code not unused or failed");
    }
    Verdict::Rejected("Failed")
}

pub fn target() -> Target {
    Target::new("pairing_initiator", seeds, one)
        .alloc_bound(1024 * 1024)
        .error_kinds(&["Failed"])
}

pub fn one_bytes(data: &[u8]) {
    let slot = data.first().map_or(0, |b| usize::from(*b) % SLOTS);
    hardening::runner::check_bytes(&target(), slot, data.get(1..).unwrap_or_default());
}
