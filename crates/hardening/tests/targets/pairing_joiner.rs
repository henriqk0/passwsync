//! Target 9 `pairing_joiner` (FR-013): `PairingJoiner::on_frame` fed a genuine initiator
//! transcript with one message replaced (SPAKE_A, msg2, PairPending, PairCommit). A mutated
//! exchange ends failed on the joiner and pins nothing there.

use std::sync::OnceLock;

use device_link::pairing::{InitiatorState, JoinerState};
use hardening::mutate::{Input, Seed};
use hardening::oracle::{FailureKind, Verdict};
use hardening::runner::Target;

use super::common::{check, violation};
use super::handshake::{Substitute, pairing_run};

pub const SLOTS: usize = 4;

fn recorded() -> &'static Vec<Vec<u8>> {
    static RECORDED: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    RECORDED.get_or_init(|| {
        let run = pairing_run(None, None);
        assert!(
            matches!(run.joiner, JoinerState::Paired(_)),
            "genuine pairing"
        );
        run.to_joiner
    })
}

pub fn seeds() -> Vec<Seed> {
    let labels = ["spake-a", "msg2", "pending", "commit"];
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
    let run = pairing_run(None, Some(&sub));
    if !input.mutated {
        let paired = matches!(run.joiner, JoinerState::Paired(_))
            && matches!(run.initiator, InitiatorState::Paired(_))
            && run.joiner_pins == 1;
        return match check(paired, "genuine exchange did not pair") {
            Ok(()) => Verdict::Accepted,
            Err(v) => v,
        };
    }
    if !matches!(run.joiner, JoinerState::Failed(_)) {
        return violation(FailureKind::StateLeak, "mutated exchange did not fail");
    }
    if run.joiner_pins != 0 {
        return violation(FailureKind::StateLeak, "mutated exchange pinned a peer");
    }
    Verdict::Rejected("Failed")
}

pub fn target() -> Target {
    Target::new("pairing_joiner", seeds, one)
        .alloc_bound(1024 * 1024)
        .error_kinds(&["Failed"])
}

pub fn one_bytes(data: &[u8]) {
    let slot = data.first().map_or(0, |b| usize::from(*b) % SLOTS);
    hardening::runner::check_bytes(&target(), slot, data.get(1..).unwrap_or_default());
}
