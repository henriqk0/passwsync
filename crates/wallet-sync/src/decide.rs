//! The want rule (contracts/sync-protocol.md "Want rule") and the mark checks it relies on
//! (research R10, R11).

use vault_core::StateVector;

/// A received state may exceed `max(local, peer mark)` by at most this much per device.
pub const JUMP_BOUND: u64 = 1 << 32;

/// What the receiver knows when it decides whether to `Want` a peer's copy.
pub struct WantInput<'a> {
    pub peer_state: &'a StateVector,
    /// The peer flagged its copy as not offered (possible rollback on its side).
    pub no_offer: bool,
    pub local_state: &'a StateVector,
    /// Newest authenticated state received from that peer.
    pub peer_mark: Option<&'a StateVector>,
    /// Claimed states of the pending copies already stored (from any peer).
    pub pending: Vec<&'a StateVector>,
    /// A transfer slot is free.
    pub slot_free: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Want,
    NoOffer,
    /// The peer offers a state older than one it sent before (FR-021a).
    OlderStateOffered,
    /// The peer has no change we lack (or a stored pending copy already has it).
    NoNeed,
    /// A counter jumped implausibly far (FR-031): never requested.
    Invalid,
    /// No free transfer slot: retried in a later round, not a failure.
    SlotBusy,
}

impl Decision {
    pub fn is_failure(self) -> bool {
        matches!(self, Self::Invalid)
    }
}

/// `true` when some component of `state` exceeds `max(local, mark)` by more than 2^32.
pub fn jump_too_large(
    state: &StateVector,
    local: &StateVector,
    mark: Option<&StateVector>,
) -> bool {
    state.iter().any(|(device, counter)| {
        let base = local.get(device).max(mark.map_or(0, |m| m.get(device)));
        counter > base.saturating_add(JUMP_BOUND)
    })
}

pub fn decide(input: &WantInput<'_>) -> Decision {
    if input.no_offer {
        return Decision::NoOffer;
    }
    if input
        .peer_mark
        .is_some_and(|mark| !input.peer_state.dominates(mark))
    {
        return Decision::OlderStateOffered;
    }
    if input.local_state.dominates(input.peer_state) {
        return Decision::NoNeed;
    }
    if jump_too_large(input.peer_state, input.local_state, input.peer_mark) {
        return Decision::Invalid;
    }
    if input.pending.iter().any(|p| p.dominates(input.peer_state)) {
        return Decision::NoNeed;
    }
    if !input.slot_free {
        return Decision::SlotBusy;
    }
    Decision::Want
}
