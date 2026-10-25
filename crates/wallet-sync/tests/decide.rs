//! 004 T049: the want rule (contracts/sync-protocol.md "Want rule").

use vault_core::{DeviceId, StateVector};
use wallet_sync::decide::{Decision, WantInput, decide};

fn sv(pairs: &[(&str, u64)]) -> StateVector {
    StateVector::from_pairs(
        pairs
            .iter()
            .map(|(d, c)| (DeviceId::new(*d).unwrap(), *c))
            .collect(),
    )
    .unwrap()
}

fn input<'a>(peer: &'a StateVector, local: &'a StateVector) -> WantInput<'a> {
    WantInput {
        peer_state: peer,
        no_offer: false,
        local_state: local,
        peer_mark: None,
        pending: Vec::new(),
        slot_free: true,
    }
}

#[test]
fn a_peer_with_a_change_we_lack_is_wanted() {
    let (peer, local) = (sv(&[("a", 2)]), sv(&[("a", 1)]));
    assert_eq!(decide(&input(&peer, &local)), Decision::Want);
    let (peer, local) = (sv(&[("a", 1), ("b", 1)]), sv(&[("a", 2)]));
    assert_eq!(decide(&input(&peer, &local)), Decision::Want, "concurrent");
}

#[test]
fn no_offer_means_no_want() {
    let (peer, local) = (sv(&[("a", 2)]), sv(&[("a", 1)]));
    let mut i = input(&peer, &local);
    i.no_offer = true;
    assert_eq!(decide(&i), Decision::NoOffer);
}

#[test]
fn a_state_below_the_peer_mark_is_an_older_state_offered() {
    let (peer, local, mark) = (sv(&[("a", 2)]), sv(&[("a", 1)]), sv(&[("a", 3)]));
    let mut i = input(&peer, &local);
    i.peer_mark = Some(&mark);
    assert_eq!(decide(&i), Decision::OlderStateOffered);
    let concurrent_mark = sv(&[("b", 1)]);
    i.peer_mark = Some(&concurrent_mark);
    assert_eq!(decide(&i), Decision::OlderStateOffered, "not >= mark");
    let equal_mark = sv(&[("a", 2)]);
    i.peer_mark = Some(&equal_mark);
    assert_eq!(decide(&i), Decision::Want);
}

#[test]
fn nothing_new_means_no_need() {
    let (peer, local) = (sv(&[("a", 1)]), sv(&[("a", 2)]));
    assert_eq!(decide(&input(&peer, &local)), Decision::NoNeed);
    let same = sv(&[("a", 2)]);
    assert_eq!(decide(&input(&same, &local)), Decision::NoNeed);
}

#[test]
fn a_jump_beyond_2_pow_32_is_invalid() {
    let local = sv(&[("a", 10)]);
    let ok = sv(&[("a", 10 + (1u64 << 32))]);
    assert_eq!(decide(&input(&ok, &local)), Decision::Want);
    let bad = sv(&[("a", 11 + (1u64 << 32))]);
    assert_eq!(decide(&input(&bad, &local)), Decision::Invalid);
    // The bound counts from max(local, peer mark).
    let mark = sv(&[("a", 100)]);
    let near_mark = sv(&[("a", 100 + (1u64 << 32))]);
    let mut i = input(&near_mark, &local);
    i.peer_mark = Some(&mark);
    assert_eq!(decide(&i), Decision::Want);
    let new_device = sv(&[("a", 10), ("z", 1u64 << 33)]);
    assert_eq!(decide(&input(&new_device, &local)), Decision::Invalid);
}

#[test]
fn a_stored_pending_copy_that_already_covers_the_state_means_no_need() {
    let (peer, local) = (sv(&[("a", 3)]), sv(&[("a", 1)]));
    let pending = sv(&[("a", 3)]);
    let mut i = input(&peer, &local);
    i.pending = vec![&pending];
    assert_eq!(decide(&i), Decision::NoNeed);
    let older = sv(&[("a", 2)]);
    i.pending = vec![&older];
    assert_eq!(decide(&i), Decision::Want);
}

#[test]
fn no_free_slot_is_a_retry_not_a_failure() {
    let (peer, local) = (sv(&[("a", 2)]), sv(&[("a", 1)]));
    let mut i = input(&peer, &local);
    i.slot_free = false;
    assert_eq!(decide(&i), Decision::SlotBusy);
    assert!(!Decision::SlotBusy.is_failure());
    assert!(Decision::Invalid.is_failure());
}
