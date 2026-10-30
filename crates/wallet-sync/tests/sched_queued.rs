//! 007 (FR-045): `Scheduler::queued` tells a bounded background window whether any round is
//! still wanted, so the window can end early.

mod support;

use std::time::Duration;

use support::TestRng;
use wallet_sync::ports::PeerId;
use wallet_sync::round::RoundClass;
use wallet_sync::sched::{Scheduler, SyncTiming};

const A: PeerId = PeerId([1; 32]);

fn s(secs: u64) -> Duration {
    Duration::from_secs(secs)
}

fn none_running(_: PeerId) -> bool {
    false
}

#[test]
fn nothing_is_queued_without_an_eligible_peer() {
    let mut x = Scheduler::new(SyncTiming::default(), Box::new(TestRng(5)));
    assert!(!x.queued());
    x.wallet_saved(s(0));
    assert!(!x.queued(), "a save with no peer queues nothing");
}

#[test]
fn a_channel_up_or_a_save_queues_a_round_until_it_is_taken() {
    let mut x = Scheduler::new(SyncTiming::default(), Box::new(TestRng(5)));
    x.channel_up(A, s(0));
    assert!(x.queued());
    assert_eq!(x.due(s(0), &none_running), vec![A]);
    assert!(!x.queued(), "taken by due()");
    x.round_finished(A, RoundClass::Ok, s(1));
    assert!(!x.queued());
    x.wallet_saved(s(2));
    assert!(x.queued(), "waiting for the quiet period");
    let quiet = x.timing().quiet;
    assert_eq!(x.due(s(2) + quiet, &none_running), vec![A]);
    assert!(!x.queued());
}
