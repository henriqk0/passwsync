//! 004 T111 (FR-027, FR-028, research R14): event-driven scheduling on fake clocks.

mod support;

use std::time::Duration;

use support::TestRng;
use wallet_sync::ports::PeerId;
use wallet_sync::round::RoundClass;
use wallet_sync::sched::{Scheduler, SyncTiming};

const A: PeerId = PeerId([1; 32]);
const B: PeerId = PeerId([2; 32]);

fn s(secs: u64) -> Duration {
    Duration::from_secs(secs)
}

fn sched() -> Scheduler {
    Scheduler::new(SyncTiming::default(), Box::new(TestRng(99)))
}

fn none_running(_: PeerId) -> bool {
    false
}

#[test]
fn a_channel_coming_up_starts_a_round_at_once() {
    let mut x = sched();
    assert!(x.due(s(0), &none_running).is_empty());
    x.channel_up(A, s(10));
    assert_eq!(x.due(s(10), &none_running), vec![A]);
    assert!(x.due(s(10), &none_running).is_empty(), "once");
}

#[test]
fn local_saves_are_coalesced_by_the_quiet_period() {
    let mut x = sched();
    x.channel_up(A, s(0));
    x.channel_up(B, s(0));
    x.due(s(0), &none_running);
    x.round_finished(A, RoundClass::Ok, s(1));
    x.round_finished(B, RoundClass::Ok, s(1));
    x.wallet_saved(s(100));
    x.wallet_saved(s(102));
    x.wallet_saved(s(104));
    assert!(
        x.due(s(104), &none_running).is_empty(),
        "still within the quiet period"
    );
    assert_eq!(
        x.next_deadline(),
        Some(s(105)),
        "5 s after the first save of the burst"
    );
    let mut due = x.due(s(105), &none_running);
    due.sort();
    assert_eq!(due, vec![A, B], "rounds with every connected peer");
    assert!(x.due(s(106), &none_running).is_empty());
}

#[test]
fn unlock_with_pending_copies_and_sync_now_start_rounds() {
    let mut x = sched();
    x.channel_up(A, s(0));
    x.due(s(0), &none_running);
    x.round_finished(A, RoundClass::Ok, s(1));
    x.unlocked_with_pending(s(50));
    assert_eq!(x.due(s(50), &none_running), vec![A]);
    x.round_finished(A, RoundClass::Ok, s(51));
    x.sync_now(s(60), &none_running);
    assert_eq!(x.due(s(60), &none_running), vec![A], "within 2 s");
}

#[test]
fn sync_now_bypasses_the_backoff_once_and_presses_while_running_are_coalesced() {
    let mut x = sched();
    x.channel_up(A, s(0));
    x.due(s(0), &none_running);
    x.round_finished(A, RoundClass::Failed, s(1));
    assert!(x.due(s(2), &none_running).is_empty(), "backing off");
    x.sync_now(s(2), &none_running);
    assert_eq!(x.due(s(2), &none_running), vec![A], "bypass");
    // While that round runs, more presses do nothing.
    let running = |p: PeerId| p == A;
    x.sync_now(s(3), &running);
    x.sync_now(s(3), &running);
    x.round_finished(A, RoundClass::Ok, s(4));
    assert!(x.due(s(4), &none_running).is_empty(), "no second round");
}

#[test]
fn the_safety_interval_triggers_a_round_with_jitter() {
    let mut x = sched();
    x.channel_up(A, s(0));
    x.channel_up(B, s(0));
    x.due(s(0), &none_running);
    x.round_finished(A, RoundClass::Ok, s(0));
    x.round_finished(B, RoundClass::Ok, s(0));
    let deadline = x.next_deadline().unwrap();
    assert!(
        deadline >= s(2880) && deadline <= s(4320),
        "1 h +-20 %: {deadline:?}"
    );
    assert!(x.due(s(2879), &none_running).is_empty());
    let mut fired = x.due(s(4320), &none_running);
    fired.sort();
    assert_eq!(fired, vec![A, B]);
    // The two peers do not fire at the same instant.
    let mut y = sched();
    y.channel_up(A, s(0));
    y.channel_up(B, s(0));
    y.due(s(0), &none_running);
    y.round_finished(A, RoundClass::Ok, s(0));
    y.round_finished(B, RoundClass::Ok, s(0));
    let first = y.next_deadline().unwrap();
    assert_eq!(y.due(first, &none_running).len(), 1, "jitter spreads peers");
}

#[test]
fn backoff_doubles_from_30_s_to_1_h_with_jitter_and_resets_on_success() {
    let mut x = sched();
    x.channel_up(A, s(0));
    x.due(s(0), &none_running);
    let mut now = s(0);
    let mut delays = Vec::new();
    for _ in 0..10 {
        x.round_finished(A, RoundClass::Timeout, now);
        let next = x.next_deadline().unwrap();
        delays.push((next - now).as_secs());
        now = next;
        assert_eq!(
            x.due(now, &none_running),
            vec![A],
            "retried at the backoff deadline"
        );
    }
    assert!((24..=36).contains(&delays[0]), "{delays:?}");
    assert!((48..=72).contains(&delays[1]), "{delays:?}");
    assert!(
        delays.iter().all(|d| *d <= 4320),
        "capped near 1 h: {delays:?}"
    );
    assert!(delays[9] >= 2880, "{delays:?}");
    x.round_finished(A, RoundClass::Ok, now);
    x.round_finished(A, RoundClass::Failed, now);
    let next = x.next_deadline().unwrap();
    assert!((next - now).as_secs() <= 36, "reset after success");
}

#[test]
fn busy_is_a_backoff_without_counting_as_a_failure() {
    let mut x = sched();
    x.channel_up(A, s(0));
    x.due(s(0), &none_running);
    x.round_finished(A, RoundClass::Busy, s(0));
    let next = x.next_deadline().unwrap();
    assert!((24..=36).contains(&next.as_secs()));
    x.due(next, &none_running);
    x.round_finished(A, RoundClass::Busy, next);
    let again = x.next_deadline().unwrap();
    assert!((again - next).as_secs() <= 36, "not doubled");
}

#[test]
fn legacy_peers_are_never_scheduled_and_nothing_runs_without_peers() {
    let mut x = sched();
    assert_eq!(x.next_deadline(), None, "no timers without peers");
    x.set_legacy(A, true);
    x.channel_up(A, s(0));
    assert!(x.due(s(0), &none_running).is_empty());
    x.sync_now(s(1), &none_running);
    x.wallet_saved(s(1));
    assert!(x.due(s(100), &none_running).is_empty());
    x.channel_down(A);
    assert_eq!(x.next_deadline(), None);
}

#[test]
fn a_running_round_is_never_doubled() {
    let mut x = sched();
    x.channel_up(A, s(0));
    let running = |p: PeerId| p == A;
    assert!(x.due(s(0), &running).is_empty());
    assert_eq!(
        x.due(s(1), &none_running),
        vec![A],
        "kept until the peer is free"
    );
}
