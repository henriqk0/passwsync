//! 004 T139: negative scope (FR-039, FR-006c, FR-002): no sharing, no relay, no names.

mod support;

use support::*;
use wallet_sync::codec::{Ctl, decode};
use wallet_sync::record::{SyncRecord, encode};

#[test]
fn the_control_message_set_is_exactly_0x01_to_0x0a() {
    let tails: [&[u8]; 6] = [
        &[],
        &[0, 0],
        &[0, 0, 1],
        &[0, 0, 0, 0, 0],
        &[0, 0, 0, 0, 0, 100],
        &[0, 0, 0, 0],
    ];
    for ctype in 0u8..=255 {
        let decodable = tails.iter().any(|tail| {
            let mut bytes = vec![ctype, 0, 0, 0, 1];
            bytes.extend_from_slice(tail);
            decode(&bytes).is_ok()
        });
        assert_eq!(
            decodable,
            (0x01..=0x0A).contains(&ctype),
            "ctype {ctype:#04x}"
        );
    }
}

#[test]
fn there_is_no_create_share_or_invite_message() {
    // Exhaustive: adding any message kind breaks this match (and needs a spec change).
    fn kind(c: &Ctl) -> u8 {
        match c {
            Ctl::Tags { .. } => 1,
            Ctl::Matches { .. } => 2,
            Ctl::Summary { .. } => 3,
            Ctl::Want { .. } => 4,
            Ctl::Refuse { .. } => 5,
            Ctl::CopyStart { .. } => 6,
            Ctl::CopyEnd { .. } => 7,
            Ctl::CopyAbort { .. } => 8,
            Ctl::Done { .. } => 9,
            Ctl::Busy { .. } => 10,
        }
    }
    assert_eq!(kind(&Ctl::Done { round: 1 }), 9);
}

#[test]
fn records_and_messages_carry_no_names_settings_or_pairing_data() {
    let record = SyncRecord::new(
        wid(1),
        "Secret Wallet Name".into(),
        [0; 32],
        sv(&[("dev", 1)]),
    );
    let text = encode(&record);
    assert!(!text.contains("Secret Wallet Name"));
    let (mut a, mut b) = (device(1), device(2));
    add_wallet(&a, wid(1), "Secret Wallet Name", sv(&[("x", 2)]), 1);
    add_wallet(&b, wid(1), "Other Local Name", sv(&[("x", 1)]), 2);
    connect(&mut a, &mut b, [9; 32]);
    a.engine.start_round(b.id);
    let t = pump(&mut a, &mut b);
    for needle in ["Secret Wallet Name", "Other Local Name"] {
        assert!(!t.raw.windows(needle.len()).any(|w| w == needle.as_bytes()));
    }
}

#[test]
fn only_connected_peers_are_ever_addressed() {
    let mut a = device(1);
    add_wallet(&a, wid(1), "W", sv(&[("x", 1)]), 1);
    let stranger = wallet_sync::ports::PeerId([99; 32]);
    assert!(!a.engine.start_round(stranger));
    assert!(a.engine.poll_outgoing(stranger, 64).is_empty());
    // Frames from a peer without a channel are ignored.
    a.engine.on_frame(
        stranger,
        1,
        wallet_sync::round::Frame::Ctl {
            more: false,
            fragment: vec![0x09, 0, 0, 0, 1],
        },
    );
    assert!(a.engine.poll_outgoing(stranger, 64).is_empty());
}

#[test]
fn sync_never_creates_or_deletes_a_wallet_file() {
    let (mut a, mut b) = (device(1), device(2));
    add_wallet(&a, wid(1), "Shared", sv(&[("x", 1)]), 1);
    add_wallet(&a, wid(2), "Only-A", sv(&[("x", 1)]), 1);
    add_wallet(&b, wid(1), "Shared", sv(&[("x", 3)]), 2);
    let before = (a.source.get("Shared"), b.source.get("Shared"));
    connect(&mut a, &mut b, [9; 32]);
    a.engine.start_round(b.id);
    pump(&mut a, &mut b);
    b.engine.start_round(a.id);
    pump(&mut a, &mut b);
    assert_eq!((a.source.get("Shared"), b.source.get("Shared")), before);
    assert!(b.source.get("Only-A").is_none());
    assert!(a.source.get("Only-A").is_some());
}
