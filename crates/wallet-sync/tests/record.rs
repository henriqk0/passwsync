//! 004 T040: the sync record text format (contracts/host-runtime-sync.md "Record format").

use std::collections::{BTreeMap, BTreeSet};

use vault_core::{DeviceId, StateVector, WalletId};
use wallet_sync::ports::PeerId;
use wallet_sync::record::{
    Flags, Outcome, PeerSyncState, PendingCopy, PendingStatus, Position, Prepared, RecordError,
    SyncRecord, SyncWarning, WarningKind, decode, encode, sha256,
};

fn sv(pairs: &[(&str, u64)]) -> StateVector {
    StateVector::from_pairs(
        pairs
            .iter()
            .map(|(d, c)| (DeviceId::new(*d).unwrap(), *c))
            .collect(),
    )
    .unwrap()
}

fn full() -> SyncRecord {
    let p1 = PeerId([1; 32]);
    let p2 = PeerId([2; 32]);
    let mut r = SyncRecord::new(
        WalletId::from_bytes([0xab; 16]),
        "Personal wallet".into(),
        [3; 32],
        sv(&[("a", 2), ("b", 1)]),
    );
    r.mark = sv(&[("a", 2), ("b", 1)]);
    r.prepared = Some(Prepared {
        digest: [4; 32],
        state: sv(&[("a", 3), ("b", 1)]),
        peer_marks: BTreeMap::from([(p1, sv(&[("b", 1)]))]),
        consumed: BTreeSet::from([p1]),
    });
    r.flags = Flags {
        rollback_state: true,
        rollback_digest: false,
        too_many_conflicts: true,
        duplicate_wallet_id: false,
    };
    r.peers.insert(
        p1,
        PeerSyncState {
            peer_mark: Some(sv(&[("a", 1)])),
            last_round_at: Some(1_761_200_000),
            last_outcome: Outcome::Ok,
            position: Position::InSync,
        },
    );
    r.peers.insert(
        p2,
        PeerSyncState {
            peer_mark: None,
            last_round_at: None,
            last_outcome: Outcome::OlderStateOffered,
            position: Position::OlderStateOffered,
        },
    );
    r.pending.insert(
        p2,
        PendingCopy {
            claimed: sv(&[("c", 9)]),
            size: 4096,
            received_at: 1_761_200_100,
            status: PendingStatus::CannotOpen,
        },
    );
    r.warnings.push(SyncWarning {
        id: 77,
        kind: WarningKind::OlderStateOffered,
        peer: Some(p2),
        at: 1_761_200_200,
    });
    r.warnings.push(SyncWarning {
        id: 78,
        kind: WarningKind::PossibleRollback,
        peer: None,
        at: 1_761_200_300,
    });
    r
}

#[test]
fn every_field_round_trips() {
    let r = full();
    let text = encode(&r);
    assert_eq!(decode(&text), Ok(r));
    let empty = SyncRecord::new(
        WalletId::from_bytes([1; 16]),
        "W".into(),
        [0; 32],
        StateVector::new(),
    );
    assert_eq!(decode(&encode(&empty)), Ok(empty));
}

#[test]
fn exact_text_layout() {
    let text = encode(&full());
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "passwsync-sync-record-v1");
    assert_eq!(lines[1], format!("wallet_id {}", "ab".repeat(16)));
    assert_eq!(lines[2], format!("wallet_name {}", hex(b"Personal wallet")));
    assert_eq!(lines[3], format!("digest {}", "03".repeat(32)));
    assert_eq!(
        lines[4], "state 61:2,62:1",
        "device ids as hex of their bytes"
    );
    assert_eq!(
        lines[5],
        format!(
            "prepared {} 61:3,62:1 {}=62:1 {}",
            "04".repeat(32),
            "01".repeat(32),
            "01".repeat(32)
        )
    );
    assert_eq!(lines[6], "mark 61:2,62:1");
    assert_eq!(lines[7], "flags rollback_state,too_many_conflicts");
    assert_eq!(
        lines[8],
        format!("peer {} 61:1 1761200000 ok in_sync", "01".repeat(32))
    );
    assert_eq!(
        lines[9],
        format!(
            "peer {} - - older_state_offered older_state_offered",
            "02".repeat(32)
        )
    );
    assert_eq!(
        lines[10],
        format!(
            "pending {} 63:9 4096 1761200100 cannot_open",
            "02".repeat(32)
        )
    );
    assert_eq!(
        lines[11],
        format!(
            "warning 77 older_state_offered {} 1761200200",
            "02".repeat(32)
        )
    );
    assert_eq!(lines[12], "warning 78 possible_rollback - 1761200300");
    let check_line = lines[13];
    let preceding = &text[..text.len() - check_line.len() - 1];
    assert_eq!(
        check_line,
        format!("check {}", hex(&sha256(preceding.as_bytes())))
    );
    assert_eq!(lines.len(), 14);
    assert!(text.ends_with('\n'));
    let empty = SyncRecord::new(
        WalletId::from_bytes([1; 16]),
        "W".into(),
        [0; 32],
        StateVector::new(),
    );
    let text = encode(&empty);
    assert!(text.contains("\nstate -\nprepared -\nmark -\nflags -\n"));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Re-checksums an edited record so only the edited rule is tested.
fn resign(body: &str) -> String {
    format!("{body}check {}\n", hex(&sha256(body.as_bytes())))
}

fn body_of(text: &str) -> String {
    let cut = text.rfind("check ").unwrap();
    text[..cut].to_string()
}

#[test]
fn checksum_mismatch_is_corrupted() {
    let text = encode(&full());
    let tampered = text.replacen("mark 61:2", "mark 61:9", 1);
    assert_eq!(decode(&tampered), Err(RecordError::Corrupted));
    let truncated = &text[..text.len() - 10];
    assert_eq!(decode(truncated), Err(RecordError::Corrupted));
}

#[test]
fn grammar_violations_are_corrupted() {
    let body = body_of(&encode(&full()));
    let cases = [
        body.replacen("flags ", "flagz ", 1),
        format!("{body}unknown line\n"),
        body.replacen("state 61:2,62:1", "state 62:1,61:2", 1),
        body.replacen("state 61:2,62:1", "state 61:0", 1),
        body.replacen("state 61:2,62:1", "state 61:2,61:3", 1),
        body.replacen("state 61:2,62:1", "state zz:2", 1),
        body.replacen("digest 03", "digest 0g", 1),
        body.replacen("flags rollback_state", "flags rollback_maybe", 1),
        body.replacen(" ok in_sync", " great in_sync", 1),
        body.replacen("cannot_open", "lost", 1),
        body.replacen("passwsync-sync-record-v1", "passwsync-sync-record-v2", 1),
        body.replacen("warning 78 possible_rollback", "warning 78 bogus", 1),
        body.replacen("wallet_name ", "wallet_name  ", 1),
    ];
    for (i, case) in cases.iter().enumerate() {
        assert_eq!(
            decode(&resign(case)),
            Err(RecordError::Corrupted),
            "case {i}"
        );
    }
}

#[test]
fn limits_are_enforced() {
    let mut r = full();
    let many: Vec<(DeviceId, u64)> = (0..256)
        .map(|i| (DeviceId::new(format!("{i:03}")).unwrap(), 1))
        .collect();
    r.state = StateVector::from_pairs(many).unwrap();
    let text = encode(&r);
    assert!(decode(&text).is_ok(), "256 devices");
    let body = body_of(&text);
    let extra = body.replacen("state 303030:1", "state 2f:1,303030:1", 1);
    assert_eq!(
        decode(&resign(&extra)),
        Err(RecordError::Corrupted),
        "257 devices"
    );

    let mut r = full();
    r.peers.clear();
    r.pending.clear();
    for i in 0..32u8 {
        r.peers
            .insert(PeerId([i + 10; 32]), PeerSyncState::default());
    }
    let text = encode(&r);
    assert!(decode(&text).is_ok(), "32 peers");
    let body = body_of(&text);
    let extra = format!("{body}peer {} - - none unknown\n", "ff".repeat(32));
    assert_eq!(
        decode(&resign(&extra)),
        Err(RecordError::Corrupted),
        "33 peers"
    );

    let huge = format!("passwsync-sync-record-v1\n{}", "x".repeat(1024 * 1024));
    assert_eq!(decode(&huge), Err(RecordError::Corrupted), "> 1 MiB");
}

#[test]
fn the_record_never_holds_secrets_by_construction() {
    // Only ids, digests, counters, local names and closed words: no field takes free text
    // except the (hex-encoded) local wallet name.
    let text = encode(&full());
    assert!(!text.contains("Personal wallet"), "the name is hex-encoded");
}
