//! 004 T133: static checks of the sync core: no unsafe code, no printing, and no `Debug`
//! output that shows wallet ids, state vectors, names or keys.

use std::fs;
use std::path::Path;

use vault_core::{DeviceId, StateVector, WalletId};
use wallet_sync::ports::{MergeRequest, PeerId};
use wallet_sync::record::{SyncRecord, encode};
use wallet_sync::round::SyncEvent;

/// Every source file under `src/`, including subdirectories (005 adds `src/share/`).
fn sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<(String, String)>) {
        for entry in fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                let text = fs::read_to_string(&path).unwrap();
                out.push((path.display().to_string(), text));
            }
        }
    }
    let mut out = Vec::new();
    walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    out
}

#[test]
fn no_unsafe_and_no_printing() {
    for (path, text) in sources() {
        for needle in ["unsafe ", "println!", "eprintln!", "dbg!", "print!("] {
            assert!(!text.contains(needle), "{needle} in {path}");
        }
    }
    let lib = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).unwrap();
    assert!(lib.contains("#![forbid(unsafe_code)]"));
}

#[test]
fn debug_output_shows_no_ids_states_or_names() {
    let wallet = WalletId::from_bytes([0xAB; 16]);
    let state =
        StateVector::from_pairs(vec![(DeviceId::new("DEVICE-MARKER").unwrap(), 4242)]).unwrap();
    let mut record = SyncRecord::new(wallet, "NAME-MARKER".into(), [0xCD; 32], state.clone());
    record.raise_peer_mark(PeerId([0xEF; 32]), &state);
    let request = MergeRequest {
        wallet,
        wallet_name: "NAME-MARKER".into(),
        peer: PeerId([0xEF; 32]),
        claimed: state.clone(),
        peer_mark: Some(state.clone()),
    };
    let event = SyncEvent::Merged {
        wallet,
        name: "NAME-MARKER".into(),
        peer: PeerId([0xEF; 32]),
        conflicts: 1,
    };
    for text in [
        format!("{record:?}"),
        format!("{request:?}"),
        format!("{event:?}"),
        format!("{state:?}"),
    ] {
        for needle in [
            "171, 171",
            "abab",
            "DEVICE-MARKER",
            "4242",
            "NAME-MARKER",
            "205, 205",
            "cdcd",
        ] {
            assert!(!text.contains(needle), "{needle} in {text}");
        }
    }
    // The record file itself never holds the name in clear either.
    assert!(!encode(&record).contains("NAME-MARKER"));
}

// --- 005 T087: share types never show codes, proofs, rids, received ids or wallet data ---

#[test]
fn share_debug_output_shows_no_secret() {
    use wallet_sync::ports::ReceivedMeta;
    use wallet_sync::share::codec::{AbortReason, ShareMsg};
    use wallet_sync::share::{InviteWallet, OutFrame, ShareEvent};

    let proof = [0xAB; 32];
    let rid = 0x1234_5678u32;
    let texts = [
        format!("{:?}", ShareMsg::Redeem { rid, proof }),
        format!(
            "{:?}",
            ShareMsg::Abort {
                rid,
                reason: AbortReason::Busy
            }
        ),
        format!("{:?}", OutFrame::Msg(ShareMsg::End { rid })),
        format!("{:?}", OutFrame::Data(b"CIPHER-MARKER".to_vec())),
        format!(
            "{:?}",
            ReceivedMeta {
                id: [0xCD; 16],
                sender: PeerId([1; 32]),
                received_at: 1,
                size: 2
            }
        ),
        format!(
            "{:?}",
            InviteWallet {
                name: "NAME-MARKER".into(),
                id: WalletId::from_bytes([0xAB; 16]),
                format: 2
            }
        ),
        format!(
            "{:?}",
            ShareEvent::Received {
                peer: PeerId([1; 32]),
                bytes: 3
            }
        ),
    ];
    for text in texts {
        for needle in [
            "171",
            "abab",
            "305419896",
            "12345678",
            "cdcd",
            "205",
            "NAME-MARKER",
            "CIPHER-MARKER",
        ] {
            assert!(!text.contains(needle), "{needle} in {text}");
        }
    }
}
