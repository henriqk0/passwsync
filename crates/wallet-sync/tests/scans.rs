//! 004 T133: static checks of the sync core: no unsafe code, no printing, and no `Debug`
//! output that shows wallet ids, state vectors, names or keys.

use std::fs;
use std::path::Path;

use vault_core::{DeviceId, StateVector, WalletId};
use wallet_sync::ports::{MergeRequest, PeerId};
use wallet_sync::record::{SyncRecord, encode};
use wallet_sync::round::SyncEvent;

fn sources() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let text = fs::read_to_string(entry.path()).unwrap();
        out.push((entry.path().display().to_string(), text));
    }
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
