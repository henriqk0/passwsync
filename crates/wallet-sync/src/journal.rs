//! Two-phase save journal (research R12, FR-023 to FR-025, SC-007): (1) the record gets
//! `prepared` (new digest, state, peer-mark updates, consumed pending copies); (2) the wallet
//! file is written atomically; (3) the record commits; (4) consumed pending files go. After a
//! crash at any point, [`recover`] makes the record describe the real file again.

use std::collections::{BTreeMap, BTreeSet};

use vault_core::{StateVector, WalletId};

use crate::ports::{PeerId, StoreError, SyncStore};
use crate::record::{FileCheck, Prepared, SyncRecord, sha256};

/// One journaled save.
pub struct SaveRequest<'a> {
    pub wallet: WalletId,
    /// Local file name of the wallet.
    pub name: &'a str,
    /// The encrypted bytes being written.
    pub bytes: &'a [u8],
    /// Their (authenticated) state vector.
    pub state: &'a StateVector,
    /// Peer marks raised by copies merged into these bytes.
    pub peer_marks: BTreeMap<PeerId, StateVector>,
    /// Pending copies merged into these bytes.
    pub consumed: BTreeSet<PeerId>,
}

/// Step 1.
pub fn prepare(record: &mut SyncRecord, request: &SaveRequest<'_>) {
    record.prepared = Some(Prepared {
        digest: sha256(request.bytes),
        state: request.state.clone(),
        peer_marks: request.peer_marks.clone(),
        consumed: request.consumed.clone(),
    });
}

/// Step 3: applies the prepared save; returns the pending copies to delete (step 4).
pub fn commit(record: &mut SyncRecord) -> BTreeSet<PeerId> {
    let Some(prepared) = record.prepared.take() else {
        return BTreeSet::new();
    };
    record.committed(prepared.digest, &prepared.state);
    for (peer, mark) in &prepared.peer_marks {
        record.raise_peer_mark(*peer, mark);
    }
    for peer in &prepared.consumed {
        record.pending.remove(peer);
    }
    prepared.consumed
}

/// What start-up recovery did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recovery {
    /// Nothing was in flight and the file matches.
    Clean,
    /// The prepared save had reached the file: committed (delete these pending files).
    Committed(BTreeSet<PeerId>),
    /// The prepared save never reached the file: dropped, the old state stands.
    Discarded,
    /// The file matches neither: changed outside the service (possible rollback).
    Flagged,
    /// No wallet file.
    Missing,
}

/// Start-up step 5c for one record, given the digest of the wallet file. Idempotent.
pub fn recover(record: &mut SyncRecord, file: Option<[u8; 32]>) -> Recovery {
    match record.check_file(file) {
        FileCheck::Missing => Recovery::Missing,
        FileCheck::Prepared => Recovery::Committed(commit(record)),
        FileCheck::Unchanged => {
            if record.prepared.take().is_some() {
                Recovery::Discarded
            } else {
                Recovery::Clean
            }
        }
        FileCheck::Changed => {
            record.prepared = None;
            Recovery::Flagged
        }
    }
}

/// Runs steps 1-4 around `write` (the atomic wallet-file write). `Err` means the wallet file
/// was not written (the record is as before). A failed commit still returns `Ok`: the file is
/// saved and the next start-up commits.
pub fn journaled_save(
    store: &dyn SyncStore,
    request: &SaveRequest<'_>,
    write: &mut dyn FnMut(&[u8]) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let wallet = request.wallet;
    store.update(&wallet, &mut |r| {
        let mut r = r.unwrap_or_else(|| {
            let mut fresh = SyncRecord::new(
                wallet,
                request.name.to_string(),
                [0; 32],
                StateVector::new(),
            );
            fresh.mark = StateVector::new();
            fresh
        });
        r.wallet_name = request.name.to_string();
        prepare(&mut r, request);
        Some(r)
    })?;
    if let Err(error) = write(request.bytes) {
        let _ = store.update(&wallet, &mut |r| {
            let mut r = r?;
            r.prepared = None;
            Some(r)
        });
        return Err(error);
    }
    let mut consumed = BTreeSet::new();
    let committed = store.update(&wallet, &mut |r| {
        let mut r = r?;
        consumed = commit(&mut r);
        Some(r)
    });
    if committed.is_ok() {
        for peer in &consumed {
            let _ = store.delete_pending(&wallet, peer);
        }
    }
    Ok(())
}
