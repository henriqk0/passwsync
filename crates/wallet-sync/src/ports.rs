//! Ports of the sync core (research R1). Adapters live in the host (`passwsyncd`); in-memory
//! fakes live in [`crate::testkit`].

use std::fmt;
use std::io::Read;
use std::time::Duration;

use vault_core::{StateVector, WalletId};

use crate::record::SyncRecord;

/// A paired device, by its 32-byte device id (003 `DeviceId`). Not secret.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Exactly 64 lowercase hex digits.
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        let mut out = [0u8; 32];
        for (slot, i) in out.iter_mut().zip((0..64).step_by(2)) {
            *slot = u8::from_str_radix(&text[i..i + 2], 16).ok()?;
        }
        Some(Self(out))
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", &self.to_hex()[..8])
    }
}

/// Coarse storage failures (never carry paths or contents).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    NotFound,
    /// A record exists but cannot be used (bad grammar, checksum, mode or owner).
    Corrupted,
    /// The disk is full.
    NoSpace,
    Io,
}

/// Records, pending copies and partial copies, per wallet id (owner-only files in the host).
pub trait SyncStore: Send + Sync {
    /// Wallet ids that have a record directory.
    fn wallets(&self) -> Result<Vec<WalletId>, StoreError>;
    fn load(&self, wallet: &WalletId) -> Result<Option<SyncRecord>, StoreError>;
    /// Atomic read-modify-write of one record: `f` gets the current record (`None` when
    /// missing) and returns the record to write (`None`: leave it as it is). Returns the
    /// record as stored afterwards.
    fn update(
        &self,
        wallet: &WalletId,
        f: &mut dyn FnMut(Option<SyncRecord>) -> Option<SyncRecord>,
    ) -> Result<Option<SyncRecord>, StoreError>;
    /// Starts receiving a copy into `incoming-<peer>.part`.
    fn begin_incoming(
        &self,
        wallet: &WalletId,
        peer: &PeerId,
    ) -> Result<Box<dyn IncomingCopy>, StoreError>;
    fn read_pending(&self, wallet: &WalletId, peer: &PeerId) -> Result<Vec<u8>, StoreError>;
    fn delete_pending(&self, wallet: &WalletId, peer: &PeerId) -> Result<(), StoreError>;
    /// Peers with a `pending-<peer>` file for `wallet`.
    fn pending_peers(&self, wallet: &WalletId) -> Result<Vec<PeerId>, StoreError>;
}

/// A copy being received. Dropped without `finish` = aborted.
pub trait IncomingCopy: Send {
    fn append(&mut self, bytes: &[u8]) -> Result<(), StoreError>;
    /// Makes the complete copy `pending-<peer>` atomically (replacing an older one).
    fn finish(self: Box<Self>) -> Result<(), StoreError>;
    /// Deletes the partial file.
    fn abort(self: Box<Self>);
}

/// The device's own stored wallet files (only these are ever offered, FR-006a).
pub trait WalletSource: Send + Sync {
    /// Size and a reader of the stored file `wallet_name`.
    fn open(&self, wallet_name: &str) -> Result<(u64, Box<dyn Read + Send>), StoreError>;
    /// SHA-256 of the stored file; `None` when it does not exist.
    fn digest(&self, wallet_name: &str) -> Result<Option<[u8; 32]>, StoreError>;
}

/// What the engine asks the host to merge: the pending copy of `peer`.
#[derive(Clone, PartialEq, Eq)]
pub struct MergeRequest {
    pub wallet: WalletId,
    pub wallet_name: String,
    pub peer: PeerId,
    /// The state claimed in the peer's `Summary`; must equal the authenticated one.
    pub claimed: StateVector,
    /// The authenticated copy's state must dominate this (FR-021a).
    pub peer_mark: Option<StateVector>,
}

impl fmt::Debug for MergeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MergeRequest")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

/// Result of a merge attempt (the host saves through the journal).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeOutcome {
    Merged {
        conflicts: u32,
        self_rollback: bool,
        password_adopted: bool,
    },
    /// The copy brought nothing new (pending deleted, peer mark raised).
    Unchanged,
    /// The wallet is locked: the copy stays pending.
    Locked,
    /// Another password or a corrupted copy.
    CannotOpen,
    /// Concurrent password changes: the person chooses.
    PasswordConflict,
    /// More than 16 versions for an entry.
    TooManyConflicts,
    /// Wrong wallet id, claimed state mismatch, below the peer mark or jump too large.
    Invalid,
    /// The merged wallet could not be saved (rolled back).
    StorageFailed,
}

pub trait Merger: Send + Sync {
    fn merge(&self, request: &MergeRequest) -> MergeOutcome;
}

/// 005: non-secret metadata of one received wallet file (no wallet name, id or state).
#[derive(Clone, PartialEq, Eq)]
pub struct ReceivedMeta {
    /// Random id, the file name stem; not secret but never sent and never shown by `Debug`.
    pub id: [u8; 16],
    pub sender: PeerId,
    /// Wall-clock receipt time (expiry after 24 h).
    pub received_at: u64,
    /// Ciphertext size in bytes.
    pub size: u64,
}

impl fmt::Debug for ReceivedMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceivedMeta")
            .field("sender", &self.sender)
            .field("received_at", &self.received_at)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

/// 005: received wallet files (ciphertext only, owner-only in the host). Start-up clean-up
/// is the host's job through `list` and `delete`.
pub trait ReceivedStore: Send + Sync {
    /// Complete entries, oldest first.
    fn list(&self) -> Result<Vec<ReceivedMeta>, StoreError>;
    /// Starts receiving into a partial file; `finish` writes the ciphertext then the meta
    /// atomically; dropping the writer without `finish` deletes the partial file.
    fn begin(
        &self,
        id: [u8; 16],
        sender: PeerId,
        received_at: u64,
    ) -> Result<Box<dyn IncomingCopy>, StoreError>;
    fn read(&self, id: [u8; 16]) -> Result<Vec<u8>, StoreError>;
    fn delete(&self, id: [u8; 16]) -> Result<(), StoreError>;
}

/// Monotonic time (stops while suspended is fine: it only drives timers).
pub trait MonoClock: Send + Sync {
    fn now(&self) -> Duration;
}

/// Unix seconds, for display only (never used for ordering or marks).
pub trait WallClock: Send + Sync {
    fn unix_now(&self) -> u64;
}
