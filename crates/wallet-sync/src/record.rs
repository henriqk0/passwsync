//! The per-wallet sync record (data-model.md "SyncRecord", contracts/host-runtime-sync.md
//! "Record format"): a strict line-based text file with a SHA-256 check line. It holds only
//! ids, digests, counters, closed words and the hex-encoded local wallet name.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use sha2::{Digest, Sha256};
use vault_core::{DeviceId, StateVector, WalletId};

use crate::ports::PeerId;

const HEADER: &str = "passwsync-sync-record-v1";
/// Records larger than this are corrupt.
pub const MAX_RECORD: usize = 1024 * 1024;
/// At most this many peers (the 003 pairing limit).
pub const MAX_PEERS: usize = 32;
/// Warnings kept per wallet.
pub const MAX_WARNINGS: usize = 64;

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Journal step 1 (research R12): what the next committed save will record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepared {
    pub digest: [u8; 32],
    pub state: StateVector,
    /// `peer_mark[p]` values raised by this save (authenticated copy states).
    pub peer_marks: BTreeMap<PeerId, StateVector>,
    /// Pending copies merged by this save, deleted once it is committed.
    pub consumed: BTreeSet<PeerId>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    /// Authenticated state below the high-water mark (FR-021).
    pub rollback_state: bool,
    /// The wallet file changed outside the service; cleared by an unlock (FR-012).
    pub rollback_digest: bool,
    /// A merge would exceed 16 versions per entry: resolve first (FR-031).
    pub too_many_conflicts: bool,
    /// Another wallet file has the same wallet id.
    pub duplicate_wallet_id: bool,
}

impl Flags {
    pub fn possible_rollback(&self) -> bool {
        self.rollback_state || self.rollback_digest
    }

    pub fn disabled(&self) -> bool {
        self.too_many_conflicts || self.duplicate_wallet_id
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Outcome {
    #[default]
    None,
    Ok,
    Failed,
    OlderStateOffered,
    InvalidCopy,
}

impl Outcome {
    pub fn word(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::OlderStateOffered => "older_state_offered",
            Self::InvalidCopy => "invalid_copy",
        }
    }

    fn parse(word: &str) -> Option<Self> {
        Some(match word {
            "none" => Self::None,
            "ok" => Self::Ok,
            "failed" => Self::Failed,
            "older_state_offered" => Self::OlderStateOffered,
            "invalid_copy" => Self::InvalidCopy,
            _ => return None,
        })
    }
}

/// Where a peer stands for one wallet (closed set shared with contracts/http-api-sync.md).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Position {
    InSync,
    Behind,
    Ahead,
    Diverged,
    #[default]
    Unknown,
    Offline,
    OlderStateOffered,
    Error,
}

impl Position {
    pub fn word(self) -> &'static str {
        match self {
            Self::InSync => "in_sync",
            Self::Behind => "behind",
            Self::Ahead => "ahead",
            Self::Diverged => "diverged",
            Self::Unknown => "unknown",
            Self::Offline => "offline",
            Self::OlderStateOffered => "older_state_offered",
            Self::Error => "error",
        }
    }

    fn parse(word: &str) -> Option<Self> {
        Some(match word {
            "in_sync" => Self::InSync,
            "behind" => Self::Behind,
            "ahead" => Self::Ahead,
            "diverged" => Self::Diverged,
            "unknown" => Self::Unknown,
            "offline" => Self::Offline,
            "older_state_offered" => Self::OlderStateOffered,
            "error" => Self::Error,
            _ => return None,
        })
    }
}

/// Per wallet x peer (data-model.md "PeerSyncState").
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerSyncState {
    /// Newest authenticated state received from that peer (FR-021a).
    pub peer_mark: Option<StateVector>,
    pub last_round_at: Option<u64>,
    pub last_outcome: Outcome,
    pub position: Position,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingStatus {
    Waiting,
    CannotOpen,
    PasswordConflict,
    TooManyConflicts,
}

impl PendingStatus {
    pub fn word(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::CannotOpen => "cannot_open",
            Self::PasswordConflict => "password_conflict",
            Self::TooManyConflicts => "too_many_conflicts",
        }
    }

    fn parse(word: &str) -> Option<Self> {
        Some(match word {
            "waiting" => Self::Waiting,
            "cannot_open" => Self::CannotOpen,
            "password_conflict" => Self::PasswordConflict,
            "too_many_conflicts" => Self::TooManyConflicts,
            _ => return None,
        })
    }
}

/// A received copy stored as ciphertext (`pending-<peer>`), at most one per peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingCopy {
    /// The state the peer claimed in its `Summary` (checked against the authenticated one).
    pub claimed: StateVector,
    pub size: u64,
    pub received_at: u64,
    pub status: PendingStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WarningKind {
    PossibleRollback,
    OlderStateOffered,
    InvalidCopy,
    CannotOpen,
    SelfRollbackRecovered,
    PasswordAdopted,
    RecordCorrupted,
    DuplicateWalletId,
}

impl WarningKind {
    pub fn word(self) -> &'static str {
        match self {
            Self::PossibleRollback => "possible_rollback",
            Self::OlderStateOffered => "older_state_offered",
            Self::InvalidCopy => "invalid_copy",
            Self::CannotOpen => "cannot_open",
            Self::SelfRollbackRecovered => "self_rollback_recovered",
            Self::PasswordAdopted => "password_adopted",
            Self::RecordCorrupted => "record_corrupted",
            Self::DuplicateWalletId => "duplicate_wallet_id",
        }
    }

    fn parse(word: &str) -> Option<Self> {
        Some(match word {
            "possible_rollback" => Self::PossibleRollback,
            "older_state_offered" => Self::OlderStateOffered,
            "invalid_copy" => Self::InvalidCopy,
            "cannot_open" => Self::CannotOpen,
            "self_rollback_recovered" => Self::SelfRollbackRecovered,
            "password_adopted" => Self::PasswordAdopted,
            "record_corrupted" => Self::RecordCorrupted,
            "duplicate_wallet_id" => Self::DuplicateWalletId,
            _ => return None,
        })
    }
}

/// Shown until dismissed; dismissal never changes marks or data (FR-036).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncWarning {
    pub id: u64,
    pub kind: WarningKind,
    pub peer: Option<PeerId>,
    pub at: u64,
}

/// One per wallet held (and unlocked once) on this device. Never sent anywhere.
#[derive(Clone, PartialEq, Eq)]
pub struct SyncRecord {
    pub wallet_id: WalletId,
    /// Local file name of the wallet.
    pub wallet_name: String,
    /// SHA-256 of the wallet file last saved or verified by this service.
    pub digest: [u8; 32],
    /// Authenticated state vector of that file.
    pub state: StateVector,
    pub prepared: Option<Prepared>,
    /// High-water mark: join of every committed state (FR-021).
    pub mark: StateVector,
    pub flags: Flags,
    pub peers: BTreeMap<PeerId, PeerSyncState>,
    pub pending: BTreeMap<PeerId, PendingCopy>,
    pub warnings: Vec<SyncWarning>,
}

/// Shows flags and counts only: never the wallet id, name, digest or vectors.
impl std::fmt::Debug for SyncRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncRecord")
            .field("flags", &self.flags)
            .field("peers", &self.peers.len())
            .field("pending", &self.pending.len())
            .field("warnings", &self.warnings.len())
            .finish_non_exhaustive()
    }
}

impl SyncRecord {
    /// A record describing an authenticated file: the mark starts at its state.
    pub fn new(
        wallet_id: WalletId,
        wallet_name: String,
        digest: [u8; 32],
        state: StateVector,
    ) -> Self {
        Self {
            wallet_id,
            wallet_name,
            digest,
            mark: state.clone(),
            state,
            prepared: None,
            flags: Flags::default(),
            peers: BTreeMap::new(),
            pending: BTreeMap::new(),
            warnings: Vec::new(),
        }
    }

    /// Adds a warning unless the same kind for the same peer is already shown; the oldest
    /// is dropped beyond 64.
    pub fn warn(&mut self, id: u64, kind: WarningKind, peer: Option<PeerId>, at: u64) {
        if self
            .warnings
            .iter()
            .any(|w| w.kind == kind && w.peer == peer)
        {
            return;
        }
        if self.warnings.len() >= MAX_WARNINGS {
            self.warnings.remove(0);
        }
        self.warnings.push(SyncWarning { id, kind, peer, at });
    }

    pub fn peer_mut(&mut self, peer: PeerId) -> &mut PeerSyncState {
        self.peers.entry(peer).or_default()
    }

    /// A save committed `state` as file `digest`: the mark joins it; a state below the old
    /// mark is flagged "possible rollback" until a later state reaches the mark (FR-021).
    pub fn committed(&mut self, digest: [u8; 32], state: &StateVector) {
        self.flags.rollback_state = !state.dominates(&self.mark);
        self.flags.rollback_digest = false;
        self.digest = digest;
        self.state = state.clone();
        self.mark = self.mark.join(state);
    }

    /// An unlock authenticated file `digest` with `state`: the digest flag clears; the state
    /// flag follows the mark (FR-012, FR-021).
    pub fn authenticated(&mut self, digest: [u8; 32], state: &StateVector) {
        self.committed(digest, state);
    }

    /// Compares the wallet file's digest with the record (at start-up and before rounds).
    pub fn check_file(&mut self, digest: Option<[u8; 32]>) -> FileCheck {
        let Some(digest) = digest else {
            return FileCheck::Missing;
        };
        if digest == self.digest {
            return FileCheck::Unchanged;
        }
        if self.prepared.as_ref().is_some_and(|p| p.digest == digest) {
            return FileCheck::Prepared;
        }
        self.flags.rollback_digest = true;
        FileCheck::Changed
    }

    /// The newest authenticated state received from `peer` (never lowered, FR-021a).
    pub fn raise_peer_mark(&mut self, peer: PeerId, state: &StateVector) {
        let slot = &mut self.peer_mut(peer).peer_mark;
        *slot = Some(match slot.take() {
            Some(mark) => mark.join(state),
            None => state.clone(),
        });
    }
}

/// What a check of the wallet file against its record found (research R10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileCheck {
    /// The file is the one the record describes.
    Unchanged,
    /// The file is the one a prepared (not yet committed) save wrote.
    Prepared,
    /// The file changed outside the service: flagged until an unlock authenticates it.
    Changed,
    /// No wallet file.
    Missing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// Unknown line, bad value, limit exceeded or checksum mismatch: sync is disabled for
    /// the wallet until the person resets it (never reset silently, FR-025).
    Corrupted,
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

fn unhex_n<const N: usize>(text: &str) -> Option<[u8; N]> {
    unhex(text)?.try_into().ok()
}

/// `-` or `<device-id hex>:<counter>,...` sorted by device id.
pub fn sv_text(state: &StateVector) -> String {
    if state.is_empty() {
        return "-".into();
    }
    state
        .iter()
        .map(|(d, c)| format!("{}:{c}", hex(d.as_str().as_bytes())))
        .collect::<Vec<_>>()
        .join(",")
}

pub fn parse_sv(text: &str) -> Option<StateVector> {
    if text == "-" {
        return Some(StateVector::new());
    }
    let mut pairs = Vec::new();
    for item in text.split(',') {
        let (id, counter) = item.split_once(':')?;
        let id = String::from_utf8(unhex(id)?).ok()?;
        if counter.is_empty()
            || !counter.bytes().all(|b| b.is_ascii_digit())
            || counter.starts_with('0')
        {
            return None;
        }
        pairs.push((DeviceId::new(id).ok()?, counter.parse::<u64>().ok()?));
        if pairs.len() > StateVector::MAX_DEVICES {
            return None;
        }
    }
    StateVector::from_pairs(pairs).ok()
}

fn parse_u64(text: &str) -> Option<u64> {
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    text.parse().ok()
}

fn opt_u64(text: &str) -> Option<Option<u64>> {
    if text == "-" {
        Some(None)
    } else {
        parse_u64(text).map(Some)
    }
}

fn peer(text: &str) -> Option<PeerId> {
    unhex_n::<32>(text).map(PeerId)
}

pub fn encode(record: &SyncRecord) -> String {
    let mut s = String::with_capacity(512);
    let _ = writeln!(s, "{HEADER}");
    let _ = writeln!(s, "wallet_id {}", hex(record.wallet_id.as_bytes()));
    let _ = writeln!(s, "wallet_name {}", hex(record.wallet_name.as_bytes()));
    let _ = writeln!(s, "digest {}", hex(&record.digest));
    let _ = writeln!(s, "state {}", sv_text(&record.state));
    match &record.prepared {
        None => s.push_str("prepared -\n"),
        Some(p) => {
            let updates = if p.peer_marks.is_empty() {
                "-".to_string()
            } else {
                p.peer_marks
                    .iter()
                    .map(|(peer, sv)| format!("{}={}", peer.to_hex(), sv_text(sv)))
                    .collect::<Vec<_>>()
                    .join(";")
            };
            let consumed = if p.consumed.is_empty() {
                "-".to_string()
            } else {
                p.consumed
                    .iter()
                    .map(PeerId::to_hex)
                    .collect::<Vec<_>>()
                    .join(",")
            };
            let _ = writeln!(
                s,
                "prepared {} {} {updates} {consumed}",
                hex(&p.digest),
                sv_text(&p.state)
            );
        }
    }
    let _ = writeln!(s, "mark {}", sv_text(&record.mark));
    let f = record.flags;
    let flags: Vec<&str> = [
        (f.rollback_state, "rollback_state"),
        (f.rollback_digest, "rollback_digest"),
        (f.too_many_conflicts, "too_many_conflicts"),
        (f.duplicate_wallet_id, "duplicate_wallet_id"),
    ]
    .into_iter()
    .filter_map(|(on, word)| on.then_some(word))
    .collect();
    let _ = writeln!(
        s,
        "flags {}",
        if flags.is_empty() {
            "-".to_string()
        } else {
            flags.join(",")
        }
    );
    for (id, p) in &record.peers {
        let _ = writeln!(
            s,
            "peer {} {} {} {} {}",
            id.to_hex(),
            p.peer_mark.as_ref().map_or("-".to_string(), sv_text),
            p.last_round_at.map_or("-".to_string(), |t| t.to_string()),
            p.last_outcome.word(),
            p.position.word()
        );
    }
    for (id, p) in &record.pending {
        let _ = writeln!(
            s,
            "pending {} {} {} {} {}",
            id.to_hex(),
            sv_text(&p.claimed),
            p.size,
            p.received_at,
            p.status.word()
        );
    }
    for w in &record.warnings {
        let _ = writeln!(
            s,
            "warning {} {} {} {}",
            w.id,
            w.kind.word(),
            w.peer.map_or("-".to_string(), |p| p.to_hex()),
            w.at
        );
    }
    let check = hex(&sha256(s.as_bytes()));
    let _ = writeln!(s, "check {check}");
    s
}

fn parse_prepared(fields: &[&str]) -> Option<Option<Prepared>> {
    match fields {
        ["-"] => Some(None),
        [digest, state, updates, consumed] => {
            let mut peer_marks = BTreeMap::new();
            if *updates != "-" {
                for item in updates.split(';') {
                    let (p, sv) = item.split_once('=')?;
                    if peer_marks.insert(peer(p)?, parse_sv(sv)?).is_some() {
                        return None;
                    }
                }
            }
            let mut consumed_set = BTreeSet::new();
            if *consumed != "-" {
                for p in consumed.split(',') {
                    if !consumed_set.insert(peer(p)?) {
                        return None;
                    }
                }
            }
            if peer_marks.len() > MAX_PEERS || consumed_set.len() > MAX_PEERS {
                return None;
            }
            Some(Some(Prepared {
                digest: unhex_n::<32>(digest)?,
                state: parse_sv(state)?,
                peer_marks,
                consumed: consumed_set,
            }))
        }
        _ => None,
    }
}

fn parse_flags(text: &str) -> Option<Flags> {
    let mut flags = Flags::default();
    if text == "-" {
        return Some(flags);
    }
    for word in text.split(',') {
        let slot = match word {
            "rollback_state" => &mut flags.rollback_state,
            "rollback_digest" => &mut flags.rollback_digest,
            "too_many_conflicts" => &mut flags.too_many_conflicts,
            "duplicate_wallet_id" => &mut flags.duplicate_wallet_id,
            _ => return None,
        };
        if *slot {
            return None;
        }
        *slot = true;
    }
    Some(flags)
}

/// Strict decoding; any deviation from the grammar is `Corrupted`.
pub fn decode(text: &str) -> Result<SyncRecord, RecordError> {
    decode_inner(text).ok_or(RecordError::Corrupted)
}

fn decode_inner(text: &str) -> Option<SyncRecord> {
    if text.len() > MAX_RECORD || !text.ends_with('\n') {
        return None;
    }
    let body_end = text[..text.len() - 1].rfind('\n')? + 1;
    let (body, check_line) = text.split_at(body_end);
    let check = check_line.strip_suffix('\n')?.strip_prefix("check ")?;
    if check != hex(&sha256(body.as_bytes())) {
        return None;
    }
    let mut lines = body.lines();
    if lines.next()? != HEADER {
        return None;
    }
    let mut field = |name: &str| -> Option<String> {
        let line = lines.next()?;
        let value = line.strip_prefix(name)?.strip_prefix(' ')?;
        (!value.is_empty() && !value.contains(' ') || name == "prepared").then(|| value.to_string())
    };
    let wallet_id = WalletId::from_bytes(unhex_n::<16>(&field("wallet_id")?)?);
    let name_hex = field("wallet_name")?;
    let wallet_name = String::from_utf8(unhex(&name_hex)?).ok()?;
    if wallet_name.is_empty() {
        return None;
    }
    let digest = unhex_n::<32>(&field("digest")?)?;
    let state = parse_sv(&field("state")?)?;
    let prepared_text = field("prepared")?;
    let prepared = parse_prepared(&prepared_text.split(' ').collect::<Vec<_>>())?;
    let mark = parse_sv(&field("mark")?)?;
    let flags = parse_flags(&field("flags")?)?;
    let mut record = SyncRecord {
        wallet_id,
        wallet_name,
        digest,
        state,
        prepared,
        mark,
        flags,
        peers: BTreeMap::new(),
        pending: BTreeMap::new(),
        warnings: Vec::new(),
    };
    // Repeated sections in fixed order: peers, pending, warnings.
    let mut section = 0;
    for line in lines {
        let parts: Vec<&str> = line.split(' ').collect();
        match parts.as_slice() {
            ["peer", id, mark, last, outcome, position] if section <= 0 => {
                let state = PeerSyncState {
                    peer_mark: if *mark == "-" {
                        None
                    } else {
                        Some(parse_sv(mark)?)
                    },
                    last_round_at: opt_u64(last)?,
                    last_outcome: Outcome::parse(outcome)?,
                    position: Position::parse(position)?,
                };
                let id = peer(id)?;
                if record
                    .peers
                    .keys()
                    .next_back()
                    .is_some_and(|last| *last >= id)
                    || record.peers.len() >= MAX_PEERS
                {
                    return None;
                }
                record.peers.insert(id, state);
            }
            ["pending", id, claimed, size, at, status] if section <= 1 => {
                section = 1;
                let id = peer(id)?;
                if record
                    .pending
                    .keys()
                    .next_back()
                    .is_some_and(|last| *last >= id)
                    || record.pending.len() >= MAX_PEERS
                {
                    return None;
                }
                record.pending.insert(
                    id,
                    PendingCopy {
                        claimed: parse_sv(claimed)?,
                        size: parse_u64(size)?,
                        received_at: parse_u64(at)?,
                        status: PendingStatus::parse(status)?,
                    },
                );
            }
            ["warning", id, kind, p, at] => {
                section = 2;
                if record.warnings.len() >= MAX_WARNINGS {
                    return None;
                }
                record.warnings.push(SyncWarning {
                    id: parse_u64(id)?,
                    kind: WarningKind::parse(kind)?,
                    peer: if *p == "-" { None } else { Some(peer(p)?) },
                    at: parse_u64(at)?,
                });
            }
            _ => return None,
        }
    }
    Some(record)
}
