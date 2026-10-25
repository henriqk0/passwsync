//! Deterministic merge of wallet copies (004, research R5 and R6): per entry, the union of
//! all versions minus duplicates and dominated versions (a lattice join), the state vector
//! joined component-wise, and the password-change epoch compared like a version vector.

use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::entry::{MAX_VERSIONS, canonical_order};
use crate::{
    Entry, EntryId, KdfConfig, OpenedCopy, StateVector, Timestamp, Vault, VaultError, VaultKey,
    VaultStorage, Version, VersionOrdering, VersionVector,
};

/// A received state may exceed the local one by at most this much per device (R4, R11).
pub const JUMP_BOUND: u64 = 1 << 32;

/// What a merge did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Anything changed (entries, state, epoch or key).
    pub changed: bool,
    /// Entries conflicted now that were not before.
    pub conflicts_added: u32,
    /// Entries no longer conflicted (a dominating version arrived, FR-017).
    pub conflicts_cleared: u32,
    /// The merging device recorded a "merge change" (counter reuse detected, R5).
    pub merge_change: bool,
    /// The copy's newer password (KDF parameters, salt, key) was adopted (FR-022).
    pub password_adopted: bool,
    /// The copy knew changes of this device that this device had lost (R10).
    pub self_rollback_recovered: bool,
}

/// Why a merge was refused. On every error the vault is exactly as before.
#[derive(Debug)]
pub enum MergeError {
    /// The authenticated wallet id differs.
    WalletMismatch,
    /// An entry would have more than 16 versions; resolve conflicts first.
    TooManyConflicts,
    /// Both sides changed the master password concurrently; the person chooses.
    PasswordConflict,
    /// A state component exceeds the local one by more than 2^32.
    JumpTooLarge,
    /// The merged state would name more than 256 devices.
    TooManyDevices,
    /// The merged result could not be sealed or saved (rolled back).
    Save(VaultError),
}

impl fmt::Display for MergeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WalletMismatch => "the copy belongs to another wallet",
            Self::TooManyConflicts => "too many conflicts, resolve first",
            Self::PasswordConflict => "the master password was changed on two devices",
            Self::JumpTooLarge => "the copy claims an implausible number of changes",
            Self::TooManyDevices => "a wallet may be changed by at most 256 devices",
            Self::Save(_) => "the merged wallet could not be saved",
        })
    }
}

impl std::error::Error for MergeError {}

/// How the person resolves a conflict (FR-016); indices address `[current, conflicts...]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Keep one version.
    Keep(usize),
    /// Keep the current version; every other live version becomes a new credential.
    KeepBoth,
}

/// Which password a merge of concurrent password changes keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordChoice {
    Local,
    Copy,
}

#[derive(Clone, Copy)]
enum Source {
    Local(usize),
    Copy(usize),
}

/// Entry changes computed before anything is touched.
#[derive(Default)]
struct Plan {
    replace: Vec<(usize, Entry)>,
    append: Vec<Entry>,
    differs_from_copy: bool,
    conflicts_added: u32,
    conflicts_cleared: u32,
}

/// What a committed merge replaced, so a failed save can put it back exactly.
pub(crate) struct Undo {
    replaced: Vec<(usize, Entry)>,
    appended: usize,
    created_at: Timestamp,
    state: StateVector,
    epoch: VersionVector,
    key: Option<(KdfConfig, [u8; 32], VaultKey)>,
}

fn same_set(a: &[[u8; 32]], b: &[[u8; 32]]) -> bool {
    a.len() == b.len() && a.iter().all(|h| b.contains(h))
}

/// Merges one entry's versions; `None` when the local entry stays as it is.
fn merge_entry(local: &Entry, copy: Entry, plan: &mut Plan) -> Result<Option<Entry>, MergeError> {
    let created: Timestamp = local.created_at().min(copy.created_at());
    let local_hashes: Vec<[u8; 32]> = local.versions().iter().map(Version::content_hash).collect();
    let mut copy_versions: Vec<Option<Version>> =
        copy.into_versions().into_iter().map(Some).collect();
    let copy_hashes: Vec<[u8; 32]> = copy_versions
        .iter()
        .map(|v| v.as_ref().map_or([0; 32], Version::content_hash))
        .collect();
    // Union without duplicates (same content hash = same version).
    let mut candidates: Vec<(Source, [u8; 32])> =
        Vec::with_capacity(local_hashes.len() + copy_hashes.len());
    let mut seen = HashSet::new();
    for (i, h) in local_hashes.iter().enumerate() {
        if seen.insert(*h) {
            candidates.push((Source::Local(i), *h));
        }
    }
    for (i, h) in copy_hashes.iter().enumerate() {
        if seen.insert(*h) {
            candidates.push((Source::Copy(i), *h));
        }
    }
    let vector = |source: Source| -> &VersionVector {
        match source {
            Source::Local(i) => local.versions()[i].version(),
            Source::Copy(i) => copy_versions[i]
                .as_ref()
                .map(Version::version)
                .unwrap_or_else(|| unreachable!()),
        }
    };
    // Keep the maximal versions: drop every version strictly older than another.
    let survivors: Vec<(Source, [u8; 32])> = candidates
        .iter()
        .filter(|(source, _)| {
            !candidates
                .iter()
                .any(|(other, _)| vector(*other).compare(vector(*source)) == VersionOrdering::Newer)
        })
        .copied()
        .collect();
    if survivors.len() > MAX_VERSIONS {
        return Err(MergeError::TooManyConflicts);
    }
    let survivor_hashes: Vec<[u8; 32]> = survivors.iter().map(|(_, h)| *h).collect();
    if !same_set(&survivor_hashes, &copy_hashes) {
        plan.differs_from_copy = true;
    }
    if same_set(&survivor_hashes, &local_hashes) && created == local.created_at() {
        return Ok(None);
    }
    let mut versions: Vec<(Version, [u8; 32])> = survivors
        .into_iter()
        .map(|(source, h)| match source {
            Source::Local(i) => (local.versions()[i].duplicate(), h),
            Source::Copy(i) => (copy_versions[i].take().unwrap_or_else(|| unreachable!()), h),
        })
        .collect();
    versions.sort_by(|a, b| canonical_order((&a.0, &a.1), (&b.0, &b.1)));
    let merged = Entry::from_checked(
        local.id(),
        created,
        versions.into_iter().map(|(v, _)| v).collect(),
    );
    match (local.is_conflicted(), merged.is_conflicted()) {
        (false, true) => plan.conflicts_added += 1,
        (true, false) => plan.conflicts_cleared += 1,
        _ => {}
    }
    Ok(Some(merged))
}

fn plan_entries(local: &[Entry], copy: Vec<Entry>) -> Result<Plan, MergeError> {
    let index: HashMap<EntryId, usize> =
        local.iter().enumerate().map(|(i, e)| (e.id(), i)).collect();
    let mut plan = Plan::default();
    let mut in_copy = HashSet::with_capacity(copy.len());
    for entry in copy {
        in_copy.insert(entry.id());
        match index.get(&entry.id()) {
            None => {
                if entry.is_conflicted() {
                    plan.conflicts_added += 1;
                }
                plan.append.push(entry);
            }
            Some(&i) => {
                if let Some(merged) = merge_entry(&local[i], entry, &mut plan)? {
                    plan.replace.push((i, merged));
                }
            }
        }
    }
    if local.iter().any(|e| !in_copy.contains(&e.id())) {
        plan.differs_from_copy = true;
    }
    Ok(plan)
}

impl Vault {
    /// Merges an authenticated copy (research R5, R6). Deterministic, commutative,
    /// associative and idempotent over entries and state. On error nothing changes.
    pub fn merge(&mut self, copy: OpenedCopy) -> Result<MergeReport, MergeError> {
        self.merge_inner(copy, None).map(|(report, _undo)| report)
    }

    /// Merges a copy whose password change is concurrent with ours, keeping `keep`'s key;
    /// the epoch becomes `join + increment(me)` and the merge counts as a change by this
    /// device (FR-022).
    pub fn merge_choosing_password(
        &mut self,
        copy: OpenedCopy,
        keep: PasswordChoice,
    ) -> Result<MergeReport, MergeError> {
        self.merge_inner(copy, Some(keep))
            .map(|(report, _undo)| report)
    }

    /// [`merge`](Self::merge) then save; on a save failure the vault is exactly as before
    /// (002 save-or-rollback rule).
    pub fn merge_saved(
        &mut self,
        copy: OpenedCopy,
        storage: &mut dyn VaultStorage,
    ) -> Result<MergeReport, MergeError> {
        self.merge_then_save(copy, None, storage)
    }

    /// [`merge_choosing_password`](Self::merge_choosing_password) then save, with rollback.
    pub fn merge_choosing_password_saved(
        &mut self,
        copy: OpenedCopy,
        keep: PasswordChoice,
        storage: &mut dyn VaultStorage,
    ) -> Result<MergeReport, MergeError> {
        self.merge_then_save(copy, Some(keep), storage)
    }

    fn merge_then_save(
        &mut self,
        copy: OpenedCopy,
        choice: Option<PasswordChoice>,
        storage: &mut dyn VaultStorage,
    ) -> Result<MergeReport, MergeError> {
        let (report, undo) = self.merge_inner(copy, choice)?;
        if !report.changed {
            return Ok(report);
        }
        if let Err(error) = self.save(storage) {
            self.undo(undo);
            return Err(MergeError::Save(error));
        }
        Ok(report)
    }

    fn merge_inner(
        &mut self,
        copy: OpenedCopy,
        choice: Option<PasswordChoice>,
    ) -> Result<(MergeReport, Undo), MergeError> {
        let OpenedCopy {
            wallet_id,
            created_at: copy_created,
            state: copy_state,
            password_epoch: copy_epoch,
            entries: copy_entries,
            kdf: copy_kdf,
            salt: copy_salt,
            key: copy_key,
        } = copy;
        if wallet_id != self.wallet_id {
            return Err(MergeError::WalletMismatch);
        }
        let (adopt, epoch, password_change) =
            match (choice, copy_epoch.compare(&self.password_epoch)) {
                (None, VersionOrdering::Equal | VersionOrdering::Older) => {
                    (false, self.password_epoch.clone(), false)
                }
                (None, VersionOrdering::Newer) => (true, copy_epoch.clone(), false),
                (None, VersionOrdering::Concurrent) => return Err(MergeError::PasswordConflict),
                (Some(keep), _) => {
                    let mut joined = self.password_epoch.join(&copy_epoch);
                    joined.increment(&self.device);
                    (keep == PasswordChoice::Copy, joined, true)
                }
            };
        if copy_state
            .iter()
            .any(|(device, counter)| counter > self.state.get(device).saturating_add(JUMP_BOUND))
        {
            return Err(MergeError::JumpTooLarge);
        }
        let self_rollback = copy_state.get(&self.device) > self.state.get(&self.device);
        let plan = plan_entries(&self.entries, copy_entries)?;
        let mut state = self.state.join(&copy_state);
        if state.len() > StateVector::MAX_DEVICES {
            return Err(MergeError::TooManyDevices);
        }
        let differs_from_local = !plan.replace.is_empty() || !plan.append.is_empty();
        let merge_change = (state == self.state && differs_from_local)
            || (state == copy_state && plan.differs_from_copy);
        if merge_change || password_change {
            state
                .bump(&self.device)
                .map_err(|_| MergeError::TooManyDevices)?;
        }
        let created_at = self.created_at.min(copy_created);
        let changed = differs_from_local
            || created_at != self.created_at
            || state != self.state
            || adopt
            || epoch != self.password_epoch;
        let report = MergeReport {
            changed,
            conflicts_added: plan.conflicts_added,
            conflicts_cleared: plan.conflicts_cleared,
            merge_change,
            password_adopted: adopt,
            self_rollback_recovered: self_rollback,
        };
        // Commit: from here on nothing can fail.
        let mut replaced = Vec::with_capacity(plan.replace.len());
        for (i, entry) in plan.replace {
            replaced.push((i, std::mem::replace(&mut self.entries[i], entry)));
        }
        let appended = plan.append.len();
        self.entries.extend(plan.append);
        let undo = Undo {
            replaced,
            appended,
            created_at: std::mem::replace(&mut self.created_at, created_at),
            state: std::mem::replace(&mut self.state, state),
            epoch: std::mem::replace(&mut self.password_epoch, epoch),
            key: if adopt {
                let old_key = std::mem::replace(&mut self.key, copy_key);
                let old = (self.kdf, self.salt, old_key);
                self.kdf = copy_kdf;
                self.salt = copy_salt;
                Some(old)
            } else {
                None
            },
        };
        Ok((report, undo))
    }

    pub(crate) fn undo(&mut self, undo: Undo) {
        let keep = self.entries.len() - undo.appended;
        self.entries.truncate(keep);
        for (i, entry) in undo.replaced.into_iter().rev() {
            self.entries[i] = entry;
        }
        self.created_at = undo.created_at;
        self.state = undo.state;
        self.password_epoch = undo.epoch;
        if let Some((kdf, salt, key)) = undo.key {
            self.kdf = kdf;
            self.salt = salt;
            self.key = key;
        }
    }

    /// Resolves a conflict: the kept version gets `join(all versions) + increment(me)`, so it
    /// dominates every resolved version and clears the conflict wherever it arrives
    /// (FR-016, FR-017). `KeepBoth` returns the ids of the new credentials.
    pub fn resolve(&mut self, id: EntryId, how: Resolution) -> Result<Vec<EntryId>, VaultError> {
        self.resolve_inner(id, how).map(|(ids, _)| ids)
    }

    /// [`resolve`](Self::resolve) then save; on a save failure the vault is exactly as before.
    pub fn resolve_saved(
        &mut self,
        id: EntryId,
        how: Resolution,
        storage: &mut dyn VaultStorage,
    ) -> Result<Vec<EntryId>, VaultError> {
        let (ids, (index, previous, appended, state)) = self.resolve_inner(id, how)?;
        if let Err(error) = self.save(storage) {
            let keep = self.entries.len() - appended;
            self.entries.truncate(keep);
            self.entries[index] = previous;
            self.state = state;
            return Err(error);
        }
        Ok(ids)
    }

    #[allow(clippy::type_complexity)]
    fn resolve_inner(
        &mut self,
        id: EntryId,
        how: Resolution,
    ) -> Result<(Vec<EntryId>, (usize, Entry, usize, StateVector)), VaultError> {
        let index = self
            .entries
            .iter()
            .position(|e| e.id() == id)
            .ok_or(VaultError::EntryNotFound)?;
        let entry = &self.entries[index];
        if !entry.is_conflicted() {
            return Err(VaultError::NotConflicted);
        }
        let versions = entry.versions();
        let keep = match how {
            Resolution::Keep(i) => i,
            Resolution::KeepBoth => 0,
        };
        let kept = versions.get(keep).ok_or(VaultError::InvalidVersionIndex)?;
        let now = self.clock.now();
        let mut vector = versions
            .iter()
            .fold(VersionVector::empty(), |acc, v| acc.join(v.version()));
        vector.increment(&self.device);
        let current = match kept.fields() {
            Some(fields) => {
                Version::new_live(fields.duplicate(), now, self.device.clone(), vector)?
            }
            None => Version::new_deleted(
                kept.deleted_at().unwrap_or(now),
                now,
                self.device.clone(),
                vector,
            ),
        };
        let mut state = self.bumped_state()?;
        let mut extra = Vec::new();
        if how == Resolution::KeepBoth {
            for (i, version) in versions.iter().enumerate() {
                if i == keep {
                    continue;
                }
                if let Some(fields) = version.fields() {
                    state.bump(&self.device)?;
                    extra.push(Entry::new_live(fields.duplicate(), &self.device, now)?);
                }
            }
        }
        let resolved = Entry::from_checked(id, entry.created_at(), vec![current]);
        let ids: Vec<EntryId> = extra.iter().map(Entry::id).collect();
        let appended = extra.len();
        let previous = std::mem::replace(&mut self.entries[index], resolved);
        self.entries.extend(extra);
        let old_state = std::mem::replace(&mut self.state, state);
        Ok((ids, (index, previous, appended, old_state)))
    }

    /// Entries with concurrent versions, in list order (title, then id).
    pub fn conflicted(&self) -> Vec<&Entry> {
        let mut found: Vec<&Entry> = self.entries.iter().filter(|e| e.is_conflicted()).collect();
        found.sort_by_cached_key(|entry| {
            (entry.fields().map(|f| f.title.to_lowercase()), entry.id())
        });
        found
    }

    /// `[current, conflicts...]` of any entry (live or tombstone).
    pub fn versions(&self, id: EntryId) -> Option<&[Version]> {
        self.entries
            .iter()
            .find(|e| e.id() == id)
            .map(Entry::versions)
    }
}
