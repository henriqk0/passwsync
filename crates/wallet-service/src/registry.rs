//! The wallet registry: one slot per known wallet, locked or unlocked (data-model.md).
//! Lock order: create lock → one slot's attempt lock → KDF gate; the registry map and a
//! slot's state are only ever held briefly, never across a key derivation.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use subtle::ConstantTimeEq;
use vault_core::{
    Clock, DeviceId, EntryFields, EntryId, KdfConfig, MasterPassword, Timestamp, Vault,
    peek_kdf_config,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{ElapsedClock, ServiceError, WalletDirectory, WalletName};

const MIN_PASSWORD_CHARS: usize = 12;

/// Largest Argon2 memory a wallet may ask for: keeps one key derivation inside the
/// locked-memory budget (research R4).
pub const KDF_MEMORY_CAP_KIB: u32 = 131_072;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockOutcome {
    Unlocked,
    /// Nothing to do; the password was wiped unused and no KDF ran.
    AlreadyUnlocked,
}

/// Settings the service is built with.
#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub device: DeviceId,
    /// Cost for wallets created here (`KdfConfig::DEFAULT` in production).
    pub wallet_kdf: KdfConfig,
    pub auto_lock: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletStatus {
    pub name: WalletName,
    pub unlocked: bool,
}

/// A credential in a list: never the password or notes (FR-024).
#[derive(Debug)]
pub struct EntrySummary {
    pub id: EntryId,
    pub title: Zeroizing<String>,
    pub username: Zeroizing<String>,
    pub url: Zeroizing<String>,
    /// 004: the credential has concurrent versions (FR-035).
    pub conflicted: bool,
}

/// One credential's details, without the password.
pub struct EntryView {
    pub id: EntryId,
    pub title: Zeroizing<String>,
    pub username: Zeroizing<String>,
    pub url: Zeroizing<String>,
    pub notes: Zeroizing<String>,
    pub created_at: Timestamp,
    pub modified_at: Timestamp,
}

impl std::fmt::Debug for EntryView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryView")
            .field("id", &self.id)
            .field("title", &self.title.as_str())
            .field("notes", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// The one field that may be read back on its own (reveal / copy).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Password,
    Username,
}

impl Field {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "password" => Some(Self::Password),
            "username" => Some(Self::Username),
            _ => None,
        }
    }
}

pub(crate) fn copy(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

pub(crate) enum Slot {
    Locked,
    Unlocked {
        /// Boxed: a vault is much larger than the locked variant.
        vault: Box<Vault>,
        /// Monotonic time of the last deliberate action.
        last_activity: Duration,
    },
}

/// One wallet's state plus the lock that serializes its unlock attempts, so a key
/// derivation never holds the state lock that list and lock need.
pub(crate) struct WalletSlot {
    pub(crate) state: Mutex<Slot>,
    pub(crate) attempts: Mutex<()>,
}

impl WalletSlot {
    fn new(state: Slot) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(state),
            attempts: Mutex::new(()),
        })
    }
}

pub(crate) type SlotRef = Arc<WalletSlot>;

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Lets each vault own a clock while the service keeps sharing one.
struct SharedClock(Arc<dyn Clock>);

impl Clock for SharedClock {
    fn now(&self) -> Timestamp {
        self.0.now()
    }
}

/// Application use cases over the wallets in one directory. Shared across threads.
pub struct Service {
    pub(crate) dir: Arc<dyn WalletDirectory>,
    clock: Arc<dyn Clock>,
    pub(crate) elapsed: Arc<dyn ElapsedClock>,
    pub(crate) config: ServiceConfig,
    slots: Mutex<BTreeMap<WalletName, SlotRef>>,
    /// Serializes wallet creation (check name free → KDF → first save → register).
    create_lock: Mutex<()>,
    /// One key derivation or merge at a time, service-wide (memory budget, 004 T058).
    pub(crate) kdf_gate: Mutex<()>,
    kdf_active: Arc<AtomicUsize>,
    /// `boottime - monotonic` when a suspend was last accounted for.
    suspend_offset: Mutex<Duration>,
    /// 004: the host's pending-copy port (none: no sync).
    pub(crate) pending: Mutex<Option<Arc<dyn crate::PendingCopies>>>,
}

/// More time than this between the two clocks means the computer was suspended.
const SUSPEND_THRESHOLD: Duration = Duration::from_secs(5);

fn suspend_offset(elapsed: &dyn ElapsedClock) -> Duration {
    elapsed.boottime().saturating_sub(elapsed.monotonic())
}

impl Service {
    pub fn new(
        dir: Arc<dyn WalletDirectory>,
        clock: Arc<dyn Clock>,
        elapsed: Arc<dyn ElapsedClock>,
        config: ServiceConfig,
    ) -> Self {
        Self {
            suspend_offset: Mutex::new(suspend_offset(elapsed.as_ref())),
            dir,
            clock,
            elapsed,
            config,
            slots: Mutex::new(BTreeMap::new()),
            create_lock: Mutex::new(()),
            kdf_gate: Mutex::new(()),
            kdf_active: Arc::new(AtomicUsize::new(0)),
            pending: Mutex::new(None),
        }
    }

    /// 004: connects the sync layer (pending copies, unlock notification).
    pub fn set_pending_copies(&self, port: Arc<dyn crate::PendingCopies>) {
        *lock(&self.pending) = Some(port);
    }

    pub(crate) fn pending_port(&self) -> Option<Arc<dyn crate::PendingCopies>> {
        lock(&self.pending).clone()
    }

    pub fn config(&self) -> &ServiceConfig {
        &self.config
    }

    pub(crate) fn vault_clock(&self) -> Box<dyn Clock> {
        Box::new(SharedClock(Arc::clone(&self.clock)))
    }

    /// Wallets in the directory plus any unlocked wallet whose file has disappeared, sorted.
    /// Background: never counts as activity.
    pub fn list(&self) -> Result<Vec<WalletStatus>, ServiceError> {
        let mut names = self.dir.list()?;
        let mut unlocked = Vec::new();
        for (name, slot) in self.all_slots() {
            if matches!(*lock(&slot.state), Slot::Unlocked { .. }) {
                unlocked.push(name);
            }
        }
        names.extend(unlocked.iter().cloned());
        names.sort();
        names.dedup();
        Ok(names
            .into_iter()
            .map(|name| WalletStatus {
                unlocked: unlocked.contains(&name),
                name,
            })
            .collect())
    }

    /// Creates a wallet with a new master password and leaves it unlocked. Checks, in order:
    /// name, the two entries match, length, name not taken. Nothing is written on failure.
    pub fn create(
        &self,
        name: &str,
        password: Zeroizing<String>,
        confirm: Zeroizing<String>,
    ) -> Result<WalletName, ServiceError> {
        let name = WalletName::parse(name)?;
        if !bool::from(password.as_bytes().ct_eq(confirm.as_bytes())) {
            return Err(ServiceError::PasswordMismatch);
        }
        drop(confirm);
        if password.chars().count() < MIN_PASSWORD_CHARS {
            return Err(ServiceError::PasswordTooShort);
        }
        // Hold the create lock (not the registry map) across the check, the KDF and the
        // first save so two creations of the same name cannot race.
        let _creating = lock(&self.create_lock);
        let unlocked_here = lock(&self.slots)
            .get(&name)
            .cloned()
            .is_some_and(|slot| matches!(*lock(&slot.state), Slot::Unlocked { .. }));
        if unlocked_here || self.dir.exists(&name)? {
            return Err(ServiceError::WalletExists);
        }
        let vault = self.derive(|| {
            Vault::create(
                MasterPassword::new(take(password)),
                self.config.wallet_kdf,
                self.config.device.clone(),
                self.vault_clock(),
            )
        })?;
        vault.save(self.dir.storage(&name).as_mut())?;
        // Once saved the directory lists the wallet, so a locked slot may already exist.
        let slot = Arc::clone(
            lock(&self.slots)
                .entry(name.clone())
                .or_insert_with(|| WalletSlot::new(Slot::Locked)),
        );
        *lock(&slot.state) = Slot::Unlocked {
            vault: Box::new(vault),
            last_activity: self.elapsed.monotonic(),
        };
        Ok(name)
    }

    /// Runs one key derivation at a time, service-wide.
    pub(crate) fn derive<T>(
        &self,
        run: impl FnOnce() -> Result<T, vault_core::VaultError>,
    ) -> Result<T, ServiceError> {
        let _gate = lock(&self.kdf_gate);
        self.kdf_active.fetch_add(1, Ordering::SeqCst);
        let result = run();
        self.kdf_active.fetch_sub(1, Ordering::SeqCst);
        Ok(result?)
    }

    /// Holds the KDF gate, so key derivations wait as if a slow one were running. Test hook.
    #[cfg(feature = "testkit")]
    pub fn hold_kdf_gate(&self) -> MutexGuard<'_, ()> {
        lock(&self.kdf_gate)
    }

    /// Number of key derivations running right now (0 or 1). Test hook.
    #[cfg(feature = "testkit")]
    pub fn kdf_gate_probe(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.kdf_active)
    }

    /// Unlocks a wallet with its master password. Attempts on one wallet are serialized by
    /// its attempt lock; an already unlocked wallet returns at once without a KDF run.
    /// Wallets asking for more Argon2 memory than [`KDF_MEMORY_CAP_KIB`] are refused before
    /// the KDF. The state lock is not held during the derivation, so the list and other
    /// operations keep being served.
    pub fn unlock(
        &self,
        name: &WalletName,
        password: Zeroizing<String>,
    ) -> Result<UnlockOutcome, ServiceError> {
        let slot = self.slot(name)?;
        let _attempt = lock(&slot.attempts);
        if self.touch_if_unlocked(&slot) {
            return Ok(UnlockOutcome::AlreadyUnlocked);
        }
        let bytes = Zeroizing::new(self.dir.storage(name).load()?);
        if peek_kdf_config(&bytes)?.memory_kib > KDF_MEMORY_CAP_KIB {
            return Err(ServiceError::KdfParamsOutOfRange);
        }
        let mut vault = self.derive(|| {
            // A copy wiped on drop: the password is still needed for pending copies (004).
            Vault::unlock(
                &bytes,
                MasterPassword::new(password.as_str().to_owned()),
                self.config.device.clone(),
                self.vault_clock(),
            )
        })?;
        self.after_unlock(name, &bytes, &vault);
        self.merge_pending_at_unlock(name, &mut vault, &password);
        drop(password);
        *lock(&slot.state) = Slot::Unlocked {
            vault: Box::new(vault),
            last_activity: self.elapsed.monotonic(),
        };
        Ok(UnlockOutcome::Unlocked)
    }

    /// Records activity and returns true if the slot is unlocked.
    fn touch_if_unlocked(&self, slot: &WalletSlot) -> bool {
        match &mut *lock(&slot.state) {
            Slot::Unlocked { last_activity, .. } => {
                *last_activity = self.elapsed.monotonic();
                true
            }
            Slot::Locked => false,
        }
    }

    /// The slot for `name`, created (locked) if the directory lists the wallet.
    pub(crate) fn slot(&self, name: &WalletName) -> Result<SlotRef, ServiceError> {
        if let Some(slot) = lock(&self.slots).get(name) {
            return Ok(Arc::clone(slot));
        }
        if !self.dir.list()?.contains(name) {
            return Err(ServiceError::WalletNotFound);
        }
        let mut slots = lock(&self.slots);
        let slot = slots
            .entry(name.clone())
            .or_insert_with(|| WalletSlot::new(Slot::Locked));
        Ok(Arc::clone(slot))
    }

    /// Runs a deliberate action on an unlocked wallet and records the activity.
    pub(crate) fn with_unlocked<T>(
        &self,
        name: &WalletName,
        action: impl FnOnce(&mut Vault) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        let slot = self.slot(name)?;
        let mut state = lock(&slot.state);
        match &mut *state {
            Slot::Locked => Err(ServiceError::WalletLocked),
            Slot::Unlocked {
                vault,
                last_activity,
            } => {
                *last_activity = self.elapsed.monotonic();
                action(vault)
            }
        }
    }

    /// Adds a credential; the wallet is saved before this returns. On save failure nothing
    /// changes in memory or on disk.
    pub fn add_entry(
        &self,
        name: &WalletName,
        fields: EntryFields,
    ) -> Result<EntryId, ServiceError> {
        let mut storage = self.dir.storage(name);
        self.with_unlocked(name, |vault| {
            Ok(vault.add_entry_saved(fields, storage.as_mut())?)
        })
    }
}

impl Service {
    /// Case-insensitive search over title, username, URL and notes; an empty query lists
    /// everything. Order as vault-core (title, then id).
    pub fn search(
        &self,
        name: &WalletName,
        query: &str,
    ) -> Result<Vec<EntrySummary>, ServiceError> {
        self.with_unlocked(name, |vault| {
            Ok(vault
                .search(query)
                .into_iter()
                .filter_map(|entry| {
                    entry.fields().map(|f| EntrySummary {
                        id: entry.id(),
                        title: copy(&f.title),
                        username: copy(&f.username),
                        url: copy(&f.url),
                        conflicted: entry.is_conflicted(),
                    })
                })
                .collect())
        })
    }

    pub fn get_entry(&self, name: &WalletName, id: EntryId) -> Result<EntryView, ServiceError> {
        self.with_unlocked(name, |vault| {
            let entry = vault.get(id).ok_or(ServiceError::EntryNotFound)?;
            let f = entry.fields().ok_or(ServiceError::EntryNotFound)?;
            Ok(EntryView {
                id,
                title: copy(&f.title),
                username: copy(&f.username),
                url: copy(&f.url),
                notes: copy(&f.notes),
                created_at: entry.created_at(),
                modified_at: entry.modified_at(),
            })
        })
    }

    /// One credential's password or username: the only way a password leaves the service.
    pub fn field(
        &self,
        name: &WalletName,
        id: EntryId,
        field: Field,
    ) -> Result<Zeroizing<String>, ServiceError> {
        self.with_unlocked(name, |vault| {
            let fields = vault
                .get(id)
                .and_then(|entry| entry.fields())
                .ok_or(ServiceError::EntryNotFound)?;
            Ok(copy(match field {
                Field::Password => &fields.password,
                Field::Username => &fields.username,
            }))
        })
    }

    /// Whole-value replacement, saved before returning; rolled back exactly on save failure.
    pub fn update_entry(
        &self,
        name: &WalletName,
        id: EntryId,
        fields: EntryFields,
    ) -> Result<(), ServiceError> {
        let mut storage = self.dir.storage(name);
        self.with_unlocked(name, |vault| {
            Ok(vault.update_entry_saved(id, fields, storage.as_mut())?)
        })
    }

    /// As [`Self::update_entry`], but the stored password is kept: it is merged here, so an
    /// edit never needs the password to travel to the browser (FR-024). `fields.password`
    /// is ignored and wiped.
    pub fn update_entry_keeping_password(
        &self,
        name: &WalletName,
        id: EntryId,
        mut fields: EntryFields,
    ) -> Result<(), ServiceError> {
        let mut storage = self.dir.storage(name);
        self.with_unlocked(name, |vault| {
            let stored = vault
                .get(id)
                .and_then(|entry| entry.fields())
                .ok_or(ServiceError::EntryNotFound)?;
            fields.password.zeroize();
            fields.password.push_str(&stored.password);
            Ok(vault.update_entry_saved(id, fields, storage.as_mut())?)
        })
    }

    /// Locks one wallet (its key and entries are wiped). `Ok(false)` if it was already
    /// locked.
    pub fn lock(&self, name: &WalletName) -> Result<bool, ServiceError> {
        let slot = self.slot(name)?;
        Ok(Self::lock_slot(&slot))
    }

    fn lock_slot(slot: &WalletSlot) -> bool {
        let previous = std::mem::replace(&mut *lock(&slot.state), Slot::Locked);
        // Dropping the vault wipes it; done outside the match for clarity.
        let was_unlocked = matches!(previous, Slot::Unlocked { .. });
        if let Slot::Unlocked { vault, .. } = previous {
            vault.lock();
        }
        was_unlocked
    }

    fn all_slots(&self) -> Vec<(WalletName, SlotRef)> {
        lock(&self.slots)
            .iter()
            .map(|(name, slot)| (name.clone(), Arc::clone(slot)))
            .collect()
    }

    /// Locks every wallet; returns the names that were unlocked, sorted.
    pub fn lock_all(&self) -> Vec<WalletName> {
        self.all_slots()
            .into_iter()
            .filter(|(_, slot)| Self::lock_slot(slot))
            .map(|(name, _)| name)
            .collect()
    }

    /// Locks every wallet idle for at least the auto-lock time; returns their names.
    pub fn sweep(&self) -> Vec<WalletName> {
        let now = self.elapsed.monotonic();
        let mut locked = Vec::new();
        for (name, slot) in self.all_slots() {
            let mut guard = lock(&slot.state);
            let idle = match &*guard {
                Slot::Unlocked { last_activity, .. } => {
                    now.saturating_sub(*last_activity) >= self.config.auto_lock
                }
                Slot::Locked => false,
            };
            if idle {
                if let Slot::Unlocked { vault, .. } = std::mem::replace(&mut *guard, Slot::Locked) {
                    vault.lock();
                }
                locked.push(name);
            }
        }
        locked
    }

    /// If the computer was suspended (boot time ran more than 5 s ahead of monotonic time
    /// since the last detection), locks every wallet and returns the names locked.
    pub fn check_suspend(&self) -> Option<Vec<WalletName>> {
        let current = suspend_offset(self.elapsed.as_ref());
        {
            let mut offset = lock(&self.suspend_offset);
            if current.saturating_sub(*offset) <= SUSPEND_THRESHOLD {
                return None;
            }
            *offset = current;
        }
        Some(self.lock_all())
    }

    /// Deletes (tombstone), saved before returning; rolled back exactly on save failure.
    pub fn delete_entry(&self, name: &WalletName, id: EntryId) -> Result<(), ServiceError> {
        let mut storage = self.dir.storage(name);
        self.with_unlocked(name, |vault| {
            Ok(vault.delete_entry_saved(id, storage.as_mut())?)
        })
    }
}

/// Moves the string out of its `Zeroizing` wrapper without copying the bytes.
pub(crate) fn take(mut secret: Zeroizing<String>) -> String {
    std::mem::take(&mut *secret)
}
