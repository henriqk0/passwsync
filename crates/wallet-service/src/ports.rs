use std::time::Duration;

use vault_core::{StateVector, StorageError, VaultStorage, WalletId};

use crate::{CopyFacts, CopyVerdict, WalletName};

/// Port to the place where wallets live, one encrypted blob per name.
pub trait WalletDirectory: Send + Sync {
    /// Valid wallet names present, sorted by byte order.
    fn list(&self) -> Result<Vec<WalletName>, StorageError>;
    fn exists(&self, name: &WalletName) -> Result<bool, StorageError>;
    /// Storage bound to one wallet; it need not exist yet.
    fn storage(&self, name: &WalletName) -> Box<dyn VaultStorage + Send>;
}

/// Port to the elapsed-time clocks used for idle auto-lock and suspend detection.
pub trait ElapsedClock: Send + Sync {
    /// Time since an arbitrary start; stops while the computer is suspended.
    fn monotonic(&self) -> Duration;
    /// Time since boot; keeps counting while suspended.
    fn boottime(&self) -> Duration;
}

/// A paired device holding a pending copy (the 003 device id; opaque here).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerRef(pub [u8; 32]);

/// A received copy waiting for an unlock (004, research R13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRef {
    pub peer: PeerRef,
    /// The state the peer claimed; the authenticated one must equal it.
    pub claimed_state: StateVector,
    pub size: u64,
}

/// What became of a pending copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingOutcome {
    Merged {
        conflicts: u32,
        self_rollback: bool,
        password_adopted: bool,
    },
    /// Nothing new in it.
    Unchanged,
    /// Another master password, or corrupted: stays pending (FR-008).
    CannotOpen,
    /// Concurrent password changes: stays pending until the person chooses (FR-022).
    PasswordConflict,
    /// Would exceed 16 versions per entry: stays pending (FR-031).
    TooManyConflicts,
    /// Failed the sync checks: deleted with a warning.
    Invalid,
}

/// What an unlock tells the sync layer: the authenticated facts of the file just opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnlockFacts {
    pub wallet_id: WalletId,
    pub state: StateVector,
    /// Format version of the file (1 or 2).
    pub format_version: u16,
}

/// Port to the received copies of a wallet (implemented by the host, 004
/// contracts/vault-core-sync-api.md), plus the unlock notification that lets the host
/// authenticate its sync record and decide the v1 -> v2 rewrite (research R3).
pub trait PendingCopies: Send + Sync {
    fn list(&self, wallet: &WalletName) -> Vec<PendingRef>;
    fn load(&self, wallet: &WalletName, peer: &PeerRef) -> Result<Vec<u8>, StorageError>;
    /// The sync checks (requested wallet id, claimed state, peer mark, jump bound).
    fn check(&self, wallet: &WalletName, peer: &PeerRef, facts: &CopyFacts) -> CopyVerdict;
    fn outcome(&self, wallet: &WalletName, peer: &PeerRef, outcome: PendingOutcome);
    /// A wallet was unlocked from `file` (before pending copies are merged). Returns whether
    /// a version 1 file should be rewritten as version 2 now.
    fn unlocked(&self, wallet: &WalletName, file: &[u8], facts: &UnlockFacts) -> bool;
    /// The version 1 file was rewritten as version 2.
    fn upgraded(&self, wallet: &WalletName);
}

/// 005: told about every lock (manual, all, idle, suspend, stop), after the wallet is locked
/// and its keys wiped, outside the service's locks (research R7).
pub trait LockObserver: Send + Sync {
    fn locked(&self, name: &WalletName);
}

#[cfg(feature = "testkit")]
pub mod testkit {
    //! In-memory fakes of the ports. Enabled by the `testkit` feature.

    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::Duration;

    use vault_core::{StorageError, VaultStorage};

    use super::{ElapsedClock, WalletDirectory};
    use crate::WalletName;

    type Files = Arc<Mutex<BTreeMap<WalletName, Vec<u8>>>>;

    /// Wallet directory held in memory. Clones share the same files.
    #[derive(Clone, Default)]
    pub struct MemoryWalletDirectory {
        files: Files,
        failing: Arc<AtomicBool>,
    }

    impl MemoryWalletDirectory {
        pub fn new() -> Self {
            Self::default()
        }

        /// Puts raw bytes in place, as if a file were copied in.
        pub fn insert(&self, name: &WalletName, bytes: &[u8]) {
            lock(&self.files).insert(name.clone(), bytes.to_vec());
        }

        pub fn remove(&self, name: &WalletName) {
            lock(&self.files).remove(name);
        }

        pub fn bytes(&self, name: &WalletName) -> Option<Vec<u8>> {
            lock(&self.files).get(name).cloned()
        }

        /// While set, every save fails with an I/O error and leaves the bytes unchanged.
        pub fn set_failing(&self, failing: bool) {
            self.failing.store(failing, Ordering::SeqCst);
        }
    }

    impl WalletDirectory for MemoryWalletDirectory {
        fn list(&self) -> Result<Vec<WalletName>, StorageError> {
            Ok(lock(&self.files).keys().cloned().collect())
        }

        fn exists(&self, name: &WalletName) -> Result<bool, StorageError> {
            Ok(lock(&self.files).contains_key(name))
        }

        fn storage(&self, name: &WalletName) -> Box<dyn VaultStorage + Send> {
            Box::new(MemoryWalletStorage {
                files: Arc::clone(&self.files),
                failing: Arc::clone(&self.failing),
                name: name.clone(),
            })
        }
    }

    struct MemoryWalletStorage {
        files: Files,
        failing: Arc<AtomicBool>,
        name: WalletName,
    }

    impl VaultStorage for MemoryWalletStorage {
        fn load(&self) -> Result<Vec<u8>, StorageError> {
            lock(&self.files)
                .get(&self.name)
                .cloned()
                .ok_or(StorageError::NotFound)
        }

        fn store(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
            if self.failing.load(Ordering::SeqCst) {
                return Err(StorageError::Io(std::io::Error::other(
                    "injected save failure",
                )));
            }
            lock(&self.files).insert(self.name.clone(), bytes.to_vec());
            Ok(())
        }
    }

    /// Settable clocks: `advance` moves both, `suspend` moves only boot time.
    #[derive(Default)]
    pub struct FakeElapsedClock(Mutex<(Duration, Duration)>);

    impl FakeElapsedClock {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn advance(&self, by: Duration) {
            let mut clocks = lock(&self.0);
            clocks.0 += by;
            clocks.1 += by;
        }

        pub fn suspend(&self, by: Duration) {
            lock(&self.0).1 += by;
        }
    }

    impl ElapsedClock for FakeElapsedClock {
        fn monotonic(&self) -> Duration {
            lock(&self.0).0
        }

        fn boottime(&self) -> Duration {
            lock(&self.0).1
        }
    }

    fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
