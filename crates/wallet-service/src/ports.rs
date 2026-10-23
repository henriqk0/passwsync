use std::time::Duration;

use vault_core::{StorageError, VaultStorage};

use crate::WalletName;

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
