#![forbid(unsafe_code)]

use std::collections::hash_map::RandomState;
use std::fs::{self, File, OpenOptions};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use vault_core::{StorageError, VaultStorage};

/// Stores the encrypted wallet in one file, replaced atomically on every save:
/// write a temp file next to it, flush it to disk, then rename it over the target.
pub struct FileStorage {
    path: PathBuf,
}

impl FileStorage {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn parent(&self) -> &Path {
        match self.path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        }
    }

    /// Writes `bytes` to a new owner-only temp file in the target's directory.
    fn write_temp(&self, bytes: &[u8]) -> io::Result<PathBuf> {
        let name = self.path.file_name().unwrap_or_default().to_string_lossy();
        let suffix = RandomState::new().build_hasher().finish();
        let temp = self.parent().join(format!(".{name}.tmp-{suffix:016x}"));

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);

        let written = options.open(&temp).and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        });
        match written {
            Ok(()) => Ok(temp),
            Err(error) => {
                let _ = fs::remove_file(&temp);
                Err(error)
            }
        }
    }

    /// Atomically replaces the target with the temp file.
    fn commit(&self, temp: &Path) -> io::Result<()> {
        fs::rename(temp, &self.path)?;
        #[cfg(unix)]
        File::open(self.parent())?.sync_all()?;
        Ok(())
    }
}

impl VaultStorage for FileStorage {
    fn load(&self) -> Result<Vec<u8>, StorageError> {
        fs::read(&self.path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => StorageError::NotFound,
            _ => StorageError::Io(error),
        })
    }

    fn store(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        let temp = self.write_temp(bytes).map_err(StorageError::Io)?;
        self.commit(&temp).map_err(|error| {
            let _ = fs::remove_file(&temp);
            StorageError::Io(error)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::RandomState;
    use std::fs;
    use std::hash::{BuildHasher, Hasher};
    use vault_core::{DeviceId, FixedClock, KdfConfig, MasterPassword, Vault};

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let suffix = RandomState::new().build_hasher().finish();
            let path = std::env::temp_dir().join(format!("vault-storage-file-unit-{suffix:016x}"));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn entries_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn interrupted_write_leaves_the_old_wallet_intact_and_unlockable() {
        let dir = TestDir::new();
        let path = dir.0.join("wallet.pwsv");
        let password = || MasterPassword::new("correct horse battery".to_string());
        let device = || DeviceId::new("laptop").unwrap();
        let vault = Vault::create(
            password(),
            KdfConfig::MINIMUM,
            device(),
            Box::new(FixedClock::new(1)),
        )
        .unwrap();
        let mut storage = FileStorage::new(&path);
        vault.save(&mut storage).unwrap();
        let before = fs::read(&path).unwrap();

        // Crash after the temp file is written, before the rename.
        let temp = storage.write_temp(b"half-written replacement").unwrap();

        assert!(temp.exists());
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(Vault::open(&storage, password(), device(), Box::new(FixedClock::new(2))).is_ok());
    }

    #[test]
    fn failed_commit_returns_io_and_removes_the_temp_file() {
        let dir = TestDir::new();
        let target = dir.0.join("wallet.pwsv");
        fs::create_dir(&target).unwrap(); // rename of a file over a directory fails
        let mut storage = FileStorage::new(&target);

        let result = storage.store(b"ciphertext");

        assert!(matches!(result, Err(StorageError::Io(_))));
        assert_eq!(entries_in(&dir.0), ["wallet.pwsv"]);
    }

    #[cfg(unix)]
    #[test]
    fn created_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new();
        let path = dir.0.join("wallet.pwsv");
        FileStorage::new(&path).store(b"x").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn missing_file_is_not_found() {
        let dir = TestDir::new();
        let storage = FileStorage::new(dir.0.join("absent.pwsv"));
        assert!(matches!(storage.load(), Err(StorageError::NotFound)));
    }

    #[test]
    fn missing_parent_directory_is_io() {
        let dir = TestDir::new();
        let mut storage = FileStorage::new(dir.0.join("no-such-dir").join("wallet.pwsv"));
        assert!(matches!(storage.store(b"x"), Err(StorageError::Io(_))));
    }

    #[test]
    fn successful_store_leaves_no_temp_files() {
        let dir = TestDir::new();
        let mut storage = FileStorage::new(dir.0.join("wallet.pwsv"));
        storage.store(b"one").unwrap();
        storage.store(b"two").unwrap();
        assert_eq!(entries_in(&dir.0), ["wallet.pwsv"]);
    }

    #[cfg(unix)]
    #[test]
    fn temp_file_that_cannot_be_created_leaves_the_old_wallet_intact() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new();
        let path = dir.0.join("wallet.pwsv");
        let mut storage = FileStorage::new(&path);
        storage.store(b"old wallet bytes").unwrap();
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o555)).unwrap();

        let result = storage.store(b"new wallet bytes");

        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).unwrap();
        if result.is_ok() {
            return; // running as root: directory permissions are not enforced
        }
        assert!(matches!(result, Err(StorageError::Io(_))));
        assert_eq!(fs::read(&path).unwrap(), b"old wallet bytes");
        assert_eq!(entries_in(&dir.0), ["wallet.pwsv"]);
    }

    #[test]
    fn stale_temp_file_from_a_crash_does_not_block_or_corrupt_the_next_save() {
        let dir = TestDir::new();
        let path = dir.0.join("wallet.pwsv");
        let mut storage = FileStorage::new(&path);
        storage.store(b"old wallet bytes").unwrap();
        // A previous process died after writing its temp file, before the rename.
        let stale = storage.write_temp(b"abandoned write").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"old wallet bytes");

        storage.store(b"new wallet bytes").unwrap();

        assert_eq!(storage.load().unwrap(), b"new wallet bytes");
        assert!(stale.exists(), "unrelated temp files are left alone");
    }
}
