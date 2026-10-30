//! Wallet directory on disk: one `<name>.pwsw` file per wallet, written via `FileStorage`.

use std::fs;
use std::io;
use std::path::PathBuf;

use vault_core::{StorageError, VaultStorage};
use vault_storage_file::FileStorage;
use wallet_service::{WalletDirectory, WalletName};

const EXTENSION: &str = ".pwsw";

pub struct FsWalletDirectory {
    dir: PathBuf,
}

impl FsWalletDirectory {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn path(&self, name: &WalletName) -> PathBuf {
        self.dir.join(format!("{name}{EXTENSION}"))
    }
}

impl WalletDirectory for FsWalletDirectory {
    /// Regular files (not symlinks) named `<valid name>.pwsw`; everything else is ignored.
    fn list(&self) -> Result<Vec<WalletName>, StorageError> {
        let mut names = Vec::new();
        for item in fs::read_dir(&self.dir).map_err(StorageError::Io)? {
            let Ok(item) = item else { continue };
            let Ok(file_type) = item.file_type() else {
                continue;
            };
            if !file_type.is_file() {
                continue;
            }
            let file_name = item.file_name();
            let Some(stem) = file_name.to_str().and_then(|n| n.strip_suffix(EXTENSION)) else {
                continue;
            };
            if let Ok(name) = WalletName::parse(stem) {
                names.push(name);
            }
        }
        names.sort();
        Ok(names)
    }

    /// True if anything at all occupies the name, so creation never replaces it.
    fn exists(&self, name: &WalletName) -> Result<bool, StorageError> {
        match fs::symlink_metadata(self.path(name)) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(StorageError::Io(error)),
        }
    }

    fn storage(&self, name: &WalletName) -> Box<dyn VaultStorage + Send> {
        Box::new(FileStorage::new(self.path(name)))
    }
}
