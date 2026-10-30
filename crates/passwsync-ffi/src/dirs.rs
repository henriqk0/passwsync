#![forbid(unsafe_code)]
//! The app-private data directory layout (contracts/ffi-api.md section 6; FR-030, FR-031):
//! everything lives under `CoreConfig.data_dir`, directories 0700.

use std::path::{Path, PathBuf};

use host_runtime::files::{PathError, ensure_private_dir};

use crate::identity::{IDENTITY_FILE, PEERS_FILE};
use crate::settings::SETTINGS_FILE;

/// `data_dir` and its `wallets/`, `sync/` and `received/` subdirectories.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataDirs {
    pub root: PathBuf,
    pub wallets: PathBuf,
    pub sync: PathBuf,
    pub received: PathBuf,
}

impl DataDirs {
    /// Creates the directories with mode 0700, or checks the existing ones are private.
    pub fn prepare(root: &Path) -> Result<Self, PathError> {
        let dirs = Self {
            root: root.to_path_buf(),
            wallets: root.join("wallets"),
            sync: root.join("sync"),
            received: root.join("received"),
        };
        for dir in [&dirs.root, &dirs.wallets, &dirs.sync, &dirs.received] {
            ensure_private_dir(dir)?;
        }
        Ok(dirs)
    }

    pub fn settings_file(&self) -> PathBuf {
        self.root.join(SETTINGS_FILE)
    }

    pub fn device_id_file(&self) -> PathBuf {
        self.root.join("device-id")
    }

    pub fn identity_file(&self) -> PathBuf {
        self.root.join(IDENTITY_FILE)
    }

    pub fn peers_file(&self) -> PathBuf {
        self.root.join(PEERS_FILE)
    }

    pub fn clipboard_marker(&self) -> PathBuf {
        self.root.join("clipboard-pending")
    }
}
