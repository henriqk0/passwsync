#![allow(dead_code)]

use std::collections::hash_map::RandomState;
use std::fs;
use std::hash::{BuildHasher, Hasher};
use std::path::{Path, PathBuf};

/// A private temporary directory removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        let suffix = RandomState::new().build_hasher().finish();
        let path = std::env::temp_dir().join(format!("passwsyncd-{label}-{suffix:016x}"));
        fs::create_dir(&path).unwrap();
        set_mode(&path, 0o700);
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

pub fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

pub mod server;
