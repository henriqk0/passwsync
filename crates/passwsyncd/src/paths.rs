//! XDG directories, permission checks and the device identifier
//! (contracts/host-runtime.md, "Files and directories").

use std::ffi::OsString;
use std::fmt;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use device_link::files::{decode_device_key, encode_device_key};
use device_link::identity::DeviceKey;
use rand_core::{OsRng, RngCore};
use vault_core::DeviceId;
use zeroize::Zeroizing;

/// A path that cannot be used safely; start-up exits with code 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathError {
    place: String,
    problem: &'static str,
}

impl PathError {
    pub(crate) fn new(place: &Path, problem: &'static str) -> Self {
        Self {
            place: place.display().to_string(),
            problem,
        }
    }
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "path: {}: {}", self.place, self.problem)
    }
}

impl std::error::Error for PathError {}

/// The environment variables that decide where files live. Relative values are ignored, as
/// the XDG base directory specification requires.
#[derive(Clone, Debug, Default)]
pub struct Env {
    pub home: Option<PathBuf>,
    pub xdg_config_home: Option<PathBuf>,
    pub xdg_data_home: Option<PathBuf>,
    pub xdg_runtime_dir: Option<PathBuf>,
}

impl Env {
    pub fn from_process() -> Self {
        let var = |name: &str| {
            std::env::var_os(name)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        Self {
            home: var("HOME"),
            xdg_config_home: var("XDG_CONFIG_HOME"),
            xdg_data_home: var("XDG_DATA_HOME"),
            xdg_runtime_dir: var("XDG_RUNTIME_DIR"),
        }
    }
}

/// Every file and directory the service uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub config_file: PathBuf,
    pub device_id_file: PathBuf,
    /// 003: X25519 device key (contracts/host-runtime-network.md).
    pub device_key_file: PathBuf,
    /// 003: pinned peers.
    pub peers_file: PathBuf,
    pub wallets_dir: PathBuf,
    /// 004: sync records and pending copies (contracts/host-runtime-sync.md).
    pub sync_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub launch_file: PathBuf,
    pub lock_file: PathBuf,
}

impl Paths {
    pub fn resolve(env: &Env) -> Result<Self, PathError> {
        let absolute = |p: &Option<PathBuf>| p.clone().filter(|p| p.is_absolute());
        let home =
            || absolute(&env.home).ok_or_else(|| PathError::new(Path::new("$HOME"), "not set"));
        let config_home = match absolute(&env.xdg_config_home) {
            Some(path) => path,
            None => home()?.join(".config"),
        };
        let data_home = match absolute(&env.xdg_data_home) {
            Some(path) => path,
            None => home()?.join(".local/share"),
        };
        let runtime = absolute(&env.xdg_runtime_dir).ok_or_else(|| {
            PathError::new(
                Path::new("$XDG_RUNTIME_DIR"),
                "not set (no fallback is used)",
            )
        })?;
        let config_dir = config_home.join("passwsync");
        let runtime_dir = runtime.join("passwsync");
        Ok(Self {
            config_file: config_dir.join("config"),
            device_id_file: config_dir.join("device-id"),
            device_key_file: config_dir.join("device-key"),
            peers_file: config_dir.join("peers"),
            config_dir,
            wallets_dir: data_home.join("passwsync/wallets"),
            sync_dir: data_home.join("passwsync/sync"),
            launch_file: runtime_dir.join("launch-url"),
            lock_file: runtime_dir.join("instance.lock"),
            runtime_dir,
        })
    }

    /// Creates the service's directories with mode 0700 and checks existing ones.
    pub fn prepare(&self) -> Result<(), PathError> {
        ensure_private_dir(&self.config_dir)?;
        if let Some(parent) = self.wallets_dir.parent() {
            ensure_private_dir(parent)?;
        }
        ensure_private_dir(&self.wallets_dir)?;
        ensure_private_dir(&self.runtime_dir)
    }
}

/// Creates `dir` (and missing parents) or checks that the existing one is a directory owned
/// by the current user without group/other permission bits.
pub fn ensure_private_dir(dir: &Path) -> Result<(), PathError> {
    if let Some(parent) = dir.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|_| PathError::new(parent, "cannot be created"))?;
        }
    }
    match DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(PathError::new(dir, "cannot be created")),
    }
    let metadata = fs::symlink_metadata(dir).map_err(|_| PathError::new(dir, "cannot be read"))?;
    if !metadata.is_dir() {
        return Err(PathError::new(dir, "not a directory"));
    }
    check_private(dir, &metadata)
}

/// Owned by the current user, no group/other permission bits.
pub(crate) fn check_private(path: &Path, metadata: &fs::Metadata) -> Result<(), PathError> {
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(PathError::new(path, "not owned by the current user"));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(PathError::new(
            path,
            "must not be accessible by group or others",
        ));
    }
    Ok(())
}

/// Reads the device identifier, creating it (32 random lowercase hex digits and a newline,
/// mode 0600) on first run. An invalid file is refused, never replaced: change tracking for
/// sync depends on the identifier staying the same.
pub fn load_or_create_device_id(path: &Path) -> Result<DeviceId, PathError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() {
                return Err(PathError::new(path, "not a regular file"));
            }
            check_private(path, &metadata)?;
            let mut text = String::new();
            fs::File::open(path)
                .and_then(|file| file.take(64).read_to_string(&mut text))
                .map_err(|_| PathError::new(path, "cannot be read"))?;
            let hex = text
                .strip_suffix('\n')
                .filter(|hex| is_device_hex(hex))
                .ok_or_else(|| {
                    PathError::new(
                        path,
                        "invalid device identifier (expected 32 lowercase hex digits)",
                    )
                })?;
            DeviceId::new(hex).map_err(|_| PathError::new(path, "invalid device identifier"))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => create_device_id(path),
        Err(_) => Err(PathError::new(path, "cannot be read")),
    }
}

fn is_device_hex(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn create_device_id(path: &Path) -> Result<DeviceId, PathError> {
    let mut bytes = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| PathError::new(path, "secure random source failure"))?;
    let hex = crate::hex::encode(&bytes);
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| {
            file.write_all(format!("{hex}\n").as_bytes())?;
            file.sync_all()
        });
    if written.is_err() {
        let _ = fs::remove_file(path);
        return Err(PathError::new(path, "cannot be created"));
    }
    DeviceId::new(hex).map_err(|_| PathError::new(path, "invalid device identifier"))
}

/// Writes `contents` to `path` atomically (temp file, mode 0600, rename).
pub fn write_private_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut temp_name = OsString::from(".");
    temp_name.push(path.file_name().unwrap_or_default());
    temp_name.push(".tmp");
    let temp = path.with_file_name(temp_name);
    let _ = fs::remove_file(&temp);
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .and_then(|mut file| {
            file.write_all(contents)?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&temp, path));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Why a 003 device file cannot be used. Unlike 002 files this never stops the service: the
/// network stays off with a status (contracts/host-runtime-network.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceFileError {
    /// Exists but is not a private regular file of ours, cannot be read, or is malformed.
    Unusable,
    /// Missing and could not be created.
    CannotCreate,
}

/// Reads an existing private regular file (no symlink) of at most `limit` bytes.
pub(crate) fn read_private_file(path: &Path, limit: u64) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || check_private(path, &metadata).is_err() || metadata.len() > limit {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    fs::File::open(path)?.take(limit).read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

/// Loads the device key, creating it from the OS random source when the file is missing.
/// An existing file that is not usable is never replaced (FR-005).
pub fn load_or_create_device_key(path: &Path) -> Result<DeviceKey, DeviceFileError> {
    match read_private_file(path, 256) {
        Ok(Some(bytes)) => decode_device_key(&bytes).map_err(|_| DeviceFileError::Unusable),
        Ok(None) => {
            let key = DeviceKey::generate(&mut OsRng).map_err(|_| DeviceFileError::CannotCreate)?;
            let text = encode_device_key(&key);
            write_private_atomic_new(path, text.as_bytes())
                .map_err(|_| DeviceFileError::CannotCreate)?;
            Ok(key)
        }
        Err(_) => Err(DeviceFileError::Unusable),
    }
}

/// Like [`write_private_atomic`], but never replaces an existing file (hard link instead of
/// rename, so a concurrent creator wins and nothing is overwritten).
fn write_private_atomic_new(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut temp_name = OsString::from(".");
    temp_name.push(path.file_name().unwrap_or_default());
    temp_name.push(".tmp");
    let temp = path.with_file_name(temp_name);
    let _ = fs::remove_file(&temp);
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .and_then(|mut file| {
            file.write_all(contents)?;
            file.sync_all()
        })
        .and_then(|()| fs::hard_link(&temp, path));
    let _ = fs::remove_file(&temp);
    result
}
