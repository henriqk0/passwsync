//! XDG directories, permission checks and the device identifier
//! (contracts/host-runtime.md, "Files and directories"). The file helpers moved to
//! `host_runtime::files` (007, FR-004) and are re-exported here so paths stay stable.

use std::path::{Path, PathBuf};

pub use host_runtime::files::*;

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
    /// 005: received wallets awaiting a password (contracts/host-runtime-share.md).
    pub received_dir: PathBuf,
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
            received_dir: data_home.join("passwsync/received"),
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

/// 003 identity in plain owner-only files (`device-key`, `peers`): the desktop
/// [`IdentityStore`](host_runtime::net_runtime::IdentityStore).
pub struct FileIdentity<'a>(pub &'a Paths);

impl host_runtime::net_runtime::IdentityStore for FileIdentity<'_> {
    fn load_or_create_key(
        &self,
    ) -> Result<device_link::identity::DeviceKey, host_runtime::net_runtime::IdentityError> {
        load_or_create_device_key(&self.0.device_key_file)
            .map_err(|_| host_runtime::net_runtime::IdentityError::Unusable)
    }

    fn peer_store(
        &self,
        own_public: [u8; 32],
        policy: device_link::policy::AddressPolicy,
    ) -> std::sync::Arc<dyn device_link::ports::PeerStore> {
        std::sync::Arc::new(host_runtime::net_store::FilePeerStore::new(
            self.0.peers_file.clone(),
            own_public,
            policy,
        ))
    }
}
