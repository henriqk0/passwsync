#![forbid(unsafe_code)]
//! The Android [`IdentityStore`]: the 003 device key and pins, each sealed by the Keystore
//! through [`KeySealer`] (contracts/ffi-api.md section 6; FR-034, FR-035, FR-037). The sealer
//! receives only the two labels below and only the 003 encodings of the key and the pins.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use device_link::error::Error;
use device_link::files::{decode_device_key, decode_peers, encode_device_key, encode_peers};
use device_link::identity::DeviceKey;
use device_link::policy::AddressPolicy;
use device_link::ports::PeerStore;
use device_link::registry::PeerPin;
use host_runtime::files::{read_private_file, write_private_atomic};
use host_runtime::net_runtime::{IdentityError, IdentityStore};
use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::ports::KeySealer;

pub const IDENTITY_LABEL: &str = "passwsync identity v1";
pub const PEERS_LABEL: &str = "passwsync peers v1";
pub const IDENTITY_FILE: &str = "identity.sealed";
pub const PEERS_FILE: &str = "peers.sealed";
/// Sealed files larger than this are refused before `open` is called.
pub const SEALED_LIMIT: u64 = 64 * 1024;

/// Reads a sealed file (bounded) and opens it. `Ok(None)`: the file does not exist.
fn open_sealed(
    sealer: &dyn KeySealer,
    path: &Path,
    label: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>, ()> {
    let Some(sealed) = read_private_file(path, SEALED_LIMIT).map_err(|_| ())? else {
        return Ok(None);
    };
    sealer
        .open(label.to_owned(), sealed.to_vec())
        .map(|plain| Some(Zeroizing::new(plain)))
        .map_err(|_| ())
}

/// Device key and pins under `data_dir`, sealed by the Keystore.
pub struct SealedIdentity {
    dir: PathBuf,
    sealer: Arc<dyn KeySealer>,
}

impl SealedIdentity {
    pub fn new(data_dir: &Path, sealer: Arc<dyn KeySealer>) -> Self {
        Self {
            dir: data_dir.to_path_buf(),
            sealer,
        }
    }

    fn create(&self, path: &Path) -> Result<DeviceKey, IdentityError> {
        let key = DeviceKey::generate(&mut OsRng).map_err(|_| IdentityError::Unusable)?;
        let encoded = encode_device_key(&key);
        let sealed = self
            .sealer
            .seal(IDENTITY_LABEL.to_owned(), encoded.as_bytes().to_vec())
            .map_err(|_| IdentityError::Unusable)?;
        write_private_atomic(path, &sealed).map_err(|_| IdentityError::Unusable)?;
        Ok(key)
    }
}

impl IdentityStore for SealedIdentity {
    /// Missing file: a new key is created and sealed. An existing file that cannot be read,
    /// is too large, or fails to open is `Unusable` and left as it is (FR-037: the person
    /// chooses to reset).
    fn load_or_create_key(&self) -> Result<DeviceKey, IdentityError> {
        let path = self.dir.join(IDENTITY_FILE);
        match open_sealed(self.sealer.as_ref(), &path, IDENTITY_LABEL) {
            Ok(Some(plain)) => decode_device_key(&plain).map_err(|_| IdentityError::Unusable),
            Ok(None) => self.create(&path),
            Err(()) => Err(IdentityError::Unusable),
        }
    }

    fn peer_store(&self, own_public: [u8; 32], policy: AddressPolicy) -> Arc<dyn PeerStore> {
        Arc::new(SealedPeerStore {
            path: self.dir.join(PEERS_FILE),
            sealer: Arc::clone(&self.sealer),
            own_public,
            policy,
        })
    }
}

/// The 003 pins file, sealed with [`PEERS_LABEL`].
pub struct SealedPeerStore {
    path: PathBuf,
    sealer: Arc<dyn KeySealer>,
    own_public: [u8; 32],
    policy: AddressPolicy,
}

impl PeerStore for SealedPeerStore {
    /// Missing file: no pins. Anything unusable: `Malformed`, file left as it is.
    fn load(&self) -> Result<Vec<PeerPin>, Error> {
        match open_sealed(self.sealer.as_ref(), &self.path, PEERS_LABEL) {
            Ok(None) => Ok(Vec::new()),
            Ok(Some(plain)) => {
                let text = std::str::from_utf8(&plain).map_err(|_| Error::Malformed)?;
                decode_peers(text, &self.own_public, self.policy)
            }
            Err(()) => Err(Error::Malformed),
        }
    }

    fn save(&self, pins: &[PeerPin]) -> Result<(), Error> {
        let sealed = self
            .sealer
            .seal(PEERS_LABEL.to_owned(), encode_peers(pins).into_bytes())
            .map_err(|_| Error::Storage)?;
        write_private_atomic(&self.path, &sealed).map_err(|_| Error::Storage)
    }
}
