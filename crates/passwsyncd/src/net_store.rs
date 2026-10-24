//! `PeerStore` adapter over the owner-only `peers` file (research R11).

use std::path::PathBuf;

use device_link::error::Error;
use device_link::files::{decode_peers, encode_peers};
use device_link::policy::AddressPolicy;
use device_link::ports::PeerStore;
use device_link::registry::PeerPin;

use crate::paths::{read_private_file, write_private_atomic};

/// 33 lines of at most ~300 bytes fit easily.
const LIMIT: u64 = 64 * 1024;

pub struct FilePeerStore {
    path: PathBuf,
    own_public: [u8; 32],
    policy: AddressPolicy,
}

impl FilePeerStore {
    pub fn new(path: PathBuf, own_public: [u8; 32], policy: AddressPolicy) -> Self {
        Self {
            path,
            own_public,
            policy,
        }
    }
}

impl PeerStore for FilePeerStore {
    /// Missing file: no pins. Anything unusable: `Malformed`, file left as it is (FR-035).
    fn load(&self) -> Result<Vec<PeerPin>, Error> {
        match read_private_file(&self.path, LIMIT) {
            Ok(None) => Ok(Vec::new()),
            Ok(Some(bytes)) => {
                let text = std::str::from_utf8(&bytes).map_err(|_| Error::Malformed)?;
                decode_peers(text, &self.own_public, self.policy)
            }
            Err(_) => Err(Error::Malformed),
        }
    }

    fn save(&self, pins: &[PeerPin]) -> Result<(), Error> {
        write_private_atomic(&self.path, encode_peers(pins).as_bytes()).map_err(|_| Error::Storage)
    }
}
