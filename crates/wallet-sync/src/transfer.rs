//! Whole-file transfer of a wallet copy (contracts/sync-protocol.md steps 4-5): the sender
//! streams its own stored file in 1000-byte chunks while re-hashing it; the receiver streams
//! to `incoming-<peer>.part` and counts bytes. Memory per transfer: one chunk plus the
//! store's write buffer (well under 1 MiB, FR-029).

use std::io::Read;

use sha2::{Digest, Sha256};
use vault_core::{StateVector, WalletId};

use crate::codec::MAX_FRAGMENT;
use crate::ports::IncomingCopy;
use crate::slots::SlotGuard;

/// What the sender's next step produces.
pub(crate) enum ServeStep {
    Chunk(Vec<u8>),
    /// Every byte was sent and the file matched the recorded digest.
    End,
    /// The file changed (size or digest) since the record was written.
    Changed,
    ReadError,
}

/// Our side serving a `Want` (at most one per peer).
pub(crate) struct Serving {
    pub idx: u16,
    remaining: u64,
    reader: Box<dyn Read + Send>,
    hasher: Sha256,
    expected: [u8; 32],
    /// The transfer slot this serve holds (released when the serve is dropped).
    _slot: Option<SlotGuard>,
}

impl Serving {
    pub fn new(idx: u16, size: u64, reader: Box<dyn Read + Send>, expected: [u8; 32]) -> Self {
        Self {
            idx,
            remaining: size,
            reader,
            hasher: Sha256::new(),
            expected,
            _slot: None,
        }
    }

    /// Holds `slot` for as long as this serve lives.
    pub fn holding(mut self, slot: SlotGuard) -> Self {
        self._slot = Some(slot);
        self
    }

    fn read_full(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut filled = 0;
        while filled < buf.len() {
            match self.reader.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(filled)
    }

    pub fn next(&mut self) -> ServeStep {
        if self.remaining == 0 {
            // The file must end exactly here and hash to the recorded digest.
            let mut probe = [0u8; 1];
            return match self.read_full(&mut probe) {
                Ok(0) => {
                    let digest: [u8; 32] = std::mem::take(&mut self.hasher).finalize().into();
                    if digest == self.expected {
                        ServeStep::End
                    } else {
                        ServeStep::Changed
                    }
                }
                Ok(_) => ServeStep::Changed,
                Err(_) => ServeStep::ReadError,
            };
        }
        let want = MAX_FRAGMENT.min(usize::try_from(self.remaining).unwrap_or(MAX_FRAGMENT));
        let mut chunk = vec![0u8; want];
        match self.read_full(&mut chunk) {
            Ok(n) if n == want => {
                self.hasher.update(&chunk);
                self.remaining -= n as u64;
                ServeStep::Chunk(chunk)
            }
            Ok(_) => ServeStep::Changed,
            Err(_) => ServeStep::ReadError,
        }
    }
}

/// A copy we asked for, being received.
pub(crate) struct Incoming {
    pub idx: u16,
    pub wallet: WalletId,
    pub size: u64,
    pub received: u64,
    pub claimed: StateVector,
    pub writer: Option<Box<dyn IncomingCopy>>,
}

impl Incoming {
    /// Deletes the partial file.
    pub fn abort(&mut self) {
        if let Some(writer) = self.writer.take() {
            writer.abort();
        }
    }
}

impl Drop for Incoming {
    fn drop(&mut self) {
        self.abort();
    }
}
