//! Control messages (contracts/sync-protocol.md): `ctype:u8 || fields`, big-endian, strict,
//! carried in `SyncCtl` fragments of at most 1000 bytes and reassembled up to 24 KiB.

use vault_core::{DeviceId, StateVector};

use crate::error::ProtocolError;

/// Largest reassembled control message.
pub const MAX_CTL: usize = 24 * 1024;
/// Largest `SyncCtl` fragment (also the largest `CopyData` chunk).
pub const MAX_FRAGMENT: usize = 1000;
/// At most this many wallets per round (`Tags`, `Matches`).
pub const MAX_TAGS: usize = 512;
/// Smallest and largest announced copy (a wallet file is 79 bytes .. 64 MiB).
pub const MIN_COPY: u32 = 79;
pub const MAX_COPY: u32 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefuseReason {
    Busy = 1,
    NotOfferable = 2,
    Changed = 3,
    Storage = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortReason {
    ReadError = 1,
    Changed = 2,
    TooLarge = 3,
    Storage = 4,
    Cancelled = 5,
}

/// One control message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ctl {
    /// I -> R: `(tag, state_digest)` per syncable wallet in the window.
    Tags {
        round: u32,
        entries: Vec<([u8; 16], [u8; 16])>,
    },
    /// R -> I: `(idx, in_sync)` per wallet both hold.
    Matches {
        round: u32,
        entries: Vec<(u16, bool)>,
    },
    Summary {
        round: u32,
        idx: u16,
        no_offer: bool,
        state: StateVector,
    },
    Want {
        round: u32,
        idx: u16,
    },
    Refuse {
        round: u32,
        idx: u16,
        reason: RefuseReason,
    },
    CopyStart {
        round: u32,
        idx: u16,
        size: u32,
    },
    CopyEnd {
        round: u32,
        idx: u16,
    },
    CopyAbort {
        round: u32,
        idx: u16,
        reason: AbortReason,
    },
    Done {
        round: u32,
    },
    Busy {
        round: u32,
    },
}

impl Ctl {
    pub fn round(&self) -> u32 {
        match self {
            Self::Tags { round, .. }
            | Self::Matches { round, .. }
            | Self::Summary { round, .. }
            | Self::Want { round, .. }
            | Self::Refuse { round, .. }
            | Self::CopyStart { round, .. }
            | Self::CopyEnd { round, .. }
            | Self::CopyAbort { round, .. }
            | Self::Done { round }
            | Self::Busy { round } => *round,
        }
    }
}

/// The wire form of a state vector: `n:u16 || n x (len:u8 || id || counter:u64)`.
pub fn encode_state(state: &StateVector) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + state.len() * 16);
    push_state(&mut out, state);
    out
}

fn push_state(out: &mut Vec<u8>, state: &StateVector) {
    out.extend_from_slice(&(state.len() as u16).to_be_bytes());
    for (device, counter) in state.iter() {
        let id = device.as_str().as_bytes();
        out.push(id.len() as u8);
        out.extend_from_slice(id);
        out.extend_from_slice(&counter.to_be_bytes());
    }
}

pub fn encode(ctl: &Ctl) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    let head = |out: &mut Vec<u8>, ctype: u8, round: u32| {
        out.push(ctype);
        out.extend_from_slice(&round.to_be_bytes());
    };
    match ctl {
        Ctl::Tags { round, entries } => {
            out.reserve(entries.len() * 32 + 8);
            head(&mut out, 0x01, *round);
            out.extend_from_slice(&(entries.len() as u16).to_be_bytes());
            for (tag, digest) in entries {
                out.extend_from_slice(tag);
                out.extend_from_slice(digest);
            }
        }
        Ctl::Matches { round, entries } => {
            head(&mut out, 0x02, *round);
            out.extend_from_slice(&(entries.len() as u16).to_be_bytes());
            for (idx, in_sync) in entries {
                out.extend_from_slice(&idx.to_be_bytes());
                out.push(u8::from(*in_sync));
            }
        }
        Ctl::Summary {
            round,
            idx,
            no_offer,
            state,
        } => {
            head(&mut out, 0x03, *round);
            out.extend_from_slice(&idx.to_be_bytes());
            out.push(u8::from(*no_offer));
            push_state(&mut out, state);
        }
        Ctl::Want { round, idx } => {
            head(&mut out, 0x04, *round);
            out.extend_from_slice(&idx.to_be_bytes());
        }
        Ctl::Refuse { round, idx, reason } => {
            head(&mut out, 0x05, *round);
            out.extend_from_slice(&idx.to_be_bytes());
            out.push(*reason as u8);
        }
        Ctl::CopyStart { round, idx, size } => {
            head(&mut out, 0x06, *round);
            out.extend_from_slice(&idx.to_be_bytes());
            out.extend_from_slice(&size.to_be_bytes());
        }
        Ctl::CopyEnd { round, idx } => {
            head(&mut out, 0x07, *round);
            out.extend_from_slice(&idx.to_be_bytes());
        }
        Ctl::CopyAbort { round, idx, reason } => {
            head(&mut out, 0x08, *round);
            out.extend_from_slice(&idx.to_be_bytes());
            out.push(*reason as u8);
        }
        Ctl::Done { round } => head(&mut out, 0x09, *round),
        Ctl::Busy { round } => head(&mut out, 0x0A, *round),
    }
    out
}

/// A strict reader: every take checks the remaining length.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtocolError> {
        if self.0.len() < n {
            return Err(ProtocolError);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ProtocolError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, ProtocolError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, ProtocolError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    fn array16(&mut self) -> Result<[u8; 16], ProtocolError> {
        let mut a = [0u8; 16];
        a.copy_from_slice(self.take(16)?);
        Ok(a)
    }

    fn state(&mut self) -> Result<StateVector, ProtocolError> {
        let n = usize::from(self.u16()?);
        if n > StateVector::MAX_DEVICES {
            return Err(ProtocolError);
        }
        let mut pairs = Vec::with_capacity(n);
        for _ in 0..n {
            let len = usize::from(self.u8()?);
            if !(1..=64).contains(&len) {
                return Err(ProtocolError);
            }
            let id = std::str::from_utf8(self.take(len)?).map_err(|_| ProtocolError)?;
            let device = DeviceId::new(id).map_err(|_| ProtocolError)?;
            pairs.push((device, self.u64()?));
        }
        StateVector::from_pairs(pairs).map_err(|_| ProtocolError)
    }

    fn done(&self) -> Result<(), ProtocolError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ProtocolError)
        }
    }
}

fn refuse_reason(byte: u8) -> Result<RefuseReason, ProtocolError> {
    Ok(match byte {
        1 => RefuseReason::Busy,
        2 => RefuseReason::NotOfferable,
        3 => RefuseReason::Changed,
        4 => RefuseReason::Storage,
        _ => return Err(ProtocolError),
    })
}

fn abort_reason(byte: u8) -> Result<AbortReason, ProtocolError> {
    Ok(match byte {
        1 => AbortReason::ReadError,
        2 => AbortReason::Changed,
        3 => AbortReason::TooLarge,
        4 => AbortReason::Storage,
        5 => AbortReason::Cancelled,
        _ => return Err(ProtocolError),
    })
}

/// Decodes one reassembled control message; anything not exactly per contract is an error.
pub fn decode(bytes: &[u8]) -> Result<Ctl, ProtocolError> {
    if bytes.len() > MAX_CTL {
        return Err(ProtocolError);
    }
    let mut r = Reader(bytes);
    let ctype = r.u8()?;
    let round = r.u32()?;
    let ctl = match ctype {
        0x01 => {
            let n = usize::from(r.u16()?);
            if n > MAX_TAGS {
                return Err(ProtocolError);
            }
            let mut entries = Vec::with_capacity(n);
            for _ in 0..n {
                entries.push((r.array16()?, r.array16()?));
            }
            Ctl::Tags { round, entries }
        }
        0x02 => {
            let n = usize::from(r.u16()?);
            if n > MAX_TAGS {
                return Err(ProtocolError);
            }
            let mut entries = Vec::with_capacity(n);
            for _ in 0..n {
                let idx = r.u16()?;
                let in_sync = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ProtocolError),
                };
                entries.push((idx, in_sync));
            }
            Ctl::Matches { round, entries }
        }
        0x03 => {
            let idx = r.u16()?;
            let no_offer = match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(ProtocolError),
            };
            Ctl::Summary {
                round,
                idx,
                no_offer,
                state: r.state()?,
            }
        }
        0x04 => Ctl::Want {
            round,
            idx: r.u16()?,
        },
        0x05 => Ctl::Refuse {
            round,
            idx: r.u16()?,
            reason: refuse_reason(r.u8()?)?,
        },
        0x06 => {
            let idx = r.u16()?;
            let size = r.u32()?;
            if !(MIN_COPY..=MAX_COPY).contains(&size) {
                return Err(ProtocolError);
            }
            Ctl::CopyStart { round, idx, size }
        }
        0x07 => Ctl::CopyEnd {
            round,
            idx: r.u16()?,
        },
        0x08 => Ctl::CopyAbort {
            round,
            idx: r.u16()?,
            reason: abort_reason(r.u8()?)?,
        },
        0x09 => Ctl::Done { round },
        0x0A => Ctl::Busy { round },
        _ => return Err(ProtocolError),
    };
    r.done()?;
    Ok(ctl)
}

/// Splits an encoded message into `(more, fragment)` pieces of at most 1000 bytes.
pub fn fragment(message: &[u8]) -> Vec<(bool, Vec<u8>)> {
    let chunks: Vec<&[u8]> = message.chunks(MAX_FRAGMENT).collect();
    let last = chunks.len().saturating_sub(1);
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| (i != last, chunk.to_vec()))
        .collect()
}

/// Joins `SyncCtl` fragments; at most 24 KiB per message.
#[derive(Debug, Default)]
pub struct Reassembler {
    buffer: Vec<u8>,
    active: bool,
}

impl Reassembler {
    /// `Ok(Some(message))` when `more = false` completes a message.
    pub fn push(&mut self, more: bool, fragment: &[u8]) -> Result<Option<Vec<u8>>, ProtocolError> {
        if fragment.is_empty()
            || fragment.len() > MAX_FRAGMENT
            || self.buffer.len() + fragment.len() > MAX_CTL
        {
            self.reset();
            return Err(ProtocolError);
        }
        self.buffer.extend_from_slice(fragment);
        if more {
            self.active = true;
            return Ok(None);
        }
        self.active = false;
        Ok(Some(std::mem::take(&mut self.buffer)))
    }

    /// A message is partially received (a `CopyData` now is a protocol error).
    pub fn in_progress(&self) -> bool {
        self.active
    }

    pub fn reset(&mut self) {
        self.buffer = Vec::new();
        self.active = false;
    }
}
