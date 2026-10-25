//! Share message codec (005 contracts/share-protocol.md "New payload types"): one complete
//! message per `ShareMsg` frame, `stype:u8 || rid:u32 || fields`, big-endian. Unknown types,
//! unknown abort reasons, wrong lengths and trailing bytes are protocol errors.

use std::fmt;

use crate::codec::MAX_FRAGMENT;
use crate::error::ProtocolError;

/// Largest `Pending.seconds_left` (the invitation validity).
pub const MAX_SECONDS_LEFT: u16 = 300;

/// Why an exchange ended (wire code in parentheses).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AbortReason {
    /// (1) no invitation for this device, wrong code, or already used.
    Invalid,
    /// (2) the person pressed Reject.
    Rejected,
    /// (3) cancelled by the sender.
    Cancelled,
    /// (4) expired before acceptance or transfer start.
    Expired,
    /// (5) no free transfer slot, or another exchange runs.
    Busy,
    /// (6) the recipient could not store the file.
    Storage,
    /// (7) size or received bytes above the bound.
    TooLarge,
    /// (8) the stored file changed or could not be read.
    SenderError,
    /// (9) the recipient cancelled.
    RecipientCancelled,
    /// (10) the recipient already holds the maximum of received wallets.
    ReceivedLimit,
}

impl AbortReason {
    pub fn code(self) -> u8 {
        match self {
            Self::Invalid => 1,
            Self::Rejected => 2,
            Self::Cancelled => 3,
            Self::Expired => 4,
            Self::Busy => 5,
            Self::Storage => 6,
            Self::TooLarge => 7,
            Self::SenderError => 8,
            Self::RecipientCancelled => 9,
            Self::ReceivedLimit => 10,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Invalid,
            2 => Self::Rejected,
            3 => Self::Cancelled,
            4 => Self::Expired,
            5 => Self::Busy,
            6 => Self::Storage,
            7 => Self::TooLarge,
            8 => Self::SenderError,
            9 => Self::RecipientCancelled,
            10 => Self::ReceivedLimit,
            _ => return None,
        })
    }
}

/// One share control message. `rid` identifies the exchange; neither it nor the proof is
/// shown by `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub enum ShareMsg {
    Redeem { rid: u32, proof: [u8; 32] },
    Pending { rid: u32, seconds_left: u16 },
    Offer { rid: u32, size: u32 },
    End { rid: u32 },
    Stored { rid: u32 },
    Abort { rid: u32, reason: AbortReason },
}

impl fmt::Debug for ShareMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Redeem { .. } => f.write_str("Redeem"),
            Self::Pending { seconds_left, .. } => write!(f, "Pending({seconds_left} s)"),
            Self::Offer { size, .. } => write!(f, "Offer({size} bytes)"),
            Self::End { .. } => f.write_str("End"),
            Self::Stored { .. } => f.write_str("Stored"),
            Self::Abort { reason, .. } => write!(f, "Abort({reason:?})"),
        }
    }
}

impl ShareMsg {
    pub fn rid(&self) -> u32 {
        match self {
            Self::Redeem { rid, .. }
            | Self::Pending { rid, .. }
            | Self::Offer { rid, .. }
            | Self::End { rid }
            | Self::Stored { rid }
            | Self::Abort { rid, .. } => *rid,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let (stype, rid) = match self {
            Self::Redeem { rid, .. } => (0x01, rid),
            Self::Pending { rid, .. } => (0x02, rid),
            Self::Offer { rid, .. } => (0x03, rid),
            Self::End { rid } => (0x04, rid),
            Self::Stored { rid } => (0x05, rid),
            Self::Abort { rid, .. } => (0x06, rid),
        };
        let mut out = Vec::with_capacity(37);
        out.push(stype);
        out.extend_from_slice(&rid.to_be_bytes());
        match self {
            Self::Redeem { proof, .. } => out.extend_from_slice(proof),
            Self::Pending { seconds_left, .. } => {
                out.extend_from_slice(&seconds_left.to_be_bytes())
            }
            Self::Offer { size, .. } => out.extend_from_slice(&size.to_be_bytes()),
            Self::End { .. } | Self::Stored { .. } => {}
            Self::Abort { reason, .. } => out.push(reason.code()),
        }
        out
    }

    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        if body.len() > MAX_FRAGMENT {
            return Err(ProtocolError);
        }
        let (&stype, rest) = body.split_first().ok_or(ProtocolError)?;
        let (rid, fields) = match rest {
            [a, b, c, d, fields @ ..] => (u32::from_be_bytes([*a, *b, *c, *d]), fields),
            _ => return Err(ProtocolError),
        };
        match (stype, fields) {
            (0x01, proof) if proof.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(proof);
                Ok(Self::Redeem { rid, proof: out })
            }
            (0x02, [hi, lo]) => {
                let seconds_left = u16::from_be_bytes([*hi, *lo]);
                if (1..=MAX_SECONDS_LEFT).contains(&seconds_left) {
                    Ok(Self::Pending { rid, seconds_left })
                } else {
                    Err(ProtocolError)
                }
            }
            // The size range (79..=64 MiB) is the recipient's decision: out of range is
            // answered with `Abort(too_large)`, not a protocol error (share-protocol.md step 3).
            (0x03, [a, b, c, d]) => Ok(Self::Offer {
                rid,
                size: u32::from_be_bytes([*a, *b, *c, *d]),
            }),
            (0x04, []) => Ok(Self::End { rid }),
            (0x05, []) => Ok(Self::Stored { rid }),
            (0x06, [code]) => AbortReason::from_code(*code)
                .map(|reason| Self::Abort { rid, reason })
                .ok_or(ProtocolError),
            _ => Err(ProtocolError),
        }
    }
}
