//! LAN peer protocol wire format (003 contracts/peer-protocol.md, extended by 004
//! contracts/sync-protocol.md): frames, Hello, payloads.

use crate::error::Error;
use crate::name::DeviceName;

/// Largest frame body in this protocol version.
pub const MAX_FRAME: usize = 1024;
pub const HELLO_LEN: usize = 6;

/// Validates a frame length header.
pub fn frame_len(header: [u8; 2]) -> Result<usize, Error> {
    let len = usize::from(u16::from_be_bytes(header));
    if (1..=MAX_FRAME).contains(&len) {
        Ok(len)
    } else {
        Err(Error::Protocol)
    }
}

pub fn encode_frame(body: &[u8]) -> Result<Vec<u8>, Error> {
    if body.is_empty() || body.len() > MAX_FRAME {
        return Err(Error::Protocol);
    }
    let mut out = Vec::with_capacity(body.len() + 2);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// `Ok(None)` while incomplete; otherwise the body and the bytes consumed.
pub fn decode_frame(buf: &[u8]) -> Result<Option<(&[u8], usize)>, Error> {
    let Some(header) = buf.get(..2) else {
        return Ok(None);
    };
    let len = frame_len([header[0], header[1]])?;
    Ok(buf.get(2..2 + len).map(|body| (body, 2 + len)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelloKind {
    Channel,
    Pairing,
}

pub fn hello(kind: HelloKind) -> [u8; HELLO_LEN] {
    hello_versioned(kind, HelloVersion::V1)
}

/// 003 parser: version 1 only (a v1 device rejects version 2 before any crypto, 004 R7).
pub fn parse_hello(body: &[u8]) -> Result<HelloKind, Error> {
    match parse_hello_versioned(body)? {
        (kind, HelloVersion::V1) => Ok(kind),
        _ => Err(Error::Protocol),
    }
}

/// Channel protocol version announced in the Hello (004, contracts/sync-protocol.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HelloVersion {
    /// 003: maintenance messages only.
    V1,
    /// 004: v1 plus the sync payload types 0x20 and 0x21.
    V2,
    /// 005: v2 plus the share payload types 0x30 and 0x31.
    V3,
}

/// `PWSC || version || kind`. Pairing exists only in version 1.
pub fn hello_versioned(kind: HelloKind, version: HelloVersion) -> [u8; HELLO_LEN] {
    let k = match kind {
        HelloKind::Channel => 1,
        HelloKind::Pairing => 2,
    };
    let v = match version {
        HelloVersion::V1 => 1,
        HelloVersion::V2 => 2,
        HelloVersion::V3 => 3,
    };
    [b'P', b'W', b'S', b'C', v, k]
}

/// Accepts channel Hello v1, v2 and v3 and pairing Hello v1.
pub fn parse_hello_versioned(body: &[u8]) -> Result<(HelloKind, HelloVersion), Error> {
    match body {
        [b'P', b'W', b'S', b'C', 1, 1] => Ok((HelloKind::Channel, HelloVersion::V1)),
        [b'P', b'W', b'S', b'C', 1, 2] => Ok((HelloKind::Pairing, HelloVersion::V1)),
        [b'P', b'W', b'S', b'C', 2, 1] => Ok((HelloKind::Channel, HelloVersion::V2)),
        [b'P', b'W', b'S', b'C', 3, 1] => Ok((HelloKind::Channel, HelloVersion::V3)),
        _ => Err(Error::Protocol),
    }
}

/// Largest `SyncCtl` fragment or `CopyData` chunk (fits a 1024-byte frame with the AEAD tag).
pub const MAX_SYNC_CHUNK: usize = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    Rejected = 1,
    Expired = 2,
    SelfPair = 3,
    AlreadyPaired = 4,
    Limit = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    Shutdown = 1,
    Duplicate = 2,
}

/// Messages carried inside Noise (never in clear).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    PairHello {
        name: DeviceName,
    },
    PairPending {
        seconds_left: u16,
    },
    PairCommit {
        name: DeviceName,
    },
    PairReject {
        reason: RejectReason,
    },
    PairAck,
    ChannelHello {
        name: DeviceName,
    },
    Welcome {
        name: DeviceName,
    },
    Refused,
    Keepalive,
    NameUpdate {
        name: DeviceName,
    },
    Close {
        reason: CloseReason,
    },
    /// 004 (channel v2 only): one fragment of a sync control message.
    SyncCtl {
        more: bool,
        fragment: Vec<u8>,
    },
    /// 004 (channel v2 only): a chunk of the sender's current wallet-copy transfer.
    CopyData {
        bytes: Vec<u8>,
    },
    /// 005 (channel v3 only): one complete share message (opaque here, 1..=1000 bytes).
    ShareMsg {
        body: Vec<u8>,
    },
    /// 005 (channel v3 only): a chunk of the sender's current share transfer (1..=1000 bytes).
    ShareData {
        bytes: Vec<u8>,
    },
}

fn push_name(out: &mut Vec<u8>, name: &DeviceName) {
    let bytes = name.as_str().as_bytes();
    // DeviceName guarantees <= 64 scalars, i.e. <= 256 bytes; names over 255 bytes cannot be
    // built from 64 scalars of at most 4 bytes each except at exactly 256, refused at parse.
    out.push(bytes.len().min(255) as u8);
    out.extend_from_slice(&bytes[..bytes.len().min(255)]);
}

impl Payload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        match self {
            Self::PairHello { name } => {
                out.push(0x01);
                push_name(&mut out, name);
            }
            Self::PairPending { seconds_left } => {
                out.push(0x02);
                out.extend_from_slice(&seconds_left.to_be_bytes());
            }
            Self::PairCommit { name } => {
                out.push(0x03);
                push_name(&mut out, name);
            }
            Self::PairReject { reason } => out.extend_from_slice(&[0x04, *reason as u8]),
            Self::PairAck => out.push(0x05),
            Self::ChannelHello { name } => {
                out.push(0x10);
                push_name(&mut out, name);
            }
            Self::Welcome { name } => {
                out.push(0x11);
                push_name(&mut out, name);
            }
            Self::Refused => out.push(0x12),
            Self::Keepalive => out.push(0x13),
            Self::NameUpdate { name } => {
                out.push(0x14);
                push_name(&mut out, name);
            }
            Self::Close { reason } => out.extend_from_slice(&[0x15, *reason as u8]),
            Self::SyncCtl { more, fragment } => {
                out.reserve(fragment.len() + 2);
                out.push(0x20);
                out.push(u8::from(*more));
                out.extend_from_slice(fragment);
            }
            Self::CopyData { bytes } => {
                out.reserve(bytes.len() + 1);
                out.push(0x21);
                out.extend_from_slice(bytes);
            }
            Self::ShareMsg { body } => {
                out.reserve(body.len() + 1);
                out.push(0x30);
                out.extend_from_slice(body);
            }
            Self::ShareData { bytes } => {
                out.reserve(bytes.len() + 1);
                out.push(0x31);
                out.extend_from_slice(bytes);
            }
        }
        out
    }

    /// Channel v2 decoding: the 003 set plus `SyncCtl` and `CopyData` (1..=1000 bytes).
    pub fn decode_v2(bytes: &[u8]) -> Result<Self, Error> {
        let chunk_ok = |chunk: &[u8]| (1..=MAX_SYNC_CHUNK).contains(&chunk.len());
        match bytes {
            [0x20, more @ (0 | 1), fragment @ ..] if chunk_ok(fragment) => Ok(Self::SyncCtl {
                more: *more == 1,
                fragment: fragment.to_vec(),
            }),
            [0x20, ..] => Err(Error::Protocol),
            [0x21, data @ ..] if chunk_ok(data) => Ok(Self::CopyData {
                bytes: data.to_vec(),
            }),
            [0x21, ..] => Err(Error::Protocol),
            _ => Self::decode(bytes),
        }
    }

    /// Channel v3 decoding: the v2 set plus `ShareMsg` and `ShareData` (1..=1000 bytes).
    pub fn decode_v3(bytes: &[u8]) -> Result<Self, Error> {
        let chunk_ok = |chunk: &[u8]| (1..=MAX_SYNC_CHUNK).contains(&chunk.len());
        match bytes {
            [0x30, body @ ..] if chunk_ok(body) => Ok(Self::ShareMsg {
                body: body.to_vec(),
            }),
            [0x31, data @ ..] if chunk_ok(data) => Ok(Self::ShareData {
                bytes: data.to_vec(),
            }),
            [0x30 | 0x31, ..] => Err(Error::Protocol),
            _ => Self::decode_v2(bytes),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (&kind, rest) = bytes.split_first().ok_or(Error::Protocol)?;
        let name = |rest: &[u8]| -> Result<DeviceName, Error> {
            let (&len, text) = rest.split_first().ok_or(Error::Protocol)?;
            if text.len() != usize::from(len) {
                return Err(Error::Protocol);
            }
            let text = std::str::from_utf8(text).map_err(|_| Error::Protocol)?;
            DeviceName::parse(text).map_err(|_| Error::Protocol)
        };
        let empty = |rest: &[u8], value: Self| {
            if rest.is_empty() {
                Ok(value)
            } else {
                Err(Error::Protocol)
            }
        };
        match kind {
            0x01 => Ok(Self::PairHello { name: name(rest)? }),
            0x02 => match rest {
                [hi, lo] => Ok(Self::PairPending {
                    seconds_left: u16::from_be_bytes([*hi, *lo]),
                }),
                _ => Err(Error::Protocol),
            },
            0x03 => Ok(Self::PairCommit { name: name(rest)? }),
            0x04 => {
                let reason = match rest {
                    [1] => RejectReason::Rejected,
                    [2] => RejectReason::Expired,
                    [3] => RejectReason::SelfPair,
                    [4] => RejectReason::AlreadyPaired,
                    [5] => RejectReason::Limit,
                    _ => return Err(Error::Protocol),
                };
                Ok(Self::PairReject { reason })
            }
            0x05 => empty(rest, Self::PairAck),
            0x10 => Ok(Self::ChannelHello { name: name(rest)? }),
            0x11 => Ok(Self::Welcome { name: name(rest)? }),
            0x12 => empty(rest, Self::Refused),
            0x13 => empty(rest, Self::Keepalive),
            0x14 => Ok(Self::NameUpdate { name: name(rest)? }),
            0x15 => {
                let reason = match rest {
                    [1] => CloseReason::Shutdown,
                    [2] => CloseReason::Duplicate,
                    _ => return Err(Error::Protocol),
                };
                Ok(Self::Close { reason })
            }
            _ => Err(Error::Protocol),
        }
    }
}
