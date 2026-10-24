//! LAN peer protocol v1 wire format (contracts/peer-protocol.md): frames, Hello, payloads.

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
    let k = match kind {
        HelloKind::Channel => 1,
        HelloKind::Pairing => 2,
    };
    [b'P', b'W', b'S', b'C', 1, k]
}

pub fn parse_hello(body: &[u8]) -> Result<HelloKind, Error> {
    match body {
        [b'P', b'W', b'S', b'C', 1, 1] => Ok(HelloKind::Channel),
        [b'P', b'W', b'S', b'C', 1, 2] => Ok(HelloKind::Pairing),
        _ => Err(Error::Protocol),
    }
}

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
    PairHello { name: DeviceName },
    PairPending { seconds_left: u16 },
    PairCommit { name: DeviceName },
    PairReject { reason: RejectReason },
    PairAck,
    ChannelHello { name: DeviceName },
    Welcome { name: DeviceName },
    Refused,
    Keepalive,
    NameUpdate { name: DeviceName },
    Close { reason: CloseReason },
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
        }
        out
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
