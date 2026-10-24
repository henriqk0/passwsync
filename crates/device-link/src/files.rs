//! Text codecs for the `device-key` and `peers` files (contracts/host-runtime-network.md).
//! Decoding is strict: any deviation is `Error::Malformed`.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::SocketAddrV4;

use zeroize::Zeroizing;

use crate::error::Error;
use crate::identity::{DeviceKey, decode_hex, decode_hex32, encode_hex};
use crate::name::DeviceName;
use crate::policy::AddressPolicy;
use crate::registry::{MAX_PINS, PeerPin};

const KEY_HEADER: &str = "passwsync-device-key-v1";
const PEERS_HEADER: &str = "passwsync-peers-v1";

pub fn encode_device_key(key: &DeviceKey) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(KEY_HEADER.len() + 66));
    text.push_str(KEY_HEADER);
    text.push('\n');
    let hex = Zeroizing::new(encode_hex(key.private_bytes()));
    text.push_str(&hex);
    text.push('\n');
    text
}

pub fn decode_device_key(bytes: &[u8]) -> Result<DeviceKey, Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Malformed)?;
    let rest = text
        .strip_prefix(KEY_HEADER)
        .and_then(|r| r.strip_prefix('\n'))
        .and_then(|r| r.strip_suffix('\n'))
        .ok_or(Error::Malformed)?;
    let private = Zeroizing::new(decode_hex32(rest).ok_or(Error::Malformed)?);
    Ok(DeviceKey::from_zeroizing(private))
}

pub fn encode_peers(pins: &[PeerPin]) -> String {
    let mut text = String::with_capacity(PEERS_HEADER.len() + 1 + pins.len() * 200);
    text.push_str(PEERS_HEADER);
    text.push('\n');
    for pin in pins {
        let last_seen = pin.last_seen.map_or("-".to_string(), |t| t.to_string());
        let last_addr = pin.last_addr.map_or("-".to_string(), |a| a.to_string());
        let _ = writeln!(
            text,
            "{} {} {} {} {}",
            encode_hex(&pin.public),
            pin.paired_at,
            last_seen,
            last_addr,
            encode_hex(pin.name.as_str().as_bytes())
        );
    }
    text
}

fn decimal(field: &str) -> Result<u64, Error> {
    if field.is_empty() || field.len() > 20 || !field.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Malformed);
    }
    field.parse().map_err(|_| Error::Malformed)
}

/// IPv4 literal `a.b.c.d:port` passing `policy`, port 1..=65535.
pub fn parse_peer_addr(field: &str, policy: AddressPolicy) -> Result<SocketAddrV4, Error> {
    let addr: SocketAddrV4 = field.parse().map_err(|_| Error::InvalidAddress)?;
    if addr.port() == 0 || !policy.allows_v4(*addr.ip()) || addr.to_string() != field {
        return Err(Error::InvalidAddress);
    }
    Ok(addr)
}

pub fn decode_peers(
    text: &str,
    own_public: &[u8; 32],
    policy: AddressPolicy,
) -> Result<Vec<PeerPin>, Error> {
    let body = text
        .strip_prefix(PEERS_HEADER)
        .and_then(|r| r.strip_prefix('\n'))
        .ok_or(Error::Malformed)?;
    if !body.is_empty() && !body.ends_with('\n') {
        return Err(Error::Malformed);
    }
    let mut pins = Vec::new();
    let mut seen = BTreeSet::new();
    for line in body.split_terminator('\n') {
        if pins.len() == MAX_PINS {
            return Err(Error::Malformed);
        }
        let fields: Vec<&str> = line.split(' ').collect();
        let [pk, paired, seen_at, addr, name] = fields.as_slice() else {
            return Err(Error::Malformed);
        };
        let public = decode_hex32(pk).ok_or(Error::Malformed)?;
        if &public == own_public || !seen.insert(public) {
            return Err(Error::Malformed);
        }
        let paired_at = decimal(paired)?;
        let last_seen = match *seen_at {
            "-" => None,
            other => Some(decimal(other)?),
        };
        let last_addr = match *addr {
            "-" => None,
            other => Some(parse_peer_addr(other, policy).map_err(|_| Error::Malformed)?),
        };
        let name_bytes = decode_hex(name).ok_or(Error::Malformed)?;
        let name = String::from_utf8(name_bytes).map_err(|_| Error::Malformed)?;
        let name = DeviceName::parse(&name).map_err(|_| Error::Malformed)?;
        pins.push(PeerPin {
            public,
            name,
            paired_at,
            last_seen,
            last_addr,
        });
    }
    Ok(pins)
}
