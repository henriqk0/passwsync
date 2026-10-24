//! Discovery datagram codec and the nearby list (research R6, FR-014..FR-016). Announcements
//! are untrusted hints: they never create trust and never mark a device as paired.

use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::time::Duration;

use crate::error::DropReason;
use crate::identity::DeviceId;
use crate::policy::AddressPolicy;

pub const ANNOUNCE_LEN: usize = 39;
pub const MAX_NEARBY: usize = 64;
const MAGIC: &[u8; 5] = b"PWSD\x01";

pub fn encode_announce(id: &DeviceId, peer_port: u16) -> [u8; ANNOUNCE_LEN] {
    let mut out = [0u8; ANNOUNCE_LEN];
    out[..5].copy_from_slice(MAGIC);
    out[5..37].copy_from_slice(id.as_bytes());
    out[37..].copy_from_slice(&peer_port.to_be_bytes());
    out
}

/// Exactly 39 bytes, the right magic and version, a port of at least 1024, not our own ID.
pub fn decode_announce(bytes: &[u8], own: &DeviceId) -> Result<(DeviceId, u16), DropReason> {
    if bytes.len() != ANNOUNCE_LEN || &bytes[..5] != MAGIC {
        return Err(DropReason::Malformed);
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&bytes[5..37]);
    let id = DeviceId::from_bytes(raw);
    let port = u16::from_be_bytes([bytes[37], bytes[38]]);
    if port < 1024 || id == *own {
        return Err(DropReason::Malformed);
    }
    Ok((id, port))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NearbyDevice {
    pub id: DeviceId,
    pub addr: SocketAddrV4,
    pub paired: bool,
}

#[derive(Clone, Copy, Debug)]
struct Heard {
    addr: SocketAddrV4,
    last_heard: Duration,
    paired: bool,
}

/// At most [`MAX_NEARBY`] non-paired entries (paired peers never take those slots, so a
/// flood cannot hide them); entries expire `expiry` after they were last heard.
pub struct NearbyList {
    expiry: Duration,
    policy: AddressPolicy,
    entries: BTreeMap<DeviceId, Heard>,
}

impl NearbyList {
    pub fn new(expiry: Duration, policy: AddressPolicy) -> Self {
        Self {
            expiry,
            policy,
            entries: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Records an announcement from `source` (its IP plus the announced peer port).
    pub fn observe(
        &mut self,
        id: DeviceId,
        source: SocketAddrV4,
        peer_port: u16,
        now: Duration,
        paired: bool,
    ) -> Result<SocketAddrV4, DropReason> {
        if !self.policy.allows_v4(*source.ip()) {
            return Err(DropReason::Public);
        }
        let addr = SocketAddrV4::new(*source.ip(), peer_port);
        let unpaired = self.entries.values().filter(|h| !h.paired).count();
        match self.entries.get_mut(&id) {
            Some(heard) => {
                heard.addr = addr;
                heard.last_heard = now;
                heard.paired = paired;
            }
            None if !paired && unpaired >= MAX_NEARBY => return Err(DropReason::Overflow),
            None => {
                self.entries.insert(
                    id,
                    Heard {
                        addr,
                        last_heard: now,
                        paired,
                    },
                );
            }
        }
        Ok(addr)
    }

    pub fn expire(&mut self, now: Duration) {
        let expiry = self.expiry;
        self.entries
            .retain(|_, heard| now.saturating_sub(heard.last_heard) < expiry);
    }

    pub fn remove(&mut self, id: &DeviceId) {
        self.entries.remove(id);
    }

    /// Current entries; `is_paired` (the registry) decides the paired flag.
    pub fn views(&self, now: Duration, is_paired: impl Fn(&DeviceId) -> bool) -> Vec<NearbyDevice> {
        self.entries
            .iter()
            .filter(|(_, heard)| now.saturating_sub(heard.last_heard) < self.expiry)
            .map(|(id, heard)| NearbyDevice {
                id: *id,
                addr: heard.addr,
                paired: is_paired(id),
            })
            .collect()
    }
}
