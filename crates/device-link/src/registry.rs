//! Trusted peers: pins and the registry (data-model.md "PeerPin").

use std::net::SocketAddrV4;

use crate::identity::DeviceId;
use crate::name::DeviceName;

pub const MAX_PINS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerPin {
    /// The pinned key; never replaced (FR-028).
    pub public: [u8; 32],
    pub name: DeviceName,
    pub paired_at: u64,
    pub last_seen: Option<u64>,
    pub last_addr: Option<SocketAddrV4>,
}

impl PeerPin {
    pub fn id(&self) -> DeviceId {
        DeviceId::from_public(&self.public)
    }
}

use std::sync::Arc;

use crate::error::Error;
use crate::ports::PeerStore;

/// At most [`MAX_PINS`] pins keyed by device ID. Every change is saved through the store
/// before it takes effect; a failed save changes nothing.
pub struct PeerRegistry {
    own_public: [u8; 32],
    pins: Vec<PeerPin>,
    store: Arc<dyn PeerStore>,
}

impl PeerRegistry {
    pub fn load(own_public: [u8; 32], store: Arc<dyn PeerStore>) -> Result<Self, Error> {
        let pins = store.load()?;
        Ok(Self {
            own_public,
            pins,
            store,
        })
    }

    pub fn own_id(&self) -> DeviceId {
        DeviceId::from_public(&self.own_public)
    }

    pub fn len(&self) -> usize {
        self.pins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.pins.len() >= MAX_PINS
    }

    pub fn list(&self) -> &[PeerPin] {
        &self.pins
    }

    pub fn get(&self, id: &DeviceId) -> Option<&PeerPin> {
        self.pins.iter().find(|p| p.id() == *id)
    }

    pub fn contains(&self, id: &DeviceId) -> bool {
        self.get(id).is_some()
    }

    pub fn is_pinned_key(&self, public: &[u8; 32]) -> bool {
        use subtle::ConstantTimeEq;
        self.pins.iter().any(|p| bool::from(p.public.ct_eq(public)))
    }

    pub fn find_by_addr(&self, addr: SocketAddrV4) -> Option<&PeerPin> {
        self.pins.iter().find(|p| p.last_addr == Some(addr))
    }

    /// Checks the pin rules without changing anything.
    pub fn check_new(&self, public: &[u8; 32]) -> Result<(), Error> {
        if public == &self.own_public {
            return Err(Error::SelfPair);
        }
        if self.is_pinned_key(public) || self.contains(&DeviceId::from_public(public)) {
            return Err(Error::AlreadyPaired);
        }
        if self.is_full() {
            return Err(Error::Limit);
        }
        Ok(())
    }

    pub fn pin(&mut self, pin: PeerPin) -> Result<(), Error> {
        self.check_new(&pin.public)?;
        let mut next = self.pins.clone();
        next.push(pin);
        self.store.save(&next)?;
        self.pins = next;
        Ok(())
    }

    pub fn revoke(&mut self, id: &DeviceId) -> Result<PeerPin, Error> {
        let index = self
            .pins
            .iter()
            .position(|p| p.id() == *id)
            .ok_or(Error::NotFound)?;
        let mut next = self.pins.clone();
        let removed = next.remove(index);
        self.store.save(&next)?;
        self.pins = next;
        Ok(removed)
    }

    /// Name changes arrive only over an authenticated channel; saved at once.
    pub fn update_name(&mut self, id: &DeviceId, name: DeviceName) -> Result<(), Error> {
        let index = self
            .pins
            .iter()
            .position(|p| p.id() == *id)
            .ok_or(Error::NotFound)?;
        let mut next = self.pins.clone();
        next[index].name = name;
        self.store.save(&next)?;
        self.pins = next;
        Ok(())
    }

    /// In memory only (saved by [`Self::persist`] on close and stop, not on every message).
    pub fn touch(&mut self, id: &DeviceId, now_unix: u64, addr: Option<SocketAddrV4>) {
        if let Some(pin) = self.pins.iter_mut().find(|p| p.id() == *id) {
            pin.last_seen = Some(now_unix);
            if addr.is_some() {
                pin.last_addr = addr;
            }
        }
    }

    /// Records where a pin was reached after an authenticated pairing, in memory only.
    /// Never fed from unauthenticated announcements (FR-014).
    pub fn note_addr(&mut self, id: &DeviceId, addr: SocketAddrV4) {
        if let Some(pin) = self.pins.iter_mut().find(|p| p.id() == *id) {
            pin.last_addr = Some(addr);
        }
    }

    pub fn persist(&self) -> Result<(), Error> {
        self.store.save(&self.pins)
    }
}
