#![forbid(unsafe_code)]
//! Networking, identity reset and pairing (US4; contracts/ffi-api.md section 5, FR-037 to
//! FR-043, FR-050 to FR-053). Everything goes through the shared `NetRuntime`, exactly as the
//! desktop's HTTP handlers do; the node runs only in the foreground, during the linger after it
//! and during a background sync window.

use std::net::SocketAddrV4;
use std::sync::atomic::Ordering;
use std::time::Duration;

use device_link::code::normalize_code;
use device_link::identity::DeviceId;
use device_link::link::Warning;
use device_link::pairing::AcceptError;
use device_link_net::{JoinError, PairStartError, RevokeError, Snapshot};
use host_runtime::log::LogEvent;
use host_runtime::net_runtime::{IdentityStore, NetState};

use crate::api::{Inner, PasswsyncCore};
use crate::error::CoreError;
use crate::identity::{IDENTITY_FILE, PEERS_FILE, SealedIdentity};
use crate::lifecycle::linger_should_pause;
use crate::records::{
    CoreEvent, DeviceView, NearbyView, NetStateView, NetworkView, PairingState, PairingView,
    PeerView,
};
use crate::secret::SecretInput;

/// Fixed-token mapping of the 003 initiator and joiner states (tested in
/// `pairing_loopback.rs`).
pub fn pairing_state(word: &str) -> PairingState {
    match word {
        "waiting" | "connecting" | "exchanging" => PairingState::Waiting,
        "awaiting_acceptance" => PairingState::Confirming,
        "paired" => PairingState::Completed,
        _ => PairingState::Failed,
    }
}

fn pairing_error(reason: &'static str) -> CoreError {
    CoreError::Pairing { reason }
}

/// A device id typed or chosen in the UI; anything else is `device_not_found`.
pub(crate) fn device_id(text: &str) -> Result<DeviceId, CoreError> {
    DeviceId::from_hex(text).map_err(|_| pairing_error("device_not_found"))
}

pub(crate) fn device_view(id: &DeviceId, name: Option<&str>) -> DeviceView {
    DeviceView {
        id: id.to_hex(),
        fingerprint: id.fingerprint().to_string(),
        name: name.unwrap_or("unknown device").to_owned(),
    }
}

impl Inner {
    /// The node's snapshot, or an empty one while it does not run.
    pub(crate) fn snapshot(&self) -> Snapshot {
        self.host.net.snapshot().unwrap_or_default()
    }

    /// The name of a paired device, when known.
    pub(crate) fn peer_name(&self, id: &DeviceId) -> Option<String> {
        self.snapshot()
            .paired
            .iter()
            .find(|p| p.id == *id)
            .map(|p| p.name.as_str().to_owned())
    }

    /// A transfer (sync round, invitation or redemption) is running.
    pub(crate) fn transfer_running(&self) -> bool {
        if !self.host.sync.running().is_empty() {
            return true;
        }
        let view = self.host.share.core().engine().view();
        view.invitation
            .as_ref()
            .is_some_and(|i| i.state == "transferring")
            || view
                .receive
                .as_ref()
                .is_some_and(|r| r.state == "receiving")
    }

    /// One linger check of the sweeper thread (FR-042).
    pub(crate) fn linger_check(&self, elapsed: Duration) {
        if self.window_running.load(Ordering::SeqCst) {
            return;
        }
        if linger_should_pause(
            elapsed,
            self.transfer_running(),
            self.linger,
            self.transfer_cap,
        ) {
            self.host.net.pause();
            self.lifecycle().end_linger();
            self.notify(CoreEvent::NetworkChanged);
        }
    }

    fn net_state(&self) -> NetStateView {
        let net = &self.host.net;
        if net.is_paused() {
            return NetStateView::Paused;
        }
        match net.state() {
            NetState::Off => NetStateView::Off,
            NetState::IdentityUnusable => NetStateView::IdentityUnusable,
            NetState::PeersUnusable => NetStateView::PeersUnusable,
            NetState::PortInUse(_) => NetStateView::PortInUse,
            NetState::NoLocalNetwork => NetStateView::NoLocalNetwork,
            NetState::On if self.eligible.is_empty() => NetStateView::NoLocalNetwork,
            NetState::On => NetStateView::On,
        }
    }

    fn pairing_view(&self) -> PairingView {
        let snapshot = self.snapshot();
        if let Some(init) = snapshot.pairing.as_ref() {
            return PairingView {
                state: pairing_state(init.state),
                code: init.code.as_ref().map(|digits| digits.as_str().to_owned()),
                peer: init
                    .peer
                    .as_ref()
                    .map(|p| device_view(&p.id, Some(p.name.as_str()))),
                expires_in_ms: init.expires_in.saturating_mul(1000),
            };
        }
        if let Some(join) = snapshot.join.as_ref() {
            return PairingView {
                state: pairing_state(join.state),
                code: None,
                peer: join
                    .peer
                    .as_ref()
                    .map(|id| device_view(id, join.peer_name.as_ref().map(|n| n.as_str()))),
                expires_in_ms: join.seconds_left.map_or(0, |s| u64::from(s) * 1000),
            };
        }
        PairingView {
            state: PairingState::Idle,
            code: None,
            peer: None,
            expires_in_ms: 0,
        }
    }
}

#[uniffi::export]
impl PasswsyncCore {
    /// Networking state, this device, nearby and paired devices (FR-038 to FR-041).
    pub fn network(&self) -> NetworkView {
        let core = &self.inner;
        let snapshot = core.snapshot();
        let share = core.host.share.core();
        NetworkView {
            state: core.net_state(),
            this_device: core
                .host
                .net
                .this_device
                .as_ref()
                .map(|d| device_view(&d.id, Some(d.name.as_str()))),
            nearby: snapshot
                .nearby
                .iter()
                .map(|n| NearbyView {
                    device: device_view(
                        &n.id,
                        snapshot
                            .paired
                            .iter()
                            .find(|p| p.id == n.id)
                            .map(|p| p.name.as_str()),
                    ),
                    address: n.addr.to_string(),
                    paired: n.paired,
                })
                .collect(),
            paired: snapshot
                .paired
                .iter()
                .map(|p| PeerView {
                    device: device_view(&p.id, Some(p.name.as_str())),
                    status: p.status.as_str().to_owned(),
                    share: share.peer_share(&p.id).to_owned(),
                })
                .collect(),
            warnings: snapshot
                .warnings
                .iter()
                .map(|w| match w {
                    Warning::UnpairedKeyAtAddress { .. } => "unpaired_key_at_address".to_owned(),
                })
                .collect(),
        }
    }

    /// The networking switch; switching on needs the confirmation. Applies at the next start.
    pub fn set_networking(&self, enabled: bool, confirmed: bool) -> Result<(), CoreError> {
        if enabled && !confirmed {
            return Err(CoreError::InvalidInput);
        }
        self.inner
            .save_settings(|settings| settings.network.enabled = enabled)
    }

    /// The interfaces Kotlin's `NetworkClassifier` marked local Wi-Fi or Ethernet (FR-039).
    pub fn set_eligible_interfaces(&self, names: Vec<String>) {
        let core = &self.inner;
        core.eligible.set_names(&names);
        let net = &core.host.net;
        if core.eligible.is_empty() {
            if net.node().is_some() {
                // Closes every socket and waits for a local network (retried on tick).
                net.pause();
                net.resume();
            }
        } else if !net.is_paused() && net.state() == NetState::NoLocalNetwork {
            net.tick(core.elapsed.monotonic());
        }
        core.notify(CoreEvent::NetworkChanged);
    }

    /// True exactly while the node runs; Kotlin holds the `MulticastLock` then (FR-043).
    pub fn multicast_wanted(&self) -> bool {
        self.inner.host.net.node().is_some()
    }

    /// New identity: Keystore key regenerated, new device key, no pins; the networking
    /// setting and the wallets stay as they are; the new identity is used from the next
    /// start (FR-037).
    pub fn reset_identity(&self) -> Result<(), CoreError> {
        let core = &self.inner;
        core.require_foreground()?;
        core.sealer.reset().map_err(|_| CoreError::Platform)?;
        core.host.sync.stop();
        core.host.net.stop();
        for file in [IDENTITY_FILE, PEERS_FILE] {
            match std::fs::remove_file(core.dirs.root.join(file)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(CoreError::Storage),
            }
        }
        let identity = SealedIdentity::new(&core.dirs.root, std::sync::Arc::clone(&core.sealer));
        drop(
            identity
                .load_or_create_key()
                .map_err(|_| CoreError::IdentityUnusable)?,
        );
        core.save_settings(|_| {})?;
        core.log.emit(&LogEvent::IdentityReset);
        core.notify(CoreEvent::NetworkChanged);
        Ok(())
    }

    /// Shows a pairing code (003 initiator). No wallet is needed.
    pub fn start_pairing(&self) -> Result<PairingView, CoreError> {
        let core = &self.inner;
        core.require_foreground()?;
        match core.host.net.start_pairing() {
            Err(_) => Err(CoreError::NetworkOff),
            Ok(Err(PairStartError::Busy)) => Err(CoreError::Busy),
            Ok(Err(PairStartError::Limit)) => Err(pairing_error("pair_limit")),
            Ok(Err(PairStartError::TooManyCodes)) => Err(pairing_error("too_many_codes")),
            Ok(Err(PairStartError::Random)) => Err(CoreError::Internal),
            Ok(Ok(())) => {
                core.notify(CoreEvent::PairingChanged);
                Ok(core.pairing_view())
            }
        }
    }

    /// Joins the nearby device `peer_id` with the code it shows (003 joiner).
    pub fn join_pairing(&self, peer_id: String, code: Vec<u8>) -> Result<(), CoreError> {
        let code = SecretInput::try_from(code)?;
        let core = &self.inner;
        core.require_foreground()?;
        let digits = normalize_code(code.as_str()).map_err(|_| pairing_error("invalid_code"))?;
        drop(code);
        let id = device_id(&peer_id)?;
        let addr: SocketAddrV4 = core
            .snapshot()
            .nearby
            .iter()
            .find(|n| n.id == id)
            .map(|n| n.addr)
            .ok_or_else(|| pairing_error("not_nearby"))?;
        match core.host.net.join(addr, &digits, Some(id)) {
            Err(_) => Err(CoreError::NetworkOff),
            Ok(Ok(())) => {
                core.notify(CoreEvent::PairingChanged);
                Ok(())
            }
            Ok(Err(JoinError::InvalidAddress)) => Err(pairing_error("invalid_address")),
            Ok(Err(JoinError::InvalidCode)) => Err(pairing_error("invalid_code")),
            Ok(Err(JoinError::Busy)) => Err(CoreError::Busy),
            Ok(Err(JoinError::AlreadyPaired)) => Err(pairing_error("already_paired")),
            Ok(Err(JoinError::Limit)) => Err(pairing_error("pair_limit")),
            Ok(Err(JoinError::SelfPair)) => Err(pairing_error("self")),
        }
    }

    /// The initiator accepts the device awaiting acceptance after comparing fingerprints.
    pub fn accept_pairing(&self, peer_id: String) -> Result<(), CoreError> {
        let core = &self.inner;
        core.require_foreground()?;
        let id = device_id(&peer_id)?;
        match core.host.net.accept(&id) {
            Ok(_) => {
                core.notify(CoreEvent::PairingChanged);
                core.notify(CoreEvent::NetworkChanged);
                Ok(())
            }
            Err(AcceptError::NothingPending) => Err(pairing_error("nothing_pending")),
            Err(AcceptError::Mismatch) => Err(pairing_error("pairing_mismatch")),
            Err(AcceptError::Expired) => Err(pairing_error("expired")),
            Err(AcceptError::Storage) => Err(CoreError::Storage),
        }
    }

    /// The initiator refuses the device awaiting acceptance.
    pub fn reject_pairing(&self) {
        self.inner.host.net.reject();
        self.inner.notify(CoreEvent::PairingChanged);
    }

    /// Ends the shown code.
    pub fn cancel_pairing(&self) {
        self.inner.host.net.cancel_pairing();
        self.inner.notify(CoreEvent::PairingChanged);
    }

    /// The current pairing as the UI shows it.
    pub fn pairing(&self) -> PairingView {
        self.inner.pairing_view()
    }

    /// Removes the pin, closes the channel, ends sync with it and deletes its unopened
    /// received wallets (003 + 004 + 005).
    pub fn revoke_device(&self, peer_id: String) -> Result<(), CoreError> {
        let core = &self.inner;
        core.require_foreground()?;
        let id = device_id(&peer_id)?;
        match core.host.net.revoke(&id) {
            Ok(()) => {
                core.host.sync.revoke(&id);
                core.host.share.peer_revoked(&id);
                core.notify(CoreEvent::NetworkChanged);
                Ok(())
            }
            Err(RevokeError::NotFound) => Err(pairing_error("device_not_found")),
            Err(RevokeError::Storage) => Err(CoreError::Storage),
        }
    }
}
