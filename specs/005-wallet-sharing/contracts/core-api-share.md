# Contract: additive API for sharing (wallet-sync, wallet-service, device-link, device-link-net)

Additive only; existing 001–004 signatures and behaviour are unchanged unless stated. The 004
`vault-core-sync-api.md` contract MUST be updated in the change that implements these items.
vault-core is unchanged. Rationale: [research.md](../research.md) R1, R3, R5–R11.

## wallet-sync (`share` module, sans-IO)

```rust
pub mod share {
    pub const INVITE_VALIDITY: Duration = Duration::from_secs(300);
    pub const MAX_RECEIVED: usize = 8;
    pub const RECEIVED_RETENTION_SECS: u64 = 86_400;

    /// HMAC-SHA-256 redemption proof (contracts/share-protocol.md).
    pub fn redeem_proof(code: &str, session: &[u8; 32], sender: &PeerId,
                        recipient: &PeerId, rid: u32) -> [u8; 32];

    pub enum ShareMsg { Redeem { rid: u32, proof: [u8; 32] }, Pending { rid: u32, seconds_left: u16 },
                        Offer { rid: u32, size: u32 }, End { rid: u32 }, Stored { rid: u32 },
                        Abort { rid: u32, reason: AbortReason } }
    impl ShareMsg { pub fn encode(&self) -> Vec<u8>; pub fn decode(body: &[u8]) -> Result<Self, ProtocolError>; }

    /// Non-secret metadata of one received file (no wallet name, id or state).
    pub struct ReceivedMeta { pub id: [u8; 16], pub sender: PeerId, pub received_at: u64, pub size: u64 }

    /// Start-up clean-up is the host's job (host-runtime-share.md, step 5e); the port has no
    /// clean-start method.
    pub trait ReceivedStore: Send + Sync {
        fn list(&self) -> Result<Vec<ReceivedMeta>, StoreError>;
        fn begin(&self, id: [u8; 16], sender: PeerId, received_at: u64)
            -> Result<Box<dyn IncomingCopy>, StoreError>;   // 004 writer trait
        fn read(&self, id: [u8; 16]) -> Result<Vec<u8>, StoreError>;
        fn delete(&self, id: [u8; 16]) -> Result<(), StoreError>;
    }

    pub struct ShareEngine { /* invitation, tombstone, redemption, per-channel exchanges */ }
    impl ShareEngine {
        pub fn new(deps: ShareDeps) -> Self;   // store, received, source, mono, wall, rng, slots
        // channel events (from the SyncFrameSink dispatch)
        pub fn channel_up(&mut self, peer: PeerId, conn: u64, session: [u8; 32], share: bool);
        pub fn channel_down(&mut self, peer: PeerId, conn: u64);
        pub fn on_msg(&mut self, peer: PeerId, conn: u64, msg: ShareMsg);
        pub fn on_data(&mut self, peer: PeerId, conn: u64, bytes: &[u8]);
        pub fn poll_outgoing(&mut self, peer: PeerId, max: usize) -> Vec<OutFrame>;
        // sender actions
        pub fn create(&mut self, wallet: InviteWallet, recipient: PeerId,
                      code: Zeroizing<String>) -> Result<(), CreateError>;
        pub fn cancel(&mut self) -> CancelOutcome;            // Cancelled | AlreadyDelivered | Nothing
        pub fn accept(&mut self, recipient: PeerId, eligible: &dyn Fn(&WalletName) -> bool)
            -> Result<(), AcceptError>;
        pub fn reject(&mut self) -> Result<(), RejectError>;
        pub fn wallet_locked(&mut self, wallet: &WalletName);
        pub fn peer_revoked(&mut self, peer: PeerId);
        // recipient actions
        pub fn redeem(&mut self, sender: Option<PeerId>, code: Zeroizing<String>) -> Result<(), RedeemError>;
        pub fn sender_channel(&mut self, peer: PeerId, conn: u64); // channel ensured for the redemption
        pub fn cancel_redemption(&mut self);
        // time and views
        pub fn tick(&mut self) -> Vec<ShareEvent>;            // sweeper; also returns log/notice events
        pub fn take_events(&mut self) -> Vec<ShareEvent>;
        pub fn view(&self) -> ShareView;                       // no code after redemption, no proof
    }

    /// Shared with the 004 Engine: service-wide transfer limit (2).
    pub struct TransferSlots { /* Mutex<usize>, max */ }
    impl TransferSlots { pub fn new(max: usize) -> Arc<Self>; pub fn try_take(self: &Arc<Self>) -> Option<SlotGuard>; }
}
```

`InviteWallet = { name: WalletName(String), id: WalletId }`; `create` checks eligibility through
`SyncStore::load` (record valid, not flagged, file digest equal) and the format (record exists
only for v2 after 004; a v1 file is refused as `format_v1`). The 004 `EngineDeps` gains
`slots: Arc<TransferSlots>` (default `TransferSlots::new(2)`), replacing its private counter with
identical behaviour.

Rules: `ShareEngine` never logs or exposes the code; `Debug` of every type omits codes, proofs and
`rid`. Received ids and `rid` come from the injected RNG.

## wallet-service

```rust
pub trait LockObserver: Send + Sync { fn locked(&self, name: &WalletName); }

impl Service {
    pub fn set_lock_observer(&self, observer: Arc<dyn LockObserver>);   // one observer
    /// Opens a received file with `password` and makes it a held, unlocked wallet named `name`.
    /// Order: validate name, not existing (create lock), KDF cap, derive (KDF gate), format 2,
    /// `decide(facts)`, store bytes verbatim, `PendingCopies::unlocked`, register unlocked.
    /// On any error nothing is written and the password is wiped.
    pub fn adopt_received(&self, name: &str, bytes: &[u8], password: Zeroizing<String>,
                          decide: &dyn Fn(&UnlockFacts) -> AdoptVerdict)
        -> Result<WalletName, ServiceError>;
}
pub enum AdoptVerdict { Proceed, AlreadyPresent(WalletName) }
// ServiceError gains: AlreadyPresent(WalletName)
```

`locked` is called after the slot is locked and zeroized, outside service locks, for manual,
all, idle, suspend and stop locks.

## device-link

```rust
pub enum HelloVersion { V1, V2, V3 }          // V3: Hello `PWSC || 3 || 1`, prologue `passwsync-channel-v3`
pub enum Payload { /* …, */ ShareMsg { body: Vec<u8> } /* 0x30 */, ShareData { bytes: Vec<u8> } /* 0x31 */ }
impl Channel { pub fn share_enabled(&self) -> bool; }   // true only for V3
```

`parse_hello_versioned` accepts `PWSC || 3 || 1`; the 003 `parse_hello` stays v1-only. Share
payloads on a channel below V3 → `Error::Protocol`.

## device-link-net

```rust
pub trait SyncFrameSink: Send + Sync {
    /* existing 004 methods unchanged */
    fn channel_version(&self, _peer: DeviceId, _conn: u64, _version: HelloVersion) {}  // NEW, default no-op
}
pub enum NetEvent { /* …, */ PeerNoShare(DeviceId) }  // NEW: v3 dial fell back to v2
impl Node {
    /// `send_sync` now also accepts ShareMsg/ShareData on V3 channels (else SendError::NotShareEnabled).
    pub fn send_sync(&self, peer: &DeviceId, conn: u64, payload: &Payload) -> Result<(), SendError>;
    /// Returns an existing channel to `expected`, or dials `hint` (address policy) / the peer's
    /// known address. With `expected = None` the responder's static must be a pinned key.
    pub fn ensure_channel(&self, expected: Option<DeviceId>, hint: Option<SocketAddrV4>)
        -> Result<(DeviceId, u64), EnsureError>;   // NotPaired | IdMismatch | Unreachable | NetworkOff | SelfDevice
}
```

`ensure_channel` blocks at most the 003 step timeouts per dial attempt and is called from a
short-lived worker, never from an HTTP handler thread for longer than that (the HTTP route
returns `202` at once).
