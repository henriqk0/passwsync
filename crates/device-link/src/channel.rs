//! Secure channel between paired devices (research R2): `Noise_XX_25519_ChaChaPoly_BLAKE2s`
//! via `snow`, prologue `passwsync-channel-v1 || Hello`. The dialer checks the responder's
//! static key against the pin before revealing its own; the responder answers `Welcome`
//! only to a pinned key, else one `Refused`. After that only `Keepalive`, `NameUpdate` and
//! `Close` are accepted (FR-031); any AEAD failure ends the channel (FR-027).

use snow::{HandshakeState, TransportState};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::identity::{DeviceId, DeviceKey};
use crate::name::DeviceName;
use crate::noise;
use crate::pairing::{CHANNEL_PROLOGUE, CHANNEL_PROLOGUE_V2, CHANNEL_PROLOGUE_V3, NOISE_CHANNEL};
use crate::wire::{
    HelloKind, HelloVersion, MAX_FRAME, Payload, hello_versioned, parse_hello_versioned,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelError {
    /// The responder at the pinned peer's address proved a different key (dialer side).
    KeyMismatch { presented: DeviceId },
    /// The dialer's key is not pinned (responder side); `Refused` was queued.
    Unpaired { presented: DeviceId },
    /// The peer answered `Refused` (dialer side).
    Refused,
    /// Authentication failure: tamper, replay, reorder, wrong keys.
    Crypto,
    /// Malformed or unexpected message.
    Protocol,
}

/// An authenticated channel (transport phase).
pub struct Channel {
    transport: Box<TransportState>,
    peer_public: [u8; 32],
    peer_name: DeviceName,
    dialer_id: DeviceId,
    is_dialer: bool,
    closed: bool,
    /// 004: Hello version of this channel (v2 carries sync frames).
    version: HelloVersion,
    /// 004: Noise handshake hash, equal on both ends and unique per session (R9).
    session: [u8; 32],
}

/// Shows only public facts; never key material.
impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("peer", &self.peer_id())
            .field("dialer", &self.dialer_id)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl Channel {
    pub fn peer_public(&self) -> &[u8; 32] {
        &self.peer_public
    }

    pub fn peer_id(&self) -> DeviceId {
        DeviceId::from_public(&self.peer_public)
    }

    pub fn peer_name(&self) -> &DeviceName {
        &self.peer_name
    }

    /// The device that opened the connection (used to resolve duplicates, FR-029).
    pub fn dialer_id(&self) -> DeviceId {
        self.dialer_id
    }

    pub fn is_dialer(&self) -> bool {
        self.is_dialer
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// 004: whether this channel was negotiated with Hello v2 or v3 (sync frames allowed).
    pub fn sync_enabled(&self) -> bool {
        matches!(self.version, HelloVersion::V2 | HelloVersion::V3)
    }

    /// 005: whether this channel was negotiated with Hello v3 (share frames allowed).
    pub fn share_enabled(&self) -> bool {
        self.version == HelloVersion::V3
    }

    /// The Hello version this channel was negotiated with.
    pub fn version(&self) -> HelloVersion {
        self.version
    }

    /// 004: the Noise handshake hash (32 bytes), equal on both ends, different per session.
    /// Not secret; binds sync tags to this session.
    pub fn session_hash(&self) -> [u8; 32] {
        self.session
    }

    /// 004: encrypts a `SyncCtl` or `CopyData` payload; only on a sync-enabled channel.
    /// 005: also `ShareMsg` / `ShareData`, only on a share-enabled (v3) channel.
    pub fn seal_sync(&mut self, payload: &Payload) -> Result<Vec<u8>, ChannelError> {
        let chunk_ok = |len: usize| (1..=crate::wire::MAX_SYNC_CHUNK).contains(&len);
        let valid = match payload {
            Payload::SyncCtl { fragment, .. } => chunk_ok(fragment.len()) && self.sync_enabled(),
            Payload::CopyData { bytes } => chunk_ok(bytes.len()) && self.sync_enabled(),
            Payload::ShareMsg { body } => chunk_ok(body.len()) && self.share_enabled(),
            Payload::ShareData { bytes } => chunk_ok(bytes.len()) && self.share_enabled(),
            _ => false,
        };
        if !valid {
            return Err(ChannelError::Protocol);
        }
        self.seal_bytes(&payload.encode())
    }

    /// Encrypts a maintenance message.
    pub fn seal(&mut self, payload: &Payload) -> Result<Vec<u8>, ChannelError> {
        match payload {
            Payload::Keepalive | Payload::NameUpdate { .. } | Payload::Close { .. } => {}
            _ => return Err(ChannelError::Protocol),
        }
        self.seal_any(&payload.encode())
    }

    /// Encrypts arbitrary plaintext; tests use it to send what the protocol forbids.
    #[cfg(feature = "testkit")]
    pub fn seal_any(&mut self, plain: &[u8]) -> Result<Vec<u8>, ChannelError> {
        self.seal_bytes(plain)
    }

    #[cfg(not(feature = "testkit"))]
    fn seal_any(&mut self, plain: &[u8]) -> Result<Vec<u8>, ChannelError> {
        self.seal_bytes(plain)
    }

    fn seal_bytes(&mut self, plain: &[u8]) -> Result<Vec<u8>, ChannelError> {
        if self.closed {
            return Err(ChannelError::Protocol);
        }
        let mut buf = [0u8; MAX_FRAME];
        match self.transport.write_message(plain, &mut buf) {
            Ok(n) => Ok(buf[..n].to_vec()),
            Err(_) => {
                self.closed = true;
                Err(ChannelError::Crypto)
            }
        }
    }

    /// Decrypts one frame. Any failure closes the channel for good.
    pub fn open(&mut self, frame: &[u8]) -> Result<Payload, ChannelError> {
        let result = self.open_inner(frame);
        if result.is_err() {
            self.closed = true;
        }
        result
    }

    fn open_inner(&mut self, frame: &[u8]) -> Result<Payload, ChannelError> {
        if self.closed || frame.is_empty() || frame.len() > MAX_FRAME {
            return Err(ChannelError::Protocol);
        }
        let mut buf = Zeroizing::new([0u8; MAX_FRAME]);
        let n = self
            .transport
            .read_message(frame, buf.as_mut())
            .map_err(|_| ChannelError::Crypto)?;
        let decoded = match self.version {
            HelloVersion::V3 => Payload::decode_v3(&buf[..n]),
            HelloVersion::V2 => Payload::decode_v2(&buf[..n]),
            HelloVersion::V1 => Payload::decode(&buf[..n]),
        };
        match decoded {
            Ok(
                payload @ (Payload::Keepalive
                | Payload::NameUpdate { .. }
                | Payload::Close { .. }
                | Payload::SyncCtl { .. }
                | Payload::CopyData { .. }
                | Payload::ShareMsg { .. }
                | Payload::ShareData { .. }),
            ) => Ok(payload),
            _ => Err(ChannelError::Protocol),
        }
    }
}

/// The prologue for `hello` (v1, v2 or v3); an unknown Hello falls back to v1, which then
/// fails the handshake against any real peer.
fn prologue(hello: &[u8]) -> Vec<u8> {
    let base = match parse_hello_versioned(hello) {
        Ok((_, HelloVersion::V2)) => CHANNEL_PROLOGUE_V2,
        Ok((_, HelloVersion::V3)) => CHANNEL_PROLOGUE_V3,
        _ => CHANNEL_PROLOGUE,
    };
    [base, hello].concat()
}

fn hello_version(hello: &[u8]) -> HelloVersion {
    parse_hello_versioned(hello).map_or(HelloVersion::V1, |(_, version)| version)
}

fn handshake_hash(hs: &HandshakeState) -> [u8; 32] {
    let mut session = [0u8; 32];
    let hash = hs.get_handshake_hash();
    let n = hash.len().min(32);
    session[..n].copy_from_slice(&hash[..n]);
    session
}

enum DialStep {
    AwaitMsg2(Box<HandshakeState>),
    AwaitWelcome(Box<TransportState>, [u8; 32], [u8; 32]),
    Done,
}

/// The connecting side.
pub struct ChannelDialer {
    own_id: DeviceId,
    expected: [u8; 32],
    name: DeviceName,
    step: DialStep,
    out: Vec<Vec<u8>>,
    version: HelloVersion,
}

impl ChannelDialer {
    /// Queues the Hello and msg1. `expected` is the pinned key of the peer being dialed.
    /// Channel protocol v1 (003).
    pub fn start(key: &DeviceKey, expected: [u8; 32], name: DeviceName) -> Result<Self, Error> {
        Self::start_version(key, expected, name, HelloVersion::V1)
    }

    /// As [`start`](Self::start) with the given Hello version (004: v2 enables sync).
    pub fn start_version(
        key: &DeviceKey,
        expected: [u8; 32],
        name: DeviceName,
        version: HelloVersion,
    ) -> Result<Self, Error> {
        let hello = hello_versioned(HelloKind::Channel, version);
        let prologue = prologue(&hello);
        let mut hs = noise::builder(NOISE_CHANNEL, key.private_bytes(), &prologue)?
            .build_initiator()
            .map_err(|_| Error::Crypto)?;
        let msg1 = noise::write_handshake(&mut hs, &[])?;
        Ok(Self {
            own_id: key.id(),
            expected,
            name,
            step: DialStep::AwaitMsg2(Box::new(hs)),
            out: vec![hello.to_vec(), msg1],
            version,
        })
    }

    pub fn outgoing(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.out)
    }

    /// `Ok(None)`: msg3 queued; `Ok(Some(channel))`: `Welcome` received.
    pub fn on_frame(&mut self, body: &[u8]) -> Result<Option<Channel>, ChannelError> {
        if body.is_empty() || body.len() > MAX_FRAME {
            self.step = DialStep::Done;
            return Err(ChannelError::Protocol);
        }
        match std::mem::replace(&mut self.step, DialStep::Done) {
            DialStep::AwaitMsg2(mut hs) => {
                let payload =
                    noise::read_handshake(&mut hs, body).map_err(|_| ChannelError::Crypto)?;
                if !payload.is_empty() {
                    return Err(ChannelError::Protocol);
                }
                let presented = noise::remote_static(&hs).map_err(|_| ChannelError::Protocol)?;
                // Check the pin before revealing our own static key in msg3.
                if !bool::from(subtle::ConstantTimeEq::ct_eq(
                    &presented[..],
                    &self.expected[..],
                )) {
                    return Err(ChannelError::KeyMismatch {
                        presented: DeviceId::from_public(&presented),
                    });
                }
                let hello = Zeroizing::new(
                    Payload::ChannelHello {
                        name: self.name.clone(),
                    }
                    .encode(),
                );
                let msg3 =
                    noise::write_handshake(&mut hs, &hello).map_err(|_| ChannelError::Crypto)?;
                let session = handshake_hash(&hs);
                let ts = hs.into_transport_mode().map_err(|_| ChannelError::Crypto)?;
                self.out.push(msg3);
                self.step = DialStep::AwaitWelcome(Box::new(ts), presented, session);
                Ok(None)
            }
            DialStep::AwaitWelcome(mut ts, peer_public, session) => {
                match noise::open(&mut ts, body) {
                    Ok(Payload::Welcome { name }) => Ok(Some(Channel {
                        transport: ts,
                        peer_public,
                        peer_name: name,
                        dialer_id: self.own_id,
                        is_dialer: true,
                        closed: false,
                        version: self.version,
                        session,
                    })),
                    Ok(Payload::Refused) => Err(ChannelError::Refused),
                    Ok(_) => Err(ChannelError::Protocol),
                    Err(Error::Crypto) => Err(ChannelError::Crypto),
                    Err(_) => Err(ChannelError::Protocol),
                }
            }
            DialStep::Done => Err(ChannelError::Protocol),
        }
    }
}

enum RespStep {
    AwaitMsg1(Box<HandshakeState>),
    AwaitMsg3(Box<HandshakeState>),
    Done,
}

/// The accepting side, created after a valid channel Hello.
pub struct ChannelResponder {
    private: Zeroizing<[u8; 32]>,
    name: DeviceName,
    hello: Vec<u8>,
    step: RespStep,
    out: Vec<Vec<u8>>,
}

impl ChannelResponder {
    pub fn new(key: &DeviceKey, name: DeviceName, hello: &[u8]) -> Self {
        Self {
            private: Zeroizing::new(*key.private_bytes()),
            name,
            hello: hello.to_vec(),
            step: RespStep::Done,
            out: Vec::new(),
        }
        .started()
    }

    fn started(mut self) -> Self {
        let prologue = prologue(&self.hello);
        if let Ok(hs) = noise::builder(NOISE_CHANNEL, &self.private, &prologue)
            .and_then(|b| b.build_responder().map_err(|_| Error::Crypto))
        {
            self.step = RespStep::AwaitMsg1(Box::new(hs));
        }
        self
    }

    pub fn outgoing(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.out)
    }

    /// `Ok(None)`: msg2 queued. `Ok(Some(channel))`: pinned dialer, `Welcome` queued.
    /// `Err(Unpaired)`: `Refused` queued; the caller sends it and closes.
    pub fn on_frame(
        &mut self,
        body: &[u8],
        is_pinned: &dyn Fn(&[u8; 32]) -> bool,
    ) -> Result<Option<Channel>, ChannelError> {
        if body.is_empty() || body.len() > MAX_FRAME {
            self.step = RespStep::Done;
            return Err(ChannelError::Protocol);
        }
        match std::mem::replace(&mut self.step, RespStep::Done) {
            RespStep::AwaitMsg1(mut hs) => {
                let payload =
                    noise::read_handshake(&mut hs, body).map_err(|_| ChannelError::Protocol)?;
                if !payload.is_empty() {
                    return Err(ChannelError::Protocol);
                }
                let msg2 =
                    noise::write_handshake(&mut hs, &[]).map_err(|_| ChannelError::Crypto)?;
                self.out.push(msg2);
                self.step = RespStep::AwaitMsg3(hs);
                Ok(None)
            }
            RespStep::AwaitMsg3(mut hs) => {
                let payload =
                    noise::read_handshake(&mut hs, body).map_err(|_| ChannelError::Crypto)?;
                let peer_name = match Payload::decode(&payload) {
                    Ok(Payload::ChannelHello { name }) => name,
                    _ => return Err(ChannelError::Protocol),
                };
                let presented = noise::remote_static(&hs).map_err(|_| ChannelError::Protocol)?;
                let session = handshake_hash(&hs);
                let mut transport =
                    Box::new(hs.into_transport_mode().map_err(|_| ChannelError::Crypto)?);
                let pinned = is_pinned(&presented);
                let reply = if pinned {
                    Payload::Welcome {
                        name: self.name.clone(),
                    }
                } else {
                    Payload::Refused
                };
                let frame =
                    noise::seal(&mut transport, &reply).map_err(|_| ChannelError::Crypto)?;
                self.out.push(frame);
                if !pinned {
                    return Err(ChannelError::Unpaired {
                        presented: DeviceId::from_public(&presented),
                    });
                }
                Ok(Some(Channel {
                    transport,
                    peer_public: presented,
                    peer_name,
                    dialer_id: DeviceId::from_public(&presented),
                    is_dialer: false,
                    closed: false,
                    version: hello_version(&self.hello),
                    session,
                }))
            }
            RespStep::Done => Err(ChannelError::Protocol),
        }
    }
}
