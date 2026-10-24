//! The complete log (contracts/host-runtime.md "Log"). The only entry point takes a closed
//! [`LogEvent`]; there is no free-form string API, so bodies, tokens, cookies, titles and
//! secrets cannot be logged (FR-033a).

use std::fmt;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use device_link::error::{DropCounters, DropCounts, FailReason};
use device_link::identity::Fingerprint;
use device_link::name::InterfaceName;
use wallet_service::WalletName;

/// Why networking is not running (003).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetUnavailable {
    IdentityUnusable,
    PeersUnusable,
    PortInUse(u16),
    NoLocalNetwork,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisconnectReason {
    Timeout,
    Closed,
    Error,
    Duplicate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefuseReason {
    Unpaired,
    Revoked,
    KeyMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    CoreDumps,
    NonDumpable,
    MemlockLimit,
    Mlockall,
}

impl Protection {
    pub fn name(self) -> &'static str {
        match self {
            Self::CoreDumps => "core-dumps",
            Self::NonDumpable => "non-dumpable",
            Self::MemlockLimit => "memlock-limit",
            Self::Mlockall => "mlockall",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockReason {
    Manual,
    All,
    Idle,
    Suspend,
    Stop,
}

/// Coarse failure classes; never carry details.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorClass {
    Permission,
    Resource,
    LimitTooLow,
    Io,
    Storage,
    Internal,
}

impl ErrorClass {
    fn word(self) -> &'static str {
        match self {
            Self::Permission => "permission",
            Self::Resource => "resource",
            Self::LimitTooLow => "limit-too-low",
            Self::Io => "io",
            Self::Storage => "storage",
            Self::Internal => "internal",
        }
    }

    /// Classifies an OS error number without keeping any of its text.
    pub fn from_errno(errno: rustix::io::Errno) -> Self {
        use rustix::io::Errno;
        if errno == Errno::PERM || errno == Errno::ACCESS {
            Self::Permission
        } else if errno == Errno::NOMEM || errno == Errno::AGAIN {
            Self::Resource
        } else {
            Self::Io
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RejectionCounts {
    pub host: u64,
    pub origin: u64,
    pub csrf: u64,
    pub session: u64,
    pub size: u64,
    pub peer: u64,
}

/// Every line the service can log.
#[derive(Debug)]
pub enum LogEvent<'a> {
    Started {
        addr: SocketAddr,
    },
    LaunchFile {
        path: &'a Path,
    },
    ProtectionsApplied,
    ProtectionFailed {
        which: Protection,
        class: ErrorClass,
    },
    Unlocked {
        wallet: &'a WalletName,
    },
    Locked {
        wallet: &'a WalletName,
        reason: LockReason,
    },
    SuspendDetected,
    Rejected(RejectionCounts),
    Error {
        class: ErrorClass,
    },
    Stopping,
    // --- 003 network events (contracts/host-runtime-network.md) ---
    NetworkOff,
    NetworkOn {
        peer: u16,
        discovery: u16,
        interfaces: &'a [InterfaceName],
    },
    NetworkUnavailable(NetUnavailable),
    InterfacesChanged {
        interfaces: &'a [InterfaceName],
    },
    PairingStarted,
    PairingSucceeded {
        fingerprint: &'a Fingerprint,
    },
    PairingFailed(FailReason),
    PeerConnected {
        fingerprint: &'a Fingerprint,
    },
    PeerDisconnected {
        fingerprint: &'a Fingerprint,
        why: DisconnectReason,
    },
    PeerRefused {
        fingerprint: &'a Fingerprint,
        why: RefuseReason,
    },
    RefusedByPeer {
        fingerprint: &'a Fingerprint,
    },
    DeviceRevoked {
        fingerprint: &'a Fingerprint,
    },
    Dropped(DropCounts),
}

fn write_names(f: &mut fmt::Formatter<'_>, names: &[InterfaceName]) -> fmt::Result {
    for (i, name) in names.iter().enumerate() {
        if i > 0 {
            f.write_str(",")?;
        }
        f.write_str(name.as_str())?;
    }
    Ok(())
}

impl fmt::Display for LogEvent<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Started { addr } => write!(f, "started {addr}"),
            Self::LaunchFile { path } => write!(f, "launch file {}", path.display()),
            Self::ProtectionsApplied => f.write_str("protections applied"),
            Self::ProtectionFailed { which, class } => {
                write!(f, "protection failed: {} ({})", which.name(), class.word())
            }
            Self::Unlocked { wallet } => write!(f, "unlocked {wallet}"),
            Self::Locked { wallet, reason } => {
                let word = match reason {
                    LockReason::Manual => "manual",
                    LockReason::All => "all",
                    LockReason::Idle => "idle",
                    LockReason::Suspend => "suspend",
                    LockReason::Stop => "stop",
                };
                write!(f, "locked {wallet} ({word})")
            }
            Self::SuspendDetected => f.write_str("suspend detected"),
            Self::Rejected(c) => write!(
                f,
                "rejected host={} origin={} csrf={} session={} size={} peer={}",
                c.host, c.origin, c.csrf, c.session, c.size, c.peer
            ),
            Self::Error { class } => write!(f, "error {}", class.word()),
            Self::Stopping => f.write_str("stopping"),
            Self::NetworkOff => f.write_str("network off"),
            Self::NetworkOn {
                peer,
                discovery,
                interfaces,
            } => {
                write!(
                    f,
                    "network on peer={peer} discovery={discovery} interfaces="
                )?;
                write_names(f, interfaces)
            }
            Self::NetworkUnavailable(why) => match why {
                NetUnavailable::IdentityUnusable => {
                    f.write_str("network unavailable (identity-unusable)")
                }
                NetUnavailable::PeersUnusable => {
                    f.write_str("network unavailable (peers-unusable)")
                }
                NetUnavailable::PortInUse(port) => {
                    write!(f, "network unavailable (port-in-use {port})")
                }
                NetUnavailable::NoLocalNetwork => {
                    f.write_str("network unavailable (no-local-network)")
                }
            },
            Self::InterfacesChanged { interfaces } => {
                f.write_str("network interfaces changed ")?;
                write_names(f, interfaces)
            }
            Self::PairingStarted => f.write_str("pairing started"),
            Self::PairingSucceeded { fingerprint } => write!(f, "pairing succeeded {fingerprint}"),
            Self::PairingFailed(reason) => write!(f, "pairing failed ({reason})"),
            Self::PeerConnected { fingerprint } => write!(f, "peer connected {fingerprint}"),
            Self::PeerDisconnected { fingerprint, why } => {
                let word = match why {
                    DisconnectReason::Timeout => "timeout",
                    DisconnectReason::Closed => "closed",
                    DisconnectReason::Error => "error",
                    DisconnectReason::Duplicate => "duplicate",
                };
                write!(f, "peer disconnected {fingerprint} ({word})")
            }
            Self::PeerRefused { fingerprint, why } => {
                let word = match why {
                    RefuseReason::Unpaired => "unpaired",
                    RefuseReason::Revoked => "revoked",
                    RefuseReason::KeyMismatch => "key-mismatch",
                };
                write!(f, "peer refused {fingerprint} ({word})")
            }
            Self::RefusedByPeer { fingerprint } => write!(f, "refused by peer {fingerprint}"),
            Self::DeviceRevoked { fingerprint } => write!(f, "device revoked {fingerprint}"),
            Self::Dropped(c) => write!(
                f,
                "dropped public={} malformed={} oversized={} overflow={} timeout={}",
                c.public, c.malformed, c.oversized, c.overflow, c.timeout
            ),
        }
    }
}

type Sink = Arc<Mutex<dyn Write + Send>>;

/// Line-oriented log writer (stderr in production).
#[derive(Clone)]
pub struct Log {
    sink: Sink,
}

impl Log {
    pub fn stderr() -> Self {
        Self {
            sink: Arc::new(Mutex::new(std::io::stderr())),
        }
    }

    /// For tests: a log writing into a shared buffer.
    pub fn to_buffer() -> (Self, Arc<Mutex<Vec<u8>>>) {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::new(Mutex::new(SharedBuffer(Arc::clone(&buffer))));
        (Self { sink }, buffer)
    }

    /// Why start-up failed (configuration, paths, instance, port). These messages name keys
    /// and paths only, never request data or secrets.
    pub fn fatal(&self, error: &crate::app::StartError) {
        let mut sink = self.sink.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = writeln!(sink, "passwsyncd: {error}");
        let _ = sink.flush();
    }

    pub fn emit(&self, event: &LogEvent<'_>) {
        let mut sink = self.sink.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = writeln!(sink, "passwsyncd: {event}");
        let _ = sink.flush();
    }
}

struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Why a request or connection was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Host,
    Origin,
    Csrf,
    Session,
    Size,
    Peer,
}

const LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Rejection counters, aggregated and logged at most once per minute.
#[derive(Default)]
pub struct Rejections {
    host: AtomicU64,
    origin: AtomicU64,
    csrf: AtomicU64,
    session: AtomicU64,
    size: AtomicU64,
    peer: AtomicU64,
    last_emit: Mutex<Option<Duration>>,
}

impl Rejections {
    fn counter(&self, reason: Reason) -> &AtomicU64 {
        match reason {
            Reason::Host => &self.host,
            Reason::Origin => &self.origin,
            Reason::Csrf => &self.csrf,
            Reason::Session => &self.session,
            Reason::Size => &self.size,
            Reason::Peer => &self.peer,
        }
    }

    pub fn count(&self, reason: Reason) {
        self.counter(reason).fetch_add(1, Ordering::Relaxed);
    }

    pub fn get(&self, reason: Reason) -> u64 {
        self.counter(reason).load(Ordering::Relaxed)
    }

    /// Returns the aggregated line and resets the counters if anything was counted and the
    /// last line is at least a minute old (`now` is monotonic time).
    pub fn flush(&self, now: Duration) -> Option<LogEvent<'static>> {
        let mut last = self
            .last_emit
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if last.is_some_and(|at| now.saturating_sub(at) < LOG_INTERVAL) {
            return None;
        }
        let reasons = [
            Reason::Host,
            Reason::Origin,
            Reason::Csrf,
            Reason::Session,
            Reason::Size,
            Reason::Peer,
        ];
        if reasons.iter().all(|r| self.get(*r) == 0) {
            return None;
        }
        let take = |r| self.counter(r).swap(0, Ordering::Relaxed);
        let counts = RejectionCounts {
            host: take(Reason::Host),
            origin: take(Reason::Origin),
            csrf: take(Reason::Csrf),
            session: take(Reason::Session),
            size: take(Reason::Size),
            peer: take(Reason::Peer),
        };
        *last = Some(now);
        Some(LogEvent::Rejected(counts))
    }
}

/// Gate for the aggregated `dropped ...` line: at most once per minute, only when non-zero.
#[derive(Default)]
pub struct DropLog {
    last_emit: Mutex<Option<Duration>>,
}

impl DropLog {
    pub fn flush(&self, counters: &DropCounters, now: Duration) -> Option<LogEvent<'static>> {
        let mut last = self
            .last_emit
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if last.is_some_and(|at| now.saturating_sub(at) < LOG_INTERVAL) {
            return None;
        }
        if counters.snapshot().is_zero() {
            return None;
        }
        *last = Some(now);
        Some(LogEvent::Dropped(counters.take()))
    }
}
