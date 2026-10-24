//! Closed error and failure-reason sets; no variant carries text.

use std::fmt;

/// Why a pairing attempt failed (data-model.md "PairingSession").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FailReason {
    WrongCodeOrTampered,
    Expired,
    Rejected,
    Timeout,
    IdMismatch,
    SelfPair,
    AlreadyPaired,
    Limit,
    RefusedNotPairing,
    Unreachable,
    Cancelled,
    Protocol,
}

impl FailReason {
    pub const ALL: [Self; 12] = [
        Self::WrongCodeOrTampered,
        Self::Expired,
        Self::Rejected,
        Self::Timeout,
        Self::IdMismatch,
        Self::SelfPair,
        Self::AlreadyPaired,
        Self::Limit,
        Self::RefusedNotPairing,
        Self::Unreachable,
        Self::Cancelled,
        Self::Protocol,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::WrongCodeOrTampered => "wrong_code_or_tampered",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Timeout => "timeout",
            Self::IdMismatch => "id_mismatch",
            Self::SelfPair => "self",
            Self::AlreadyPaired => "already_paired",
            Self::Limit => "limit",
            Self::RefusedNotPairing => "refused_not_pairing",
            Self::Unreachable => "unreachable",
            Self::Cancelled => "cancelled",
            Self::Protocol => "protocol",
        }
    }
}

impl fmt::Display for FailReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    InvalidName,
    InvalidDeviceId,
    InvalidCode,
    InvalidAddress,
    Malformed,
    Protocol,
    Storage,
    SelfPair,
    AlreadyPaired,
    Limit,
    NotFound,
    TooManyCodes,
    Random,
    Crypto,
}

impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidName => "invalid_name",
            Self::InvalidDeviceId => "invalid_device_id",
            Self::InvalidCode => "invalid_code",
            Self::InvalidAddress => "invalid_address",
            Self::Malformed => "malformed",
            Self::Protocol => "protocol",
            Self::Storage => "storage_error",
            Self::SelfPair => "self",
            Self::AlreadyPaired => "already_paired",
            Self::Limit => "pair_limit",
            Self::NotFound => "device_not_found",
            Self::TooManyCodes => "too_many_codes",
            Self::Random => "random",
            Self::Crypto => "crypto",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for Error {}

/// Why untrusted traffic was dropped before any processing (aggregated, never per packet).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DropReason {
    /// Source address fails the address policy.
    Public,
    Malformed,
    Oversized,
    /// A bound was full (connections, nearby list).
    Overflow,
    Timeout,
}

/// Lock-free drop counters shared by the network threads.
#[derive(Default, Debug)]
pub struct DropCounters {
    public: std::sync::atomic::AtomicU64,
    malformed: std::sync::atomic::AtomicU64,
    oversized: std::sync::atomic::AtomicU64,
    overflow: std::sync::atomic::AtomicU64,
    timeout: std::sync::atomic::AtomicU64,
}

/// A snapshot of [`DropCounters`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DropCounts {
    pub public: u64,
    pub malformed: u64,
    pub oversized: u64,
    pub overflow: u64,
    pub timeout: u64,
}

impl DropCounts {
    pub fn is_zero(&self) -> bool {
        *self == Self::default()
    }
}

impl DropCounters {
    fn counter(&self, reason: DropReason) -> &std::sync::atomic::AtomicU64 {
        match reason {
            DropReason::Public => &self.public,
            DropReason::Malformed => &self.malformed,
            DropReason::Oversized => &self.oversized,
            DropReason::Overflow => &self.overflow,
            DropReason::Timeout => &self.timeout,
        }
    }

    pub fn count(&self, reason: DropReason) {
        self.counter(reason)
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn get(&self, reason: DropReason) -> u64 {
        self.counter(reason)
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> DropCounts {
        DropCounts {
            public: self.get(DropReason::Public),
            malformed: self.get(DropReason::Malformed),
            oversized: self.get(DropReason::Oversized),
            overflow: self.get(DropReason::Overflow),
            timeout: self.get(DropReason::Timeout),
        }
    }

    /// Returns the counts and resets them to zero.
    pub fn take(&self) -> DropCounts {
        let take = |r| {
            self.counter(r)
                .swap(0, std::sync::atomic::Ordering::Relaxed)
        };
        DropCounts {
            public: take(DropReason::Public),
            malformed: take(DropReason::Malformed),
            oversized: take(DropReason::Oversized),
            overflow: take(DropReason::Overflow),
            timeout: take(DropReason::Timeout),
        }
    }
}
