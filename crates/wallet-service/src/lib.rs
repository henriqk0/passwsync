//! Application layer shared by passwsync hosts: wallet registry (locked/unlocked slots),
//! browser sessions, idle auto-lock and suspend detection. No HTTP, filesystem, or OS calls:
//! every external interaction goes through the ports in this crate.
#![forbid(unsafe_code)]

mod adopt;
mod error;
mod name;
mod ports;
mod registry;
mod sessions;
mod sync;

pub use adopt::AdoptVerdict;
pub use error::ServiceError;
pub use name::{InvalidName, WalletName};
#[cfg(feature = "testkit")]
pub use ports::testkit;
pub use ports::{
    ElapsedClock, LockObserver, PeerRef, PendingCopies, PendingOutcome, PendingRef, UnlockFacts,
    WalletDirectory,
};
pub use registry::{
    EntrySummary, EntryView, Field, KDF_MEMORY_CAP_KIB, Service, ServiceConfig, UnlockOutcome,
    WalletStatus,
};
pub use sessions::{Authenticated, BrowserSession, Grant, LaunchToken, Sessions, Token};
pub use sync::{ConflictSummary, ConflictVersion, CopyFacts, CopyVerdict, EpochRelation};
pub use vault_core::MergeReport;
