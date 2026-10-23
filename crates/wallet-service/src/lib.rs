//! Application layer shared by passwsync hosts: wallet registry (locked/unlocked slots),
//! browser sessions, idle auto-lock and suspend detection. No HTTP, filesystem, or OS calls:
//! every external interaction goes through the ports in this crate.
#![forbid(unsafe_code)]

mod error;
mod name;
mod ports;
mod registry;
mod sessions;

pub use error::ServiceError;
pub use name::{InvalidName, WalletName};
#[cfg(feature = "testkit")]
pub use ports::testkit;
pub use ports::{ElapsedClock, WalletDirectory};
pub use registry::{
    EntrySummary, EntryView, Field, KDF_MEMORY_CAP_KIB, Service, ServiceConfig, UnlockOutcome,
    WalletStatus,
};
pub use sessions::{Authenticated, BrowserSession, Grant, LaunchToken, Sessions, Token};
