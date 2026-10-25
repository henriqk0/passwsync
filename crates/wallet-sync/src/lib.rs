//! Sans-IO wallet sync protocol (feature 004): no sockets, files, threads or clocks of its
//! own. Everything external goes through the ports in [`ports`].
#![forbid(unsafe_code)]

pub mod codec;
pub mod decide;
pub mod error;
pub mod journal;
pub mod ports;
pub mod record;
pub mod round;
pub mod sched;
pub mod share;
pub mod slots;
pub mod status;
pub mod tags;
#[cfg(feature = "testkit")]
pub mod testkit;
mod transfer;
