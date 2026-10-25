//! Adapters of the passwsync local service: loopback HTTP server, embedded web UI,
//! filesystem wallet directory, XDG paths, process hardening, signals and logging.
//! The binary in `main.rs` only wires these together.
#![forbid(unsafe_code)]
pub mod app;
pub mod assets;
pub mod clock;
pub mod config;
pub mod fs_dir;
pub mod hardening;
mod hex;
pub mod http;
pub mod log;
pub mod net_runtime;
pub mod net_store;
pub mod paths;
pub mod peer;
pub mod qr;
pub mod share_runtime;
pub mod share_store;
pub mod signals;
pub mod sweeper;
pub mod sync_runtime;
pub mod sync_store;
