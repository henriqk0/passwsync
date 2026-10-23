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
pub mod paths;
pub mod peer;
pub mod signals;
pub mod sweeper;
