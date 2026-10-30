//! Runtimes shared by both passwsync hosts (the desktop service `passwsyncd` and the Android
//! app through `passwsync-ffi`): logging, configuration, private files, the elapsed clock,
//! process hardening, the filesystem wallet directory, networking, sync and sharing.
//! Moved out of `passwsyncd` unchanged (007, FR-004); the code exists once.
#![forbid(unsafe_code)]
pub mod clock;
pub mod config;
pub mod files;
pub mod fs_dir;
pub mod hardening;
pub mod hex;
pub mod log;
pub mod net_runtime;
pub mod net_store;
pub mod share_runtime;
pub mod share_store;
pub mod sync_runtime;
pub mod sync_store;
pub mod wiring;
