//! Boundary between the shared Rust core (`host-runtime`) and the Android app (UniFFI,
//! contracts/ffi-api.md). Secrets cross only as wipeable byte vectors. The only unsafe code of
//! the workspace is `memprotect` (FR-005); every other module forbids it.
#![deny(unsafe_code)]

pub mod api;
pub mod clipboard;
pub mod dirs;
pub mod error;
pub mod identity;
pub mod interfaces;
pub mod lifecycle;
pub mod memprotect;
pub mod network;
pub mod ports;
pub mod protect;
pub mod records;
pub mod secret;
pub mod settings;
pub mod share;
pub mod sync;
#[cfg(feature = "testkit")]
pub mod testkit;
pub mod window;

uniffi::setup_scaffolding!();

/// Every freed block of the app process is zeroed first (FR-005, FR-009).
#[global_allocator]
static ALLOC: memprotect::WipeOnFree<std::alloc::System> =
    memprotect::WipeOnFree::new(std::alloc::System);
