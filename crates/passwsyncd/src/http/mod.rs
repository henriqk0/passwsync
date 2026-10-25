//! Loopback HTTP adapter: bounded request reading, the protection pipeline, pages, and the
//! JSON API.

pub mod api;
pub mod api_network;
pub mod api_sync;
pub mod guard;
pub mod pages;
pub mod request;
pub mod response;
pub mod server;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use wallet_service::{ElapsedClock, Service, Sessions};

use crate::config::Settings;
use crate::log::{Log, Rejections};

/// Everything request handlers share.
pub struct AppState {
    pub port: u16,
    pub settings: Settings,
    pub sessions: Mutex<Sessions>,
    pub rejections: Arc<Rejections>,
    pub log: Log,
    pub launch_file: PathBuf,
    pub elapsed: Arc<dyn ElapsedClock>,
    pub service: Arc<Service>,
    pub net: Arc<crate::net_runtime::NetRuntime>,
    /// 004: wallet sync (inactive while networking is off).
    pub sync: Arc<crate::sync_runtime::SyncRuntime>,
}

impl AppState {
    pub fn sessions(&self) -> MutexGuard<'_, Sessions> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn host(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    pub fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}
