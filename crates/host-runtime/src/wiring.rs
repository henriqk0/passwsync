//! Composition shared by both hosts: passwsyncd start-up steps 5a-5e (networking, sync,
//! wallet service, sharing) and the lock sweep of the sweeper (contracts
//! shared-runtime-extraction.md section 3.4). Moved out of the desktop service's start-up and
//! sweeper (007, FR-004); the order of side effects is unchanged.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use vault_core::SystemClock;
use wallet_service::{ElapsedClock, Service, ServiceConfig, WalletDirectory};

use crate::config::Settings;
use crate::fs_dir::FsWalletDirectory;
use crate::log::{LockReason, Log, LogEvent};
use crate::net_runtime::{IdentityStore, NetDeps, NetRuntime};
use crate::share_runtime::ShareRuntime;
use crate::share_store::FsReceivedStore;
use crate::sync_runtime::{JournalingDirectory, SyncRuntime};

/// The data directories of one host (each already exists, owner-only).
#[derive(Clone, Debug)]
pub struct HostDirs {
    pub wallets: PathBuf,
    pub sync: PathBuf,
    pub received: PathBuf,
}

/// The running shared runtimes of one host.
pub struct HostCore {
    pub service: Arc<Service>,
    pub net: Arc<NetRuntime>,
    pub sync: Arc<SyncRuntime>,
    pub share: Arc<ShareRuntime>,
}

impl HostCore {
    /// 5a/5b net start, `TransferSlots(2)`, `FsReceivedStore`, `SyncRuntime`,
    /// `JournalingDirectory` over `FsWalletDirectory`, `Service`, `sync.attach`, `sync.start`
    /// if networking is on and the key is held, `ShareRuntime`, lock observer,
    /// `share.startup_cleanup`: in this exact order.
    pub fn assemble(
        dirs: &HostDirs,
        settings: &Settings,
        identity: &dyn IdentityStore,
        net: NetDeps,
        service: ServiceConfig,
        elapsed: Arc<dyn ElapsedClock>,
        log: &Log,
    ) -> Self {
        // 5a/5b. Device identity and (if enabled) networking; never fatal.
        let net = Arc::new(NetRuntime::start(
            settings.network.clone(),
            identity,
            net,
            log,
        ));
        // 004: every save goes through the journaling directory (inactive with networking off).
        // 005: one transfer limit for sync and share together; received wallets (step 5e).
        let slots = wallet_sync::slots::TransferSlots::new(2);
        let received = Arc::new(FsReceivedStore::new(dirs.received.clone()));
        let sync = Arc::new(SyncRuntime::new(
            dirs.sync.clone(),
            dirs.wallets.clone(),
            received,
            slots,
            Arc::clone(&net),
            log.clone(),
            settings.sync_interval,
        ));
        let wallets: Arc<dyn WalletDirectory> = Arc::new(JournalingDirectory::new(
            Arc::new(FsWalletDirectory::new(dirs.wallets.clone())),
            sync.shared(),
        ));
        let service = Arc::new(Service::new(
            wallets,
            Arc::new(SystemClock),
            elapsed,
            service,
        ));
        sync.attach(&service);
        // 5c/5d: sync only while networking is on (FR-001).
        if net.settings.enabled && net.key_held() {
            sync.start();
        }
        let share = Arc::new(ShareRuntime::new(
            sync.shared(),
            Arc::clone(&service),
            Arc::clone(&net),
            log.clone(),
        ));
        // 005: every lock cause cancels an invitation for that wallet (FR-009a).
        service.set_lock_observer(share.lock_observer());
        // 5e. Received wallets: clean-up of partial and inconsistent files (never fatal).
        share.startup_cleanup();
        Self {
            service,
            net,
            sync,
            share,
        }
    }

    /// The sweeper's extra work: network retry and drop counts, then the share engine.
    pub fn tick(&self, now: Duration) {
        self.net.tick(now);
        self.share.tick();
    }
}

/// Locks everything if a suspend is detected, logging it. Also runs before every request.
pub fn lock_if_suspended(service: &Service, log: &Log) {
    if let Some(locked) = service.check_suspend() {
        log.emit(&LogEvent::SuspendDetected);
        for wallet in &locked {
            log.emit(&LogEvent::Locked {
                wallet,
                reason: LockReason::Suspend,
            });
        }
    }
}

/// Suspend check, then idle locks, with the `SuspendDetected`/`Locked` log events.
pub fn sweep_locks(service: &Service, log: &Log) {
    lock_if_suspended(service, log);
    for wallet in &service.sweep() {
        log.emit(&LogEvent::Locked {
            wallet,
            reason: LockReason::Idle,
        });
    }
}
