#![forbid(unsafe_code)]
//! `PasswsyncCore`, the one exported object (contracts/ffi-api.md section 5). Every call is
//! synchronous; every wallet-mutating call saves before it returns. Before any call that can
//! read wallet data the suspend check, idle sweep and deadlines run (FR-016).

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

use device_link::identity::Fingerprint;
use device_link::name::{DeviceName, InterfaceName};
use host_runtime::clock::OsElapsedClock;
use host_runtime::config::{self, Settings};
use host_runtime::files::{load_or_create_device_id, write_private_atomic};
use host_runtime::fs_dir::FsWalletDirectory;
use host_runtime::log::{LockReason, Log, LogEvent};
use host_runtime::net_runtime::NetDeps;
use host_runtime::wiring::{self, HostCore, HostDirs};
use vault_core::{
    EntryFields, EntryId, KdfConfig, MasterPassword, SystemClock, Vault, peek_kdf_config,
};
use wallet_service::{
    ElapsedClock, EntrySummary, EntryView, Field, KDF_MEMORY_CAP_KIB, LockObserver, ServiceConfig,
    ServiceError, WalletDirectory, WalletName,
};
use zeroize::Zeroizing;

use crate::dirs::DataDirs;
use crate::error::CoreError;
use crate::identity::SealedIdentity;
use crate::interfaces::EligibleInterfaces;
use crate::lifecycle::{Lifecycle, spawn_sweeper};
use crate::ports::{Clipboard, KeySealer, LogSink, UiNotifier};
use crate::protect::{self, OsProcess, ProcessControls};
use crate::records::{
    BackgroundPlan, CopyField, CopyTicket, CoreConfig, CoreEvent, CredentialDetails,
    CredentialInput, CredentialSummary, ProtectionStatus, RevealTicket, SettingsInput,
    SettingsView, WalletInfo,
};
use crate::secret::SecretInput;
use crate::settings::{self, LoadedSettings};

/// Prefix of every log line of the app (`logcat -s passwsync`).
const LOG_PREFIX: &str = "passwsync";
/// The node lingers this long after the app leaves the foreground (FR-042).
pub(crate) const KEEP_NETWORK_MS: u64 = 10_000;
/// A running transfer may keep the node up to this long after leaving the foreground.
pub(crate) const TRANSFER_CAP_MS: u64 = 120_000;
const MIN_PASSWORD_CHARS: usize = 12;

pub use crate::network::pairing_state;

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The one-core-per-process guard (FR-011, R17).
#[derive(Debug, Default)]
pub struct Instance(AtomicBool);

impl Instance {
    pub fn new() -> Self {
        Self::default()
    }

    /// The guard of this process, used by the exported `start`.
    pub fn process() -> Arc<Self> {
        static PROCESS: OnceLock<Arc<Instance>> = OnceLock::new();
        Arc::clone(PROCESS.get_or_init(|| Arc::new(Self::new())))
    }

    fn claim(&self) -> bool {
        self.0
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    fn release(&self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Releases the instance claim when start-up fails half way.
struct Claim(Option<Arc<Instance>>);

impl Claim {
    fn keep(mut self) -> Arc<Instance> {
        self.0.take().expect("claim held")
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        if let Some(instance) = self.0.take() {
            instance.release();
        }
    }
}

/// What `start` is built from besides the foreign ports. Production: [`Deps::production`];
/// tests replace the process controls, the clock and the KDF cost.
pub struct Deps {
    pub process: Arc<dyn ProcessControls>,
    pub elapsed: Arc<dyn ElapsedClock>,
    /// Cost for wallets created here (`KdfConfig::DEFAULT` in production, FR-013).
    pub wallet_kdf: KdfConfig,
    pub net: NetDeps,
    pub instance: Arc<Instance>,
    /// Sweeper period while in the foreground (15 s in production).
    pub sweep_period: Duration,
    /// Node linger after leaving the foreground without a transfer (10 s in production).
    pub linger: Duration,
    /// Longest linger while a transfer runs (120 s in production).
    pub transfer_cap: Duration,
    /// Longest background sync window (120 s in production).
    pub window_limit: Duration,
}

impl Deps {
    pub fn production() -> Self {
        Self {
            process: Arc::new(OsProcess),
            elapsed: Arc::new(OsElapsedClock),
            wallet_kdf: KdfConfig::DEFAULT,
            net: NetDeps::production(),
            instance: Instance::process(),
            sweep_period: Duration::from_secs(15),
            linger: Duration::from_millis(KEEP_NETWORK_MS),
            transfer_cap: Duration::from_millis(TRANSFER_CAP_MS),
            window_limit: Duration::from_secs(120),
        }
    }
}

/// Feeds the closed-set lines of [`Log`] to the foreign `LogSink`, one call per line.
struct LineWriter {
    sink: Arc<dyn LogSink>,
    buffer: Vec<u8>,
}

impl Write for LineWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for &byte in bytes {
            if byte == b'\n' {
                let line = String::from_utf8_lossy(&self.buffer).into_owned();
                self.buffer.clear();
                self.sink.line(line);
            } else {
                self.buffer.push(byte);
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The settings file as it will apply at the next start.
struct Saved {
    settings: Settings,
    restart_required: bool,
}

/// The state behind the exported object.
pub struct Inner {
    pub(crate) protection: ProtectionStatus,
    pub(crate) host: HostCore,
    pub(crate) dirs: DataDirs,
    /// The settings in force for this process.
    pub(crate) running: Settings,
    reset_notice: bool,
    saved: Mutex<Saved>,
    fingerprint: Option<Fingerprint>,
    pub(crate) log: Log,
    pub(crate) clipboard_port: Arc<dyn Clipboard>,
    pub(crate) notifier: Arc<dyn UiNotifier>,
    pub(crate) elapsed: Arc<dyn ElapsedClock>,
    /// Monotonic time of the last deliberate action per unlocked wallet (mirror of the
    /// service's idle timer, for the background deadline).
    activity: Mutex<BTreeMap<WalletName, Duration>>,
    lifecycle: Arc<Lifecycle>,
    pub(crate) clipboard: Mutex<crate::clipboard::ClipboardState>,
    pub(crate) reveals: Mutex<Vec<crate::clipboard::Reveal>>,
    pub(crate) eligible: Arc<EligibleInterfaces>,
    pub(crate) shut_down: AtomicBool,
    /// The settings file as saved (for `set_networking`), the sealer (identity reset).
    pub(crate) sealer: Arc<dyn KeySealer>,
    pub(crate) linger: Duration,
    pub(crate) transfer_cap: Duration,
    pub(crate) window_limit: Duration,
    /// A background sync window is running.
    pub(crate) window_running: AtomicBool,
}

/// Every lock (manual, all, idle, suspend, share) ends here as well as in the share engine.
struct CoreLocks {
    share: Arc<dyn LockObserver>,
    core: Weak<Inner>,
}

impl LockObserver for CoreLocks {
    fn locked(&self, name: &WalletName) {
        self.share.locked(name);
        if let Some(core) = self.core.upgrade() {
            core.after_lock(name);
        }
    }
}

pub(crate) fn wallet(name: &str) -> Result<WalletName, CoreError> {
    WalletName::parse(name).map_err(|_| CoreError::InvalidName)
}

fn ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

impl Inner {
    pub(crate) fn lifecycle(&self) -> Arc<Lifecycle> {
        Arc::clone(&self.lifecycle)
    }

    pub(crate) fn notify(&self, event: CoreEvent) {
        self.notifier.changed(event);
    }

    /// Suspend check, idle locks, then the clipboard and reveal deadlines.
    pub(crate) fn housekeep(&self) {
        wiring::sweep_locks(&self.host.service, &self.log);
        self.clipboard_deadline();
        self.reveal_deadlines();
    }

    /// One sweeper pass.
    pub(crate) fn sweep(&self) {
        self.housekeep();
        self.host.tick(self.elapsed.monotonic());
    }

    pub(crate) fn touch(&self, name: &WalletName) {
        lock(&self.activity).insert(name.clone(), self.elapsed.monotonic());
    }

    /// Called for every lock, outside every service lock.
    fn after_lock(&self, name: &WalletName) {
        lock(&self.activity).remove(name);
        self.end_reveals(Some(name));
        self.clear_clipboard();
        self.notify(CoreEvent::Locked {
            name: name.as_str().to_owned(),
        });
    }

    pub(crate) fn require_protections(&self) -> Result<(), CoreError> {
        match self.protection.missing {
            Some(which) => Err(CoreError::ProtectionMissing { which }),
            None => Ok(()),
        }
    }

    /// The earliest idle-lock deadline of an unlocked wallet, from now.
    fn idle_deadline(&self) -> Option<Duration> {
        let now = self.elapsed.monotonic();
        lock(&self.activity)
            .values()
            .map(|last| (*last + self.running.auto_lock).saturating_sub(now))
            .min()
    }

    pub(crate) fn plan_deadline_only(&self) -> BackgroundPlan {
        let deadline = [
            self.idle_deadline(),
            self.clipboard_remaining(),
            self.reveal_remaining(),
        ]
        .into_iter()
        .flatten()
        .min();
        BackgroundPlan {
            deadline_in_ms: deadline.map(ms),
            periodic_window_minutes: None,
            extra_window: false,
            keep_network_ms: KEEP_NETWORK_MS,
        }
    }

    /// Saves `edit` applied to the saved settings; they apply at the next start.
    pub(crate) fn save_settings(&self, edit: impl FnOnce(&mut Settings)) -> Result<(), CoreError> {
        let mut saved = lock(&self.saved);
        let mut next = saved.settings.clone();
        edit(&mut next);
        write_private_atomic(&self.dirs.settings_file(), config::encode(&next).as_bytes())
            .map_err(|_| CoreError::Storage)?;
        saved.settings = next;
        saved.restart_required = true;
        Ok(())
    }

    /// Refused with `NotForeground` unless the app is in the foreground (FR-051).
    pub(crate) fn require_foreground(&self) -> Result<(), CoreError> {
        if self.lifecycle.is_foreground() {
            Ok(())
        } else {
            Err(CoreError::NotForeground)
        }
    }

    fn lock_everything(&self, reason: LockReason) {
        for name in self.host.service.lock_all() {
            self.log.emit(&LogEvent::Locked {
                wallet: &name,
                reason,
            });
        }
        self.end_reveals(None);
        self.clear_clipboard();
        self.notify(CoreEvent::AllLocked);
    }

    /// Reads the wallet file and opens it with `current` (the KDF cap first): proves the
    /// person knows the current password before it is replaced (FR-019).
    fn verify_password(&self, name: &WalletName, current: SecretInput) -> Result<(), CoreError> {
        let dir = FsWalletDirectory::new(self.dirs.wallets.clone());
        let bytes = Zeroizing::new(dir.storage(name).load().map_err(ServiceError::from)?);
        let kdf = peek_kdf_config(&bytes).map_err(ServiceError::from)?;
        if kdf.memory_kib > KDF_MEMORY_CAP_KIB {
            return Err(CoreError::KdfParamsOutOfRange);
        }
        let master = MasterPassword::new(std::mem::take(&mut *current.into_zeroizing()));
        Vault::unlock(
            &bytes,
            master,
            self.host.service.config().device.clone(),
            Box::new(SystemClock),
        )
        .map(drop)
        .map_err(|error| ServiceError::from(error).into())
    }
}

/// The app core. One per process.
#[derive(uniffi::Object)]
pub struct PasswsyncCore {
    pub(crate) inner: Arc<Inner>,
    instance: Arc<Instance>,
    sweeper: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for PasswsyncCore {
    fn drop(&mut self) {
        self.inner.lifecycle.stop();
        if let Some(handle) = lock(&self.sweeper).take() {
            let _ = handle.join();
        }
        self.inner.host.net.stop();
        self.instance.release();
    }
}

impl PasswsyncCore {
    /// `start` with explicit dependencies (tests use fakes; the exported `start` uses
    /// [`Deps::production`]). Order of contracts/ffi-api.md section 5.
    pub fn start_with(
        config: CoreConfig,
        sealer: Arc<dyn KeySealer>,
        clipboard: Arc<dyn Clipboard>,
        log_sink: Arc<dyn LogSink>,
        notifier: Arc<dyn UiNotifier>,
        deps: Deps,
    ) -> Result<Arc<Self>, CoreError> {
        if !deps.instance.claim() {
            return Err(CoreError::AlreadyStarted);
        }
        let claim = Claim(Some(Arc::clone(&deps.instance)));
        // 1. Protections first.
        let protection = protect::determine(deps.process.as_ref());
        let log = Log::with_sink(
            LOG_PREFIX,
            Arc::new(Mutex::new(LineWriter {
                sink: log_sink,
                buffer: Vec::new(),
            })),
        );
        log.emit(&LogEvent::ProtectionLevel {
            level: protect::log_level(protection.memory_lock),
        });
        // 2. Directories (0700), 3. settings (invalid: defaults, networking off, notice),
        // 4. device identifier.
        let dirs =
            DataDirs::prepare(Path::new(&config.data_dir)).map_err(|_| CoreError::Storage)?;
        let LoadedSettings {
            settings: running,
            reset_notice,
        } = settings::load(&dirs.root, &log);
        let device =
            load_or_create_device_id(&dirs.device_id_file()).map_err(|_| CoreError::Storage)?;
        // 5. Identity sealed by the Keystore; interfaces filtered by Kotlin's classification.
        let only = running
            .network
            .interface
            .as_deref()
            .and_then(|name| InterfaceName::parse(name).ok());
        let eligible = Arc::new(match deps.net.interfaces.clone() {
            Some(source) => EligibleInterfaces::over(source, deps.net.policy, only),
            None => EligibleInterfaces::new(deps.net.policy, only),
        });
        eligible.set_names(&config.eligible_interfaces);
        let mut net = deps.net;
        net.interfaces = Some(eligible.clone());
        let identity = SealedIdentity::new(&dirs.root, Arc::clone(&sealer));
        // 6. The shared runtimes, exactly as the desktop wires them.
        let host = HostCore::assemble(
            &HostDirs {
                wallets: dirs.wallets.clone(),
                sync: dirs.sync.clone(),
                received: dirs.received.clone(),
            },
            &running,
            &identity,
            net,
            ServiceConfig {
                device,
                wallet_kdf: deps.wallet_kdf,
                auto_lock: running.auto_lock,
            },
            Arc::clone(&deps.elapsed),
            &log,
        );
        // 7. The node stays paused until the app is in the foreground (FR-042).
        host.net.set_interfaces(eligible.clone());
        host.net.pause();
        let fingerprint = host
            .net
            .this_device
            .as_ref()
            .map(|device| device.fingerprint.clone());
        let share_observer = host.share.lock_observer();
        let inner = Arc::new(Inner {
            protection,
            host,
            dirs,
            saved: Mutex::new(Saved {
                settings: running.clone(),
                restart_required: false,
            }),
            running,
            reset_notice,
            fingerprint,
            log,
            clipboard_port: clipboard,
            notifier,
            elapsed: deps.elapsed,
            activity: Mutex::new(BTreeMap::new()),
            lifecycle: Arc::new(Lifecycle::default()),
            clipboard: Mutex::new(crate::clipboard::ClipboardState::Idle),
            reveals: Mutex::new(Vec::new()),
            eligible,
            shut_down: AtomicBool::new(false),
            sealer,
            linger: deps.linger,
            transfer_cap: deps.transfer_cap,
            window_limit: deps.window_limit,
            window_running: AtomicBool::new(false),
        });
        inner.host.service.set_lock_observer(Arc::new(CoreLocks {
            share: share_observer,
            core: Arc::downgrade(&inner),
        }));
        // 8. A clipboard left pending by the previous process is cleared now (FR-023).
        inner.clear_pending_marker_at_start();
        // 9. Received wallets unopened for 24 h (the partial-file clean-up ran in `assemble`).
        inner.sweep_received();
        let sweeper = spawn_sweeper(Arc::downgrade(&inner), deps.sweep_period)
            .map_err(|_| CoreError::Internal)?;
        Ok(Arc::new(Self {
            inner,
            instance: claim.keep(),
            sweeper: Mutex::new(Some(sweeper)),
        }))
    }
}

#[uniffi::export]
impl PasswsyncCore {
    /// Starts the process's one core (FR-011).
    #[uniffi::constructor]
    pub fn start(
        config: CoreConfig,
        sealer: Arc<dyn KeySealer>,
        clipboard: Arc<dyn Clipboard>,
        log: Arc<dyn LogSink>,
        notifier: Arc<dyn UiNotifier>,
    ) -> Result<Arc<Self>, CoreError> {
        Self::start_with(config, sealer, clipboard, log, notifier, Deps::production())
    }

    /// Fixed at start (FR-008); shown on the Security screen.
    pub fn protection_status(&self) -> ProtectionStatus {
        self.inner.protection.clone()
    }

    /// Every wallet, locked or not. Never counts as activity.
    pub fn list_wallets(&self) -> Result<Vec<WalletInfo>, CoreError> {
        let core = &self.inner;
        core.housekeep();
        let pending = core.clipboard_source();
        Ok(core
            .host
            .service
            .list()?
            .into_iter()
            .map(|status| WalletInfo {
                conflicts: core.host.service.conflict_count(&status.name).unwrap_or(0),
                pending_copy: pending.as_ref() == Some(&status.name),
                sync: core.wallet_sync(&status.name).0,
                unlocked: status.unlocked,
                name: status.name.as_str().to_owned(),
            })
            .collect())
    }

    /// Creates a wallet (KDF default cost) and leaves it unlocked (FR-013).
    pub fn create_wallet(
        &self,
        name: String,
        password: Vec<u8>,
        confirm: Vec<u8>,
    ) -> Result<(), CoreError> {
        let password = SecretInput::try_from(password)?;
        let confirm = SecretInput::try_from(confirm)?;
        let core = &self.inner;
        core.require_protections()?;
        core.housekeep();
        let name =
            core.host
                .service
                .create(&name, password.into_zeroizing(), confirm.into_zeroizing())?;
        core.touch(&name);
        core.log.emit(&LogEvent::Unlocked { wallet: &name });
        core.notify(CoreEvent::WalletsChanged);
        Ok(())
    }

    /// Unlocks a wallet; a wrong password and a corrupted file give the same error (FR-014).
    pub fn unlock_wallet(&self, name: String, password: Vec<u8>) -> Result<(), CoreError> {
        let password = SecretInput::try_from(password)?;
        let core = &self.inner;
        core.require_protections()?;
        core.housekeep();
        let name = wallet(&name)?;
        core.host.service.unlock(&name, password.into_zeroizing())?;
        core.touch(&name);
        core.log.emit(&LogEvent::Unlocked { wallet: &name });
        core.notify(CoreEvent::WalletsChanged);
        Ok(())
    }

    /// Locks one wallet: its key and entries are wiped, reveals end, the clipboard is cleared.
    pub fn lock_wallet(&self, name: String) -> Result<(), CoreError> {
        let core = &self.inner;
        let name = wallet(&name)?;
        if core.host.service.lock(&name)? {
            core.log.emit(&LogEvent::Locked {
                wallet: &name,
                reason: LockReason::Manual,
            });
        }
        Ok(())
    }

    /// Locks every wallet.
    pub fn lock_all(&self) {
        self.inner.lock_everything(LockReason::All);
    }

    /// Replaces the master password of an unlocked wallet after checking the current one.
    pub fn change_password(
        &self,
        name: String,
        current: Vec<u8>,
        new: Vec<u8>,
        confirm: Vec<u8>,
    ) -> Result<(), CoreError> {
        let current = SecretInput::try_from(current)?;
        let new = SecretInput::try_from(new)?;
        let confirm = SecretInput::try_from(confirm)?;
        let core = &self.inner;
        core.require_protections()?;
        core.housekeep();
        let name = wallet(&name)?;
        if !subtle_eq(new.as_str(), confirm.as_str()) {
            return Err(CoreError::PasswordMismatch);
        }
        if new.as_str().chars().count() < MIN_PASSWORD_CHARS {
            return Err(CoreError::PasswordTooShort);
        }
        core.host.service.touch(&name)?;
        core.verify_password(&name, current)?;
        core.host
            .service
            .change_password(&name, new.into_zeroizing(), confirm.into_zeroizing())?;
        core.touch(&name);
        Ok(())
    }

    /// Credentials matching `query` (case-insensitive over title, username, URL and notes),
    /// without passwords or notes (FR-010). Counts as activity.
    pub fn search(&self, name: String, query: String) -> Result<Vec<CredentialSummary>, CoreError> {
        let core = &self.inner;
        core.housekeep();
        let name = wallet(&name)?;
        let found = core.host.service.search(&name, &query)?;
        core.touch(&name);
        Ok(found.into_iter().map(summary).collect())
    }

    /// One credential without its password.
    pub fn get_credential(&self, name: String, id: String) -> Result<CredentialDetails, CoreError> {
        let core = &self.inner;
        core.housekeep();
        let name = wallet(&name)?;
        let view = core.host.service.get_entry(&name, entry_id(&id)?)?;
        core.touch(&name);
        Ok(details(view))
    }

    /// Adds a credential; saved before this returns. Returns its id.
    pub fn add_credential(
        &self,
        name: String,
        input: CredentialInput,
    ) -> Result<String, CoreError> {
        let core = &self.inner;
        core.housekeep();
        let name = wallet(&name)?;
        let entry = fields(input)?;
        let id = core.host.service.add_entry(&name, entry)?;
        core.touch(&name);
        Ok(id.to_string())
    }

    /// Replaces a credential; `input.password == None` keeps the stored password.
    pub fn update_credential(
        &self,
        name: String,
        id: String,
        input: CredentialInput,
    ) -> Result<(), CoreError> {
        let core = &self.inner;
        core.housekeep();
        let name = wallet(&name)?;
        let id = entry_id(&id)?;
        let keep = input.password.is_none();
        let entry = fields(input)?;
        if keep {
            core.host
                .service
                .update_entry_keeping_password(&name, id, entry)?;
        } else {
            core.host.service.update_entry(&name, id, entry)?;
        }
        core.touch(&name);
        Ok(())
    }

    /// Deletes a credential; saved before this returns.
    pub fn delete_credential(&self, name: String, id: String) -> Result<(), CoreError> {
        let core = &self.inner;
        core.housekeep();
        let name = wallet(&name)?;
        core.host.service.delete_entry(&name, entry_id(&id)?)?;
        core.touch(&name);
        Ok(())
    }

    /// The only call returning a password; hidden again after `hide_in_ms` (FR-024).
    pub fn reveal_password(&self, name: String, id: String) -> Result<RevealTicket, CoreError> {
        let core = &self.inner;
        core.housekeep();
        let name = wallet(&name)?;
        let id = entry_id(&id)?;
        let value = core.host.service.field(&name, id, Field::Password)?;
        core.touch(&name);
        Ok(core.reveal(&name, id, value))
    }

    /// The credential view was left: every reveal ends.
    pub fn leave_credential_view(&self) {
        self.inner.end_reveals(None);
    }

    /// Copies a field to the clipboard, marked sensitive, cleared after the timeout (FR-021).
    pub fn copy_field(
        &self,
        name: String,
        id: String,
        field: CopyField,
    ) -> Result<CopyTicket, CoreError> {
        let core = &self.inner;
        core.housekeep();
        let name = wallet(&name)?;
        let field = match field {
            CopyField::Username => Field::Username,
            CopyField::Password => Field::Password,
        };
        let value = core.host.service.field(&name, entry_id(&id)?, field)?;
        core.touch(&name);
        core.copy(&name, value)
    }

    /// Countdown until the clipboard is cleared.
    pub fn clipboard_pending_ms(&self) -> Option<u64> {
        let core = &self.inner;
        core.clipboard_deadline();
        core.clipboard_remaining().map(ms)
    }

    /// The deadline job: idle sweep, clipboard and reveal deadlines; returns the next plan.
    pub fn on_deadline(&self) -> BackgroundPlan {
        let core = &self.inner;
        core.housekeep();
        core.plan()
    }

    /// The screen went off: every wallet locks and the clipboard is cleared now (FR-017).
    pub fn on_screen_off(&self) {
        self.inner.lock_everything(LockReason::All);
    }

    /// The app came to the foreground: suspend check and idle sweep first, then the sweeper
    /// runs (FR-016, FR-042).
    pub fn on_foreground(&self) {
        let core = &self.inner;
        core.housekeep();
        core.lifecycle.enter_foreground();
        if core.running.network.enabled && !core.shut_down.load(Ordering::SeqCst) {
            core.host.net.resume();
            core.notify(CoreEvent::NetworkChanged);
        }
    }

    /// The app left the foreground: the sweeper parks; the plan names the next deadline.
    pub fn on_background(&self) -> BackgroundPlan {
        let core = &self.inner;
        core.housekeep();
        // FR-051: a pairing, an invitation whose transfer has not started and a redemption end.
        core.host.net.cancel_pairing();
        core.cancel_unstarted_shares();
        core.lifecycle
            .enter_background(core.host.net.node().is_some());
        core.plan()
    }

    /// The settings as they apply at the next start.
    pub fn settings(&self) -> SettingsView {
        let core = &self.inner;
        let saved = lock(&core.saved);
        settings::view(
            &LoadedSettings {
                settings: saved.settings.clone(),
                reset_notice: core.reset_notice,
            },
            core.fingerprint.as_ref(),
            saved.restart_required,
        )
    }

    /// Validates and saves the settings (atomic, 0600); they apply at the next start (FR-033).
    pub fn update_settings(&self, input: SettingsInput) -> Result<(), CoreError> {
        let core = &self.inner;
        let next = edited(&lock(&core.saved).settings, &input)?;
        core.save_settings(|settings| *settings = next)
    }

    /// "Restart now": locks everything, clears the clipboard, pauses the node and stops the
    /// sweeper. Idempotent.
    pub fn shutdown(&self) {
        let core = &self.inner;
        core.lock_everything(LockReason::Stop);
        if !core.shut_down.swap(true, Ordering::SeqCst) {
            core.host.net.pause();
            core.host.sync.stop();
            core.lifecycle.stop();
            if let Some(handle) = lock(&self.sweeper).take() {
                let _ = handle.join();
            }
        }
    }
}

pub(crate) fn entry_id(id: &str) -> Result<EntryId, CoreError> {
    id.parse().map_err(|_| CoreError::EntryNotFound)
}

fn text(value: &Zeroizing<String>) -> String {
    value.as_str().to_owned()
}

fn summary(entry: EntrySummary) -> CredentialSummary {
    CredentialSummary {
        id: entry.id.to_string(),
        title: text(&entry.title),
        username: text(&entry.username),
        url: text(&entry.url),
        conflicted: entry.conflicted,
    }
}

fn details(view: EntryView) -> CredentialDetails {
    CredentialDetails {
        id: view.id.to_string(),
        title: text(&view.title),
        username: text(&view.username),
        url: text(&view.url),
        notes: text(&view.notes),
        created_at: view.created_at,
        modified_at: view.modified_at,
    }
}

/// The 001 entry fields of an input; `None` password: empty (an edit keeps the stored one).
fn fields(input: CredentialInput) -> Result<EntryFields, CoreError> {
    let pw = match input.password {
        Some(raw) => std::mem::take(&mut *SecretInput::try_from(raw)?.into_zeroizing()),
        None => String::new(),
    };
    Ok(EntryFields {
        title: input.title,
        username: input.username,
        password: pw,
        url: input.url,
        notes: input.notes,
    })
}

fn subtle_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// The saved settings with the edit applied, or `InvalidInput` (002/003/004 ranges).
fn edited(current: &Settings, input: &SettingsInput) -> Result<Settings, CoreError> {
    let invalid = || CoreError::InvalidInput;
    let in_range = |value: u32, min: u32, max: u32| (min..=max).contains(&value);
    if !in_range(input.auto_lock_minutes, 1, 240)
        || !in_range(input.clipboard_clear_seconds, 5, 300)
        || !in_range(input.sync_interval_minutes, 15, 1440)
    {
        return Err(invalid());
    }
    let mut next = current.clone();
    next.auto_lock = Duration::from_secs(u64::from(input.auto_lock_minutes) * 60);
    next.clipboard_clear = Duration::from_secs(u64::from(input.clipboard_clear_seconds));
    next.sync_interval = Duration::from_secs(u64::from(input.sync_interval_minutes) * 60);
    next.network.device_name = match &input.device_name {
        Some(name) => Some(DeviceName::parse(name).map_err(|_| invalid())?),
        None => None,
    };
    next.network.interface = match &input.network_interface {
        Some(name) => Some(
            InterfaceName::parse(name)
                .map_err(|_| invalid())?
                .as_str()
                .to_owned(),
        ),
        None => None,
    };
    // The file must read back to exactly these settings.
    match config::parse(&config::encode(&next)) {
        Ok(parsed) if parsed.network == next.network => Ok(next),
        _ => Err(invalid()),
    }
}
