#![forbid(unsafe_code)]
//! Plain data crossing the FFI (contracts/ffi-api.md section 4). No field holds a secret
//! except `CredentialInput.password` and `RevealTicket.password`, both wipeable bytes; types
//! holding one do not derive `Debug`.

use crate::error::Protection;

/// `start` input: the app-private root and the interfaces Kotlin classified as eligible.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CoreConfig {
    pub data_dir: String,
    pub eligible_interfaces: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MemoryLockLevel {
    Full,
    SecretsOnly,
    None,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ProtectionStatus {
    pub core_dumps_disabled: bool,
    pub non_dumpable: bool,
    pub memory_lock: MemoryLockLevel,
    pub can_unlock: bool,
    pub missing: Option<Protection>,
}

/// `wallet_sync::status::WalletSyncState`; reasons are fixed tokens.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum WalletSyncState {
    SyncOff,
    Disabled { reason: String },
    PossibleRollback,
    Conflicts { count: u32 },
    ChangesWaiting,
    Syncing,
    SyncError,
    NotSynced { reason: String },
    InSync,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct WalletInfo {
    pub name: String,
    pub unlocked: bool,
    pub conflicts: u32,
    pub pending_copy: bool,
    pub sync: WalletSyncState,
}

/// Search result: no password, no notes (FR-010).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CredentialSummary {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub conflicted: bool,
}

/// One credential without its password.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CredentialDetails {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    pub created_at: i64,
    pub modified_at: i64,
}

/// Add/edit input. `password == None` on edit keeps the stored password. Secret: no `Debug`.
#[derive(uniffi::Record)]
pub struct CredentialInput {
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    pub password: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CopyField {
    Username,
    Password,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CopyTicket {
    pub clear_in_ms: u64,
}

/// A revealed password, hidden again after `hide_in_ms`. Secret: no `Debug`.
#[derive(uniffi::Record)]
pub struct RevealTicket {
    pub password: Vec<u8>,
    pub hide_in_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SettingsView {
    pub auto_lock_minutes: u32,
    pub clipboard_clear_seconds: u32,
    pub networking: bool,
    pub device_name: String,
    pub sync_interval_minutes: u32,
    pub network_interface: Option<String>,
    pub reset_notice: bool,
    pub restart_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SettingsInput {
    pub auto_lock_minutes: u32,
    pub clipboard_clear_seconds: u32,
    pub device_name: Option<String>,
    pub sync_interval_minutes: u32,
    pub network_interface: Option<String>,
}

/// `host_runtime::net_runtime::NetState` plus `paused`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum NetStateView {
    Off,
    IdentityUnusable,
    PeersUnusable,
    PortInUse,
    NoLocalNetwork,
    On,
    Paused,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DeviceView {
    pub id: String,
    pub fingerprint: String,
    pub name: String,
}

/// A 003 `GET /api/nearby` entry.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct NearbyView {
    pub device: DeviceView,
    pub address: String,
    pub paired: bool,
}

/// A paired device (005 peer list).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PeerView {
    pub device: DeviceView,
    pub status: String,
    pub share: String,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct NetworkView {
    pub state: NetStateView,
    pub this_device: Option<DeviceView>,
    pub nearby: Vec<NearbyView>,
    pub paired: Vec<PeerView>,
    pub warnings: Vec<String>,
}

/// Fixed-token mapping of the 003 initiator and joiner states.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PairingState {
    Idle,
    Waiting,
    Confirming,
    Completed,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PairingView {
    pub state: PairingState,
    /// Shown by the initiator only; never logged.
    pub code: Option<String>,
    pub peer: Option<DeviceView>,
    pub expires_in_ms: u64,
}

/// The fields of the 004 `WalletSyncView`.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct WalletSyncView {
    pub wallet: String,
    pub state: WalletSyncState,
    pub conflicts: u32,
    pub last_synced_at: Option<i64>,
}

/// The per-device entry of 004 `GET /api/sync`.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PeerSyncView {
    pub device: DeviceView,
    pub state: String,
    pub last_synced_at: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SyncView {
    pub wallets: Vec<WalletSyncView>,
    pub peers: Vec<PeerSyncView>,
    pub running: bool,
}

/// 004 conflict list entry; no password.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ConflictView {
    pub id: String,
    pub title: String,
    pub versions: u32,
}

/// One concurrent version; no password.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ConflictVersionView {
    pub index: u32,
    pub deleted: bool,
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    pub modified_at: i64,
    pub device: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ConflictChoice {
    Keep { index: u32 },
    Both,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PendingStatus {
    Waiting,
    CannotOpen,
    PasswordConflict,
    TooManyConflicts,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PendingCopyView {
    pub peer: DeviceView,
    pub received_at: i64,
    pub status: PendingStatus,
}

/// `vault_core::PasswordChoice`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PasswordChoiceKind {
    Local,
    Copy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum InvitationState {
    Active,
    AwaitingAcceptance,
    Transferring,
    Completed,
    Cancelled,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct InvitationView {
    /// Shown by the sender only; never logged.
    pub code: String,
    pub recipient: DeviceView,
    pub expires_in_ms: u64,
    pub state: InvitationState,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ReceivedView {
    pub id: String,
    pub from: DeviceView,
    pub received_at: i64,
    pub expires_in_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct BackgroundPlan {
    pub deadline_in_ms: Option<u64>,
    pub periodic_window_minutes: Option<u32>,
    pub extra_window: bool,
    pub keep_network_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum WindowEnd {
    Finished,
    TimeLimit,
    NoNetwork,
    Off,
    NoPeers,
    Busy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct WindowReport {
    pub ran: bool,
    pub reason: WindowEnd,
    pub peers_reached: u32,
    pub rounds: u32,
    pub duration_ms: u64,
}

/// What changed; the UI re-reads the affected view.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CoreEvent {
    WalletsChanged,
    Locked { name: String },
    AllLocked,
    ClipboardCleared,
    RevealExpired,
    NetworkChanged,
    PairingChanged,
    SyncChanged,
    ShareChanged,
    ReceivedExpired,
}
