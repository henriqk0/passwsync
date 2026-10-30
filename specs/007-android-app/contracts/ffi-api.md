# Contract: FFI API (`crates/passwsync-ffi`)

The boundary between the Kotlin app and the Rust core (FR-001–FR-011, research R5–R11).
Generated with UniFFI 0.32.2 proc-macros; Kotlin package `io.github.henriqk0.passwsync.core`
(`uniffi.toml`: `[bindings.kotlin] package_name = "io.github.henriqk0.passwsync.core"`,
`cdylib_name = "passwsync_ffi"`). Everything here is host-tested through the Rust API; the
generated Kotlin is checked by binding rules B1–B6 ([android-policy.md](android-policy.md)).

## 1. Crate rules

```toml
[package]  name = "passwsync-ffi"
[lib]      name = "passwsync_ffi"; crate-type = ["cdylib", "lib"]
[features] testkit = ["host-runtime/testkit"]
[dev-dependencies] passwsync-ffi = { path = ".", features = ["testkit"] }   # tests see the fakes (wallet-service precedent)
[dependencies]
host-runtime, wallet-service, vault-core, device-link, device-link-net, wallet-sync  # path
uniffi = { version = "=0.32.2", default-features = false }
rustix (workspace), zeroize (workspace, derive), rand_core (workspace)
[lints.rust]   unsafe_code = "deny"
[lints.clippy] all = "warn"
```

- `src/lib.rs`: `#![deny(unsafe_code)]`, `uniffi::setup_scaffolding!();`,
  `#[global_allocator] static ALLOC: memprotect::WipeOnFree<std::alloc::System>`.
- Every other `src/*.rs` file starts with `#![forbid(unsafe_code)]` (FR-005 "forbid"; `unsafe_scope.rs` checks it).
- `src/memprotect.rs` is the **only** file with `#![allow(unsafe_code)]` or the token `unsafe`
  (test `unsafe_scope.rs` scans every `.rs` under `crates/`: any other `unsafe`/`allow(unsafe_code)`
  fails; every other workspace member must have `[lints] workspace = true`).
- No `async` exports, no `String` parameter or return for a secret (B-rules), no `Debug` derive
  on a type holding a secret, no `println!`/`eprintln!`/`dbg!`.

## 2. Secret rules (FR-009, FR-010; research R7)

| Value | Direction | FFI type | Rust handling |
|-------|-----------|----------|---------------|
| master password, confirmation, current/new password | in | `Vec<u8>` (`ByteArray`) | `SecretInput::from(Vec<u8>)` → `Zeroizing<String>` in place; non-UTF-8 ⇒ `InvalidInput` |
| credential password (add/edit) | in | `Vec<u8>` | same |
| pairing code typed by the joiner, invite code typed by the recipient | in | `Vec<u8>` | same, digits only |
| revealed password | out | `Vec<u8>` | only `reveal_password`; buffer page-locked until lifted |
| copied username/password | out to port | `Vec<u8>` | only `Clipboard::set_sensitive`; never returned |
| identity / pins plaintext | out/in to port | `Vec<u8>` | only `KeySealer::seal/open` with labels §6 |
| code shown by the phone (pairing initiator, share sender) | out | `String` | display only; never logged |

Every inbound secret buffer is wiped on drop, including on every error path; the Rust heap is
wiped on free (memprotect). Kotlin wipes its `ByteArray`s in `finally` (scan S4, `Secrets.use`).

**Platform-text exception (FR-009 amendment)**: the clipboard entry and the displayed revealed password need the platform's text type. Kotlin converts secret bytes only in `Secrets.platformText`, callable only from `platform/ClipboardAdapter.kt` and `screens/CredentialView.kt`; the residual is recorded in research R7.

## 3. Foreign ports (`#[uniffi::export(with_foreign)]`, all `Send + Sync`)

```rust
pub trait KeySealer {
    /// AES-GCM under the non-exportable Keystore key; AAD = label. Returns iv‖ct‖tag.
    fn seal(&self, label: String, plaintext: Vec<u8>) -> Result<Vec<u8>, PlatformError>;
    /// Fails on any tag mismatch, missing or invalidated key.
    fn open(&self, label: String, sealed: Vec<u8>) -> Result<Vec<u8>, PlatformError>;
    /// Deletes and regenerates the Keystore key (identity reset, FR-037).
    fn reset(&self) -> Result<(), PlatformError>;
}
pub trait Clipboard {
    /// Sets a plain-text clip with ClipDescription.EXTRA_IS_SENSITIVE; returns the clip timestamp.
    fn set_sensitive(&self, value: Vec<u8>) -> Result<i64, PlatformError>;
    /// Clears when the current clip has `timestamp` or cannot be inspected. Returns true if cleared.
    fn clear_if_ours(&self, timestamp: i64) -> bool;
}
pub trait LogSink { fn line(&self, text: String); }          // → android.util.Log.i only
pub trait UiNotifier { fn changed(&self, event: CoreEvent); }  // any thread; Kotlin posts to main
#[derive(uniffi::Error)] pub enum PlatformError { Unavailable, Invalidated, Failed }
```

Fakes in `testkit`: `FakeSealer` (not crypto: wraps plaintext in a label-checked envelope,
records every label and plaintext, can simulate tamper, invalidation and unavailability; the
confidentiality and authenticity come from the real Keystore and are device-checked),
`FakeClipboard` (records sets/clears, can simulate "cannot inspect" and "replaced by another
app"), `RecordingLog`, `RecordingNotifier`.

## 4. Records and enums (no secrets unless marked)

```text
CoreConfig { data_dir: String, eligible_interfaces: Vec<String> }
ProtectionStatus { core_dumps_disabled: bool, non_dumpable: bool, memory_lock: MemoryLockLevel,
                   can_unlock: bool, missing: Option<Protection> }
MemoryLockLevel = Full | SecretsOnly | None
Protection = CoreDumps | NonDumpable
WalletInfo { name: String, unlocked: bool, conflicts: u32, pending_copy: bool,
             sync: WalletSyncState }
CredentialSummary { id: String, title: String, username: String, url: String, conflicted: bool }
                                         # no password, no notes (FR-010)
CredentialDetails { id, title, username, url, notes: String, created_at: i64, modified_at: i64 }
                                         # no password
CredentialInput { title: String, username: String, url: String, notes: String,
                  password: Option<Vec<u8>> }   # None on edit = keep password; secret
CopyField = Username | Password
CopyTicket { clear_in_ms: u64 }
RevealTicket { password: Vec<u8> /* secret */, hide_in_ms: u64 }
SettingsView { auto_lock_minutes: u32, clipboard_clear_seconds: u32, networking: bool,
               device_name: String, sync_interval_minutes: u32, network_interface: Option<String>,
               reset_notice: bool, restart_required: bool }
SettingsInput { auto_lock_minutes, clipboard_clear_seconds, device_name: Option<String>,
                sync_interval_minutes, network_interface: Option<String> }
NetworkView { state: NetStateView /* off|identity_unusable|peers_unusable|port_in_use|no_local_network|on, plus
              paused = NetRuntime::is_paused(); host-runtime's NetState enum gets no new variant */,
              this_device: Option<DeviceView>, nearby: Vec<NearbyView>, paired: Vec<PeerView>,
              warnings: Vec<String> }
DeviceView { id: String, fingerprint: String, name: String }
PairingView { state: PairingState, code: Option<String> /* initiator only */, peer: Option<DeviceView>,
              expires_in_ms: u64 }
SyncView { wallets: Vec<WalletSyncView>, peers: Vec<PeerSyncView>, running: bool }
ConflictView, ConflictVersionView     # as 004 http-api-sync, without passwords
InvitationView { code: String, recipient: DeviceView, expires_in_ms: u64, state: InvitationState }
ReceivedView { id: String, from: DeviceView, received_at: i64, expires_in_ms: u64 }
BackgroundPlan { deadline_in_ms: Option<u64>, periodic_window_minutes: Option<u32>,
                 extra_window: bool, keep_network_ms: u64 }
WindowReport { ran: bool, reason: WindowEnd /* finished|time_limit|no_network|off|no_peers|busy */,
               peers_reached: u32, rounds: u32, duration_ms: u64 }
CoreEvent = WalletsChanged | Locked{name} | AllLocked | ClipboardCleared | RevealExpired
          | NetworkChanged | PairingChanged | SyncChanged | ShareChanged | ReceivedExpired
```

`CoreError` (one flat `#[derive(uniffi::Error)]` enum; `Display` = fixed English message, no
interpolated user data) has exactly 37 variants:
- 25, one per `wallet_service::ServiceError` variant with the same name: `InvalidName`, `PasswordTooShort`,
  `PasswordMismatch`, `EmptyTitle`, `FieldTooLarge`, `WalletNotFound`, `EntryNotFound`, `WalletExists`,
  `WalletLocked`, `InvalidPasswordOrCorrupted` (wrong password and corrupted file share it), `MalformedFile`,
  `UnsupportedVersion`, `UnsupportedKdf`, `KdfParamsOutOfRange` (distinct), `WalletTooLarge`, `EntryConflicted`,
  `CannotOpenCopy`, `CopyRejected` (stable code `invalid_copy`), `TooManyConflicts`, `PasswordConflict`,
  `NotConflicted`, `InvalidVersionIndex`, `AlreadyPresent`, `Storage`, `Internal`;
- 12 others: `ProtectionMissing{which}`, `InvalidInput`, `NetworkOff`, `NotForeground`, `NoPeer`, `Busy`,
  `IdentityUnusable`, `PeersUnusable`, `Pairing{reason}`, `Share{reason}`, `AlreadyStarted`, `Platform`.
`reason` values are fixed tokens, never user data. Rule B5 compares this list exactly.

Referenced views and enums (each mirrors the named source; none carries a secret):
- `WalletSyncState`: the `wallet_sync::status::WalletSyncState` enum; `WalletSyncView`: the fields of passwsyncd `http/api_sync.rs` `WalletSyncView`.
- `PeerSyncView`: the per-device entry of 004 `GET /api/sync` (`specs/004-wallet-sync-protocol/contracts/http-api-sync.md`) plus `DeviceView`.
- `ConflictView { id, title, versions: u32 }` and `ConflictVersionView { index, deleted, title, username, url, notes, modified_at, device }`: 004 `GET /api/wallets/{name}/conflicts[/{id}]`; no password field.
- `ConflictChoice = Keep { index: u32 } | Both`: 004 `POST .../resolve` (`{ "keep": 0 }` or `{ "keep": "both" }`).
- `PendingCopyView { peer: DeviceView, received_at: i64, status }`, `status` = `waiting | cannot_open | password_conflict | too_many_conflicts` (004 pending list).
- `PasswordChoiceKind = Local | Copy`: `vault_core::PasswordChoice`.
- `DeviceView` and `PeerView`: passwsyncd `http/api_share.rs` `PeerView` fields plus `DeviceView`.
- `NearbyView`: the fields of the 003 `GET /api/nearby` entry (`specs/003-device-identity-pairing/contracts/http-api-network.md`), without secrets.
- `PairingState`: a fixed-token mapping of `device_link::pairing` `InitiatorState` and `JoinerState`; the mapping table lives in `api.rs` and is tested in `pairing_loopback.rs`.
- `InvitationState = active | awaiting_acceptance | transferring | completed | cancelled | expired`: 005 `http-api-share.md`.

## 5. `PasswsyncCore` methods

All synchronous. "Blocking" = may take > 100 ms (Kotlin calls it on `CoreExecutor`). "Fg" = refused
with `NotForeground` unless the app is in the foreground (FR-051). Every wallet-mutating call
saves atomically before returning `Ok` (FR-020).

| Method | Notes | FR |
|--------|-------|----|
| `start(config, sealer, clipboard, log, notifier) -> Arc<Self>` (constructor) | process singleton (`AlreadyStarted`); order: protections → dirs (0700) → settings (invalid ⇒ defaults, networking off, `reset_notice`) → device id → identity via `SealedIdentity` → `HostCore::assemble` with `EligibleInterfaces` → node **paused** → pending clipboard marker ⇒ clear → share startup cleanup → expired received sweep | FR-007, FR-008, FR-015, FR-023, FR-033, FR-037 |
| `protection_status() -> ProtectionStatus` | | FR-008 |
| `list_wallets() -> Vec<WalletInfo>` | | FR-013 |
| `create_wallet(name, password, confirm)` blocking | refuses on `ProtectionMissing`; ≥ 12 chars; `KdfConfig::DEFAULT` | FR-007, FR-013 |
| `unlock_wallet(name, password)` blocking | KDF params peeked first, > 128 MiB ⇒ `kdf_params_out_of_range`; same message for wrong password/corrupt; merges pending copies (004) | FR-014 |
| `lock_wallet(name)`, `lock_all()` | wipes, cancels reveals, clears clipboard immediately | FR-018 |
| `change_password(name, current, new, confirm)` blocking | 001 operation via wallet-service | FR-019 |
| `search(name, query) -> Vec<CredentialSummary>` | 001 case-insensitive substring over title/username/URL/notes; results without passwords/notes; touches idle timer | FR-010, FR-020 |
| `get_credential(name, id) -> CredentialDetails` | | FR-020 |
| `add_credential(name, input) -> String`, `update_credential(name, id, input)`, `delete_credential(name, id)` | `input.password == None` on update keeps it | FR-020 |
| `reveal_password(name, id) -> RevealTicket` | `hide_in_ms` = clipboard timeout; `RevealExpired` event at deadline, on lock, on `leave_credential_view()` | FR-024 |
| `leave_credential_view()` | ends reveals | FR-024 |
| `copy_field(name, id, field) -> CopyTicket` | `Clipboard::set_sensitive`, marker, deadline | FR-021, FR-022 |
| `clipboard_pending_ms() -> Option<u64>` | countdown | FR-022 |
| `conflicts(name) -> Vec<ConflictView>`, `conflict_versions(name, id) -> Vec<ConflictVersionView>` | 004 conflict shapes; no passwords | FR-049, FR-010 |
| `reveal_conflict_password(name, id, index) -> RevealTicket`, `copy_conflict_field(name, id, index, field: CopyField) -> CopyTicket` | desktop parity (004 `.../field`); same hide and clipboard rules as `reveal_password` and `copy_field` | FR-049, FR-021, FR-024 |
| `resolve_conflict(name, id, choice: ConflictChoice)` | `Keep{index}` or `Both` (004 `.../resolve`) | FR-049 |
| `pending_copies(name) -> Vec<PendingCopyView>`, `open_pending_with_password(name, peer_id, password: Vec<u8>)` blocking, `resolve_password_choice(name, peer_id, choice: PasswordChoiceKind, password: Vec<u8>)` | 004 pending copies (desktop name `open_pending_with_password`); a password is needed only to open a copy under another master password; the password choice takes the copy's password like the desktop `.../choose` (`{ keep, password }`; amended in T115) | FR-047, FR-049 |
| `settings() -> SettingsView`, `update_settings(input)` | validated (002/003/004 ranges); saved; `restart_required = true` | FR-033 |
| `set_networking(enabled, confirmed: bool)` | `enabled && !confirmed` ⇒ `InvalidInput`; saved; applies at next start | FR-038 |
| `set_eligible_interfaces(names)` | from `NetworkClassifier`; empty ⇒ `no_local_network` | FR-039 |
| `network() -> NetworkView` | | FR-038–FR-041 |
| `reset_identity()` Fg | `KeySealer::reset`, new key, empty pins, networking stays as set | FR-037 |
| `start_pairing() -> PairingView` Fg, `join_pairing(peer_id, code)` Fg blocking, `accept_pairing(peer_id)` Fg, `reject_pairing()`, `cancel_pairing()`, `pairing() -> PairingView` | 003 exactly; no wallet needed | FR-050, FR-051, FR-053 |
| `revoke_device(peer_id)` Fg | 003 + 005 deletions | FR-050, FR-052 |
| `sync_status() -> SyncView`, `sync_now()` Fg | | FR-049 |
| `create_invitation(wallet, recipient_id) -> InvitationView` Fg, `accept_recipient(recipient_id)` Fg, `cancel_invitation()`, `invitation() -> Option<InvitationView>` | 005 exactly | FR-052 |
| `redeem_invitation(sender_id, code)` Fg blocking, `received() -> Vec<ReceivedView>`, `open_received(id, local_name, password)` blocking, `discard_received(id)` | 005 exactly | FR-052 |
| `on_foreground()` | suspend check + idle sweep **before** UI shows data; resumes node if networking on; sweeper runs | FR-016, FR-042 |
| `on_background() -> BackgroundPlan` | cancels pairing + not-started invitations/redemptions; linger: node paused after ≤ 10 s, or when the running transfer ends, ≤ 120 s; sweeper parks | FR-042, FR-046, FR-051 |
| `on_screen_off()` | lock all + clipboard clear now | FR-017, FR-022 |
| `on_deadline() -> BackgroundPlan` | deadline job: idle sweep + clipboard deadline | FR-016, FR-022 |
| `background_plan() -> BackgroundPlan` | at app start (jobs not persisted) | FR-044, FR-048 |
| `run_sync_window() -> WindowReport` blocking | ≤ 120 s; refuses when off/no peer/no eligible interface; resume → announce → rounds → stop early when `rounds_idle` → pause; received expiry sweep; never unlocks or caches a password | FR-011, FR-044, FR-045, FR-047 |
| `multicast_wanted() -> bool` | true while the node is running; Kotlin holds `MulticastLock` exactly then (polled after each lifecycle call and on `NetworkChanged`) | FR-043 |
| `shutdown()` | lock all, clipboard clear, pause node, stop threads (Restart now) | FR-033 |

## 6. Files (root = `CoreConfig.data_dir` = `Context.getNoBackupFilesDir()`)

| Path | Content | Writer |
|------|---------|--------|
| `wallets/<name>.pwsw` | 001/004 encrypted wallet | `vault-storage-file` via `FsWalletDirectory` + `JournalingDirectory` |
| `sync/`, `received/` | 004/005 records, pending and received ciphertext | moved stores |
| `identity.sealed` | `KeySealer.seal("passwsync identity v1", encode_device_key(key))` | `files::write_private_atomic` |
| `peers.sealed` | `KeySealer.seal("passwsync peers v1", encode_peers(pins))` | `SealedPeerStore` |
| `device-id` | vault `DeviceId` (non-secret) | `files::load_or_create_device_id` |
| `settings` | 002/003/004 `key = value` grammar via `config::encode` | `files::write_private_atomic` |
| `clipboard-pending` | `deadline_boottime_s=<u64>\nclip_timestamp=<i64>\n` (no value, no hash) | `files::write_private_atomic`; removed after clear |

Directories 0700, files 0600, atomic rename; nothing outside `data_dir` (FR-030, FR-031).
`KeySealer` receives only the two labels above (FR-035 test with a recording sealer and a wallet
marker).

## 7. Threads

Core sweeper (15 s, condvar; parked in background), the moved 003/004/005 threads while the node
runs, nothing else. `UiNotifier.changed` and `LogSink.line` may be called from any of them; Kotlin
must not call back into the core synchronously from those callbacks.

## 8. Host tests (passwsync-ffi/tests)

| File | Covers |
|------|--------|
| `protections.rs` | `FakeProcess`: each failure ⇒ create/unlock/change/open refused with `ProtectionMissing{which}`; levels full / secrets-only / none; status + one `ProtectionLevel` log line |
| `memprotect.rs` | `WipeOnFree<Recording>` zeroes every block before inner dealloc (incl. realloc); `PageLocker` refcount (two buffers on one page; unlock order), limit exhaustion ⇒ graceful no-lock |
| `secrets.rs` | non-UTF-8 ⇒ `InvalidInput`; inbound buffers wiped on success and every error path (instrumented `SecretInput`) |
| `wallets.rs`, `credentials.rs` | every wallet/credential method; wrong password = corrupt message; 128 MiB cap; atomic save failure leaves file intact (fault-injecting dir) |
| `autolock.rs` | idle via `FakeElapsedClock` incl. suspend; sync activity does not touch; screen-off; new core instance starts all locked |
| `clipboard.rs` | deadline, lock, screen-off, background deadline via `on_deadline`, marker at next start, "cannot inspect ⇒ clear", "replaced by other app ⇒ keep"; reveal expiry |
| `settings.rs` | ranges, invalid ⇒ defaults + networking off + notice, confirmation required, restart_required |
| `identity.rs` | seal labels, tamper ⇒ `identity_unusable`/`peers_unusable` + networking off, `reset_identity` clears pins, no wallet bytes ever sealed |
| `network.rs` | networking off ⇒ zero sockets (fd count), paused at start, eligible-interface filter, `multicast_wanted`, linger ≤ 10 s / ≤ 120 s with transfer |
| `pairing_loopback.rs`, `sync_loopback.rs`, `share_loopback.rs` | two/three cores over loopback (`testkit` policy), and core ↔ desktop interop against a plain `HostCore` wired exactly as passwsyncd wires it (no dev-dependency on `passwsyncd`); Fg refusals; background cancels |
| `window.rs`, `background_plan.rs` | window bounds, early finish, refusals, unsent ⇒ extra window, off/no peer ⇒ no plan |
| `leakage.rs` | marker password/username/notes/code never in any `CoreError` Display/Debug, log line, list/search record, sealed plaintext, settings or marker file (SC-003) |
| `unsafe_scope.rs`, `api_surface.rs` | §1 rules; exported-method inventory equals §5 (fails on undocumented export) |
