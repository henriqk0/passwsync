# Contract: Shared Runtime Extraction (`crates/host-runtime`)

Implements FR-004 and SC-004 (research R4). The runtimes that both hosts need are **moved**
from `passwsyncd` into the new library crate `host-runtime`. Code exists once; `passwsyncd`
behaves identically and its test files stay **unchanged** (same bytes).

## 1. Crate

```toml
[package]
name = "host-runtime"          # lib name host_runtime
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[lints]
workspace = true               # unsafe_code = "forbid"

[features]
testkit = ["wallet-service/testkit", "vault-core/testkit", "device-link/testkit",
           "device-link-net/testkit", "wallet-sync/testkit"]

[dependencies]
wallet-service, vault-core, vault-storage-file, device-link, device-link-net, wallet-sync  # path deps
rustix (workspace: mm, process, fs, time, std), rand_core (getrandom), sha2, zeroize (derive)
```

Forbidden dependencies (architecture test `tests/architecture.rs` reads `Cargo.toml`):
`passwsyncd`, `passwsync-ffi`, `uniffi*`, `httparse`, `signal-hook`, `qrcodegen`, `serde_json`.

## 2. What moves (by `git mv`, then the edits listed in §3)

| From `crates/passwsyncd/src/` | To `crates/host-runtime/src/` | Notes |
|-------------------------------|-------------------------------|-------|
| `log.rs` | `log.rs` | whole closed set; `fatal` leaves (§3.2) |
| `config.rs` | `config.rs` | grammar, `Settings`, `NetworkSettings`, `load`, `parse`; + `encode` |
| `clock.rs` | `clock.rs` | `OsElapsedClock` (MONOTONIC + BOOTTIME) |
| `fs_dir.rs` | `fs_dir.rs` | `FsWalletDirectory` |
| `hex.rs` | `hex.rs` | becomes `pub mod hex` (used by `files`, `share_store`); passwsyncd's `http/guard.rs`, `http/pages.rs`, `http/api_share.rs` use it through a private facade `mod hex { pub use host_runtime::hex::*; }` |
| `hardening.rs` | `hardening.rs` | `Hardening`, `OsHardening`, `FakeHardening`, `apply`, `memlock_sufficient`, `REQUIRED_MEMLOCK_BYTES` |
| `net_store.rs` | `net_store.rs` | `FilePeerStore` |
| `net_runtime.rs` | `net_runtime.rs` | `NetRuntime`, `NetDeps`, `NetState`, `ThisDevice`, `NetOff` |
| `sync_store.rs` | `sync_store.rs` | `FileSyncStore`, `WriteStep`, `classify` |
| `sync_runtime.rs` | `sync_runtime.rs` | `SyncRuntime`, `SyncShared`, `FsWalletSource`, `JournalingDirectory`, `WarningView` |
| `share_store.rs` | `share_store.rs` | `FsReceivedStore`, `ReceiveFault`, `encode_meta` |
| `share_runtime.rs` | `share_runtime.rs` | `ShareRuntime`, `ShareCore`, `ShareError`, … + `new_invite_code` (from `qr.rs`) |
| `paths.rs` (parts) | `files.rs` | `ensure_private_dir`, `read_private_file`, `write_private_atomic`, `load_or_create_device_id`, `load_or_create_device_key`, `DeviceFileError`, `PathError` |
| `app.rs` steps 5a–5e | `wiring.rs` | `HostCore::assemble`, `HostCore::tick`, `sweep_locks` |

Stays in passwsyncd: `main.rs`, `app.rs` (start-up order, protections policy, listener,
instance lock, launch file, signals, exit codes), `assets.rs`, `http/*`, `paths.rs` (XDG
resolution, `Env`, `Paths`, re-exports of `files`), `peer.rs`, `qr.rs` (QR rendering),
`signals.rs`, `sweeper.rs` (thread + rejection flush; calls `host_runtime::wiring::sweep_locks`).

## 3. Seams (the only non-mechanical edits)

### 3.1 Identity port for `NetRuntime::start`

```rust
/// Where the device identity and the pins live (desktop: plain owner-only files;
/// Android: Keystore-sealed blobs).
pub trait IdentityStore: Send + Sync {
    fn load_or_create_key(&self) -> Result<DeviceKey, IdentityError>;
    fn peer_store(&self, own_public: [u8; 32], policy: AddressPolicy) -> Arc<dyn PeerStore>;
}
pub enum IdentityError { Unusable }

impl NetRuntime {
    pub fn start(settings: NetworkSettings, identity: &dyn IdentityStore,
                 deps: NetDeps, log: &Log) -> Self;      // was (…, paths: &Paths, …)
}
```

passwsyncd adds `paths::FileIdentity<'a>(&'a Paths)` implementing it with exactly the previous
calls (`load_or_create_device_key(&paths.device_key_file)`, `FilePeerStore::new(paths.peers_file
…)`). `NetDeps` keeps **exactly** its five public fields (`policy`, `interfaces`, `timing`,
`announce_ports`, `sync`) and `production()`: passwsyncd's `tests/common/server.rs` builds it with
a struct literal.

### 3.2 Log prefix and `fatal`

```rust
impl Log {
    pub fn stderr() -> Self;                                  // prefix "passwsyncd" (unchanged)
    pub fn to_buffer() -> (Self, Arc<Mutex<Vec<u8>>>);        // prefix "passwsyncd" (unchanged)
    pub fn with_sink(prefix: &'static str, sink: Arc<Mutex<dyn Write + Send>>) -> Self;  // new
    pub fn emit(&self, event: &LogEvent<'_>);                 // "{prefix}: {event}" (unchanged text)
    pub fn line(&self, text: &dyn std::fmt::Display);          // new, used by passwsyncd's fatal
}
```

passwsyncd: `pub trait FatalLog { fn fatal(&self, error: &StartError); }` implemented for `Log`
via `line`; `app.rs` imports it, call sites unchanged.

### 3.3 Additive APIs used only by the app (passwsyncd never calls them)

| API | Purpose (FR) |
|-----|--------------|
| `NetRuntime::pause()` / `resume()` / `is_paused()` | close every socket and drop the node but keep identity/pins in memory; restart node (FR-042, FR-045) |
| `NetRuntime::set_interfaces(Arc<dyn InterfaceSource>)` | eligible-interface source swap before resume (FR-039) |
| `SyncRuntime::has_unsent_changes() -> bool` | local state not covered by any peer mark (FR-046) |
| `SyncRuntime::rounds_idle() -> bool` | every reachable peer's round finished (FR-045) |
| `config::encode(&Settings) -> String` | settings screen writes (FR-033); `parse(encode(s)) == s` property test |
| `LogEvent::{ProtectionLevel, NetworkSwitched, WindowStarted, WindowEnded, ClipboardCleared, IdentityReset, SettingsReset}` | app lifecycle events (FR-008, FR-057) |
| `wiring::HostCore` | composition shared by both hosts (below) |

### 3.4 `HostCore` (composition of passwsyncd start-up steps 5a–5e)

```rust
pub struct HostDirs { pub wallets: PathBuf, pub sync: PathBuf, pub received: PathBuf }
pub struct HostCore {
    pub service: Arc<Service>, pub net: Arc<NetRuntime>,
    pub sync: Arc<SyncRuntime>, pub share: Arc<ShareRuntime>,
}
impl HostCore {
    /// 5a/5b net start, TransferSlots(2), FsReceivedStore, SyncRuntime, JournalingDirectory over
    /// FsWalletDirectory, Service, sync.attach, sync.start if networking on and key held,
    /// ShareRuntime, lock observer, share.startup_cleanup — in this exact order.
    pub fn assemble(dirs: &HostDirs, settings: &Settings, identity: &dyn IdentityStore,
                    net: NetDeps, service: ServiceConfig, elapsed: Arc<dyn ElapsedClock>,
                    log: &Log) -> Self;
    /// The sweeper `extra` closure: net.tick(now); share.tick().
    pub fn tick(&self, now: Duration);
}
/// Suspend check + idle sweep with the Locked/SuspendDetected log events (from sweeper.rs).
pub fn sweep_locks(service: &Service, log: &Log);
```

`passwsyncd::app::start_with` calls `HostCore::assemble` between "listener bound" and "signals",
then continues with sessions, launch file, `AppState`, sweeper and server exactly as before.
Order of side effects (log lines, files created) is identical; `tests/startup*.rs` and
`tests/log.rs` prove it.

### 3.5 Import rewrites inside moved modules (mechanical, required)

- `net_store.rs`: `crate::paths::{read_private_file, write_private_atomic}` becomes `crate::files::…`.
- `share_store.rs`: `crate::paths::write_private_atomic` becomes `crate::files::write_private_atomic`.
- `net_runtime.rs`: the `crate::paths::{self, Paths}` import is removed together with the §3.1 seam.
- `share_runtime.rs`: `crate::qr::new_invite_code` becomes the local, moved `new_invite_code`.
- `log.rs`: the `crate::app::StartError` use is removed together with `fatal` (§3.2).
- After these rewrites no moved module imports `crate::{app,http,peer,qr,signals,sweeper,assets,paths}`; `host-runtime/tests/scans.rs` asserts this (task T007).

## 4. Facade files in passwsyncd

Every moved module keeps a file at its old path containing only re-exports, e.g.

```rust
//! Moved to `host-runtime` (007, FR-004); re-exported so paths stay stable.
pub use host_runtime::sync_runtime::*;
```

`lib.rs` keeps `pub mod` for each (`log`, `config`, `clock`, `fs_dir`, `hardening`,
`net_runtime`, `net_store`, `sync_runtime`, `sync_store`, `share_runtime`, `share_store`).
`paths.rs` re-exports the `files` items it used to define. `qr.rs` re-exports
`new_invite_code`. Facades contain no logic.

## 5. Invariants (each is a test or a gate)

| # | Invariant | Check |
|---|-----------|-------|
| X1 | `git diff --stat main -- crates/passwsyncd/tests` is empty | `android/verify.sh` step `passwsyncd-tests-unchanged` |
| X2 | `cargo test -p passwsyncd --frozen --offline` passes (incl. `#[ignore]` set unchanged) | verify step `workspace-tests` |
| X3 | `host-runtime` forbids unsafe, prints nothing (`println!`, `eprintln!`, `dbg!`, `print!(`), logs only via `LogEvent`, never derives `Debug` for code/password/proof/rid holders | `host-runtime/tests/scans.rs` (same rules as passwsyncd's 004/005 scans, over the moved files). passwsyncd's own scans (unchanged) read the facades after the move and still pass, but no longer cover the moved code; this guard is the one for moved code |
| X4 | No dependency cycle; dependency directions as in §1; core crates never mention `android`, `uniffi`, `jni` | `host-runtime/tests/architecture.rs`, `passwsync-ffi/tests/api_surface.rs` (Cargo cannot build cycles; the test pins *directions*) |
| X5 | `HostCore::assemble` emits the same log lines in the same order as passwsyncd 006 for the same inputs | `host-runtime/tests/wiring.rs` (golden lines taken from passwsyncd's start-up tests) |
| X6 | Additive methods do nothing unless called; `pause()` closes every socket within 1 s, `resume()` restores discovery and pins | `host-runtime/tests/net_pause.rs` (loopback, socket count via `/proc/self/fd` on Linux) |
| X7 | `config::encode` round-trips every valid `Settings`; `parse` behaviour unchanged | `host-runtime/tests/config_encode.rs`; passwsyncd `tests/config.rs` unchanged |
| X8 | `Cargo.lock`: the only new packages are UniFFI's runtime set (research R1) | verify step `lock-diff` lists new packages; `cargo deny` clean |

## 6. Migration order (for tasks)

1. Red: create `host-runtime` with `tests/architecture.rs`, `tests/scans.rs` (failing: files
   absent). 2. Move `log`, `hex`, `files`, `clock`, `config`, `hardening` + facades; run
   passwsyncd suite. 3. Move `fs_dir`, `net_store`, `net_runtime` with the identity seam + facades;
   suite. 4. Move `sync_store`, `sync_runtime`, `share_store`, `share_runtime` (+ `new_invite_code`)
   + facades; suite. 5. Extract `wiring` from `app.rs`; X5 golden test; suite. 6. Additive APIs
   test-first (X6, X7, unsent/idle). Each step ends with the full passwsyncd suite green and X1
   empty.
