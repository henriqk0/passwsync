# Research: Android App (007)

All decisions are non-interactive: the most secure option first, then the simplest
(roadmap global rule). Each entry: **Decision**, **Rationale**, **Alternatives considered**.
Probe results quoted below were measured on the development host on 2026-10-28 in a scratch
workspace (not committed).

## R1. Binding generator: UniFFI 0.32.2, proc-macro mode, Kotlin, library-mode generation

**Decision**: `uniffi = { version = "=0.32.2", default-features = false }` in the boundary crate
(proc-macro mode: `uniffi::setup_scaffolding!()`, `#[derive(uniffi::Object|Record|Enum|Error)]`,
`#[uniffi::export]`, no UDL file, no async exports). Kotlin sources are generated with
**library mode** (`generate --library <host cdylib> --language kotlin --no-format`) by a separate
tool workspace `tools/uniffi-bindgen/` (`uniffi = { version = "=0.32.2", default-features = false,
features = ["cli"] }`, `fn main() { uniffi::uniffi_bindgen_main() }`), excluded from the root
workspace and with its own `Cargo.lock`.

**Rationale / probe evidence**:
- Availability: UniFFI was **not** in the local cargo cache; crates.io was reachable. 0.32.2
  (released 2026-09-23, > 2 weeks old, MPL-2.0 like this project) was fetched once into the
  cache by the probe (`cargo generate-lockfile` + build). Host verification can therefore run
  `--frozen --offline` (SC-001) once the lock files are committed.
- The probe cdylib with an exported object, a byte-vector argument, an error enum and a
  foreign-implemented trait built for `x86_64-unknown-linux-gnu`; library-mode generation wrote
  one Kotlin file (1 810 lines for the probe) that depends only on **JNA** (`com.sun.jna.*`).
  `ktlint` is not installed, so `--no-format` is required (otherwise a warning is printed).
- **Lint scope**: the probe compiled with `#![forbid(unsafe_code)]` at the crate root:
  UniFFI's derive/attribute/scaffolding expansions come from an external proc-macro crate and do
  not trip `unsafe_code`. Therefore only the hand-written memory-protection module needs an
  exception (R6); the generated scaffolding needs none.
- Runtime crates linked into the app library (probe, `-e normal,no-proc-macro`): `uniffi`,
  `uniffi_core`, `uniffi_pipeline`, `anyhow`, `bytes`, `once_cell`, `static_assertions`,
  `tempfile`, `fastrand`, `getrandom 0.4`, `heck`, `indexmap`, `hashbrown`, `equivalent`,
  `libc`, `linux-raw-sys`, `rustix`, `bitflags`, `cfg-if` (several already in our lock). Build-only
  (proc-macro): `uniffi_macros`, `uniffi_meta`, `uniffi_internal_macros`, `syn`, `quote`,
  `proc-macro2`, `serde`, `toml`, `winnow`, `camino`, `fs-err`, `siphasher`.
- The `cli` feature adds ~40 more crates (`clap`, `askama`, `goblin`, `weedle2`, `basic-toml`,
  `textwrap`, …). In one workspace Cargo feature unification would put them in the root lock and
  `cargo deny` reports **RUSTSEC-2026-0374 (`basic-toml` unmaintained)** through
  `askama_derive`. Keeping the generator in its own workspace keeps the root lock (desktop + app)
  free of them, and the advisory is ignored only in the tool's own `deny.toml`, with reason
  "build-time template parsing of our own templates, never shipped".
- `cargo deny --offline check` with the project `deny.toml` on the library-only set: advisories
  ok, licenses ok (MIT/Apache/MPL), bans ok (duplicate warnings only: `getrandom` third major,
  `syn` 2/3, already tolerated). `cargo audit --no-fetch`: no vulnerability.

**Alternatives considered**: UDL file (extra IDL to keep in sync, no benefit with proc-macros);
hand-written JNI (`jni` crate; large amounts of `unsafe`-adjacent glue and manual lifetime
management, violates FR-005 spirit); `flapigen`/`rifgen` (unmaintained); generator in the root
workspace (pollutes the shipped lock, needs a workspace-wide advisory ignore); a newer `0.32.x`
release if any appears later (must be ≥ 2 weeks old and re-vetted; pinned with `=`).

## R2. App language, UI toolkit and third-party libraries

**Decision**: Kotlin with the **platform** toolkit only: `android.app.Activity`, plain `View`s
and XML layouts, `Theme.DeviceDefault`, `android.app.job.JobScheduler`/`JobService`,
`android.security.keystore` + `javax.crypto`, `android.content.ClipboardManager`,
`android.net.ConnectivityManager`. Runtime libraries: **`kotlin-stdlib`** (implicit) and
**`net.java.dev.jna:jna:5.19.1@aar`** (required by UniFFI Kotlin bindings; 2026-06-12). No
AndroidX, no Material, no Compose, no coroutines, no WorkManager, no Google Play services.

**Rationale**: every AndroidX artifact adds code, manifest entries (e.g. `androidx.startup`
`InitializationProvider`, WorkManager receivers and its own `SystemJobService`) and supply-chain
surface; the platform APIs cover all needs since API 33. Fewer merged-manifest components makes
FR-055 (one exported component) hold without `tools:node="remove"` tricks.

**Alternatives considered**: Jetpack Compose (large dependency tree, compiler plugin);
WorkManager (adds receivers/services/providers to the merged manifest, its own DB); AppCompat
(only needed for old APIs, minSdk is 33).

## R3. SDK levels, build tool versions, local-network permission

**Decision**: `minSdk = 33` (spec), `compileSdk = 37`, `targetSdk = 37` (Android 17).
Android Gradle Plugin **9.4.1** (2026-09-18) with AGP's built-in Kotlin support (no separate
`kotlin-android` plugin; Kotlin Gradle Plugin version as resolved by AGP 9.4.1, recorded by
Gradle dependency locking); Gradle **9.8.1** (2026-10-07) installed on the device-build host
(no wrapper JAR committed: a binary blob that cannot be produced or reviewed here). Gradle
dependency locking (`gradle.lockfile`) and dependency verification
(`gradle/verification-metadata.xml`, SHA-256) are generated on the first device build and
committed then (device task). NDK: an LTS r28 or newer, version pinned in
`android/rust-android.env` and checked by `android/build-rust.sh`.

Local network: apps targeting **SDK 37** have local-network access blocked by default and must
hold the runtime permission **`android.permission.ACCESS_LOCAL_NETWORK`** (`NEARBY_DEVICES`
group); apps targeting < 37 get an implicit grant through `INTERNET`
([Local network permission](https://developer.android.com/privacy-and-security/local-network-permission)).
The app declares it and requests it **only** when the person confirms turning networking on
(FR-038); refusal keeps networking off. On API 33–36 devices the permission is not enforced and
the request is skipped.

**Rationale**: targeting the newest stable SDK gives the platform-enforced consent layer for LAN
access on top of the in-app switch (most secure); versions chosen are ≥ 2 weeks old.

**Alternatives considered**: `targetSdk = 36` (no runtime permission; simpler but loses the OS
gate and would be forced up later); AGP 9.5.0 (released the day of planning, too new); Gradle
9.8.2 (9 days old); committing `gradle-wrapper.jar` (unreviewable binary).

## R4. Shared runtime extraction (FR-004)

**Decision**: new library crate **`crates/host-runtime`** receives, by `git mv` plus minimal
edits, the passwsyncd modules both hosts need: `log`, `config`, `clock`, `fs_dir`, `hex`,
`hardening` (the `Hardening` trait and its `rustix` implementation; each host keeps its own
policy for applying it), `net_store`, `net_runtime`, `sync_store`, `sync_runtime`,
`share_store`, `share_runtime`, and the
private-file helpers + device id/key loaders from `paths` (as `files`). A new `wiring` module
holds the composition steps 5a–5e of `passwsyncd::app::start_with` (`HostCore::assemble`) and the
lock part of the sweeper tick. passwsyncd keeps HTTP, UI assets, XDG paths, hardening, signals,
peer-UID, QR rendering, instance lock and start-up, and **re-exports** every moved module under
its old path through thin facade files (e.g. `src/sync_runtime.rs` = `pub use
host_runtime::sync_runtime::*;`). Full contract: [contracts/shared-runtime-extraction.md](contracts/shared-runtime-extraction.md).

**Rationale**: passwsyncd's integration tests import `passwsyncd::{log, config, clock, fs_dir,
net_runtime, net_store, sync_store, share_store, paths, sweeper}` and two scan tests read
`src/sync_runtime.rs`, `src/sync_store.rs`, `src/share_runtime.rs`, `src/share_store.rs` and
`src/qr.rs` by path; facade files keep every test **byte-for-byte unchanged** (SC-004) while the
code exists once. The moved modules depend only on `wallet-service`, `wallet-sync`,
`device-link(-net)`, `vault-core`, `vault-storage-file`, `rustix`, `rand_core`, `sha2`,
`zeroize` (checked by grep of their `use` lines): no HTTP, signals or QR. Dependency graph stays
acyclic: `passwsyncd → host-runtime → {wallet-service, wallet-sync, device-link-net,
device-link, vault-storage-file, vault-core}`, `passwsync-ffi → host-runtime (+ same)`.

The only non-mechanical seams (all additive, desktop behaviour identical):
1. `NetRuntime::start` takes an `IdentityStore` port instead of `&Paths` (passwsyncd passes
   `FileIdentity`, a 20-line adapter over the existing files); `NetDeps` keeps exactly its five
   fields because tests build it with a struct literal.
2. `Log` gets a line prefix (`Log::stderr()`/`to_buffer()` keep `"passwsyncd"`), and
   `Log::line(&dyn Display)`; `fatal(&StartError)` becomes a passwsyncd extension trait
   (call syntax `log.fatal(&error)` unchanged).
3. `share_runtime` calls `host_runtime::share_runtime::new_invite_code` (moved from `qr.rs`; `qr.rs`
   re-exports it).
4. Additive methods for the app: `NetRuntime::{pause, resume, is_paused}`,
   `SyncRuntime::{has_unsent_changes, rounds_idle}`, `config::encode`; new `LogEvent` variants for
   app lifecycle events. passwsyncd never calls them.

**Alternatives considered**: copying the runtimes into the boundary crate (forbidden by FR-004);
moving tests together with code (changes passwsyncd tests, violates SC-004 "unchanged"); a
`RuntimeEvent` + `EventLog` trait split instead of moving `log.rs` (more churn, two closed sets
to keep in sync); making passwsyncd a library dependency of the boundary crate (drags HTTP,
signal-hook, qrcodegen, httparse into the app).

## R5. Boundary crate shape: one coarse object, ports as foreign traits

**Decision**: crate **`crates/passwsync-ffi`** (`crate-type = ["cdylib", "lib"]`, lib name
`passwsync_ffi`). Exported surface: one object `PasswsyncCore` (constructor `start`), plain
records/enums for views, one error enum `CoreError`, and four foreign-implemented traits
(`#[uniffi::export(with_foreign)]`): `KeySealer`, `Clipboard`, `LogSink`, `UiNotifier`. All
calls are synchronous; Kotlin calls blocking ones (unlock, create, sync window, transfers) from a
single background executor thread. Android-specific inputs that are *data*, not behaviour
(app-private directory path, eligible interface names, lifecycle and screen events) arrive as
method arguments. Full contract: [contracts/ffi-api.md](contracts/ffi-api.md).

**Rationale**: coarse calls keep the boundary small and auditable (FR-002); all policy (timers,
clipboard deadline, lock rules, background plan, settings validation, window bounds) lives in
Rust and is host-testable (Principle III); the Kotlin side is a thin adapter that cannot be
compiled here. Each foreign trait has an in-memory fake in the crate's `testkit` feature
(FR-003).

**Alternatives considered**: fine-grained exports of `wallet-service`/`wallet-sync` types
(huge, leaks internals, every type needs FFI wrappers); async exports (pull in an executor and
`kotlinx-coroutines`); a callback-heavy design where Kotlin drives timers (policy untestable on
the host).

## R6. Unsafe scope, memory locking and wipe-on-free

**Decision**: `passwsync-ffi` does not use `[lints] workspace = true` (whose `forbid` cannot be
relaxed per module); it declares the same lints with `unsafe_code = "deny"` and the crate root
has `#![deny(unsafe_code)]`. Exactly one module, `src/memprotect.rs`, carries
`#![allow(unsafe_code)]`, with a `// SAFETY:` comment per block, and contains:
1. `PageLocker`: reference-counted `mlock`/`munlock` (via `rustix::mm::{mlock, munlock}`, the
   only `unsafe fn`s needed) of the pages under the boundary's secret buffers, so two buffers on
   one page never unlock each other; bounded by the remaining `RLIMIT_MEMLOCK`.
2. `WipeOnFree<A: GlobalAlloc>`: the cdylib's `#[global_allocator]`, wrapping `System`, which
   zeroes every block (volatile, `zeroize`) before freeing it. Generic over the inner allocator
   so host tests verify wiping with a recording fake allocator, without reading freed memory.
Everything else uses safe `rustix` calls: `setrlimit(Core, 0)`,
`set_dumpable_behavior(NotDumpable)`, `getrlimit(Memlock)`, `mlockall(CURRENT | FUTURE)`.

Protection levels (FR-008): **full** when `mlockall` succeeds (limit ≥ current + 256 MiB budget
checked first, as on the desktop); otherwise **secrets only** when the page locker can lock the
boundary buffers; otherwise **none**. Core-dump and non-dumpable failures make the core refuse
create/unlock/change-password/open-received (`CoreError::ProtectionMissing`).

**Rationale**: UniFFI copies every byte vector through a `RustBuffer` that it frees without
wiping (`uniffi_core::RustBuffer::destroy` → `drop(Vec)`, source checked); `snow` keeps key
copies without zeroize (003 residual); decrypted `String`s inside vault-core are dropped normally.
A wipe-on-free allocator closes all three Rust-heap residuals in ~30 lines, which is simpler and
stronger than wrapping each type. Page locking of arbitrary core allocations would need a
locking allocator with its own arena (much more unsafe code); Android has no disk swap by
default (zram only, spec assumption), so "secrets only" covers the buffers the boundary owns.

**Spec impact** (recorded as plan amendment in spec.md): FR-005's single unsafe module is a
*memory-protection* module (locking **and** wipe-on-free); FR-008's "secrets only" level covers
boundary-held secret buffers (password inputs, reveal/copy values, identity plaintext), not
key-derivation scratch or entries held inside vault-core.

**Alternatives considered**: `region`/`memsec` crates (new dependencies for 10 lines);
`zeroizing-alloc` crate (tiny but unreviewed dependency for 20 lines of code we can test);
`mlockall(MCL_FUTURE | MCL_ONFAULT)` without the limit check (later allocations fail with
ENOMEM → crashes); no allocator (leaves three documented residuals open).

## R7. Secrets across the boundary (FR-009, FR-010)

**Decision**: inbound secrets (master password, confirmation, new password, credential password,
pairing code, invite code) are `Vec<u8>` (Kotlin `ByteArray`), UTF-8, wrapped on entry into
`Zeroizing` and converted in place (`String::from_utf8`, no copy) to the `Zeroizing<String>`
that `wallet-service` takes; Kotlin builds the bytes from the `Editable` with a `CharsetEncoder`
(no `String`), then fills the `ByteArray` and the field's chars with zeros in `finally`. Outbound
secrets exist in exactly two calls: `reveal_password` (returns `Vec<u8>`) and `copy_field`
(value handed only to the `Clipboard` port, never returned). List/search/detail records never
carry passwords; `search` results never carry notes. Pairing and invite codes the *phone* shows
are returned as `String` for display (short-lived, not wallet secrets, never logged).

The **only other** secret that crosses is the device identity private key, as plaintext of
`KeySealer::seal/open` (R8). The caller-requested rule "no secrets across the boundary beyond
explicit reveal/copy" is therefore met **with two recorded exceptions**: inbound password/code
entry (inherent) and the identity blob for platform-key-store sealing (inherent to FR-034).

**Residuals** (documented): JVM copies the platform makes (`Editable` internals before wiping,
`TextView` text for a revealed password, `ClipData` and the system clipboard service) cannot be
wiped by the app; JNA's transient native memory for `RustBuffer` is Rust-allocated and therefore
wiped by R6.

**Alternatives considered**: `String` parameters (immutable, unwipeable on the JVM; forbidden by
FR-009); returning the copy value to Kotlin (needless extra crossing); a hand-written
`FfiConverter` that lifts in place (depends on UniFFI internals; R6 covers the same copy).

## R8. Platform key store use (FR-034, FR-035, FR-037)

**Decision**: one AES-256 key, alias `passwsync-identity-v1`, generated with
`KeyGenParameterSpec(PURPOSE_ENCRYPT | PURPOSE_DECRYPT)`, `BLOCK_MODE_GCM`,
`ENCRYPTION_PADDING_NONE`, `setRandomizedEncryptionRequired(true)`,
`setUserAuthenticationRequired(false)`, `setUnlockedDeviceRequired(false)`,
`setIsStrongBoxBacked(true)` with fallback to TEE when StrongBox is absent; never exported.
Kotlin `KeystoreSealer` implements `KeySealer.seal(label, plaintext) → iv ‖ ciphertext ‖ tag`
(`AES/GCM/NoPadding`, 96-bit IV chosen by Keystore, 128-bit tag, AAD = label) and
`open(label, blob)`. Rust owns the files: `identity.sealed` (label `passwsync identity v1`,
plaintext = 003 `encode_device_key`) and `peers.sealed` (label `passwsync peers v1`,
plaintext = 003 `encode_peers`), both written with the existing owner-only atomic writer.
Open failure ⇒ `NetState::IdentityUnusable` or `PeersUnusable` (003 behaviour), networking off,
`reset_identity()` offered (new key, empty pins). Nothing wallet-related ever reaches
`KeySealer` (FR-035; host test with a recording fake asserts labels and that no wallet marker
appears in any sealed plaintext).

**Rationale**: the key is non-exportable and hardware-backed when possible, AES-GCM in Keystore
is vetted platform crypto (no hand-rolled crypto), the AAD label prevents swapping the two
blobs, GCM gives tamper detection. No user authentication or unlocked-device requirement because
background windows must open the channel while the screen is locked.

**Alternatives considered**: Keystore wraps a data key that Rust uses with `aes-gcm` (the data key
would be exportable app memory, weaker than FR-034); Keystore X25519 keys (`snow` needs raw
private keys); EncryptedFile (AndroidX security-crypto, deprecated, extra dependency).

## R9. Clipboard (FR-021–FR-024)

**Decision**: policy in Rust (`clipboard.rs`), mechanism in Kotlin. `copy_field` fetches the
value, calls `Clipboard::set_sensitive(value)`, writes the non-secret marker
`clipboard-pending` (content: deadline in boot-time seconds and the clip timestamp returned by
the port), and records the deadline. Clearance runs on the first of: deadline reached (core timer
while alive, or the deadline job, R10), any lock (manual, idle, screen-off), core start with a
marker present (FR-023). `Clipboard::clear_if_ours(timestamp)` clears when the current clip's
`ClipDescription` timestamp equals the recorded one **or the clip cannot be read** (background
read restriction). Kotlin sets `ClipDescription.EXTRA_IS_SENSITIVE = true` in a
`PersistableBundle` on every clip (policy scan S2). Reveal deadline = clipboard timeout, also
returned by the core; `UiNotifier` announces `RevealExpired`/`Locked` so Kotlin hides it.

**Rationale**: all timing and marker rules become host tests with a fake clipboard and fake
clock; Android 13+ blocks background clipboard reads, so "cannot be checked ⇒ clear" is the only
safe rule.

**Alternatives considered**: comparing the clip content (needs reading the secret back; not
possible in background); clearing on going to background (breaks pasting into another app).

## R10. Lifecycle, timers and background work (FR-016, FR-017, FR-042–FR-048)

**Decision**:
- Foreground: a core sweeper thread (15 s, condvar, like passwsyncd) runs idle locks, suspend
  check, clipboard deadline, net tick, share tick.
- `on_background()` cancels pairing and not-started invitations (FR-051), starts the network
  linger (sockets closed ≤ 10 s, or when the running transfer ends, at most 120 s; FR-042) and
  returns a `BackgroundPlan`: `deadline_in_ms` (earliest of idle-lock and clipboard deadlines),
  `periodic_window_minutes` (sync interval if networking on and ≥ 1 paired device, else none),
  `extra_window` (true when `has_unsent_changes`, FR-046). The sweeper parks while in background
  (zero wakeups from Rust, SC-008).
- Kotlin schedules with **JobScheduler** only: job 1 = deadline (`setMinimumLatency(d)`,
  `setOverrideDeadline(d + 5 s)`), job 2 = periodic window (`setPeriodic(interval)`,
  `setRequiresBatteryNotLow(true)`, `setRequiredNetwork(Wi-Fi|Ethernet, NOT_VPN, INTERNET
  removed)`), job 3 = one extra window (same constraints, no periodic). One non-exported
  `JobService` (`android:permission="android.permission.BIND_JOB_SERVICE"`) dispatches by job id
  to `core.on_deadline()` or `core.run_sync_window()` on a background thread. Jobs are **not
  persisted** across reboot (that needs `RECEIVE_BOOT_COMPLETED`, forbidden by FR-054); the plan
  is re-applied at every app start and every `on_background`.
- `on_screen_off()` (runtime-registered `ACTION_SCREEN_OFF` receiver, `RECEIVER_NOT_EXPORTED`)
  locks all wallets and clears the clipboard immediately (FR-017, FR-022).
- `run_sync_window()` (≤ 120 s): resume node, announce, start rounds for every reachable paired
  peer, return as soon as all rounds are idle or the bound is reached, pause node (every socket
  closed, multicast lock released by Kotlin after return), sweep expired received wallets
  (FR-052). It refuses to run when networking is off, no peer is paired, or no eligible
  interface exists.
- Idle clock: `CLOCK_BOOTTIME` (counts deep sleep), already used by `OsElapsedClock`.

**Rationale**: no foreground service, no exact alarms, no battery exemption (FR-044); every
decision is a pure function of core state, tested on the host.

**Alternatives considered**: WorkManager (R2); `AlarmManager.set` inexact for the deadline
(unbounded delay, extra API); persisted jobs (needs a forbidden permission); a Rust timer while
in background (frozen by the cached-app freezer anyway, and wakes the CPU).

## R11. Interface eligibility (FR-039)

**Decision**: Kotlin `NetworkClassifier` uses `ConnectivityManager.registerNetworkCallback` for
networks with `TRANSPORT_WIFI` or `TRANSPORT_ETHERNET` and `NET_CAPABILITY_NOT_VPN`, and passes
their `LinkProperties.interfaceName`s to `core.set_eligible_interfaces(names)`. The core wraps
`OsInterfaces` in `EligibleInterfaces` (an `InterfaceSource` that keeps only those names, after
the 003 private/link-local address filter). Empty set ⇒ `no_local_network`, no window.

**Rationale**: an IPv4 private address alone cannot distinguish Wi-Fi from carrier or VPN
interfaces (some carriers hand out 10.x); the platform's transport classification is
authoritative, Rust keeps the address filter.

**Alternatives considered**: interface-name heuristics (`wlan*`, unreliable); Rust-only
classification (no transport information below the framework).

## R12. Storage layout and backup (FR-030–FR-033)

**Decision**: root = `Context.getNoBackupFilesDir()` (app-private, internal, excluded from Auto
Backup by the platform) with `wallets/`, `sync/`, `received/`, `identity.sealed`,
`peers.sealed`, `device-id`, `settings`, `clipboard-pending` (contracts/ffi-api.md "Files").
All created owner-only by the moved host-runtime helpers. Manifest:
`android:allowBackup="false"`, `android:dataExtractionRules="@xml/data_extraction_rules"`
excluding every domain from both `<cloud-backup>` and `<device-transfer>`,
`android:hasFragileUserData="false"`. Settings use the existing 002/003/004 `key = value`
grammar (`host-runtime::config`) plus a new `encode`; invalid ⇒ defaults with networking off and
`settings_reset = true` reported once (FR-033). Settings changes are saved immediately and
**applied at the next app start**; the settings screen offers "Restart now" (locks all, exits
the process). This mirrors the desktop (config read once at start).

**Rationale**: two independent backup barriers; reuse of the reviewed parser and writer; no
runtime reconfiguration paths in the shared runtimes.

**Alternatives considered**: `filesDir` (backed up unless rules work); SharedPreferences
(second store, XML in a backed-up domain); live reconfiguration (new code in NetRuntime/Service
for a rare action).

## R13. KDF memory ceiling (FR-014)

**Decision**: reuse `wallet_service::KDF_MEMORY_CAP_KIB` = **128 MiB** unchanged; wallets above
it are refused before derivation with the existing `KdfParamsOutOfRange` code (distinct message).
Wallets created on the phone use `KdfConfig::DEFAULT` (64 MiB), so desktop and phone open each
other's wallets.

**Rationale**: stricter than the spec's 256 MiB, no change to wallet-service, and lower peak
memory on phones (SC-011). Recorded as plan amendment to FR-014 and the edge case.

**Alternatives considered**: a per-host cap parameter in `ServiceConfig` (wallet-service change
for a looser limit).

## R14. Logging (FR-057)

**Decision**: the moved closed `LogEvent` set (host-runtime) gains app events
(`ProtectionLevel`, `NetworkSwitched`, `WindowStarted`, `WindowEnded{peers, rounds, reason}`,
`ClipboardCleared{reason}`, `IdentityReset`, `SettingsReset`) and is written through
`Log::with_sink("passwsync", LogSinkWriter)` to the Kotlin `LogSink`, which calls
`android.util.Log.i("passwsync", line)` and nothing else. Kotlin code never logs anything else
(scan S8). Release builds keep these non-secret lines (FR-057 allows them).

**Alternatives considered**: Rust writing to `/dev/log`/`__android_log_write` (needs `unsafe`
FFI or another crate); no logs (loses the FR-008 "logged" requirement).

## R15. Host verification and policy checks (FR-058, FR-059)

**Decision**: `android/verify.sh` (bash) orchestrates; checks over XML and Kotlin text are
**Python 3 standard-library** scripts run with `python3 -I` (`xml.etree.ElementTree`, `re`,
`unittest`), no pip packages; `xmllint --noout --nonet` for well-formedness. Negative tests are
**mutations**: `android/policy/mutations.py` lists, per rule id, an edit (replace/insert/add
file) applied to a temporary copy of `android/`; the checker must fail *with that rule id*
(SC-002) and must pass on the untouched tree. Binding checks run the same way on the generated
Kotlin. Dependency vetting: `cargo deny --offline check` and `cargo audit --no-fetch` on the root
workspace and on `tools/uniffi-bindgen`; root `deny.toml` gains a `[bans] deny` list of
networking/telemetry crates (FR-040). Kotlin linter (`ktlint`) runs only when on `PATH`; absence
prints `SKIPPED ktlint (not installed)` and does not fail. Full contract:
[contracts/verify.md](contracts/verify.md); rules: [contracts/android-policy.md](contracts/android-policy.md).

**Tools present on the host (checked)**: `cargo 1.99.1`, `rustc 1.99.1`, `cargo-deny 0.20.2`,
`cargo-audit 0.22.2` (advisory DB 2026-10-24 at `~/.cargo/advisory-db`; both cargo tools live in `~/.cargo/bin`), `python3`, `xmllint`, `java`. Absent:
`kotlinc`, `ktlint`, `detekt`, `gradle`, Android SDK/NDK, Android Rust targets.

**Alternatives considered**: Rust tests with an XML crate (`roxmltree`: new dependency in the
shipped lock for a dev check); full sample trees per rule (bulky, drift from real sources);
Android Lint (needs the SDK).

## R16. Cross-compilation (device-only)

**Decision**: `android/build-rust.sh` (run on a host with rustup + NDK) builds
`passwsync-ffi` for `aarch64-linux-android` (arm64-v8a) and `x86_64-linux-android` (emulator)
with `--release --frozen`, linker `<ndk>/toolchains/llvm/prebuilt/linux-x86_64/bin/<triple>33-clang`,
`-C link-arg=-Wl,-z,max-page-size=16384` (16 KB pages), copies `libpasswsync_ffi.so` to
`android/app/src/main/jniLibs/<abi>/`, and generates Kotlin bindings from the host build into
`android/app/build/generated/uniffi/` (Gradle source dir). Gradle runs no `Exec` tasks.

**Alternatives considered**: `cargo-ndk` (extra tool); Gradle Rust plugins (third-party plugin
code in the build).

## R17. Process model (FR-011)

**Decision**: single process; manifest check forbids any `android:process` attribute; the core
is a process-wide singleton (`start` refuses a second instance in the same process); the
`JobService` runs in the main process and uses the same core.

## R18. Dependency summary (constitution: minimal, vetted)

| Where | New | Notes |
|-------|-----|-------|
| Root Cargo lock (shipped in app) | `uniffi =0.32.2` + ~25 transitive (R1) | MPL/MIT/Apache; deny/audit clean |
| `tools/uniffi-bindgen` (own lock, dev only) | `uniffi =0.32.2` `cli` + ~40 | one ignored unmaintained advisory (basic-toml), build-time only |
| App (Gradle) | `net.java.dev.jna:jna:5.19.1@aar` | required by UniFFI Kotlin |
| Build tools (device host) | AGP 9.4.1, Gradle 9.8.1, NDK r28+ | locked + verified on first device build |
| desktop `passwsyncd` | none | moved code only |
