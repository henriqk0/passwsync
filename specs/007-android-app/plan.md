# Implementation Plan: Android App

**Branch**: `feat/007-android-app` | **Date**: 2026-10-28 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/007-android-app/spec.md`

## Summary

Add a second host, an Android app, that reuses the Rust core unchanged. Three pieces:

1. **`crates/host-runtime`** (new library): the networking, sync and sharing runtimes, their
   file stores, the closed log set, the settings grammar, OS clocks, the filesystem wallet
   directory and the composition of these (`HostCore`) are **moved** out of `passwsyncd`
   (`git mv` + small additive seams). `passwsyncd` re-exports every moved module under its old
   path, so its full test suite passes unchanged (FR-004, SC-004).
2. **`crates/passwsync-ffi`** (new cdylib): the UniFFI 0.32.2 boundary. One coarse object
   `PasswsyncCore` with wallet, credential, settings, networking, pairing, sync, sharing,
   lifecycle and status calls; four foreign ports (`KeySealer`, `Clipboard`, `LogSink`,
   `UiNotifier`) with in-memory fakes; all policy (protections, clipboard deadlines, screen-off
   lock, background plan, bounded sync windows, Keystore-sealed identity and pins, interface
   eligibility) in host-testable Rust. Unsafe code exists only in `src/memprotect.rs`
   (reference-counted page locking + wipe-on-free global allocator); secrets cross only as
   wipeable byte vectors and only for entry, explicit reveal/copy, and identity sealing.
3. **`android/`**: a Gradle/Kotlin app using only platform APIs plus JNA (single exported
   launcher activity, `FLAG_SECURE` everywhere, recents screenshot off, backup and data
   extraction excluded, cleartext forbidden, JobScheduler windows with Wi-Fi/battery
   constraints, no AndroidX/Play services), and **`android/verify.sh`**: the offline host gate
   (workspace tests, host cdylib build, Kotlin binding generation and checks, XML
   well-formedness, manifest/XML/Gradle policy, source policy scan, mutation negative tests,
   `cargo deny`/`cargo audit`, optional ktlint). Device-only checks are listed in
   [quickstart.md](quickstart.md) and stay pending.

## Technical Context

**Language/Version**: Rust stable (host 1.99.1), edition 2024, MSRV 1.85; Kotlin (AGP 9.4.1
built-in Kotlin); Bash + Python 3 stdlib for verification

**Primary Dependencies**: existing crates (vault-core, vault-storage-file, wallet-service,
device-link, device-link-net, wallet-sync, rustix, zeroize, rand_core, sha2); **new**:
`uniffi =0.32.2` (no default features) in `passwsync-ffi`; `uniffi =0.32.2` with `cli` in the
separate `tools/uniffi-bindgen` workspace; app: `net.java.dev.jna:jna:5.19.1@aar`; build:
AGP 9.4.1, Gradle 9.8.1, NDK r28+ (research R1–R3, R18)

**Storage**: app `noBackupFilesDir`: `wallets/` (001/004 files via `vault-storage-file`),
`sync/`, `received/` (004/005 stores), `identity.sealed` + `peers.sealed` (Keystore AES-GCM
blobs), `device-id`, `settings` (002 grammar), `clipboard-pending` marker; all owner-only,
atomic writes (research R8, R12; contracts/ffi-api.md "Files")

**Testing**: `cargo test` — host-runtime unit/integration tests (moved scans + architecture
test), passwsyncd suite unchanged, passwsync-ffi tests through the Rust API with fakes
(`FakeSealer`, `FakeClipboard`, `RecordingLog`, `RecordingNotifier`, `FakeProcess`,
`FakeElapsedClock`, loopback `AddressPolicy::testkit()` two/three-instance pairing, sync and
sharing), allocator and page-locker unit tests with recording fakes, unsafe-scope and
leak-marker scans; Python `unittest` for the policy checkers; mutation suite for every policy
rule; manual device checks D1–D25 (quickstart)

**Target Platform**: host build/tests on Linux x86_64; app on Android 13+ (API 33) phones,
`arm64-v8a` (+ `x86_64` emulator), compile/target SDK 37

**Project Type**: mobile app (Kotlin shell) + Rust FFI library + shared Rust runtime library

**Performance Goals**: unlock with default KDF < 3 s on a mid-range phone (SC-005); change
visible on the other device ≤ 30 s after the 5 s quiet period in foreground (US5.1);
sync window ≤ 2 min; clipboard cleared ≤ timeout + 5 s (SC-007)

**Constraints**: networking off ⇒ no socket and no scheduled work (FR-038, FR-048); LAN IPv4
private/link-local on Wi-Fi/Ethernet only; no DNS/internet; ≤ 1 periodic window per safety
interval + 1 per foreground exit with unsent changes; < 1 % battery/day idle (SC-009);
< 128 MiB RSS with 1 000 credentials (SC-011); KDF memory cap 128 MiB; unsafe only in
`memprotect.rs`; no third-party Android libraries except JNA

**Scale/Scope**: one person, ≤ 100 wallets, ≤ 32 paired devices (003 bound); ~14 screens in one
activity; FFI surface ≈ 60 methods

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Gate | Pre-research | Post-design |
|-----------|------|--------------|-------------|
| I. Security-First | Encrypted at rest, no plaintext to network/storage/logs/swap, vetted crypto only | PASS — spec reuses the core; Keystore only for the identity | PASS — wallets only via vault-core files in `noBackupFilesDir`; identity/pins sealed by Keystore AES-GCM with AAD labels (R8), **no crypto written by us**; secrets as wipeable bytes, wipe-on-free allocator for the whole Rust heap (R6, R7); core dumps off + non-dumpable fail closed; memory locked full/secrets-only with status (R6); FLAG_SECURE, recents off, backup + D2D excluded, cleartext forbidden, no web view, single exported activity, closed log set (contracts/android-policy.md); EXCEPTION pending approval: non-secret records and wallet file names are plaintext (Complexity Tracking) |
| I. (P2P E2E) | P2P E2E + mutually authenticated | PASS — 003–005 protocols unchanged | PASS — same Noise channel and pins; interface allow-list narrows exposure (R11) |
| II. Simplicity | Simplest equal option; complexity justified | PASS | PASS — one coarse FFI object, platform APIs only, settings apply at restart, policy in Rust, verification in bash + stdlib Python; deviations below |
| III. TDD | Tests first for everything testable on the host | PASS — spec tags 61 FRs [H]/[H+D]/[D] | PASS WITH RECORDED EXCEPTION — every [H] and the host half of every [H+D] maps to a Rust test, a policy rule with a mutation, or a binding check (data-model §10); Kotlin behaviour has no red-first unit test (Complexity Tracking, pending approval) |
| IV. Hexagonal | Core free of infra; ports + fakes | PASS | PASS — domain/application crates untouched; Android concerns enter through 4 foreign ports and plain-data calls; `host-runtime` holds adapters shared by both hosts; graph acyclic (contracts/shared-runtime-extraction.md) |
| V. Resource Efficiency | Deliberate allocation, wiped secrets, measured | PASS | PASS — no background service, parked sweeper in background, JobScheduler constraints, 128 MiB KDF cap, wipe-on-free; SC-008/009/011 measured on device |
| VI. Decentralization | P2P, no server | PASS | PASS — LAN only, no accounts, no Play services |
| Workflow | Minimal, vetted, reviewed deps | PASS | PASS — UniFFI vetted with deny/audit (one tool-only advisory isolated, R1); JNA only Android library; deny list for networking crates (R15) |
| Roadmap globals | Offline, no accounts, master password only secret, key never persisted/wrapped, FR-025a | PASS | PASS — wallet key never reaches Keystore (FR-035 test); unlock once per process; FR-025a via R6 + auto-lock + screen-off lock |

Gates pass. Deviations are listed in Complexity Tracking.

## Project Structure

### Documentation (this feature)

```text
specs/007-android-app/
├── plan.md              # This file
├── research.md          # Phase 0 (R1–R18)
├── data-model.md        # Phase 1
├── quickstart.md        # Phase 1: host validation + device-only checks D1–D25
├── contracts/
│   ├── ffi-api.md                      # exported Rust API, ports, errors, files, secret rules
│   ├── android-policy.md               # manifest/XML/Gradle rules M*, source rules S*, binding rules B*
│   ├── verify.md                       # android/verify.sh CLI, steps, exit codes, mutations
│   └── shared-runtime-extraction.md    # what moves, seams, facades, invariants
├── checklists/requirements.md
└── tasks.md             # Phase 2 (/speckit-tasks; not created here)
```

### Source Code (repository root)

```text
Cargo.toml                      # members += host-runtime, passwsync-ffi; exclude = ["tools/uniffi-bindgen"]
deny.toml                       # + [bans] deny list (networking/telemetry crates)
crates/
├── host-runtime/               # NEW (moved from passwsyncd; lints = workspace, unsafe forbidden)
│   ├── src/ lib.rs log.rs config.rs clock.rs fs_dir.rs hex.rs files.rs hardening.rs
│   │        net_store.rs net_runtime.rs sync_store.rs sync_runtime.rs
│   │        share_store.rs share_runtime.rs wiring.rs (HostCore, sweep_locks)
│   └── tests/ architecture.rs scans.rs wiring.rs net_pause.rs unsent.rs config_encode.rs log_app_events.rs log_seam.rs
├── passwsync-ffi/              # NEW boundary (cdylib + lib; own lints, unsafe denied except memprotect)
│   ├── uniffi.toml             # Kotlin package io.github.henriqk0.passwsync.core, cdylib name
│   ├── src/ lib.rs             # setup_scaffolding!, #![deny(unsafe_code)], #[global_allocator]
│   │        api.rs (PasswsyncCore) records.rs error.rs ports.rs (KeySealer, Clipboard, LogSink, UiNotifier)
│   │        secret.rs (SecretInput) protect.rs (ProcessControls + levels) memprotect.rs (ONLY unsafe)
│   │        dirs.rs settings.rs identity.rs (SealedIdentity, SealedPeerStore) interfaces.rs (EligibleInterfaces)
│   │        clipboard.rs lifecycle.rs (foreground/background/linger, BackgroundPlan) window.rs
│   │        testkit.rs (fakes, feature "testkit")
│   └── tests/ protections.rs memprotect.rs secrets.rs wallets.rs credentials.rs clipboard.rs
│              autolock.rs settings.rs identity.rs network.rs pairing_loopback.rs sync_loopback.rs
│              window.rs background_plan.rs share_loopback.rs leakage.rs unsafe_scope.rs api_surface.rs file_modes.rs testkit_fakes.rs errors.rs api_inventory.txt
├── passwsyncd/                 # moved modules become facade files (pub use host_runtime::…)
├── wallet-service/ wallet-sync/ device-link/ device-link-net/ vault-core/ vault-storage-file/   # unchanged
tools/
└── uniffi-bindgen/             # NEW separate workspace: Cargo.toml, Cargo.lock, deny.toml, src/main.rs
android/
├── settings.gradle.kts build.gradle.kts gradle.properties gradle/libs.versions.toml
├── rust-android.env            # pinned NDK revision, targets, min API
├── build-rust.sh               # device-host only: cross-compile + bindgen (R16)
├── verify.sh                   # offline host gate (contracts/verify.md)
├── policy/ common.py check_manifest.py check_sources.py check_bindings.py mutations.py reviewed-crates.txt
│   └── tests/ test_check_manifest.py test_check_sources.py test_check_bindings.py
└── app/
    ├── build.gradle.kts proguard-rules.pro
    └── src/main/
        ├── AndroidManifest.xml
        ├── kotlin/io/github/henriqk0/passwsync/
        │   ├── PasswsyncApp.kt          # Application: core start, lifecycle counting, screen-off receiver
        │   ├── SecureActivity.kt         # FLAG_SECURE + setRecentsScreenshotEnabled(false)
        │   ├── MainActivity.kt           # the only activity; swaps screen views
        │   ├── SecureDialogs.kt          # every dialog, FLAG_SECURE on its window
        │   ├── Secrets.kt                # Editable → ByteArray (CharsetEncoder), wipe helpers
        │   ├── CoreExecutor.kt           # single background thread for blocking core calls
        │   ├── platform/ KeystoreSealer.kt ClipboardAdapter.kt LogcatSink.kt UiBridge.kt
        │   │             NetworkClassifier.kt MulticastLockHolder.kt LocalNetworkPermission.kt
        │   │             JobPlanner.kt CoreJobService.kt ScreenOffReceiver.kt
        │   └── screens/ WalletList Create Unlock Credentials CredentialView CredentialEdit
        │                Conflicts Settings Network Devices Pairing Share Receive Received SyncStatus
        │                Security About (one *.kt each)
        └── res/ layout/*.xml values/strings.xml values/themes.xml xml/network_security_config.xml
                 xml/data_extraction_rules.xml drawable/ic_launcher_foreground.xml mipmap-anydpi/ic_launcher.xml
```

**Structure Decision**: two new workspace members (`host-runtime`, `passwsync-ffi`), one excluded
tool workspace, and a top-level `android/` directory that holds the Gradle project, its policy
checks and the host gate. Dependencies point inward and stay acyclic:
`passwsyncd → host-runtime`, `passwsync-ffi → host-runtime`, `host-runtime → {wallet-service,
wallet-sync, device-link-net, device-link, vault-storage-file, vault-core}`. No core crate knows
about Android, HTTP or UniFFI (architecture test). The Android files are written during
implementation even though they cannot be built here; their static properties are gated by
`android/verify.sh`.

## Design Decisions (summary; details in research.md)

1. **Extraction by move + facades** (R4): code exists once; passwsyncd test files unchanged;
   seams are additive (identity port, log prefix, pause/resume, unsent-changes query, encode).
2. **Coarse FFI object + four foreign ports** (R5); synchronous calls on one Kotlin executor.
3. **Unsafe**: crate-level `deny`, one `#![allow(unsafe_code)]` module (`memprotect.rs`); every other module file starts with `#![forbid(unsafe_code)]` (FR-005):
   refcounted `mlock` + `WipeOnFree` global allocator; UniFFI expansions need no exception
   (probe-verified) (R6).
4. **Secrets**: `ByteArray` in, `Zeroizing` immediately; out only via `reveal_password` and the
   `Clipboard` port; identity plaintext only to `KeySealer` (R7, R8).
5. **Keystore**: one non-exportable AES-GCM key, StrongBox when present, no user auth; protects
   only identity + pins; tamper ⇒ 003 unusable states + reset offer (R8).
6. **Background**: JobScheduler only (deadline job, periodic window, one extra window), Wi-Fi/
   Ethernet non-VPN + battery-not-low constraints, not persisted; Rust computes the plan (R10).
7. **Settings apply at next start**; networking switch needs in-app confirmation and, on API 37,
   `ACCESS_LOCAL_NETWORK` (R3, R12).
8. **Verification**: one script, stdlib Python checks with mutation-based negative tests,
   deny/audit on both locks, optional ktlint (R15).

## Plan amendments to the spec

Recorded in spec.md "Plan amendments 2026-10-28": FR-005 (memory-protection module includes the
wipe-on-free allocator), FR-008 ("secrets only" = boundary-held buffers), FR-014 + edge case
(KDF ceiling is the existing 128 MiB cap), FR-033 (changes apply at next app start), FR-044
(jobs not persisted across reboot; re-planned at next app start), FR-054 (`ACCESS_LOCAL_NETWORK`
requested when networking is turned on, target SDK 37).

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Android's app seccomp filter or SELinux blocks `mlockall`/`mlock`/`prlimit64`/`prctl` (a blocked syscall can kill the process with SIGSYS instead of returning an error) | These calls are in bionic's app allow-list as far as we know, but this is unverified: device check D3 runs first, on a debug build. An error return lowers the level to "secrets only"/"none"; a core-dump/non-dumpable failure refuses unlock with a named message. If D3 shows a kill, the call is removed and the spec deviation recorded |
| Non-dumpable process breaks JNA or `/proc/self` reads | D3/D4; fall back recorded as spec deviation only if a device proves it |
| Clipboard deadline job delayed by app-standby buckets | App was just in foreground ("active" bucket); `setOverrideDeadline(d+5s)`; screen-off clears at once; D12 measures SC-007 |
| `ACTION_SCREEN_OFF` not delivered while frozen | Receiver registered in Application; on resume `on_foreground()` runs suspend check + idle sweep before showing UI; D9 |
| Broadcast discovery filtered by Wi-Fi power save | `MulticastLock` while networking active (FR-043); manual address remains (003); D16 |
| UniFFI Kotlin binding needs a newer Kotlin than AGP bundles | Generated code checked by B-rules on host; device build D1 confirms; pin KGP explicitly in the version catalog if needed |
| Wipe-on-free cost on large frees (Argon2 64 MiB) | One `memset` per unlock (~10 ms); measured in SC-005 check D6 |
| Wrong eligible-interface set (e.g. hotspot) | Only Wi-Fi/Ethernet transports, NOT_VPN; address filter still applies; D17 |

## Complexity Tracking

| Deviation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| Two new crates (`host-runtime`, `passwsync-ffi`) | FR-004 forbids copying runtimes; FR-002 needs a boundary crate; FR-003 keeps Android out of core crates | Boundary depending on `passwsyncd` drags HTTP/signals/QR into the app; one crate cannot keep UniFFI out of the desktop |
| Separate `tools/uniffi-bindgen` workspace with its own lock | Keeps ~40 CLI crates and an unmaintained-crate advisory out of the shipped lock | Same workspace: feature unification puts them in the root lock and needs a workspace-wide advisory ignore |
| Unsafe module `memprotect.rs` with a global allocator (FR-005 widened) | UniFFI transport buffers, `snow` key copies and core strings are freed unwiped; page locking needs `mlock(ptr)` | No allocator leaves three residuals; a locking arena allocator is far more unsafe code; third-party crates add unreviewed deps for ~30 lines |
| `deny` instead of `forbid` for `unsafe_code` in `passwsync-ffi` | `forbid` cannot be relaxed for one module | Workspace lints apply `forbid` to every member; an unsafe-scope test enforces that only `memprotect.rs` allows it |
| Facade files in passwsyncd for moved modules | SC-004: passwsyncd tests (including path-based scans) unchanged | Editing tests to new paths violates "unchanged"; leaving code in place violates FR-004 |
| JNA dependency | Required by UniFFI Kotlin bindings | Hand-written JNI needs much more glue and native code |
| Python 3 for policy checks | XML parsing + regex with negative tests, stdlib only, present on host | Pure bash cannot parse XML reliably; Rust XML crate adds a dependency to the lock |
| Two JobScheduler job kinds (deadline + windows) | Clipboard/idle deadlines must fire while the app is cached/frozen (FR-016, FR-022) | In-process timers are frozen; exact alarms are forbidden; clearing on background breaks pasting |
| `ACCESS_LOCAL_NETWORK` runtime permission | Target SDK 37 blocks LAN without it | Target 36 avoids it but drops the platform consent layer and must change soon |
| Constitution I exception (PENDING MAINTAINER APPROVAL): non-secret records stored in plaintext (settings, sync/share records, device id, wallet file names) | Spec Session 2026-10-28 Q5 (no key-store encryption of non-secret records); same plaintext-metadata pattern as desktop 002-006; encrypting them needs a storage seam in the shared stores (desktop behaviour must not change, FR-004) and changes the 001 wallet file naming, which is outside this feature (FR-061) | Encrypt everything via `KeySealer` in this feature: rejected for scope and for FR-004. Alternatives for the maintainer: approve this exception, require the seam in a follow-up feature, or amend the constitution in a separate change |
| Constitution I residual (PENDING APPROVAL): JVM copies of secrets (`Editable`, `TextView` for a revealed password, `ClipData`, the system clipboard service) | The platform clipboard and text display require the platform text type (FR-021, FR-024); no byte-only path exists | Minimised: the single `Secrets.platformText` conversion is callable from two sites only (S4); residual documented in research R7 |
| Constitution III exception (PENDING APPROVAL): Kotlin and Gradle behaviour has no red-first unit test | No Kotlin compiler, Android SDK or device on the host (spec Verification constraint) | Shell kept thin; every decision lives in Rust with tests first; Kotlin gated by red-first policy checks and device checks D1-D25 |
