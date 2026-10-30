# Data Model: Android App (007)

No new wallet format, protocol or cryptography (FR-061). This feature adds host-side state
around the existing 001–005 entities. Field-level FFI shapes are in
[contracts/ffi-api.md](contracts/ffi-api.md) §4; this document gives meaning, validation and
state transitions.

## 1. App host instance (`PasswsyncCore`)

One per process (FR-011, R17). Holds:

| Field | Type | Notes |
|-------|------|-------|
| `protection` | `ProtectionStatus` | fixed at `start` |
| `host` | `host_runtime::wiring::HostCore` | Service (wallet registry), NetRuntime, SyncRuntime, ShareRuntime |
| `settings` | `host_runtime::config::Settings` | loaded at start; edits saved, applied next start |
| `lifecycle` | `Lifecycle` (§6) | |
| `clipboard` | `ClipboardState` (§5) | |
| `reveals` | set of `(wallet, entry, deadline)` | in memory only |
| `eligible` | `Arc<EligibleInterfaces>` | names from Kotlin (§8) |
| ports | `KeySealer`, `Clipboard`, `LogSink`, `UiNotifier` | foreign |

Invariant: a new process starts with every wallet locked (no key persisted anywhere; FR-015).

## 2. Protection status (FR-007, FR-008)

```text
ProtectionStatus { core_dumps_disabled, non_dumpable, memory_lock: Full|SecretsOnly|None,
                   can_unlock = core_dumps_disabled && non_dumpable, missing: first failed }
```

Determination at `start`, in order: `setrlimit(RLIMIT_CORE, 0)` → `prctl(PR_SET_DUMPABLE, 0)` →
`getrlimit(RLIMIT_MEMLOCK)`: if soft limit is unlimited or ≥ 256 MiB (the desktop
`REQUIRED_MEMLOCK_BYTES`) try `mlockall(CURRENT|FUTURE)` → `Full`; else, or if `mlockall` fails,
probe the page locker with one page → `SecretsOnly`; else `None`. One `ProtectionLevel` log line.
`can_unlock == false` ⇒ `create_wallet`, `unlock_wallet`, `change_password`, `open_received`,
`open_pending_with_password` return `ProtectionMissing{which}`; everything else (status screen,
settings, pairing) works.

## 3. Secret input / output

| Entity | Lifetime | Wiping |
|--------|----------|--------|
| `SecretInput` (Rust) | one call | `Zeroizing<Vec<u8>>` → in-place `Zeroizing<String>`; page-locked when level ≥ SecretsOnly |
| `RevealTicket.password` | until lifted by UniFFI | Rust buffer page-locked, wiped on free (allocator) |
| Kotlin `ByteArray` | `Secrets.use { }` block | `fill(0)` in `finally`; `Editable` overwritten then cleared |

Validation: UTF-8 (else `InvalidInput`); length bounds of 001 (`FieldTooLarge`); master password
≥ 12 characters (001); codes: digits only after 003 `normalize_code`.

## 4. Files in app-private storage (FR-030, FR-031)

Root `data_dir` = `noBackupFilesDir` (0700). See ffi-api.md §6 for the exact file list.

| File | Secret? | Encrypted by | Corruption/tamper behaviour |
|------|---------|--------------|------------------------------|
| `wallets/*.pwsw` | ciphertext | vault-core (Argon2id + AES-256-GCM) | 001 generic error |
| `sync/*`, `received/*` | ciphertext + non-secret records | vault-core / none | 004/005 rules |
| `identity.sealed` | device private key | Keystore AES-GCM, AAD `passwsync identity v1` | `identity_unusable`, networking off, reset offered (FR-037) |
| `peers.sealed` | pins (integrity) | Keystore AES-GCM, AAD `passwsync peers v1` | `peers_unusable`, networking off (003 FR-035) |
| `device-id` | no | — | regenerated as 002 does |
| `settings` | no | — | defaults, networking off, `reset_notice` (FR-033) |
| `clipboard-pending` | no (deadline + clip timestamp only) | — | treated as "clear now" |

Sealed blob layout (produced by Kotlin, opaque to Rust): `iv(12) ‖ ciphertext ‖ tag(16)`; Rust
bounds the file at 64 KiB before calling `open`.

## 5. Clipboard state (FR-021–FR-024)

```text
ClipboardState = Idle | Pending { deadline_boottime, clip_timestamp }
```

| From | Event | To | Action |
|------|-------|----|--------|
| any | `copy_field` | Pending(now + timeout) | `set_sensitive`, write marker, notify |
| Pending | deadline reached (sweeper, `on_deadline`) | Idle | `clear_if_ours(ts)`, remove marker, `ClipboardCleared`, log |
| Pending | lock (any cause), `on_screen_off`, `shutdown` | Idle | same, immediately |
| (start) | marker present | Idle | `clear_if_ours(ts)` (or unconditional clear if marker unreadable), remove marker |

Timeout = `clipboard_clear_seconds` (5–300, default 30). Reveal deadlines use the same timeout.

## 6. Lifecycle (FR-016, FR-017, FR-042, FR-051)

```text
Lifecycle = Foreground
          | Background { since, linger_until: since + 10 s, transfer_cap: since + 120 s }
          | Window { started, limit: started + 120 s }       # background sync window
```

| From | Event | To | Effects |
|------|-------|----|---------|
| Background/start | `on_foreground` | Foreground | suspend check + idle sweep first; `resume` node if networking on; sweeper runs |
| Foreground | `on_background` | Background | cancel pairing, not-started invitation/redemption; sweeper parks; returns `BackgroundPlan` |
| Background | linger elapsed and no transfer, or transfer ended, or cap reached | Background (node paused) | `pause` node: all sockets closed, unfinished transfer discarded |
| Background | `run_sync_window` | Window | refuse if off / no peer / no eligible interface / already running |
| Window | all rounds idle or limit | Background (node paused) | `WindowEnded` log, received-expiry sweep, report |
| any | `on_screen_off` | unchanged | lock all, clipboard clear |

"Fg-only" calls (pairing, revoke, invitation create/accept, redeem, sync now, reset identity)
return `NotForeground` outside `Foreground`.

## 7. Background plan (FR-044–FR-048)

```text
BackgroundPlan {
  deadline_in_ms:   min(next idle-lock deadline of unlocked wallets, clipboard deadline) or none,
  periodic_window_minutes: sync_interval_minutes if networking on && paired ≥ 1 && identity usable, else none,
  extra_window:     periodic_window_minutes.is_some() && sync.has_unsent_changes(),
  keep_network_ms:  10 000, or up to 120 000 while a transfer runs
}
```

Kotlin maps it 1:1 to JobScheduler jobs (ids 1 deadline, 2 periodic, 3 extra) and **cancels** any
job whose field is `none/false` (FR-048: networking off or no peer ⇒ no job at all).

## 8. Eligible interfaces (FR-039)

`EligibleInterfaces { names: RwLock<BTreeSet<InterfaceName>>, inner: OsInterfaces }` implements
`InterfaceSource::scan()` = `inner.scan()` filtered by `names` (after the 003 private/link-local
policy inside `OsInterfaces`). Optional `network_interface` setting narrows further. Empty ⇒
`no_local_network`.

## 9. Settings (FR-033)

Same grammar and ranges as the desktop (`host-runtime::config`):

| Key | Range | Default | Android UI |
|-----|-------|---------|-----------|
| `auto_lock_minutes` | 1–240 | 15 | yes |
| `clipboard_clear_seconds` | 5–300 | 30 | yes |
| `network` | on/off | off | switch + confirmation + `ACCESS_LOCAL_NETWORK` on API 37 |
| `device_name` | 003 `DeviceName` | `passwsync device XXXX` | yes |
| `network_interface` | 003 `InterfaceName` | none | yes (advanced) |
| `sync_interval_minutes` | 15–1440 | 60 | yes |
| `peer_port`, `discovery_port` | 1024–65535 | 27472 / 27473 | no (defaults; desktop-compatible) |
| `port` | — | — | never written by the app; ignored if present |

Transitions: edit ⇒ validate ⇒ `encode` ⇒ atomic write ⇒ `restart_required = true`. Invalid file
at start ⇒ defaults (networking **off**) + `reset_notice` + `SettingsReset` log line.

## 10. Requirement → host check map (TDD inventory)

| FR | Host check |
|----|-----------|
| 001, 003, 004 | `host-runtime/tests/architecture.rs`, ffi `api_surface.rs`, passwsyncd suite, verify X1 |
| 002, 006 | verify steps 6–9, B1–B6 |
| 005 | `unsafe_scope.rs` |
| 007, 008 | `protections.rs`, `memprotect.rs` |
| 009, 010 | `secrets.rs`, `leakage.rs`, B2, B3, S4 |
| 011 | M10, S13, core singleton test |
| 013–016, 018–020 | `wallets.rs`, `credentials.rs`, `autolock.rs` |
| 017 | `autolock.rs` (`on_screen_off`), S11 |
| 021–024 | `clipboard.rs`, S3 |
| 025 | X4, S16 |
| 026, 027 | S1, S2, X7 |
| 028 | X6 |
| 029 | X5, S5 |
| 030–033 | `settings.rs`, file-mode tests, S6, M1, M2, X2 |
| 034–037 | `identity.rs`, S15 |
| 038–043 | `network.rs`, M3, X3, S7, S12, deny bans |
| 044–048 | `window.rs`, `background_plan.rs`, M9, S10 |
| 049 | `sync_loopback.rs` |
| 050–053 | `pairing_loopback.rs`, `share_loopback.rs` |
| 054–056 | M4, M5, M6–M8, M12, G3–G5, S9 |
| 057 | `leakage.rs`, S8, `log_app_events.rs` |
| 058, 059 | verify.sh, mutations |
| 012, 060 | device only (D2, quickstart) |
