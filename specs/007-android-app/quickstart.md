# Quickstart: Validating the Android App (007)

Two parts: **host validation** (the gate for this feature, runs offline here) and **device-only
checks** (need the Android SDK/NDK and a phone or emulator; recorded as *pending* until run,
FR-060). Rules and commands referenced here are defined in [contracts/verify.md](contracts/verify.md),
[contracts/android-policy.md](contracts/android-policy.md) and [contracts/ffi-api.md](contracts/ffi-api.md).

## Part A — Host validation (offline)

### Prerequisites

- Rust stable (edition 2024), `cargo-deny`, `cargo-audit` with a local advisory DB, `python3`,
  `xmllint`, `git`. Optional: `ktlint`. On the 2026-10-28 host, cargo-deny 0.20.2 and cargo-audit 0.22.2 are in `~/.cargo/bin` and the advisory DB is at `~/.cargo/advisory-db`.
- Dependency cache filled **once** while online (UniFFI 0.32.2 is already in the local cache
  since planning):
  ```sh
  cargo fetch --locked
  cargo fetch --locked --manifest-path tools/uniffi-bindgen/Cargo.toml
  ```

### Run

```sh
android/verify.sh            # full gate; expected last line: RESULT 0
android/verify.sh --quick    # inner loop; RESULT 2 (incomplete by design)
```

### Expected outcomes

| Scenario | Expected |
|----------|----------|
| Clean checkout, cache filled, network unplugged | every step `PASS`, `SKIPPED ktlint (not installed)`, `RESULT 0` (SC-001) |
| `crates/passwsyncd/tests` untouched; full suite | step 2 and 4 `PASS` (SC-004) |
| Any single mutation from `mutations.py` | detected under its own rule id (SC-002) |
| Edit `AndroidManifest.xml` to `allowBackup="true"` by hand | step 11 `FAIL M1 …`, `RESULT 1` |
| Change a secret parameter to `String` in `api.rs` | step 9 `FAIL B2 …` and `api_surface.rs` fails |
| Add `unsafe` outside `memprotect.rs` | step 4 (`unsafe_scope.rs`) fails |
| Uninstall `xmllint` from `PATH` | `MISSING tools xmllint`, `RESULT 2` |

### Useful focused commands

```sh
cargo test --frozen --offline -p passwsync-ffi --test clipboard
cargo test --frozen --offline -p host-runtime --test architecture
python3 -I android/policy/check_manifest.py android
```

## Part B — Device-only checks (pending until run)

### Prerequisites (device-build host)

Android SDK with platform 37 and build-tools, NDK (revision pinned in `android/rust-android.env`),
Gradle 9.8.1, rustup with `aarch64-linux-android` and `x86_64-linux-android`, a phone on
Android 13+ (or an API 33+ and an API 37 emulator), a desktop running passwsyncd 006 on the same
Wi-Fi.

```sh
android/build-rust.sh                      # cross-compiles libpasswsync_ffi.so, generates bindings
cd android && gradle --write-locks assembleRelease   # first build: commit gradle.lockfile
gradle --write-verification-metadata sha256 help      # first build: commit verification-metadata.xml
adb install -r app/build/outputs/apk/release/app-release.apk   # signed with a local key
```

### Checks

Record each as `pending` → `pass`/`fail` with device model, Android version and date.

| Id | Check | Expected | FR/SC |
|----|-------|----------|-------|
| D1 | Build and install as above | build succeeds with locked, verified dependencies; app starts | FR-060 |
| D2 | `aapt2 dump badging` / `xmltree` on the APK | not debuggable; `android:allowBackup=false`; no `testOnly` | FR-012 |
| D3 | First start on a debug build, `logcat -s passwsync` | `ProtectionLevel` line, process not killed (seccomp); `cat /proc/<pid>/status` shows `VmLck` > 0 for full/secrets-only | FR-007, FR-008 |
| D4 | `cat /proc/<pid>/limits` and `run-as` dumpable state | core size 0; process non-dumpable; JNA works | FR-007, SC-012 |
| D5 | Security status screen on every launch (10 launches) | level shown every time | SC-012 |
| D6 | US1: create wallet, kill app (`am force-stop`), reopen, unlock | locked after restart; unlock < 3 s (default KDF) | FR-013–FR-015, SC-005 |
| D7 | US1.2: wrong password vs. corrupted file (`run-as` truncate) | identical message | FR-014 |
| D8 | Idle timeout 1 min; change device clock ±1 h | locks after 1 min of inactivity regardless of clock change | FR-016 |
| D9 | Screen off with a wallet unlocked and a copied password | wallet locked and clipboard empty when screen turns on | FR-017, FR-022 |
| D10 | US2: add/search/edit/delete; copy password; open the system clipboard preview/keyboard clipboard | no preview of the value (sensitive flag) | FR-020, FR-021 |
| D11 | Reveal password, wait timeout / leave view / lock | hidden each time | FR-024 |
| D12 | Copy password, switch to another app, wait timeout + 5 s; repeat 20× | cleared in 100 % of trials | FR-022, SC-007 |
| D13 | Copy, then force-stop; restart | clipboard cleared at start | FR-023 |
| D14 | Keyboard on password fields (Gboard + one other IME) | no suggestions, no learning, no autofill save prompt | FR-025 |
| D15 | Screenshot, screen recording, cast, recents overview, split screen, a dialog open | blank/blocked content everywhere | FR-026, FR-027, SC-006 |
| D16 | Networking off: `ss -tuanp`/`/proc/net/{tcp,udp}` for the app uid | no socket | FR-038 |
| D17 | Turn networking on (confirmation, API 37 permission prompt); Wi-Fi + VPN active; mobile data only | sockets only on the Wi-Fi interface; with mobile data only: "no local network" | FR-038, FR-039 |
| D18 | US4: pair phone ↔ desktop (both roles), revoke | both pinned, fingerprints match; revoke closes channel | FR-050, FR-053 |
| D19 | US5.1: edit on desktop and phone in foreground | change on the other device ≤ 30 s after the quiet period | FR-047 |
| D20 | US5.2/5.3: background on Wi-Fi; `adb shell cmd jobscheduler run -f <pkg> 2`; mobile data only; battery saver/low | window runs ≤ 2 min and closes sockets; no window on mobile data or low battery | FR-044, FR-045 |
| D21 | Merged manifest of the APK | permissions exactly the M4 allow-list; one exported activity; one non-exported job service; no providers/receivers | FR-054, FR-055 |
| D22 | US6: share desktop → phone and phone → desktop; open with master password; 24 h expiry (clock-independent via `adb` time travel in emulator) | 005 behaviour identical to two desktops | FR-052, SC-010 |
| D23 | Backup: `adb shell bmgr backupnow <pkg>`, device-to-device transfer test (`bmgr` D2D) | no app file in either | FR-032, SC-006 |
| D24 | 24 h idle: networking off, then networking on hourly; `dumpsys batterystats`, `dumpsys jobscheduler`, `dumpsys deviceidle` (force Doze) | 0 wakeups with networking off; ≤ 1 window/h + 1 per foreground exit with unsent changes; < 1 % battery; RSS < 128 MiB with 1 000 credentials | FR-048, SC-008, SC-009, SC-011 |
| D25 | TalkBack on: complete the US1 and US2 flows and read every control label | every control announces its label and every flow completes | FR-028 |

### Results (recorded 2026-10-28, no device or Android SDK on the dev host)

| Id | Task | Status | Automated equivalents run on the host |
|----|------|--------|----------------------------------------|
| D2 | T078 | Not run here | M1, M2, M11, X2, G2 (check_manifest.py + mutations) |
| D3, D4, D5 | T090 | Not run here | `protections.rs`, `memprotect.rs`; Security level on the wallet list header (code) |
| D6, D7, D8 | T091 | Not run here | `wallets.rs`, `autolock.rs` |
| D9 | T092 | Not run here | `autolock.rs` (`on_screen_off`), `clipboard.rs` (every lock clears) |
| D10, D11, D14, D25 | T100 | Not run here | `credentials.rs`, `clipboard.rs`, S3, X4, S16, X6 |
| D15 | T077 | Not run here | S1, S2, X7 |
| D23 | T078 | Not run here | M1, M2, X2 |
| D12, D13 | T101 | Not run here | `clipboard.rs` (deadline, marker cleared at next start) |
| D16, D17 | T109 | Not run here | `network.rs` (zero sockets, eligible interfaces, public address refused), M3, X3, S7 |
| D18 | T110 | Not run here | `pairing_loopback.rs` (core and plain desktop `HostCore`, both roles, revoke) |
| D22 | T124 | Not run here | `share_loopback.rs` (core and plain desktop `HostCore`, both directions) |
| D19, D20, D24 | T118 | Not run here | `sync_loopback.rs`, `window.rs`, `background_plan.rs`, M9, S10 |

### Device results (FR-060; fill in when run on a device, never mark pass from the host)

| Id | Result | Device model | Android version | Date |
|----|--------|--------------|-----------------|------|
| D1 | pending | | | |
| D2 | pending | | | |
| D3 | pending | | | |
| D4 | pending | | | |
| D5 | pending | | | |
| D6 | pending | | | |
| D7 | pending | | | |
| D8 | pending | | | |
| D9 | pending | | | |
| D10 | pending | | | |
| D11 | pending | | | |
| D12 | pending | | | |
| D13 | pending | | | |
| D14 | pending | | | |
| D15 | pending | | | |
| D16 | pending | | | |
| D17 | pending | | | |
| D18 | pending | | | |
| D19 | pending | | | |
| D20 | pending | | | |
| D21 | pending | | | |
| D22 | pending | | | |
| D23 | pending | | | |
| D24 | pending | | | |
| D25 | pending | | | |

Also documented for the person (About screen): uninstall/clear data deletes all wallets held only
on this device; screen readers can read visible content (residual risk).
