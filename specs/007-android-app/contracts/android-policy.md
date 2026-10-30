# Contract: Android Manifest, XML, Gradle, Source and Binding Policy

Static rules checked on the host by `android/policy/*.py` (Python 3 stdlib, run with
`python3 -I`), driven by `android/verify.sh` ([verify.md](verify.md)). Every rule has an id, a
failure message that starts with the id, and at least one **mutation** in
`android/policy/mutations.py` that must make the checker fail with that id (FR-059, SC-002).
The unmodified `android/` tree must pass every rule.

Scope: `android/app/src/main/AndroidManifest.xml`, `android/app/src/main/res/**`,
`android/**/*.gradle.kts`, `android/gradle/libs.versions.toml`, `android/app/proguard-rules.pro`,
`android/app/src/main/kotlin/**/*.kt`, and the generated bindings
(`target/android-verify/kotlin/**/*.kt`). The device check D21 confirms the **merged** manifest
of the built APK (`aapt2 dump xmltree`), because library manifests are merged at build time.

## 1. Manifest rules (`check_manifest.py`)

| Id | Rule | FR |
|----|------|----|
| M1 | `<application>` has `android:allowBackup="false"` and `android:hasFragileUserData="false"`; no `android:fullBackupContent` other than `"false"`; no `android:backupAgent` | FR-032 |
| M2 | `<application android:dataExtractionRules="@xml/data_extraction_rules">` and that file (X2) exists | FR-032 |
| M3 | `<application android:networkSecurityConfig="@xml/network_security_config">` and `android:usesCleartextTraffic="false"` | FR-041 |
| M4 | `<uses-permission>` set **equals** the allow-list {`INTERNET`, `ACCESS_NETWORK_STATE`, `CHANGE_WIFI_MULTICAST_STATE`, `ACCESS_LOCAL_NETWORK`} (all `android.permission.`); no `<uses-permission-sdk-23>`, no `<permission>`, no `maxSdkVersion` tricks | FR-054 |
| M5 | Explicit deny-list also reported by name when present (defence against allow-list edits): `CAMERA`, `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION`, `ACCESS_BACKGROUND_LOCATION`, `NEARBY_WIFI_DEVICES`, `READ_CONTACTS`, `GET_ACCOUNTS`, `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`, `READ_MEDIA_*`, `MANAGE_EXTERNAL_STORAGE`, `POST_NOTIFICATIONS`, `RECEIVE_BOOT_COMPLETED`, `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`, `SCHEDULE_EXACT_ALARM`, `USE_EXACT_ALARM`, `FOREGROUND_SERVICE*`, `WAKE_LOCK`, `SYSTEM_ALERT_WINDOW`, `QUERY_ALL_PACKAGES`, `READ_LOGS`, `com.google.android.gms.permission.AD_ID` | FR-054, FR-056 |
| M6 | Exactly one `<activity>` with `android:exported="true"`; it is `.MainActivity`, has exactly one `<intent-filter>` with exactly `action.MAIN` + `category.LAUNCHER` and no `<data>`; it sets `android:taskAffinity=""` and `android:allowTaskReparenting="false"` | FR-055 |
| M7 | Every `<activity>`, `<service>`, `<receiver>`, `<provider>`, `<activity-alias>` declares `android:exported` explicitly; all except M6's are `"false"` | FR-055 |
| M8 | No `<provider>`, no `<receiver>`, no `<activity-alias>`, no `<queries>`, no `<data>` anywhere, no `<intent-filter>` other than M6's, no `android:sharedUserId` | FR-055 |
| M9 | Exactly one `<service>`: `.platform.CoreJobService`, `android:exported="false"`, `android:permission="android.permission.BIND_JOB_SERVICE"`, no `foregroundServiceType`, no intent filter | FR-044 |
| M10 | No `android:process` attribute on any element | FR-011 |
| M11 | No `android:debuggable` attribute (release is non-debuggable by default; D2 confirms) and no `android:testOnly` | FR-012 |
| M12 | No `<uses-library>`, no `<meta-data>` naming `com.google.*`, `firebase`, `gms`, `ads`, `analytics`, `crashlytics` | FR-040, FR-056 |
| M13 | `<uses-sdk>` absent from the manifest (SDK levels live in Gradle, G1) | — |

## 2. Resource XML rules (`check_manifest.py`)

| Id | Rule | FR |
|----|------|----|
| X1 | Every `*.xml` under `res/` and the manifest is well-formed (`xmllint --noout --nonet`; also parsed by ElementTree; DOCTYPE/ENTITY declarations rejected) | FR-058 |
| X2 | `xml/data_extraction_rules.xml`: root `<data-extraction-rules>` has `<cloud-backup>` and `<device-transfer>`; each contains `<exclude domain="D" path="."/>` for **every** D in {root, file, database, sharedpref, external, device_root, device_file, device_database, device_sharedpref} and **no** `<include>`; `cloud-backup` has no `disableIfNoEncryptionCapabilities="false"` | FR-032 |
| X3 | `xml/network_security_config.xml`: exactly one `<base-config cleartextTrafficPermitted="false">` whose `<trust-anchors>` contains only `<certificates src="system"/>`; no `<domain-config>`, no `<debug-overrides>`, no `src="user"`, no `overridePins`, no `<pin-set>` | FR-041 |
| X4 | Layouts: every `EditText` whose `android:id` contains `password` (case-insensitive) or whose `inputType` contains `Password` has `android:inputType` containing `textPassword` and `textNoSuggestions`, `android:imeOptions` containing `flagNoPersonalizedLearning`, `android:importantForAutofill="noExcludeDescendants"` or `"no"`, and no `android:autofillHints` | FR-025 |
| X5 | Layouts: no `<WebView>` or `android.webkit.*` element; no `android:autoLink`; no `<VideoView>`/`<SurfaceView>` | FR-029 |
| X6 | Layouts: every `Button`, `ImageButton`, `ImageView` (clickable), `EditText`, `Switch`, `CheckBox`, `RadioButton`, `Spinner` has an accessibility label: `android:contentDescription`, or `android:text`/`android:hint` (EditText needs `android:hint` or `android:labelFor` from a `TextView`); every user-visible text attribute is a `@string/` reference (English `values/strings.xml`, no other locale folders) | FR-028 |
| X7 | `values/themes.xml` app theme parent is `android:Theme.DeviceDefault*`; no `android:windowDisablePreview`-style overrides that would show content before `FLAG_SECURE` | FR-026 |

## 3. Gradle rules (`check_manifest.py`)

| Id | Rule | FR |
|----|------|----|
| G1 | `app/build.gradle.kts`: `minSdk = 33`, `targetSdk = 37`, `compileSdk = 37`; `applicationId = "io.github.henriqk0.passwsync"` | spec, R3 |
| G2 | release `buildTypes`: `isDebuggable = false`, `isMinifyEnabled = true`, `isJniDebuggable = false`; no `debuggable true`, no `testCoverageEnabled` in release | FR-012 |
| G3 | Plugins: only `com.android.application` (AGP 9.4.1, built-in Kotlin); no other plugin ids | FR-040, FR-056 |
| G4 | Dependencies: exactly {`net.java.dev.jna:jna:5.19.1@aar`} in `implementation` (Kotlin stdlib implicit); no `testImplementation` of networked libs; versions only from `gradle/libs.versions.toml`; no dynamic versions (`+`, `latest.`), no `SNAPSHOT` | FR-040, FR-056 |
| G5 | Repositories: only `google()` and `mavenCentral()` in `settings.gradle.kts` (`dependencyResolutionManagement` with `RepositoriesMode.FAIL_ON_PROJECT_REPOS`); no `jcenter`, no `maven(url=…)`, no `mavenLocal` | supply chain |
| G6 | `dependenciesInfo { includeInApk = false; includeInBundle = false }`; `buildFeatures { buildConfig = false }`; no `Exec`/`exec {`/`ProcessBuilder` in Gradle files | R16 |
| G7 | `proguard-rules.pro` keeps `com.sun.jna.**` and `io.github.henriqk0.passwsync.core.**` (JNA uses reflection); it has no `-keepattributes SourceFile,LineNumberTable` and no `-printmapping` to a shared path | FR-012 |

## 4. Kotlin source rules (`check_sources.py`)

Text rules over `app/src/main/kotlin/**/*.kt` after stripping `//` and `/* */` comments and string
literals (except where a rule names a literal).

| Id | Rule | FR |
|----|------|----|
| S1 | Every class extending `Activity` extends `SecureActivity`; `SecureActivity.kt` calls `window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)` and `setRecentsScreenshotEnabled(false)` in `onCreate` **before** `super.onCreate`/`setContentView`; no `clearFlags(` with `FLAG_SECURE` anywhere | FR-026, FR-027 |
| S2 | `AlertDialog`, `Dialog(`, `PopupWindow(`, `Toast.`, `Snackbar` appear only in `SecureDialogs.kt`; `SecureDialogs.kt` adds `FLAG_SECURE` to every dialog window it creates; no `Toast` containing data (Toast is not allowed at all) | FR-026 |
| S3 | `ClipboardManager`/`setPrimaryClip`/`ClipData` appear only in `platform/ClipboardAdapter.kt`, which contains `ClipDescription.EXTRA_IS_SENSITIVE` set to `true` in a `PersistableBundle` on every `ClipData` before `setPrimaryClip` | FR-021 |
| S4 | Secrets: no `.text.toString()`, `.getText().toString()`, `String(` with a `ByteArray` argument, `decodeToString(`, `toString(Charsets` in any file except `Secrets.kt` (the only conversion site); `Secrets.platformText(` only in `platform/ClipboardAdapter.kt` and `screens/CredentialView.kt` (FR-009 amendment); every core call whose generated parameter is a secret `ByteArray` (B2 list) is wrapped in `Secrets.use { … }` (which fills with zeros in `finally`) | FR-009 |
| S5 | No `android.webkit`, `WebView`, `CustomTabs`, `Intent.ACTION_VIEW` with a URI | FR-029 |
| S6 | Storage: no `getExternalFilesDir`, `getExternalCacheDir`, `Environment.getExternalStorage`, `MediaStore`, `FileProvider`, `ContentResolver.insert`, `getSharedPreferences`, `openFileOutput`, `MODE_WORLD_`, `DocumentFile`, `ACTION_CREATE_DOCUMENT`/`OPEN_DOCUMENT`; the only directory handed to the core is `noBackupFilesDir` | FR-030, FR-031 |
| S7 | Network: no `java.net.URL`, `HttpURLConnection`, `HttpsURLConnection`, `okhttp`, `retrofit`, `ktor`, `Socket(`, `DatagramSocket(`, `InetAddress.getByName`, `InetAddress.getAllByName`, `DnsResolver`, `NsdManager`, `WifiP2p`; all sockets live in Rust | FR-040, FR-039 |
| S8 | Logging: `android.util.Log` only in `platform/LogcatSink.kt`, which calls only `Log.i(TAG, line)` with the core-provided line; no `println`, `print(`, `printStackTrace`, `System.out`, `System.err`, `Log.d`, `Log.v`, `Log.w`, `Log.e`, `Log.wtf` anywhere | FR-057, FR-012 |
| S9 | Accounts/proprietary: no `AccountManager`, `com.google.android.gms`, `com.google.firebase`, `AdvertisingIdClient`, `play.core`, `BiometricPrompt`, `FingerprintManager`, `AutofillService` | FR-056, FR-061 |
| S10 | Background: `JobScheduler` used only in `platform/JobPlanner.kt`; the window jobs (ids 2 and 3) set `setRequiresBatteryNotLow(true)` and `setRequiredNetwork(` with `TRANSPORT_WIFI`, `TRANSPORT_ETHERNET`, `NET_CAPABILITY_NOT_VPN` and `removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)`; the deadline job (id 1) sets neither constraint; no `setPersisted(true)`, no `setExpedited`, no `AlarmManager`, no `startForegroundService`, no `startForeground(`, no `PowerManager.WakeLock`, no `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` | FR-044, FR-048 |
| S11 | Receivers: `registerReceiver(` only in `platform/ScreenOffReceiver.kt`, with `Context.RECEIVER_NOT_EXPORTED` and only `Intent.ACTION_SCREEN_OFF` | FR-017, FR-055 |
| S12 | `MulticastLock`: `createMulticastLock` only in `platform/MulticastLockHolder.kt`, `setReferenceCounted(false)`, released in the same file when `multicast_wanted()` is false | FR-043 |
| S13 | No `Process.myPid`-based second-process logic, no `:remote`/`android:process`; core is started only in `PasswsyncApp.onCreate` | FR-011 |
| S14 | No camera/QR: no `CameraManager`, `camera2`, `zxing`, `BarcodeDetector`, `QRCode` | FR-061 |
| S15 | Keystore: `KeyStore.getInstance("AndroidKeyStore")` and `KeyGenParameterSpec` only in `platform/KeystoreSealer.kt`, with `BLOCK_MODE_GCM`, `ENCRYPTION_PADDING_NONE`, `setRandomizedEncryptionRequired(true)`, `setUserAuthenticationRequired(false)`; `updateAAD(` called on every cipher; no `setUserAuthenticationValidityDurationSeconds`; the file calls no `PasswsyncCore` method (it only implements the `KeySealer` port, so wallet data cannot reach it) | FR-034, FR-035 |
| S16 | Password fields created in code (if any) use `InputType.TYPE_TEXT_VARIATION_PASSWORD`, `EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING`, `IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS` | FR-025 |
| S17 | Every Kotlin file declares package `io.github.henriqk0.passwsync` or a sub-package; no `@Suppress("…Secure…")`; no reflection on generated binding classes | — |

## 5. Generated binding rules (`check_bindings.py`, over the host-generated Kotlin)

| Id | Rule | FR |
|----|------|----|
| B1 | Generated package is `io.github.henriqk0.passwsync.core`; library name `passwsync_ffi`; the file imports only `com.sun.jna.*`, `java.*`, `kotlin.*` (no `kotlinx.coroutines`: no async exports) | R1, R2 |
| B2 | Secret parameters are `ByteArray`: `createWallet(name: String, password: ByteArray, confirm: ByteArray)`, `unlockWallet(…, password: ByteArray)`, `changePassword(…, current, new, confirm: ByteArray)`, `CredentialInput.password: ByteArray?`, `joinPairing(…, code: ByteArray)`, `redeemInvitation(…, code: ByteArray)`, `openReceived(…, password: ByteArray)`, `openPendingWithPassword(…, password: ByteArray)`, `KeySealer.seal/open` payloads, `Clipboard.setSensitive(value: ByteArray)`; **no** parameter or field whose name matches `password|secret|code|plaintext|key` has type `String` (allow-list: `InvitationView.code`, `PairingView.code`, display only) | FR-009 |
| B3 | `CredentialSummary` has exactly the fields `id, title, username, url, conflicted`; `CredentialDetails` has no `password` field; no record other than `RevealTicket` and the inbound `CredentialInput` has a `ByteArray` field named `password` (the inbound one is secret input, B2) | FR-010 |
| B4 | The exported method set equals the list in [ffi-api.md](ffi-api.md) §5 (same inventory as `api_surface.rs`) | FR-002 |
| B5 | `CoreError` variant set equals the 37 names listed in ffi-api.md §4 | FR-014 |
| B6 | No `suspend fun`, no `Flow`, no `java.lang.ref.Cleaner` bypass flags changed by us (generated as-is) | R5 |

## 6. Mutations (negative tests)

`mutations.py` holds a list of `Mutation(rule, path, kind, find, replace)` with
`kind ∈ {replace, insert_after, add_file, delete_file}`. At least one per rule id above; the
harness copies `android/` (and the generated bindings) to a temporary directory, applies one
mutation, runs the checker, and requires: exit status 1 **and** a failure line starting with that
rule id. Examples: M1 `allowBackup="false"` → `"true"`; M4 add `<uses-permission
android:name="android.permission.CAMERA"/>`; M6 add a second exported activity; X2 delete the
`device_sharedpref` exclude; X3 add `<certificates src="user"/>`; S1 remove the
`setRecentsScreenshotEnabled(false)` line; S3 remove `EXTRA_IS_SENSITIVE`; S7 add a file with
`java.net.URL("http://example.org")`; B2 change `password: ByteArray` to `password: String` in the
generated file. A mutation that leaves the checker passing fails the verify step.
