"""Mutation harness (contracts/android-policy.md section 6; FR-059, SC-002).

Each `Mutation(rule, path, kind, find, replace)` is applied, alone, to a fresh copy of the
tree; the owning checker must then exit 1 with a line starting with `rule`. A mutation that
leaves the checker passing, is detected only under another id, or does not apply is a failure,
and so is a rule id of the three checkers without any mutation. `path` is relative to the
android directory, or to the generated-bindings directory for B rules.

usage: python3 -I mutations.py <android-dir> <bindings-dir> <work-dir> [--inventory FILE]
"""

import contextlib
import importlib
import io
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

KINDS = ("replace", "insert_after", "add_file", "delete_file")
OWNERS = {"M": "check_manifest", "X": "check_manifest", "G": "check_manifest",
          "S": "check_sources", "B": "check_bindings"}


@dataclass(frozen=True)
class Mutation:
    rule: str
    path: str
    kind: str
    find: str = ""
    replace: str = ""

    def __post_init__(self):
        if self.kind not in KINDS:
            raise ValueError(f"unknown mutation kind {self.kind!r}")
        if self.rule[:1] not in OWNERS or not self.rule[1:].isdigit():
            raise ValueError(f"unknown rule id {self.rule!r}")


# Added by each story phase together with the real files they mutate (one or more per rule).
MAN = "app/src/main/AndroidManifest.xml"
RES = "app/src/main/res"
DXR = f"{RES}/xml/data_extraction_rules.xml"
NSC = f"{RES}/xml/network_security_config.xml"
THEMES = f"{RES}/values/themes.xml"
STRINGS = f"{RES}/values/strings.xml"
APP = "app/build.gradle.kts"
SETTINGS = "settings.gradle.kts"
TOML = "gradle/libs.versions.toml"
PRO = "app/proguard-rules.pro"
KT = "app/src/main/kotlin/io/github/henriqk0/passwsync"
PERM = '<uses-permission android:name="android.permission.INTERNET" />'
APP_END = "    </application>"
SERVICE_END = 'android:permission="android.permission.BIND_JOB_SERVICE" />'
MAIN_FILTER_END = "            </intent-filter>"


def kotlin(name: str, body: str) -> Mutation:
    """A new Kotlin file in the app package (add_file)."""
    return Mutation(RULE_OF[name], f"{KT}/{name}.kt", "add_file", "",
                    f"package io.github.henriqk0.passwsync\n\n{body}\n")


RULE_OF = {"Net": "S7", "Web": "S5", "Prefs": "S6", "Accounts": "S9", "Camera": "S14",
           "Second": "S13", "Popup": "S2", "Leak": "S1"}

# --- US3 (T075): manifest, resource XML, Gradle and the screen/storage source rules ---------
US3 = [
    Mutation("M1", MAN, "replace", 'android:allowBackup="false"', 'android:allowBackup="true"'),
    Mutation("M1", MAN, "replace", 'android:hasFragileUserData="false"', 'android:hasFragileUserData="true"'),
    Mutation("M1", MAN, "replace", 'android:fullBackupContent="false"', 'android:fullBackupContent="@xml/backup"'),
    Mutation("M2", MAN, "replace", 'android:dataExtractionRules="@xml/data_extraction_rules"', 'android:dataExtractionRules="@xml/other_rules"'),
    Mutation("M2", DXR, "delete_file"),
    Mutation("M3", MAN, "replace", 'android:usesCleartextTraffic="false"', 'android:usesCleartextTraffic="true"'),
    Mutation("M3", MAN, "replace", 'android:networkSecurityConfig="@xml/network_security_config"', 'android:networkSecurityConfig="@xml/other"'),
    Mutation("M4", MAN, "insert_after", PERM, '\n    <uses-permission android:name="android.permission.VIBRATE" />'),
    Mutation("M4", MAN, "replace", '    <uses-permission android:name="android.permission.ACCESS_LOCAL_NETWORK" />\n', ""),
    Mutation("M5", MAN, "insert_after", PERM, '\n    <uses-permission android:name="android.permission.CAMERA" />'),
    Mutation("M5", MAN, "insert_after", PERM, '\n    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />'),
    Mutation("M6", MAN, "replace", APP_END,
             '        <activity android:name=".SecondActivity" android:exported="true" />\n' + APP_END),
    Mutation("M6", MAN, "replace", 'android:taskAffinity=""', 'android:taskAffinity="io.github.other"'),
    Mutation("M6", MAN, "replace", MAIN_FILTER_END,
             MAIN_FILTER_END + '\n            <intent-filter>\n                <action android:name="android.intent.action.MAIN" />\n'
             '                <category android:name="android.intent.category.LAUNCHER" />\n            </intent-filter>'),
    Mutation("M7", MAN, "replace", SERVICE_END,
             SERVICE_END + '\n        <activity android:name=".Hidden" />'),
    Mutation("M8", MAN, "replace", APP_END,
             '        <provider android:name=".Files" android:authorities="x" android:exported="false" />\n' + APP_END),
    Mutation("M8", MAN, "replace", APP_END, "    </application>\n    <queries />"),
    Mutation("M9", MAN, "replace", SERVICE_END,
             SERVICE_END + '\n        <service android:name=".Other" android:exported="false" />'),
    Mutation("M9", MAN, "replace", 'android:permission="android.permission.BIND_JOB_SERVICE"', 'android:permission="android.permission.INTERNET"'),
    Mutation("M10", MAN, "replace", 'android:name=".PasswsyncApp"', 'android:name=".PasswsyncApp"\n        android:process=":remote"'),
    Mutation("M11", MAN, "replace", 'android:name=".PasswsyncApp"', 'android:name=".PasswsyncApp"\n        android:debuggable="true"'),
    Mutation("M11", MAN, "replace", 'android:name=".PasswsyncApp"', 'android:name=".PasswsyncApp"\n        android:testOnly="true"'),
    Mutation("M12", MAN, "replace", APP_END,
             '        <meta-data android:name="com.google.android.gms.version" android:value="1" />\n' + APP_END),
    Mutation("M13", MAN, "insert_after", PERM, '\n    <uses-sdk android:minSdkVersion="33" />'),
    Mutation("X1", NSC, "replace", "</network-security-config>", "<network-security-config>"),
    Mutation("X1", THEMES, "replace", '<?xml version="1.0" encoding="utf-8"?>',
             '<?xml version="1.0" encoding="utf-8"?>\n<!DOCTYPE r [<!ENTITY e "x">]>'),
    Mutation("X2", DXR, "replace", '    <exclude domain="device_sharedpref" path="." />\n    </device-transfer>', "    </device-transfer>"),
    Mutation("X2", DXR, "replace", '<exclude domain="root" path="." />', '<include domain="root" path="." />'),
    Mutation("X3", NSC, "insert_after", '<certificates src="system" />', '\n            <certificates src="user" />'),
    Mutation("X3", NSC, "replace", 'cleartextTrafficPermitted="false"', 'cleartextTrafficPermitted="true"'),
    Mutation("X3", NSC, "replace", "</network-security-config>",
             '    <domain-config><domain>example.org</domain></domain-config>\n</network-security-config>'),
    Mutation("X7", THEMES, "replace", 'parent="android:Theme.DeviceDefault.DayNight"', 'parent="android:Theme.Material"'),
    Mutation("X7", THEMES, "insert_after", '<item name="android:windowActionBar">true</item>',
             '\n        <item name="android:windowDisablePreview">true</item>'),
    Mutation("G1", APP, "replace", "minSdk = 33", "minSdk = 26"),
    Mutation("G1", APP, "replace", "targetSdk = 37", "targetSdk = 34"),
    Mutation("G1", APP, "replace", 'applicationId = "io.github.henriqk0.passwsync"', 'applicationId = "org.example"'),
    Mutation("G2", APP, "replace", "isDebuggable = false", "isDebuggable = true"),
    Mutation("G2", APP, "replace", "isMinifyEnabled = true", "isMinifyEnabled = false"),
    Mutation("G2", APP, "replace", "isJniDebuggable = false", "isJniDebuggable = true"),
    Mutation("G3", APP, "insert_after", "alias(libs.plugins.android.application)", '\n    id("com.google.gms.google-services")'),
    Mutation("G4", APP, "insert_after", 'implementation(variantOf(libs.jna) { artifactType("aar") })',
             '\n    implementation("com.squareup.okhttp3:okhttp:4.12.0")'),
    Mutation("G4", TOML, "replace", 'jna = "5.19.1"', 'jna = "5.+"'),
    Mutation("G5", SETTINGS, "insert_after", "        mavenCentral()\n    }\n}\n\ndependencyResolutionManagement {\n"
             "    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)\n    repositories {",
             "\n        jcenter()"),
    Mutation("G5", SETTINGS, "replace", "RepositoriesMode.FAIL_ON_PROJECT_REPOS", "RepositoriesMode.PREFER_PROJECT"),
    Mutation("G6", APP, "replace", "includeInApk = false", "includeInApk = true"),
    Mutation("G6", APP, "replace", "buildConfig = false", "buildConfig = true"),
    Mutation("G6", APP, "insert_after", 'implementation(variantOf(libs.jna) { artifactType("aar") })\n}',
             '\n\ntasks.register<Exec>("cargo") { commandLine("cargo", "build") }'),
    Mutation("G7", PRO, "replace", "-keep class com.sun.jna.** { *; }\n", ""),
    Mutation("G7", PRO, "insert_after", "-dontwarn java.awt.**", "\n-keepattributes SourceFile,LineNumberTable"),
    Mutation("S1", f"{KT}/SecureActivity.kt", "replace", "        setRecentsScreenshotEnabled(false)\n", ""),
    Mutation("S1", f"{KT}/SecureActivity.kt", "replace",
             "        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)\n"
             "        setRecentsScreenshotEnabled(false)\n        super.onCreate(savedInstanceState)",
             "        super.onCreate(savedInstanceState)\n"
             "        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)\n"
             "        setRecentsScreenshotEnabled(false)"),
    Mutation("S1", f"{KT}/MainActivity.kt", "replace", "class MainActivity : SecureActivity()", "class MainActivity : android.app.Activity()"),
    kotlin("Leak", "fun leak(w: android.view.Window) = w.clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)"),
    Mutation("S2", f"{KT}/SecureDialogs.kt", "replace",
             "        dialog.window?.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)\n        dialog.show()\n    }\n\n    /** A message",
             "        dialog.show()\n    }\n\n    /** A message"),
    kotlin("Popup", "fun popup(c: android.content.Context) = android.widget.Toast.makeText(c, \"x\", 0).show()"),
    kotlin("Web", "fun web(c: android.content.Context) = android.webkit.WebView(c)"),
    kotlin("Prefs", "fun prefs(c: android.content.Context) = c.getSharedPreferences(\"p\", 0)"),
    kotlin("Net", 'val u = java.net.URL("http://example.org")'),
    kotlin("Accounts", "fun accounts(c: android.content.Context) = android.accounts.AccountManager.get(c)"),
    kotlin("Camera", "fun camera(c: android.content.Context) = c.getSystemService(android.hardware.camera2.CameraManager::class.java)"),
    kotlin("Second", "fun pid() = android.os.Process.myPid()"),
    Mutation("S17", f"{KT}/MainActivity.kt", "replace", "package io.github.henriqk0.passwsync", "package org.example.app"),
    Mutation("S17", f"{KT}/PasswsyncApp.kt", "insert_after", "import android.app.Application",
             '\n\n@Suppress("InsecureFlagSecure")\nval reflect = Class.forName("x")'),
]


# --- US1 (T089): password fields, layouts, secrets, logging, receiver, Keystore -------------
LAYOUT = f"{RES}/layout"
UNLOCK_PW = """            android:id="@+id/master_password"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:hint="@string/master_password"
            android:inputType="textPassword|textNoSuggestions"
            android:imeOptions="actionDone|flagNoPersonalizedLearning"
            android:importantForAutofill="noExcludeDescendants" />"""
US1 = [
    Mutation("X4", f"{LAYOUT}/unlock.xml", "replace", 'android:inputType="textPassword|textNoSuggestions"', 'android:inputType="textPassword"'),
    Mutation("X4", f"{LAYOUT}/create.xml", "replace", "actionNext|flagNoPersonalizedLearning", "actionNext"),
    Mutation("X4", f"{LAYOUT}/unlock.xml", "replace", 'android:importantForAutofill="noExcludeDescendants"', 'android:importantForAutofill="auto"'),
    Mutation("X4", f"{LAYOUT}/unlock.xml", "replace", UNLOCK_PW,
             UNLOCK_PW.replace(' />', '\n            android:autofillHints="password" />')),
    Mutation("X5", f"{LAYOUT}/about.xml", "replace", '            android:text="@string/about_storage"',
             '            android:text="@string/about_storage"\n            android:autoLink="web"'),
    Mutation("X5", f"{LAYOUT}/about.xml", "replace", "    </LinearLayout>\n</ScrollView>",
             '        <WebView android:layout_width="match_parent" android:layout_height="wrap_content" />\n    </LinearLayout>\n</ScrollView>'),
    Mutation("X6", f"{LAYOUT}/wallet_list.xml", "replace", 'android:text="@string/create_wallet"', 'android:text="Create wallet"'),
    Mutation("X6", f"{LAYOUT}/unlock.xml", "replace", '            android:hint="@string/master_password"\n', ""),
    Mutation("X6", f"{LAYOUT}/wallet_list.xml", "replace", '            android:text="@string/lock_all" />', " />"),
    Mutation("X6", f"{RES}/values-de/strings.xml", "add_file", "",
             '<?xml version="1.0" encoding="utf-8"?>\n<resources>\n    <string name="app_name">passwsync</string>\n</resources>\n'),
    Mutation("S4", f"{KT}/screens/Unlock.kt", "replace",
             "            Secrets.use(password) {\n                core.unlockWallet(wallet, password)\n            }",
             "            core.unlockWallet(wallet, password)"),
    Mutation("S4", f"{KT}/screens/Create.kt", "replace",
             "Secrets.plain(find<EditText>(R.id.wallet_name))", "find<EditText>(R.id.wallet_name).text.toString()"),
    Mutation("S4", f"{KT}/screens/Unlock.kt", "insert_after", "        find<TextView>(R.id.unlock_wallet_name).text = wallet",
             "\n        val shown = Secrets.platformText(byteArrayOf())"),
    Mutation("S4", f"{KT}/Secrets.kt", "delete_file"),
    Mutation("S8", f"{KT}/platform/LogcatSink.kt", "replace", "Log.i(TAG, line)", "Log.d(TAG, line)"),
    Mutation("S8", f"{KT}/platform/LogcatSink.kt", "replace", "Log.i(TAG, line)", "Log.i(TAG, \"x\" + line)"),
    Mutation("S8", f"{KT}/screens/About.kt", "insert_after", "activity.back() }", "\n        println(\"about\")"),
    Mutation("S8", f"{KT}/screens/Security.kt", "insert_after", "val status = core.protectionStatus()",
             "\n        android.util.Log.i(\"passwsync\", status.toString())"),
    Mutation("S11", f"{KT}/platform/ScreenOffReceiver.kt", "replace", "Context.RECEIVER_NOT_EXPORTED", "Context.RECEIVER_EXPORTED"),
    Mutation("S11", f"{KT}/platform/ScreenOffReceiver.kt", "replace", "IntentFilter(Intent.ACTION_SCREEN_OFF)",
             "IntentFilter(Intent.ACTION_SCREEN_OFF).apply { addAction(Intent.ACTION_USER_PRESENT) }"),
    Mutation("S11", f"{KT}/PasswsyncApp.kt", "insert_after", "registerActivityLifecycleCallbacks(this)",
             "\n            registerReceiver(null, android.content.IntentFilter(\"x\"), RECEIVER_NOT_EXPORTED)"),
    Mutation("S15", f"{KT}/platform/KeystoreSealer.kt", "replace", ".setUserAuthenticationRequired(false)", ".setUserAuthenticationRequired(true)"),
    Mutation("S15", f"{KT}/platform/KeystoreSealer.kt", "replace", ".setRandomizedEncryptionRequired(true)\n", "\n"),
    Mutation("S15", f"{KT}/platform/KeystoreSealer.kt", "replace",
             "            cipher.updateAAD(label.toByteArray(Charsets.UTF_8))\n            val iv", "            val iv"),
    Mutation("S15", f"{KT}/platform/KeystoreSealer.kt", "replace", "KeyProperties.BLOCK_MODE_GCM", "KeyProperties.BLOCK_MODE_CBC"),
    Mutation("S15", f"{KT}/screens/Security.kt", "insert_after", "val status = core.protectionStatus()",
             "\n        val store = java.security.KeyStore.getInstance(\"AndroidKeyStore\")"),
    Mutation("S15", f"{KT}/platform/KeystoreSealer.kt", "insert_after", "private fun store(): KeyStore",
             " = KeyStore.getInstance(\"AndroidKeyStore\").apply { load(null) }\n    fun leak(core: io.github.henriqk0.passwsync.core.PasswsyncCore) = core.listWallets()\n    private fun unused(): KeyStore"),
    Mutation("S16", f"{KT}/screens/Unlock.kt", "insert_after", "        find<TextView>(R.id.unlock_wallet_name).text = wallet",
             "\n        find<EditText>(R.id.master_password).inputType = android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD"),
    Mutation("S16", f"{KT}/screens/Unlock.kt", "insert_after", "        find<TextView>(R.id.unlock_wallet_name).text = wallet",
             "\n        find<EditText>(R.id.master_password).setAutofillHints(\"password\")"),
]

# --- US2 (T099): clipboard, secret calls, deadline job ----------------------------------------
US2 = [
    Mutation("S3", f"{KT}/platform/ClipboardAdapter.kt", "replace", "putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)",
             "putBoolean(\"sensitive\", true)"),
    Mutation("S3", f"{KT}/platform/ClipboardAdapter.kt", "replace", "putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)",
             "putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, false)"),
    Mutation("S3", f"{KT}/platform/ClipboardAdapter.kt", "replace",
             "            clip.description.extras = PersistableBundle().apply {\n"
             "                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)\n            }\n", ""),
    Mutation("S3", f"{KT}/screens/CredentialView.kt", "insert_after", "    private fun copy(field: CopyField) {",
             "\n        activity.getSystemService(android.content.ClipboardManager::class.java).setPrimaryClip(android.content.ClipData.newPlainText(\"\", \"x\"))"),
    Mutation("S4", f"{KT}/screens/CredentialEdit.kt", "replace",
             "            Secrets.use(password) {\n                if (existing == null) {\n                    core.addCredential(wallet, input)\n"
             "                } else {\n                    core.updateCredential(wallet, existing, input)\n                }\n            }",
             "            if (existing == null) {\n                core.addCredential(wallet, input)\n"
             "            } else {\n                core.updateCredential(wallet, existing, input)\n            }"),
    Mutation("S4", f"{KT}/screens/Credentials.kt", "insert_after", "    private fun render(found: List<CredentialSummary>) {",
             "\n        val shown = Secrets.platformText(byteArrayOf())"),
    Mutation("S4", f"{KT}/screens/CredentialView.kt", "replace", "Secrets.platformText(ticket.password)",
             "ticket.password.decodeToString()"),
    Mutation("S10", f"{KT}/platform/JobPlanner.kt", "replace", ".setOverrideDeadline(deadline.toLong() + SLACK_MS)",
             ".setOverrideDeadline(deadline.toLong() + SLACK_MS)\n                    .setPersisted(true)"),
    Mutation("S10", f"{KT}/platform/JobPlanner.kt", "replace", ".setOverrideDeadline(deadline.toLong() + SLACK_MS)",
             ".setOverrideDeadline(deadline.toLong() + SLACK_MS)\n                    .setRequiresBatteryNotLow(true)"),
    Mutation("S10", f"{KT}/platform/CoreJobService.kt", "insert_after", "val core = app.core ?: return false",
             "\n        getSystemService(android.app.AlarmManager::class.java)"),
    Mutation("S10", f"{KT}/platform/CoreJobService.kt", "insert_after", "val core = app.core ?: return false",
             "\n        getSystemService(android.app.job.JobScheduler::class.java).cancelAll()"),
]

# --- US4 (T108): networking stays in Rust, multicast lock, local-network permission ---------
MCL = f"{KT}/platform/MulticastLockHolder.kt"
NETS = f"{KT}/screens/Network.kt"
US4 = [
    Mutation("S7", NETS, "insert_after", "    override fun bind() {",
             "\n        java.net.Socket(\"192.168.1.2\", 1)"),
    Mutation("S7", NETS, "insert_after", "    override fun bind() {",
             "\n        java.net.InetAddress.getByName(\"desktop.local\")"),
    Mutation("S7", f"{KT}/platform/NetworkClassifier.kt", "insert_after", "    fun start() {",
             "\n        val nsd = android.net.nsd.NsdManager::class.java"),
    Mutation("S7", NETS, "insert_after", "    override fun bind() {",
             "\n        java.net.URL(\"https://example.org\").openConnection()"),
    Mutation("S12", MCL, "replace", "setReferenceCounted(false)", "setReferenceCounted(true)"),
    Mutation("S12", MCL, "replace", "        } else if (lock.isHeld) {\n            lock.release()\n        }", "        }"),
    Mutation("S12", MCL, "delete_file"),
    Mutation("S12", NETS, "insert_after", "    override fun bind() {",
             "\n        activity.getSystemService(android.net.wifi.WifiManager::class.java).createMulticastLock(\"x\").acquire()"),
    Mutation("M4", MAN, "insert_after", PERM, '\n    <uses-permission android:name="android.permission.NEARBY_WIFI_DEVICES" />'),
    Mutation("M4", MAN, "replace", '    <uses-permission android:name="android.permission.CHANGE_WIFI_MULTICAST_STATE" />\n', ""),
    Mutation("X3", NSC, "replace", 'cleartextTrafficPermitted="false"', 'cleartextTrafficPermitted="true" '),
]

# --- US5 (T117): background windows only through JobScheduler, one job service, one process --
JOBS = f"{KT}/platform/JobPlanner.kt"
JOBSVC = f"{KT}/platform/CoreJobService.kt"
US5 = [
    Mutation("S10", JOBS, "replace", ".setPeriodic(periodic.toLong() * MINUTE_MS)",
             ".setPeriodic(periodic.toLong() * MINUTE_MS)\n                    .setPersisted(true)"),
    Mutation("S10", JOBS, "replace",
             ".setMinimumLatency(plan.keepNetworkMs.toLong())\n                    .setRequiresBatteryNotLow(true)\n",
             ".setMinimumLatency(plan.keepNetworkMs.toLong())\n"),
    Mutation("S10", JOBS, "replace",
             ".setPeriodic(periodic.toLong() * MINUTE_MS)\n                    .setRequiresBatteryNotLow(true)\n"
             "                    .setRequiredNetwork(localNetwork())\n",
             ".setPeriodic(periodic.toLong() * MINUTE_MS)\n"),
    Mutation("S10", JOBS, "replace", "            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)\n", ""),
    Mutation("S10", JOBS, "replace", "            .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)\n", ""),
    Mutation("S10", JOBS, "replace", "const val EXTRA_WINDOW_JOB = 3", "const val EXTRA_WINDOW_JOB = 4"),
    Mutation("S10", JOBSVC, "insert_after", "val core = app.core ?: return false",
             "\n        val alarms = getSystemService(android.app.AlarmManager::class.java)"),
    Mutation("S10", JOBSVC, "insert_after", "val core = app.core ?: return false",
             "\n        val wake = getSystemService(android.os.PowerManager::class.java).newWakeLock(1, \"x\") as android.os.PowerManager.WakeLock"),
    Mutation("M9", MAN, "insert_after", SERVICE_END,
             '\n\n        <service\n            android:name=".platform.SyncService"\n            android:exported="false" />'),
    Mutation("M10", MAN, "replace", 'android:name=".platform.CoreJobService"',
             'android:name=".platform.CoreJobService"\n            android:process=":sync"'),
]

# --- Polish (T127): binding rules over copies of the real generated Kotlin ------------------
GEN = "io/github/henriqk0/passwsync/core/passwsync_ffi.kt"
CREATE = "fun `createWallet`(`name`: kotlin.String, `password`: kotlin.ByteArray, `confirm`: kotlin.ByteArray)"
LIST = "    fun `listWallets`(): List<WalletInfo>"
BINDINGS = [
    Mutation("B1", GEN, "replace", "package io.github.henriqk0.passwsync.core", "package org.example.core"),
    Mutation("B1", GEN, "insert_after", "import com.sun.jna.Library", "\nimport okhttp3.OkHttpClient"),
    Mutation("B1", GEN, "replace", 'findLibraryName(componentName = "passwsync_ffi")', 'findLibraryName(componentName = "other_lib")'),
    Mutation("B2", GEN, "replace", CREATE,
             "fun `createWallet`(`name`: kotlin.String, `password`: kotlin.String, `confirm`: kotlin.ByteArray)"),
    Mutation("B2", GEN, "replace", "data class RevealTicket (\n    var `password`: kotlin.ByteArray",
             "data class RevealTicket (\n    var `password`: kotlin.String"),
    Mutation("B3", GEN, "replace", "data class SettingsView (\n",
             "data class SettingsView (\n    var `password`: kotlin.ByteArray\n    , \n"),
    Mutation("B3", GEN, "insert_after", "data class CredentialSummary (\n", "    var `notes`: kotlin.String\n    , \n"),
    Mutation("B4", GEN, "insert_after", LIST, "\n    fun `exportAll`(): kotlin.ByteArray\n"),
    Mutation("B5", GEN, "replace", "class AlreadyStarted(message: String) : CoreException(message)",
             "class AlreadyRunning(message: String) : CoreException(message)"),
    Mutation("B6", GEN, "replace", LIST, "    suspend fun `listWallets`(): List<WalletInfo>"),
]

MUTATIONS: list = US3 + US1 + US2 + US4 + US5 + BINDINGS


def owner(rule: str) -> str:
    return OWNERS[rule[0]]


def all_rules():
    rules = []
    for module in ("check_manifest", "check_sources", "check_bindings"):
        rules.extend(importlib.import_module(module).RULES)
    return rules


def coverage(mutations, rules):
    covered = {m.rule for m in mutations}
    return [rule for rule in rules if rule not in covered]


class NotApplicable(Exception):
    pass


def apply(mutation: Mutation, root: Path):
    path = root / mutation.path
    if mutation.kind == "add_file":
        if path.exists():
            raise NotApplicable(f"{mutation.path} already exists")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(mutation.replace, encoding="utf-8")
        return
    if not path.is_file():
        raise NotApplicable(f"{mutation.path} does not exist")
    if mutation.kind == "delete_file":
        path.unlink()
        return
    text = path.read_text(encoding="utf-8")
    if not mutation.find or mutation.find not in text:
        raise NotApplicable(f"{mutation.find!r} not in {mutation.path}")
    if mutation.kind == "replace":
        text = text.replace(mutation.find, mutation.replace, 1)
    else:
        at = text.index(mutation.find) + len(mutation.find)
        text = text[:at] + mutation.replace + text[at:]
    path.write_text(text, encoding="utf-8")


def run_checker(name: str, args):
    module = importlib.import_module(name)
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        try:
            code = module.main([str(a) for a in args])
        except SystemExit as stop:
            code = stop.code
    return code, out.getvalue().splitlines()


def checker_args(name, android_dir: Path, bindings_dir: Path, inventory):
    if name == "check_bindings":
        return [bindings_dir] + (["--inventory", inventory] if inventory else [])
    return [android_dir]


def run_one(mutation: Mutation, android_dir: Path, bindings_dir: Path, work: Path, inventory=None):
    """(ok, detail). The copy lives under `work` and is removed afterwards."""
    work.mkdir(parents=True, exist_ok=True)
    copy = work / "case"
    shutil.rmtree(copy, ignore_errors=True)
    try:
        android_copy, bindings_copy = copy / "android", copy / "bindings"
        shutil.copytree(android_dir, android_copy)
        if Path(bindings_dir).is_dir():
            shutil.copytree(bindings_dir, bindings_copy)
        else:
            bindings_copy.mkdir(parents=True)
        target = bindings_copy if mutation.rule.startswith("B") else android_copy
        label = f"{mutation.rule} {mutation.kind} {mutation.path}"
        try:
            apply(mutation, target)
        except NotApplicable as error:
            return False, f"{label}: does not apply ({error})"
        name = owner(mutation.rule)
        code, lines = run_checker(name, checker_args(name, android_copy, bindings_copy, inventory))
        ids = [line.split(":", 1)[0] for line in lines]
        if code != 1 or not lines:
            return False, f"{label}: not detected by {name} (exit {code})"
        if mutation.rule not in ids:
            return False, f"{label}: detected under {sorted(set(ids))}, not {mutation.rule}"
        return True, label
    finally:
        shutil.rmtree(copy, ignore_errors=True)


def run_all(mutations, android_dir, bindings_dir, work, inventory=None, rules=None):
    failures = []
    android_dir, bindings_dir, work = Path(android_dir), Path(bindings_dir), Path(work)
    for name in ("check_manifest", "check_sources", "check_bindings"):
        if name == "check_bindings" and not bindings_dir.is_dir():
            continue
        code, lines = run_checker(name, checker_args(name, android_dir, bindings_dir, inventory))
        if code != 0:
            failures.append(f"baseline: {name} fails on the unmodified tree ({'; '.join(lines[:3])})")
    for mutation in mutations:
        ok, detail = run_one(mutation, android_dir, bindings_dir, work, inventory)
        if not ok:
            failures.append(detail)
    for rule in coverage(mutations, all_rules() if rules is None else rules):
        failures.append(f"no mutation for {rule}")
    return failures


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    inventory = None
    if "--inventory" in argv:
        at = argv.index("--inventory")
        if at + 1 >= len(argv):
            argv = []
        else:
            inventory = argv[at + 1]
            del argv[at:at + 2]
    if len(argv) != 3 or not Path(argv[0]).is_dir():
        print("usage: python3 -I mutations.py <android-dir> <bindings-dir> <work-dir> [--inventory FILE]",
              file=sys.stderr)
        return 64
    failures = run_all(MUTATIONS, argv[0], argv[1], argv[2], inventory)
    print(f"mutations: {len(MUTATIONS)} run, {len(failures)} failures")
    for failure in failures:
        print(f"MUTATION-FAIL {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
