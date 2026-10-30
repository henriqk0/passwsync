"""check_sources.py: one or more negative tests per Kotlin source rule S1-S17, each a single
violation applied to the good fixture's Kotlin, plus the positive case."""

import unittest

from support import PolicyCase, mutate, run_checker

K = "app/src/main/kotlin/io/github/henriqk0/passwsync"
APP = f"{K}/PasswsyncApp.kt"
SECURE = f"{K}/SecureActivity.kt"
MAIN = f"{K}/MainActivity.kt"
DIALOGS = f"{K}/SecureDialogs.kt"
SECRETS = f"{K}/Secrets.kt"
SEALER = f"{K}/platform/KeystoreSealer.kt"
CLIP = f"{K}/platform/ClipboardAdapter.kt"
LOGCAT = f"{K}/platform/LogcatSink.kt"
JOBS = f"{K}/platform/JobPlanner.kt"
SCREEN = f"{K}/platform/ScreenOffReceiver.kt"
MCAST = f"{K}/platform/MulticastLockHolder.kt"
VIEW = f"{K}/screens/CredentialView.kt"
EXTRA = f"{K}/screens/Extra.kt"

FLAGS = "window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)\n"
SHOT = "setRecentsScreenshotEnabled(false)\n"


def repl(path, find, replace):
    return ("replace", path, find, replace)


def extra(code, package="io.github.henriqk0.passwsync.screens"):
    """A new file with one offending statement inside a function."""
    return ("add", EXTRA, f"package {package}\n\nclass Extra {{\n    fun run() {{\n        {code}\n    }}\n}}\n")


CASES = {
    "S1_no_recents_off": ("S1", repl(SECURE, "        " + SHOT, "")),
    "S1_no_flag_secure": ("S1", repl(SECURE, "        " + FLAGS, "")),
    "S1_flags_after_super": ("S1", repl(SECURE, "        " + FLAGS + "        " + SHOT + "        super.onCreate(savedInstanceState)\n",
                                        "        super.onCreate(savedInstanceState)\n        " + FLAGS + "        " + SHOT)),
    "S1_plain_activity": ("S1", repl(MAIN, "class MainActivity : SecureActivity()", "class MainActivity : android.app.Activity()")),
    "S1_clear_flags": ("S1", repl(MAIN, "setContentView(R.layout.screen_unlock)", "setContentView(R.layout.screen_unlock)\n        window.clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)")),
    "S1_set_content_before_flags": ("S1", repl(SECURE, "        " + FLAGS, "        setContentView(0)\n        " + FLAGS)),
    "S2_toast": ("S2", extra("android.widget.Toast.makeText(null, 0, 0).show()")),
    "S2_toast_in_dialogs": ("S2", repl(DIALOGS, "dialog.show()", "dialog.show()\n        android.widget.Toast.makeText(context, message, 0).show()")),
    "S2_alert_dialog_elsewhere": ("S2", extra("android.app.AlertDialog.Builder(null).create()")),
    "S2_snackbar": ("S2", extra("Snackbar.make(null, 0, 0)")),
    "S2_dialog_without_secure": ("S2", repl(DIALOGS, "        dialog.window?.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)\n", "")),
    "S3_not_sensitive": ("S3", repl(CLIP, "putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)", "putBoolean(\"x\", true)")),
    "S3_sensitive_false": ("S3", repl(CLIP, "putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)", "putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, false)")),
    "S3_clip_elsewhere": ("S3", extra("val m: android.content.ClipboardManager? = null")),
    "S3_second_unmarked_clip": ("S3", repl(CLIP, "manager.setPrimaryClip(clip)", "manager.setPrimaryClip(clip)\n        manager.setPrimaryClip(ClipData.newPlainText(\"\", \"x\"))")),
    "S4_text_to_string": ("S4", extra("val s = field.text.toString()")),
    "S4_decode_to_string": ("S4", extra("val s = bytes.decodeToString()")),
    "S4_string_of_bytes": ("S4", extra("val s = String(bytes)")),
    "S4_charsets": ("S4", extra("val s = bytes.toString(Charsets.UTF_8)")),
    "S4_platform_text_elsewhere": ("S4", extra("val s = Secrets.platformText(bytes)")),
    "S4_secret_call_unwrapped": ("S4", repl(VIEW, "        Secrets.use(password) {\n            core.unlockWallet(wallet, password)\n        }", "        core.unlockWallet(wallet, password)")),
    "S5_webview": ("S5", extra("val w = android.webkit.WebView(null)")),
    "S5_action_view": ("S5", extra("val i = android.content.Intent(android.content.Intent.ACTION_VIEW, uri)")),
    "S5_custom_tabs": ("S5", extra("CustomTabsIntent.Builder().build()")),
    "S6_shared_preferences": ("S6", extra("context.getSharedPreferences(\"p\", 0)")),
    "S6_external_files": ("S6", extra("context.getExternalFilesDir(null)")),
    "S6_files_dir_to_core": ("S6", repl(APP, "CoreConfig(noBackupFilesDir.absolutePath, emptyList())", "CoreConfig(filesDir.absolutePath, emptyList())")),
    "S6_open_file_output": ("S6", extra("context.openFileOutput(\"x\", 0)")),
    "S7_url": ("S7", extra("val u = java.net.URL(\"http://example.org\")")),
    "S7_socket": ("S7", extra("val s = java.net.Socket(\"h\", 1)")),
    "S7_nsd": ("S7", extra("val n: android.net.nsd.NsdManager? = null")),
    "S7_okhttp": ("S7", extra("val c = okhttp3.OkHttpClient()")),
    "S8_log_d": ("S8", repl(LOGCAT, "Log.i(TAG, line)", "Log.d(TAG, line)")),
    "S8_println": ("S8", extra("println(\"x\")")),
    "S8_log_elsewhere": ("S8", extra("android.util.Log.i(\"t\", \"x\")")),
    "S8_log_other_argument": ("S8", repl(LOGCAT, "Log.i(TAG, line)", "Log.i(TAG, line + \"!\")")),
    "S8_stack_trace": ("S8", extra("Exception().printStackTrace()")),
    "S9_account_manager": ("S9", extra("val a: android.accounts.AccountManager? = null")),
    "S9_gms": ("S9", extra("com.google.android.gms.common.GoogleApiAvailability.getInstance()")),
    "S9_biometric": ("S9", extra("val b: android.hardware.biometrics.BiometricPrompt? = null")),
    "S10_persisted": ("S10", repl(JOBS, ".setMinimumLatency(deadline.toLong())", ".setMinimumLatency(deadline.toLong())\n                .setPersisted(true)")),
    "S10_no_battery_not_low": ("S10", repl(JOBS, ".setPeriodic(minutes.toLong() * 60_000L)\n                .setRequiresBatteryNotLow(true)", ".setPeriodic(minutes.toLong() * 60_000L)")),
    "S10_no_network_on_extra": ("S10", repl(JOBS, "            JobInfo.Builder(EXTRA_JOB, service)\n                .setRequiresBatteryNotLow(true)\n                .setRequiredNetwork(localNetwork())", "            JobInfo.Builder(EXTRA_JOB, service)\n                .setRequiresBatteryNotLow(true)")),
    "S10_deadline_constrained": ("S10", repl(JOBS, ".setMinimumLatency(deadline.toLong())", ".setMinimumLatency(deadline.toLong())\n                .setRequiresBatteryNotLow(true)")),
    "S10_internet_kept": ("S10", repl(JOBS, "        .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)\n", "")),
    "S10_alarm": ("S10", extra("val a: android.app.AlarmManager? = null")),
    "S10_scheduler_elsewhere": ("S10", extra("val s: android.app.job.JobScheduler? = null")),
    "S10_foreground": ("S10", extra("context.startForegroundService(intent)")),
    "S11_second_receiver": ("S11", extra("context.registerReceiver(r, f, android.content.Context.RECEIVER_NOT_EXPORTED)")),
    "S11_exported_receiver": ("S11", repl(SCREEN, "Context.RECEIVER_NOT_EXPORTED", "Context.RECEIVER_EXPORTED")),
    "S11_other_action": ("S11", repl(SCREEN, "IntentFilter(Intent.ACTION_SCREEN_OFF)", "IntentFilter(Intent.ACTION_USER_PRESENT)")),
    "S12_lock_elsewhere": ("S12", extra("wifi.createMulticastLock(\"x\")")),
    "S12_reference_counted": ("S12", repl(MCAST, "setReferenceCounted(false)", "setReferenceCounted(true)")),
    "S12_never_released": ("S12", repl(MCAST, "            lock.release()\n", "")),
    "S13_my_pid": ("S13", extra("val p = android.os.Process.myPid()")),
    "S13_remote_process": ("S13", extra("val p = \":remote\"")),
    "S13_core_start_elsewhere": ("S13", extra("PasswsyncCore.start(config, a, b, c, d)")),
    "S13_core_start_outside_on_create": ("S13", repl(APP, "        core = PasswsyncCore.start(config, KeystoreSealer(), ClipboardAdapter(this), LogcatSink(), UiBridge())\n        ScreenOffReceiver.register(this, core)\n    }",
                                                     "        ScreenOffReceiver.register(this, core)\n    }\n\n    fun later(config: CoreConfig) {\n        core = PasswsyncCore.start(config, KeystoreSealer(), ClipboardAdapter(this), LogcatSink(), UiBridge())\n    }")),
    "S14_camera": ("S14", extra("val c: android.hardware.camera2.CameraManager? = null")),
    "S14_zxing": ("S14", extra("val r = com.google.zxing.MultiFormatReader()")),
    "S15_auth_required": ("S15", repl(SEALER, ".setUserAuthenticationRequired(false)", ".setUserAuthenticationRequired(true)")),
    "S15_no_randomized": ("S15", repl(SEALER, "                .setRandomizedEncryptionRequired(true)\n", "")),
    "S15_no_aad": ("S15", repl(SEALER, "        cipher.updateAAD(label.toByteArray())\n        return cipher.doFinal(sealed", "        return cipher.doFinal(sealed")),
    "S15_calls_core": ("S15", repl(SEALER, "    override fun reset() {", "    fun leak(core: io.github.henriqk0.passwsync.core.PasswsyncCore) = core.listWallets()\n\n    override fun reset() {")),
    "S15_keystore_elsewhere": ("S15", extra("java.security.KeyStore.getInstance(\"AndroidKeyStore\")")),
    "S15_validity": ("S15", repl(SEALER, ".setUserAuthenticationRequired(false)", ".setUserAuthenticationRequired(false)\n                .setUserAuthenticationValidityDurationSeconds(30)")),
    "S15_cbc": ("S15", repl(SEALER, "KeyProperties.BLOCK_MODE_GCM", "KeyProperties.BLOCK_MODE_CBC")),
    "S16_password_field_in_code": ("S16", extra("edit.inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD")),
    "S16_autofill_hints": ("S16", extra("edit.setAutofillHints(\"password\")")),
    "S17_wrong_package": ("S17", extra("val x = 1", package="com.example.other")),
    "S17_suppress_secure": ("S17", repl(MAIN, "class MainActivity", "@Suppress(\"SecureFlag\")\nclass MainActivity")),
    "S17_reflection": ("S17", extra("Class.forName(\"io.github.henriqk0.passwsync.core.PasswsyncCore\")")),
    "S17_no_package": ("S17", ("add", EXTRA, "class Extra\n")),
}


def apply(root, change):
    if change[0] == "replace":
        mutate(root / change[1], change[2], change[3])
    else:
        path = root / change[1]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(change[2], encoding="utf-8")


class CheckSources(PolicyCase):
    checker = "check_sources"

    def test_good_fixture_passes(self):
        self.assertPasses(self.tree())

    def test_comments_and_strings_do_not_count(self):
        root = self.tree()
        apply(root, extra('val s = "WebView Log.d(x) java.net.URL"  // println(x) Toast.makeText'))
        self.assertPasses(root)

    def test_usage_error(self):
        self.assertEqual(run_checker(self.checker, "/nonexistent")[0], 64)


def make(rule, change):
    def test(self):
        root = self.tree()
        apply(root, change)
        self.assertFails(root, rule)
    return test


for case, (rule, change) in CASES.items():
    setattr(CheckSources, f"test_{case}", make(rule, change))


if __name__ == "__main__":
    unittest.main()
