"""Kotlin source rules S1-S17 of contracts/android-policy.md section 4, over
`app/src/main/kotlin/**/*.kt` after stripping comments and string literals (rules that name a
literal look at the raw text).

usage: python3 -I check_sources.py <android-dir>
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import Finding, block_after, run_main, strip_kotlin  # noqa: E402

RULES = [f"S{i}" for i in range(1, 18)]

KOTLIN = "app/src/main/kotlin"
PACKAGE_DIR = "io/github/henriqk0/passwsync"
PACKAGE = re.compile(r"^io\.github\.henriqk0\.passwsync(\.\w+)*$")
SECRET_CALLS = re.compile(
    r"\.(createWallet|unlockWallet|changePassword|joinPairing|redeemInvitation|openReceived|"
    r"openPendingWithPassword|addCredential|updateCredential)\s*\("
)


class Source:
    def __init__(self, path: Path, name: str):
        self.path = path
        self.name = name
        self.raw = path.read_text(encoding="utf-8")
        self.code = strip_kotlin(self.raw)
        self.compact = re.sub(r"\s+", "", self.code)


def sources(root: Path):
    base = root / KOTLIN
    package_dir = base / PACKAGE_DIR
    out = {}
    for path in sorted(base.rglob("*.kt")) if base.is_dir() else []:
        try:
            name = path.relative_to(package_dir).as_posix()
        except ValueError:
            name = path.relative_to(base).as_posix()
        out[name] = Source(path, name)
    return out


def paren_args(text: str, open_paren: int) -> str:
    depth = 0
    for i in range(open_paren, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1:i]
    return text[open_paren + 1:]


def function_body(code: str, name: str):
    match = re.search(rf"\bfun\s+{name}\s*\(", code)
    if not match:
        return None
    span = block_after(code, match.end())
    return code[span[0]:span[1]] if span else None


class Checker:
    def __init__(self, root: Path):
        self.files = sources(root)
        self.out = []

    def add(self, rule, message):
        self.out.append(Finding(rule, message))

    def get(self, name, rule):
        source = self.files.get(name)
        if source is None:
            self.add(rule, f"{name} is missing")
        return source

    def forbid(self, rule, pattern, what, allowed=(), raw=False):
        regex = re.compile(pattern)
        for name, source in self.files.items():
            if name in allowed:
                continue
            match = regex.search(source.raw if raw else source.code)
            if match:
                self.add(rule, f"{name}: {what} ({match.group(0).strip()})")

    def run(self):
        for rule in RULES:
            getattr(self, rule.lower())()
        return self.out

    # S1 FLAG_SECURE and recents
    def s1(self):
        for name, source in self.files.items():
            for match in re.finditer(r"\bclass\s+(\w+)(?:\s*(?:private\s+)?(?:constructor\s*)?\([^)]*\))?\s*:\s*([\w.]+)\s*\(", source.code):
                cls, parent = match.group(1), match.group(2).split(".")[-1]
                if cls == "SecureActivity":
                    if parent != "Activity":
                        self.add("S1", f"{name}: SecureActivity must extend Activity")
                elif parent.endswith("Activity") and parent != "SecureActivity":
                    self.add("S1", f"{name}: {cls} must extend SecureActivity, not {parent}")
        self.forbid("S1", r"clearFlags\s*\([^)]*FLAG_SECURE", "FLAG_SECURE must never be cleared")
        secure = self.get("SecureActivity.kt", "S1")
        if secure is None:
            return
        body = function_body(secure.code, "onCreate")
        if body is None:
            self.add("S1", "SecureActivity.kt: onCreate is missing")
            return
        body = re.sub(r"\s+", "", body)
        flags = body.find("window.setFlags(WindowManager.LayoutParams.FLAG_SECURE,WindowManager.LayoutParams.FLAG_SECURE)")
        shot = body.find("setRecentsScreenshotEnabled(false)")
        if flags < 0:
            self.add("S1", "SecureActivity.onCreate must set FLAG_SECURE")
        if shot < 0:
            self.add("S1", "SecureActivity.onCreate must call setRecentsScreenshotEnabled(false)")
        for marker in ("super.onCreate(", "setContentView("):
            at = body.find(marker)
            if at >= 0 and (flags > at or shot > at):
                self.add("S1", f"FLAG_SECURE and recents must be set before {marker[:-1]}")

    # S2 dialogs
    def s2(self):
        self.forbid("S2", r"\bAlertDialog\b|(?<![\w.])Dialog\s*\(|\bPopupWindow\s*\(|\bSnackbar\b|\bDialogFragment\b",
                    "dialogs only in SecureDialogs.kt", allowed=("SecureDialogs.kt",))
        self.forbid("S2", r"\bToast\b", "Toast is not allowed")
        dialogs = self.get("SecureDialogs.kt", "S2")
        if dialogs is None:
            return
        created = len(re.findall(r"\.create\s*\(\s*\)|(?<![\w.])Dialog\s*\(|\bPopupWindow\s*\(", dialogs.code))
        secured = len(re.findall(r"(setFlags|addFlags)\(WindowManager\.LayoutParams\.FLAG_SECURE", dialogs.compact))
        if secured == 0 or secured < created:
            self.add("S2", f"SecureDialogs.kt: {created} dialog windows but {secured} FLAG_SECURE")

    # S3 clipboard
    def s3(self):
        adapter_name = "platform/ClipboardAdapter.kt"
        self.forbid("S3", r"\bClipboardManager\b|\bsetPrimaryClip\b|\bClipData\b",
                    "clipboard only in platform/ClipboardAdapter.kt", allowed=(adapter_name,))
        adapter = self.get(adapter_name, "S3")
        if adapter is None:
            return
        c = adapter.compact
        sensitive = c.count("putBoolean(ClipDescription.EXTRA_IS_SENSITIVE,true)")
        clips = max(c.count("setPrimaryClip("), len(re.findall(r"ClipData\.new\w+\(", c)))
        extras = c.count("description.extras=PersistableBundle()")
        if sensitive == 0 or "EXTRA_IS_SENSITIVE,false" in c:
            self.add("S3", "ClipboardAdapter.kt must set EXTRA_IS_SENSITIVE to true")
        if extras < clips or sensitive < clips:
            self.add("S3", f"{clips} clips but {min(extras, sensitive)} marked sensitive")

    # S4 secrets
    def s4(self):
        self.get("Secrets.kt", "S4")
        self.forbid("S4", r"\.text\.toString\(\)|\.getText\(\)\.toString\(\)|(?<![\w.])String\(\s*[^)\s]|"
                          r"decodeToString\(|toString\(\s*Charsets|Charsets?\.UTF_8\.decode\(",
                    "secret conversion outside Secrets.kt", allowed=("Secrets.kt",))
        self.forbid("S4", r"Secrets\.platformText\(", "Secrets.platformText outside its two callers",
                    allowed=("platform/ClipboardAdapter.kt", "screens/CredentialView.kt"))
        for name, source in self.files.items():
            spans = []
            for match in re.finditer(r"\bSecrets\.use\b", source.code):
                span = block_after(source.code, match.end())
                if span:
                    spans.append(span)
            for call in SECRET_CALLS.finditer(source.code):
                if not any(a < call.start() < b for a, b in spans):
                    self.add("S4", f"{name}: {call.group(1)} must be inside Secrets.use {{ }}")

    def s5(self):
        self.forbid("S5", r"android\.webkit|\bWebView\b|CustomTabs|ACTION_VIEW", "no web content")

    def s6(self):
        self.forbid("S6", r"getExternalFilesDir|getExternalCacheDir|Environment\.getExternalStorage|MediaStore|"
                          r"FileProvider|ContentResolver\.insert|contentResolver\.insert|getSharedPreferences|"
                          r"openFileOutput|MODE_WORLD_|DocumentFile|ACTION_CREATE_DOCUMENT|ACTION_OPEN_DOCUMENT",
                    "storage outside noBackupFilesDir")
        for name, source in self.files.items():
            for match in re.finditer(r"\bCoreConfig\s*\(", source.code):
                if "noBackupFilesDir" not in paren_args(source.code, match.end() - 1):
                    self.add("S6", f"{name}: CoreConfig must be given noBackupFilesDir")

    def s7(self):
        self.forbid("S7", r"java\.net\.URL\b|(?<![\w.])URL\(|HttpURLConnection|HttpsURLConnection|okhttp|retrofit|ktor|"
                          r"\bSocket\s*\(|DatagramSocket|InetAddress\.getByName|InetAddress\.getAllByName|"
                          r"DnsResolver|NsdManager|WifiP2p", "networking belongs to Rust")

    def s8(self):
        sink = "platform/LogcatSink.kt"
        self.forbid("S8", r"\bandroid\.util\.Log\b|(?<![\w.])Log\.\w+\s*\(", "logging only in platform/LogcatSink.kt",
                    allowed=(sink,))
        self.forbid("S8", r"\bprintln\b|(?<![\w.])print\s*\(|printStackTrace|System\.out|System\.err|"
                          r"\bLog\.(d|v|w|e|wtf)\s*\(", "forbidden output")
        source = self.files.get(sink)
        if source is not None:
            for match in re.finditer(r"(?<![\w.])Log\.\w+\s*\(", source.code):
                call = re.sub(r"\s+", "", match.group(0) + paren_args(source.code, match.end() - 1) + ")")
                if call != "Log.i(TAG,line)":
                    self.add("S8", f"{sink}: only Log.i(TAG, line) is allowed ({call})")

    def s9(self):
        self.forbid("S9", r"AccountManager|com\.google\.android\.gms|com\.google\.firebase|AdvertisingIdClient|"
                          r"play\.core|BiometricPrompt|FingerprintManager|AutofillService", "no accounts or proprietary services")

    def s10(self):
        planner_name = "platform/JobPlanner.kt"
        self.forbid("S10", r"\bJobScheduler\b|\bJobInfo\b", "JobScheduler only in platform/JobPlanner.kt",
                    allowed=(planner_name,))
        self.forbid("S10", r"setPersisted\(\s*true|setExpedited|AlarmManager|startForegroundService|startForeground\s*\(|"
                           r"WakeLock|ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", "background work beyond JobScheduler")
        planner = self.get(planner_name, "S10")
        if planner is None:
            return
        c = planner.compact
        for token in ("TRANSPORT_WIFI", "TRANSPORT_ETHERNET", "NET_CAPABILITY_NOT_VPN",
                      "removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)"):
            if token not in c:
                self.add("S10", f"{planner_name}: window network request needs {token}")
        consts = dict(re.findall(r"constval(\w+)=(\d+)", c))
        seen = set()
        for match in re.finditer(r"JobInfo\.Builder\(([\w.]+),", c):
            end = c.find(".build()", match.end())
            segment = c[match.end():end if end >= 0 else len(c)]
            ident = consts.get(match.group(1), match.group(1))
            seen.add(ident)
            if ident in ("2", "3"):
                if "setRequiresBatteryNotLow(true)" not in segment or "setRequiredNetwork(" not in segment:
                    self.add("S10", f"window job {ident} needs setRequiresBatteryNotLow(true) and setRequiredNetwork")
            elif ident == "1":
                if "setRequiresBatteryNotLow" in segment or "setRequiredNetwork" in segment:
                    self.add("S10", "the deadline job 1 must have no battery or network constraint")
            else:
                self.add("S10", f"unexpected job id {match.group(1)}")
        if seen != {"1", "2", "3"}:
            self.add("S10", f"jobs 1, 2 and 3 expected, found {sorted(seen)}")

    def s11(self):
        receiver_name = "platform/ScreenOffReceiver.kt"
        self.forbid("S11", r"registerReceiver\s*\(", "receivers only in platform/ScreenOffReceiver.kt",
                    allowed=(receiver_name,))
        receiver = self.get(receiver_name, "S11")
        if receiver is None:
            return
        calls = list(re.finditer(r"registerReceiver\(", receiver.compact))
        if len(calls) != 1:
            self.add("S11", f"exactly one registerReceiver expected, found {len(calls)}")
        for call in calls:
            if "Context.RECEIVER_NOT_EXPORTED" not in paren_args(receiver.compact, call.end() - 1):
                self.add("S11", "registerReceiver must use Context.RECEIVER_NOT_EXPORTED")
        actions = set(re.findall(r"Intent\.(ACTION_\w+)", receiver.code))
        if actions != {"ACTION_SCREEN_OFF"}:
            self.add("S11", f"only Intent.ACTION_SCREEN_OFF is allowed (found {sorted(actions)})")

    def s12(self):
        holder_name = "platform/MulticastLockHolder.kt"
        self.forbid("S12", r"createMulticastLock", "MulticastLock only in platform/MulticastLockHolder.kt",
                    allowed=(holder_name,))
        holder = self.get(holder_name, "S12")
        if holder is None:
            return
        c = holder.compact
        if "setReferenceCounted(false)" not in c or "setReferenceCounted(true)" in c:
            self.add("S12", "the multicast lock must not be reference counted")
        if ".release()" not in c or "multicastWanted()" not in c:
            self.add("S12", "the multicast lock must be released when multicastWanted() is false")

    def s13(self):
        self.forbid("S13", r"Process\.myPid|\bmyPid\s*\(", "no second-process logic")
        self.forbid("S13", r":remote\b|android:process", "no second process", raw=True)
        self.forbid("S13", r"PasswsyncCore\.start\s*\(", "the core starts only in PasswsyncApp.onCreate",
                    allowed=("PasswsyncApp.kt",))
        app = self.get("PasswsyncApp.kt", "S13")
        if app is None:
            return
        starts = len(re.findall(r"PasswsyncCore\.start\s*\(", app.code))
        body = function_body(app.code, "onCreate") or ""
        if starts != 1 or len(re.findall(r"PasswsyncCore\.start\s*\(", body)) != 1:
            self.add("S13", "PasswsyncCore.start must be called exactly once, in PasswsyncApp.onCreate")

    def s14(self):
        self.forbid("S14", r"CameraManager|camera2|zxing|BarcodeDetector|QRCode", "no camera or QR")

    def s15(self):
        sealer_name = "platform/KeystoreSealer.kt"
        self.forbid("S15", r"KeyStore\.getInstance|KeyGenParameterSpec", "Keystore only in platform/KeystoreSealer.kt",
                    allowed=(sealer_name,))
        self.forbid("S15", r"setUserAuthenticationValidityDurationSeconds|setUserAuthenticationParameters",
                    "no user-authentication validity")
        sealer = self.get(sealer_name, "S15")
        if sealer is None:
            return
        c = sealer.compact
        if '"AndroidKeyStore"' not in sealer.raw:
            self.add("S15", "KeystoreSealer.kt must use AndroidKeyStore")
        for token in ("KeyProperties.BLOCK_MODE_GCM", "KeyProperties.ENCRYPTION_PADDING_NONE",
                      "setRandomizedEncryptionRequired(true)", "setUserAuthenticationRequired(false)"):
            if token not in c:
                self.add("S15", f"KeystoreSealer.kt needs {token}")
        if re.search(r"BLOCK_MODE_(CBC|ECB|CTR)|setUserAuthenticationRequired\(true\)", c):
            self.add("S15", "KeystoreSealer.kt: only GCM without user authentication")
        inits = len(re.findall(r"\.init\(Cipher\.", c))
        if inits == 0 or c.count("updateAAD(") < inits:
            self.add("S15", f"updateAAD must be called on every cipher ({inits} init)")
        if re.search(r"\bPasswsyncCore\b|(?<![\w.])core\.", sealer.code):
            self.add("S15", "KeystoreSealer.kt must not call PasswsyncCore")

    def s16(self):
        for name, source in self.files.items():
            if re.search(r"TYPE_TEXT_VARIATION_(WEB_)?PASSWORD", source.code):
                for token in ("IME_FLAG_NO_PERSONALIZED_LEARNING", "IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS"):
                    if token not in source.code:
                        self.add("S16", f"{name}: password field in code needs {token}")
        self.forbid("S16", r"TYPE_TEXT_VARIATION_VISIBLE_PASSWORD|setAutofillHints\s*\(|AUTOFILL_HINT_",
                    "password fields must not be visible or autofilled")

    def s17(self):
        for name, source in self.files.items():
            match = re.search(r"^\s*package\s+([\w.]+)", source.code, re.M)
            if not match or not PACKAGE.match(match.group(1)):
                self.add("S17", f"{name}: package must be io.github.henriqk0.passwsync or a sub-package")
        self.forbid("S17", r"@Suppress\([^)]*[Ss]ecure", "no @Suppress of a secure lint", raw=True)
        self.forbid("S17", r"Class\.forName|getDeclaredMethod|getDeclaredField|kotlin\.reflect|"
                           r"::class\.java\.getMethod|\.javaClass\.getMethod", "no reflection")


def check(root: Path):
    return Checker(root).run()


def main(argv=None):
    return run_main(sys.argv[1:] if argv is None else argv, "check_sources.py", check)


if __name__ == "__main__":
    sys.exit(main())
